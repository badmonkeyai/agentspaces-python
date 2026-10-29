# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The content swarm, ``aspace:cap/content-swarm`` (SPEC v0.1.23 §7.1, §8,
annex G; srad/large-networks-bulk-data.md): a large artifact is a signed
``Manifest`` entry naming the CIDv1 root of its fixed-size pieces, each
member that holds pieces writes a leased ``Holding``, and the pieces move as
tagged ``PIPE_DATA`` payloads from every reachable holder at once, verified
against the manifest's table before they are stored or served.

    content = Content(Pipes(peer), Space(peer, "content"), FileStore(path))
    manifest = content.publish(data, name="weights.bin")
    fetch = content.fetch(manifest["root"]); fetch.wait(60); fetch.read_bytes()

A dial-only client reaches holders it has seen on its socket directly and
every other holder through its seed when the seed holds the RELAY role
(``Peer.send_pipe``); a space with the capability attached escalates a
payload above ``escalate_above`` to an artifact (SPEC §7.1, group E).
"""

from __future__ import annotations

import hashlib
import os
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import cbor
from ..space import duration_millis

TYPE = "aspace:cap/content-swarm"
MANIFEST_TYPE = "ai.badmonkey.agentspaces.agent.content.Manifest#v1"
HOLDING_TYPE = "ai.badmonkey.agentspaces.agent.content.Holding#v1"

VERSION = 1
INLINE_TABLE_PIECES = 64
HASH_BYTES = 32
MIN_PIECE_SIZE = 64 * 1024
MAX_PIECE_SIZE = 4 * 1024 * 1024
DEFAULT_PIECE_SIZE = 1024 * 1024
MAX_HAVE_BYTES = 8 * 1024
RANGE_UNIT = 64 * 1024

PIECE_WANT, PIECE, HAVE, CANCEL, REJECT, MANIFEST_WANT, MANIFEST = 1, 2, 3, 4, 5, 6, 7
REASON_NOT_HELD, REASON_OVER_BUDGET, REASON_POLICY, REASON_UNKNOWN_ROOT = 1, 2, 3, 4

SEALING_NONE, SEALING_GROUP_KEY = "none", "group-key"
HASHING_PLAIN, HASHING_SEALED = "plain", "sealed"

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


# ------------------------------------------------------------------ roots

def base32_lower(data: bytes) -> str:
    """RFC 4648 base32, lower case, unpadded: the multibase ``b`` form."""
    out, buffer, bits = [], 0, 0
    for b in data:
        buffer = (buffer << 8) | b
        bits += 8
        while bits >= 5:
            out.append(_B32[(buffer >> (bits - 5)) & 0x1F])
            bits -= 5
    if bits:
        out.append(_B32[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def content_root(table: bytes) -> str:
    """The CIDv1 of a piece table: 0x01, raw 0x55, sha2-256 0x12, 32 bytes, base32 ``b``."""
    if len(table) % HASH_BYTES:
        raise ValueError("table is not a multiple of 32 bytes")
    digest = hashlib.sha256(table).digest()
    return "b" + base32_lower(bytes([0x01, 0x55, 0x12, 0x20]) + digest)


def is_root(ref) -> bool:
    """Whether a ``payloadRef`` names a content root (``b``) rather than one block (``z``)."""
    return isinstance(ref, str) and len(ref) > 1 and ref[0] == "b"


def hash_pieces(data: bytes, piece_size: int = DEFAULT_PIECE_SIZE) -> bytes:
    """The piece table of bytes in memory."""
    table = bytearray()
    for start in range(0, len(data), piece_size):
        table += hashlib.sha256(data[start:start + piece_size]).digest()
    return bytes(table)


def hash_file(path, piece_size: int = DEFAULT_PIECE_SIZE) -> tuple[bytes, int]:
    """The piece table and size of a file, read piece by piece."""
    table, size = bytearray(), 0
    with open(path, "rb") as f:
        while True:
            piece = f.read(piece_size)
            if not piece:
                break
            size += len(piece)
            table += hashlib.sha256(piece).digest()
    return bytes(table), size


def pieces_of(size: int, piece_size: int) -> int:
    return 0 if size == 0 else (size + piece_size - 1) // piece_size


def piece_length(size: int, piece_size: int, index: int) -> int:
    return min(piece_size, size - index * piece_size)


def verifies(table: bytes, index: int, piece: bytes) -> bool:
    start = index * HASH_BYTES
    if index < 0 or start + HASH_BYTES > len(table):
        return False
    return hashlib.sha256(piece).digest() == table[start:start + HASH_BYTES]


# ------------------------------------------------------------------ records

def manifest(root: str, size: int, piece_size: int, table: bytes | None, origin: str, created_ms: int,
             *, table_ref: str | None = None, name: str | None = None, media_type: str | None = None,
             attrs: dict | None = None, sealing: str = SEALING_NONE, key_epoch: int | None = None,
             hashing: str = HASHING_PLAIN) -> dict:
    """A ``Manifest`` value in Java field order (annex G)."""
    return {"v": VERSION, "root": root, "size": int(size), "pieceSize": int(piece_size),
            "pieces": pieces_of(size, piece_size), "table": table, "tableRef": table_ref,
            "tableRefs": None, "name": name, "mediaType": media_type, "sealing": sealing,
            "keyEpoch": key_epoch, "hashing": hashing, "origin": origin, "created": int(created_ms),
            "attrs": cbor.canonical_map({str(k): str(v) for k, v in attrs.items()}) if attrs else None}


def manifest_violation(m: dict) -> str | None:
    """The first broken invariant of a manifest, or None (SPEC annex G)."""
    try:
        if m.get("v") != VERSION:
            return f"unsupported manifest version {m.get('v')}"
        ps = int(m["pieceSize"])
        if ps < MIN_PIECE_SIZE or ps > MAX_PIECE_SIZE or ps & (ps - 1):
            return "pieceSize is not a power of two in [64 KiB, 4 MiB]"
        size = int(m["size"])
        if size < 0 or int(m["pieces"]) != pieces_of(size, ps):
            return "pieces does not match ceil(size / pieceSize)"
        table, ref = m.get("table"), m.get("tableRef")
        if (table is None) == (ref is None):
            return "exactly one of table and tableRef must be present"
        if table is not None:
            if int(m["pieces"]) > INLINE_TABLE_PIECES:
                return "inline table above the inline bound"
            if len(table) != int(m["pieces"]) * HASH_BYTES:
                return "table length does not match pieces"
            if content_root(table) != m["root"]:
                return "table does not hash to the root"
        if m.get("sealing") not in (SEALING_NONE, SEALING_GROUP_KEY):
            return "unknown sealing"
        if m.get("hashing") not in (HASHING_PLAIN, HASHING_SEALED):
            return "unknown hashing"
        if not is_root(m.get("root")):
            return "root is not a content root"
        return None
    except (KeyError, TypeError, ValueError) as e:
        return f"malformed manifest: {e}"


def manifest_tags(m: dict) -> dict:
    """The manifest's tags as Java writes them (LB-M-09): the user's attrs, then root and name,
    which keep their meaning when an attr reuses the key."""
    tags = dict(m.get("attrs") or {})
    tags["root"] = m["root"]
    if m.get("name"):
        tags["name"] = m["name"]
    else:
        tags.pop("name", None)
    return tags


def encode_have(have: set[int] | list[int], pieces: int) -> bytes:
    """Alternating runs of zeros and ones as unsigned varints, zeros first."""
    present = set(have)
    out, i, value = bytearray(), 0, False
    while i < pieces:
        run = 0
        while i < pieces and ((i in present) == value):
            run += 1
            i += 1
        while run & ~0x7F:
            out.append((run & 0x7F) | 0x80)
            run >>= 7
        out.append(run)
        value = not value
    return bytes(out)


def decode_have(data: bytes | None, pieces: int) -> set[int]:
    """The pieces a holding states; every piece when the field is null."""
    if data is None:
        return set(range(pieces))
    have, pos, i, value = set(), 0, 0, False
    while pos < len(data) and i < pieces:
        run, shift = 0, 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            run |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        end = min(pieces, i + run)
        if value:
            have.update(range(i, end))
        i = end
        value = not value
    return have


def holding(root: str, holder: str, have: set[int], pieces: int, via: list[str] | None = None) -> dict:
    """A ``Holding`` value in Java field order."""
    complete = pieces > 0 and len(have) >= pieces
    encoded = None if complete else encode_have(have, pieces)
    if encoded is not None and len(encoded) > MAX_HAVE_BYTES:
        encoded = None
    return {"v": VERSION, "root": root, "holder": holder, "complete": complete, "have": encoded,
            "count": len(have), "via": list(via) if via else None, "cost": None}


def holding_tags(h: dict) -> dict:
    return {"root": h["root"], "holder": h["holder"]}


# ------------------------------------------------------------------ messages

def piece_want(root, index, offset, length, req) -> dict:
    return {"t": PIECE_WANT, "root": root, "index": int(index), "offset": int(offset),
            "length": int(length), "req": int(req)}


def piece(root, index, offset, data: bytes, req) -> dict:
    return {"t": PIECE, "root": root, "index": int(index), "offset": int(offset), "bytes": data, "req": int(req)}


def have_message(root, have: bytes | None, complete: bool) -> dict:
    return {"t": HAVE, "root": root, "have": have, "complete": bool(complete)}


def cancel(root, index, req) -> dict:
    return {"t": CANCEL, "root": root, "index": int(index), "req": int(req)}


def reject(root, index, reason) -> dict:
    return {"t": REJECT, "root": root, "index": int(index), "reason": int(reason)}


def manifest_want(root) -> dict:
    return {"t": MANIFEST_WANT, "root": root}


def manifest_reply(root, record: bytes) -> dict:
    return {"t": MANIFEST, "root": root, "record": record}


# ------------------------------------------------------------------ stores

class MemoryStore:
    """Pieces on the heap; for tests and small artifacts."""

    kind = "memory"
    writable = True

    def __init__(self):
        self._held: dict[str, tuple[dict, dict[int, bytes]]] = {}
        self._pinned: set[str] = set()
        self._lock = threading.Lock()

    def roots(self) -> set[str]:
        return set(self._held)

    def manifest(self, root: str) -> dict | None:
        held = self._held.get(root)
        return held[0] if held else None

    def open(self, m: dict) -> None:
        with self._lock:
            self._held.setdefault(m["root"], (m, {}))

    def have(self, root: str) -> set[int]:
        held = self._held.get(root)
        return set(held[1]) if held else set()

    def read(self, root: str, index: int, offset: int, length: int) -> bytes | None:
        held = self._held.get(root)
        if not held or index not in held[1]:
            return None
        data = held[1][index]
        if offset < 0 or offset > len(data):
            return None
        return data[offset:offset + length]

    def write(self, root: str, index: int, data: bytes) -> None:
        held = self._held.get(root)
        if held is None:
            raise ValueError(f"root {root} is not open in this store")
        with self._lock:
            held[1].setdefault(index, bytes(data))

    def read_all(self, root: str) -> bytes:
        held = self._held.get(root)
        if held is None or len(held[1]) < held[0]["pieces"]:
            raise ValueError(f"root {root} is incomplete here")
        return b"".join(held[1][i] for i in range(held[0]["pieces"]))

    def pin(self, root): self._pinned.add(root)
    def unpin(self, root): self._pinned.discard(root)
    def flush(self): pass
    def forget(self, root): self._held.pop(root, None)


class FileStore:
    """One directory per root under ``path``: ``data`` (pieces at their offsets),
    ``have`` (the verified bitfield), ``manifest.cbor``. Reads every root back on
    start, so a fetch resumes and a holder republishes; the bitfield is persisted
    every eight pieces and on ``flush``."""

    kind = "file"
    writable = True
    PERSIST_EVERY = 8

    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._held: dict[str, dict] = {}  # root -> {"manifest", "dir", "have": set, "persisted": int}
        self._lock = threading.Lock()
        for d in self.path.iterdir():
            mf = d / "manifest.cbor"
            if mf.is_file():
                m = cbor.loads(mf.read_bytes())
                have = set()
                hf = d / "have"
                if hf.is_file():
                    have = decode_have(hf.read_bytes(), int(m["pieces"]))
                self._held[m["root"]] = {"manifest": m, "dir": d, "have": have, "persisted": len(have)}

    def roots(self) -> set[str]:
        return set(self._held)

    def manifest(self, root: str) -> dict | None:
        held = self._held.get(root)
        return held["manifest"] if held else None

    def open(self, m: dict) -> None:
        with self._lock:
            if m["root"] in self._held:
                return
            d = self.path / "".join(c if c.isalnum() else "_" for c in m["root"])
            d.mkdir(parents=True, exist_ok=True)
            (d / "manifest.cbor").write_bytes(cbor.dumps(m))
            data = d / "data"
            if not data.exists():
                with open(data, "wb") as f:
                    if int(m["size"]) > 0:
                        f.seek(int(m["size"]) - 1)
                        f.write(b"\0")
            self._held[m["root"]] = {"manifest": m, "dir": d, "have": set(), "persisted": 0}

    def have(self, root: str) -> set[int]:
        held = self._held.get(root)
        return set(held["have"]) if held else set()

    def read(self, root: str, index: int, offset: int, length: int) -> bytes | None:
        held = self._held.get(root)
        if not held or index not in held["have"]:
            return None
        m = held["manifest"]
        plen = piece_length(int(m["size"]), int(m["pieceSize"]), index)
        if offset < 0 or offset > plen:
            return None
        n = min(length, plen - offset)
        with open(held["dir"] / "data", "rb") as f:
            f.seek(index * int(m["pieceSize"]) + offset)
            return f.read(n)

    def write(self, root: str, index: int, data: bytes) -> None:
        held = self._held.get(root)
        if held is None:
            raise ValueError(f"root {root} is not open in this store")
        m = held["manifest"]
        with self._lock:
            if index in held["have"]:
                return
            with open(held["dir"] / "data", "r+b") as f:
                f.seek(index * int(m["pieceSize"]))
                f.write(data)
                held["have"].add(index)
                complete = len(held["have"]) >= int(m["pieces"])
                if complete or len(held["have"]) - held["persisted"] >= self.PERSIST_EVERY:
                    f.flush()
                    os.fsync(f.fileno())
                    self._persist(held)

    def _persist(self, held: dict) -> None:
        m = held["manifest"]
        tmp = held["dir"] / "have.tmp"
        tmp.write_bytes(encode_have(held["have"], int(m["pieces"])))
        os.replace(tmp, held["dir"] / "have")
        held["persisted"] = len(held["have"])

    def flush(self) -> None:
        with self._lock:
            for held in self._held.values():
                if len(held["have"]) > held["persisted"]:
                    with open(held["dir"] / "data", "r+b") as f:
                        f.flush()
                        os.fsync(f.fileno())
                    self._persist(held)

    def read_all(self, root: str) -> bytes:
        held = self._held.get(root)
        if held is None or len(held["have"]) < int(held["manifest"]["pieces"]):
            raise ValueError(f"root {root} is incomplete here")
        return (held["dir"] / "data").read_bytes()[: int(held["manifest"]["size"])]

    def pin(self, root):
        held = self._held.get(root)
        if held:
            (held["dir"] / "pin").touch()

    def unpin(self, root):
        held = self._held.get(root)
        if held:
            (held["dir"] / "pin").unlink(missing_ok=True)

    def forget(self, root):
        held = self._held.pop(root, None)
        if held:
            for f in held["dir"].iterdir():
                f.unlink()
            held["dir"].rmdir()


# ------------------------------------------------------------------ the fetch

@dataclass
class _Source:
    peer: str
    have: set[int]
    via: list | None = None
    window: int = 2
    in_flight: int = 0
    range_length: int = RANGE_UNIT
    srtt_ms: float = -1.0
    successes: int = 0
    timeouts: int = 0
    dropped_until: float = 0.0
    bytes_verified: int = 0
    assignment: dict | None = None   # {"index", "length", "buffer": bytearray, "units": set, "next": int}
    retry: list = field(default_factory=list)


class Fetch:
    """One fetch: the scheduler of SRAD §3.4 in miniature (rarest first, a
    window of ranges per source, timeouts that halve it, endgame duplicates,
    per-piece verification, strikes), driven from ``Content.tick``."""

    MIN_TIMEOUT_S = 10.0
    MAX_WINDOW = 32
    TIMEOUTS_BEFORE_DROP = 3
    DROP_S = 60.0

    def __init__(self, content: "Content", root: str):
        self.content = content
        self.root = root
        self.manifest: dict | None = None
        self.table: bytes | None = None
        self.verified: set[int] = set()
        self.sources: dict[str, _Source] = {}
        self.outstanding: dict[int, tuple[_Source, int, int, int, float]] = {}
        self.assigned: dict[int, list[_Source]] = {}
        self.trace: list[str] = []
        self.done = threading.Event()
        self.failure: str | None = None
        self.bytes_received = 0
        self.started = time.monotonic()
        self.holdings_read_at = 0.0
        self.manifest_asked_at = 0.0
        self._lock = threading.RLock()
        self._scheduling = False
        self._reschedule = False

    # ---- the handle

    @property
    def complete(self) -> bool:
        return self.done.is_set() and self.failure is None

    def wait(self, timeout_s: float | None = None) -> bool:
        self.done.wait(timeout_s)
        return self.complete

    def progress(self) -> dict:
        with self._lock:
            pieces = int(self.manifest["pieces"]) if self.manifest else 0
            return {"piecesVerified": len(self.verified), "pieces": pieces, "bytesReceived": self.bytes_received,
                    "bytesBySource": {p: s.bytes_verified for p, s in self.sources.items()},
                    "sourcesActive": sum(1 for s in self.sources.values() if s.in_flight > 0),
                    "fraction": (len(self.verified) / pieces) if pieces else 0.0}

    def read_bytes(self) -> bytes:
        if not self.complete:
            raise ValueError(f"fetch of {self.root} is not complete")
        return self.content.store.read_all(self.root)

    def cancel(self) -> None:
        with self._lock:
            if not self.done.is_set():
                self.failure = "cancelled"
                self.done.set()

    def _note(self, line: str) -> None:
        self.trace.append(line)
        del self.trace[:-256]

    # ---- driving

    def start(self, m: dict, table: bytes) -> None:
        with self._lock:
            if self.manifest is not None:
                return
            self.manifest, self.table = m, table
            self.content.store.open(m)
            self.verified = {i for i in self.content.store.have(self.root) if i < int(m["pieces"])}
            self.bytes_received = sum(piece_length(int(m["size"]), int(m["pieceSize"]), i) for i in self.verified)
            self._note(f"start: {m['pieces']} pieces of {m['pieceSize']} bytes, {len(self.verified)} already verified")
            if len(self.verified) >= int(m["pieces"]):
                self._finish()
                return
            self._refresh_sources()
            self._schedule()

    def tick(self) -> None:
        with self._lock:
            if self.done.is_set() or self.manifest is None:
                return
            now = time.monotonic()
            self._time_out(now)
            if now - self.holdings_read_at >= 5.0:
                self._refresh_sources()
            self._schedule()

    def _refresh_sources(self) -> None:
        self.holdings_read_at = time.monotonic()
        pieces = int(self.manifest["pieces"])
        seen = set()
        for h in self.content.holdings(self.root):
            peer = h["holder"]
            if peer == self.content.self_id or peer in seen:
                continue
            seen.add(peer)
            have = decode_have(h.get("have"), pieces) if not h.get("complete") else set(range(pieces))
            via = [v for v in (h.get("via") or []) if isinstance(v, str)] or None
            if peer in self.sources:
                self.sources[peer].have = have
                self.sources[peer].via = via
            elif len(self.sources) < self.content.max_sessions:
                self.sources[peer] = _Source(peer, have, via)
                self._note(f"source {peer[:10]} ({'complete' if h.get('complete') else str(h.get('count')) + ' pieces'})")

    def _time_out(self, now: float) -> None:
        expired = [req for req, (s, _i, _o, _l, sent) in self.outstanding.items()
                   if now - sent > max(self.MIN_TIMEOUT_S, 8 * s.srtt_ms / 1000 if s.srtt_ms > 0 else 0)]
        for req in expired:
            s, index, offset, length, _sent = self.outstanding.pop(req)
            s.in_flight = max(0, s.in_flight - 1)
            s.window = max(1, s.window // 2)
            s.range_length = max(RANGE_UNIT, s.range_length // 2)
            s.timeouts += 1
            s.retry.insert(0, (index, offset, length))
            if s.timeouts >= self.TIMEOUTS_BEFORE_DROP:
                s.dropped_until = now + self.DROP_S
                s.timeouts = 0
                self._release(s)
                self._note(f"source {s.peer[:10]} timed out {self.TIMEOUTS_BEFORE_DROP} times; dropped for 60 s")

    def _release(self, s: _Source) -> None:
        a = s.assignment
        if a is None:
            return
        s.assignment = None
        s.retry.clear()
        holders = self.assigned.get(a["index"])
        if holders:
            holders[:] = [x for x in holders if x is not s]
            if not holders:
                self.assigned.pop(a["index"], None)

    def _schedule(self) -> None:
        if self._scheduling:
            self._reschedule = True
            return
        self._scheduling = True
        try:
            while True:
                self._reschedule = False
                self._schedule_once()
                if not self._reschedule or self.done.is_set():
                    break
        finally:
            self._scheduling = False

    def _schedule_once(self) -> None:
        if self.done.is_set() or self.manifest is None:
            return
        now = time.monotonic()
        pieces = int(self.manifest["pieces"])
        availability = [0] * pieces
        for s in self.sources.values():
            for i in s.have:
                if i < pieces:
                    availability[i] += 1
        endgame = not any(i not in self.verified and i not in self.assigned for i in range(pieces))
        order = sorted(self.sources.values(), key=lambda s: (self.content.hops_to(s.peer), -s.bytes_verified))
        for s in order:
            if s.dropped_until > now:
                continue
            granted = 0
            while s.in_flight < s.window and granted < s.window:
                rng = self._next_range(s, availability, endgame)
                if rng is None:
                    break
                index, offset, length = rng
                req = self.content.next_req()
                self.outstanding[req] = (s, index, offset, length, now)
                s.in_flight += 1
                granted += 1
                self.content.send(s.peer, piece_want(self.root, index, offset, length, req), s.via)
                if self._reschedule:
                    break

    def _next_range(self, s: _Source, availability: list[int], endgame: bool):
        if s.retry:
            index, offset, length = s.retry.pop(0)
            if index not in self.verified and s.assignment and s.assignment["index"] == index:
                return index, offset, length
        a = s.assignment
        if a is not None and (a["index"] in self.verified or len(a["units"]) >= a["unit_count"]):
            self._release(s)
            a = None
        if a is None:
            index = self._pick(s, availability, endgame)
            if index < 0:
                return None
            m = self.manifest
            length = piece_length(int(m["size"]), int(m["pieceSize"]), index)
            a = {"index": index, "length": length, "buffer": bytearray(length), "units": set(),
                 "unit_count": (length + RANGE_UNIT - 1) // RANGE_UNIT, "next": 0}
            s.assignment = a
            self.assigned.setdefault(index, []).append(s)
        if a["next"] >= a["length"]:
            return None
        offset = a["next"]
        length = min(s.range_length, a["length"] - offset)
        a["next"] += length
        return a["index"], offset, length

    def _pick(self, s: _Source, availability: list[int], endgame: bool) -> int:
        pieces = int(self.manifest["pieces"])
        best, best_count, ties = -1, 1 << 30, 0
        cold = not self.verified and not self.assigned
        for i in range(pieces):
            if i in self.verified or i not in s.have:
                continue
            holders = self.assigned.get(i)
            if holders and (not endgame or s in holders):
                continue
            count = 0 if cold else availability[i]
            if count < best_count:
                best, best_count, ties = i, count, 1
            elif count == best_count:
                ties += 1
                if self.content.random.randrange(ties) == 0:
                    best = i
        return best

    def on_piece(self, sender: str, msg: dict) -> None:
        with self._lock:
            if self.done.is_set() or self.manifest is None:
                return
            out = self.outstanding.pop(int(msg.get("req", -1)), None)
            if out is None:
                return
            s, index, offset, length, sent = out
            if s.peer != sender or index != msg.get("index") or offset != msg.get("offset"):
                return
            s.in_flight = max(0, s.in_flight - 1)
            rtt = (time.monotonic() - sent) * 1000
            s.srtt_ms = rtt if s.srtt_ms < 0 else (s.srtt_ms * 7 + rtt) / 8
            s.timeouts = 0
            data = msg.get("bytes") or b""
            a = s.assignment
            if a is None or a["index"] != index or index in self.verified:
                self._schedule()
                return
            if len(data) != length or offset + length > a["length"]:
                s.retry.insert(0, (index, offset, length))
                self._schedule()
                return
            a["buffer"][offset:offset + length] = data
            a["units"].update(range(offset // RANGE_UNIT, (offset + length - 1) // RANGE_UNIT + 1))
            s.successes += 1
            if s.window < self.MAX_WINDOW:
                s.window += 1
            if s.successes % 8 == 0 and s.range_length < int(self.manifest["pieceSize"]):
                s.range_length = min(int(self.manifest["pieceSize"]), s.range_length * 2)
            if len(a["units"]) >= a["unit_count"]:
                self._complete_piece(s, a)
            self._schedule()

    def on_reject(self, sender: str, msg: dict) -> None:
        with self._lock:
            s = self.sources.get(sender)
            if s is None:
                return
            for req, (src, index, offset, length, _sent) in list(self.outstanding.items()):
                if src is s and index == msg.get("index"):
                    self.outstanding.pop(req)
                    s.in_flight = max(0, s.in_flight - 1)
                    s.retry.insert(0, (index, offset, length))
                    break
            if msg.get("reason") in (REASON_OVER_BUDGET, REASON_POLICY):
                s.dropped_until = time.monotonic() + self.DROP_S
                self._note(f"source {s.peer[:10]} rejected ({msg.get('reason')}); dropped for a while")
            else:
                s.have.discard(int(msg.get("index", -1)))
            self._release(s)
            self._schedule()

    def _complete_piece(self, s: _Source, a: dict) -> None:
        data = bytes(a["buffer"])
        if verifies(self.table, a["index"], data):
            self.content.store.write(self.root, a["index"], data)
            self.verified.add(a["index"])
            self.bytes_received += len(data)
            s.bytes_verified += len(data)
            for other in self.assigned.pop(a["index"], []):
                if other is not s:
                    for req, (src, index, _o, _l, _sent) in list(self.outstanding.items()):
                        if src is other and index == a["index"]:
                            self.outstanding.pop(req)
                            other.in_flight = max(0, other.in_flight - 1)
                            self.content.send(other.peer, cancel(self.root, index, req), other.via)
                    other.assignment = None
                    other.retry.clear()
            s.assignment = None
            self.content._on_piece_verified(self)
            if len(self.verified) >= int(self.manifest["pieces"]):
                self._finish()
        else:
            self._note(f"piece {a['index']} from {s.peer[:10]} failed its hash; struck")
            self.content.pieces_struck += 1
            self._release(s)
            s.dropped_until = float("inf")

    def _finish(self) -> None:
        self._note(f"complete: {len(self.verified)} pieces, {self.bytes_received} bytes in "
                   f"{int((time.monotonic() - self.started) * 1000)} ms")
        self.outstanding.clear()
        self.done.set()
        self.content._on_complete(self)


# ------------------------------------------------------------------ the capability

class Content:
    """The content swarm over a ``Pipes`` and the group's content ``Space``.

    ``store`` is a ``MemoryStore`` or ``FileStore``; ``piece_size`` the
    publisher's default; ``max_sessions`` and ``max_window`` the scheduler's
    bounds. ``run(interval)`` drives the ticks on a thread, or call ``tick``.
    Attach to a peer (``peer.content = content``) and every ``Space`` over it
    escalates a payload above ``escalate_above`` to an artifact.
    """

    HOLDING_LEASE = "2m"
    MANIFEST_LEASE = "7d"

    def __init__(self, pipes, space, store=None, *, piece_size: int = DEFAULT_PIECE_SIZE,
                 max_sessions: int = 16, max_window: int = 32, escalate_above: int = 4 * 1024 * 1024,
                 may_serve: Callable[[str, dict], bool] | None = None, seed: int | None = None):
        self.pipes = pipes
        self.peer = pipes.peer
        self.space = space
        self.store = store or MemoryStore()
        self.piece_size = int(piece_size)
        self.max_sessions = max_sessions
        self.max_window = max_window
        self.escalate_above = int(escalate_above)
        self.may_serve = may_serve
        self.random = random.Random(seed)
        self.self_id = self.peer.identity.peer_id
        self.fetches: dict[str, Fetch] = {}
        self.holder_state: dict[str, dict] = {}   # root -> {"count", "written_at", "entry_id"}
        self.manifest_entries: dict[str, str] = {}
        self._req = 0
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self.bytes_served = 0
        self.wants_refused = 0
        self.pieces_struck = 0
        pipes.on_capability(TYPE, self._on_frame)
        self.peer.content = self
        self.start()

    # ---- wiring

    def start(self) -> None:
        """Publishes holdings for everything the store already holds."""
        for root in self.store.roots():
            if self.store.have(root):
                self._refresh_holding(root, force=True)

    def run(self, interval_s: float = 0.25) -> None:
        if self._running:
            return
        self._running = True

        def loop():
            while self._running and getattr(self.peer, "connected", True):
                try:
                    self.tick()
                except Exception:
                    pass
                time.sleep(interval_s)

        self._thread = threading.Thread(target=loop, name="content-tick", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.store.flush()

    def next_req(self) -> int:
        with self._lock:
            self._req += 1
            return self._req

    def send(self, to: str, msg: dict, via: list | None = None) -> None:
        self.pipes.send(to, TYPE, cbor.dumps(msg), via)

    def hops_to(self, peer_id: str) -> int:
        return 0 if self.peer.relay_for(peer_id) is None else 1

    def now_ms(self) -> int:
        return self.peer._now_ms()

    # ---- the replica

    def _records(self, type_name: str, root: str | None = None) -> list[dict]:
        now = self.now_ms()
        found = []
        for dto in list(self.peer.states.values()):
            record = dto.get("record") or {}
            if record.get("type") != type_name or dto.get("completed") or not self.space._mine(dto):
                continue
            if int((record.get("lease") or {}).get("expiresAtMillis", 0)) <= now:
                continue
            if root is not None and (record.get("tags") or {}).get("root") != root:
                continue
            payload = record.get("payload")
            if payload is None:
                continue
            try:
                value = cbor.loads(payload)
            except Exception:
                continue
            if isinstance(value, dict):
                found.append(value)
        return found

    def manifest_of(self, root: str) -> dict | None:
        m = self.store.manifest(root)
        if m is not None:
            return m
        for candidate in self._records(MANIFEST_TYPE, root):
            if manifest_violation(candidate) is None:
                return candidate
        return None

    def holdings(self, root: str) -> list[dict]:
        """One holding per holder: the fullest one, since a holder that cannot withdraw
        its earlier partial holdings (this client) leaves them to lapse."""
        best: dict[str, dict] = {}
        for h in self._records(HOLDING_TYPE, root):
            if h.get("v") != VERSION or not isinstance(h.get("holder"), str):
                continue
            seen = best.get(h["holder"])
            if seen is None or (h.get("complete"), int(h.get("count") or 0)) > (seen.get("complete"), int(seen.get("count") or 0)):
                best[h["holder"]] = h
        return list(best.values())

    def describe(self, root: str) -> dict | None:
        m = self.manifest_of(root)
        if m is None:
            return None
        hs = self.holdings(root)
        return {"manifest": m, "completeHolders": sum(1 for h in hs if h.get("complete")),
                "partialHolders": sum(1 for h in hs if not h.get("complete")),
                "held": len(self.store.have(root))}

    def list_manifests(self, limit: int = 1000) -> list[dict]:
        return [m for m in self._records(MANIFEST_TYPE) if manifest_violation(m) is None][:limit]

    # ---- publish

    def publish(self, data, *, name=None, media_type=None, attrs=None, lease=MANIFEST_LEASE,
                piece_size=None, replicate=True, sealing=SEALING_NONE) -> dict:
        """Publishes bytes or a file path; returns the manifest."""
        piece_size = int(piece_size or self.piece_size)
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data)
            table, size = hash_pieces(data, piece_size), len(data)
            reader = lambda i: data[i * piece_size:(i + 1) * piece_size]  # noqa: E731
        else:
            path = Path(data)
            table, size = hash_file(path, piece_size)

            def reader(i, _path=path):
                with open(_path, "rb") as f:
                    f.seek(i * piece_size)
                    return f.read(piece_size)
        n = pieces_of(size, piece_size)
        if n > INLINE_TABLE_PIECES:
            raise ValueError("artifacts above 64 pieces need the block exchange for their table; "
                             "use a larger piece size (this client keeps the table inline)")
        m = manifest(content_root(table), size, piece_size, table, self.self_id, self.now_ms(),
                     name=name, media_type=media_type, attrs=attrs, sealing=sealing)
        self.store.open(m)
        for i in range(n):
            self.store.write(m["root"], i, reader(i))
        return self._published(m, lease, replicate)

    def publish_opaque(self, payload: bytes, lease_millis: int) -> str:
        """A space's escalation seam: the payload as the space produced it; returns the root."""
        m = self.publish(payload, media_type="application/cbor", lease=f"{lease_millis}ms",
                         piece_size=self._piece_size_for(len(payload)))
        return m["root"]

    def _piece_size_for(self, size: int) -> int:
        ps = self.piece_size
        while pieces_of(size, ps) > INLINE_TABLE_PIECES and ps < MAX_PIECE_SIZE:
            ps *= 2
        return ps

    def _published(self, m: dict, lease, replicate: bool) -> dict:
        self.store.pin(m["root"])
        if replicate and not self._records(MANIFEST_TYPE, m["root"]):
            self.manifest_entries[m["root"]] = self._write(MANIFEST_TYPE, m, lease, manifest_tags(m))
        self._refresh_holding(m["root"], force=True)
        return m

    def share(self, root: str, lease=MANIFEST_LEASE) -> dict:
        """The bridge: writes a manifest here for a root the store holds in full."""
        m = self.store.manifest(root)
        if m is None or len(self.store.have(root)) < int(m["pieces"]):
            raise ValueError(f"root {root} is not complete in this store")
        here = dict(m)
        here["origin"], here["created"] = self.self_id, self.now_ms()
        return self._published(here, lease, True)

    def pin(self, root): self.store.pin(root)
    def unpin(self, root): self.store.unpin(root)

    # ---- fetch

    def fetch(self, root: str) -> Fetch:
        if not is_root(root):
            raise ValueError(f"not a content root: {root}")
        with self._lock:
            existing = self.fetches.get(root)
            if existing is not None:
                return existing
            f = Fetch(self, root)
            self.fetches[root] = f
        self._drive(f)
        return f

    def local(self, root: str) -> bytes | None:
        """The complete artifact when the store holds it (the space's read seam)."""
        m = self.store.manifest(root)
        if m is None or len(self.store.have(root)) < int(m["pieces"]):
            return None
        return self.store.read_all(root)

    def ensure(self, root: str) -> None:
        """Starts or continues acquiring a root (the space's read seam)."""
        self.fetch(root)

    def _drive(self, f: Fetch) -> None:
        if f.done.is_set():
            self.fetches.pop(f.root, None)
            return
        if f.manifest is None:
            m = self.manifest_of(f.root)
            if m is None:
                now = time.monotonic()
                if now - f.manifest_asked_at >= 2.0:
                    f.manifest_asked_at = now
                    for h in self.holdings(f.root):
                        if h["holder"] != self.self_id:
                            self.send(h["holder"], manifest_want(f.root))
                return
            if m.get("table") is None:
                f.failure = "the manifest's table is a block; this client keeps tables inline"
                f._note(f.failure)
                f.done.set()
                return
            if m.get("sealing") != SEALING_NONE:
                f.failure = "sealed root; this client holds no content key"
                f._note(f.failure)
                f.done.set()
                return
            f.start(m, m["table"])
            if f.done.is_set():
                self.fetches.pop(f.root, None)
            return
        f.tick()
        if f.done.is_set():
            self.fetches.pop(f.root, None)

    def tick(self) -> None:
        for f in list(self.fetches.values()):
            self._drive(f)
        for root in list(self.holder_state):
            self._refresh_holding(root, force=False)

    # ---- holdings

    def _refresh_holding(self, root: str, force: bool) -> None:
        m = self.store.manifest(root)
        if m is None:
            return
        have = self.store.have(root)
        if not have:
            return
        state = self.holder_state.setdefault(root, {"count": -1, "written_at": 0.0, "entry_id": None})
        now = time.monotonic()
        complete = len(have) >= int(m["pieces"])
        changed = state["count"] != len(have)
        due = force or state["entry_id"] is None or (changed and (complete or now - state["written_at"] >= 10
                                                                    or len(have) - state["count"] >= 32))
        if due:
            via = [self.peer.seed_peer] if self.peer.relay_for(self.self_id) is not None else None
            h = holding(root, self.self_id, have, int(m["pieces"]), via)
            state["entry_id"] = self._write(HOLDING_TYPE, h, self.HOLDING_LEASE, holding_tags(h))
            state.update(count=len(have), written_at=now)
        elif now - state["written_at"] >= 50 and state["entry_id"]:
            try:
                self.peer.renew_entry(self.space.name, state["entry_id"], 120_000, None)
                state["written_at"] = now
            except Exception:
                state["entry_id"] = None

    def _on_piece_verified(self, f: Fetch) -> None:
        self._refresh_holding(f.root, force=False)

    def _on_complete(self, f: Fetch) -> None:
        self.store.pin(f.root)
        self._refresh_holding(f.root, force=True)
        self.store.flush()

    # ---- the holder side

    def _on_frame(self, sender: str, payload: bytes) -> None:
        try:
            msg = cbor.loads(payload)
        except Exception:
            return
        if not isinstance(msg, dict):
            return
        t = msg.get("t")
        if t == PIECE_WANT:
            self._serve(sender, msg)
        elif t == PIECE:
            f = self.fetches.get(msg.get("root"))
            if f is not None:
                f.on_piece(sender, msg)
                if f.done.is_set():
                    self.fetches.pop(f.root, None)
        elif t == REJECT:
            f = self.fetches.get(msg.get("root"))
            if f is not None:
                f.on_reject(sender, msg)
        elif t == MANIFEST_WANT:
            m = self.store.manifest(msg.get("root"))
            if m is not None:
                self.send(sender, manifest_reply(m["root"], cbor.dumps(m)))
        elif t == MANIFEST:
            f = self.fetches.get(msg.get("root"))
            if f is None or f.manifest is not None:
                return
            try:
                m = cbor.loads(msg.get("record") or b"")
            except Exception:
                return
            if isinstance(m, dict) and m.get("root") == f.root and manifest_violation(m) is None:
                self.store.open(m)
                self._drive(f)

    def _serve(self, sender: str, want: dict) -> None:
        root = want.get("root")
        m = self.store.manifest(root)
        if m is None:
            return self._reject(sender, want, REASON_UNKNOWN_ROOT)
        if self.may_serve is not None and not self.may_serve(sender, m):
            return self._reject(sender, want, REASON_POLICY)
        if m.get("sealing") != SEALING_NONE:
            return self._reject(sender, want, REASON_POLICY)
        length = int(want.get("length", 0))
        if length <= 0 or length > MAX_PIECE_SIZE:
            return self._reject(sender, want, REASON_UNKNOWN_ROOT)
        data = self.store.read(root, int(want.get("index", -1)), int(want.get("offset", 0)), length)
        if data is None:
            return self._reject(sender, want, REASON_NOT_HELD)
        self.bytes_served += len(data)
        self.send(sender, piece(root, want["index"], want["offset"], data, want["req"]))

    def _reject(self, sender: str, want: dict, reason: int) -> None:
        self.wants_refused += 1
        self.send(sender, reject(want.get("root"), int(want.get("index", -1)), reason))

    def _write(self, type_name: str, value: dict, lease, tags: dict) -> str:
        """A reserved record (``<fqcn>#v1``) written in Java field order, never escalated."""
        return self.peer.write_entry(self.space.name, type_name, value, agent_name=self.space.agent_name,
                                     lease_millis=duration_millis(lease), agent=self.space.agent, tags=tags)

    def stats(self) -> dict:
        return {"fetchesActive": len(self.fetches), "rootsHeld": len(self.store.roots()),
                "bytesServed": self.bytes_served, "wantsRefused": self.wants_refused,
                "piecesStruck": self.pieces_struck}


