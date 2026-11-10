# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The tree exchange over the content swarm (srad/agentspaces-pdt.md §3.5,
§10.2; PD-X-01 to PD-X-08, PD-P-01 to PD-P-03, PD-S-06): tags 8 to 11 inside
``aspace:cap/content-swarm`` frames.

- ``NODE_WANT`` 8 ``{t, req, cids}`` (1 to 256 CIDs); ``NODES`` 9 ``{t, req,
  nodes, sealed, epoch, missing}`` with exactly one of ``nodes`` and ``sealed``
  present and at most 4 MiB of node bytes; ``TREE_WANT`` 10 ``{t, req, root,
  haves, budget, sketch}`` with at most 64 haves and a budget in (0, 64 MiB];
  ``TREE_END`` 11 ``{t, req, frontier, reason}`` with at most 1,024 frontier
  CIDs and reasons 1 done, 2 budget, 3 haves not held, 4 walk cap. ``REJECT``
  (tag 5) refuses a tree request with ``index`` -1.
- The holder answers a ``TREE_WANT`` breadth first, pruning every subtree it
  finds under a ``haves`` root it holds; when it holds none of the haves it
  sends two levels and closes with reason 3.
- The fetcher asks ``NODE_WANT`` for the root, then one ``TREE_WANT`` per child
  of the root (or one for the root when it has at most one child) across the
  top two sources, and sends the frontier as ``NODE_WANT`` batches. Every node
  verifies against a CID the fetcher asked for or reached through a verified
  parent; an unsolicited answer is dropped; a node that matches nothing strikes
  its sender.
- In ``group-key`` mode a holder seals the node list under the write epoch
  with AES-256-GCM and the AAD ``aspace:pdt|<recipient>|<req>``; the sealed
  bytes are ``nonce || ciphertext || tag`` as the group key seals.
- The advertisement carries ``trees = "1"``; tags 8 to 11 go only to a member
  whose newest content-swarm advertisement carries it.

PDT 2 phase 7 (srad/agentspaces-pdt2.md §6.10, P2-C-01, P2-F-05) brings this port to feature level 2: it reads
every message of tags 8 to 12 strictly under its annex I schema (``read_message``), the level-2 schemas of 6.10.4
included, and advertises ``pdt = "2"``. A fetch applies the ``NODES.deltas`` of a ``TREE_WANT`` answer (P2-Z-01) by
the rules of Java's ``TreeFetchSession``; the holder answers ``CHALLENGE`` (tag 12, P2-S-07) and sketch rounds
(``TREE_WANT`` with root ``""``, P2-K-02) through ``sync.SketchServer``, and ``reconcile_held`` runs the asker's side.
A level-2 form goes only to a member whose newest advertisement carries ``pdt`` as canonical decimal text of 2 or
above; a sketch from a member read at level 1 gets the level-1 refusal, ``REJECT`` reason 3. This holder keeps no
delta frames, so it never sends ``NODES.deltas``."""

from __future__ import annotations

import hashlib
import os
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .. import cbor
from ..capabilities import content as swarm
from . import cids, dcz, nodes, sync

NODE_WANT, NODES, TREE_WANT, TREE_END, CHALLENGE = 8, 9, 10, 11, 12
TREE_INDEX = -1
END_DONE, END_BUDGET, END_HAVES_NOT_HELD, END_WALK_CAP, END_SKETCH = 1, 2, 3, 4, 5
MAX_PICKS = 16
MAX_WANT_CIDS = 256
MAX_NODES_BYTES = 4 * 1024 * 1024
MAX_HAVES = 64
MAX_TREE_BUDGET = 64 * 1024 * 1024
MAX_FRONTIER = 1024
MAX_WALK_NODES = 100_000
NODE_FRAMING_BYTES = 5
MESSAGE_FRAMING_BYTES = 33
SEALING_AAD_PREFIX = "aspace:pdt|"
TREES_PARAMETER = "trees"
TREES_VERSION = "1"
#: The PDT feature level on the content-swarm advertisement (P2-F-05): this port reads every level-2 schema of 6.10.4.
PDT_PARAMETER = "pdt"
PDT_LEVEL = "2"
HINT_RECORDLESS = "wire.recordless"


# ------------------------------------------------------------------ messages

def node_want(req: int, cid_list: list[str]) -> dict:
    return {"t": NODE_WANT, "req": int(req), "cids": list(cid_list)}


def nodes_message(req: int, node_list: list[bytes] | None, sealed: bytes | None, epoch: int | None,
                  missing: list[str] | None) -> dict:
    return {"t": NODES, "req": int(req), "nodes": node_list, "sealed": sealed, "epoch": epoch, "missing": missing}


def tree_want(req: int, root: str, haves: list[str] | None, budget: int, sketch: bytes | None = None) -> dict:
    return {"t": TREE_WANT, "req": int(req), "root": root, "haves": haves, "budget": int(budget), "sketch": sketch}


def tree_end(req: int, frontier: list[str], reason: int, sketch: bytes | None = None) -> dict:
    """A ``TREE_END``; ``sketch``, the reply of a reconciliation round, is appended and left off when None (rule 13)."""
    msg = {"t": TREE_END, "req": int(req), "frontier": list(frontier), "reason": int(reason)}
    if sketch is not None:
        msg["sketch"] = sketch
    return msg


# The annex I schema of each tree message (PDT 2 phase 7, §6.10.4): its fields in Java's order, then the fields a
# later level appends, which leave the wire when null (P2-F-07).
_SCHEMAS = {NODE_WANT: (("t", "req", "cids"), ()),
            NODES: (("t", "req", "nodes", "sealed", "epoch", "missing"), ("deltas",)),
            TREE_WANT: (("t", "req", "root", "haves", "budget", "sketch"), ()),
            TREE_END: (("t", "req", "frontier", "reason"), ("sketch",)),
            CHALLENGE: (("t", "req", "root", "picks"), ())}
_INT, _LONG = 1 << 31, 1 << 63


def _int(value, bound=_INT) -> bool:
    return type(value) is int and -bound <= value < bound


def _texts(value, nullable: bool) -> bool:
    return (nullable and value is None) or (isinstance(value, list) and all(isinstance(v, str) for v in value))


def _fields(value: dict, fixed: tuple, appended: tuple) -> bool:
    return list(value) == list(fixed) + [f for f in appended if f in value] \
        and all(value[f] is not None for f in appended if f in value)


def _typed(msg: dict) -> bool:
    t = msg["t"]
    if not _int(msg["req"]):
        return False
    if t == NODE_WANT:
        return _texts(msg["cids"], False)
    if t == NODES:
        return ((msg["nodes"] is None or (isinstance(msg["nodes"], list) and all(isinstance(n, bytes) for n in msg["nodes"])))
                and (msg["sealed"] is None or isinstance(msg["sealed"], bytes))
                and (msg["epoch"] is None or _int(msg["epoch"], _LONG)) and _texts(msg["missing"], True)
                and ("deltas" not in msg or (isinstance(msg["deltas"], list) and all(
                    isinstance(d, dict) and _fields(d, ("cid", "base", "dcz"), ()) and isinstance(d["cid"], str)
                    and isinstance(d["base"], str) and isinstance(d["dcz"], bytes) for d in msg["deltas"]))))
    if t == TREE_WANT:
        return (isinstance(msg["root"], str) and _texts(msg["haves"], True) and _int(msg["budget"], _LONG)
                and (msg["sketch"] is None or isinstance(msg["sketch"], bytes)))
    if t == TREE_END:
        return _texts(msg["frontier"], True) and _int(msg["reason"]) and ("sketch" not in msg or isinstance(msg["sketch"], bytes))
    return isinstance(msg["root"], str) and isinstance(msg["picks"], list) and all(
        isinstance(p, dict) and _fields(p, ("cid",), ("offset", "length")) and isinstance(p["cid"], str)
        and ("offset" not in p or _int(p["offset"], _LONG)) and ("length" not in p or _int(p["length"]))
        for p in msg["picks"])


def fits_schema(msg) -> bool:
    """Whether a decoded tree message holds exactly its schema's fields, in order and of their types (§9.1)."""
    if not isinstance(msg, dict) or msg.get("t") not in _SCHEMAS or type(msg.get("t")) is not int:
        return False
    fixed, appended = _SCHEMAS[msg["t"]]
    return _fields(msg, fixed, appended) and _typed(msg)


def read_message(raw: bytes) -> dict | None:
    """A tree message read strictly (PDT 2 phase 7, P2-F-05): the wire encoding of one map that fits its schema, or
    None. ``cbor.loads`` reads only the wire encoding, so the message re-encodes to exactly these bytes."""
    try:
        msg = cbor.loads(raw)
    except ValueError:
        return None
    return msg if fits_schema(msg) else None


def _cid_list(value, bound: int, what: str) -> str | None:
    if not isinstance(value, list):
        return f"{what} is not a list"
    if len(value) > bound:
        return f"{what} names more than {bound} cids"
    for c in value:
        if not cids.is_cid(c):
            return f"{what} carries a malformed cid"
    return None


def violation(msg: dict) -> str | None:
    """The first broken bound of a tree message (PD-X-02), or None."""
    t = msg.get("t")
    if not isinstance(msg.get("req"), int):
        return "req is not an integer"
    if t == NODE_WANT:
        if not isinstance(msg.get("cids"), list) or not msg["cids"]:
            return "a NODE_WANT names at least one cid"
        return _cid_list(msg["cids"], MAX_WANT_CIDS, "cids")
    if t == NODES:
        plain, sealed = msg.get("nodes"), msg.get("sealed")
        if (plain is None) == (sealed is None):
            return "a NODES carries exactly one of nodes and sealed"
        if (sealed is None) != (msg.get("epoch") is None):
            return "epoch is present exactly when sealed is"
        if sealed is not None and msg.get("deltas") is not None:
            # PDT 2 phase 4 measures (srad/agentspaces-pdt2.md §10.14): frames travel in plaintext answers only
            return "a sealed NODES carries no deltas"
        if plain is not None:
            if not isinstance(plain, list) or any(not isinstance(n, bytes) for n in plain):
                return "nodes is not a list of byte strings"
            size = sum(len(n) for n in plain)
            if size > MAX_NODES_BYTES:
                return f"a NODES carries at most {MAX_NODES_BYTES} bytes of nodes"
        elif not isinstance(sealed, bytes) or len(sealed) > MAX_NODES_BYTES:
            return f"a NODES carries at most {MAX_NODES_BYTES} sealed bytes"
        deltas = msg.get("deltas")
        if deltas is not None:
            # PDT 2 phase 7, P2-Z-01: at most 256 deltas, each a chunk, a base, and a frame, in the 4 MiB bound
            if len(deltas) > MAX_WANT_CIDS:
                return f"a NODES carries at most {MAX_WANT_CIDS} deltas, got {len(deltas)}"
            if any(not cids.is_cid(d.get("cid")) or not cids.is_cid(d.get("base")) or not isinstance(d.get("dcz"), bytes)
                   for d in deltas):
                return "deltas holds an entry without a CID, a base CID, and a frame"
            if size + sum(len(d["dcz"]) for d in deltas) > MAX_NODES_BYTES:
                return f"a NODES carries at most {MAX_NODES_BYTES} bytes of nodes and deltas"
        if msg.get("missing") is not None:
            return _cid_list(msg["missing"], MAX_WANT_CIDS, "missing")
        return None
    if t == TREE_WANT:
        if msg.get("root") == "" and msg.get("sketch") is not None:
            # PDT 2 phase 7, P2-K-02 (rule 12): a reconciliation round names no root and no haves
            if msg.get("haves"):
                return "a sketch TREE_WANT names no haves"
            budget = msg.get("budget")
            return None if isinstance(budget, int) and 0 < budget <= MAX_TREE_BUDGET \
                else f"budget is not in (0, {MAX_TREE_BUDGET}]"
        if not cids.is_cid(msg.get("root")):
            return "root is not a cid"
        if msg.get("haves") is not None:
            bad = _cid_list(msg["haves"], MAX_HAVES, "haves")
            if bad:
                return bad
        budget = msg.get("budget")
        if not isinstance(budget, int) or budget <= 0 or budget > MAX_TREE_BUDGET:
            return f"budget is not in (0, {MAX_TREE_BUDGET}]"
        return None
    if t == TREE_END:
        bad = _cid_list(msg.get("frontier"), MAX_FRONTIER, "frontier")
        if bad:
            return bad
        if msg.get("reason") not in (END_DONE, END_BUDGET, END_HAVES_NOT_HELD, END_WALK_CAP, END_SKETCH):
            return "unknown TREE_END reason"
        if (msg["reason"] == END_SKETCH) != (msg.get("sketch") is not None):
            return f"a TREE_END carries a sketch exactly when its reason is {END_SKETCH}"
        if msg["reason"] == END_SKETCH and msg["frontier"]:
            return "a sketch TREE_END carries an empty frontier"
        return None
    if t == CHALLENGE:
        # PDT 2 phase 7, P2-S-07: 1 to 16 picks; a node pick names a CID, a chunk-group pick a BLAKE3 identity
        if not cids.is_cid(msg.get("root")):
            return "root is not a cid"
        picks = msg.get("picks") or []
        if not picks:
            return "a CHALLENGE names at least one pick"
        if len(picks) > MAX_PICKS:
            return f"a CHALLENGE names at most {MAX_PICKS} picks, got {len(picks)}"
        for pick in picks:
            if ("offset" in pick) != ("length" in pick):
                return "a pick carries both or neither of offset and length"
            if not (cids.is_cid(pick.get("cid")) if "offset" not in pick else cids.is_identity(pick.get("cid"))):
                return ("picks holds a value that is not a CID: a node pick names a sha2-256 CID and a chunk-group"
                        " pick a BLAKE3 identity")
            if pick.get("offset", 0) < 0:
                return "a pick's offset is negative"
            if "length" in pick and not 0 < pick["length"] <= MAX_NODES_BYTES:
                return f"a pick's length is not in (0, {MAX_NODES_BYTES}]"
        return None
    return f"not a tree message: tag {t}"


# ------------------------------------------------------------------ sealing

def sealing_aad(recipient: str, req: int) -> bytes:
    return f"{SEALING_AAD_PREFIX}{recipient}|{req}".encode("utf-8")


def seal_nodes(key: bytes, node_list: list[bytes], aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, cbor.dumps(list(node_list)), aad)


def open_nodes(keys: list[bytes], sealed: bytes, aad: bytes) -> list[bytes] | None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    if len(sealed) < 12 + 16:
        return None
    for key in keys:
        try:
            plain = AESGCM(key).decrypt(sealed[:12], sealed[12:], aad)
        except InvalidTag:
            continue
        try:
            value = cbor.loads(plain)
        except ValueError:
            return None
        if isinstance(value, list) and all(isinstance(n, bytes) for n in value):
            return value
        return None
    return None


# ------------------------------------------------------------------ the fetch

#: The first bench of a source that answered ``missing`` for a CID, in seconds; each later such answer doubles it up
#: to ``MISSING_BENCH_MAX_S`` (swarm retries, ROBUSTNESS.md §10.3 B6 and E4).
MISSING_BENCH_S = 1.0
MISSING_BENCH_MAX_S = 16.0


@dataclass
class _Source:
    peer: str
    via: list | None = None
    window: int = 4
    in_flight: int = 0
    srtt_ms: float = -1.0
    timeouts: int = 0
    strikes: int = 0
    dropped_until: float = 0.0
    bytes_verified: int = 0
    #: CIDs this source answered ``missing`` for, each with ``[bench end, answers]``: a holder that lacked a node may
    #: hold it later, so the fetch asks it again once the bench ends, with a random spread (swarm retries).
    missing: dict = field(default_factory=dict)
    hops: int = 0
    #: A frame of this source did not open, so the fetch opens none of its later frames (P2-Q-SEC-05).
    frames_refused: bool = False

    def lacks(self, cid: str, now: float) -> bool:
        bench = self.missing.get(cid)
        return bench is not None and now < bench[0]

    def lack(self, cid: str, now: float) -> None:
        bench = self.missing.setdefault(cid, [0.0, 0])
        if now < bench[0]:
            return
        bench[1] += 1
        wait = min(MISSING_BENCH_MAX_S, MISSING_BENCH_S * 2 ** (bench[1] - 1))
        bench[0] = now + wait + random.uniform(0, wait / 2)


@dataclass
class _Request:
    req: int
    source: _Source
    kind: str                       # "nodes" or "tree"
    cids: list[str]                 # asked (nodes) or [subtree] (tree)
    sent_at: float
    depth: int                      # the dependency chain length this request sits at
    matched: set = field(default_factory=set)
    pointer: int = 0
    delivered: int = 0


class TreeFetch:
    """One tree fetch (or a bare batch of nodes when ``bare``): driven from ``Trees.tick``
    and from the frames that arrive; ``wait`` blocks the caller."""

    MIN_TIMEOUT_S = 10.0
    TIMEOUTS_BEFORE_DROP = 3
    DROP_S = 60.0

    def __init__(self, trees: "Trees", root: str | None, haves: list[str], prefer: list[str],
                 timeout: float | None, bare: list[str] | None = None, budget: int = MAX_TREE_BUDGET):
        self.trees = trees
        self.store = trees.store
        self.root = root
        self.haves = [h for h in haves if h != root][:MAX_HAVES]
        self.prefer = list(prefer)
        self.timeout = timeout
        self.bare = bare
        self.budget = budget
        self.sources: dict[str, _Source] = {}
        self.outstanding: dict[int, _Request] = {}
        self.frontier: deque = deque()
        self.frontier_set: set[str] = set()
        self.frontier_depth: dict[str, int] = {}
        self.asked: set[str] = set()
        self.expected: dict[bytes, str] = {}       # digest -> cid the fetcher may accept
        self.verified: set[str] = set()
        self.under_walk: set[str] = set()            # cids discovered inside a subtree walk still in flight
        self.planned = False
        self.done = threading.Event()
        self.failure: str | None = None
        self.bytes_received = 0
        self.requests = 0
        self.round_trips = 0
        self.duplicates = 0
        self.foreign_refused = 0
        self.started = time.monotonic()
        self.sources_read_at = 0.0
        self.trace: list[str] = []
        self._lock = threading.RLock()
        self._scheduling = False
        self._reschedule = False
        if bare is not None:
            for c in bare:
                self._expect(c)
                self._queue(c, 0)
        else:
            self._expect(root)

    # ---- the handle

    @property
    def complete(self) -> bool:
        return self.done.is_set() and self.failure is None

    def wait(self, timeout_s: float | None = None) -> bool:
        self.done.wait(timeout_s)
        return self.complete

    def progress(self) -> dict:
        with self._lock:
            return {"bytesReceived": self.bytes_received, "requests": self.requests, "roundTrips": self.round_trips,
                    "bytesBySource": {p: s.bytes_verified for p, s in self.sources.items() if s.bytes_verified},
                    "nodesVerified": len(self.verified), "duplicates": self.duplicates,
                    "sourcesActive": sum(1 for s in self.sources.values() if s.in_flight > 0),
                    "foreignRefused": self.foreign_refused}

    def cancel(self) -> None:
        with self._lock:
            if not self.done.is_set():
                self._finish("cancelled")

    def _note(self, line: str) -> None:
        self.trace.append(line)
        del self.trace[:-256]

    # ---- bookkeeping

    def _expect(self, cid: str) -> None:
        self.expected[cids.parse(cid).digest] = cid

    def _queue(self, cid: str, depth: int) -> None:
        if cid in self.frontier_set or self.store.has(cid):
            return
        self.frontier.append(cid)
        self.frontier_set.add(cid)
        self.frontier_depth[cid] = depth

    def _is_complete(self) -> bool:
        if self.bare is not None:
            return all(self.store.has(c) for c in self.bare)
        return self.store.complete(self.root)

    def _finish(self, failure: str | None = None) -> None:
        self.failure = failure
        self._note(f"{'failed: ' + failure if failure else 'complete'}: {len(self.verified)} nodes, "
                   f"{self.bytes_received} bytes in {int((time.monotonic() - self.started) * 1000)} ms, "
                   f"{self.requests} requests, {self.round_trips} round trips")
        for r in list(self.outstanding.values()):
            r.source.in_flight = max(0, r.source.in_flight - 1)
        self.outstanding.clear()
        self.done.set()
        self.trees._on_fetch_done(self)

    # ---- driving

    def start(self) -> None:
        with self._lock:
            if self._is_complete():
                self._finish()
                return
            self._refresh_sources()
            self._schedule()

    def tick(self) -> None:
        with self._lock:
            if self.done.is_set():
                return
            now = time.monotonic()
            self._time_out(now)
            if now - self.sources_read_at >= 2.0:
                self._refresh_sources()
            self._schedule()
            if self.done.is_set():
                return
            if self.timeout is not None and now - self.started > self.timeout and self._stalled():
                self._finish(f"no reachable holder answered for {self.root or self.bare} within {self.timeout:.1f} s")

    def _stalled(self) -> bool:
        if self.outstanding:
            return False
        now = time.monotonic()
        usable = [s for s in self.sources.values() if s.dropped_until <= now]
        if not usable:
            return True
        return all(all(s.lacks(c, now) for s in usable) for c in self.frontier_set) if self.frontier_set else True

    def _refresh_sources(self) -> None:
        self.sources_read_at = time.monotonic()
        candidates: list[tuple[str, list | None]] = []
        if self.bare is None:
            for h in self.trees.holders(self.root):
                candidates.append((h["holder"], h.get("via")))
            for have in self.haves:
                for h in self.trees.holders(have):
                    candidates.append((h["holder"], h.get("via")))
        else:
            for c in self.bare:
                for h in self.trees.holders(c):
                    candidates.append((h["holder"], h.get("via")))
            for root in self.trees.followed_roots():
                for h in self.trees.holders(root):
                    candidates.append((h["holder"], h.get("via")))
        for p in self.prefer:
            candidates.insert(0, (p, None))
        me = self.trees.self_id
        for peer, via in candidates:
            if peer == me or peer in self.sources:
                continue
            if not self.trees.advertises_trees(peer):
                continue
            if len(self.sources) >= self.trees.max_sessions:
                break
            self.sources[peer] = _Source(peer, [v for v in (via or []) if isinstance(v, str)] or None,
                                         hops=self.trees.hops_to(peer))
            self._note(f"source {peer[:10]}")
        # the preferred sources rank first
        for i, p in enumerate(self.prefer):
            if p in self.sources:
                self.sources[p].hops = -1

    def _time_out(self, now: float) -> None:
        for req, r in list(self.outstanding.items()):
            limit = max(self.MIN_TIMEOUT_S, 8 * r.source.srtt_ms / 1000 if r.source.srtt_ms > 0 else 0)
            if now - r.sent_at <= limit:
                continue
            self.outstanding.pop(req)
            s = r.source
            s.in_flight = max(0, s.in_flight - 1)
            s.window = max(1, s.window // 2)
            s.timeouts += 1
            self._release(r)
            if s.timeouts >= self.TIMEOUTS_BEFORE_DROP:
                s.dropped_until = now + self.DROP_S
                s.timeouts = 0
                self._note(f"source {s.peer[:10]} timed out {self.TIMEOUTS_BEFORE_DROP} times; dropped for 60 s")

    def _release(self, r: _Request) -> None:
        """Puts what a request did not deliver back on the frontier."""
        if r.kind == "nodes":
            for c in r.cids:
                if c not in r.matched:
                    self.asked.discard(c)
                    self._queue(c, r.depth)
        else:
            subtree = r.cids[0]
            self.asked.discard(subtree)
            if r.delivered == 0:
                self._queue(subtree, r.depth)
            else:
                # a partially delivered walk is not walked again: the rest goes as NODE_WANT batches (PD-X-06)
                for c in self.store.missing(subtree):
                    self._queue(c, r.depth + 1)
            for c in list(self.under_walk):
                self.under_walk.discard(c)
                if not self.store.has(c):
                    self._queue(c, r.depth + 1)

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

    def _ranked(self, now: float) -> list[_Source]:
        return sorted((s for s in self.sources.values() if s.dropped_until <= now),
                      key=lambda s: (s.hops, s.strikes, -s.bytes_verified, s.srtt_ms if s.srtt_ms > 0 else 1e9))

    def _schedule_once(self) -> None:
        if self.done.is_set():
            return
        if not self.outstanding and not self.frontier and self._is_complete():
            self._finish()
            return
        now = time.monotonic()
        ranked = self._ranked(now)
        if not ranked:
            return
        if self.bare is None:
            if not self.store.has(self.root):
                if self.root not in self.asked:
                    asked = next((s for s in ranked if not s.lacks(self.root, now)), None)
                    if asked is not None:
                        self._send_node_want(asked, [self.root], 0)
                return
            if not self.planned:
                self._plan_subtrees(ranked)
                if self._reschedule:
                    return
        # the frontier as NODE_WANT batches across every usable source
        idle = [s for s in ranked if s.in_flight < s.window]
        i = 0
        while self.frontier and idle:
            s = idle[i % len(idle)]
            batch, depth = [], 0
            skipped = []
            while self.frontier and len(batch) < MAX_WANT_CIDS:
                c = self.frontier.popleft()
                self.frontier_set.discard(c)
                if self.store.has(c) or c in self.asked:
                    continue
                if s.lacks(c, now):
                    skipped.append(c)
                    continue
                batch.append(c)
                depth = max(depth, self.frontier_depth.get(c, 0))
            for c in skipped:
                self._queue(c, self.frontier_depth.get(c, 0))
            if not batch:
                if skipped and len(idle) > 1:
                    idle.pop(i % len(idle))
                    continue
                break
            self._send_node_want(s, batch, depth)
            if s.in_flight >= s.window:
                idle.remove(s)
            else:
                i += 1
            if self._reschedule or self.done.is_set():
                return
        if not self.outstanding and not self.frontier and self._is_complete():
            self._finish()

    def _plan_subtrees(self, ranked: list[_Source]) -> None:
        self.planned = True
        data = self.store.get(self.root)
        children = self.store.links(self.root, data) if data is not None else []
        self.verified.add(self.root)
        for c in children:
            self._expect(c)
        wanted = [c for c in children if not self.store.complete(c)]
        if len(children) <= 1:
            wanted = [self.root] if not self.store.complete(self.root) else []
        top = ranked[:2]
        for i, subtree in enumerate(wanted):
            # an answer that arrives during the send (an in-process holder) only marks a reschedule, so the plan
            # still asks for every wanted subtree; a root held before the fetch has no frontier to fall back on
            # (PDT 2 phase 7: a push that stored the root and part of the tree)
            if self.done.is_set():
                return
            self._send_tree_want(top[i % len(top)], subtree, 1 if subtree != self.root else 0)

    def _send_node_want(self, s: _Source, batch: list[str], depth: int) -> None:
        req = self.trees.next_req()
        self.outstanding[req] = _Request(req, s, "nodes", list(batch), time.monotonic(), depth)
        self.asked.update(batch)
        s.in_flight += 1
        self.requests += 1
        self.trees.register(req, self)
        self.trees.send(s.peer, node_want(req, batch), s.via)

    def _send_tree_want(self, s: _Source, subtree: str, depth: int) -> None:
        req = self.trees.next_req()
        self.outstanding[req] = _Request(req, s, "tree", [subtree], time.monotonic(), depth)
        self.asked.add(subtree)
        s.in_flight += 1
        self.requests += 1
        self.trees.register(req, self)
        haves = [h for h in self.haves if h != subtree] or None
        self.trees.send(s.peer, tree_want(req, subtree, haves, self.budget), s.via)

    # ---- answers

    def on_nodes(self, sender: str, msg: dict) -> None:
        with self._lock:
            if self.done.is_set():
                return
            r = self.outstanding.get(msg.get("req"))
            if r is None or r.source.peer != sender:
                return  # unsolicited: dropped (PD-X-04)
            s = r.source
            node_list = self.trees.open(sender, r.req, msg)
            if node_list is None:
                # unopenable (sealed under a key this peer lacks): released without a strike, and the
                # source backs off so the same answer is not asked for again on the next schedule
                self._note(f"a NODES from {sender[:10]} could not be opened; request released, source backed off")
                self.outstanding.pop(r.req)
                s.in_flight = max(0, s.in_flight - 1)
                s.dropped_until = time.monotonic() + self.DROP_S
                self.trees.nodes_unopenable += 1
                self._release(r)
                self._schedule()
                return
            rtt = (time.monotonic() - r.sent_at) * 1000
            s.srtt_ms = rtt if s.srtt_ms < 0 else (s.srtt_ms * 7 + rtt) / 8
            s.timeouts = 0
            for data in node_list:
                cid = self._match(r, data)
                if cid is None:
                    return self._strike(r, f"a node from {sender[:10]} matched nothing it was asked for")
                self._accept(r, cid, data)
            if r.kind == "tree" and msg.get("deltas") is not None:
                # PDT 2 phase 7, P2-Z-01: a level-2 holder sends a chunk as a frame over a base under the haves
                for delta in msg["deltas"]:
                    struck = self._accept_delta(r, delta)
                    if struck:
                        return self._strike(r, struck)
            if r.kind == "nodes":
                missing = msg.get("missing")
                now = time.monotonic()
                if missing is not None:
                    for c in missing:
                        if c in r.cids and c not in r.matched:
                            s.lack(c, now)
                            self.asked.discard(c)
                            self._queue(c, r.depth)
                if missing is not None or len(r.matched) >= len(r.cids):
                    self.outstanding.pop(r.req)
                    s.in_flight = max(0, s.in_flight - 1)
                    self.round_trips = max(self.round_trips, r.depth + 1)
                    for c in r.cids:
                        if c not in r.matched and not s.lacks(c, now):
                            self.asked.discard(c)
                            self._queue(c, r.depth)
                    if s.window < self.trees.max_window:
                        s.window += 1
            self._schedule()

    def _strike(self, r: _Request, why: str) -> None:
        s = r.source
        s.strikes += 1
        s.dropped_until = float("inf")
        self.trees.nodes_struck += 1
        self._note(f"{why}; struck")
        self.outstanding.pop(r.req, None)
        s.in_flight = max(0, s.in_flight - 1)
        self._release(r)
        self._schedule()

    def _accept_delta(self, r: _Request, delta: dict) -> str | None:
        """Applies one delta of a ``TREE_WANT`` answer as Java's ``TreeFetchSession.acceptDelta`` does; returns why
        its sender is struck, or None. A delta for a chunk no verified node links, or a frame that rebuilds bytes
        its CID does not name, strikes; a frame that does not open costs no strike, and the fetch then asks for the
        chunk whole and opens no later frame from that source (P2-Q-SEC-05); a delta over a base this store lacks
        asks for the chunk by ``NODE_WANT``. Only the verified chunk is stored, never the frame."""
        cid, base, frame = delta["cid"], delta["base"], delta["dcz"]
        digest = cids.parse(cid).digest
        if self.expected.get(digest) != cid:
            self.foreign_refused += 1
            return f"a delta from {r.source.peer[:10]} names {cid}, which no verified node links to"
        if self.store.has(cid) or cid in self.verified:
            self.bytes_received += len(frame)  # a duplicate delivery still costs its bytes
            return None
        chunks = cids.codec_of(cid) == cids.RAW and cids.codec_of(base) == cids.RAW
        if not chunks:
            self.trees.deltas_refused += 1
        held = self.store.get(base) if chunks and not r.source.frames_refused else None
        if held is None:
            self._note(f"a delta for {cid} over {base} is not applied here; asking for the chunk by NODE_WANT")
            self.asked.discard(cid)
            self._queue(cid, r.depth + 1)
            return None
        try:
            chunk = dcz.decode(held, frame)
        except dcz.DczRefused as e:
            self.trees.deltas_refused += 1
            r.source.frames_refused = True
            self._note(f"a delta for {cid} from {r.source.peer[:10]} refused ({e}); asking for it whole")
            self.asked.discard(cid)
            self._queue(cid, r.depth + 1)
            return None
        if not cids.verifies(cid, chunk):
            self.trees.deltas_refused += 1
            return f"a delta from {r.source.peer[:10]} rebuilds bytes that do not hash to {cid}"
        self.trees.deltas_applied += 1
        self._accept(r, cid, chunk, len(frame))
        return None

    def _match(self, r: _Request, data: bytes) -> str | None:
        digest = hashlib.sha256(data).digest()
        if r.kind == "nodes":
            # in asked order; a skipped CID counts as lacking at that source
            p = r.pointer
            while p < len(r.cids):
                candidate = r.cids[p]
                if cids.parse(candidate).digest == digest:
                    for skipped in r.cids[r.pointer:p]:
                        if skipped not in r.matched:
                            r.source.lack(skipped, time.monotonic())
                    r.pointer = p + 1
                    r.matched.add(candidate)
                    return candidate
                p += 1
            return self.expected.get(digest) if digest in self.expected and self.expected[digest] in r.cids else None
        cid = self.expected.get(digest)
        return cid

    def _accept(self, r: _Request, cid: str, data: bytes, wire_bytes: int | None = None) -> None:
        """Stores a verified node and follows its links; ``wire_bytes`` is what it cost to receive (a delta's frame)."""
        r.delivered += 1
        self.bytes_received += len(data) if wire_bytes is None else wire_bytes
        r.source.bytes_verified += len(data)
        if cid in self.verified:
            self.duplicates += 1
        self.verified.add(cid)
        self.asked.discard(cid)
        new = self.store.put_verified(cid, data)
        if new:
            self.trees.nodes_received += 1
        if self.bare is not None:
            return
        if r.kind == "tree":
            self.round_trips = max(self.round_trips, r.depth + 1)
        for link in self.store.links(cid, data):
            self._expect(link)
            if self.store.has(link):
                continue
            if r.kind == "tree":
                self.under_walk.add(link)
            else:
                self._queue(link, r.depth + 1)

    def on_tree_end(self, sender: str, msg: dict) -> None:
        with self._lock:
            if self.done.is_set():
                return
            r = self.outstanding.get(msg.get("req"))
            if r is None or r.source.peer != sender or r.kind != "tree":
                return
            self.outstanding.pop(r.req)
            s = r.source
            s.in_flight = max(0, s.in_flight - 1)
            s.timeouts = 0
            subtree = r.cids[0]
            self.asked.discard(subtree)
            for c in msg.get("frontier") or []:
                if cids.parse(c).digest not in self.expected:
                    self.foreign_refused += 1
                    s.strikes += 1
                    continue
                self._queue(c, r.depth + 1)
            # a CID a NODE_WANT already asks for (a delta that did not apply asked for its chunk) is not asked again
            in_flight = {c for x in self.outstanding.values() if x.kind == "nodes" for c in x.cids if c not in x.matched}
            for c in list(self.under_walk):
                self.under_walk.discard(c)
                if c not in in_flight:
                    self._queue(c, r.depth + 1)
            for c in self.store.missing(subtree):
                self._expect(c)
                if c not in in_flight:
                    self._queue(c, r.depth + 1)
            if s.window < self.trees.max_window:
                s.window += 1
            self._schedule()

    def on_reject(self, sender: str, msg: dict) -> None:
        with self._lock:
            s = self.sources.get(sender)
            if s is None:
                return
            root = msg.get("root")
            for req, r in list(self.outstanding.items()):
                if r.source is s and (r.cids[0] == root or root in r.cids):
                    self.outstanding.pop(req)
                    s.in_flight = max(0, s.in_flight - 1)
                    if msg.get("reason") in (swarm.REASON_OVER_BUDGET, swarm.REASON_POLICY):
                        s.dropped_until = time.monotonic() + self.DROP_S
                    else:
                        for c in r.cids:
                            s.lack(c, time.monotonic())
                    self._release(r)
                    break
            self._schedule()


# ------------------------------------------------------------------ the capability

class Trees:
    """The tree exchange attached to a ``Content`` swarm over a ``NodeStore``:
    the holder side (``NODE_WANT``, ``TREE_WANT``), the fetcher
    (``fetch_tree``, ``fetch_nodes``), tree-root holdings, the ``trees``
    parameter on the advertisement, and sealing in ``group-key`` mode when
    ``keys`` (epoch to 32-byte content key) are given."""

    HOLDING_LEASE = "2m"
    ADVERTISEMENT_TTL = "PT15M"

    def __init__(self, content, store, *, keys: dict[int, bytes] | None = None, write_epoch: int = 0,
                 advertisements: dict | None = None, advertise: bool = True, may_serve: Callable | None = None,
                 max_sessions: int = 16, max_window: int = 32, load_timeout: float = 10.0, seed: int | None = None,
                 walk_cap: int = MAX_WALK_NODES):
        self.content = content
        self.peer = content.peer
        self.store = store
        self.keys = dict(keys or {})
        self.write_epoch = write_epoch
        self.explicit_ads = advertisements
        self.may_serve = may_serve
        self.max_sessions = max_sessions
        self.max_window = max_window
        self.load_timeout = load_timeout
        self.walk_cap = walk_cap
        self.random = random.Random(seed)
        self.self_id = self.peer.identity.peer_id
        self.fetches: list[TreeFetch] = []
        self._by_req: dict[int, TreeFetch] = {}
        self._followed: set[str] = set()
        self.holder_state: dict[str, dict] = {}
        self.nodes_served = 0
        self.bytes_served = 0
        self.nodes_received = 0
        self.nodes_struck = 0
        self.nodes_unopenable = 0
        self.tree_requests_rejected = 0
        self.tree_messages_dropped = 0
        # PDT 2 phase 7: chunks rebuilt from a delta and deltas refused (P2-Z-01), challenges answered (P2-S-07)
        self.deltas_applied = 0
        self.deltas_refused = 0
        self.challenges_answered = 0
        # the roots this peer reconciles (P2-K-03): those it holds complete, unless a host gives another set
        self.reconcile_set: Callable[[], list[str]] = self.held_roots
        self.sketches = sync.SketchServer(lambda: self.reconcile_set())
        self.sessions: dict[int, sync.SketchSession] = {}
        self.advertised_at = 0.0
        self._lock = threading.Lock()
        content.trees = self
        if advertise and hasattr(self.peer, "publish_ad"):
            self.advertise()

    # ---- wiring

    def describe(self) -> dict:
        """This node's content-swarm CapabilityAdvertisement with ``trees = "1"`` (PD-X-01) and ``pdt = "2"``, the
        PDT feature level (PDT 2 phase 7, P2-F-05)."""
        from ..identity import instant_iso
        now_ms = self.peer._now_ms()
        return {"id": f"aspace://{self.peer.group}/cap/content-swarm/{self.self_id}",
                "issuer": self.self_id, "group": self.peer.group,
                "issued": instant_iso(now_ms - now_ms % 1000), "ttl": self.ADVERTISEMENT_TTL,
                "capabilityType": swarm.TYPE, "version": "0.1", "binding": "pipe",
                "parameters": cbor.canonical_map({
                    "pieceSizes": f"{swarm.MIN_PIECE_SIZE}-{swarm.MAX_PIECE_SIZE}",
                    "sealing": swarm.SEALING_GROUP_KEY if self.keys else swarm.SEALING_NONE,
                    "seedMode": "always", TREES_PARAMETER: TREES_VERSION, PDT_PARAMETER: PDT_LEVEL}),
                "costHints": {}}

    def advertise(self) -> None:
        self.peer.publish_ad("CapabilityAdvertisement", self.describe())
        self.advertised_at = time.monotonic()

    def _ad_parameters(self, peer_id: str) -> dict | None:
        if self.explicit_ads is not None:
            return self.explicit_ads.get(peer_id)
        now = self.peer._now_ms()
        best = None
        for e in self.peer.ads.values():
            ad = e.get("ad") or {}
            if (e.get("type") != "CapabilityAdvertisement" or e.get("issuer") != peer_id
                    or ad.get("capabilityType") != swarm.TYPE or e.get("expires", 0) <= now):
                continue
            if best is None or str(ad.get("issued")) > str(best.get("issued")):
                best = ad
        return None if best is None else (best.get("parameters") or {})

    def advertises_trees(self, peer_id: str) -> bool:
        params = self._ad_parameters(peer_id)
        return params is not None and params.get(TREES_PARAMETER) == TREES_VERSION

    def reads_level_two(self, peer_id: str) -> bool:
        """Whether a member's newest unexpired advertisement carries ``pdt`` as canonical decimal text of 2 or above,
        so it may receive a level-2 form (P2-F-05); a member without one is read at level 1."""
        level = (self._ad_parameters(peer_id) or {}).get(PDT_PARAMETER)
        return isinstance(level, str) and level.isascii() and level.isdigit() and (level == "0" or level[0] != "0") \
            and int(level) >= 2

    def held_roots(self) -> list[str]:
        """The tree roots this peer holds complete and publishes holdings for: its set for reconciliation (P2-K-03)."""
        return [root for root in list(self.holder_state) if self.store.complete(root)]

    def advertises_sealing(self, peer_id: str) -> bool:
        params = self._ad_parameters(peer_id)
        return params is not None and params.get("sealing") == swarm.SEALING_GROUP_KEY

    def group_seals(self) -> bool:
        """Whether any member's current advertisement says the group seals (PD-P-03)."""
        if self.explicit_ads is not None:
            return any((p or {}).get("sealing") == swarm.SEALING_GROUP_KEY for p in self.explicit_ads.values())
        now = self.peer._now_ms()
        for e in self.peer.ads.values():
            ad = e.get("ad") or {}
            if (e.get("type") == "CapabilityAdvertisement" and ad.get("capabilityType") == swarm.TYPE
                    and e.get("expires", 0) > now and (ad.get("parameters") or {}).get("sealing") == swarm.SEALING_GROUP_KEY):
                return True
        return False

    def next_req(self) -> int:
        return self.content.next_req()

    def send(self, to: str, msg: dict, via: list | None = None) -> None:
        self.content.send(to, msg, via)

    def hops_to(self, peer_id: str) -> int:
        return self.content.hops_to(peer_id)

    def register(self, req: int, fetch: TreeFetch) -> None:
        self._by_req[req] = fetch

    def holders(self, root: str) -> list[dict]:
        found = self.content.holdings(root)
        found.sort(key=lambda h: (not h.get("complete"), -int(h.get("count") or 0)))
        return found

    def followed_roots(self) -> list[str]:
        return list(self._followed)

    def follow(self, root: str) -> None:
        self._followed.add(root)

    # ---- fetching

    def fetch_tree(self, root: str, haves=(), prefer=(), timeout: float | None = None) -> TreeFetch:
        """Every node under ``root`` absent under the ``haves`` roots this store holds (PD-X-05, PD-X-06)."""
        cids.parse(root)
        self._followed.add(root)
        with self._lock:
            for f in self.fetches:
                if f.root == root and f.bare is None and not f.done.is_set():
                    return f
            f = TreeFetch(self, root, list(haves), list(prefer), timeout if timeout is not None else self.load_timeout)
            self.fetches.append(f)
        f.start()
        return f

    def fetch_nodes(self, cid_list: list[str], prefer=(), timeout: float | None = None) -> TreeFetch:
        """A bare batch: the nodes named, following no links."""
        for c in cid_list:
            cids.parse(c)
        with self._lock:
            f = TreeFetch(self, None, [], list(prefer), timeout if timeout is not None else self.load_timeout,
                          bare=list(cid_list))
            self.fetches.append(f)
        f.start()
        return f

    def load(self, cid: str, prefer=(), timeout: float | None = None) -> bytes:
        """The bytes of one node: the store, else a bare batch waited for (PD-V-06)."""
        data = self.store.get(cid)
        if data is not None:
            return data
        f = self.fetch_nodes([cid], prefer, timeout)
        f.wait(timeout if timeout is not None else self.load_timeout)
        data = self.store.get(cid)
        if data is None:
            raise nodes.NodeUnavailable(cid, list(f.sources), f"node {cid} could not be fetched: {f.failure or 'timed out'}"
                                        f" (sources tried: {list(f.sources)})")
        return data

    def _on_fetch_done(self, f: TreeFetch) -> None:
        with self._lock:
            if f in self.fetches:
                self.fetches.remove(f)
            for req in [r for r, x in self._by_req.items() if x is f]:
                self._by_req.pop(req, None)
        if f.bare is None and f.complete:
            self.hold(f.root)

    def active_fetches(self) -> list[TreeFetch]:
        return list(self.fetches)

    # ---- holdings (PD-S-06)

    def hold(self, root: str) -> int:
        """Pins a root and publishes a tree-root Holding (``have`` null, ``complete``, ``count``)."""
        count = self.store.pin(root)
        self._refresh_holding(root, force=True)
        return count

    def release(self, root: str) -> int:
        count = self.store.unpin(root)
        if count == 0:
            self.holder_state.pop(root, None)
        return count

    def _refresh_holding(self, root: str, force: bool) -> None:
        state = self.holder_state.setdefault(root, {"count": -1, "written_at": 0.0, "walked_at": 0.0, "entry_id": None})
        now = time.monotonic()
        if force or now - state["walked_at"] >= 10.0 or state["entry_id"] is None:
            count = self.store.held_under(root)
            complete = self.store.complete(root)
            state["walked_at"] = now
        else:
            count, complete = state["count"], state.get("complete", False)
        due = force or state["entry_id"] is None or (count != state["count"] and now - state["written_at"] >= 10)
        if due:
            via = [self.peer.seed_peer] if self.peer.relay_for(self.self_id) is not None else None
            h = {"v": swarm.VERSION, "root": root, "holder": self.self_id, "complete": bool(complete), "have": None,
                 "count": int(count), "via": via, "cost": None}
            state["entry_id"] = self.content._write(swarm.HOLDING_TYPE, h, self.HOLDING_LEASE, swarm.holding_tags(h))
            state.update(count=count, complete=complete, written_at=now)
        elif now - state["written_at"] >= 50 and state["entry_id"]:
            try:
                self.peer.renew_entry(self.content.space.name, state["entry_id"], 120_000, None)
                state["written_at"] = now
            except Exception:
                state["entry_id"] = None

    def tick(self) -> None:
        for f in list(self.fetches):
            f.tick()
        for req, session in list(self.sessions.items()):
            session.tick()
            if session.done:
                self.sessions.pop(req, None)
        for root in list(self.holder_state):
            if root in self.store.pinned():
                self._refresh_holding(root, force=False)
        if self.advertised_at and time.monotonic() - self.advertised_at >= 300:
            self.advertise()

    # ---- frames

    def on_frame(self, sender: str, msg: dict) -> None:
        t = msg.get("t")
        # PDT 2 phase 7 (§9.1): a tree message outside its schema is undecodable; dropped, counted, nobody struck,
        # and a NODES releases its request as a NODES that breaks a bound does
        undecodable = t in _SCHEMAS and not fits_schema(msg)
        if undecodable and t != NODES:
            self.tree_messages_dropped += 1
            return
        if t in (NODE_WANT, TREE_WANT, CHALLENGE):
            bad = violation(msg)
            if bad:
                self.tree_messages_dropped += 1
                return
            if t == NODE_WANT:
                self._serve_node_want(sender, msg)
            elif t == CHALLENGE:
                self._serve_challenge(sender, msg)
            elif msg["root"] == "":
                self._serve_sketch(sender, msg)
            else:
                self._serve_tree_want(sender, msg)
        elif t == TREE_END and msg.get("reason") == END_SKETCH:
            session = self.sessions.get(msg.get("req"))
            if violation(msg) or session is None or session.holder != sender:
                self.tree_messages_dropped += 1
                return
            session.on_reply(msg["sketch"])
            if session.done:
                self.sessions.pop(msg["req"], None)
        elif t in (NODES, TREE_END):
            bad = undecodable or violation(msg)
            if bad:
                self.tree_messages_dropped += 1
                f = self._by_req.get(msg["req"]) if type(msg.get("req")) is int else None
                if f is not None and t == NODES:
                    with f._lock:
                        r = f.outstanding.pop(msg.get("req"), None)
                        if r is not None and r.source.peer == sender:
                            r.source.in_flight = max(0, r.source.in_flight - 1)
                            f._release(r)
                return
            f = self._by_req.get(msg.get("req"))
            if f is None:
                return
            if t == NODES:
                f.on_nodes(sender, msg)
            else:
                f.on_tree_end(sender, msg)
        elif t == swarm.REJECT and msg.get("index") == TREE_INDEX and msg.get("root") == "":
            # a refusal of a sketch round names no request, so it ends this peer's oldest session with that holder
            session = next((x for x in self.sessions.values() if x.holder == sender), None)
            if session is not None:
                session.on_reject(msg.get("reason"))
                self.sessions = {r: x for r, x in self.sessions.items() if not x.done}
        elif t == swarm.REJECT and msg.get("index") == TREE_INDEX:
            for f in list(self.fetches):
                f.on_reject(sender, msg)

    def open(self, sender: str, req: int, msg: dict) -> list[bytes] | None:
        if msg.get("nodes") is not None:
            return msg["nodes"]
        if not self.keys:
            return None
        epoch = msg.get("epoch")
        keys = [self.keys[epoch]] if epoch in self.keys else list(self.keys.values())
        return open_nodes(keys, msg["sealed"], sealing_aad(self.self_id, req))

    def _reject(self, sender: str, root: str, reason: int) -> None:
        self.tree_requests_rejected += 1
        self.send(sender, swarm.reject(root, TREE_INDEX, reason))

    def _may_serve(self, sender: str, root: str) -> bool:
        if self.may_serve is not None:
            try:
                if not self.may_serve(sender, root):
                    return False
            except Exception:
                return False
        return True

    def _must_seal(self, sender: str) -> bool:
        return self.group_seals() or self.advertises_sealing(sender)

    def _send_nodes(self, to: str, req: int, batch: list[bytes], missing: list[str] | None) -> bool:
        if self.keys:
            key = self.keys.get(self.write_epoch)
            if key is None:
                return False
            sealed = seal_nodes(key, batch, sealing_aad(to, req))
            self.send(to, nodes_message(req, None, sealed, self.write_epoch, missing))
        else:
            self.send(to, nodes_message(req, batch, None, None, missing))
        self.nodes_served += len(batch)
        self.bytes_served += sum(len(n) for n in batch)
        return True

    def _packed(self, to: str, req: int, stream, missing: list[str] | None) -> bool:
        """Sends node bytes from ``stream`` packed under 4 MiB per message, ``missing`` on the last."""
        batch, size = [], MESSAGE_FRAMING_BYTES
        for data in stream:
            if batch and size + len(data) + NODE_FRAMING_BYTES > MAX_NODES_BYTES:
                if not self._send_nodes(to, req, batch, None):
                    return False
                batch, size = [], MESSAGE_FRAMING_BYTES
            batch.append(data)
            size += len(data) + NODE_FRAMING_BYTES
        return self._send_nodes(to, req, batch, missing)

    def _serve_node_want(self, sender: str, msg: dict) -> None:
        req, wanted = msg["req"], msg["cids"]
        for c in wanted:
            if not self._may_serve(sender, c):
                return self._reject(sender, wanted[0], swarm.REASON_POLICY)
        if not self.keys and self._must_seal(sender):
            return self._reject(sender, wanted[0], swarm.REASON_POLICY)
        if self.keys and self.keys.get(self.write_epoch) is None:
            return self._reject(sender, wanted[0], swarm.REASON_POLICY)
        found, missing = [], []
        for c in wanted:
            data = self.store.get(c)
            if data is None:
                missing.append(c)
            else:
                found.append(data)
        self._packed(sender, req, found, missing or None)

    def _serve_tree_want(self, sender: str, msg: dict) -> None:
        req, root = msg["req"], msg["root"]
        haves = [h for h in (msg.get("haves") or []) if h != root]
        if not self._may_serve(sender, root):
            return self._reject(sender, root, swarm.REASON_POLICY)
        if not self.keys and self._must_seal(sender):
            return self._reject(sender, root, swarm.REASON_POLICY)
        if self.keys and self.keys.get(self.write_epoch) is None:
            return self._reject(sender, root, swarm.REASON_POLICY)
        if not self.store.has(root):
            return self._reject(sender, root, swarm.REASON_NOT_HELD)
        budget = int(msg["budget"])
        prune: set[str] = set()
        held_haves = [h for h in dict.fromkeys(haves) if self.store.has(h)]
        walked = 0
        for h in held_haves:
            reach = self.store.reachable(h)
            walked += len(reach)
            prune |= reach
            if walked >= self.walk_cap:
                break
        two_levels = bool(haves) and not held_haves
        sent: set[str] = set()
        queue: deque = deque([(root, 0)])
        frontier: list[str] = []
        reason = END_DONE
        spent = 0

        def walk():
            nonlocal walked, spent, reason
            while queue:
                cid, level = queue.popleft()
                if cid in prune or cid in sent:
                    continue
                if two_levels and level > 1:
                    frontier.append(cid)
                    continue
                data = self.store.get(cid)
                if data is None:
                    continue
                if spent + len(data) > budget and sent:
                    reason = END_BUDGET
                    queue.appendleft((cid, level))
                    return
                if walked >= self.walk_cap:
                    reason = END_WALK_CAP
                    queue.appendleft((cid, level))
                    return
                sent.add(cid)
                spent += len(data)
                walked += 1
                yield data
                for link in self.store.links(cid, data):
                    if link not in prune and link not in sent:
                        queue.append((link, level + 1))
            if two_levels:
                reason = END_HAVES_NOT_HELD

        if not self._packed(sender, req, walk(), None):
            return self._reject(sender, root, swarm.REASON_POLICY)
        rest = frontier + [c for c, _ in queue if c not in sent and c not in prune]
        self.send(sender, tree_end(req, list(dict.fromkeys(rest))[:MAX_FRONTIER], reason))

    def _serve_challenge(self, sender: str, msg: dict) -> None:
        """Answers a possession challenge (P2-S-07) as Java's ``TreeServer.serve``: the grant as for a ``NODE_WANT``,
        the held node picks in ``NODES`` under the challenge's ``req`` with the rest in ``missing``, and ``REJECT``
        reason 1 when this peer holds none. A chunk-group pick (a BLAKE3 identity) reads as missing, as in Java."""
        root, picks = msg["root"], msg["picks"]
        artifact = cids.codec_of(root) == cids.RAW
        if not self._may_serve(sender, root) or (not artifact and not all(
                self._may_serve(sender, p["cid"]) for p in picks if "offset" not in p)):
            return self._reject(sender, root, swarm.REASON_POLICY)
        if (not self.keys and self._must_seal(sender)) or (self.keys and self.keys.get(self.write_epoch) is None):
            return self._reject(sender, root, swarm.REASON_POLICY)
        held, missing = [], []
        for pick in picks:
            data = None if "offset" in pick else self.store.get(pick["cid"])
            if data is None:
                missing.append(pick["cid"])
            else:
                held.append(data)
        if not held:
            return self._reject(sender, root, swarm.REASON_NOT_HELD)
        if self._packed(sender, msg["req"], held, missing or None) and not missing:
            self.challenges_answered += 1

    def _serve_sketch(self, sender: str, msg: dict) -> None:
        """Answers a reconciliation round (P2-K-02, rule 12) with ``TREE_END`` reason 5 and the reply appended; a member
        this holder reads at level 1 gets the level-1 refusal (P2-F-05, the phase 5 adversary's A6)."""
        if not self.reads_level_two(sender):
            return self._reject(sender, "", swarm.REASON_POLICY)
        answer = self.sketches.answer(sender, msg["req"], msg["sketch"], msg["budget"])
        if answer[0] == "reply":
            self.send(sender, tree_end(msg["req"], [], END_SKETCH, answer[1]))
        elif answer[0] == "refuse":
            self._reject(sender, "", answer[1])
        else:
            self.tree_messages_dropped += 1

    def reconcile_held(self, holder: str, expected: int = 0) -> sync.SketchSession:
        """Reconciles this peer's set (``reconcile_set``, by default ``held_roots``) with a level-2 holder's (P2-K-02,
        P2-K-03): by RIBLT first when ``expected`` is above 0, falling back to negentropy, else by negentropy. The
        session's ``outcome`` is ``(have, need)``: the roots this peer holds that the holder lacks, and the roots the
        holder holds that this peer lacks. A member read at level 1 gets no sketch (P2-F-05)."""
        if not self.reads_level_two(holder):
            raise ValueError(f"{holder} is read at level 1: a sketch goes only to a member at level 2 (P2-F-05)")
        req = self.next_req()
        session = sync.SketchSession(holder, req, self.reconcile_set(),
                                     lambda sketch: self.send(holder, tree_want(req, "", [], sync.MAX_SKETCH_BYTES, sketch)),
                                     expected)
        self.sessions[req] = session
        session.start()
        if session.done:
            self.sessions.pop(req, None)
        return session

    def stats(self) -> dict:
        return {"treeFetchesActive": len(self.fetches), "nodesServed": self.nodes_served, "bytesServed": self.bytes_served,
                "nodesReceived": self.nodes_received, "nodesStruck": self.nodes_struck,
                "nodesUnopenable": self.nodes_unopenable,
                "treeRequestsRejected": self.tree_requests_rejected, "treeMessagesDropped": self.tree_messages_dropped,
                "deltasApplied": self.deltas_applied, "deltasRefused": self.deltas_refused,
                "challengesAnswered": self.challenges_answered, "nodesHeld": self.store.count()}
