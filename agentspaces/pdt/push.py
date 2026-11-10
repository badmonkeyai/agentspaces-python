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

"""The follower's side of eager push (srad/agentspaces-pdt2.md §3.4, S5 of §6.4; PDT 2 phase 7, P2-C-01, P2-P-02,
P2-Q-SEC-03): the Python port of Java's ``PushReceiver``.

A writer with push on announces the push on its head (``pdt.push``, the canonical decimal count of its bundles) and
publishes the delta's nodes as ``PushBundle`` rumours on the ref's stream ``pdt:<space>:<name>``. The bundle record,
``{v, root, seq, part, parts, nodes}``, is read strictly (``decode_bundle``): a field outside its schema, a field out
of order or of another type makes it undecodable (rule 16, P2-F-08).

A follower takes each bundle of a stream it follows, spends its bytes from the stream's token bucket
(``bytes_per_second`` a second, up to ``max_bytes`` at once), and holds its nodes aside, at most ``max_bytes`` and
``max_bytes // 160`` nodes per root and ``PENDING_ROOTS`` roots per stream; a root no head announced never displaces
one a head announced (the phase 5 adversary's A2 and A5). Once a live head announces the push of its root
(``expect``), the follower stores each held node that hashes to a CID the root reaches through nodes this push stored,
and drops the rest, as an inline delta is verified. The walk runs once from the root and resumes only at the links the
push still lacks, so a bundle that brings none of them costs no walk (A3). A root whose bundles complete it needs no
request. The grace of an announced root is sized for lateness (swarm retries, ROBUSTNESS.md §10): the gossip bus's
repair window plus the time the announced bundles take at the stream's budget, between ``GRACE_MS`` and
``MAX_GRACE_MS``. Past it the follower fetches what is missing and still stores the bundles that come late, for
``ORPHAN_GRACES`` graces from the announcement. Nobody is struck: a member that does not follow a ref relays its
bundles without reading them (rule 16), so the sender of a bad bundle may be an honest relay. This client relays no
rumour, so it has no forward filter; the Python content swarm keeps no download budget, so the stream budget is the
one this follower spends."""

from __future__ import annotations

import hashlib
import threading
import time

from .. import cbor
from . import cids

VERSION = 1
MAX_BYTES = 1 << 20
MAX_PARTS = 64
MAX_SEQ = 1 << 53
ATTR = "pdt.push"
#: The writer's budget and each stream's on a follower, and the most bytes one root holds, as Java's defaults.
BYTES_PER_SECOND = 2 << 20
MAX_DELTA_BYTES = 8 << 20
#: What keeping one node aside costs beyond its bytes, so a root holds at most ``max_bytes // HELD_NODE_OVERHEAD``
#: nodes (the phase 5 adversary's A2).
HELD_NODE_OVERHEAD = 160
PENDING_ROOTS = 4
ORPHAN_GRACES = 2
GRACE_MS = 2_000
MAX_GRACE_MS = 15_000
#: The gossip bus's repair window before it has a graft sample: its base, a spread window, the first backoff, and a
#: second spread window (Java's ``GossipBus.repairWindowMillis``), by which a member that missed a bundle's eager copy
#: has asked two members that announced it.
REPAIR_WINDOW_MS = 500 + 1_000 + 1_000 + 1_000
NONE, WAIT, LATE = "none", "wait", "late"

FIELDS = ("v", "root", "seq", "part", "parts", "nodes")
_JAVA_INT = 1 << 31
_JAVA_LONG = 1 << 63


def stream(space: str, name: str) -> str:
    """The stream of a ref: ``pdt:<space>:<name>`` (P2-P-01)."""
    return f"pdt:{space}:{name}"


def decode_bundle(raw: bytes) -> dict | None:
    """The bundle the bytes hold, read strictly, or None: the six fields in Java's order, ``v``, ``part`` and
    ``parts`` Java ints, ``seq`` a Java long, ``root`` text, and ``nodes`` a list of byte strings."""
    try:
        value = cbor.loads(raw)
    except ValueError:
        return None
    if not isinstance(value, dict) or list(value) != list(FIELDS):
        return None
    if not all(type(value[f]) is int and -_JAVA_INT <= value[f] < _JAVA_INT for f in ("v", "part", "parts")):
        return None
    if type(value["seq"]) is not int or not -_JAVA_LONG <= value["seq"] < _JAVA_LONG:
        return None
    if not isinstance(value["root"], str) or not isinstance(value["nodes"], list):
        return None
    if not all(isinstance(n, bytes) for n in value["nodes"]):
        return None
    return value


def bundle_violation(b: dict) -> str | None:
    """The first rule a bundle breaks, as Java's ``PushBundle.violation``, or None."""
    if b["v"] != VERSION:
        return f"unsupported PushBundle version {b['v']}"
    if not cids.is_cid(b["root"]):
        return f"root is not a CID: {b['root']}"
    if b["seq"] < 0 or b["seq"] > MAX_SEQ:
        return f"seq {b['seq']} is outside 0 to {MAX_SEQ}"
    if b["parts"] < 1 or b["parts"] > MAX_PARTS or b["part"] < 0 or b["part"] >= b["parts"]:
        return f"part {b['part']} of {b['parts']} is outside 1 to {MAX_PARTS} parts"
    if not b["nodes"]:
        return "a bundle carries at least one node"
    if any(not n for n in b["nodes"]):
        return "a bundle carries an empty node"
    total = sum(len(n) for n in b["nodes"])
    if total > MAX_BYTES:
        return f"a bundle carries at most {MAX_BYTES} bytes of nodes, got {total}"
    return None


def announced(attrs) -> int:
    """The bundles a head announces in ``pdt.push``: canonical decimal 1 to 64, else 0 (no push)."""
    text = (attrs or {}).get(ATTR)
    if not isinstance(text, str) or not text.isascii() or not text.isdigit() or text[0] == "0" or len(text) > 2:
        return 0
    parts = int(text)
    return parts if parts <= MAX_PARTS else 0


class _Assembly:
    def __init__(self, root: str, now: int):
        self.root = root
        self.created = now
        self.anchored = -1
        self.grace = 0
        self.late = False
        self.held: dict[bytes, bytes] = {}
        self.held_bytes = 0
        self.stored: set[str] = set()
        self.missing: dict[bytes, str] = {}
        self.complete = False


class _Stream:
    def __init__(self, tokens: float, now: int):
        self.tokens = tokens
        self.refilled = now
        self.assemblies: dict[str, _Assembly] = {}


class PushReceiver:
    """Takes the bundles of the streams it follows into a node store; ``clock`` gives epoch milliseconds."""

    def __init__(self, store, clock=None, bytes_per_second: int = BYTES_PER_SECOND, max_bytes: int = MAX_DELTA_BYTES,
                 grace_ms: int = GRACE_MS, max_grace_ms: int = MAX_GRACE_MS):
        if bytes_per_second <= 0 or max_bytes <= 0 or grace_ms > max_grace_ms:
            raise ValueError("push budgets are positive and the grace is at most its ceiling")
        self.store = store
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.bytes_per_second = bytes_per_second
        self.max_bytes = max_bytes
        self.max_nodes = max_bytes // HELD_NODE_OVERHEAD
        self.grace_ms = grace_ms
        self.max_grace_ms = max_grace_ms
        self.streams: dict[str, _Stream] = {}
        self.counts = {"bundlesReceived": 0, "bundlesDropped": 0, "nodesStored": 0, "bytesStored": 0,
                       "nodesDropped": 0, "fallbacks": 0}
        self._lock = threading.RLock()

    def follow(self, stream_id: str) -> None:
        with self._lock:
            self.streams.setdefault(stream_id, _Stream(self.max_bytes, self.clock()))

    def unfollow(self, stream_id: str) -> None:
        with self._lock:
            self.streams.pop(stream_id, None)

    def on_bundle(self, stream_id: str, payload: bytes) -> None:
        """Takes one bundle of a followed stream, as the module comment says."""
        with self._lock:
            s = self.streams.get(stream_id)
            if s is None:
                return
            bundle = decode_bundle(payload)
            if bundle is None or bundle_violation(bundle) is not None:
                self.counts["bundlesDropped"] += 1
                return
            now = self.clock()
            s.tokens = min(self.max_bytes, s.tokens + (now - s.refilled) * self.bytes_per_second / 1000)
            s.refilled = now
            if s.tokens < len(payload):
                self.counts["bundlesDropped"] += 1
                return
            s.tokens -= len(payload)
            a = s.assemblies.get(bundle["root"])
            if a is None:
                if not self._room(s, announced_root=False):
                    self.counts["bundlesDropped"] += 1  # every root this stream holds was announced
                    return
                a = s.assemblies[bundle["root"]] = _Assembly(bundle["root"], now)
            if a.complete:
                self.counts["bundlesReceived"] += 1
                self.counts["nodesDropped"] += len(bundle["nodes"])
                return
            size = sum(len(n) for n in bundle["nodes"])
            if a.held_bytes + size > self.max_bytes or len(a.held) + len(bundle["nodes"]) > self.max_nodes:
                self.counts["bundlesDropped"] += 1
                return
            self.counts["bundlesReceived"] += 1
            found = []
            for node in bundle["nodes"]:
                digest = hashlib.sha256(node).digest()
                if digest not in a.held:
                    a.held[digest] = node
                    a.held_bytes += len(node)
                    link = a.missing.pop(digest, None)
                    if link is not None:
                        found.append(link)
            if found:
                self._walk(a, found)

    def _room(self, s: _Stream, announced_root: bool) -> bool:
        """Room for one more root: a complete root goes first, then the oldest no head announced; an announced root
        displaces the oldest announced one only for another announced root."""
        if len(s.assemblies) < PENDING_ROOTS:
            return True
        gone = next((a for a in s.assemblies.values() if a.complete), None)
        if gone is None:
            gone = next((a for a in s.assemblies.values() if a.anchored < 0), None)
        if gone is None and announced_root:
            gone = next(iter(s.assemblies.values()))
        if gone is None:
            return False
        self.counts["nodesDropped"] += len(gone.held)
        del s.assemblies[gone.root]
        return True

    def expect(self, stream_id: str, root: str, parts: int) -> None:
        """A live head announced the push of its root: the held nodes the root reaches are stored now, the rest as
        their bundles arrive."""
        with self._lock:
            s = self.streams.get(stream_id)
            if s is None:
                return
            now = self.clock()
            a = s.assemblies.get(root)
            if a is None:
                self._room(s, announced_root=True)
                a = s.assemblies[root] = _Assembly(root, now)
            if a.anchored < 0:
                a.anchored = now
                a.grace = self.grace(parts)
                self._walk(a, [root])

    def grace(self, parts: int) -> int:
        """The wait for an announced push of ``parts`` bundles: the bus's repair window plus the bundles' largest bytes
        at the stream's budget, between the grace and its ceiling (swarm retries)."""
        sized = REPAIR_WINDOW_MS + parts * MAX_BYTES * 1000 // self.bytes_per_second
        return max(self.grace_ms, min(self.max_grace_ms, sized))

    def _walk(self, a: _Assembly, start: list) -> None:
        frontier = list(start)
        while frontier:
            cid = frontier.pop()
            if cid in a.stored or self.store.has(cid):
                continue
            try:
                digest = cids.parse(cid).digest
            except ValueError:
                continue
            data = a.held.pop(digest, None)
            if data is None:
                a.missing[digest] = cid
                continue
            a.held_bytes -= len(data)
            self.store.put_verified(cid, data)
            a.stored.add(cid)
            self.counts["nodesStored"] += 1
            self.counts["bytesStored"] += len(data)
            frontier.extend(self.store.links(cid, data))
        if not a.missing:
            a.complete = True
            self.counts["nodesDropped"] += len(a.held)  # what the root does not reach was never part of its delta
            a.held.clear()
            a.held_bytes = 0

    def check(self, stream_id: str, root: str) -> str:
        """``WAIT`` within the grace of an announced push of a root not yet complete, ``LATE`` past it (the follower
        fetches what is missing), else ``NONE``."""
        with self._lock:
            s = self.streams.get(stream_id)
            a = None if s is None else s.assemblies.get(root)
            if a is None or a.anchored < 0 or a.complete:
                return NONE
            if self.clock() - a.anchored < a.grace:
                return WAIT
            if not a.late:
                a.late = True
                self.counts["fallbacks"] += 1
            return LATE

    def expire(self) -> None:
        """Drops the bundles of roots held too long: an announced root ``ORPHAN_GRACES`` of its own graces after the
        announcement, a root no head announced ``ORPHAN_GRACES`` floor graces after its first bundle."""
        with self._lock:
            now = self.clock()
            for s in self.streams.values():
                for root, a in list(s.assemblies.items()):
                    anchored = a.anchored >= 0
                    since = a.anchored if anchored else a.created
                    limit = a.grace * ORPHAN_GRACES if anchored else self.grace_ms * ORPHAN_GRACES
                    if now - since > limit:
                        self.counts["nodesDropped"] += len(a.held)
                        del s.assemblies[root]

    def stats(self) -> dict:
        with self._lock:
            return dict(self.counts)
