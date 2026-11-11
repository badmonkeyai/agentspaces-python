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

"""Refs (srad/agentspaces-pdt.md §3.6, §10.2; PD-R-01 to PD-R-09, PD-X-07,
PD-X-10, PD-P-04): a ref is the set of live ``PRef#v1`` entries of one name in
one space; its heads are the entries no other live entry with a larger seq
lists in ``base``, equal roots folded. ``deref`` returns the single head's
value or the deterministic merge of §3.6.1 and never writes; ``swap(f)`` reads
the heads, applies ``f``, writes the new nodes (inline on the head up to
32 KiB, else by request), and writes a head whose ``base`` lists the heads it
read and whose ``seq`` is one more than their largest. In ``linear`` mode
``swap`` takes the head entry under the space's take and completes it with
the successor, as the Python ``@reduce`` path does.

The merge: maps and sets merge key-wise against the lowest common base found
over the base links (at most 64 steps); a key changed on both sides takes the
head with the later issued HLC (ties by issuer PeerId bytes), reported as a
``PConflict`` with reason ``LATER_HLC``; vectors and blobs take the later head
whole (``WHOLE_HEAD``) unless a merge function is registered for the name.
When the walks share no version and every walk ends at first versions within
the bound, the empty value is the base (HLC round five, 2026-11-08, decision
E16); past the walk bound or without the base the later head wins whole
(``NO_COMMON_BASE``)."""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable

from .. import cbor, wire
from ..peer import lease_of, present
from ..space import Space, duration_millis
from . import cids, nodes, push
from . import push as _push
from .ancestry import ANCESTRY_ATTR, ancestry_cid
from .bao import claim_of
from .blob import PBlob
from .champ import PMap, PSet
from .db import DbReader
from .kinds import MAX_BASE, VgNode
from .text import TEXT_PREFIX, is_text, replica_of
from .store import NodeStore, RecordingStore
from .tree import Trees
from .values import Ctx, StoreLoader, StoreThenFetchLoader, read_payload
from .vector import PVector

PREF_TYPE = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1"
VERSION = 1
#: PDT 2 phase 7 (P2-F-06, §6.10.3 rules 1 to 8): a head whose tree holds a node of a kind outside annex H's level-1
#: set, or a text value, is version 2; a level-2 reader reads both.
VERSION_2 = 2
NAME_TAG, ROOT_TAG = "name", "root"
KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE = "map", "set", "vector", "blob", "tree"
#: A DataScript database, a ``db`` root over ``dn`` nodes; its heads are always version 2 (P2-D-03, rule 8).
KIND_DB = "db"
KINDS = {KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE, KIND_DB}
#: The node kinds outside annex H's level-1 set that a value tree may hold (rule 8).
LEVEL_TWO_KINDS = frozenset({nodes.KIND_DB, nodes.KIND_DN, nodes.KIND_RR, nodes.KIND_RV, nodes.KIND_T})
MODE_MULTI, MODE_LINEAR = "multi", "linear"
SEALING_NONE, SEALING_GROUP_KEY, SEALING_SEALED_NODES = "none", "group-key", "sealed-nodes"
MAX_NAME_BYTES = 256
#: The first wait before a root whose fetch failed is fetched again, in seconds; each later failure doubles it up to
#: ``UNLOADABLE_BACKOFF`` load timeouts, with a random spread of up to half (swarm retries, ROBUSTNESS.md §10.3 E1).
RETRY_BASE_S = 1.0
UNLOADABLE_BACKOFF = 4
#: The vg nodes whose failed fetch a ref remembers for its backoff, at most (swarm retries).
CHAIN_MISSES_KEPT = 1024
#: The grace before a writer cancels its own superseded head: two gossip rounds, as Java's ``Refs.CANCEL_GRACE_MILLIS``
#: (PD-R-03; PDT 2 phase 7, P2-X-05).
CANCEL_GRACE_MS = 2_000
INLINE_DELTA_BYTES = 32 * 1024
#: How often a read waiting for an announced push looks again (P2-P-02).
PUSH_POLL_S = 0.02
MAX_ATTRS, MAX_ATTRS_BYTES = 32, 4 * 1024
MAX_MODE_BYTES = 32
MAX_SEQ = 1 << 53
MAX_BASE_STEPS = 64
ISSUED_ATTR, ISSUER_ATTR = "pdt.issued", "pdt.issuer"
RESERVED_ATTRS = frozenset({ISSUED_ATTR, ISSUER_ATTR})
FOLLOW_FULL, FOLLOW_LAZY = "full", "lazy"
EMPTY_BASE = ""

LATER_HLC, WHOLE_HEAD, NO_COMMON_BASE, MERGE_FUNCTION_FAILED = "LATER_HLC", "WHOLE_HEAD", "NO_COMMON_BASE", "MERGE_FUNCTION_FAILED"


# ------------------------------------------------------------------ the record

def pref_record(name: str, kind: str, root: str, base: list[str] | None = None, seq: int = 1, size: int = 0,
                node_list: list[bytes] | None = None, mode: str = MODE_MULTI, sealing: str = SEALING_NONE,
                key_epoch: int | None = None, attrs: dict | None = None, version: int = VERSION) -> dict:
    """A ``PRef`` value in Java field order; ``nodes``, ``keyEpoch``, and ``attrs`` leave the wire when None.
    ValueError for attrs every reader refuses: a key that is not text, or a value that is not text
    under a key other than ``pdt.issued`` and ``pdt.issuer`` (HLC round six, 2026-11-08, R1)."""
    record = {"v": version, "name": name, "kind": kind, "root": root, "base": list(base or []),
              "seq": int(seq), "size": int(size)}
    if node_list is not None:
        record["nodes"] = [bytes(n) for n in node_list]
    record["mode"] = mode
    record["sealing"] = sealing
    if key_epoch is not None:
        record["keyEpoch"] = int(key_epoch)
    if attrs is not None:
        for key, value in attrs.items():
            if not isinstance(key, str) or (key not in RESERVED_ATTRS and not isinstance(value, str)):
                raise ValueError(f"PRef attrs map text to text, got {key!r}: {value!r}")
        record["attrs"] = cbor.canonical_map(attrs)
    return record


# PRef's fields in the order Java's record declares them, and the three that leave the wire when
# null (HLC round six, 2026-11-08, rulings F1 and F3).
PREF_FIELDS = ("v", "name", "kind", "root", "base", "seq", "size", "nodes", "mode", "sealing", "keyEpoch", "attrs")
OMITTED_WHEN_NULL = frozenset({"nodes", "keyEpoch", "attrs"})
_TEXT_FIELDS = ("name", "kind", "root", "mode", "sealing")
_LONG_FIELDS = ("seq", "size", "keyEpoch")


def _java_integer(value, bits: int) -> bool:
    """Whether ``value`` is an integer, a boolean excluded, that a Java integer of ``bits`` holds."""
    return type(value) is int and -(1 << (bits - 1)) <= value < (1 << (bits - 1))


def decode_pref(raw: bytes) -> dict | None:
    """The ``PRef`` the bytes hold, or None when they are undecodable (HLC round six, 2026-11-08,
    rulings F1, F3 and R1). ``cbor.loads`` reads only the wire encoding, so the item it returns
    re-encodes to exactly these bytes (F3): a wider head, a definite map, a duplicate or non-text
    key, or a trailing byte never decodes. ``pref_of`` then judges the record. The caller ignores
    an undecodable head and counts it in headsIgnored (R3); ``pref_violation`` judges the bounds."""
    try:
        return pref_of(cbor.loads(raw))
    except ValueError:
        return None


def pref_of(value) -> dict | None:
    """``value`` when a decoded item is a ``PRef`` record, None otherwise (HLC round six,
    2026-11-08, rulings F1 and R1). A PRef is a protocol record: one map whose keys are exactly
    Java's fields in their declared order, ``nodes``, ``keyEpoch`` and ``attrs`` absent when null
    and every other field present; ``v`` a Java int, ``seq``, ``size`` and ``keyEpoch`` Java
    longs, the five text fields text, ``base`` an array of text, ``nodes`` an array of byte
    strings, and ``attrs`` a map in the canonical key order. An attr under ``pdt.issued`` or
    ``pdt.issuer`` may hold any item, which falls back when it is no stamp or agent id (E10);
    under every other key the value is text. No item of another kind is coerced."""
    if not isinstance(value, dict):
        return None
    if list(value) != [f for f in PREF_FIELDS if f not in OMITTED_WHEN_NULL or f in value]:
        return None
    if any(value[f] is None for f in OMITTED_WHEN_NULL if f in value):
        return None
    if not _java_integer(value["v"], 32) or not all(_java_integer(value[f], 64) for f in _LONG_FIELDS if f in value):
        return None
    if not all(isinstance(value[f], str) for f in _TEXT_FIELDS):
        return None
    if not isinstance(value["base"], list) or not all(isinstance(b, str) for b in value["base"]):
        return None
    if "nodes" in value and (not isinstance(value["nodes"], list)
                             or not all(isinstance(n, bytes) for n in value["nodes"])):
        return None
    attrs = value.get("attrs")
    if attrs is not None:
        if not isinstance(attrs, dict) or list(attrs) != list(cbor.canonical_map(attrs)):
            return None
        if not all(isinstance(v, str) for k, v in attrs.items() if k not in RESERVED_ATTRS):
            return None
    return value


def pref_tags(record: dict) -> dict:
    return {NAME_TAG: record["name"], ROOT_TAG: record["root"]}


def pref_violation(r: dict) -> str | None:
    """The first broken bound of §3.6 as pinned in 10.2, or None."""
    try:
        if r.get("v") not in (VERSION, VERSION_2):
            return f"unsupported PRef version {r.get('v')}"
        if r.get("kind") == KIND_DB and r.get("v") != VERSION_2:
            return f"a db head is version {VERSION_2}, found {r.get('v')}"
        name = r.get("name")
        if not isinstance(name, str) or not name:
            return "empty name"
        if len(name.encode("utf-8")) > MAX_NAME_BYTES:
            return f"name longer than {MAX_NAME_BYTES} bytes"
        if r.get("kind") not in KINDS:
            return f"unknown kind {r.get('kind')}"
        if not r.get("root"):
            return "empty root"
        if not cids.is_cid(r["root"]):
            return "root is not a CID"
        base = r.get("base") or []
        if len(base) > MAX_BASE:
            return f"more than {MAX_BASE} bases"
        for b in base:
            if not b:
                return "empty base root"
            if not cids.is_cid(b):
                return "base root is not a CID"
        seq, size = r.get("seq"), r.get("size")
        if not isinstance(seq, int) or seq < 0:
            return "negative seq"
        if seq > MAX_SEQ:
            return f"seq above {MAX_SEQ}"
        if not isinstance(size, int) or size < 0:
            return "negative size"
        if r.get("nodes") is not None:
            for n in r["nodes"]:
                if not n:
                    return "empty inline node"
            if sum(len(n) for n in r["nodes"]) > INLINE_DELTA_BYTES:
                return f"inline nodes larger than {INLINE_DELTA_BYTES} bytes"
        for field in ("mode", "sealing"):
            v = r.get(field)
            if not isinstance(v, str) or not v:
                return f"empty {field}"
            if len(v.encode("utf-8")) > MAX_MODE_BYTES:
                return f"{field} longer than {MAX_MODE_BYTES} bytes"
        if r.get("keyEpoch") is not None and r["keyEpoch"] < 0:
            return "negative keyEpoch"
        attrs = r.get("attrs")
        if attrs is not None:
            if len(attrs) > MAX_ATTRS:
                return f"more than {MAX_ATTRS} attrs"
            # keys and text values count; a fallback item under a reserved key counts nothing (HLC
            # round six, 2026-11-08, R1)
            if sum(len(k.encode("utf-8")) + (len(v.encode("utf-8")) if isinstance(v, str) else 0)
                   for k, v in attrs.items()) > MAX_ATTRS_BYTES:
                return f"attrs larger than {MAX_ATTRS_BYTES} bytes"
        return None
    except (TypeError, ValueError, AttributeError) as e:
        return f"malformed PRef: {e}"


def inline_bytes(record: dict) -> int:
    return sum(len(n) for n in (record.get("nodes") or []))


@dataclass(frozen=True)
class PRef:
    """A decoded head, for callers that prefer attributes to a dict."""
    name: str
    kind: str
    root: str
    base: tuple
    seq: int
    size: int
    mode: str
    sealing: str
    nodes: tuple | None = None
    key_epoch: int | None = None
    attrs: dict | None = None

    @staticmethod
    def of(record: dict) -> "PRef":
        return PRef(record["name"], record["kind"], record["root"], tuple(record.get("base") or []), record["seq"],
                    record["size"], record["mode"], record["sealing"],
                    None if record.get("nodes") is None else tuple(record["nodes"]), record.get("keyEpoch"),
                    record.get("attrs"))

    def record(self) -> dict:
        return pref_record(self.name, self.kind, self.root, list(self.base), self.seq, self.size,
                           None if self.nodes is None else list(self.nodes), self.mode, self.sealing,
                           self.key_epoch, self.attrs)


@dataclass(frozen=True)
class PConflict:
    name: str
    key: object
    winner_root: str
    loser_root: str
    reason: str


@dataclass(frozen=True)
class Head:
    """One version of a ref as a reader keeps it, with the merge order's fields."""
    root: str
    base: tuple
    seq: int
    size: int
    kind: str
    mode: str
    issuer: str
    issued: tuple          # (physical, logical, node)
    entry_id: str
    expires_at_millis: int
    push_parts: int = 0    # the bundles the head announces in pdt.push (P2-P-02)

    def order(self) -> tuple:
        peer = self.issuer.split("/", 1)[0].encode("utf-8")
        return (self.issued[0], self.issued[1], peer, self.root)


def _hlc(stamp) -> tuple:
    """The entry's own issue stamp as ``(physical, logical, node)``; the peer folded only a
    state whose stamp the rule accepts, so the fallback ``(0, 0, "")`` never orders a head."""
    return wire.parse_hlc(stamp) or (0, 0, "")


def head_order(issued, issuer, attrs: dict, now_ms: int) -> tuple:
    """The ``(issued, issuer)`` a head of the entry orders by, as Refs.java's toHead reads
    the reserved attrs a rewrite carries (PD-R-08; HLC round four, 2026-11-08, decision
    D2). An acceptable ``pdt.issued`` (``wire.acceptable_hlc``) replaces the entry's own
    stamp, and ``pdt.issuer`` its issuer, or the entry's issuer stays when the attrs carry
    no ``pdt.issuer`` key. A ``pdt.issued`` that is absent, null, not text, or refused by the
    rule, or a ``pdt.issuer`` key whose value is null, not text, or no agent id, leaves the
    entry's own stamp and issuer together: a present null issuer counts as a bad issuer and
    never pairs ``pdt.issued`` with the entry's issuer (HLC round five, 2026-11-08, decision
    E10). A ``pdt.issued`` whose physical time lies past the reader's wall ``now_ms`` +
    MAX_DRIFT + the 5 s far-future margin falls back the same way, so a writer cannot win
    every conflict by stamping ahead (HLC round six, 2026-11-08, R2). The attrs are advisory
    payload, so the reader refuses and counts nothing for them and keeps the head.
    ``issued`` is the entry's own stamp text."""
    own = _hlc(issued), issuer
    stamped = attrs.get(ISSUED_ATTR)
    original = wire.acceptable_hlc(str(stamped)) if isinstance(stamped, str) else None
    original_issuer = attrs[ISSUER_ATTR] if ISSUER_ATTR in attrs else issuer
    line = now_ms + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_SKEW_MARGIN_MILLIS
    if original is None or original[0] > line or not wire.is_agent_id(original_issuer):
        return own
    return original, str(original_issuer)


def heads_among(entries: list[Head]) -> list[Head]:
    """The entries no other entry supersedes, equal roots folded (10.2)."""
    superseded_below: dict[str, int] = {}
    for h in entries:
        by = 1 << 62 if h.seq >= MAX_SEQ else h.seq
        for b in h.base:
            superseded_below[b] = max(superseded_below.get(b, -1), by)
    by_root: dict[str, Head] = {}
    for h in sorted(entries, key=Head.order):
        by = superseded_below.get(h.root)
        if by is not None and by > h.seq:
            continue
        kept = by_root.get(h.root)
        if kept is None or h.seq > kept.seq:
            by_root[h.root] = h
    return sorted(by_root.values(), key=Head.order)


# ------------------------------------------------------------------ kinds

class _Kind:
    def __init__(self, name: str, empty, load, size):
        self.name = name
        self.empty = empty
        self.load = load
        self.size = size

    @property
    def by_key(self) -> bool:
        return self.name in (KIND_MAP, KIND_SET, KIND_TREE)


_KINDS = {
    KIND_MAP: _Kind(KIND_MAP, PMap.empty, PMap.load, lambda v: v.count()),
    KIND_TREE: _Kind(KIND_TREE, PMap.empty, PMap.load, lambda v: v.count()),
    KIND_SET: _Kind(KIND_SET, PSet.empty, PSet.load, lambda v: v.count()),
    KIND_VECTOR: _Kind(KIND_VECTOR, PVector.empty, PVector.load, lambda v: v.count()),
    KIND_BLOB: _Kind(KIND_BLOB, lambda store, loader=None: PBlob.of(b"", store),
                     lambda store, root, loader=None: PBlob.load(store, root, loader), lambda v: v.size()),
    # PDT 2 phase 7, P2-C-01 group D: a db ref reads as a lazy DataScript reader; DataScript writes it
    KIND_DB: _Kind(KIND_DB, lambda store, loader=None: None,
                   lambda store, root, loader=None: DbReader(root, loader or StoreLoader(store)), lambda v: v.max_eid),
}


# ------------------------------------------------------------------ the handle

class Ref:
    """The handle of one named ref over a ``Pdt``."""

    def __init__(self, pdt: "Pdt", name: str, kind: str, mode: str):
        if kind not in KINDS:
            raise ValueError(f"unknown ref kind {kind}")
        self.pdt = pdt
        self.name = name
        self.kind = _KINDS[kind]
        self.mode = mode
        self.known: dict[str, Head] = {}
        self.ignored: set[str] = set()
        #: Late heads counted, by (entry id, cause), while the entries are live (swarm retries, ROBUSTNESS.md §10.3 E1).
        self.late: set[tuple[str, str]] = set()
        #: The fetch of each root under way, and the roots whose fetch failed: [failures, monotonic time the next is due].
        self.fetching: dict = {}
        self.retries: dict[str, list] = {}
        #: The head entries this peer wrote, by entry id: {"root", "base", "renewed_at" (peer ms), "lease",
        #: "superseded_at" (peer ms or None), "displaced", "vg" (the vg node it pinned, or None)}; a revert within
        #: the grace gives one root two entries.
        self.own: dict[str, dict] = {}
        self.last_heads: list[Head] = []
        self.watchers: list[Callable] = []
        self.conflict_listeners: list[Callable] = []
        self.delivered_roots: tuple = ()
        self.complete_roots: set[str] = set()
        self.held_roots_cache: dict[str, bool] = {}
        self.deltas_inline = 0
        self.deltas_fetched = 0
        self.nodes_dropped = 0
        self.heads_ignored = 0
        #: Heads left out of reads while their roots were still loading, by cause; heads ignored for a fault count in
        #: heads_ignored instead (swarm retries).
        self.heads_late = {"timeout": 0, "failedFetch": 0, "lazyLoad": 0}
        self.bases_fetched = 0
        self.conflicts = 0
        #: The version graph (PDT 2 phase 7, P2-V-01, P2-V-02): each root's vg node CID as a head or a chain link
        #: named it, and the vg nodes read.
        self.ancestry: dict[str, str] = {}
        self.chain: dict[str, VgNode] = {}
        #: The (identity, outboard root) each blob version's first head named in pdt.blake3 and pdt.bao, which the
        #: loaded value carries for a verified window (PDT 2 phase 7, P2-B-01, P2-B-03; advisory, rule 10).
        self.claims: dict[str, tuple[str, str]] = {}
        #: vg nodes whose fetch failed: [failures, monotonic time the next ask is due] (swarm retries).
        self.chain_misses: dict[str, list] = {}
        self._lock = threading.RLock()

    # ---- reading

    @property
    def store(self) -> NodeStore:
        return self.pdt.store

    def held(self, root: str) -> bool:
        if root in self.complete_roots:
            return True
        if self.pdt.follow == FOLLOW_LAZY:
            return self.store.has(root)
        if self.store.complete(root):
            self.complete_roots.add(root)
            return True
        return False

    def _live_entries(self) -> list[Head]:
        """The live entries of the name as heads, recording each among the known versions. An
        entry whose PRef does not decode, breaks a bound, or names another ref or kind is
        ignored and counted once in headsIgnored, as Refs.java's toHead counts it; the ignored
        entries are remembered only while they are live (HLC round six, 2026-11-08, R1, R3)."""
        peer, space = self.pdt.peer, self.pdt.space
        space_id = space._space_id()
        now = peer._now_ms()
        live, ids = [], set()
        for entry_id, dto in list(peer.states.items()):
            record = dto.get("record") or {}
            # a completed entry, or one its issuer cancelled (P2-X-05), is no head
            if record.get("type") != PREF_TYPE or record.get("spaceId") != space_id or not present(dto):
                continue
            if (record.get("tags") or {}).get(NAME_TAG) != self.name:
                continue
            # PDT 2 phase 7 gate: the lease register, which the writer's renewal moves (SPEC §7.3), and not the lease
            # the record was written with, so a renewed head lives on past its first lease
            expires_at = int(lease_of(dto).get("expiresAtMillis", 0))
            if expires_at <= now:
                continue
            ids.add(entry_id)
            raw = peer.payload_of(dto)
            if raw is None:
                continue
            value = decode_pref(raw)
            if (value is None or pref_violation(value) is not None or value["name"] != self.name
                    or value["kind"] != self.kind.name):
                self._ignore(entry_id)
                continue
            issued, issuer = head_order(record.get("issued"), str(record.get("issuer")), value.get("attrs") or {}, now)
            head = Head(value["root"], tuple(value["base"]), value["seq"], value["size"], value["kind"],
                        value["mode"], issuer, issued, entry_id, expires_at, push.announced(value.get("attrs")))
            self._know(head)
            vg = ancestry_cid(value)
            if vg is not None:
                self.ancestry.setdefault(head.root, vg)
            claim = claim_of(value.get("attrs"))
            if claim is not None:
                self.claims.setdefault(head.root, claim)
            if value.get("nodes") and not self.held(head.root) and head.entry_id not in self.ignored:
                self._apply_inline(head.root, value["nodes"])
            live.append(head)
        self.ignored.intersection_update(ids)
        self.late = {note for note in self.late if note[0] in ids}
        return live

    def _ignore(self, entry_id: str) -> None:
        if entry_id not in self.ignored:
            self.ignored.add(entry_id)
            self.heads_ignored += 1

    def _know(self, head: Head) -> None:
        """Records a head among the known versions as Refs.java's toHead does. A record with a
        larger seq for a known root is a later version that recreated the root; the version
        keeps the union of the bases every record of it named, the newer record's bases first,
        and otherwise the known version takes the entry it was last seen as. The base order
        decides which shared version the breadth-first walk meets first, so every reader picks
        the same common base (HLC round six, 2026-11-08, R4)."""
        known = self.known.get(head.root)
        if known is None:
            self.known[head.root] = head
            return
        newer = head.seq > known.seq
        first, then = (head.base, known.base) if newer else (known.base, head.base)
        bases = tuple(dict.fromkeys(first + then))
        kept = head if newer else replace(known, entry_id=head.entry_id, expires_at_millis=head.expires_at_millis)
        self.known[head.root] = replace(kept, base=bases)

    def _apply_inline(self, root: str, inline: list[bytes]) -> None:
        """Verifies inline nodes by a walk from the root through the store plus the inline set (PD-X-07)."""
        by_digest = {}
        for data in inline:
            by_digest[nodes_sha(data)] = data
        used = set()
        frontier = [root]
        seen = set()
        while frontier:
            cid = frontier.pop()
            if cid in seen:
                continue
            seen.add(cid)
            data = self.store.get(cid)
            if data is None:
                digest = cids.parse(cid).digest
                data = by_digest.get(digest)
                if data is None:
                    continue
                self.store.put_verified(cid, data)
                used.add(digest)
            frontier.extend(self.store.links(cid, data))
        dropped = len(by_digest) - len(used)
        if dropped:
            self.nodes_dropped += dropped
        if used:
            self.deltas_inline += 1

    def _loadable(self, heads: list[Head], wait: bool) -> list[Head]:
        waiting, pushing = [], []
        lazy_late = set()
        for h in heads:
            if h.entry_id in self.ignored:
                continue
            if self.held(h.root):
                continue
            if self.pdt.follow == FOLLOW_LAZY:
                self.pdt.trees.follow(h.root)
                try:
                    self.pdt.trees.load(h.root, prefer=[h.issuer.split("/", 1)[0]], timeout=self.pdt.load_timeout if wait else 0.0)
                except nodes.NodeUnavailable:
                    lazy_late.add(h.entry_id)
                continue
            if self._pushing(h):
                pushing.append(h)
                continue
            waiting.append(h)
        fetches = []
        for h in waiting:
            f = self._fetch(h)
            if f is not None:
                fetches.append((h, f))
        deadline = time.monotonic() + self.pdt.load_timeout
        while wait and pushing and time.monotonic() < deadline:
            # P2-P-02: a head whose push is in its grace waits for its bundles; past the grace the follower fetches
            # what they left missing, from the other holders before the writer (swarm retries, P4 and P6)
            for h in list(pushing):
                if self._pushing(h):
                    continue
                pushing.remove(h)
                if not self.held(h.root):
                    f = self._fetch(h, others_first=True)
                    if f is not None:
                        fetches.append((h, f))
            if pushing:
                time.sleep(PUSH_POLL_S)
        if wait and fetches:
            for h, f in fetches:
                f.wait(max(0.0, deadline - time.monotonic()))
        self._settle_fetches()
        out = []
        for h in heads:
            if h.entry_id in self.ignored:
                continue
            if self.held(h.root):
                out.append(h)
                for _h, f in fetches:
                    if _h is h and f.complete:
                        self.deltas_fetched += 1
                continue
            if wait:
                # swarm retries: the read's wait is the caller's; the fetch goes on, and a failed one is retried
                running = self.fetching.get(h.root)
                cause = ("lazyLoad" if h.entry_id in lazy_late
                         else "timeout" if running is not None and not running.done.is_set() else "failedFetch")
                self._late(h.entry_id, cause)
        return out

    def _pushing(self, h: Head) -> bool:
        """Whether a head waits for its announced push (P2-P-02): the bundles already held are stored the first time
        the head is seen, and a push that completes the root needs no fetch."""
        receiver = self.pdt.push
        if receiver is None or not h.push_parts:
            return False
        stream_id = push.stream(self.pdt.space.name, self.name)
        receiver.expect(stream_id, h.root, h.push_parts)
        return not self.held(h.root) and receiver.check(stream_id, h.root) == push.WAIT

    def _late(self, entry_id: str, cause: str) -> None:
        if (entry_id, cause) not in self.late:
            self.late.add((entry_id, cause))
            self.heads_late[cause] += 1

    def _fetch(self, h: Head, others_first: bool = False):
        """The fetch of a head's root: the one under way, else a new one unless a failed one's backoff still runs. A
        first fetch asks the issuer; a retry, and the fetch after a push's grace, ask the other holders of the root,
        the issuer behind them (swarm retries, ROBUSTNESS.md §10.3 E1, P4, P6)."""
        running = self.fetching.get(h.root)
        if running is not None and not running.done.is_set():
            return running
        retry = self.retries.get(h.root)
        if retry is not None and time.monotonic() < retry[1]:
            return None
        issuer = h.issuer.split("/", 1)[0]
        prefer = [issuer]
        if retry is not None or others_first:
            others = [x.get("holder") for x in self.pdt.trees.holders(h.root) if x.get("holder") not in (None, issuer)]
            prefer = others or prefer
        haves = [r for r in self._retained_roots() if r != h.root][:MAX_BASE]
        f = self.pdt.trees.fetch_tree(h.root, haves=haves, prefer=prefer, timeout=self.pdt.load_timeout)
        self.fetching[h.root] = f
        return f

    def _settle_fetches(self) -> None:
        """Forgets finished fetches; a failed one schedules the next after a backoff that doubles with each failure,
        with a random spread, so the members that missed one root do not all ask again together."""
        now = time.monotonic()
        for root, f in list(self.fetching.items()):
            if not f.done.is_set():
                continue
            del self.fetching[root]
            if f.complete or self.held(root):
                self.retries.pop(root, None)
                continue
            retry = self.retries.setdefault(root, [0, 0.0])
            retry[0] += 1
            cap = max(RETRY_BASE_S, self.pdt.load_timeout * UNLOADABLE_BACKOFF)
            wait = min(cap, RETRY_BASE_S * 2 ** (retry[0] - 1))
            retry[1] = now + wait + random.uniform(0, wait / 2)

    def _retained_roots(self) -> list[str]:
        return [r for r in self.known if r in self.complete_roots or self.store.complete(r)]

    def heads(self, wait: bool = True) -> list[Head]:
        """The heads in merge order (PD-R-02); a head whose root cannot load within the timeout is ignored."""
        with self._lock:
            live = self._live_entries()
            return heads_among(self._loadable(live, wait))

    def _value_of(self, root: str, store=None):
        store = store or self.store
        value = self.kind.load(store, root, self.pdt.loader)
        if self.kind.name == KIND_BLOB:
            value.claim = self.claims.get(root)
        return value

    def deref(self):
        """The ref's value: the single head's, or the merge of §3.6.1; never writes."""
        with self._lock:
            heads = self.heads(True)
            if not heads:
                return self.kind.empty(self.store, self.pdt.loader)
            self.last_heads = heads
            return self._materialize(heads, self.store)

    def _conflict(self, event: PConflict) -> None:
        self.conflicts += 1
        self.pdt.conflicts += 1
        for listener in list(self.conflict_listeners):
            try:
                listener(event)
            except Exception:
                pass

    def _materialize(self, heads: list[Head], store):
        if len(heads) == 1:
            return self._value_of(heads[0].root, store)
        fn = self.pdt.merge_functions.get(self.name)
        latest = heads[-1]
        if fn is None and not self.kind.by_key:
            for other in heads[:-1]:
                self._conflict(PConflict(self.name, None, latest.root, other.root, WHOLE_HEAD))
            return self._value_of(latest.root, store)
        base_root = self._common_base(heads)
        if base_root is None and fn is None:
            for other in heads[:-1]:
                self._conflict(PConflict(self.name, None, latest.root, other.root, NO_COMMON_BASE))
            return self._value_of(latest.root, store)
        base = None if base_root is None else (self.kind.empty(store, self.pdt.loader) if base_root == EMPTY_BASE
                                                else self._value_of(base_root, store))
        acc = self._value_of(heads[0].root, store)
        for i in range(1, len(heads)):
            later, earlier = heads[i], heads[i - 1]
            later_value = self._value_of(later.root, store)
            if fn is not None:
                try:
                    merged = fn(base, acc, later_value)
                    if merged is None:
                        raise ValueError("the merge function returned None")
                    acc = merged
                    continue
                except Exception:
                    self.pdt.merge_function_failures += 1
                    self._conflict(PConflict(self.name, None, later.root, earlier.root, MERGE_FUNCTION_FAILED))
                    if not self.kind.by_key or base_root is None:
                        acc = later_value
                        continue

            def resolver(key, b, mine, theirs, later=later, earlier=earlier):
                self._conflict(PConflict(self.name, key, later.root, earlier.root, LATER_HLC))
                return theirs
            if self.kind.name == KIND_SET:
                acc = _merge_set(acc, base, later_value, resolver)
            else:
                acc = acc.merge3(base, later_value, resolver)
        return acc

    def _walk(self, root: str, sources: list[str] | None = None) -> tuple[list[str], bool]:
        """The roots reachable from ``root`` over base links, breadth first and the root itself
        first, as Refs.java's ancestors lists them: a root first reached at step 64 joins the
        walk and the walk does not follow its bases. With them, whether the walk ends at first
        versions within the bound: every root it reaches is a version this reader knows, and
        every version at step 64 has no base (HLC round five, 2026-11-08, decision E16).
        A version reads its bases from the live entries seen and, when no entry of it was seen,
        from its vg node (PDT 2 phase 7, P2-V-02); with ``sources`` a vg node the store lacks is
        fetched from them by ``NODE_WANT``, as a merge does, and the tick reads only the nodes it holds."""
        seen: dict[str, None] = {}
        complete = True
        frontier = [(root, 0)]
        while frontier:
            cid, depth = frontier.pop(0)
            if cid in seen:
                continue
            seen[cid] = None
            bases = self._bases(cid, sources)
            if bases is None:
                complete = False
                continue
            if depth >= MAX_BASE_STEPS:
                complete = complete and not bases
                continue
            self._learn_parents(cid, bases, sources)
            for b in bases:
                if b not in seen:
                    frontier.append((b, depth + 1))
        return list(seen), complete

    def _bases(self, root: str, sources: list[str] | None) -> tuple | None:
        """A version's bases: from the entries seen, else from its vg node; None when neither describes it."""
        version = self.known.get(root)
        if version is not None:
            return version.base
        node = self._chain_node(root, sources)
        return None if node is None else node.bases

    def _chain_node(self, root: str, sources: list[str] | None) -> VgNode | None:
        """The vg node of a version, read before or now through the CID its head or a child's link named. A node that
        does not hash to its CID or names another root leaves the version without ancestry (P2-V-02)."""
        node = self.chain.get(root)
        if node is not None:
            return node
        cid = self.ancestry.get(root)
        if cid is None:
            return None
        data = self._chain_bytes(cid, sources)
        if data is None:
            return None
        try:
            node = VgNode.decode(cid, data)
        except nodes.NodeFormatError:
            node = None
        if node is None or node.root != root or not cids.verifies(cid, data):
            self.ancestry.pop(root, None)
            return None
        self.chain[root] = node
        self.pdt.chain_nodes_read += 1
        return node

    def _chain_bytes(self, cid: str, sources: list[str] | None) -> bytes | None:
        """A vg node from the store, else, with ``sources``, by ``NODE_WANT`` from them first and then the holders.
        A node whose fetch failed is asked for again only after a backoff that doubles with each failure, with a
        random spread (swarm retries, ROBUSTNESS.md §10.2), so a head that names a node nobody holds costs each merge
        no load timeout."""
        data = self.store.get(cid)
        if data is not None or sources is None:
            return data
        miss = self.chain_misses.get(cid)
        now = time.monotonic()
        if miss is not None and now < miss[1]:
            return None
        try:
            data = self.pdt.trees.load(cid, prefer=sources, timeout=self.pdt.load_timeout)
        except nodes.NodeUnavailable:
            self.pdt.chain_nodes_missed += 1
            miss = self.chain_misses.setdefault(cid, [0, 0.0])
            miss[0] += 1
            wait = min(max(RETRY_BASE_S, self.pdt.load_timeout * UNLOADABLE_BACKOFF), RETRY_BASE_S * 2 ** (miss[0] - 1))
            miss[1] = time.monotonic() + wait + random.uniform(0, wait / 2)
            while len(self.chain_misses) > CHAIN_MISSES_KEPT:
                del self.chain_misses[next(iter(self.chain_misses))]
            return None
        self.chain_misses.pop(cid, None)
        return data

    def _learn_parents(self, root: str, bases: tuple, sources: list[str] | None) -> None:
        """Learns which vg node describes each base no entry seen describes: the version's vg node links one per base."""
        if all(b in self.known or b in self.ancestry or b in self.chain for b in bases):
            return
        child = self._chain_node(root, sources)
        if child is None:
            return
        for link in child.previous:
            data = self._chain_bytes(link.cid, sources)
            if data is None or not cids.verifies(link.cid, data):
                continue
            try:
                parent = VgNode.decode(link.cid, data)
            except nodes.NodeFormatError:
                continue
            if parent.root in bases:
                self.ancestry.setdefault(parent.root, link.cid)
                if parent.root not in self.chain:
                    self.chain[parent.root] = parent
                    self.pdt.chain_nodes_read += 1

    def _chain_sources(self, heads: list[Head]) -> list[str]:
        """The peers a walk asks for the vg nodes its store lacks (P2-V-02): the heads' issuers first, then the writer of
        every version this reader knows, as Java's Refs.chainSources lists them. A head's writer may lack the vg node of
        its base, which the base's own writer then alone holds (chain walk sources, srad/agentspaces-pdt2.md §10.20)."""
        return list(dict.fromkeys(h.issuer.split("/", 1)[0] for h in [*heads, *self.known.values()]))

    def _common_base(self, heads: list[Head]) -> str | None:
        """The lowest common base of the heads (PD-R-06): the first root in the latest head's
        walk that every other walk reaches, fetched when the store lacks it. When the walks
        share no root and every walk ends at first versions within the bound, the empty value
        is their base, so the three-way merge keeps every key of every writer (HLC round five,
        2026-11-08, decision E16); otherwise there is none."""
        if all(not h.base for h in heads):
            return EMPTY_BASE
        sources = self._chain_sources(heads)
        walked = [self._walk(h.root, sources) for h in heads]
        walks = [w for w, _ in walked]
        others = [set(w) for w in walks[:-1]]
        for candidate in walks[-1]:
            if not all(candidate in w for w in others):
                continue
            if self.held(candidate):
                return candidate
            issuers = list(dict.fromkeys(h.issuer.split("/", 1)[0] for h in heads))
            haves = [h.root for h in heads if self.held(h.root)][:MAX_BASE]
            f = self.pdt.trees.fetch_tree(candidate, haves=haves, prefer=issuers, timeout=self.pdt.load_timeout)
            f.wait(self.pdt.load_timeout)
            if self.held(candidate):
                self.bases_fetched += 1
                return candidate
            return None
        return EMPTY_BASE if all(complete for _, complete in walked) else None

    # ---- writing

    def swap(self, f: Callable):
        """Applies ``f`` to the current value and publishes the result as a new head (PD-R-03, PD-R-04)."""
        if self.kind.name == KIND_DB:
            raise ValueError("this client reads a db ref and writes none;"
                             " write db refs with DataScript through agentspaces-datascript")
        if self.mode == MODE_LINEAR:
            return self._swap_linear(f)
        with self._lock:
            heads = self.heads(True)
            recording = RecordingStore(self.store)
            current = self._materialize(heads, recording) if heads else self.kind.empty(recording, self.pdt.loader)
            self.last_heads = heads
            new_value = f(current)
            if new_value is None:
                raise ValueError("a swap function returns the new value")
            if getattr(new_value, "store", None) is not recording:
                new_value = _copy_into(new_value, recording, self.kind)
            root = new_value.root()
            return self._publish(new_value, root, heads, recording)

    def _publish(self, new_value, root: str, heads: list[Head], recording: RecordingStore, taken_id: str | None = None):
        if len(heads) == 1 and heads[0].root == root and taken_id is None:
            return new_value  # nothing changed, nothing to publish
        reachable = self.store.reachable(root)
        delta = {cid: data for cid, data in recording.written.items() if cid in reachable}
        total = sum(len(d) for d in delta.values())
        inline = list(delta.values()) if 0 < total <= self.pdt.inline_delta else None
        if total == 0 and self.store.get(root) is not None:
            # a swap back to a held version (an ancestor's content): ship the root node alone
            inline = [self.store.get(root)]
        seq = min(max([h.seq for h in heads], default=0), MAX_SEQ - 1) + 1
        base = [h.root for h in heads][:MAX_BASE]
        vg = self._write_ancestry(root, base)
        record = pref_record(self.name, self.kind.name, root, base, seq, self.kind.size(new_value), inline,
                             self.mode, self.pdt.sealing, self.pdt.key_epoch_for_heads(),
                             None if vg is None else {ANCESTRY_ATTR: vg}, _tree_version(self.store, reachable))
        bad = pref_violation(record)
        if bad:
            raise ValueError(f"the head would be refused by every reader: {bad}")
        self.store.pin(root)
        if vg is not None:
            self.store.pin(vg)  # the writer holds its vg node while the head is its own (P2-V-01)
        self.complete_roots.add(root)
        entry_id = self.pdt.write_head(record)
        now = self.pdt.peer._now_ms()
        # an older own entry for the same root (a revert within the grace) is displaced, and the own heads this
        # one supersedes start their grace, as Java's Refs.write marks them (PDT 2 phase 7, P2-X-05)
        superseded = {h.root for h in heads}
        for own in self.own.values():
            if own["root"] == root:
                own["displaced"] = True
            elif own["root"] in superseded and own["superseded_at"] is None:
                own["superseded_at"] = now
        self.own[entry_id] = {"root": root, "base": tuple(base), "renewed_at": now, "lease": self.pdt.head_lease_ms,
                              "superseded_at": None, "displaced": False, "vg": vg}
        if inline is None:
            self.pdt.trees.hold(root)
        else:
            self.pdt.trees.follow(root)
        if taken_id is not None:
            self.pdt.peer.complete_entry(self.pdt.space.name, taken_id, agent=self.pdt.space.agent)
        self.pdt.swaps += 1
        return new_value

    def _write_ancestry(self, root: str, base: list[str]) -> str | None:
        """Writes the vg node of a new version and returns its CID for ``pdt.ancestry`` (PDT 2 phase 7,
        P2-V-01): the root, the bases, this writer, a stamp of now, and a link to the vg node of each base that has
        one, in the order of the bases. No value root links it and no head carries it inline (rule 4). None, and no
        chain, over the sealed-nodes mode, where a keyless member could not read it."""
        if self.pdt.sealing == SEALING_SEALED_NODES:
            return None
        issuer = self.pdt.space_agent_id()
        previous = [nodes.Link(self.ancestry[b]) for b in base if b in self.ancestry]
        node = VgNode(root, base, issuer, f"{self.pdt.peer._now_ms()}:0:{issuer}", previous)
        cid = self.store.put(node.encode())
        self.ancestry.setdefault(root, cid)
        self.chain.setdefault(root, node)
        return cid

    def _takes(self, payload, tags: dict) -> bool:
        """Whether a linear swap may take an entry: a head of this name whose payload decodes
        as a PRef, as Java's take decodes each candidate and passes over one that does not
        (ReplicatedSpace.decodeIfMatches), so a hostile entry tagged with the name never
        becomes the taken head (HLC round six, 2026-11-08, R1, R3)."""
        return tags.get(NAME_TAG) == self.name and pref_of(payload) is not None

    def _swap_linear(self, f: Callable):
        peer, space = self.pdt.peer, self.pdt.space
        for attempt in range(self.pdt.take_retries + 1):
            with self._lock:
                live = self._live_entries()
            if not live:
                with self._lock:
                    heads = self.heads(True)
                    if not heads:
                        recording = RecordingStore(self.store)
                        new_value = f(self.kind.empty(recording, self.pdt.loader))
                        if getattr(new_value, "store", None) is not recording:
                            new_value = _copy_into(new_value, recording, self.kind)
                        return self._publish(new_value, new_value.root(), [], recording)
            taken = peer.take_entry(space.name, PREF_TYPE, agent_name=space.agent_name,
                                    lease_millis=self.pdt.take_lease_ms, settle_seconds=self.pdt.take_settle,
                                    timeout_seconds=self.pdt.take_timeout_s, agent=space.agent,
                                    matches=self._takes)
            if taken is None:
                continue
            with self._lock:
                self._live_entries()
                dto = peer.states.get(taken)
                root = decode_pref(peer.payload_of(dto))["root"]
                head = self.known.get(root)
                heads = self._loadable([head], True) if head else []
                if not heads:
                    peer.complete_entry(space.name, taken, agent=space.agent)
                    raise nodes.NodeUnavailable(root, [], f"the taken head of {self.name} could not be loaded")
                recording = RecordingStore(self.store)
                current = self._value_of(head.root, recording)
                self.last_heads = heads
                new_value = f(current)
                if getattr(new_value, "store", None) is not recording:
                    new_value = _copy_into(new_value, recording, self.kind)
                return self._publish(new_value, new_value.root(), heads, recording, taken_id=taken)
        raise TimeoutError(f"could not take the head of {self.name} in {self.pdt.take_retries + 1} attempts")

    # ---- watching and history

    def watch(self, listener: Callable) -> Callable:
        """Calls ``listener(value)`` on the tick after a new head arrives and loads (PD-R-07)."""
        self.watchers.append(listener)
        return lambda: self.watchers.remove(listener)

    def on_conflict(self, listener: Callable) -> Callable:
        self.conflict_listeners.append(listener)
        return lambda: self.conflict_listeners.remove(listener)

    def history(self, n: int) -> list[Head]:
        """Up to ``n`` earlier versions, newest first, over the held base links (PD-R-09)."""
        if n <= 0:
            return []
        with self._lock:
            heads = self.last_heads or self.heads(False)
            exclude = {h.root for h in heads}
            out, seen = [], set()
            frontier = [h.root for h in heads]
            while frontier and len(out) < n:
                cid = frontier.pop(0)
                if cid in seen:
                    continue
                seen.add(cid)
                version = self.known.get(cid)
                if version is None:
                    continue
                if cid not in exclude and self.held(cid):
                    out.append(version)
                frontier.extend(version.base)
            return out

    def at(self, root: str):
        if self.held(root) or self.pdt.follow == FOLLOW_LAZY:
            return self._value_of(root)
        raise nodes.NodeUnavailable(root, [], f"version {root} of {self.name} is not held")

    def tick(self) -> None:
        if self.pdt.follow != FOLLOW_LAZY and (self.fetching or self.retries):
            self._retry()
        if self.own:
            self._tend_own()
        if self.watchers:
            heads = self.heads(True)
            roots = tuple(h.root for h in heads)
            if roots and roots != self.delivered_roots:
                self.delivered_roots = roots
                self.last_heads = heads
                value = self._materialize(heads, self.store)
                for listener in list(self.watchers):
                    try:
                        listener(value)
                    except Exception:
                        pass

    def _tend_own(self) -> None:
        """Renews this writer's live heads at half their lease and cancels each own head the grace after it was
        superseded, as Java's ``Refs.tick`` does (PDT 2 phase 7, P2-X-05). An own head is superseded while it lies
        below the lowest common base of the held heads (``_cancellable``), or once an own entry for the same root
        displaced it and none of its bases is live; it stays while a fork still walks through it, so a lagging
        reader finds a base, and its grace starts again when it stops being superseded."""
        peer, space = self.pdt.peer, self.pdt.space
        now = peer._now_ms()
        with self._lock:
            live = self._live_entries()
            cancellable = self._cancellable(live)
        live_roots = {h.root for h in live}
        for entry_id, own in list(self.own.items()):
            dto = peer.states.get(entry_id)
            if dto is None or not present(dto):
                self.own.pop(entry_id, None)  # completed by a take, withdrawn, or gone
                continue
            superseded = own["root"] in cancellable or (own["displaced"] and live_roots.isdisjoint(own["base"]))
            if superseded and own["superseded_at"] is None:
                own["superseded_at"] = now
            elif not superseded:
                own["superseded_at"] = None
            if own["superseded_at"] is not None:
                if now - own["superseded_at"] >= CANCEL_GRACE_MS:
                    try:
                        peer.cancel_entry(space.name, entry_id, agent=space.agent)
                    except ValueError:
                        pass  # the entry lapsed or was consumed meanwhile
                    self.own.pop(entry_id, None)
                    if own["vg"] is not None:
                        self.store.unpin(own["vg"])
                    if not any(o["root"] == own["root"] for o in self.own.values()):
                        self.store.unpin(own["root"])
                continue
            if now - own["renewed_at"] >= own["lease"] // 2:
                try:
                    peer.renew_entry(space.name, entry_id, own["lease"], agent=space.agent)
                    own["renewed_at"] = now
                except Exception:
                    self.own.pop(entry_id, None)

    def _cancellable(self, live: list[Head]) -> set[str]:
        """The roots a writer may cancel, as Java's ``Refs.cancellable``: the strict ancestors of the lowest common
        base of the held heads. A live head this reader does not hold yet but still expects (its fetch never failed)
        bounds that base from below, since the base the fleet picks once it lands lies no higher. Empty when no head
        is held or the walks share no base within the bound."""
        loadable, arriving = [], []
        for h in live:
            if h.entry_id in self.ignored:
                continue
            if self.held(h.root):
                loadable.append(h)
            elif self.pdt.follow != FOLLOW_LAZY and h.root not in self.retries:
                arriving.append(h)
        heads = heads_among(loadable)
        if not heads:
            return set()
        others = [set(self._walk(h.root)[0]) for h in heads[:-1]] + [set(self._walk(h.root)[0]) for h in arriving]
        lowest = next((c for c in self._walk(heads[-1].root)[0] if all(c in w for w in others)), None)
        if lowest is None:
            return set()
        return set(self._walk(lowest)[0]) - {lowest}

    def _retry(self) -> None:
        """Swarm retries (ROBUSTNESS.md §10.3 E1): a live head whose fetch failed is fetched again from the tick once
        its backoff ends, with no read needed; the nodes stored before stay, so the fetch asks only for the rest."""
        with self._lock:
            self._settle_fetches()
            live = self._live_entries()
            roots = {h.root for h in live}
            self.retries = {r: v for r, v in self.retries.items() if r in roots}
            now = time.monotonic()
            for h in live:
                retry = self.retries.get(h.root)
                if (retry is not None and now >= retry[1] and h.entry_id not in self.ignored and h.root not in self.fetching
                        and not self.held(h.root)):
                    self._fetch(h)

    def stats(self) -> dict:
        return {"heads": len(self.last_heads), "deltasInline": self.deltas_inline, "deltasFetched": self.deltas_fetched,
                "conflicts": self.conflicts, "headsIgnored": self.heads_ignored, "headsLate": sum(self.heads_late.values()),
                "headsLateBy": dict(self.heads_late), "nodesDropped": self.nodes_dropped,
                "basesFetched": self.bases_fetched, "known": len(self.known)}


def _tree_version(store, reachable) -> int:
    """The version a head over a tree takes (P2-F-06, §6.10.3 rules 1 to 3 and 8): 2 when the tree holds a node of a
    kind outside annex H's level-1 set or a text value, inline or spilled, else 1."""
    for cid in reachable:
        if cids.codec_of(cid) != cids.DAG_CBOR:
            continue
        data = store.get(cid)
        if data is None:
            continue
        if nodes.kind_of(data) in LEVEL_TWO_KINDS:
            return VERSION_2
        if TEXT_PREFIX in data and _holds_text(nodes.decode(data, cid)):
            return VERSION_2
    return VERSION


def _holds_text(item) -> bool:
    if isinstance(item, nodes.Embedded):
        return is_text(item.bytes)
    if isinstance(item, dict):
        return any(_holds_text(v) for v in item.values())
    if isinstance(item, (list, tuple)):
        return any(_holds_text(v) for v in item)
    return False


def nodes_sha(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()


def _copy_into(value, store, kind: _Kind):
    """A value built over another store, copied into this swap's recording store."""
    root = value.root()
    for cid in value.store.reachable(root):
        data = value.store.get(cid)
        if data is not None:
            store.put_verified(cid, data)
    return kind.load(store, root, value.loader if hasattr(value, "loader") else None)


def _merge_set(mine: PSet, base: PSet, theirs: PSet, resolver) -> PSet:
    """The set merge: presence decides, a key added on one side and removed on the other asks the resolver."""
    my_diff = mine.as_map().diff_raw(base.as_map())
    their_diff = theirs.as_map().diff_raw(base.as_map())
    out = mine.as_map()
    for kb, (before, after) in their_diff.items():
        my = my_diff.get(kb)
        if my is None:
            out = out.dissoc_raw(kb) if after is None else out.assoc_raw(kb, PSet.NULL)
            continue
        if (my[1] is None) == (after is None):
            continue
        key = cbor.loads(kb)
        kept = resolver(key, before is not None, my[1] is not None, after is not None)
        out = out.assoc_raw(kb, PSet.NULL) if kept else out.dissoc_raw(kb)
    return PSet(out)


# ------------------------------------------------------------------ the facade

class Pdt:
    """The facade of §7.2 in Python: a node store, the tree exchange over the
    content swarm, and refs in a space.

    ``content`` is the peer's ``Content``; ``space`` the ref space (its heads are
    ordinary signed, leased entries). ``keys`` (epoch to 32-byte content key)
    turns on ``group-key`` sealing of ``NODES`` answers; ``sealing`` is what the
    heads carry. ``follow`` is ``"full"`` (fetch the delta when a head arrives)
    or ``"lazy"`` (load on access); ``mode`` maps ref names to ``"linear"``."""

    def __init__(self, content, space: Space, store: NodeStore | None = None, *, trees: Trees | None = None,
                 keys: dict[int, bytes] | None = None, write_epoch: int = 0, sealing: str = SEALING_NONE,
                 inline_delta: int = INLINE_DELTA_BYTES, head_lease="10m", load_timeout: float = 10.0,
                 follow: str = FOLLOW_FULL, mode: dict | None = None, take_lease="30s", take_timeout="15s",
                 take_retries: int = 3, take_settle: float = 0.6, advertise: bool = True, seed: int | None = None,
                 push: bool = False):
        self.content = content
        self.space = space
        self.peer = space.peer
        self.store = store if store is not None else (trees.store if trees is not None else NodeStore())
        self.trees = trees or Trees(content, self.store, keys=keys, write_epoch=write_epoch, advertise=advertise,
                                    load_timeout=load_timeout, seed=seed)
        self.keys = dict(keys or {})
        self.write_epoch = write_epoch
        self.sealing = sealing
        self.inline_delta = inline_delta
        self.head_lease_ms = duration_millis(head_lease)
        self.load_timeout = load_timeout
        self.follow = follow
        self.modes = dict(mode or {})
        self.take_lease_ms = duration_millis(take_lease)
        self.take_timeout_s = duration_millis(take_timeout) / 1000
        self.take_retries = take_retries
        self.take_settle = take_settle
        self.refs: dict[str, Ref] = {}
        self.merge_functions: dict[str, Callable] = {}
        self.merge_function_failures = 0
        self.conflicts = 0
        self.swaps = 0
        self.loader = StoreThenFetchLoader(self.store, self._fetch_one)
        # PDT 2 phase 7, P2-P-02: with push on, a full follower takes each ref's pushed bundles from its stream
        self.push = (_push.PushReceiver(self.store, clock=self.peer._now_ms)
                     if push and follow == FOLLOW_FULL else None)
        self._running = False
        self._thread = None
        self.payloads_read = 0
        self.chain_nodes_read = 0
        self.chain_nodes_missed = 0
        #: The replica id this facade's texts edit under (P2-T-02): eight base32 characters of its agent id.
        self.replica = replica_of(self.space_agent_id())
        # the space read path hands dag-cbor payload roots here (PD-E-01, PD-C-04)
        self.peer.pdt = self
        # PDT 2 phase 2: ask for the heads written before this facade started, as the TypeScript facade
        # pulls each ref space it opens (HLC round six, R11); the peer re-pulls the space on a reconnect
        self.peer.pull_space(space.name)

    # ---- escalated space payloads (group E)

    def payload(self, root: str) -> bytes | None:
        """The bytes of an escalated space payload (srad/agentspaces-pdt.md §3.7, PD-E-01, PD-E-03):
        reassembled when the store holds the tree whole, else None after starting one tree fetch
        for the root, as ``Content.local`` and ``Content.ensure`` do for a flat artifact; reads
        never block on the network."""
        cids.parse(root)
        if self.store.complete(root):
            data = read_payload(root, Ctx(StoreLoader(self.store), self.store))
            self.payloads_read += 1
            return data
        self.trees.fetch_tree(root)
        return None

    def _fetch_one(self, cid: str) -> bytes:
        # PDT 2 phase 8, P2-O-03: a lazy read asks the issuers of the heads this facade knows first, as the Java reader
        # prefers the issuer (PD-S-06): a head whose delta rode inline has no holding, and once a take or a cancel
        # removed the head before it, no followed root has a holder for the nodes the two versions share
        issuers = list(dict.fromkeys(h.issuer.split("/", 1)[0] for ref in list(self.refs.values())
                                     for h in list(ref.known.values())))
        return self.trees.load(cid, prefer=issuers, timeout=self.load_timeout)

    def space_agent_id(self) -> str:
        """The agent id this facade writes heads as: the ref space's agent, else this peer under the space's name."""
        agent = self.space.agent
        return agent.agent_id if agent is not None else f"{self.peer.identity.peer_id}/{self.space.agent_name}"

    def key_epoch_for_heads(self) -> int | None:
        return self.write_epoch if self.sealing != SEALING_NONE and self.keys else None

    def write_head(self, record: dict) -> str:
        return self.peer.write_entry(self.space.name, PREF_TYPE, record, agent_name=self.space.agent_name,
                                     lease_millis=self.head_lease_ms, agent=self.space.agent, tags=pref_tags(record))

    # ---- refs

    def ref(self, name: str, kind: str = KIND_MAP, mode: str | None = None) -> Ref:
        if len(name.encode("utf-8")) > MAX_NAME_BYTES or not name:
            raise ValueError("a ref name is 1 to 256 bytes")
        ref = self.refs.get(name)
        if ref is None:
            ref = Ref(self, name, kind, mode or self.modes.get(name, MODE_MULTI))
            self.refs[name] = ref
            if self.push is not None:
                stream_id = _push.stream(self.space.name, name)
                self.push.follow(stream_id)
                self.peer.on_stream(stream_id, lambda _sender, _item, payload: self.push.on_bundle(stream_id, payload))
        elif ref.kind.name != kind:
            raise ValueError(f"ref {name} is a {ref.kind.name}, asked for as a {kind}")
        return ref

    def map_ref(self, name: str, mode: str | None = None) -> Ref:
        return self.ref(name, KIND_MAP, mode)

    def set_ref(self, name: str, mode: str | None = None) -> Ref:
        return self.ref(name, KIND_SET, mode)

    def vector_ref(self, name: str, mode: str | None = None) -> Ref:
        return self.ref(name, KIND_VECTOR, mode)

    def blob_ref(self, name: str, mode: str | None = None) -> Ref:
        return self.ref(name, KIND_BLOB, mode)

    def db_ref(self, name: str) -> Ref:
        """A DataScript database ref (PDT 2 phase 7, P2-C-01 group D): ``deref`` gives a lazy ``DbReader`` of the head
        that agentspaces-datascript wrote, or None before the first; this client never writes one."""
        return self.ref(name, KIND_DB)

    def merge_for(self, name: str, fn: Callable) -> None:
        """Registers ``fn(base, earlier, later)`` as the merge of a name's heads on this reader."""
        self.merge_functions[name] = fn

    # ---- values without a ref

    def pmap(self) -> PMap:
        return PMap.empty(self.store, self.loader)

    def pvector(self) -> PVector:
        return PVector.empty(self.store, self.loader)

    def blob(self, source) -> PBlob:
        return PBlob.of(source, self.store)

    # ---- driving

    def tick(self) -> None:
        self.trees.tick()
        if self.push is not None:
            self.push.expire()
        for ref in list(self.refs.values()):
            try:
                ref.tick()
            except Exception:
                pass

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

        self._thread = threading.Thread(target=loop, name="pdt-tick", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._running = False

    def stats(self) -> dict:
        out = {"refs": len(self.refs), "heads": sum(len(r.last_heads) for r in self.refs.values()),
               "deltasInline": sum(r.deltas_inline for r in self.refs.values()),
               "deltasFetched": sum(r.deltas_fetched for r in self.refs.values()), "conflicts": self.conflicts,
               "headsIgnored": sum(r.heads_ignored for r in self.refs.values()),
               "headsLate": sum(sum(r.heads_late.values()) for r in self.refs.values()),
               "nodesDropped": sum(r.nodes_dropped for r in self.refs.values()),
               "basesFetched": sum(r.bases_fetched for r in self.refs.values()), "swaps": self.swaps,
               "mergeFunctionFailures": self.merge_function_failures, "chainNodesRead": self.chain_nodes_read,
               "chainNodesMissed": self.chain_nodes_missed}
        if self.push is not None:
            out.update({"push" + name[0].upper() + name[1:]: count for name, count in self.push.stats().items()})
        out.update(self.store.stats())
        return out

