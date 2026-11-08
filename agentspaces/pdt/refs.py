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
whole (``WHOLE_HEAD``) unless a merge function is registered for the name;
past the walk bound or without the base the later head wins whole
(``NO_COMMON_BASE``)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

from .. import cbor, wire
from ..space import Space, duration_millis
from . import cids, nodes
from .blob import PBlob
from .champ import PMap, PSet
from .store import NodeStore, RecordingStore
from .tree import Trees
from .values import Ctx, StoreLoader, StoreThenFetchLoader, read_payload
from .vector import PVector

PREF_TYPE = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1"
VERSION = 1
NAME_TAG, ROOT_TAG = "name", "root"
KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE = "map", "set", "vector", "blob", "tree"
KINDS = {KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE}
MODE_MULTI, MODE_LINEAR = "multi", "linear"
SEALING_NONE, SEALING_GROUP_KEY, SEALING_SEALED_NODES = "none", "group-key", "sealed-nodes"
MAX_NAME_BYTES = 256
MAX_BASE = 8
INLINE_DELTA_BYTES = 32 * 1024
MAX_ATTRS, MAX_ATTRS_BYTES = 32, 4 * 1024
MAX_MODE_BYTES = 32
MAX_SEQ = 1 << 53
MAX_BASE_STEPS = 64
ISSUED_ATTR, ISSUER_ATTR = "pdt.issued", "pdt.issuer"
FOLLOW_FULL, FOLLOW_LAZY = "full", "lazy"
EMPTY_BASE = ""

LATER_HLC, WHOLE_HEAD, NO_COMMON_BASE, MERGE_FUNCTION_FAILED = "LATER_HLC", "WHOLE_HEAD", "NO_COMMON_BASE", "MERGE_FUNCTION_FAILED"


# ------------------------------------------------------------------ the record

def pref_record(name: str, kind: str, root: str, base: list[str] | None = None, seq: int = 1, size: int = 0,
                node_list: list[bytes] | None = None, mode: str = MODE_MULTI, sealing: str = SEALING_NONE,
                key_epoch: int | None = None, attrs: dict | None = None) -> dict:
    """A ``PRef`` value in Java field order; ``nodes``, ``keyEpoch``, and ``attrs`` leave the wire when None."""
    record = {"v": VERSION, "name": name, "kind": kind, "root": root, "base": list(base or []),
              "seq": int(seq), "size": int(size)}
    if node_list is not None:
        record["nodes"] = [bytes(n) for n in node_list]
    record["mode"] = mode
    record["sealing"] = sealing
    if key_epoch is not None:
        record["keyEpoch"] = int(key_epoch)
    if attrs is not None:
        record["attrs"] = cbor.canonical_map({str(k): str(v) for k, v in attrs.items()})
    return record


def pref_tags(record: dict) -> dict:
    return {NAME_TAG: record["name"], ROOT_TAG: record["root"]}


def pref_violation(r: dict) -> str | None:
    """The first broken bound of §3.6 as pinned in 10.2, or None."""
    try:
        if r.get("v") != VERSION:
            return f"unsupported PRef version {r.get('v')}"
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
            if sum(len(str(k).encode()) + len(str(v).encode()) for k, v in attrs.items()) > MAX_ATTRS_BYTES:
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

    def order(self) -> tuple:
        peer = self.issuer.split("/", 1)[0].encode("utf-8")
        return (self.issued[0], self.issued[1], peer, self.root)


def _hlc(stamp) -> tuple:
    """The stamp's ``(physical, logical, node)``, read as Refs.java reads it with
    HlcTimestamp.parse (HLC logical counter, 2026-11-08 (Rust team report)), so Java and
    this client order heads alike; ``(0, 0, "")`` when that parse fails, which keeps the
    entry's own stamp in place of an advisory one."""
    return wire.parse_hlc(stamp) or (0, 0, "")


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
                     lambda store, root, loader=None: PBlob.load(store, root), lambda v: v.size()),
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
        self.unloadable: set[str] = set()
        self.own: dict[str, dict] = {}         # entry id -> {"root", "written_at", "lease"}
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
        self.bases_fetched = 0
        self.conflicts = 0
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
        peer, space = self.pdt.peer, self.pdt.space
        space_id = space._space_id()
        now = peer._now_ms()
        live = []
        for entry_id, dto in list(peer.states.items()):
            record = dto.get("record") or {}
            if record.get("type") != PREF_TYPE or record.get("spaceId") != space_id or dto.get("completed"):
                continue
            if (record.get("tags") or {}).get(NAME_TAG) != self.name:
                continue
            if int((record.get("lease") or {}).get("expiresAtMillis", 0)) <= now:
                continue
            raw = peer.payload_of(dto)
            if raw is None:
                continue
            try:
                value = cbor.loads(raw)
            except ValueError:
                continue
            if not isinstance(value, dict) or pref_violation(value) is not None or value["kind"] != self.kind.name:
                continue
            issued, issuer = _hlc(record.get("issued")), str(record.get("issuer"))
            attrs = value.get("attrs") or {}
            if attrs.get(ISSUED_ATTR) and attrs.get(ISSUER_ATTR):
                stamped = _hlc(attrs[ISSUED_ATTR])
                if stamped != (0, 0, ""):
                    issued, issuer = stamped, attrs[ISSUER_ATTR]
            head = Head(value["root"], tuple(value.get("base") or []), value["seq"], value["size"], value["kind"],
                        value["mode"], issuer, issued, entry_id, int(record["lease"]["expiresAtMillis"]))
            known = self.known.get(head.root)
            if known is None or head.seq > known.seq:
                base = tuple(dict.fromkeys(list(known.base) + list(head.base))) if known else head.base
                self.known[head.root] = Head(head.root, base, head.seq, head.size, head.kind, head.mode, head.issuer,
                                             head.issued, head.entry_id, head.expires_at_millis)
            elif known is not None and set(head.base) - set(known.base):
                self.known[head.root] = Head(known.root, tuple(dict.fromkeys(list(known.base) + list(head.base))),
                                             known.seq, known.size, known.kind, known.mode, known.issuer, known.issued,
                                             known.entry_id, known.expires_at_millis)
            if value.get("nodes") and not self.held(head.root) and head.entry_id not in self.ignored:
                self._apply_inline(head.root, value["nodes"])
            live.append(head)
        return live

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
        waiting = []
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
                    pass
                continue
            waiting.append(h)
        fetches = []
        for h in waiting:
            haves = [r for r in self._retained_roots() if r != h.root][:MAX_BASE]
            f = self.pdt.trees.fetch_tree(h.root, haves=haves, prefer=[h.issuer.split("/", 1)[0]],
                                          timeout=self.pdt.load_timeout)
            fetches.append((h, f))
        if wait and fetches:
            deadline = time.monotonic() + self.pdt.load_timeout
            for h, f in fetches:
                f.wait(max(0.0, deadline - time.monotonic()))
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
                self.ignored.add(h.entry_id)
                self.heads_ignored += 1
        return out

    def _retained_roots(self) -> list[str]:
        return [r for r in self.known if r in self.complete_roots or self.store.complete(r)]

    def heads(self, wait: bool = True) -> list[Head]:
        """The heads in merge order (PD-R-02); a head whose root cannot load within the timeout is ignored."""
        with self._lock:
            live = self._live_entries()
            return heads_among(self._loadable(live, wait))

    def _value_of(self, root: str, store=None):
        store = store or self.store
        return self.kind.load(store, root, self.pdt.loader)

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

    def _ancestors(self, root: str) -> list[str]:
        seen: dict[str, None] = {}
        frontier = [(root, 0)]
        while frontier:
            cid, depth = frontier.pop(0)
            if cid in seen or depth >= MAX_BASE_STEPS:
                continue
            seen[cid] = None
            version = self.known.get(cid)
            if version is None:
                continue
            for b in version.base:
                if b not in seen:
                    frontier.append((b, depth + 1))
        return list(seen)

    def _common_base(self, heads: list[Head]) -> str | None:
        if all(not h.base for h in heads):
            return EMPTY_BASE
        walks = [self._ancestors(h.root) for h in heads]
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
        return None

    # ---- writing

    def swap(self, f: Callable):
        """Applies ``f`` to the current value and publishes the result as a new head (PD-R-03, PD-R-04)."""
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
        record = pref_record(self.name, self.kind.name, root, base, seq, self.kind.size(new_value), inline,
                             self.mode, self.pdt.sealing, self.pdt.key_epoch_for_heads(), None)
        bad = pref_violation(record)
        if bad:
            raise ValueError(f"the head would be refused by every reader: {bad}")
        self.store.pin(root)
        self.complete_roots.add(root)
        entry_id = self.pdt.write_head(record)
        self.own[entry_id] = {"root": root, "written_at": time.monotonic(), "lease": self.pdt.head_lease_ms}
        if inline is None:
            self.pdt.trees.hold(root)
        else:
            self.pdt.trees.follow(root)
        if taken_id is not None:
            self.pdt.peer.complete_entry(self.pdt.space.name, taken_id, agent=self.pdt.space.agent)
        self.pdt.swaps += 1
        return new_value

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
                                    matches=lambda payload, tags: tags.get(NAME_TAG) == self.name)
            if taken is None:
                continue
            with self._lock:
                self._live_entries()
                dto = peer.states.get(taken)
                record = cbor.loads(peer.payload_of(dto))
                head = self.known.get(record["root"])
                heads = self._loadable([head], True) if head else []
                if not heads:
                    peer.complete_entry(space.name, taken, agent=space.agent)
                    raise nodes.NodeUnavailable(record["root"], [], f"the taken head of {self.name} could not be loaded")
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
        now = time.monotonic()
        peer, space = self.pdt.peer, self.pdt.space
        for entry_id, own in list(self.own.items()):
            dto = peer.states.get(entry_id)
            if dto is None or dto.get("completed"):
                self.own.pop(entry_id, None)
                continue
            if now - own["written_at"] >= own["lease"] / 2000:
                try:
                    peer.renew_entry(space.name, entry_id, own["lease"], agent=space.agent)
                    own["written_at"] = now
                except Exception:
                    self.own.pop(entry_id, None)
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

    def stats(self) -> dict:
        return {"heads": len(self.last_heads), "deltasInline": self.deltas_inline, "deltasFetched": self.deltas_fetched,
                "conflicts": self.conflicts, "headsIgnored": self.heads_ignored, "nodesDropped": self.nodes_dropped,
                "basesFetched": self.bases_fetched, "known": len(self.known)}


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
                 take_retries: int = 3, take_settle: float = 0.6, advertise: bool = True, seed: int | None = None):
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
        self._running = False
        self._thread = None
        self.payloads_read = 0
        # the space read path hands dag-cbor payload roots here (PD-E-01, PD-C-04)
        self.peer.pdt = self

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
        return self.trees.load(cid, timeout=self.load_timeout)

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
               "nodesDropped": sum(r.nodes_dropped for r in self.refs.values()),
               "basesFetched": sum(r.bases_fetched for r in self.refs.values()), "swaps": self.swaps,
               "mergeFunctionFailures": self.merge_function_failures}
        out.update(self.store.stats())
        return out

