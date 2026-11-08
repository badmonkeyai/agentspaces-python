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

"""``PMap`` and ``PSet``, the CHAMP trie of srad/agentspaces-pdt.md §3.2 and
§10.2 (PD-V-01, PD-V-02, PD-V-04, PD-V-06, PD-V-07, PD-V-09): the key's hash
is sha256 of its canonical CBOR, level ``d`` reads bits ``5d..5d+4`` of the
digest as a big-endian bit string, a node is ``{k:"m", d, n, e, c}`` with
``cnt`` on the root alone, a child left with one entry after a removal inlines
into its parent (canonical compaction), and past level 51 keys sit in an
``mc`` node sorted by key bytes. Nodes load on demand through the loader, and
every lazy load verifies the node's shape at its level (PD-N-04).

Every operation returns a new value and leaves the receiver unchanged;
equality is by root."""

from __future__ import annotations

from typing import Callable, Iterator

from . import cids, nodes, values
from .nodes import NodeFormatError
from .values import Ctx, Flusher, StoreLoader, TreeNode

COLLISION_LEVEL = 52
NOT_FOUND = object()


def index(digest: bytes, level: int) -> int:
    """The five-bit slot of a digest at a level."""
    first = level * 5
    idx = 0
    limit = len(digest) * 8
    for i in range(5):
        bit = first + i
        v = (digest[bit >> 3] >> (7 - (bit & 7))) & 1 if bit < limit else 0
        idx = (idx << 1) | v
    return idx


def _popcount_below(mask: int, bit: int) -> int:
    return bin(mask & (bit - 1)).count("1")


class ChampNode(TreeNode):
    """A node of the trie: kind ``m`` or, past level 51, ``mc``."""

    __slots__ = ("collision", "datamap", "nodemap", "keys", "values", "children", "cnt", "cid")

    def __init__(self, collision: bool, datamap: int, nodemap: int, keys: list, vals: list, children: list):
        self.collision = collision
        self.datamap = datamap
        self.nodemap = nodemap
        self.keys = keys
        self.values = vals
        self.children = children
        self.cnt = -1
        self.cid = None

    @staticmethod
    def empty() -> "ChampNode":
        return ChampNode(False, 0, 0, [], [], [])

    def _copy(self) -> "ChampNode":
        return ChampNode(self.collision, self.datamap, self.nodemap, list(self.keys), list(self.values), list(self.children))

    def _data_index(self, bit: int) -> int:
        return _popcount_below(self.datamap, bit)

    def _node_index(self, bit: int) -> int:
        return _popcount_below(self.nodemap, bit)

    def single_entry(self) -> bool:
        return len(self.keys) == 1 and not self.children

    # ---- reads

    def child(self, i: int, level: int, ctx: Ctx) -> "ChampNode":
        ref = self.children[i]
        if isinstance(ref, ChampNode):
            return ref
        loaded = ChampNode.load(ref, level, ctx)
        self.children[i] = loaded
        return loaded

    @staticmethod
    def load(cid: str, level: int, ctx: Ctx) -> "ChampNode":
        node = ChampNode.decode(cid, ctx.load(cid), False)
        node.verify_at(level)
        return node

    @staticmethod
    def load_root(cid: str, data: bytes) -> "ChampNode":
        node = ChampNode.decode(cid, data, True)
        node.verify_at(0)
        return node

    def verify_at(self, level: int) -> None:
        if self.collision and level < COLLISION_LEVEL:
            raise NodeFormatError(f"collision node at level {level}; keys collide only past level {COLLISION_LEVEL - 1}", self.cid)
        if not self.collision and level >= COLLISION_LEVEL:
            raise NodeFormatError(f"map node at level {level}; keys past level {COLLISION_LEVEL - 1} sit in a collision node", self.cid)
        if self.collision:
            return
        remaining = self.datamap
        for i, key in enumerate(self.keys):
            slot = (remaining & -remaining).bit_length() - 1
            remaining &= remaining - 1
            named = index(values.sha256(key), level)
            if named != slot:
                raise NodeFormatError(f"entry {i} sits in slot {slot} at level {level} where its key digest names slot {named}", self.cid)

    def find(self, digest: bytes, level: int, key: bytes, ctx: Ctx):
        node = self
        while True:
            if node.collision:
                for i, k in enumerate(node.keys):
                    if k == key:
                        return node.values[i]
                return NOT_FOUND
            bit = 1 << index(digest, level)
            if node.datamap & bit:
                i = node._data_index(bit)
                return node.values[i] if node.keys[i] == key else NOT_FOUND
            if node.nodemap & bit:
                level += 1
                node = node.child(node._node_index(bit), level, ctx)
                continue
            return NOT_FOUND

    def entries(self, level: int, ctx: Ctx):
        """Every (key, value ref) under this node, entries before children, in slot order."""
        out = []
        stack = [(self, level)]
        while stack:
            node, lvl = stack.pop()
            out.extend(zip(node.keys, node.values))
            for i in range(len(node.children) - 1, -1, -1):
                stack.append((node.child(i, lvl + 1, ctx), lvl + 1))
        return out

    def depth(self, level: int, ctx: Ctx) -> int:
        deepest = 1
        for i in range(len(self.children)):
            deepest = max(deepest, 1 + self.child(i, level + 1, ctx).depth(level + 1, ctx))
        return deepest

    # ---- writes

    def assoc(self, digest: bytes, level: int, key: bytes, value, ctx: Ctx):
        """Returns ``(node, change)`` with change None, ``"added"``, or ``"replaced"``."""
        if self.collision:
            return self._assoc_collision(key, value)
        bit = 1 << index(digest, level)
        if self.datamap & bit:
            i = self._data_index(bit)
            if self.keys[i] == key:
                if values.same_value(self.values[i], value):
                    return self, None
                n = self._copy()
                n.values[i] = value
                return n, "replaced"
            other_digest = ctx.hash(self.keys[i])
            sub = _merge_two(self.keys[i], self.values[i], other_digest, key, value, digest, level + 1)
            n = self._copy()
            del n.keys[i]
            del n.values[i]
            n.datamap &= ~bit
            n.nodemap |= bit
            n.children.insert(n._node_index(bit), sub)
            return n, "added"
        if self.nodemap & bit:
            i = self._node_index(bit)
            child = self.child(i, level + 1, ctx)
            nxt, change = child.assoc(digest, level + 1, key, value, ctx)
            if change is None or nxt is child:
                return self, change
            n = self._copy()
            n.children[i] = nxt
            return n, change
        n = self._copy()
        n.datamap |= bit
        at = n._data_index(bit)
        n.keys.insert(at, key)
        n.values.insert(at, value)
        return n, "added"

    def _assoc_collision(self, key: bytes, value):
        pos = 0
        while pos < len(self.keys):
            k = self.keys[pos]
            if k == key:
                if values.same_value(self.values[pos], value):
                    return self, None
                n = self._copy()
                n.values[pos] = value
                return n, "replaced"
            if k > key:
                break
            pos += 1
        n = self._copy()
        n.keys.insert(pos, key)
        n.values.insert(pos, value)
        return n, "added"

    def dissoc(self, digest: bytes, level: int, key: bytes, ctx: Ctx):
        """Returns ``(node, removed)`` where removed is the old value or NOT_FOUND."""
        if self.collision:
            for i, k in enumerate(self.keys):
                if k == key:
                    n = self._copy()
                    del n.keys[i]
                    del n.values[i]
                    return n, self.values[i]
            return self, NOT_FOUND
        bit = 1 << index(digest, level)
        if self.datamap & bit:
            i = self._data_index(bit)
            if self.keys[i] != key:
                return self, NOT_FOUND
            n = self._copy()
            del n.keys[i]
            del n.values[i]
            n.datamap &= ~bit
            return n, self.values[i]
        if self.nodemap & bit:
            i = self._node_index(bit)
            child = self.child(i, level + 1, ctx)
            nxt, removed = child.dissoc(digest, level + 1, key, ctx)
            if removed is NOT_FOUND:
                return self, NOT_FOUND
            n = self._copy()
            if nxt.single_entry():
                del n.children[i]
                n.nodemap &= ~bit
                n.datamap |= bit
                at = n._data_index(bit)
                n.keys.insert(at, nxt.keys[0])
                n.values.insert(at, nxt.values[0])
                return n, removed
            n.children[i] = nxt
            return n, removed
        return self, NOT_FOUND

    # ---- codec

    def encode(self, flusher: Flusher) -> bytes:
        entries = []
        for k, v in zip(self.keys, self.values):
            entries.append(nodes.Embedded(k))
            entries.append(values.embed(v, flusher))
        if self.collision:
            return nodes.encode({"k": nodes.KIND_MC, "e": entries})
        node = {"k": nodes.KIND_M, "d": self.datamap, "n": self.nodemap, "e": entries,
                "c": [nodes.Link(flusher.cid_of(c)) for c in self.children]}
        if self.cnt >= 0:
            node["cnt"] = self.cnt
        return nodes.encode(node)

    @staticmethod
    def decode(cid: str, data: bytes, root: bool) -> "ChampNode":
        node = nodes.decode(data, cid)
        kind = node.get("k")
        if kind not in (nodes.KIND_M, nodes.KIND_MC):
            raise NodeFormatError(f"expected a map node, found kind '{kind}'", cid)
        e = node.get("e") or []
        if len(e) % 2:
            raise NodeFormatError(f"entry list has an odd length {len(e)}", cid)
        keys, vals = [], []
        for i in range(len(e) // 2):
            key = e[2 * i].bytes
            if values.is_link_item(key):
                raise NodeFormatError(f"entry {i} has a bare link item as its key; keys never spill", cid)
            keys.append(key)
            vals.append(values.ref_of(e[2 * i + 1].bytes))
        if "cnt" in node and not root:
            raise NodeFormatError("'cnt' on a node that is not a map root", cid)
        if kind == nodes.KIND_MC:
            for i in range(1, len(keys)):
                if keys[i - 1] >= keys[i]:
                    raise NodeFormatError("collision node keys out of order", cid)
            n = ChampNode(True, 0, 0, keys, vals, [])
            n.cid = cid
            return n
        datamap, nodemap = node.get("d", 0), node.get("n", 0)
        if datamap > 0xFFFFFFFF or nodemap > 0xFFFFFFFF:
            raise NodeFormatError("datamap or nodemap above 32 bits", cid)
        if datamap & nodemap:
            raise NodeFormatError("datamap and nodemap share a slot", cid)
        if bin(datamap).count("1") != len(keys):
            raise NodeFormatError(f"datamap names {bin(datamap).count('1')} slots for {len(keys)} entries", cid)
        c = node.get("c") or []
        if bin(nodemap).count("1") != len(c):
            raise NodeFormatError(f"nodemap names {bin(nodemap).count('1')} slots for {len(c)} children", cid)
        n = ChampNode(False, datamap, nodemap, keys, vals, [link.cid for link in c])
        if "cnt" in node:
            n.cnt = node["cnt"]
        n.cid = cid
        return n


def _merge_two(k1, v1, d1, k2, v2, d2, level):
    if level >= COLLISION_LEVEL:
        first = k1 < k2
        return ChampNode(True, 0, 0, [k1, k2] if first else [k2, k1], [v1, v2] if first else [v2, v1], [])
    i1, i2 = index(d1, level), index(d2, level)
    if i1 != i2:
        first = i1 < i2
        return ChampNode(False, (1 << i1) | (1 << i2), 0, [k1, k2] if first else [k2, k1],
                         [v1, v2] if first else [v2, v1], [])
    sub = _merge_two(k1, v1, d1, k2, v2, d2, level + 1)
    return ChampNode(False, 0, 1 << i1, [], [], [sub])


# ------------------------------------------------------------------ diff

def _subtree_entries(node: ChampNode, level: int, ctx: Ctx) -> dict:
    return {k: v for k, v in node.entries(level, ctx)}


def diff_raw(mine: ChampNode, base: ChampNode, level: int, mine_ctx: Ctx, base_ctx: Ctx, out: dict) -> None:
    """Changes keyed by key bytes: ``(before ref or None, after ref or None)``; prunes equal CIDs (PD-V-07)."""
    if mine.cid is not None and mine.cid == base.cid:
        return
    if mine.collision or base.collision:
        _diff_entries(_subtree_entries(mine, level, mine_ctx), _subtree_entries(base, level, base_ctx), out)
        return
    for slot in range(32):
        bit = 1 << slot
        m_entry, m_child = mine.datamap & bit, mine.nodemap & bit
        b_entry, b_child = base.datamap & bit, base.nodemap & bit
        if not (m_entry or m_child or b_entry or b_child):
            continue
        if m_child and b_child:
            diff_raw(mine.child(mine._node_index(bit), level + 1, mine_ctx),
                     base.child(base._node_index(bit), level + 1, base_ctx), level + 1, mine_ctx, base_ctx, out)
            continue
        m_side = ({mine.keys[mine._data_index(bit)]: mine.values[mine._data_index(bit)]} if m_entry
                  else _subtree_entries(mine.child(mine._node_index(bit), level + 1, mine_ctx), level + 1, mine_ctx) if m_child
                  else {})
        b_side = ({base.keys[base._data_index(bit)]: base.values[base._data_index(bit)]} if b_entry
                  else _subtree_entries(base.child(base._node_index(bit), level + 1, base_ctx), level + 1, base_ctx) if b_child
                  else {})
        _diff_entries(m_side, b_side, out)


def _diff_entries(m_side: dict, b_side: dict, out: dict) -> None:
    for key, value in m_side.items():
        before = b_side.get(key)
        if before is None:
            out[key] = (None, value)
        elif not values.equal_hashed(before, value):
            out[key] = (before, value)
    for key, value in b_side.items():
        if key not in m_side:
            out[key] = (value, None)


# ------------------------------------------------------------------ PMap

class PMap:
    """A persistent map over a node store. Keys and values are any CBOR value
    (or ``Raw`` bytes); a ``None`` value is refused (``PSet`` holds nulls)."""

    def __init__(self, store, loader, node: ChampNode, count: int):
        self.store = store
        self.loader = loader
        self._node = node
        self._count = count

    @staticmethod
    def empty(store, loader=None) -> "PMap":
        return PMap(store, loader or StoreLoader(store), ChampNode.empty(), 0)

    @staticmethod
    def load(store, root: str, loader=None) -> "PMap":
        loader = loader or StoreLoader(store)
        node = ChampNode.load_root(root, loader.load(root))
        return PMap(store, loader, node, node.cnt if node.cnt >= 0 else -1)

    def ctx(self) -> Ctx:
        return Ctx(self.loader, self.store)

    # ---- reads

    def get(self, key, default=None):
        kb = values.encode_value(key)
        ref = self._node.find(values.sha256(kb), 0, kb, self.ctx())
        if ref is NOT_FOUND:
            return default
        return values.decode_value(values.resolve(ref, self.ctx()))

    def get_raw(self, key_bytes: bytes):
        ref = self._node.find(values.sha256(key_bytes), 0, key_bytes, self.ctx())
        return None if ref is NOT_FOUND else values.resolve(ref, self.ctx())

    def __contains__(self, key) -> bool:
        kb = values.encode_value(key)
        return self._node.find(values.sha256(kb), 0, kb, self.ctx()) is not NOT_FOUND

    def count(self) -> int:
        if self._count < 0:
            self._count = len(self._node.entries(0, self.ctx()))
        return self._count

    def __len__(self) -> int:
        return self.count()

    def raw_items(self) -> list[tuple[bytes, bytes]]:
        ctx = self.ctx()
        return [(k, values.resolve(v, ctx)) for k, v in self._node.entries(0, ctx)]

    def items(self) -> Iterator[tuple]:
        for k, v in self.raw_items():
            yield values.decode_value(k), values.decode_value(v)

    def keys(self):
        return [values.decode_value(k) for k, _ in self._node.entries(0, self.ctx())]

    def __iter__(self):
        return iter(self.keys())

    def to_dict(self) -> dict:
        return dict(self.items())

    def root(self) -> str:
        """The root CID, computed lazily; writes the new nodes to the store once."""
        if self._node.cid is None:
            self._node.cnt = self.count()
            Flusher.flush(self._node, self.store)
        return self._node.cid

    def flush(self) -> dict[str, bytes]:
        self._node.cnt = self.count()
        return Flusher.flush(self._node, self.store)

    def depth(self) -> int:
        return self._node.depth(0, self.ctx())

    # ---- writes

    def assoc_raw(self, kb: bytes, vb: bytes) -> "PMap":
        values.check_key(kb)
        ctx = self.ctx()
        node, change = self._node.assoc(values.sha256(kb), 0, kb, values.spill(vb, ctx), ctx)
        if change is None:
            return self
        if node is not self._node:
            node.cnt = -1
        return PMap(self.store, self.loader, node, self.count() + (1 if change == "added" else 0))

    def assoc(self, key, value) -> "PMap":
        if value is None:
            raise ValueError("a PMap value may not be None; use PSet for a null-valued map")
        return self.assoc_raw(values.encode_value(key), values.encode_value(value))

    def dissoc_raw(self, kb: bytes) -> "PMap":
        ctx = self.ctx()
        node, removed = self._node.dissoc(values.sha256(kb), 0, kb, ctx)
        if removed is NOT_FOUND:
            return self
        node.cnt = -1
        return PMap(self.store, self.loader, node, self.count() - 1)

    def dissoc(self, key) -> "PMap":
        return self.dissoc_raw(values.encode_value(key))

    def update(self, key, f: Callable) -> "PMap":
        return self.assoc(key, f(self.get(key)))

    def update_in(self, path: list, f: Callable) -> "PMap":
        """Applies ``f`` at a path through nested plain maps and lists; a missing level becomes a map."""
        if not path:
            raise ValueError("update_in needs a path")
        key, rest = path[0], path[1:]
        if not rest:
            return self.assoc(key, f(self.get(key)))
        current = self.get(key)
        return self.assoc(key, _update_nested(current, rest, f))

    def assoc_many(self, items) -> "PMap":
        m = self
        for k, v in (items.items() if isinstance(items, dict) else items):
            m = m.assoc(k, v)
        return m

    # ---- diff and merge

    def diff(self, base: "PMap") -> dict:
        """``{key: (before, after)}`` with ``None`` for absent; descends only where CIDs differ."""
        self.root()
        base.root()
        out = {}
        diff_raw(self._node, base._node, 0, self.ctx(), base.ctx(), out)
        result = {}
        for kb, (before, after) in out.items():
            result[values.decode_value(kb)] = (
                None if before is None else values.decode_value(values.resolve(before, base.ctx())),
                None if after is None else values.decode_value(values.resolve(after, self.ctx())))
        return result

    def diff_raw(self, base: "PMap") -> dict:
        self.root()
        base.root()
        out = {}
        diff_raw(self._node, base._node, 0, self.ctx(), base.ctx(), out)
        return out

    def merge3(self, base: "PMap", theirs: "PMap", resolver: Callable) -> "PMap":
        """The key-wise three-way merge of §3.6.1: ``resolver(key, base, mine, theirs)``
        (decoded values, None for absent) decides a key changed on both sides to
        different outcomes and returns the value to keep or None to remove."""
        mine_diff = self.diff_raw(base)
        their_diff = theirs.diff_raw(base)
        out = self
        for kb, (before, after) in their_diff.items():
            my = mine_diff.get(kb)
            if my is None:
                out = out.dissoc_raw(kb) if after is None else out.assoc_raw(kb, values.resolve(after, theirs.ctx()))
                continue
            if _same_outcome(my[1], after):
                continue
            key = values.decode_value(kb)
            b = None if before is None else values.decode_value(values.resolve(before, base.ctx()))
            m = None if my[1] is None else values.decode_value(values.resolve(my[1], self.ctx()))
            t = None if after is None else values.decode_value(values.resolve(after, theirs.ctx()))
            kept = resolver(key, b, m, t)
            out = out.dissoc_raw(kb) if kept is None else out.assoc_raw(kb, values.encode_value(kept))
        return out

    # ---- equality

    def __eq__(self, other) -> bool:
        return isinstance(other, PMap) and self.root() == other.root()

    def __hash__(self) -> int:
        return hash(self.root())

    def __repr__(self) -> str:
        return f"PMap[{self.count()} entries]"


def _same_outcome(a, b) -> bool:
    if a is None or b is None:
        return a is b
    return values.equal_hashed(a, b)


def _update_nested(current, path: list, f: Callable):
    key, rest = path[0], path[1:]
    if current is None:
        current = {}
    if isinstance(current, dict):
        updated = dict(current)
        updated[key] = f(current.get(key)) if not rest else _update_nested(current.get(key), rest, f)
        return updated
    if isinstance(current, list) and isinstance(key, int):
        updated = list(current)
        updated[key] = f(current[key]) if not rest else _update_nested(current[key], rest, f)
        return updated
    raise TypeError(f"cannot descend into {type(current).__name__} with key {key!r}")


# ------------------------------------------------------------------ PSet

class PSet:
    """A ``PMap`` whose values are null (PD-V-02)."""

    NULL = b"\xf6"

    def __init__(self, pmap: PMap):
        self._map = pmap

    @staticmethod
    def empty(store, loader=None) -> "PSet":
        return PSet(PMap.empty(store, loader))

    @staticmethod
    def load(store, root: str, loader=None) -> "PSet":
        return PSet(PMap.load(store, root, loader))

    def conj(self, element) -> "PSet":
        nxt = self._map.assoc_raw(values.encode_value(element), self.NULL)
        return self if nxt is self._map else PSet(nxt)

    def disj(self, element) -> "PSet":
        nxt = self._map.dissoc(element)
        return self if nxt is self._map else PSet(nxt)

    def __contains__(self, element) -> bool:
        return element in self._map

    def contains(self, element) -> bool:
        return element in self._map

    def count(self) -> int:
        return self._map.count()

    def __len__(self) -> int:
        return self._map.count()

    def __iter__(self):
        return iter(self._map.keys())

    def to_set(self) -> set:
        return set(self._map.keys())

    def root(self) -> str:
        return self._map.root()

    def as_map(self) -> PMap:
        return self._map

    def merge3(self, base: "PSet", theirs: "PSet", resolver: Callable) -> "PSet":
        raw = lambda key, b, m, t: resolver(key, b, m, t)  # noqa: E731
        return PSet(self._map.merge3(base._map, theirs._map, raw))

    def __eq__(self, other) -> bool:
        return isinstance(other, PSet) and self.root() == other.root()

    def __hash__(self) -> int:
        return hash(self.root())

    def __repr__(self) -> str:
        return f"PSet[{self.count()} elements]"
