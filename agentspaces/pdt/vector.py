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

"""``PVector``, Clojure's tailed trie over content-addressed nodes
(srad/agentspaces-pdt.md §3.2, §10.2; PD-V-03, PD-V-04): the root
``{k:"vr", n, s, r, t}`` holds the count, the shift (5 while the trie is
empty), the trie root link or null, and a tail of 1 to 32 items; an interior
node is ``{k:"v", c:[links]}`` and a leaf ``{k:"v", e:[32 items]}``;
``tailoff = n < 32 ? 0 : ((n - 1) >> 5) << 5``. ``conj`` and ``pop`` rewrite
the root alone until the tail fills or empties; the shape is a function of the
count, so the layout is canonical."""

from __future__ import annotations

from typing import Callable

from . import nodes, values
from .nodes import NodeFormatError
from .values import Ctx, Flusher, StoreLoader, TreeNode

WIDTH, BITS, MASK = 32, 5, 31


def tailoff(n: int) -> int:
    return 0 if n < WIDTH else ((n - 1) >> BITS) << BITS


def shift_for(n: int) -> int:
    off = tailoff(n)
    s = BITS
    while off > 0 and ((off - 1) >> s) >= WIDTH:
        s += BITS
    return s


class VecNode(TreeNode):
    __slots__ = ("leaf", "slots", "cid")

    def __init__(self, leaf: bool, slots: list):
        self.leaf = leaf
        self.slots = slots
        self.cid = None

    def item(self, i: int):
        if i < 0 or i >= len(self.slots):
            raise NodeFormatError(f"vector node has {len(self.slots)} slots where index {i} was expected", self.cid)
        return self.slots[i]

    def child(self, i: int, ctx: Ctx) -> "VecNode":
        ref = self.item(i)
        if isinstance(ref, VecNode):
            return ref
        loaded = VecNode.decode(ref, ctx.load(ref))
        self.slots[i] = loaded
        return loaded

    def appended(self, slot) -> "VecNode":
        return VecNode(self.leaf, self.slots + [slot])

    def shrunk(self) -> "VecNode":
        return VecNode(self.leaf, self.slots[:-1])

    def with_slot(self, i: int, slot) -> "VecNode":
        n = VecNode(self.leaf, list(self.slots))
        n.slots[i] = slot
        return n

    def encode(self, flusher: Flusher) -> bytes:
        if self.leaf:
            return nodes.encode({"k": nodes.KIND_V, "e": [values.embed(s, flusher) for s in self.slots]})
        return nodes.encode({"k": nodes.KIND_V, "c": [nodes.Link(flusher.cid_of(s)) for s in self.slots]})

    @staticmethod
    def decode(cid: str, data: bytes) -> "VecNode":
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_V:
            raise NodeFormatError(f"expected a vector node, found kind '{node.get('k')}'", cid)
        has_c, has_e = "c" in node, "e" in node
        if has_c == has_e:
            raise NodeFormatError("a vector node holds either 'c' or 'e'", cid)
        lst = node["c"] if has_c else node["e"]
        if not lst or len(lst) > WIDTH:
            raise NodeFormatError(f"vector node with {len(lst)} slots; 1 to 32 expected", cid)
        if has_e and len(lst) != WIDTH:
            raise NodeFormatError(f"vector leaf with {len(lst)} items; a leaf in the trie holds exactly 32", cid)
        slots = [link.cid for link in lst] if has_c else [values.ref_of(e.bytes) for e in lst]
        n = VecNode(has_e, slots)
        n.cid = cid
        return n


class VecRoot(TreeNode):
    __slots__ = ("n", "shift", "trie", "tail", "cid")

    def __init__(self, n: int, shift: int, trie, tail: list):
        self.n = n
        self.shift = shift
        self.trie = trie
        self.tail = tail
        self.cid = None

    @staticmethod
    def empty() -> "VecRoot":
        return VecRoot(0, BITS, None, [])

    def tailoff(self) -> int:
        return tailoff(self.n)

    def trie_node(self, ctx: Ctx) -> VecNode:
        if isinstance(self.trie, VecNode):
            return self.trie
        loaded = VecNode.decode(self.trie, ctx.load(self.trie))
        self.trie = loaded
        return loaded

    def leaf_for(self, i: int, ctx: Ctx) -> VecNode:
        node = self.trie_node(ctx)
        level = self.shift
        while level > 0:
            node = node.child((i >> level) & MASK, ctx)
            level -= BITS
        return node

    def nth(self, i: int, ctx: Ctx):
        if i < 0 or i >= self.n:
            raise IndexError(f"index {i} of a vector of {self.n}")
        off = self.tailoff()
        if i >= off:
            return self.tail[i - off]
        return self.leaf_for(i, ctx).item(i & MASK)

    # ---- writes

    def conj(self, item, ctx: Ctx) -> "VecRoot":
        off = self.tailoff()
        if self.n - off < WIDTH:
            return VecRoot(self.n + 1, self.shift, self.trie, self.tail + [item])
        tail_node = VecNode(True, list(self.tail))
        if self.trie is None:
            trie, shift = VecNode(False, [tail_node]), BITS
        elif (self.n >> BITS) > (1 << self.shift):
            trie, shift = VecNode(False, [self.trie, _new_path(self.shift, tail_node)]), self.shift + BITS
        else:
            trie, shift = self._push_tail(self.shift, self.trie_node(ctx), tail_node, ctx), self.shift
        return VecRoot(self.n + 1, shift, trie, [item])

    def _push_tail(self, level: int, parent: VecNode, tail_node: VecNode, ctx: Ctx) -> VecNode:
        subidx = ((self.n - 1) >> level) & MASK
        if level == BITS:
            return parent.appended(tail_node)
        if subidx < len(parent.slots):
            child = parent.child(subidx, ctx)
            nxt = self._push_tail(level - BITS, child, tail_node, ctx)
            return parent if nxt is child else parent.with_slot(subidx, nxt)
        return parent.appended(_new_path(level - BITS, tail_node))

    def pop(self, ctx: Ctx) -> "VecRoot":
        if self.n == 0:
            raise IndexError("pop on an empty vector")
        off = self.tailoff()
        if self.n - off > 1:
            return VecRoot(self.n - 1, self.shift, self.trie, self.tail[:-1])
        if self.n == 1:
            return VecRoot.empty()
        new_tail = list(self.leaf_for(self.n - 2, ctx).slots)
        new_trie = self._pop_tail(self.shift, self.trie_node(ctx), ctx)
        shift = self.shift
        if new_trie is None:
            shift = BITS
        elif self.shift > BITS and len(new_trie.slots) == 1:
            new_trie = new_trie.child(0, ctx)
            shift = self.shift - BITS
        return VecRoot(self.n - 1, shift, new_trie, new_tail)

    def _pop_tail(self, level: int, node: VecNode, ctx: Ctx):
        subidx = ((self.n - 2) >> level) & MASK
        if level > BITS:
            nxt = self._pop_tail(level - BITS, node.child(subidx, ctx), ctx)
            if nxt is None:
                return None if subidx == 0 else node.shrunk()
            return node.with_slot(subidx, nxt)
        return None if subidx == 0 else node.shrunk()

    def assoc_n(self, i: int, item, ctx: Ctx) -> "VecRoot":
        if i < 0 or i >= self.n:
            raise IndexError(f"index {i} of a vector of {self.n}")
        off = self.tailoff()
        if i >= off:
            if values.same_value(self.tail[i - off], item):
                return self
            tail = list(self.tail)
            tail[i - off] = item
            return VecRoot(self.n, self.shift, self.trie, tail)
        nxt = _do_assoc(self.shift, self.trie_node(ctx), i, item, ctx)
        if nxt is self.trie:
            return self
        return VecRoot(self.n, self.shift, nxt, self.tail)

    def depth(self) -> int:
        return 1 if self.trie is None else 2 + self.shift // BITS

    # ---- codec

    def encode(self, flusher: Flusher) -> bytes:
        return nodes.encode({"k": nodes.KIND_VR, "n": self.n, "s": self.shift,
                             "r": None if self.trie is None else nodes.Link(flusher.cid_of(self.trie)),
                             "t": [values.embed(item, flusher) for item in self.tail]})

    @staticmethod
    def decode(cid: str, data: bytes) -> "VecRoot":
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_VR:
            raise NodeFormatError(f"expected a vector root, found kind '{node.get('k')}'", cid)
        n, shift = node.get("n", 0), node.get("s", BITS)
        if n > 0x7FFFFFFF or shift < BITS or shift > 30 or shift % BITS:
            raise NodeFormatError(f"vector root with count {n} and shift {shift}", cid)
        trie = node["r"].cid if node.get("r") is not None else None
        t = node.get("t") or []
        if len(t) > WIDTH:
            raise NodeFormatError(f"vector tail of {len(t)} elements", cid)
        if len(t) != n - tailoff(n) or (trie is None) != (tailoff(n) == 0):
            raise NodeFormatError(f"vector tail and trie do not match the count {n}", cid)
        if shift != shift_for(n):
            raise NodeFormatError(f"vector root with shift {shift} where the count {n} implies {shift_for(n)}", cid)
        r = VecRoot(n, shift, trie, [values.ref_of(e.bytes) for e in t])
        r.cid = cid
        return r


def _new_path(level: int, node: VecNode) -> VecNode:
    if level == 0:
        return node
    return VecNode(False, [_new_path(level - BITS, node)])


def _do_assoc(level: int, node: VecNode, i: int, item, ctx: Ctx) -> VecNode:
    if level == 0:
        if values.same_value(node.slots[i & MASK], item):
            return node
        return node.with_slot(i & MASK, item)
    subidx = (i >> level) & MASK
    child = node.child(subidx, ctx)
    nxt = _do_assoc(level - BITS, child, i, item, ctx)
    return node if nxt is child else node.with_slot(subidx, nxt)


class PVector:
    """A persistent vector over a node store; every operation returns a new vector."""

    def __init__(self, store, loader, node: VecRoot):
        self.store = store
        self.loader = loader
        self._node = node

    @staticmethod
    def empty(store, loader=None) -> "PVector":
        return PVector(store, loader or StoreLoader(store), VecRoot.empty())

    @staticmethod
    def load(store, root: str, loader=None) -> "PVector":
        loader = loader or StoreLoader(store)
        return PVector(store, loader, VecRoot.decode(root, loader.load(root)))

    def ctx(self) -> Ctx:
        return Ctx(self.loader, self.store)

    def nth(self, i: int):
        return values.decode_value(values.resolve(self._node.nth(i, self.ctx()), self.ctx()))

    def __getitem__(self, i: int):
        return self.nth(i)

    def peek(self):
        return None if self._node.n == 0 else self.nth(self._node.n - 1)

    def count(self) -> int:
        return self._node.n

    def __len__(self) -> int:
        return self._node.n

    def __iter__(self):
        ctx = self.ctx()
        for i in range(self._node.n):
            yield values.decode_value(values.resolve(self._node.nth(i, ctx), ctx))

    def to_list(self) -> list:
        return list(self)

    def root(self) -> str:
        if self._node.cid is None:
            Flusher.flush(self._node, self.store)
        return self._node.cid

    def flush(self) -> dict[str, bytes]:
        return Flusher.flush(self._node, self.store)

    def conj(self, element) -> "PVector":
        if element is None:
            raise ValueError("a PVector element may not be None")
        ctx = self.ctx()
        return PVector(self.store, self.loader, self._node.conj(values.spill(values.encode_value(element), ctx), ctx))

    def conj_many(self, elements) -> "PVector":
        v = self
        for e in elements:
            v = v.conj(e)
        return v

    def pop(self) -> "PVector":
        return PVector(self.store, self.loader, self._node.pop(self.ctx()))

    def assoc(self, i: int, element) -> "PVector":
        if element is None:
            raise ValueError("a PVector element may not be None")
        ctx = self.ctx()
        nxt = self._node.assoc_n(i, values.spill(values.encode_value(element), ctx), ctx)
        return self if nxt is self._node else PVector(self.store, self.loader, nxt)

    def update(self, i: int, f: Callable) -> "PVector":
        return self.assoc(i, f(self.nth(i)))

    def depth(self) -> int:
        return self._node.depth()

    def __eq__(self, other) -> bool:
        return isinstance(other, PVector) and self.root() == other.root()

    def __hash__(self) -> int:
        return hash(self.root())

    def __repr__(self) -> str:
        return f"PVector[{self._node.n} elements]"
