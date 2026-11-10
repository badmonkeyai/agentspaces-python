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
count, so the layout is canonical.

PDT 2 phase 7 (srad/agentspaces-pdt2.md §3.7; P2-C-01 group R, P2-R-03, P2-R-04): a relaxed vector, an ``rr`` root
over ``rv`` and ``v`` nodes that another port's splices wrote, reads here. An index finds its child through ``z`` by
binary search on an ``rv`` node and by radix on a dense ``v`` node, every node is checked against the elements its
parent counts under it, and the reader refuses by name the forms §3.7 refuses: an ``rv`` node without ``z``, a size
table a radix index reads the same way, a child that holds more elements than its level holds, an ``rv`` node at the
leaf level, a leaf where an interior node belongs, and a shift past 30. ``packed`` gives the ``vr`` vector of the same
elements. This port writes no relaxed node: a write to a relaxed vector packs it first, which §10.10 allows."""

from __future__ import annotations

from typing import Callable

from . import nodes, values
from .nodes import NodeFormatError
from .values import Ctx, Flusher, StoreLoader, TreeNode

WIDTH, BITS, MASK = 32, 5, 31
#: The deepest shift a reader reads (P2-R-04), which the ``vr`` layout of 2^31 - 1 elements needs.
MAX_SHIFT = 30
MAX_COUNT = 0x7FFFFFFF


def tailoff(n: int) -> int:
    return 0 if n < WIDTH else ((n - 1) >> BITS) << BITS


def shift_for(n: int) -> int:
    off = tailoff(n)
    s = BITS
    while off > 0 and ((off - 1) >> s) >= WIDTH:
        s += BITS
    return s


class VecNode(TreeNode):
    __slots__ = ("leaf", "slots", "cid", "sizes")

    def __init__(self, leaf: bool, slots: list, sizes: list | None = None):
        self.leaf = leaf
        self.slots = slots
        self.cid = None
        #: The cumulative element counts of a relaxed node's children (an ``rv`` node), else None (PDT 2 phase 7).
        self.sizes = sizes

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
        n = VecNode._decode_v(cid, data)
        if n.leaf and len(n.slots) != WIDTH:
            raise NodeFormatError(f"vector leaf with {len(n.slots)} items; a leaf in the trie holds exactly 32", cid)
        return n

    @staticmethod
    def _decode_v(cid: str, data: bytes) -> "VecNode":
        """A ``v`` node of 1 to 32 slots."""
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_V:
            raise NodeFormatError(f"expected a vector node, found kind '{node.get('k')}'", cid)
        has_c, has_e = "c" in node, "e" in node
        if has_c == has_e:
            raise NodeFormatError("a vector node holds either 'c' or 'e'", cid)
        lst = node["c"] if has_c else node["e"]
        if not lst or len(lst) > WIDTH:
            raise NodeFormatError(f"vector node with {len(lst)} slots; 1 to 32 expected", cid)
        slots = [link.cid for link in lst] if has_c else [values.ref_of(e.bytes) for e in lst]
        n = VecNode(has_e, slots)
        n.cid = cid
        return n

    @staticmethod
    def decode_relaxed(cid: str, data: bytes, level: int, count: int) -> "VecNode":
        """A node of a relaxed tree at a known level (P2-R-04), as Java's ``VecNode.decodeRelaxed``: a ``v`` leaf of 1
        to 32 items at level 0, a dense ``v`` interior node above it, or an ``rv`` node whose size table describes a
        relaxed node; the node must hold exactly the ``count`` elements its parent counts under it."""
        if nodes.kind_of(data) == nodes.KIND_RV:
            node = VecNode._decode_rv(cid, data, level)
        else:
            node = VecNode._decode_v(cid, data)
            if node.leaf != (level == 0):
                raise NodeFormatError(f"a vector {'leaf' if node.leaf else 'interior node'} at level {level}", cid)
        width, capacity = len(node.slots), 1 << level
        fits = node.sizes[-1] == count if node.sizes is not None else (width - 1) * capacity < count <= width * capacity
        if not fits:
            raise NodeFormatError(f"a vector node of {width} slots at level {level} does not hold the {count} elements "
                                  "its parent counts under it", cid)
        return node

    @staticmethod
    def _decode_rv(cid: str, data: bytes, level: int) -> "VecNode":
        from .kinds import RvNode
        if level == 0:
            raise NodeFormatError("an rv node where a vector leaf belongs", cid)
        rv = RvNode.decode(cid, data)
        if rv.sizes is None:
            raise NodeFormatError("an rv node without z; a dense interior node is a v node", cid)
        capacity, previous, dense = 1 << level, 0, True
        for i, size in enumerate(rv.sizes):
            if size > MAX_COUNT:
                raise NodeFormatError(f"an rv size of {size} passes the 2^31 - 1 elements a vector holds", cid)
            if size - previous > capacity:
                raise NodeFormatError(f"an rv child holds {size - previous} elements, more than the {capacity} its "
                                      "level holds", cid)
            dense = dense and (i == len(rv.sizes) - 1 or size - previous == capacity)
            previous = size
        if dense:
            raise NodeFormatError("a size table on a dense node; a dense interior node is a v node", cid)
        node = VecNode(False, [link.cid for link in rv.children], list(rv.sizes))
        node.cid = cid
        return node


class VecRoot(TreeNode):
    __slots__ = ("n", "shift", "trie", "tail", "cid", "relaxed")

    def __init__(self, n: int, shift: int, trie, tail: list, relaxed: bool = False):
        self.n = n
        self.shift = shift
        self.trie = trie
        self.tail = tail
        self.cid = None
        #: Whether this is the root of a relaxed tree, kind ``rr``, read here and never written (PDT 2 phase 7).
        self.relaxed = relaxed

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
        if self.relaxed:
            return self._relaxed_nth(i, ctx)
        off = self.tailoff()
        if i >= off:
            return self.tail[i - off]
        return self.leaf_for(i, ctx).item(i & MASK)

    def _relaxed_nth(self, i: int, ctx: Ctx):
        """The element at an index of a relaxed root (P2-R-04): by binary search of ``z`` on a relaxed node and by
        radix on a dense one, each node checked against the count its parent gives it and kept once loaded."""
        off = self.n - len(self.tail)
        if i >= off:
            return self.tail[i - off]
        if not isinstance(self.trie, VecNode):
            self.trie = VecNode.decode_relaxed(self.trie, ctx.load(self.trie), self.shift, off)
        node, level, count, base = self.trie, self.shift, off, 0
        while level > 0:
            index = i - base
            if node.sizes is None:
                j = index >> level
                before = j << level
                last = len(node.slots) - 1
                child_count = (1 << level) if j < last else count - (last << level)
            else:
                lo, hi = 0, len(node.sizes) - 1
                while lo < hi:
                    mid = (lo + hi) >> 1
                    if node.sizes[mid] > index:
                        hi = mid
                    else:
                        lo = mid + 1
                j = lo
                before = node.sizes[j - 1] if j else 0
                child_count = node.sizes[j] - before
            ref = node.item(j)
            if not isinstance(ref, VecNode):
                ref = VecNode.decode_relaxed(ref, ctx.load(ref), level - BITS, child_count)
                node.slots[j] = ref
            node, level, count, base = ref, level - BITS, child_count, base + before
        return node.item(i - base)

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
        if nodes.kind_of(data) == nodes.KIND_RR:
            return VecRoot._decode_rr(cid, data)
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


    @staticmethod
    def _decode_rr(cid: str, data: bytes) -> "VecRoot":
        """An ``rr`` root (P2-R-04): the shape ``kinds.RrRoot`` checks, a count a vector can hold, a shift of at most
        30, and a tail another port may have left empty; the nodes below load on demand."""
        from .kinds import RrRoot
        rr = RrRoot.decode(cid, data)
        if rr.count > MAX_COUNT or rr.shift > MAX_SHIFT:
            raise NodeFormatError(f"rr root with count {rr.count} and shift {rr.shift}", cid)
        r = VecRoot(rr.count, rr.shift, None if rr.trie is None else rr.trie.cid,
                    [values.ref_of(e.bytes) for e in rr.tail], relaxed=True)
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

    def relaxed(self) -> bool:
        """Whether the vector's tree is relaxed, an ``rr`` root another port's splices wrote (P2-R-01)."""
        return self._node.relaxed

    def packed(self) -> "PVector":
        """The ``vr`` vector of the same elements, whose root those elements have whatever the history (P2-R-03)."""
        if not self._node.relaxed:
            return self
        ctx = self.ctx()
        root = VecRoot.empty()
        for i in range(self._node.n):
            root = root.conj(self._node.nth(i, ctx), ctx)
        return PVector(self.store, self.loader, root)

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
        if self._node.relaxed:
            return self.packed().conj(element)
        ctx = self.ctx()
        return PVector(self.store, self.loader, self._node.conj(values.spill(values.encode_value(element), ctx), ctx))

    def conj_many(self, elements) -> "PVector":
        v = self
        for e in elements:
            v = v.conj(e)
        return v

    def pop(self) -> "PVector":
        if self._node.relaxed:
            return self.packed().pop()
        return PVector(self.store, self.loader, self._node.pop(self.ctx()))

    def assoc(self, i: int, element) -> "PVector":
        if element is None:
            raise ValueError("a PVector element may not be None")
        if self._node.relaxed:
            return self.packed().assoc(i, element)
        ctx = self.ctx()
        nxt = self._node.assoc_n(i, values.spill(values.encode_value(element), ctx), ctx)
        return self if nxt is self._node else PVector(self.store, self.loader, nxt)

    def update(self, i: int, f: Callable) -> "PVector":
        return self.assoc(i, f(self.nth(i)))

    def depth(self) -> int:
        return self._node.depth()

    def __eq__(self, other) -> bool:
        """Equality of elements: two vectors compare by their packed roots (P2-R-03)."""
        return isinstance(other, PVector) and self.packed().root() == other.packed().root()

    def __hash__(self) -> int:
        return hash(self.packed().root())

    def __repr__(self) -> str:
        return f"PVector[{self._node.n} elements]"
