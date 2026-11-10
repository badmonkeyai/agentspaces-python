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

"""The DataScript database reader (srad/agentspaces-pdt2.md §3.1.5; PDT 2 phase 2, P2-D-09): a lazy
reader over the ``db`` root and ``dn`` nodes of §3.1.1 that answers ``datoms``, ``entity``, and
``lookup`` as DataScript answers them, without Datalog.

``DbReader(root, loader)`` reads the root node and nothing else. A read walks one index from its root,
loading only the nodes whose key range meets the components, and applies the tail (the datoms of the
transactions not yet folded) over the index: a retraction removes the datom it names, and an assertion
adds one. ``loader`` is any object with ``load(cid) -> bytes``; ``Pdt.loader`` reads the node store and
fetches what it lacks over the tree exchange.

The comparators are DataScript's: ``eavt``, ``aevt``, and ``avet`` order datoms by their components in
the index's order, the attribute as a Clojure keyword (namespace first, a keyword without one before
every keyword with one), and the value by ``value-compare``: numbers by value across long, double, and
big integer, other values of two classes by the class name, text by UTF-16 code unit, a UUID by its two
signed halves, and an instant by its milliseconds. A text value of a colon and a name is a keyword's
print form (P2-D-01); a text value that starts with a backslash is the string after it, the escape the
Clojure face writes for a string that starts with ``:`` or a backslash. Values come back in the datom
grammar, escape included. DataScript orders two byte arrays by identity hash, so the reader reads a byte
array component by equality and never seeks on it.

``value-compare`` is no total order: it compares numbers by value but a number and a value of another
class by class name, so an attribute that holds a big integer, a keyword or a boolean, and a double or a
long can sort in a cycle, and DataScript's sort then leaves two values out of order when other values sit
between them. The reader therefore checks neighbours only: each leaf holds its datoms in its index's
order, and each node lies between the branch key before its own and its own branch key, which are its
neighbours in the index. It refuses anything else by name."""

from __future__ import annotations

import struct
from collections import OrderedDict
from functools import cached_property, cmp_to_key
from typing import Iterator

from .. import cbor
from . import nodes
from .items import Datom, Tagged
from .kinds import DbRoot, DnNode
from .nodes import Link, NodeFormatError
from .values import Ctx, resolve

#: The components of each index, in the index's order.
COMPONENTS = {DnNode.EAVT: ("e", "a", "v"), DnNode.AEVT: ("a", "e", "v"), DnNode.AVET: ("a", "v", "e")}

#: DataScript's implicit schema, merged under every database's own.
IMPLICIT_SCHEMA = {":db/ident": {":db/unique": ":db.unique/identity"}}

#: The decoded nodes a reader keeps, least recently used first out.
CACHE_NODES = 1024

_KEYWORD, _STRING, _BYTES = "clojure.lang.Keyword", "java.lang.String", "[B"
_CLASS = {bool: "java.lang.Boolean", int: "java.lang.Long", float: "java.lang.Double", bytes: _BYTES}
_TAGGED_CLASS = {Tagged.UUID: "java.util.UUID", Tagged.INSTANT: "java.util.Date", Tagged.BIGINT: "clojure.lang.BigInt"}


def _sign(x, y) -> int:
    return (x > y) - (x < y)


def _utf16(text: str) -> bytes:
    # big-endian code units compare byte by byte in Java's String order
    return text.encode("utf-16-be")


def _keyword_key(text: str) -> tuple:
    """A keyword's print form as Clojure's ``Symbol.compareTo`` orders it: no namespace first, then the
    namespace, then the name. ``Symbol.intern`` splits at the first ``/`` unless the name is ``/``."""
    body = text[1:]
    cut = body.find("/")
    if cut == -1 or body == "/":
        return False, b"", _utf16(body)
    return True, _utf16(body[:cut]), _utf16(body[cut + 1:])


def _number(v):
    if type(v) in (int, float):
        return v
    if type(v) is Tagged and v.tag == Tagged.BIGINT:
        return v.integer()
    return None


def _is_keyword(text: str) -> bool:
    """A keyword's print form: a colon and a name. A lone ``:`` is a string."""
    return len(text) > 1 and text[0] == ":"


def _string(text: str) -> str:
    """The string a text value stands for: the Clojure face writes a string that starts with ``:`` or ``\\``
    with one more ``\\`` in front (``agentspaces.pdt``), and a reader drops it, as Java's ``DatomOrder`` does."""
    return text[1:] if text.startswith("\\") else text


def _class_name(v) -> str:
    if type(v) is str:
        return _KEYWORD if _is_keyword(v) else _STRING
    if type(v) is Tagged:
        return _TAGGED_CLASS[v.tag]
    return _CLASS[type(v)]


def compare_values(x, y) -> int | None:
    """DataScript's ``value-compare`` over two datom values as -1, 0, or 1, or None for two byte arrays
    of different content, which DataScript orders by identity hash. Neither value is a spilled link."""
    nx, ny = _number(x), _number(y)
    if nx is not None and ny is not None:
        if type(nx) is float or type(ny) is float:
            # Clojure's Numbers.compare widens a long or a big integer to a double beside a double
            return _sign(float(nx), float(ny))
        return _sign(nx, ny)
    cx, cy = _class_name(x), _class_name(y)
    if cx != cy:
        return _sign(cx, cy)
    if cx == _BYTES:
        return 0 if x == y else None
    if cx == _KEYWORD:
        return _sign(_keyword_key(x), _keyword_key(y))
    if cx == _STRING:
        return _sign(_utf16(_string(x)), _utf16(_string(y)))
    if type(x) is Tagged:
        if x.tag == Tagged.UUID:
            return _sign(struct.unpack(">qq", x.inner), struct.unpack(">qq", y.inner))
        return _sign(x.inner, y.inner)
    return _sign(x, y)


def _compare_component(field: str, d: Datom, value) -> int | None:
    if field == "a":
        return _sign(_keyword_key(d.a), _keyword_key(value))
    if field == "v":
        return compare_values(d.v, value)
    return _sign(getattr(d, field), value)


def _compare_prefix(d: Datom, fields: tuple, components: tuple) -> int | None:
    """Where a datom lies against the components: before them (-1), among them (0), after them (1), or
    None when a byte array leaves the order unknown."""
    for field, value in zip(fields, components):
        c = _compare_component(field, d, value)
        if c != 0:
            return c
    return 0


def _compare_datoms(index: str, x: Datom, y: Datom) -> int | None:
    c = _compare_prefix(x, COMPONENTS[index], tuple(getattr(y, f) for f in COMPONENTS[index]))
    return c if c != 0 else _sign(abs(x.tx), abs(y.tx))


def _known(order: int | None, unknown: int) -> int:
    """An order, or ``unknown`` in its place when byte arrays leave it unknown."""
    return unknown if order is None else order


def _same_value(x, y) -> bool:
    return compare_values(x, y) == 0


def _value_key(v) -> tuple:
    """The key of a value under DataScript's datom equality: numbers by value, the rest by class and value."""
    n = _number(v)
    if n is not None:
        return "number", n
    return _class_name(v), v


class DbReader:
    """A lazy reader over one ``db`` root (PDT 2 phase 2, P2-D-09)."""

    def __init__(self, root: str, loader):
        self.root = root
        self._loader = loader
        self._ctx = Ctx(loader)
        self._db = DbRoot.decode(root, loader.load(root))
        self._nodes: OrderedDict[str, DnNode] = OrderedDict()
        self._index_roots = {DnNode.EAVT: self._db.eavt, DnNode.AEVT: self._db.aevt, DnNode.AVET: self._db.avet}

    @property
    def max_eid(self) -> int:
        return self._db.max_eid

    @property
    def max_tx(self) -> int:
        return self._db.max_tx

    @cached_property
    def schema(self) -> dict:
        """The database's schema under DataScript's implicit one, attribute to properties."""
        item = self._db.schema.bytes
        if nodes.is_link_shaped(item):
            item = resolve(nodes.link_cid(item), self._ctx)
        schema = cbor.loads(item)
        if not all(type(a) is str and isinstance(p, dict) for a, p in schema.items()):
            raise NodeFormatError("a db schema maps each attribute to a map of its properties", self.root)
        return {**IMPLICIT_SCHEMA, **schema}

    def _attrs(self, test) -> frozenset:
        return frozenset(a for a, p in self.schema.items() if test(p))

    @cached_property
    def _unique(self) -> frozenset:
        return self._attrs(lambda p: ":db/unique" in p)

    @cached_property
    def _many(self) -> frozenset:
        return self._attrs(lambda p: p.get(":db/cardinality") == ":db.cardinality/many")

    @cached_property
    def _indexed(self) -> frozenset:
        # DataScript's rschema puts unique, ref, :db/index true, and tuple attributes in avet
        return self._attrs(lambda p: ":db/unique" in p or p.get(":db/valueType") == ":db.type/ref"
                           or p.get(":db/index") is True or ":db/tupleAttrs" in p)

    @cached_property
    def _tail(self) -> dict:
        """The tail applied in transaction order: each datom's key to its last assertion, or None after
        a retraction."""
        applied = {}
        if self._db.tail is None:
            return applied
        tail = self._load(self._db.tail.cid)
        if tail.index != DnNode.TAIL:
            raise NodeFormatError(f"the db root's 't' links index {tail.index}, expected the tail", self._db.tail.cid)
        for d in tail.datoms:
            key = (d.e, d.a, _value_key(d.v))
            applied[key] = Datom(d.e, d.a, d.v, d.tx) if d.tx > 0 else None
        return applied

    # ---- reads

    def datoms(self, index: str, *components) -> Iterator[Datom]:
        """The datoms of ``index`` whose leading components equal ``components``, in index order, as
        ``(d/datoms db index c1 c2 c3)`` returns them; the components follow the index's order."""
        if index not in COMPONENTS:
            raise ValueError(f"unknown index {index}; the indexes are eavt, aevt and avet")
        if len(components) > 3:
            raise ValueError("a read names at most three components")
        if index == DnNode.AVET and components and components[0] not in self._indexed:
            raise ValueError(f"attribute {components[0]} should be marked as :db/index true to read avet")
        fields = COMPONENTS[index][:len(components)]
        added = sorted((d for d in self._tail.values() if d is not None and self._in_index(index, d)
                        and _compare_prefix(d, fields, components) == 0),
                       key=cmp_to_key(lambda x, y: _known(_compare_datoms(index, x, y), 0)))
        return self._merge(index, self._range(index, fields, components), added)

    def entity(self, e: int) -> dict:
        """The attributes of an entity as ``(d/touch (d/entity db e))`` holds them: one value for a
        cardinality-one attribute, a tuple in index order for a cardinality-many one, a ref as its id."""
        out: dict = {}
        for d in self.datoms(DnNode.EAVT, e):
            if d.a in self._many:
                out.setdefault(d.a, []).append(d.v)
            else:
                out[d.a] = d.v
        return {a: tuple(v) if a in self._many else v for a, v in out.items()}

    def lookup(self, a: str, v) -> int | None:
        """The entity of the lookup ref ``[a v]``, as ``(d/entid db [a v])`` resolves it, or None."""
        if a not in self._unique:
            raise ValueError(f"lookup attribute {a} is not :db/unique")
        return next((d.e for d in self.datoms(DnNode.AVET, a, v)), None)

    # ---- the walk

    def _in_index(self, index: str, d: Datom) -> bool:
        return index != DnNode.AVET or d.a in self._indexed

    def _merge(self, index: str, stored: Iterator[Datom], added: list) -> Iterator[Datom]:
        i = 0
        for d in stored:
            while i < len(added) and _known(_compare_datoms(index, added[i], d), 0) < 0:
                yield added[i]
                i += 1
            yield d
        yield from added[i:]

    def _range(self, index: str, fields: tuple, components: tuple) -> Iterator[Datom]:
        tail = self._tail
        for d in self._scan(index, self._index_roots[index].cid, None, None, None, fields, components):
            c = _compare_prefix(d, fields, components)
            if c is not None and c > 0:
                return
            if c != 0 and not (c is None and self._matches(d, fields, components)):
                continue
            if (d.e, d.a, _value_key(d.v)) not in tail:
                yield d

    @staticmethod
    def _matches(d: Datom, fields: tuple, components: tuple) -> bool:
        return all(_same_value(getattr(d, f), c) if f == "v" else getattr(d, f) == c
                   for f, c in zip(fields, components))

    def _scan(self, index: str, cid: str, level: int | None, low: Datom | None, high: Datom | None,
              fields: tuple, components: tuple) -> Iterator[Datom]:
        node = self._load(cid)
        self._check(index, cid, node, level, low, high)
        if node.level == 0:
            yield from node.datoms
            return
        start = 0
        while start < len(node.datoms) and _compare_prefix(node.datoms[start], fields, components) == -1:
            start += 1
        for j in range(start, len(node.datoms)):
            yield from self._scan(index, node.children[j].cid, node.level - 1,
                                  node.datoms[j - 1] if j else low, node.datoms[j], fields, components)

    def _check(self, index: str, cid: str, node: DnNode, level: int | None, low: Datom | None,
               high: Datom | None) -> None:
        """The node's place in its index: its index, its level one below its parent's, and its datoms
        above the key before its branch key and at most that key."""
        if node.index != index:
            raise NodeFormatError(f"expected a node of index {index}, found index {node.index}", cid)
        if level is not None and node.level != level:
            raise NodeFormatError(f"a child of a level {level + 1} branch sits at level {node.level}", cid)
        if not node.datoms:
            return
        if low is not None and _known(_compare_datoms(index, node.datoms[0], low), 1) <= 0:
            raise NodeFormatError(f"a datom sits outside its branch key's range in {index}", cid)
        if high is not None and _known(_compare_datoms(index, node.datoms[-1], high), 0) > 0:
            raise NodeFormatError(f"a datom sits outside its branch key's range in {index}", cid)

    def _load(self, cid: str) -> DnNode:
        node = self._nodes.get(cid)
        if node is not None:
            self._nodes.move_to_end(cid)
            return node
        node = DnNode.decode(cid, self._loader.load(cid))
        node = DnNode(node.level, node.index, [self._resolved(cid, d) for d in node.datoms], node.children)
        if node.index != DnNode.TAIL:
            self._check_leaf(cid, node)
        self._nodes[cid] = node
        if len(self._nodes) > CACHE_NODES:
            self._nodes.popitem(last=False)
        return node

    @staticmethod
    def _check_leaf(cid: str, node: DnNode) -> None:
        for d in node.datoms:
            if d.tx < 0:
                raise NodeFormatError(f"an index holds assertions only, found a retraction in {node.index}", cid)
        if node.level > 0:
            return
        for x, y in zip(node.datoms, node.datoms[1:]):
            if _known(_compare_datoms(node.index, x, y), -1) >= 0:
                raise NodeFormatError(f"datoms out of {node.index} order", cid)

    def _resolved(self, cid: str, d: Datom) -> Datom:
        """A datom whose spilled value (PD-N-05) reads as the value it names."""
        if type(d.v) is not Link:
            return d
        try:
            return Datom(d.e, d.a, cbor.loads(resolve(d.v.cid, self._ctx)), d.tx)
        except ValueError as e:
            raise NodeFormatError(f"a spilled datom value is no datom value: {e}", cid) from None

