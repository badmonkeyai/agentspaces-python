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

"""The typed readers of the PDT 2 level-2 node kinds (srad/agentspaces-pdt2.md §3; PDT 2
phase 0, P2-D-01, P2-R-01, P2-T-01, P2-V-01, P2-B-02), ports of Java's
``ai.badmonkey.agentspaces.pdt.kinds``. Each type checks the rules that span its fields in its
constructor (a ValueError), writes its canonical bytes with ``encode``, and reads a node with
``decode(cid, data)``, which refuses another kind, a missing key, or a broken rule with a
``NodeFormatError`` naming the CID. The node codec checks each field alone.

- ``DbRoot``, kind ``db``: the root of a DataScript database. The build pins ``t``, the tail key
  §3.1.1 lacked (§10.4): always present, the link of the ``dn`` tail or null, so a head's inline
  tail is reachable from the root.
- ``DnNode``, kind ``dn``: an index leaf or branch (a branch keys each child by its largest
  datom) or the tail of unfolded transactions.
- ``RrRoot`` and ``RvNode``, kinds ``rr`` and ``rv``: an RRB vector root and interior node, with
  cumulative sizes on a relaxed node only.
- ``TextLeaf``, kind ``t``: a Fugue sequence as canonical runs, maximal and sorted by the id of
  their first character (the replica's UTF-8 bytes, then the counter); it reads its text in
  Fugue order and unions with another leaf.
- ``VgNode``, kind ``vg``: a version graph node naming its root and bases as CID text and
  linking at most one earlier ``vg`` node per base.
- ``BoNode``, kind ``bo``: a node of a blob's Bao outboard over chunk groups of 2^4 BLAKE3
  chunks, whose parents and children follow from its size alone."""

from __future__ import annotations

from dataclasses import dataclass

from .. import cbor, wire
from . import cids, nodes
from .items import CharId, Datom, TextRun
from .nodes import Embedded, Link, NodeFormatError

#: The bases a head names at most, which a vg node shares (PD-R-03); ``refs`` reads it from here, so the node kinds
#: need nothing of the ref engine.
MAX_BASE = 8


def _decode(cid: str | None, data: bytes, kind: str, required: tuple) -> dict:
    """A node of one kind with every key the kind requires besides ``k``."""
    node = nodes.decode(data, cid)
    if node[nodes.KIND_KEY] != kind:
        raise NodeFormatError(f"kind '{node[nodes.KIND_KEY]}' where a '{kind}' node belongs", cid)
    for key in required:
        if key not in node:
            raise NodeFormatError(f"a '{kind}' node lacks '{key}'", cid)
    return node


def _build(cid: str | None, constructor):
    """A typed value, its constructor's refusal turned into a refusal of the node."""
    try:
        return constructor()
    except ValueError as refused:
        raise NodeFormatError(str(refused), cid) from None


def _whole(value: int, what: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{what} is a non-negative integer")


def _links(values, what: str) -> tuple:
    values = tuple(values)
    if not all(isinstance(v, Link) for v in values):
        raise ValueError(f"{what} holds links")
    return values


# ------------------------------------------------------------------ db and dn (P2-D-01)

@dataclass(frozen=True)
class DbRoot:
    """``{k:"db", v: 1, s: schema, me: max-eid, mt: max-tx, bf: branching-factor,
    i: {aevt, avet, eavt}, t: tail link or null}``."""
    schema: Embedded
    max_eid: int
    max_tx: int
    branching: int
    eavt: Link
    aevt: Link
    avet: Link
    tail: Link | None

    VERSION = 1
    BRANCHING = 128
    REQUIRED = ("v", "s", "me", "mt", "bf", "i", "t")

    def __post_init__(self):
        if not isinstance(self.schema, Embedded):
            raise ValueError("a db schema is an embedded item")
        _links((self.eavt, self.aevt, self.avet), "a db root's index map")
        if self.tail is not None and not isinstance(self.tail, Link):
            raise ValueError("a db root's tail is a link or None")
        if type(self.max_eid) is not int or type(self.max_tx) is not int or self.max_eid < 0 or self.max_tx < 0:
            raise ValueError("max-eid and max-tx are non-negative")
        if type(self.branching) is not int or self.branching < 2:
            raise ValueError(f"a db root's branching factor is at least 2, found {self.branching}")
        _check_schema(self.schema.bytes)

    def encode(self) -> bytes:
        return nodes.encode({nodes.KIND_KEY: nodes.KIND_DB, "v": DbRoot.VERSION, "s": self.schema, "me": self.max_eid,
                             "mt": self.max_tx, "bf": self.branching,
                             "i": {"eavt": self.eavt, "aevt": self.aevt, "avet": self.avet}, "t": self.tail})

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "DbRoot":
        node = _decode(cid, data, nodes.KIND_DB, DbRoot.REQUIRED)
        if node["v"] != DbRoot.VERSION:
            raise NodeFormatError(f"db root version {node['v']}; this release reads version {DbRoot.VERSION}", cid)
        i = node["i"]
        return _build(cid, lambda: DbRoot(node["s"], node["me"], node["mt"], node["bf"], i["eavt"], i["aevt"],
                                          i["avet"], node["t"]))


def _check_schema(item: bytes) -> None:
    """The schema is a map whose keys are text, the keywords' print forms, or a spilled link to
    one (PDT 2 phase 0, P2-D-01; §3.1.1), so every reader finds the schema it expects. The wire
    encoding gives every map text keys."""
    if nodes.is_link_shaped(item):
        return
    try:
        value = cbor.loads(item)
    except ValueError as e:
        raise ValueError(f"a db schema is one item in the wire encoding: {e}") from None
    if not isinstance(value, dict):
        raise ValueError(f"a db schema is a map, found {type(value).__name__}")


@dataclass(frozen=True)
class DnNode:
    """A leaf ``{k:"dn", l: 0, x: index, e: [datom...]}``, a branch ``{k:"dn", l: level >= 1,
    x: index, e: [datom...], c: [link...]}`` whose ``e`` holds the largest key of each child, or
    a tail ``{k:"dn", l: 0, x: "tail", e: [datom...]}`` in transaction order. The reader of
    P2-D-09 checks the comparator order, since it owns the comparators."""
    level: int
    index: str
    datoms: tuple
    children: tuple = ()

    EAVT, AEVT, AVET, TAIL = "eavt", "aevt", "avet", "tail"
    INDEXES = (EAVT, AEVT, AVET, TAIL)
    REQUIRED = ("l", "x", "e")

    def __post_init__(self):
        object.__setattr__(self, "datoms", tuple(self.datoms))
        object.__setattr__(self, "children", _links(self.children, "a dn branch"))
        if not all(isinstance(d, Datom) for d in self.datoms):
            raise ValueError("a dn node holds datoms")
        if self.index not in DnNode.INDEXES:
            raise ValueError(f"a dn node names index '{self.index}'; the indexes are eavt, aevt, avet and tail")
        _whole(self.level, "a dn level")
        if self.index == DnNode.TAIL and self.level != 0:
            raise ValueError(f"a tail is a leaf, found level {self.level}")
        if self.index == DnNode.TAIL and not self.datoms:
            raise ValueError("an empty tail is no node: the db root's 't' is null instead")
        if self.level == 0 and self.children:
            raise ValueError("a leaf carries no 'c'")
        if self.level > 0 and (not self.datoms or len(self.children) != len(self.datoms)):
            raise ValueError(f"a branch holds one link per key, found {len(self.children)} links "
                             f"for {len(self.datoms)} keys")

    @staticmethod
    def leaf(index: str, datoms) -> "DnNode":
        return DnNode(0, index, datoms)

    @staticmethod
    def branch(level: int, index: str, datoms, children) -> "DnNode":
        return DnNode(level, index, datoms, children)

    @staticmethod
    def tail(datoms) -> "DnNode":
        """The datoms of transactions not yet folded into the indexes."""
        return DnNode(0, DnNode.TAIL, datoms)

    def encode(self) -> bytes:
        node = {nodes.KIND_KEY: nodes.KIND_DN, "l": self.level, "x": self.index, "e": list(self.datoms)}
        if self.level > 0:
            node["c"] = list(self.children)
        return nodes.encode(node)

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "DnNode":
        node = _decode(cid, data, nodes.KIND_DN, DnNode.REQUIRED)
        if node["l"] > 0 and "c" not in node:
            raise NodeFormatError("a 'dn' node lacks 'c': a branch links its children", cid)
        if node["l"] == 0 and "c" in node:
            raise NodeFormatError("a leaf carries no 'c'", cid)
        return _build(cid, lambda: DnNode(node["l"], node["x"], node["e"], node.get("c", ())))


# ------------------------------------------------------------------ rr and rv (P2-R-01)

WIDTH, BITS = 32, 5


@dataclass(frozen=True)
class RrRoot:
    """``{k:"rr", n: count, s: shift, r: link or null, t: [tail]}``: the ``vr`` shape over ``rv``
    interior nodes. A head whose tree holds an ``rr`` or ``rv`` node is ``PRef.v`` 2 (rule 2)."""
    count: int
    shift: int
    trie: Link | None
    tail: tuple

    WIDTH = WIDTH
    BITS = BITS
    REQUIRED = ("n", "s", "r", "t")

    def __post_init__(self):
        object.__setattr__(self, "tail", tuple(self.tail))
        if not all(isinstance(e, Embedded) for e in self.tail):
            raise ValueError("an rr tail holds embedded items")
        if self.trie is not None and not isinstance(self.trie, Link):
            raise ValueError("an rr trie is a link or None")
        _whole(self.count, "an rr count")
        if type(self.shift) is not int or self.shift < BITS or self.shift % BITS:
            raise ValueError(f"an rr shift is a positive multiple of {BITS}, found {self.shift}")
        if len(self.tail) > WIDTH:
            raise ValueError(f"an rr tail holds at most {WIDTH} elements, found {len(self.tail)}")
        if self.count < len(self.tail) or (self.trie is None and self.count != len(self.tail)):
            raise ValueError(f"an rr count of {self.count} does not fit a tail of {len(self.tail)}"
                             + (" and no trie" if self.trie is None else ""))
        if self.trie is not None and self.count == len(self.tail):
            # P2-R-01: an rv node holds at least one child, so a linked trie holds an element
            raise ValueError(f"an rr root links a trie but its count of {self.count} leaves the trie no element")

    def encode(self) -> bytes:
        return nodes.encode({nodes.KIND_KEY: nodes.KIND_RR, "n": self.count, "s": self.shift, "r": self.trie,
                             "t": list(self.tail)})

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "RrRoot":
        node = _decode(cid, data, nodes.KIND_RR, RrRoot.REQUIRED)
        return _build(cid, lambda: RrRoot(node["n"], node["s"], node["r"], node["t"]))


@dataclass(frozen=True)
class RvNode:
    """``{k:"rv", c: [link...], z: [cumulative sizes]}``, ``z`` only on a relaxed node."""
    children: tuple
    sizes: tuple | None

    REQUIRED = ("c",)

    def __post_init__(self):
        object.__setattr__(self, "children", _links(self.children, "an rv node"))
        if self.sizes is not None:
            object.__setattr__(self, "sizes", tuple(self.sizes))
        if not 1 <= len(self.children) <= WIDTH:
            raise ValueError(f"an rv node holds 1 to {WIDTH} children, found {len(self.children)}")
        if self.sizes is not None:
            if len(self.sizes) != len(self.children):
                raise ValueError("an rv size table holds one size per child")
            previous = 0
            for size in self.sizes:
                if type(size) is not int or size <= previous:
                    raise ValueError("an rv size table is strictly increasing from above 0")
                previous = size

    def encode(self) -> bytes:
        node = {nodes.KIND_KEY: nodes.KIND_RV, "c": list(self.children)}
        if self.sizes is not None:
            node["z"] = list(self.sizes)
        return nodes.encode(node)

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "RvNode":
        node = _decode(cid, data, nodes.KIND_RV, RvNode.REQUIRED)
        return _build(cid, lambda: RvNode(node["c"], node.get("z")))


# ------------------------------------------------------------------ t (P2-T-01)

def _id_order(char: CharId) -> tuple:
    """The order of character ids: the replica's UTF-8 bytes unsigned, then the counter."""
    return char.replica.encode("utf-8"), char.counter


@dataclass(frozen=True)
class _Char:
    parent: CharId | None
    left: bool
    deleted: bool
    char: str          # the character when live, "" when deleted

    def join(self, char_id: CharId, other: "_Char") -> "_Char":
        if (self.parent != other.parent or self.left != other.left
                or (not self.deleted and not other.deleted and self.char != other.char)):
            raise ValueError(f"two leaves disagree on character {char_id.name()}")
        gone = self.deleted or other.deleted
        return _Char(self.parent, self.left, gone, "" if gone else self.char)


@dataclass(frozen=True)
class TextLeaf:
    """``{k:"t", r: [run...], v: 1}`` in its one canonical form, so two replicas that hold the same
    characters write the same bytes. A writer puts a value that holds text under a ``PRef.v`` 2
    head (rule 3)."""
    runs: tuple

    VERSION = 1
    REQUIRED = ("r", "v")
    # PDT 2 phase 0 (P2-T-01, gate finding G1): the most characters, live and deleted, one leaf holds,
    # the node byte bound; a deleted run costs no text bytes, so this caps the tombstones that the
    # node bound alone leaves open, and every reader checks it before it expands a run
    MAX_CHARS = nodes.MAX_NODE_BYTES

    def __post_init__(self):
        object.__setattr__(self, "runs", tuple(self.runs))
        if not all(isinstance(r, TextRun) for r in self.runs):
            raise ValueError("a text leaf holds text runs")
        chars = _expand(self.runs)
        if _compress(chars) != list(self.runs):
            raise ValueError("the runs are not in canonical form: maximal, sorted by id")
        _order(chars)

    @staticmethod
    def of(runs) -> "TextLeaf":
        """The canonical leaf of some runs, in any order and split anywhere."""
        return TextLeaf(_compress(_expand(runs)))

    def union(self, other: "TextLeaf") -> "TextLeaf":
        """Every character of either leaf, deleted when either deleted it: Fugue's merge."""
        merged = _expand(self.runs)
        for char_id, char in _expand(other.runs).items():
            merged[char_id] = merged[char_id].join(char_id, char) if char_id in merged else char
        return TextLeaf(_compress(merged))

    def text(self) -> str:
        """The live text in Fugue order."""
        chars = _expand(self.runs)
        return "".join(chars[i].char for i in _order(chars))

    def encode(self) -> bytes:
        return nodes.encode({nodes.KIND_KEY: nodes.KIND_T, "r": list(self.runs), "v": TextLeaf.VERSION})

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "TextLeaf":
        node = _decode(cid, data, nodes.KIND_T, TextLeaf.REQUIRED)
        if node["v"] != TextLeaf.VERSION:
            raise NodeFormatError(f"text leaf version {node['v']}; this release reads version {TextLeaf.VERSION}", cid)
        return _build(cid, lambda: TextLeaf(node["r"]))


def _expand(runs) -> dict:
    """Every character by id, in the order of the runs: id order for the runs of a canonical leaf."""
    if sum(run.length for run in runs) > TextLeaf.MAX_CHARS:
        raise ValueError(f"a text leaf holds at most {TextLeaf.MAX_CHARS} characters, live and deleted")
    chars = {}
    for run in runs:
        for i in range(run.length):
            char_id = CharId(run.replica, run.counter + i)
            parent = run.parent if i == 0 else CharId(run.replica, run.counter + i - 1)
            if char_id in chars:
                raise ValueError(f"character {char_id.name()} appears twice")
            chars[char_id] = _Char(parent, i == 0 and run.side == TextRun.LEFT, run.deleted,
                                   "" if run.deleted else run.text[i])
    return chars


def _compress(chars: dict) -> list:
    """The maximal runs of characters in id order: a character continues the run before it when it
    comes from the same replica with the next counter, hangs right of that character, and shares
    its deleted flag."""
    out = []
    start = first = last = None
    length, text = 0, []
    for char_id, c in sorted(chars.items(), key=lambda item: _id_order(item[0])):
        continues = (last is not None and char_id.replica == last.replica and char_id.counter == last.counter + 1
                     and c.parent == last and not c.left and c.deleted == first.deleted)
        if not continues:
            if start is not None:
                out.append(_run(start, first, length, text))
            start, first, length, text = char_id, c, 0, []
        length += 1
        text.append(c.char)
        last = char_id
    if start is not None:
        out.append(_run(start, first, length, text))
    return out


def _run(start: CharId, first: _Char, length: int, text: list) -> TextRun:
    return TextRun(start.replica, start.counter, first.parent, TextRun.LEFT if first.left else TextRun.RIGHT,
                   length, first.deleted, "".join(text))


def _order(chars: dict) -> list:
    """The characters in Fugue order: left children, the character, right children, same-side
    siblings in id order, walked with an explicit stack so a long run costs no call depth. A
    ValueError when a parent is not in the leaf or the parents form a cycle."""
    lefts, rights, roots = {}, {}, []
    # the characters of a canonical leaf arrive in id order, so every sibling list is sorted; the
    # callers pass a leaf's own characters after the canonical check
    for char_id, c in chars.items():
        if c.parent is None:
            roots.append(char_id)
            continue
        if c.parent not in chars:
            raise ValueError(f"the parent {c.parent.name()} of {char_id.name()} is not in the leaf")
        (lefts if c.left else rights).setdefault(c.parent, []).append(char_id)
    out = []
    stack = [(r, False) for r in reversed(roots)]
    while stack:
        char_id, emit = stack.pop()
        if emit:
            out.append(char_id)
            continue
        stack.extend((r, False) for r in reversed(rights.get(char_id, ())))
        stack.append((char_id, True))
        stack.extend((left, False) for left in reversed(lefts.get(char_id, ())))
    if len(out) != len(chars):
        raise ValueError("the runs' parents form a cycle that the document root does not reach")
    return out


# ------------------------------------------------------------------ vg (P2-V-01)

@dataclass(frozen=True)
class VgNode:
    """``{k:"vg", r: root, b: [base roots], i: issuer, t: issued, p: [links to earlier vg nodes]}``.
    The build pins two points §3.10 leaves open: ``r`` and ``b`` are CID text, never links, so a
    walk of the chain reaches the chain alone; and ``p`` holds at most one link per base, so a
    merge keeps the lineage of both parents. No value root links a ``vg`` node and no head
    carries one inline (rule 4)."""
    root: str
    bases: tuple
    issuer: str
    issued: str
    previous: tuple

    REQUIRED = ("r", "b", "i", "t", "p")

    def __post_init__(self):
        object.__setattr__(self, "bases", tuple(self.bases))
        object.__setattr__(self, "previous", _links(self.previous, "a vg node's previous list"))
        if len(self.bases) > MAX_BASE:
            raise ValueError(f"a vg node names at most {MAX_BASE} bases, found {len(self.bases)}")
        if not cids.is_cid(self.root) or not all(cids.is_cid(b) for b in self.bases):
            raise ValueError("a vg node names its root and bases by CID")
        if len(self.previous) > len(self.bases):
            raise ValueError("a vg node links at most one earlier vg node per base")
        if not all(link.structured for link in self.previous):
            raise ValueError("a vg node links earlier vg nodes, which are dag-cbor")
        if not wire.is_agent_id(self.issuer):
            raise ValueError(f"a vg issuer is <peerId>/<localName>, found {self.issuer!r}")
        if wire.parse_hlc(self.issued) is None:
            raise ValueError(f"a vg issued stamp is canonical, found {self.issued!r}")

    def encode(self) -> bytes:
        return nodes.encode({nodes.KIND_KEY: nodes.KIND_VG, "r": self.root, "b": list(self.bases), "i": self.issuer,
                             "t": self.issued, "p": list(self.previous)})

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "VgNode":
        node = _decode(cid, data, nodes.KIND_VG, VgNode.REQUIRED)
        return _build(cid, lambda: VgNode(node["r"], node["b"], node["i"], node["t"], node["p"]))


# ------------------------------------------------------------------ bo (P2-B-02)

@dataclass(frozen=True)
class BoNode:
    """``{k:"bo", g: 4, n: size, p: parent chaining values, c: [links to child bo nodes]}`` over
    chunk groups of 16 BLAKE3 chunks (decision 10), reached only through ``pdt.bao`` (rule 5).
    The build pins the split rule so every port cuts the same tree:

    - ``p`` is one byte string, the parent pairs (left CV then right CV) in pre-order.
    - A node over at most ``LEAF_GROUPS`` groups (8 MiB) is a leaf holding every parent of its subtree,
      ``groups - 1`` of them; a full leaf encodes to 32,728 bytes (PDT 2 phase 4 measures, P2-Q-PRF-05,
      the owner's ruling of 2026-11-09, which cut the leaf from 256 MiB).
    - A larger node over G groups takes the smallest j >= 1 with G <= LEAF_GROUPS x FANOUT^j,
      cuts its subtree into aligned blocks of LEAF_GROUPS x FANOUT^(j-1) groups, links one child
      per block, and holds the parents above the cut, one fewer than its children."""
    size: int
    parents: bytes
    children: tuple

    GROUP_LOG = 4
    GROUP_BYTES = 1024 << GROUP_LOG
    PARENT_BYTES = 64
    LEAF_GROUPS = 1 << 9
    FANOUT = 1 << 4
    REQUIRED = ("g", "n", "p", "c")

    def __post_init__(self):
        object.__setattr__(self, "children", _links(self.children, "a bo node"))
        if type(self.parents) is not bytes:
            raise ValueError("a bo node's parents are one byte string")
        _whole(self.size, "a bo size")
        groups = BoNode.groups(self.size)
        blocks = BoNode.child_sizes(self.size)
        if len(self.children) != len(blocks):
            raise ValueError(f"a bo node over {groups} groups has {len(blocks)} children, found {len(self.children)}")
        expected = (len(blocks) if blocks else groups) - 1
        if len(self.parents) != expected * BoNode.PARENT_BYTES:
            over = f"{len(blocks)} children" if blocks else f"{groups} groups"
            raise ValueError(f"a bo node's {over} take {expected} parents, found {len(self.parents)} bytes")

    @staticmethod
    def groups(size: int) -> int:
        """The chunk groups of ``size`` bytes: at least one, since an empty blob is one empty chunk."""
        return max(1, -(-size // BoNode.GROUP_BYTES))

    @staticmethod
    def child_sizes(size: int) -> list:
        """The byte sizes of the child blocks of a node over ``size`` bytes; empty for a leaf."""
        groups = BoNode.groups(size)
        if groups <= BoNode.LEAF_GROUPS:
            return []
        block = BoNode.LEAF_GROUPS
        while groups > block * BoNode.FANOUT:
            block *= BoNode.FANOUT
        block_bytes = block * BoNode.GROUP_BYTES
        return [min(block_bytes, size - start) for start in range(0, size, block_bytes)]

    def encode(self) -> bytes:
        return nodes.encode({nodes.KIND_KEY: nodes.KIND_BO, "g": BoNode.GROUP_LOG, "n": self.size, "p": self.parents,
                             "c": list(self.children)})

    @staticmethod
    def decode(cid: str | None, data: bytes) -> "BoNode":
        node = _decode(cid, data, nodes.KIND_BO, BoNode.REQUIRED)
        if node["g"] != BoNode.GROUP_LOG:
            raise NodeFormatError(f"a bo node of group size 2^{node['g']} chunks; this release reads "
                                  f"2^{BoNode.GROUP_LOG} (decision 10)", cid)
        return _build(cid, lambda: BoNode(node["n"], node["p"], node["c"]))
