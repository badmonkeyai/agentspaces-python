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

"""A text that merges (srad/agentspaces-pdt2.md §3.9; PDT 2 phase 7, P2-C-01 group T, P2-T-01 to P2-T-03, P2-T-05):
the Python port of Java's ``PText``. A text is a Fugue sequence of characters with ids, edited by one replica at a
time, that stores as a ``t`` leaf of runs (``kinds.TextLeaf``). Positions and lengths count Unicode code points.

An insert follows Fugue: the new characters hang as the right child of the character before the position when it
has no right child, else as the left child of the next character in Fugue order (deleted ones included), and each
further character as the right child of the one before it. The next character then has no left child, since it is
the leftmost of the right subtree, so the new characters sit exactly at the position. An insert at position 0 hangs
as the left child of the first character, or as the right child of the document root when the text is empty. A
replica numbers its characters from one more than the largest counter it holds, so typing at the cursor extends one
run. A delete keeps the characters' ids and drops their text. ``merge`` is the union of two texts, which every
replica computes alike.

A text value is the wire encoding of its leaf's map, ``{k:"t", r:[run...], v:1}``, the map indefinite as every
embedded item is (rule S8), a run the array ``[replica, counter, parent, side, length, deleted, text]`` and a parent
``[replica, counter]`` or null; ``from_wire`` reads exactly that form. A map value of text above 1 KiB spills to a
``t`` node holding the canonical node bytes of the same leaf (``values.spill``), and two texts that meet in a
map merge take their union (``PMap.merge3``). A head whose value holds a text is ``PRef.v`` 2 (rule 3)."""

from __future__ import annotations

import hashlib

from .. import cbor
from . import cids, nodes
from .items import CharId, TextRun
from .kinds import TextLeaf, _Char, _compress, _expand, _order

#: The first bytes of every text value: an indefinite map whose first key ``k`` holds ``"t"``.
TEXT_PREFIX = bytes.fromhex("bf616b6174")
#: The length of a replica id ``replica_of`` derives.
REPLICA_LENGTH = 8


def replica_of(agent_id: str) -> str:
    """The replica id of an agent (P2-T-02): the first five bytes of the SHA-256 of its id's text, as eight lower-case
    base32 characters."""
    return cids.base32_lower(hashlib.sha256(agent_id.encode("utf-8")).digest()[:5])


class PText:
    """An immutable text: every edit returns a new one. ``replica`` edits it; a text read from a value has none until
    ``with_replica`` names one."""

    def __init__(self, replica: str | None, order: tuple, chars: dict, leaf: TextLeaf | None = None):
        if replica is not None and (not isinstance(replica, str) or not replica):
            raise ValueError("a replica is non-empty text")
        self.replica = replica
        self._order = order
        self._chars = chars
        self._leaf = leaf

    @staticmethod
    def empty(replica: str) -> "PText":
        return PText(replica, (), {})

    @staticmethod
    def of(leaf: TextLeaf, replica: str | None = None) -> "PText":
        chars = _expand(leaf.runs)
        return PText(replica, tuple(_order(chars)), chars, leaf)

    # ---- reads

    def length(self) -> int:
        return sum(1 for c in self._order if not self._chars[c].deleted)

    def __len__(self) -> int:
        return self.length()

    def __str__(self) -> str:
        return "".join(self._chars[c].char for c in self._order)

    def order(self) -> list[CharId]:
        """Every character id in Fugue order, deleted ones included."""
        return list(self._order)

    def leaf(self) -> TextLeaf:
        """The canonical leaf of the characters: maximal runs in id order."""
        if self._leaf is None:
            self._leaf = TextLeaf(_compress(self._chars))
        return self._leaf

    def __eq__(self, other) -> bool:
        return isinstance(other, PText) and self.leaf() == other.leaf()

    def __hash__(self) -> int:
        return hash(self.leaf())

    def __repr__(self) -> str:
        return f"PText({str(self)!r})"

    # ---- writes

    def with_replica(self, replica: str) -> "PText":
        return PText(replica, self._order, self._chars, self._leaf)

    def insert(self, pos: int, inserted: str) -> "PText":
        """The text with characters inserted before a live position from 0 to ``length()``."""
        if self.replica is None:
            raise ValueError("a text read from a value edits under a replica: call with_replica first")
        live = [i for i, c in enumerate(self._order) if not self._chars[c].deleted]
        if pos < 0 or pos > len(live):
            raise IndexError(f"position {pos} of a text of {len(live)}")
        if not inserted:
            return self
        if len(inserted) > TextLeaf.MAX_CHARS - len(self._order):
            raise ValueError(f"a text holds at most {TextLeaf.MAX_CHARS} characters, live and deleted")
        if pos == 0:
            at = 0
            parent, left = (self._order[0], True) if self._order else (None, False)
        else:
            i = live[pos - 1]
            at = i + 1
            before = self._order[i]
            has_right = any(c.parent == before and not c.left for c in self._chars.values())
            parent, left = (self._order[i + 1], True) if has_right else (before, False)
        start = 1 + max((c.counter for c in self._order if c.replica == self.replica), default=-1)
        chars = dict(self._chars)
        fresh = []
        for k, ch in enumerate(inserted):
            char_id = CharId(self.replica, start + k)
            chars[char_id] = _Char(parent, left, False, ch) if k == 0 else _Char(fresh[-1], False, False, ch)
            fresh.append(char_id)
        return PText(self.replica, self._order[:at] + tuple(fresh) + self._order[at:], chars)

    def delete(self, pos: int, length: int) -> "PText":
        """The text with ``length`` live characters deleted from a live position."""
        live = [c for c in self._order if not self._chars[c].deleted]
        if pos < 0 or length < 0 or pos + length > len(live):
            raise IndexError(f"range [{pos}, {pos + length}) of a text of {len(live)}")
        if not length:
            return self
        chars = dict(self._chars)
        for char_id in live[pos:pos + length]:
            c = chars[char_id]
            chars[char_id] = _Char(c.parent, c.left, True, "")
        return PText(self.replica, self._order, chars)

    def merge(self, other: "PText") -> "PText":
        """The union of two texts (P2-T-03): every character of either, deleted when either deleted it, in Fugue
        order, edited by this text's replica; a ValueError when they give one character two parents, sides, or
        characters."""
        return PText.of(self.leaf().union(other.leaf()), self.replica)


# ------------------------------------------------------------------ the value form

def to_wire(leaf: TextLeaf) -> bytes:
    """The value form of a leaf: the wire encoding of ``{k:"t", r:[run...], v:1}``."""
    runs = [[r.replica, r.counter, None if r.parent is None else [r.parent.replica, r.parent.counter], r.side,
             r.length, r.deleted, r.text] for r in leaf.runs]
    return cbor.dumps({nodes.KIND_KEY: nodes.KIND_T, "r": runs, "v": TextLeaf.VERSION})


def from_wire(data: bytes) -> TextLeaf:
    """The leaf of a text value, read strictly: exactly the three keys, runs in canonical form, and bytes that are the
    value form of the leaf they read as; a ValueError otherwise."""
    value = cbor.loads(data)
    if not isinstance(value, dict) or list(value) != [nodes.KIND_KEY, "r", "v"] or value[nodes.KIND_KEY] != nodes.KIND_T \
            or not isinstance(value["r"], list) or type(value["v"]) is not int or value["v"] != TextLeaf.VERSION:
        raise ValueError('a text value is {k:"t", r:[run...], v:1}')
    runs = []
    for item in value["r"]:
        if not isinstance(item, list) or len(item) != 7:
            raise ValueError("a text run is [replica, counter, parent, side, length, deleted, text]")
        replica, counter, parent, side, length, deleted, chars = item
        if parent is not None:
            if not isinstance(parent, list) or len(parent) != 2 or not isinstance(parent[0], str):
                raise ValueError("a run's parent is [replica, counter] or null")
            parent = CharId(parent[0], parent[1])
        if not isinstance(replica, str) or not isinstance(side, str) or not isinstance(chars, str):
            raise ValueError("a text run is [replica, counter, parent, side, length, deleted, text]")
        runs.append(TextRun(replica, counter, parent, side, length, deleted, chars))
    leaf = TextLeaf(runs)
    if to_wire(leaf) != data:
        raise ValueError("the bytes are not the value form of the text they read as")
    return leaf


def is_text(data: bytes) -> bool:
    """Whether a value's CBOR is a text in its value form."""
    if not data.startswith(TEXT_PREFIX):
        return False
    try:
        from_wire(data)
        return True
    except ValueError:
        return False


def union(a: bytes, b: bytes) -> bytes | None:
    """The union of two text values, or None when they disagree on a character or when the union would pass the
    1 MiB node bound as a ``t`` node (the phase 6 review's T2), so the resolver decides the key on every replica."""
    try:
        merged = from_wire(a).union(from_wire(b))
        merged.encode()
        return to_wire(merged)
    except ValueError:
        return None
