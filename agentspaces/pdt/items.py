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

"""The structured items of the PDT 2 node kinds (srad/agentspaces-pdt2.md §3.1.1, §3.9; PDT 2
phase 0, P2-D-01 and P2-T-01): a ``Datom`` of a ``dn`` node and a ``TextRun`` of a ``t`` node.
The node codec reads and writes their arrays; these types hold one decoded item each and refuse
a value outside its grammar with a ValueError, as Java's ``Datom`` and ``TextRun`` records do.

- A datom is ``[e, a, v, tx]``: the entity and the transaction as integers in Java's long range
  (a negative transaction marks a retraction, so it is never 0), the attribute as the keyword's
  print form ``":ns/name"``, and the value one of an ``int`` (an integer, or a ref under a
  ``:db.type/ref`` attribute), a ``str`` (text, or a keyword's print form), a ``bool``, ``bytes``,
  a finite ``float`` (float64 on the wire), a ``Link`` (a spilled value), or a ``Tagged`` pair.
- A run is ``[replica, counter, parent, side, length, deleted, text]``: ``parent`` is the Fugue
  parent of the run's first character as a ``CharId`` or None for the document root, ``length``
  counts code points, and a deleted run keeps its ids and drops its text."""

from __future__ import annotations

import math
import struct
import uuid as _uuid
from dataclasses import dataclass

_LONG_MIN, _LONG_MAX = -(1 << 63), (1 << 63) - 1


def is_long(value) -> bool:
    """Whether ``value`` is an ``int``, a ``bool`` excluded, inside Java's long range."""
    return type(value) is int and _LONG_MIN <= value <= _LONG_MAX


def _no_lone_surrogate(text: str, what: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{what} holds a lone surrogate") from None


@dataclass(frozen=True)
class Tagged:
    """A tagged datom value, ``[tag, inner]`` on the wire (§3.1.1): ``u`` over the 16 bytes of a
    UUID, ``i`` over epoch milliseconds, ``n`` over the minimal two's complement bytes of a big
    integer, as Java's ``BigInteger.toByteArray`` writes them."""
    tag: str
    inner: object

    UUID = "u"
    INSTANT = "i"
    BIGINT = "n"

    def __post_init__(self):
        if self.tag == Tagged.UUID:
            if type(self.inner) is not bytes or len(self.inner) != 16:
                raise ValueError("a uuid value holds 16 bytes")
        elif self.tag == Tagged.INSTANT:
            if not is_long(self.inner):
                raise ValueError("an instant value holds an integer of epoch milliseconds")
        elif self.tag == Tagged.BIGINT:
            if type(self.inner) is not bytes or not _minimal(self.inner):
                raise ValueError("a bigint value holds its minimal two's complement bytes")
        else:
            raise ValueError(f"unknown value tag '{self.tag}'")

    @staticmethod
    def uuid(value: _uuid.UUID) -> "Tagged":
        return Tagged(Tagged.UUID, value.bytes)

    @staticmethod
    def instant(epoch_millis: int) -> "Tagged":
        return Tagged(Tagged.INSTANT, epoch_millis)

    @staticmethod
    def bigint(value: int) -> "Tagged":
        magnitude = value if value >= 0 else ~value
        return Tagged(Tagged.BIGINT, value.to_bytes(magnitude.bit_length() // 8 + 1, "big", signed=True))

    def integer(self) -> int:
        """The big integer a ``n`` value holds."""
        return int.from_bytes(self.inner, "big", signed=True)

    def as_uuid(self) -> _uuid.UUID:
        """The UUID a ``u`` value holds."""
        return _uuid.UUID(bytes=self.inner)


def _minimal(b: bytes) -> bool:
    """Whether bytes are what ``BigInteger.toByteArray`` writes: non-empty, no redundant sign byte."""
    if not b:
        return False
    if len(b) == 1:
        return True
    return not (b[0] == 0 and b[1] < 0x80) and not (b[0] == 0xFF and b[1] >= 0x80)


def _datom_value_ok(v) -> bool:
    from .nodes import Link
    if type(v) is float:
        if not math.isfinite(v):
            raise ValueError(f"a datom float is finite, found {v}")
        return True
    if type(v) is int:
        if not is_long(v):
            raise ValueError("a datom integer lies in Java's long range")
        return True
    return type(v) in (str, bool, bytes, Link, Tagged)


@dataclass(frozen=True, eq=False)
class Datom:
    """One datom of a ``dn`` node (PDT 2 phase 0, P2-D-01). Two datoms are equal when their
    values are equal and of one type, so ``True``, ``1`` and ``1.0`` stay three values."""
    e: int
    a: str
    v: object
    tx: int

    def __post_init__(self):
        if not is_long(self.e):
            raise ValueError("a datom's entity is an integer in Java's long range")
        if not is_long(self.tx):
            raise ValueError("a datom's tx is an integer in Java's long range")
        if self.tx == 0:
            # P2-D-01, §3.1.1: the sign of tx marks a retraction, so 0 has no retraction form
            raise ValueError("a datom's tx is non-zero: its sign marks a retraction")
        if type(self.a) is not str:
            raise ValueError("a datom's attribute is text, the keyword's print form")
        _no_lone_surrogate(self.a, "a datom's attribute")
        if type(self.v) is str:
            _no_lone_surrogate(self.v, "a datom's text")
        if not _datom_value_ok(self.v):
            raise ValueError("a datom value is an integer, text, a boolean, bytes, a float64, a link, "
                             f"or a tagged pair, found {type(self.v).__name__}")

    def _key(self) -> tuple:
        # a float compares by its float64 bits, so 0.0 and -0.0, which encode apart, stay apart
        v = struct.pack(">d", self.v) if type(self.v) is float else self.v
        return self.e, self.a, type(self.v), v, self.tx

    def __eq__(self, other):
        return isinstance(other, Datom) and self._key() == other._key()

    def __hash__(self):
        return hash(self._key())


@dataclass(frozen=True)
class CharId:
    """A character id of a text leaf: the replica and the counter."""
    replica: str
    counter: int

    def __post_init__(self):
        if type(self.replica) is not str or not self.replica:
            raise ValueError("a character id names a non-empty replica")
        _no_lone_surrogate(self.replica, "a character id's replica")
        if not is_long(self.counter) or self.counter < 0:
            raise ValueError(f"a character counter is non-negative, found {self.counter}")

    def name(self) -> str:
        return f"{self.replica}:{self.counter}"


@dataclass(frozen=True)
class TextRun:
    """One run of a text leaf, kind ``t`` (PDT 2 phase 0, P2-T-01): characters from one replica
    with consecutive counters, each after the first the right child of the one before it."""
    replica: str
    counter: int
    parent: CharId | None
    side: str
    length: int
    deleted: bool
    text: str

    LEFT = "L"
    RIGHT = "R"

    def __post_init__(self):
        if type(self.replica) is not str or not self.replica:
            raise ValueError("a run names a non-empty replica")
        _no_lone_surrogate(self.replica, "a run's replica")
        if not is_long(self.counter) or self.counter < 0:
            raise ValueError(f"a run counter is non-negative, found {self.counter}")
        if self.parent is not None and not isinstance(self.parent, CharId):
            raise ValueError("a run's parent is a character id or None")
        if self.side not in (TextRun.LEFT, TextRun.RIGHT):
            raise ValueError(f"a run side is L or R, found '{self.side}'")
        if self.parent is None and self.side == TextRun.LEFT:
            # P2-T-01: the document root is the leftmost neighbour of every insert, so Fugue gives
            # it right children only, and every port reads a root child in one place
            raise ValueError("a child of the document root hangs on its right, found side L")
        if not is_long(self.length) or self.length < 1:
            raise ValueError(f"a run length is at least 1, found {self.length}")
        if self.counter > _LONG_MAX - self.length:
            raise ValueError("a run's counters pass 2^63 - 1")
        if type(self.deleted) is not bool:
            raise ValueError("a run's deleted flag is a boolean")
        if type(self.text) is not str:
            raise ValueError("a run's text is text")
        _no_lone_surrogate(self.text, "a run's text")
        if self.deleted and self.text:
            raise ValueError("a deleted run carries no text")
        if not self.deleted and len(self.text) != self.length:
            raise ValueError(f"a live run of length {self.length} holds {len(self.text)} code points")

    def first(self) -> CharId:
        return CharId(self.replica, self.counter)
