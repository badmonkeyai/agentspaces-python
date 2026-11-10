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

"""The node codec (srad/agentspaces-pdt.md §3.1, §10.2; PD-N-01, PD-N-03,
PD-N-04, PD-F-01): a structured node is a CBOR map with text keys in the RFC 8949
deterministic form (definite lengths, shortest integers, keys sorted by length
then bytes, which is the DAG-CBOR order), a link is tag 42 over ``0x00`` and the
binary CID, and an application key or value is an embedded CBOR item spliced in
unchanged and recovered by skipping one item. A bare link item in a value slot
names a spilled node (PD-N-05) and counts as a link of the node.

Schemas: ``m`` {d, n, e, c, cnt}, ``mc`` {e}, ``v`` {c | e}, ``vr`` {n, s, r, t},
``b`` {h, c, z}, ``x`` {v}, ``sn`` {ct, ep, ln, nc}.

PDT 2 phase 0 (srad/agentspaces-pdt2.md §3, §6.10.3 rules 1 to 6) adds the seven level-2
kinds, whose fields are strict DAG-CBOR down to every item (no embedded application item
except a ``db`` root's schema and the elements of an ``rr`` tail, which keep the rules above):
``db`` {v, s, me, mt, bf, i: {aevt, avet, eavt} links in that order, t: tail link or null}
(P2-D-01), ``dn`` {l, x text, e [datom], c} (P2-D-01), ``rr`` as ``vr`` and ``rv`` {c, z}
(P2-R-01), ``t`` {r [run], v} (P2-T-01), ``vg`` {r CID text, b [CID text], i text, t text,
p [link]} (P2-V-01), and ``bo`` {g, n, p bytes, c} (P2-B-02). Their text is well-formed UTF-8,
their integers are shortest and inside Java's long range, and a datom float is a finite float64;
the typed readers of ``kinds`` check the rules that span fields. Kinds ``s``, ``tm`` and ``ec``
are reserved (PD-F-01, P2-F-04)."""

from __future__ import annotations

from dataclasses import dataclass

import math
import struct

from .. import cbor
from . import cids
from .items import CharId, Datom, Tagged, TextRun

MAX_NODE_BYTES = 1024 * 1024
MAX_LINKS = 1024
MAX_DEPTH = 64
_LONG_MAX = (1 << 63) - 1
LINK_TAG = 42
KIND_KEY = "k"

KIND_M, KIND_MC, KIND_V, KIND_VR, KIND_B, KIND_X = "m", "mc", "v", "vr", "b", "x"
#: The sealed envelope of the ``sealed-nodes`` mode (PD-P-05, srad/agentspaces-pdt.md
#: §10.2): ``{k:"sn", ct: ciphertext and tag, ep: epoch, ln: [links of the plaintext],
#: nc: nonce}``. This port walks it (its links are in the clear) and does not open it.
KIND_SN = "sn"
#: PDT 2 phase 0 (srad/agentspaces-pdt2.md §6.10.3, rules 1 to 5): the level-2 kinds live only where
#: no level-1 reader looks, ``db``, ``dn``, ``rr``, ``rv`` and ``t`` under a ``PRef.v`` 2 head, and
#: ``vg`` and ``bo`` behind the reserved attributes ``pdt.ancestry`` and ``pdt.bao``.
KIND_DB, KIND_DN, KIND_RR, KIND_RV, KIND_T, KIND_VG, KIND_BO = "db", "dn", "rr", "rv", "t", "vg", "bo"
LEVEL1_KINDS = frozenset({KIND_M, KIND_MC, KIND_V, KIND_VR, KIND_B, KIND_X, KIND_SN})
KINDS = LEVEL1_KINDS | {KIND_DB, KIND_DN, KIND_RR, KIND_RV, KIND_T, KIND_VG, KIND_BO}
#: ``s`` for the sorted map, ``tm`` for text marks, ``ec`` for erasure-coded stripes (P2-F-04).
RESERVED_KINDS = {"s", "tm", "ec"}

UINT, LINK, LINK_OR_NULL, LINKS, EMBEDDED, EMBEDDEDS, UINTS, BYTES = range(8)
# PDT 2 phase 0 (P2-D-01, P2-T-01, P2-V-01): the strict field types of the level-2 kinds
TEXT, CID, CIDS, INDEX, DATOMS, RUNS = range(8, 14)
#: The keys of a ``db`` root's index map, in DAG-CBOR order (PDT 2 phase 0, P2-D-01).
INDEX_KEYS = ("aevt", "avet", "eavt")
SCHEMAS = {
    KIND_M: {"d": UINT, "n": UINT, "e": EMBEDDEDS, "c": LINKS, "cnt": UINT},
    KIND_MC: {"e": EMBEDDEDS},
    KIND_V: {"c": LINKS, "e": EMBEDDEDS},
    KIND_VR: {"n": UINT, "s": UINT, "r": LINK_OR_NULL, "t": EMBEDDEDS},
    KIND_B: {"h": UINT, "c": LINKS, "z": UINTS},
    KIND_X: {"v": EMBEDDED},
    KIND_SN: {"ct": BYTES, "ep": UINT, "ln": LINKS, "nc": BYTES},
    # PDT 2 phase 0 (srad/agentspaces-pdt2.md §3.1.1, §3.5, §3.7, §3.9, §3.10)
    KIND_DB: {"v": UINT, "s": EMBEDDED, "me": UINT, "mt": UINT, "bf": UINT, "i": INDEX, "t": LINK_OR_NULL},
    KIND_DN: {"l": UINT, "x": TEXT, "e": DATOMS, "c": LINKS},
    KIND_RR: {"n": UINT, "s": UINT, "r": LINK_OR_NULL, "t": EMBEDDEDS},
    KIND_RV: {"c": LINKS, "z": UINTS},
    KIND_T: {"r": RUNS, "v": UINT},
    KIND_VG: {"r": CID, "b": CIDS, "i": TEXT, "t": TEXT, "p": LINKS},
    KIND_BO: {"g": UINT, "n": UINT, "p": BYTES, "c": LINKS},
}
#: An ``sn`` node may reach 1 MiB plus 48 KiB (a 1 MiB plaintext, the tag, the nonce,
#: and up to 1,024 links in the clear); every other kind keeps the 1 MiB bound.
MAX_SEALED_NODE_BYTES = 1024 * 1024 + 48 * 1024

LINK_BYTES = 1 + cids.BINARY_LENGTH          # 0x00 and the binary CID
LINK_ITEM_LENGTH = 4 + LINK_BYTES             # d8 2a 58 25 00 <cid>


class NodeFormatError(ValueError):
    """A refusal of PD-N-04, naming the rule and the CID when known."""

    def __init__(self, rule: str, cid: str | None = None):
        super().__init__(f"{cid}: {rule}" if cid else rule)
        self.rule = rule
        self.cid = cid


class NodeUnavailable(RuntimeError):
    """A node a value needed could not be loaded (PD-V-06)."""

    def __init__(self, cid: str, sources: list | None = None, message: str | None = None):
        super().__init__(message or f"node {cid} is not available (sources tried: {sources or []})")
        self.cid = cid
        self.sources = list(sources or [])


@dataclass(frozen=True)
class Link:
    cid: str

    def __post_init__(self):
        cids.parse(self.cid)

    @property
    def structured(self) -> bool:
        return cids.codec_of(self.cid) == cids.DAG_CBOR


@dataclass(frozen=True)
class Embedded:
    """One application CBOR item, as ``cbor.dumps`` produced it."""
    bytes: bytes

    def __post_init__(self):
        if not self.bytes:
            raise ValueError("an embedded item has at least one byte")


def compare_key(key: str) -> tuple:
    encoded = key.encode("utf-8")
    return (len(encoded), encoded)


# ------------------------------------------------------------------ links

def link_item(cid: str) -> bytes:
    """The CBOR item a value slot carries for a spilled node."""
    return b"\xd8\x2a\x58\x25\x00" + cids.binary(cid)


def is_link_shaped(item: bytes) -> bool:
    return (len(item) == LINK_ITEM_LENGTH and item[0] == 0xD8 and item[1] == LINK_TAG
            and item[2] == 0x58 and item[3] == LINK_BYTES and item[4] == 0x00)


def link_cid(item: bytes) -> str:
    return cids.from_binary(item[5:])


def _check_embedded(key: str, item: bytes, key_slot: bool) -> None:
    """Refuses an embedded item outside the wire encoding (HLC round six, 2026-11-08, owner
    ruling F2 and change JD-4): every application key and value of a node is a document under
    rules S1 to S12, so tags 2, 3 and 4 stand in it and no other tag does. A bare link item in
    a value slot, a spilled value (PD-N-05), is the one exception; a key never spills, so a
    link item in a key slot is refused, as Java's ``NodeCodec.checkEmbedded`` refuses it."""
    if not key_slot and is_link_shaped(item):
        return
    try:
        cbor.loads(item)
    except ValueError as e:
        slot = "key item" if key_slot else "embedded item"
        raise NodeFormatError(f"'{key}' {slot} breaks the wire encoding: {e}") from None


def _is_keyed(kind: str, key: str) -> bool:
    """Whether a field of a kind is an entry list whose even slots hold keys."""
    return kind in (KIND_M, KIND_MC) and key == "e"


def spilled_link(item: bytes) -> str | None:
    """The CID an embedded item names when it is exactly a link item, else None."""
    if not is_link_shaped(item):
        return None
    try:
        return link_cid(item)
    except ValueError as e:
        raise NodeFormatError(f"spilled value link refused: {e}")


# ------------------------------------------------------------------ encode

def _header(major: int, value: int) -> bytes:
    m = major << 5
    if value < 24:
        return bytes([m | value])
    if value < 0x100:
        return bytes([m | 24, value])
    if value < 0x10000:
        return bytes([m | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([m | 26]) + value.to_bytes(4, "big")
    return bytes([m | 27]) + value.to_bytes(8, "big")


def _schema_of(kind) -> dict:
    if not isinstance(kind, str):
        raise NodeFormatError(f"'{KIND_KEY}' must be a text string")
    if kind in RESERVED_KINDS:
        raise NodeFormatError(f"kind '{kind}' is reserved and has no schema in this release")
    schema = SCHEMAS.get(kind)
    if schema is None:
        raise NodeFormatError(f"unknown kind '{kind}'")
    return schema


def _uint(key: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NodeFormatError(f"'{key}' must be an unsigned integer, found {value!r}")
    if value > _LONG_MAX:
        # every integer of a node lies in Java's long range, as NodeCodec reads it
        raise NodeFormatError(f"'{key}' must be an unsigned integer below 2^63, found {value}")
    return value



def _strict_text(key: str, value) -> bytes:
    """The UTF-8 of a text field of a level-2 kind (PDT 2 phase 0): a lone surrogate is refused."""
    if not isinstance(value, str):
        raise NodeFormatError(f"'{key}' must hold text, found {type(value).__name__}")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise NodeFormatError(f"'{key}' text is not well-formed UTF-8: it holds a lone surrogate") from None


def _cid_text(key: str, value) -> bytes:
    """A CID held as text (PDT 2 phase 0, P2-V-01): a ``vg`` node names roots without linking them."""
    if not cids.is_cid(value):
        found = f"'{value}'" if isinstance(value, str) else type(value).__name__
        raise NodeFormatError(f"'{key}' must hold a CID as text, found {found}")
    return value.encode("utf-8")


def encode(node: dict) -> bytes:
    """The canonical bytes of a node: ``k`` and the keys of its kind's schema."""
    if KIND_KEY not in node:
        raise NodeFormatError(f"node has no '{KIND_KEY}' field")
    schema = _schema_of(node[KIND_KEY])
    for key in node:
        if key != KIND_KEY and key not in schema:
            raise NodeFormatError(f"key '{key}' outside the schema of kind '{node[KIND_KEY]}'")
    keys = sorted(node, key=compare_key)
    out = bytearray(_header(5, len(keys)))
    links = 0

    def link(value):
        nonlocal links
        if not isinstance(value, Link):
            raise NodeFormatError(f"'{key}' must hold a link, found {type(value).__name__}")
        links += 1
        if links > MAX_LINKS:
            raise NodeFormatError(f"node has more than {MAX_LINKS} links")
        out.extend(_header(6, LINK_TAG))
        out.extend(_header(2, LINK_BYTES))
        out.append(0x00)
        out.extend(cids.binary(value.cid))

    def text(key, encoded: bytes):
        out.extend(_header(3, len(encoded)))
        out.extend(encoded)

    def sint(value: int):
        out.extend(_header(0, value) if value >= 0 else _header(1, -1 - value))

    def datom(d):
        if not isinstance(d, Datom):
            raise NodeFormatError(f"'{key}' must hold datoms, found {type(d).__name__}")
        out.extend(_header(4, 4))
        sint(d.e)
        text(key, _strict_text(key, d.a))
        v = d.v
        if type(v) is bool:
            out.append(0xF5 if v else 0xF4)
        elif type(v) is int:
            sint(v)
        elif type(v) is str:
            text(key, _strict_text(key, v))
        elif type(v) is bytes:
            out.extend(_header(2, len(v)))
            out.extend(v)
        elif type(v) is float:
            out.append(0xFB)
            out.extend(struct.pack(">d", v))
        elif isinstance(v, Link):
            link(v)
        else:
            out.extend(_header(4, 2))
            text(key, v.tag.encode("utf-8"))
            if type(v.inner) is int:
                sint(v.inner)
            else:
                out.extend(_header(2, len(v.inner)))
                out.extend(v.inner)
        sint(d.tx)

    def text_run(r):
        if not isinstance(r, TextRun):
            raise NodeFormatError(f"'{key}' must hold text runs, found {type(r).__name__}")
        out.extend(_header(4, 7))
        text(key, _strict_text(key, r.replica))
        out.extend(_header(0, r.counter))
        if r.parent is None:
            out.append(0xF6)
        else:
            out.extend(_header(4, 2))
            text(key, _strict_text(key, r.parent.replica))
            out.extend(_header(0, r.parent.counter))
        text(key, r.side.encode("utf-8"))
        out.extend(_header(0, r.length))
        out.append(0xF5 if r.deleted else 0xF4)
        text(key, _strict_text(key, r.text))

    def embedded(value, key_slot=False):
        nonlocal links
        if isinstance(value, bytes):
            value = Embedded(value)
        if not isinstance(value, Embedded):
            raise NodeFormatError(f"'{key}' must hold an embedded CBOR item, found {type(value).__name__}")
        if skip(value.bytes, 0) != len(value.bytes):
            raise NodeFormatError(f"'{key}' embedded item has trailing bytes")
        _check_embedded(key, value.bytes, key_slot)
        if is_link_shaped(value.bytes):
            links += 1
            if links > MAX_LINKS:
                raise NodeFormatError(f"node has more than {MAX_LINKS} links")
        out.extend(value.bytes)

    for key in keys:
        encoded = key.encode("utf-8")
        out.extend(_header(3, len(encoded)))
        out.extend(encoded)
        value = node[key]
        if key == KIND_KEY:
            encoded = value.encode("utf-8")
            out.extend(_header(3, len(encoded)))
            out.extend(encoded)
            continue
        field = schema[key]
        if field == UINT:
            out.extend(_header(0, _uint(key, value)))
        elif field == LINK:
            link(value)
        elif field == LINK_OR_NULL:
            if value is None:
                out.append(0xF6)
            else:
                link(value)
        elif field == LINKS:
            if not isinstance(value, list):
                raise NodeFormatError(f"'{key}' must be a list")
            out.extend(_header(4, len(value)))
            for item in value:
                link(item)
        elif field == EMBEDDED:
            embedded(value)
        elif field == EMBEDDEDS:
            if not isinstance(value, list):
                raise NodeFormatError(f"'{key}' must be a list")
            out.extend(_header(4, len(value)))
            keyed = _is_keyed(node[KIND_KEY], key)
            for i, item in enumerate(value):
                embedded(item, keyed and i % 2 == 0)
        elif field == UINTS:
            if not isinstance(value, list):
                raise NodeFormatError(f"'{key}' must be a list")
            out.extend(_header(4, len(value)))
            for item in value:
                out.extend(_header(0, _uint(key, item)))
        elif field == BYTES:
            if not isinstance(value, (bytes, bytearray)):
                raise NodeFormatError(f"'{key}' must be a byte string")
            out.extend(_header(2, len(value)))
            out.extend(value)
        elif field == TEXT:
            text(key, _strict_text(key, value))
        elif field == CID:
            text(key, _cid_text(key, value))
        elif field == CIDS:
            for item in _list(key, value, out):
                text(key, _cid_text(key, item))
        elif field == INDEX:
            if not isinstance(value, dict) or sorted(value) != list(INDEX_KEYS):
                found = sorted(value) if isinstance(value, dict) else type(value).__name__
                raise NodeFormatError(f"'{key}' must map exactly aevt, avet and eavt to links, found {found}")
            out.extend(_header(5, len(INDEX_KEYS)))
            for index in INDEX_KEYS:
                text(key, index.encode("utf-8"))
                link(value[index])
        elif field == DATOMS:
            for item in _list(key, value, out):
                datom(item)
        elif field == RUNS:
            for item in _list(key, value, out):
                text_run(item)
    if len(out) > _bound_of(node[KIND_KEY]):
        raise NodeFormatError(f"node of {len(out)} bytes exceeds {_bound_of(node[KIND_KEY])} bytes")
    return bytes(out)


def _list(key: str, value, out: bytearray) -> list:
    """A list field's items, after its array header is written."""
    if not isinstance(value, (list, tuple)):
        raise NodeFormatError(f"'{key}' must be a list")
    out.extend(_header(4, len(value)))
    return value


def _bound_of(kind) -> int:
    """The byte bound of a kind: the sealed bound for an ``sn`` envelope, 1 MiB otherwise."""
    return MAX_SEALED_NODE_BYTES if kind == KIND_SN else MAX_NODE_BYTES


# ------------------------------------------------------------------ decode

class _In:
    __slots__ = ("b", "p", "links")

    def __init__(self, b: bytes):
        self.b = b
        self.p = 0
        self.links = 0

    def peek(self) -> int:
        if self.p >= len(self.b):
            raise NodeFormatError("truncated node")
        return self.b[self.p]

    def u8(self) -> int:
        v = self.peek()
        self.p += 1
        return v

    def advance(self, count: int) -> None:
        if count < 0 or count > len(self.b) - self.p:
            raise NodeFormatError("truncated node")
        self.p += count

    def argument(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self.u8()
        if info == 25:
            return (self.u8() << 8) | self.u8()
        if info == 26:
            v = 0
            for _ in range(4):
                v = (v << 8) | self.u8()
            return v
        if info == 27:
            v = 0
            for _ in range(8):
                v = (v << 8) | self.u8()
            return v
        if info in (28, 29, 30):
            raise NodeFormatError(f"reserved additional information {info}")
        raise NodeFormatError("indefinite length in a structured field")

    def header(self, major: int, what: str) -> int:
        initial = self.u8()
        if initial >> 5 != major:
            raise NodeFormatError(f"'{what}' must be CBOR major type {major}, found major type {initial >> 5}")
        info = initial & 0x1F
        if info == 31:
            raise NodeFormatError(f"'{what}' uses an indefinite length")
        value = self.argument(info)
        if value > _LONG_MAX:
            # Java's NodeCodec reads every head into a long and refuses one past it
            raise NodeFormatError(f"'{what}' integer above 2^63 - 1")
        shortest = {24: value >= 24, 25: value >= 0x100, 26: value >= 0x10000, 27: value >= 0x100000000}.get(info, True)
        if not shortest:
            raise NodeFormatError(f"'{what}' integer not in shortest form")
        return value

    def text(self, what: str) -> str:
        """Text that is well-formed UTF-8. The reader refuses a malformed sequence with the
        NodeFormatError every caller catches, a key or a kind included, as Java refuses such a key
        as outside the schema and such a kind as unknown (PDT 2 phase 0, P2-D-01)."""
        length = self.header(3, what)
        if length > len(self.b) - self.p:
            raise NodeFormatError("truncated node")
        try:
            s = self.b[self.p:self.p + length].decode("utf-8")
        except UnicodeDecodeError:
            raise NodeFormatError(f"'{what}' text is not well-formed UTF-8") from None
        self.p += length
        return s

    def cid_text(self, what: str) -> str:
        text = self.text(what)
        if not cids.is_cid(text):
            raise NodeFormatError(f"'{what}' must hold a CID as text, found '{text}'")
        return text

    def sint(self, what: str) -> int:
        """A signed integer under its shortest head: major type 0 or 1, within Java's long range."""
        if self.peek() >> 5 == 1:
            return -1 - self.header(1, what)
        return self.header(0, what)

    def boolean(self, what: str) -> bool:
        initial = self.u8()
        if initial in (0xF4, 0xF5):
            return initial == 0xF5
        raise NodeFormatError(f"'{what}' must be a boolean, found initial byte 0x{initial:02x}")

    def byte_string(self, what: str) -> bytes:
        n = self.header(2, what)
        start = self.p
        self.advance(n)
        return bytes(self.b[start:self.p])

    def datom(self, what: str) -> Datom:
        """One datom ``[e, a, v, tx]`` under the value grammar of §3.1.1 (PDT 2 phase 0, P2-D-01)."""
        if self.header(4, what) != 4:
            raise NodeFormatError(f"'{what}' datom must hold four items")
        e = self.sint(what)
        a = self.text(what)
        v = self._datom_value(what)
        tx = self.sint(what)
        try:
            return Datom(e, a, v, tx)
        except ValueError as refused:
            raise NodeFormatError(f"'{what}' datom refused: {refused}") from None

    def _datom_value(self, what: str):
        initial = self.peek()
        major = initial >> 5
        if major in (0, 1):
            return self.sint(what)
        if major == 2:
            return self.byte_string(what)
        if major == 3:
            return self.text(what)
        if major == 6:
            return self.link(what)
        if major == 4:
            if self.header(4, what) != 2:
                raise NodeFormatError(f"'{what}' tagged datom value must hold two items")
            tag = self.text(what)
            if tag == Tagged.INSTANT:
                if self.peek() >> 5 not in (0, 1):
                    raise NodeFormatError(f"'{what}' instant value must hold an integer")
                inner = self.sint(what)
            elif tag in (Tagged.UUID, Tagged.BIGINT):
                inner = self.byte_string(what)
            else:
                raise NodeFormatError(f"'{what}' unknown value tag '{tag}'")
            try:
                return Tagged(tag, inner)
            except ValueError as refused:
                raise NodeFormatError(f"'{what}' {refused}") from None
        if major == 7:
            if initial in (0xF4, 0xF5):
                return self.boolean(what)
            if initial == 0xFB:
                self.advance(1)
                start = self.p
                self.advance(8)
                d = struct.unpack(">d", self.b[start:self.p])[0]
                if not math.isfinite(d):
                    raise NodeFormatError(f"'{what}' float value is not finite")
                return d
            if initial == 0xFA:
                raise NodeFormatError(f"'{what}' float value is float32; a datom float is float64")
            if initial == 0xF9:
                raise NodeFormatError(f"'{what}' float value is a half float; a datom float is float64")
            if initial == 0xF6:
                raise NodeFormatError(f"'{what}' datom value is null")
            raise NodeFormatError(f"'{what}' datom value is simple value 0x{initial:02x}")
        raise NodeFormatError(f"'{what}' datom value of major type {major}; the grammar holds integers, bytes, "
                              "text, links, tagged pairs, booleans and float64")

    def run(self, what: str) -> TextRun:
        """One run ``[replica, counter, parent, side, length, deleted, text]`` (PDT 2 phase 0, P2-T-01)."""
        if self.header(4, what) != 7:
            raise NodeFormatError(f"'{what}' run must hold seven items")
        replica = self.text(what)
        counter = self.header(0, what)
        parent = None
        if self.peek() == 0xF6:
            self.advance(1)
        else:
            if self.header(4, what) != 2:
                raise NodeFormatError(f"'{what}' run parent must be null or [replica, counter]")
            parent_replica = self.text(what)
            parent_counter = self.header(0, what)
            try:
                parent = CharId(parent_replica, parent_counter)
            except ValueError as refused:
                raise NodeFormatError(f"'{what}' run parent refused: {refused}") from None
        side = self.text(what)
        length = self.header(0, what)
        deleted = self.boolean(what)
        text = self.text(what)
        try:
            return TextRun(replica, counter, parent, side, length, deleted, text)
        except ValueError as refused:
            raise NodeFormatError(f"'{what}' run refused: {refused}") from None

    def link(self, what: str) -> Link:
        self.links += 1
        if self.links > MAX_LINKS:
            raise NodeFormatError(f"node has more than {MAX_LINKS} links")
        tag = self.header(6, what)
        if tag != LINK_TAG:
            raise NodeFormatError(f"'{what}' carries tag {tag}; a link is tag {LINK_TAG}")
        length = self.header(2, what)
        if length != LINK_BYTES:
            raise NodeFormatError(f"'{what}' link of {length} bytes; a link holds 0x00 and a 36-byte CID")
        if self.u8() != 0x00:
            raise NodeFormatError(f"'{what}' link does not start with the 0x00 identity byte")
        if cids.BINARY_LENGTH > len(self.b) - self.p:
            raise NodeFormatError("truncated node")
        raw = self.b[self.p:self.p + cids.BINARY_LENGTH]
        self.p += cids.BINARY_LENGTH
        try:
            return Link(cids.from_binary(raw))
        except ValueError as e:
            raise NodeFormatError(f"'{what}' link refused: {e}")

    def embedded(self, what: str, key_slot: bool) -> Embedded:
        """Reads one embedded item, which must be in the wire encoding (``_check_embedded``); a
        link-shaped item in a value slot is a spilled-value link and counts against the link
        bound."""
        start = self.p
        _skip_item(self, 0)
        item = self.b[start:self.p]
        _check_embedded(what, item, key_slot)
        if is_link_shaped(item):
            self.links += 1
            if self.links > MAX_LINKS:
                raise NodeFormatError(f"node has more than {MAX_LINKS} links")
        return Embedded(item)


def _skip_item(inp: _In, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise NodeFormatError(f"CBOR nesting deeper than {MAX_DEPTH} levels")
    initial = inp.u8()
    major, info = initial >> 5, initial & 0x1F
    if major == 7:
        if info == 24:
            inp.advance(1)
        elif info == 25:
            inp.advance(2)
        elif info == 26:
            inp.advance(4)
        elif info == 27:
            inp.advance(8)
        elif info in (28, 29, 30):
            raise NodeFormatError(f"reserved additional information {info}")
        elif info == 31:
            raise NodeFormatError("unexpected break code")
        return
    if info == 31:
        if major in (2, 3):
            while inp.peek() != 0xFF:
                chunk = inp.u8()
                if chunk >> 5 != major or (chunk & 0x1F) == 31:
                    raise NodeFormatError("malformed indefinite string chunk")
                inp.advance(inp.argument(chunk & 0x1F))
            inp.advance(1)
        elif major == 4:
            while inp.peek() != 0xFF:
                _skip_item(inp, depth + 1)
            inp.advance(1)
        elif major == 5:
            while inp.peek() != 0xFF:
                _skip_item(inp, depth + 1)
                _skip_item(inp, depth + 1)
            inp.advance(1)
        else:
            raise NodeFormatError(f"indefinite length on major type {major}")
        return
    argument = inp.argument(info)
    if major in (0, 1):
        return
    if major in (2, 3):
        inp.advance(argument)
    elif major == 4:
        for _ in range(argument):
            _skip_item(inp, depth + 1)
    elif major == 5:
        for _ in range(argument):
            _skip_item(inp, depth + 1)
            _skip_item(inp, depth + 1)
    elif major == 6:
        _skip_item(inp, depth + 1)


def skip(data: bytes, offset: int) -> int:
    """The offset just past one CBOR item of any form (the embedded-item rule)."""
    inp = _In(data)
    inp.p = offset
    _skip_item(inp, 0)
    return inp.p


_SEALED_PREFIX = b"\xa5\x61\x6b\x62\x73\x6e"  # {k: "sn", ...}, five keys


def _scan(data: bytes):
    if len(data) > MAX_NODE_BYTES and not data.startswith(_SEALED_PREFIX):
        raise NodeFormatError(f"node of {len(data)} bytes exceeds {MAX_NODE_BYTES} bytes (1 MiB)")
    if len(data) > MAX_SEALED_NODE_BYTES:
        raise NodeFormatError(f"node of {len(data)} bytes exceeds {MAX_SEALED_NODE_BYTES} bytes (1 MiB + 48 KiB)")
    inp = _In(data)
    entries = inp.header(5, "node")
    kind, offsets, previous = None, {}, None
    for _ in range(entries):
        key = inp.text("key")
        if previous is not None:
            if compare_key(previous) == compare_key(key):
                raise NodeFormatError(f"duplicate key '{key}'")
            if compare_key(previous) > compare_key(key):
                raise NodeFormatError(f"keys out of canonical order: '{key}' after '{previous}'")
        previous = key
        offsets[key] = inp.p
        if key == KIND_KEY:
            kind = inp.text(KIND_KEY)
        else:
            _skip_item(inp, 0)
    if inp.p != len(data):
        raise NodeFormatError("trailing bytes after the node map")
    if kind is None:
        raise NodeFormatError(f"node has no '{KIND_KEY}' field")
    if len(data) > _bound_of(kind):
        raise NodeFormatError(f"node of {len(data)} bytes exceeds {MAX_NODE_BYTES} bytes (1 MiB)")
    return kind, offsets


def _read_field(inp: _In, key: str, field: int, keyed: bool):
    if field == UINT:
        return inp.header(0, key)
    if field == LINK:
        return inp.link(key)
    if field == LINK_OR_NULL:
        if inp.peek() == 0xF6:
            inp.advance(1)
            return None
        return inp.link(key)
    if field == LINKS:
        return [inp.link(key) for _ in range(inp.header(4, key))]
    if field == EMBEDDED:
        return inp.embedded(key, False)
    if field == EMBEDDEDS:
        return [inp.embedded(key, keyed and i % 2 == 0) for i in range(inp.header(4, key))]
    if field == UINTS:
        return [inp.header(0, key) for _ in range(inp.header(4, key))]
    if field == BYTES:
        return inp.byte_string(key)
    if field == TEXT:
        return inp.text(key)
    if field == CID:
        return inp.cid_text(key)
    if field == CIDS:
        return [inp.cid_text(key) for _ in range(inp.header(4, key))]
    if field == INDEX:
        if inp.header(5, key) != len(INDEX_KEYS):
            raise NodeFormatError(f"'{key}' must map exactly aevt, avet and eavt to links, in that order")
        index = {}
        for expected in INDEX_KEYS:
            if inp.text(key) != expected:
                raise NodeFormatError(f"'{key}' must map exactly aevt, avet and eavt to links, in that order")
            index[expected] = inp.link(key)
        return index
    if field == DATOMS:
        return [inp.datom(key) for _ in range(inp.header(4, key))]
    if field == RUNS:
        return [inp.run(key) for _ in range(inp.header(4, key))]
    raise AssertionError(field)


def decode(data: bytes, cid: str | None = None) -> dict:
    """A node in canonical key order: ints, ``Link``s, lists, and ``Embedded`` items."""
    try:
        kind, offsets = _scan(data)
        schema = _schema_of(kind)
        inp = _In(data)
        node = {}
        for key, offset in offsets.items():
            if key == KIND_KEY:
                node[key] = kind
                continue
            field = schema.get(key)
            if field is None:
                raise NodeFormatError(f"key '{key}' outside the schema of kind '{kind}'")
            inp.p = offset
            node[key] = _read_field(inp, key, field, _is_keyed(kind, key))
        return node
    except NodeFormatError as e:
        if e.cid is None and cid is not None:
            raise NodeFormatError(e.rule, cid) from None
        raise


def kind_of(data: bytes) -> str:
    return _scan(data)[0]


def links(data: bytes, cid: str | None = None) -> list[str]:
    """The linked CIDs of a node in field order, spilled-value links included; none for a raw chunk."""
    if cid is not None and cids.codec_of(cid) == cids.RAW:
        return []
    node = decode(data, cid)
    kind = node[KIND_KEY]
    out = []
    for key, value in node.items():
        if key == KIND_KEY:
            continue
        field = SCHEMAS[kind][key]
        if field in (EMBEDDED, EMBEDDEDS):
            items = value if isinstance(value, list) else [value]
            keyed = _is_keyed(kind, key)
            for i, item in enumerate(items):
                if keyed and i % 2 == 0:
                    continue
                spilled = spilled_link(item.bytes)
                if spilled is not None:
                    out.append(spilled)
        elif field in (LINK, LINK_OR_NULL):
            if value is not None:
                out.append(value.cid)
        elif field == LINKS:
            out.extend(link.cid for link in value)
        elif field == INDEX:
            out.extend(link.cid for link in value.values())
        elif field == DATOMS:
            # PDT 2 phase 0 (P2-D-01): a spilled datom value is a link of the node, as in an embedded slot
            out.extend(d.v.cid for d in value if isinstance(d.v, Link))
    return out
