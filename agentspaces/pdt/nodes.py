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
``b`` {h, c, z}, ``x`` {v}. Kinds ``s`` and ``rr`` are reserved."""

from __future__ import annotations

from dataclasses import dataclass

from . import cids

MAX_NODE_BYTES = 1024 * 1024
MAX_LINKS = 1024
MAX_DEPTH = 64
LINK_TAG = 42
KIND_KEY = "k"

KIND_M, KIND_MC, KIND_V, KIND_VR, KIND_B, KIND_X = "m", "mc", "v", "vr", "b", "x"
#: The sealed envelope of the ``sealed-nodes`` mode (PD-P-05, srad/agentspaces-pdt.md
#: §10.2): ``{k:"sn", ct: ciphertext and tag, ep: epoch, ln: [links of the plaintext],
#: nc: nonce}``. This port walks it (its links are in the clear) and does not open it.
KIND_SN = "sn"
KINDS = {KIND_M, KIND_MC, KIND_V, KIND_VR, KIND_B, KIND_X, KIND_SN}
RESERVED_KINDS = {"s", "rr"}

UINT, LINK, LINK_OR_NULL, LINKS, EMBEDDED, EMBEDDEDS, UINTS, BYTES = range(8)
SCHEMAS = {
    KIND_M: {"d": UINT, "n": UINT, "e": EMBEDDEDS, "c": LINKS, "cnt": UINT},
    KIND_MC: {"e": EMBEDDEDS},
    KIND_V: {"c": LINKS, "e": EMBEDDEDS},
    KIND_VR: {"n": UINT, "s": UINT, "r": LINK_OR_NULL, "t": EMBEDDEDS},
    KIND_B: {"h": UINT, "c": LINKS, "z": UINTS},
    KIND_X: {"v": EMBEDDED},
    KIND_SN: {"ct": BYTES, "ep": UINT, "ln": LINKS, "nc": BYTES},
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
    return value


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

    def embedded(value):
        nonlocal links
        if isinstance(value, bytes):
            value = Embedded(value)
        if not isinstance(value, Embedded):
            raise NodeFormatError(f"'{key}' must hold an embedded CBOR item, found {type(value).__name__}")
        if skip(value.bytes, 0) != len(value.bytes):
            raise NodeFormatError(f"'{key}' embedded item has trailing bytes")
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
            for item in value:
                embedded(item)
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
    if len(out) > _bound_of(node[KIND_KEY]):
        raise NodeFormatError(f"node of {len(out)} bytes exceeds {_bound_of(node[KIND_KEY])} bytes")
    return bytes(out)


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
        shortest = {24: value >= 24, 25: value >= 0x100, 26: value >= 0x10000, 27: value >= 0x100000000}.get(info, True)
        if not shortest:
            raise NodeFormatError(f"'{what}' integer not in shortest form")
        return value

    def text(self, what: str) -> str:
        length = self.header(3, what)
        if length > len(self.b) - self.p:
            raise NodeFormatError("truncated node")
        s = self.b[self.p:self.p + length].decode("utf-8")
        self.p += length
        return s

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

    def embedded(self) -> Embedded:
        start = self.p
        _skip_item(self, 0)
        item = self.b[start:self.p]
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


def _read_field(inp: _In, key: str, field: int):
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
        return inp.embedded()
    if field == EMBEDDEDS:
        return [inp.embedded() for _ in range(inp.header(4, key))]
    if field == UINTS:
        return [inp.header(0, key) for _ in range(inp.header(4, key))]
    if field == BYTES:
        n = inp.header(2, key)
        start = inp.p
        inp.advance(n)
        return bytes(inp.b[start:inp.p])
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
            node[key] = _read_field(inp, key, field)
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
            keyed = kind in (KIND_M, KIND_MC) and key == "e"
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
    return out
