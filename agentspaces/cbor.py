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

"""CBOR (RFC 8949) in the AgentSpaces wire encoding (HLC round six, 2026-11-08): the image
of Java's CborCodec encoder, a function of the value that Java, Python, TypeScript and Ruby
all reproduce byte for byte. ``dumps`` writes it and ``loads`` reads it and nothing else, so
a document this client decodes re-encodes to exactly the bytes it received (owner ruling
F3), and a signature over those bytes verifies alike everywhere.

The encoding, by the rules S1 to S12 of the definition:

- one item per document, nothing after it (S1); at most 64 nested arrays and maps, where the
  two-element array of a tag 4 decimal counts as a level, as Jackson counts it (S2);
- every head in its shortest form (S3); an integer inside Java's long range as a plain
  integer (S4), and outside it as Jackson's bignum, tag 2 over the magnitude for a positive
  value and tag 3 over the magnitude for a negative one (S9);
- definite byte strings (S5) and arrays (S7); text of shortest-form UTF-8 with no encoded
  surrogate, definite up to 3996 UTF-16 units and in Jackson's exact chunks past that (S6);
- indefinite maps (``BF ... FF``) whose keys are distinct text strings, in the order their
  writer wrote them (S8);
- a decimal as tag 4 over [exponent, mantissa] with its trailing zeros stripped and the
  exponent inside -(2^31-1) to 2^31-1 (S9); a bignum of at most 1000 bytes, alone or as a
  mantissa (S9); no other tag (S9);
- a ``float`` as float64 and a ``Float32`` as float32, the NaN of each width only as Java's
  NaN constant writes it, and no half float (S10); false, true and null as the only simple
  values (S11); a break only where it ends an indefinite map or text (S12).

Tags 2, 3 and 4 decode into ``int`` and ``decimal.Decimal`` (owner ruling F2), which hold
exactly the value and so re-encode to the bytes they came from."""

import struct
from decimal import Decimal

_BREAK = 0xFF


class Float32(float):
    """A float Java holds as a 32-bit ``float``, written under the float32 head ``FA``
    (HLC round six, 2026-11-08, rule S10). The constructor rounds its argument to the
    nearest float32, so the value re-encodes exactly."""

    def __new__(cls, value=0.0):
        return super().__new__(cls, struct.unpack(">f", struct.pack(">f", float(value)))[0])


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def _key_order(key) -> tuple:
    """RFC 8949 §4.2.1 for text keys: length of the UTF-8 encoding, then bytes."""
    encoded = str(key).encode("utf-8")
    return (len(encoded), encoded)


def canonical_map(value: dict) -> dict:
    """A copy of a map-valued field with its entries in canonical order
    (shorter UTF-8 key first, then bytewise; RFC 8949 §4.2.1), the order the
    Java codec writes every map in as of wire v3 (ISSUE-CanonicalMaps). Apply
    it to every map field of a protocol record where it is built (tags, costHints,
    spaceBindings, resourceHints, parameters, access, digests); never to a dict
    standing for a record."""
    return {k: value[k] for k in sorted(value, key=_key_order)}


def is_canonical_map(value: dict) -> bool:
    """Whether a decoded map field lists its keys in the order ``canonical_map`` gives."""
    keys = [_key_order(key) for key in value]
    return keys == sorted(keys)


def dumps(value) -> bytes:
    """The wire encoding of a Python value; TypeError for a value it cannot hold (a map key
    that is not text, a type with no CBOR form), ValueError for a text with a lone surrogate
    or a decimal outside the encoding's range."""
    out = bytearray()
    _encode(value, out)
    return bytes(out)


# Java's long range: an integer inside it is a plain integer, any other a bignum (S4, S9).
_LONG_MIN, _LONG_MAX = -(1 << 63), (1 << 63) - 1
# The longest bignum byte string, a leading zero included: Jackson's StreamReadConstraints read
# no longer number, alone or as a decimal's mantissa (HLC round seven, 2026-11-08, S9).
MAX_BIGNUM_BYTES = 1000
# The exponent range of a tag 4 decimal: the negated scale of a Java BigDecimal, an int,
# whose -2^31 Jackson cannot negate (S9).
_EXPONENT_MAX = (1 << 31) - 1
# The one NaN of each width, as Java's Double.NaN and Float.NaN write it (S10).
_NAN64 = b"\xfb\x7f\xf8\x00\x00\x00\x00\x00\x00"
_NAN32 = b"\xfa\x7f\xc0\x00\x00"


def _encode(value, out: bytearray) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        _encode_int(value, out)
    elif isinstance(value, Float32):
        out += _NAN32 if value != value else b"\xfa" + struct.pack(">f", value)
    elif isinstance(value, float):
        out += _NAN64 if value != value else b"\xfb" + struct.pack(">d", value)
    elif isinstance(value, Decimal):
        _encode_decimal(value, out)
    elif isinstance(value, bytes):
        out += _head(2, len(value))
        out += value
    elif isinstance(value, str):
        _encode_text(value, out)
    elif isinstance(value, (list, tuple)):
        out += _head(4, len(value))
        for item in value:
            _encode(item, out)
    elif isinstance(value, dict):
        # Indefinite-length map in the dict's own order: a dict stands for a Java record
        # (declared component order) as often as for a map, so the encoder cannot sort. A
        # map-valued field (tags, costHints, ...) is put in canonical order by
        # ``canonical_map`` where it is built (wire v3, ISSUE-CanonicalMaps).
        out.append(0xBF)
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"a map key must be text: {type(key).__name__}")
            _encode_text(key, out)
            _encode(item, out)
        out.append(_BREAK)
    else:
        raise TypeError(f"cannot encode {type(value)!r}")


def _encode_int(value: int, out: bytearray) -> None:
    """A plain integer inside Java's long range, else a bignum as Jackson writes a BigInteger:
    tag 2 for a positive value and tag 3 for a negative one, over the minimal two's-complement
    bytes of the magnitude, so the first byte is below 0x80 (HLC round six, 2026-11-08, rules
    S4 and S9). Jackson reads tag 3 back as the negated magnitude, where RFC 8949 §3.4.3 reads
    -1 minus it; the encoding follows Java, the peer that writes these tags."""
    if _LONG_MIN <= value <= _LONG_MAX:
        out += _head(0, value) if value >= 0 else _head(1, -1 - value)
        return
    magnitude = abs(value)
    out.append(0xC3 if value < 0 else 0xC2)
    raw = magnitude.to_bytes(magnitude.bit_length() // 8 + 1, "big")
    if len(raw) > MAX_BIGNUM_BYTES:
        raise ValueError(f"a bignum holds at most {MAX_BIGNUM_BYTES} bytes (S9)")
    out += _head(2, len(raw))
    out += raw


def decimal_parts(value: Decimal) -> tuple:
    """``(exponent, mantissa)`` of a finite decimal with its trailing decimal zeros stripped
    exactly, zero as ``(0, 0)`` (HLC round six, 2026-11-08, rule S9). ``Decimal.normalize``
    rounds to the context's 28 digits, so it would turn 100000000000000000000000000000001
    into 1E+32; this strip never rounds. ValueError for a value the encoding cannot hold: a
    NaN, an infinity, or an exponent outside -(2^31-1) to 2^31-1."""
    if not value.is_finite():
        raise ValueError(f"no decimal of the wire holds {value}")
    sign, digits, exponent = value.as_tuple()
    mantissa = int("".join(map(str, digits)) or "0")
    if mantissa == 0:
        return 0, 0
    while mantissa % 10 == 0:
        mantissa //= 10
        exponent += 1
    if not -_EXPONENT_MAX <= exponent <= _EXPONENT_MAX:
        raise ValueError(f"the exponent of {value} lies outside -(2^31-1) to 2^31-1")
    return exponent, -mantissa if sign else mantissa


def _encode_decimal(value: Decimal, out: bytearray) -> None:
    """A decimal as tag 4 over [exponent, mantissa], normalized (rule S9)."""
    exponent, mantissa = decimal_parts(value)
    out += b"\xc4\x82"
    _encode_int(exponent, out)
    _encode_int(mantissa, out)


# The most UTF-16 units Jackson's CBORGenerator writes as one definite text string
# (MAX_LONG_STRING_CHARS); it writes a longer string as an indefinite-length string of
# definite chunks of this many units, one fewer where a chunk would end on a high surrogate
# (HLC round five, 2026-11-08, decision E8; HLC round six, 2026-11-08, rule S6).
JACKSON_CHUNK_UNITS = 3996


def utf16_units(text: str) -> int:
    """The length of ``text`` in UTF-16 code units, the length Jackson chunks text by."""
    return len(text) + sum(1 for char in text if ord(char) > 0xFFFF)


def _chunks(text: str) -> list:
    """Jackson's chunks of ``text``: the text itself up to JACKSON_CHUNK_UNITS units, else
    pieces of that many units, one fewer where a piece would end on a high surrogate."""
    # A code point takes one or two UTF-16 units, so only a string of more than half the
    # chunk in code points can run past it.
    if len(text) <= JACKSON_CHUNK_UNITS // 2:
        return [text]
    units = text.encode("utf-16-be", "surrogatepass")
    chunks, start = [], 0
    while len(units) - start > 2 * JACKSON_CHUNK_UNITS:
        end = start + 2 * JACKSON_CHUNK_UNITS
        if 0xD8 <= units[end - 2] <= 0xDB:  # a high surrogate: keep the pair together
            end -= 2
        chunks.append(units[start:end].decode("utf-16-be", "surrogatepass"))
        start = end
    chunks.append(units[start:].decode("utf-16-be", "surrogatepass"))
    return chunks


def _encode_text(value: str, out: bytearray) -> None:
    """A text string as Jackson writes it (rule S6). ValueError (a UnicodeEncodeError) for a
    lone surrogate, which no UTF-8 holds."""
    chunks = _chunks(value)
    if len(chunks) > 1:
        out.append(0x7F)
    for chunk in chunks:
        encoded = chunk.encode("utf-8")
        out += _head(3, len(encoded))
        out += encoded
    if len(chunks) > 1:
        out.append(_BREAK)


# Deepest container nesting accepted (ASF-018, rule S2): hostile deep nesting overflows
# the stack.
_MAX_DEPTH = 64
# The first argument each additional-information value of 24 to 27 may carry: a smaller
# one fits a shorter head, so it is not the shortest form (rule S3).
_HEAD_WIDTHS = {24: (1, 24), 25: (2, 0x100), 26: (4, 0x10000), 27: (8, 0x100000000)}


def loads(data: bytes):
    """Decodes exactly one item in the wire encoding; ValueError on anything else: a byte
    past the item, a truncated item, or any form rules S1 to S12 refuse (HLC round six,
    2026-11-08). A map comes back as a dict in arrival order."""
    reader = _Reader(bytes(data))
    value = reader.item(0)
    if reader.offset != len(reader.data):
        raise ValueError(f"trailing bytes after CBOR item at offset {reader.offset}")
    return value


class _Reader:
    """One document under decode: the bytes and the offset of the next head."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count > len(self.data) - self.offset:
            raise ValueError("truncated CBOR item")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def peek(self) -> int:
        if self.offset >= len(self.data):
            raise ValueError("truncated CBOR item")
        return self.data[self.offset]

    def argument(self, info: int) -> int:
        """The argument of a head whose additional information is ``info``, in its
        shortest form only (rule S3)."""
        if info < 24:
            return info
        if info not in _HEAD_WIDTHS:
            raise ValueError(f"reserved or indefinite CBOR head 0x{info:02x}")
        width, least = _HEAD_WIDTHS[info]
        value = int.from_bytes(self.take(width), "big")
        if value < least:
            raise ValueError("a CBOR head longer than its argument needs")
        return value

    def text(self, length: int) -> str:
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("text that is not well-formed UTF-8") from None

    def item(self, depth: int):
        initial = self.take(1)[0]
        major, info = initial >> 5, initial & 0x1F
        if major == 7:
            return self.simple(initial)
        if info == 31:
            if major == 3:
                return self.chunked_text()
            if major == 5:
                return self.map(depth)
            raise ValueError(f"an indefinite-length item 0x{initial:02x} the encoding never writes")
        value = self.argument(info)
        if major == 0:
            return self.long(value)
        if major == 1:
            return -1 - self.long(value)
        if major == 2:
            return self.take(value)
        if major == 3:
            text = self.text(value)
            if utf16_units(text) > JACKSON_CHUNK_UNITS:
                raise ValueError("a definite text past 3996 UTF-16 units")
            return text
        if major == 4:
            if depth >= _MAX_DEPTH:
                raise ValueError("CBOR nesting too deep")
            if value > len(self.data) - self.offset:
                raise ValueError("truncated CBOR item")
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            raise ValueError("a definite-length map; the encoding writes every map indefinite")
        return self.tagged(value, depth)

    @staticmethod
    def long(argument: int) -> int:
        if argument > _LONG_MAX:
            raise ValueError("a plain integer past Java's long range; the encoding writes a bignum")
        return argument

    def simple(self, initial: int):
        if initial == 0xF4:
            return False
        if initial == 0xF5:
            return True
        if initial == 0xF6:
            return None
        if initial == 0xFB:
            raw = self.take(8)
            value = struct.unpack(">d", raw)[0]
            if value != value and b"\xfb" + raw != _NAN64:
                raise ValueError("a NaN other than Java's Double.NaN")
            return value
        if initial == 0xFA:
            raw = self.take(4)
            value = Float32(struct.unpack(">f", raw)[0])
            if value != value and b"\xfa" + raw != _NAN32:
                raise ValueError("a NaN other than Java's Float.NaN")
            return value
        raise ValueError(f"CBOR simple value or float 0x{initial:02x} the encoding never writes")

    def chunked_text(self) -> str:
        """Text in Jackson's chunks: only a text past 3996 UTF-16 units, cut exactly where
        Jackson cuts it (rule S6)."""
        chunks = []
        while self.peek() != _BREAK:
            head = self.take(1)[0]
            if head >> 5 != 3 or head & 0x1F == 31:
                raise ValueError("an indefinite text holds a chunk that is no definite text")
            chunks.append(self.text(self.argument(head & 0x1F)))
        self.offset += 1
        text = "".join(chunks)
        if utf16_units(text) <= JACKSON_CHUNK_UNITS or chunks != _chunks(text):
            raise ValueError("an indefinite text outside Jackson's chunks")
        return text

    def map(self, depth: int) -> dict:
        if depth >= _MAX_DEPTH:
            raise ValueError("CBOR nesting too deep")
        result = {}
        while self.peek() != _BREAK:
            if self.peek() >> 5 != 3:
                raise ValueError("a map key that is no text string")
            key = self.item(depth + 1)
            if key in result:
                raise ValueError(f"the map key {key!r} twice")
            result[key] = self.item(depth + 1)
        self.offset += 1
        return result

    def tagged(self, tag: int, depth: int):
        """Tags 2 and 3 (a bignum outside Java's long range) and tag 4 (a normalized decimal),
        each in the one form rule S9 gives it; every other tag is refused."""
        if tag in (2, 3):
            return self.bignum(tag)
        if tag != 4:
            raise ValueError(f"tag {tag} never decodes; only the big-number tags 2, 3 and 4 do")
        if self.peek() != 0x82:
            raise ValueError("tag 4 encloses a two-element array")
        # The two-element array is a nesting level, as Jackson counts it (rule S2).
        if depth >= _MAX_DEPTH:
            raise ValueError("CBOR nesting too deep")
        self.offset += 1
        if self.peek() >> 5 > 1:
            raise ValueError("the exponent of tag 4 is a plain integer")
        exponent = self.item(depth + 1)
        head = self.peek()
        if head >> 5 > 1 and head not in (0xC2, 0xC3):
            raise ValueError("the mantissa of tag 4 is a plain integer or a bignum")
        mantissa = self.bignum(self.take(1)[0] & 0x1F) if head >> 5 == 6 else self.item(depth + 1)
        if not -_EXPONENT_MAX <= exponent <= _EXPONENT_MAX:
            raise ValueError("the exponent of tag 4 lies outside -(2^31-1) to 2^31-1")
        if (mantissa == 0 and exponent != 0) or (mantissa != 0 and mantissa % 10 == 0):
            raise ValueError("a decimal with trailing zeros; the encoding writes it stripped")
        sign = 1 if mantissa < 0 else 0
        return Decimal((sign, tuple(int(digit) for digit in str(abs(mantissa))), exponent))

    def bignum(self, tag: int) -> int:
        head = self.take(1)[0]
        if head >> 5 != 2 or head & 0x1F == 31:
            raise ValueError(f"tag {tag} encloses a definite-length byte string")
        length = self.argument(head & 0x1F)
        if length > MAX_BIGNUM_BYTES:
            raise ValueError(f"a bignum holds at most {MAX_BIGNUM_BYTES} bytes (S9)")
        raw = self.take(length)
        if not raw or raw[0] >= 0x80 or (len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80):
            raise ValueError("a bignum whose bytes are no minimal magnitude")
        magnitude = int.from_bytes(raw, "big")
        value = magnitude if tag == 2 else -magnitude
        if _LONG_MIN <= value <= _LONG_MAX:
            raise ValueError("a bignum inside Java's long range; the encoding writes a plain integer")
        return value
