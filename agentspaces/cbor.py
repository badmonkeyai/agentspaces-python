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

"""CBOR (RFC 8949) codec matching the Java side's Jackson encoding byte for
byte, which the cross-language golden vectors in tests/ prove. The encoding
rules Jackson follows and this module reproduces: objects are
indefinite-length maps (0xBF ... 0xFF) with keys in field order, arrays are
indefinite-length (0x9F ... 0xFF), text and byte strings are definite with
minimal length heads, integers use the minimal width, booleans/null are
F4/F5/F6, and doubles are 64-bit (0xFB). Matching bytes matter because
signatures cover the canonical CBOR of what they sign."""

import struct

_BREAK = 0xFF


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


def dumps(value) -> bytes:
    """Encodes a Python value the way the Java codec encodes its equivalent."""
    out = bytearray()
    _encode(value, out)
    return bytes(out)


def _encode(value, out: bytearray) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        if value >= 0:
            out += _head(0, value)
        else:
            out += _head(1, -1 - value)
    elif isinstance(value, float):
        out.append(0xFB)
        out += struct.pack(">d", value)
    elif isinstance(value, bytes):
        out += _head(2, len(value))
        out += value
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
        out += _head(3, len(encoded))
        out += encoded
    elif isinstance(value, (list, tuple)):
        # Definite-length arrays: the canonical form as of wire v2, matching
        # the Java codec (RFC 8949 deterministic-encoding preference). Maps
        # stay indefinite, matching Java's streaming object encoder.
        out += _head(4, len(value))
        for item in value:
            _encode(item, out)
    elif isinstance(value, dict):
        out.append(0xBF)
        for key, item in value.items():
            _encode(key, out)
            _encode(item, out)
        out.append(_BREAK)
    else:
        raise TypeError(f"cannot encode {type(value)!r}")


# Deepest container nesting accepted; hostile deep nesting overflows the stack.
_MAX_DEPTH = 64


def loads(data: bytes):
    """Decodes exactly one CBOR item; definite and indefinite forms both
    accepted, and trailing bytes are refused so malformed or smuggled input is
    loud, never silently tolerated (ASF-042)."""
    value, offset = _decode(data, 0)
    if offset != len(data):
        raise ValueError(f"trailing bytes after CBOR item at offset {offset}")
    return value


def _need(data: bytes, offset: int, count: int) -> None:
    if offset + count > len(data):
        raise ValueError("truncated CBOR item")


def _decode(data: bytes, offset: int, depth: int = 0):
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1

    # Major 7 carries simple values and floats, never a length head; handle it
    # before the length logic so float payload bytes are not eaten as lengths.
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info in (22, 23):
            return None, offset
        if info == 25:
            return struct.unpack(">e", data[offset:offset + 2])[0], offset + 2
        if info == 26:
            return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
        if info == 27:
            return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
        raise ValueError(f"unsupported CBOR simple value 0x{initial:02x}")

    if info == 31:
        length = None  # indefinite
    elif info < 24:
        length = info
    elif info == 24:
        _need(data, offset, 1)
        length = data[offset]
        offset += 1
    elif info == 25:
        _need(data, offset, 2)
        length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
    elif info == 26:
        _need(data, offset, 4)
        length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
    elif info == 27:
        _need(data, offset, 8)
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
    else:
        raise ValueError(f"unsupported CBOR head 0x{initial:02x}")

    if major == 0:
        return length, offset
    if major == 1:
        return -1 - length, offset
    if major == 2:
        _need(data, offset, length)
        return bytes(data[offset:offset + length]), offset + length
    if major == 3:
        _need(data, offset, length)
        return data[offset:offset + length].decode("utf-8"), offset + length
    if major == 4:
        items = []
        if length is None:
            while data[offset] != _BREAK:
                item, offset = _decode(data, offset, depth + 1)
                items.append(item)
            return items, offset + 1
        for _ in range(length):
            item, offset = _decode(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        result = {}
        if length is None:
            while data[offset] != _BREAK:
                key, offset = _decode(data, offset, depth + 1)
                value, offset = _decode(data, offset, depth + 1)
                result[key] = value
            return result, offset + 1
        for _ in range(length):
            key, offset = _decode(data, offset, depth + 1)
            value, offset = _decode(data, offset, depth + 1)
            result[key] = value
        return result, offset
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info in (22, 23):
            return None, offset
        if info == 25:
            raise ValueError("half-precision floats are not used on this wire")
        if info == 26:
            return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
        if info == 27:
            return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
    raise ValueError(f"unsupported CBOR item 0x{initial:02x}")
