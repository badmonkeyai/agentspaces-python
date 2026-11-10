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

"""CIDs of persistent tree nodes (srad/agentspaces-pdt.md §3.1, §10.2; PD-N-02,
PD-F-02): ``"b"`` + base32lower(``0x01``, codec, ``0x12 0x20``, sha256), with
codec ``0x71`` (dag-cbor) for a structured node and ``0x55`` (raw) for a blob
chunk. The binary form is the 36 bytes after the multibase prefix. A codec or
multihash this module does not know is refused by name."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

DAG_CBOR = 0x71
RAW = 0x55
SHA2_256 = 0x12
DIGEST_LENGTH = 32
BINARY_LENGTH = 4 + DIGEST_LENGTH
TEXT_LENGTH = 59

_B32 = "abcdefghijklmnopqrstuvwxyz234567"
_B32_INDEX = {c: i for i, c in enumerate(_B32)}
_CODEC_NAMES = {DAG_CBOR: "dag-cbor", RAW: "raw"}


def base32_lower(data: bytes) -> str:
    """RFC 4648 base32, lower case, unpadded."""
    out, buffer, bits = [], 0, 0
    for b in data:
        buffer = (buffer << 8) | b
        bits += 8
        while bits >= 5:
            out.append(_B32[(buffer >> (bits - 5)) & 0x1F])
            bits -= 5
    if bits:
        out.append(_B32[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def base32_decode(text: str) -> bytes:
    out, buffer, bits = bytearray(), 0, 0
    for c in text:
        value = _B32_INDEX.get(c)
        if value is None:
            raise ValueError(f"not a base32 character: {c!r}")
        buffer = (buffer << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    if buffer & ((1 << bits) - 1):
        raise ValueError("base32 padding bits are not zero")
    return bytes(out)


@dataclass(frozen=True)
class Parsed:
    codec: int
    digest: bytes

    @property
    def structured(self) -> bool:
        return self.codec == DAG_CBOR


def of(data: bytes, codec: int = DAG_CBOR) -> str:
    """The CID of some bytes under a codec."""
    if codec not in _CODEC_NAMES:
        raise ValueError(f"unknown codec 0x{codec:02x}")
    return "b" + base32_lower(bytes([0x01, codec, SHA2_256, DIGEST_LENGTH]) + hashlib.sha256(data).digest())


def of_digest(digest: bytes, codec: int) -> str:
    return "b" + base32_lower(bytes([0x01, codec, SHA2_256, DIGEST_LENGTH]) + digest)


#: The multihash of BLAKE3 (PDT 2, P2-B-01): a blob's identity is the CIDv1 ``raw`` over it, never a node's link.
BLAKE3 = 0x1E


def identity(digest: bytes) -> str:
    """The identity CID of a blob's 32-byte BLAKE3 hash (srad/agentspaces-pdt2.md §3.5, P2-B-01)."""
    if len(digest) != DIGEST_LENGTH:
        raise ValueError(f"a BLAKE3 identity names a 32-byte hash, got {len(digest)} bytes")
    return "b" + base32_lower(bytes([0x01, RAW, BLAKE3, DIGEST_LENGTH]) + digest)


def identity_digest(text) -> bytes | None:
    """The BLAKE3 hash an identity names, or None when the text is no identity in its canonical form."""
    if not isinstance(text, str) or len(text) != TEXT_LENGTH or text[0] != "b":
        return None
    try:
        raw = base32_decode(text[1:])
    except ValueError:
        return None
    if raw[:4] != bytes([0x01, RAW, BLAKE3, DIGEST_LENGTH]) or len(raw) != BINARY_LENGTH:
        return None
    return raw[4:]


def is_identity(text) -> bool:
    return identity_digest(text) is not None


def from_binary(binary: bytes) -> str:
    """The text form of a binary CID, validated."""
    if len(binary) != BINARY_LENGTH:
        raise ValueError(f"a binary CID is {BINARY_LENGTH} bytes, got {len(binary)}")
    text = "b" + base32_lower(binary)
    parse(text)
    return text


def binary(cid: str) -> bytes:
    """The 36 binary bytes of a CID."""
    parse(cid)
    return base32_decode(cid[1:])


def parse(cid: str) -> Parsed:
    """The codec and digest of a CID; refuses anything outside the pinned form by name."""
    if not isinstance(cid, str) or len(cid) != TEXT_LENGTH or cid[0] != "b":
        raise ValueError(f"not a base32 CIDv1 of a sha2-256 digest: {cid!r}")
    raw = base32_decode(cid[1:])
    if len(raw) != BINARY_LENGTH or raw[0] != 0x01:
        raise ValueError(f"not a CIDv1: {cid}")
    codec = raw[1]
    if codec not in _CODEC_NAMES:
        raise ValueError(f"unknown codec 0x{codec:02x} in {cid}")
    if raw[2] != SHA2_256:
        raise ValueError(f"unknown multihash 0x{raw[2]:02x} in {cid}; sha2-256 (0x12) is the one this release reads")
    if raw[3] != DIGEST_LENGTH:
        raise ValueError(f"digest length {raw[3]} in {cid}; sha2-256 digests are 32 bytes")
    return Parsed(codec, raw[4:])


def is_cid(s) -> bool:
    try:
        parse(s)
        return True
    except (ValueError, TypeError):
        return False


def codec_of(cid: str) -> int:
    return parse(cid).codec


def verifies(cid: str, data: bytes) -> bool:
    """Whether bytes hash to a CID (PD-N-06)."""
    try:
        return parse(cid).digest == hashlib.sha256(data).digest()
    except ValueError:
        return False
