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

"""The ``dcz`` field of an intra-chunk delta in ``NODES.deltas`` (srad/agentspaces-pdt2.md §3.8; PDT 2 phase 7,
P2-C-01 group Z, P2-Z-01, P2-Z-04, P2-F-02): the reader of Java's ``Dcz``.

A field is a format byte (``d`` zstd; ``v`` VCDIFF is reserved for P2-Z-05 and refused by name), the 40-byte RFC 9842
header (the skippable-frame magic ``5e 2a 4d 18 20 00 00 00`` and the base's sha-256), then exactly one zstd frame
(RFC 8878) made with the base as a raw-content dictionary. The reader trusts no size it has not checked (threat 5 of
§6.7, P2-Q-SEC-05, decision 4 of §10.12): before it decompresses it reads the zstd frame header and refuses, each by
name, a frame without a content size, a content size or a window past ``MAX_OUTPUT`` (256 KiB, the chunk bound), a
dictionary id, a reserved header bit, and more than one frame; it refuses a base past the chunk bound and a base that
starts with the zstd dictionary magic, which zstd would load as a formatted dictionary, so every port opens the same
frames. It then writes at most the declared size. The caller verifies the result against the chunk's CID.

Python 3.14's ``compression.zstd`` opens the frames. On an older Python the reader refuses every frame by name, and
the caller asks for the chunk whole, as Java does on a platform without the native library."""

from __future__ import annotations

import hashlib

try:
    from compression import zstd as _zstd
except ImportError:  # Python before 3.14: frames stay closed, the chunks travel whole
    _zstd = None

ZSTD, VCDIFF = ord("d"), ord("v")
MAX_OUTPUT = 256 * 1024
HEADER_BYTES = 1 + 8 + 32
DCZ_MAGIC = bytes.fromhex("5e2a4d1820000000")
_ZSTD_MAGIC = 0xFD2FB528
_DICTIONARY_MAGIC = 0xEC30A437
_MIN_ZSTD_BYTES = 6


class DczRefused(ValueError):
    """A field the reader refuses, named by the rule it breaks."""

    def __init__(self, why: str):
        super().__init__("dcz: " + why)


def decode(base: bytes, field: bytes) -> bytes:
    """The chunk a field writes over its base; ``DczRefused`` naming the rule the field breaks."""
    if len(field) < HEADER_BYTES + _MIN_ZSTD_BYTES:
        raise DczRefused(f"a field of {len(field)} bytes holds no format byte, RFC 9842 header, and zstd frame")
    if field[0] == VCDIFF:
        raise DczRefused("a VCDIFF frame (format byte 'v'), which this release does not read;"
                         " send a zstd frame (format byte 'd') or the whole node")
    if field[0] != ZSTD:
        raise DczRefused(f"unknown format byte 0x{field[0]:02x}; this release reads 'd' (zstd)")
    if field[1:1 + len(DCZ_MAGIC)] != DCZ_MAGIC:
        raise DczRefused("no RFC 9842 dcz header after the format byte")
    if len(base) > MAX_OUTPUT:
        raise DczRefused(f"a base of {len(base)} bytes is past the chunk bound of {MAX_OUTPUT} bytes")
    if len(base) >= 4 and int.from_bytes(base[:4], "little") == _DICTIONARY_MAGIC:
        raise DczRefused("a base that starts with the zstd dictionary magic loads as no raw dictionary")
    if field[1 + len(DCZ_MAGIC):HEADER_BYTES] != hashlib.sha256(base).digest():
        raise DczRefused("the frame names another base than the one held")
    size = _content_size(field)
    if _zstd is None:
        raise DczRefused("zstd is not available on this Python (compression.zstd arrived in 3.14)")
    frame = field[HEADER_BYTES:]
    try:
        if _zstd.get_frame_size(frame) != len(frame):
            raise DczRefused("the field holds more than one zstd frame")
        decompressor = _zstd.ZstdDecompressor(zstd_dict=_zstd.ZstdDict(base, is_raw=True))
        out = decompressor.decompress(frame, max_length=size + 1)
    except _zstd.ZstdError as e:
        raise DczRefused(f"the field is not one zstd frame that opens over the base: {e}") from e
    if len(out) != size or not decompressor.eof:
        raise DczRefused(f"the frame wrote {len(out)} bytes where its header declared {size}")
    return out


def _content_size(field: bytes) -> int:
    """The content size the zstd frame header declares, after the bound checks of the module comment."""
    at = HEADER_BYTES
    if int.from_bytes(field[at:at + 4], "little") != _ZSTD_MAGIC:
        raise DczRefused("no zstd frame after the RFC 9842 header")
    descriptor = field[at + 4]
    single_segment = descriptor & 0x20 != 0
    if descriptor & 0x08:
        raise DczRefused("the zstd frame header sets its reserved bit")
    if descriptor & 0x03:
        raise DczRefused("the zstd frame names a dictionary id; a base is a raw dictionary with none")
    p = at + 5
    window = -1
    if not single_segment:
        w = field[p]
        p += 1
        window_base = 1 << (10 + (w >> 3))
        window = window_base + (window_base // 8) * (w & 0x07)
    size_bytes = (1 if single_segment else 0, 2, 4, 8)[descriptor >> 6]
    if size_bytes == 0:
        raise DczRefused("the zstd frame declares no content size")
    if p + size_bytes > len(field):
        raise DczRefused("the zstd frame header is cut short")
    size = int.from_bytes(field[p:p + size_bytes], "little") + (256 if size_bytes == 2 else 0)
    if size > MAX_OUTPUT:
        raise DczRefused(f"a content size of {size} bytes is past the chunk bound of {MAX_OUTPUT} bytes")
    if single_segment:
        window = size
    if window > MAX_OUTPUT:
        raise DczRefused(f"a window of {window} bytes is past the bound of {MAX_OUTPUT} bytes")
    return size
