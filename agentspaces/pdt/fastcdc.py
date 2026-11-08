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

"""The content-defined chunker (srad/agentspaces-pdt.md §3.3, §10.2; PD-B-01):
FastCDC in the per-byte form of the 2016 paper with normalized chunking level 2
and cut-point skipping, pinned so that every language cuts ``pdt_fastcdc_cuts``
at the same offsets.

- Sizes: minimum 16 KiB, average 64 KiB, maximum 256 KiB.
- Gear: ``GEAR[i]`` is the big-endian unsigned 64-bit integer in the first eight
  bytes of sha256 of the single byte ``i``.
- Rolling hash ``h = (h << 1) + GEAR[b]`` over unsigned 64-bit arithmetic,
  starting from zero at index MIN of the chunk (the first MIN bytes are skipped).
- Masks: ``0xFFFFC00000000000`` (top 18 bits) while the chunk is shorter than
  the average, ``0xFFFC000000000000`` (top 14 bits) after.
- Cut: the chunk ends at the first index ``i >= MIN`` where, after folding byte
  ``i`` into ``h``, ``(h & mask) == 0``; the chunk is the ``i`` bytes before it.
  Else the chunk ends at MAX, or at the end of the input. An input of at most
  MIN bytes is one chunk."""

from __future__ import annotations

import hashlib
from typing import Iterator

MIN_SIZE = 16 * 1024
AVG_SIZE = 64 * 1024
MAX_SIZE = 256 * 1024
MASK_S = 0xFFFFC00000000000
MASK_L = 0xFFFC000000000000
_U64 = 0xFFFFFFFFFFFFFFFF

GEAR = [int.from_bytes(hashlib.sha256(bytes([i])).digest()[:8], "big") for i in range(256)]


def cut(data, offset: int, length: int) -> int:
    """The length of the chunk that starts at ``offset`` with ``length`` bytes following it."""
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError(f"range {offset}+{length} outside {len(data)} bytes")
    n = length
    if n <= MIN_SIZE:
        return n
    normal = AVG_SIZE
    if n >= MAX_SIZE:
        n = MAX_SIZE
    elif n <= normal:
        normal = n
    h = 0
    gear = GEAR
    view = memoryview(data)[offset:offset + n]
    i = MIN_SIZE
    while i < normal:
        h = ((h << 1) + gear[view[i]]) & _U64
        if h & MASK_S == 0:
            return i
        i += 1
    while i < n:
        h = ((h << 1) + gear[view[i]]) & _U64
        if h & MASK_L == 0:
            return i
        i += 1
    return i


def cuts(data) -> list[int]:
    """The end offset of every chunk, ascending; the last equals the length."""
    out, offset = [], 0
    while offset < len(data):
        offset += cut(data, offset, len(data) - offset)
        out.append(offset)
    return out


def chunks_of(data: bytes) -> list[bytes]:
    out, start = [], 0
    for end in cuts(data):
        out.append(bytes(data[start:end]))
        start = end
    return out


def chunks(stream) -> Iterator[bytes]:
    """Chunks a binary stream through a buffer of twice the maximum chunk size (PD-B-04)."""
    buffer = bytearray()
    eof = False
    while True:
        while not eof and len(buffer) < 2 * MAX_SIZE:
            more = stream.read(2 * MAX_SIZE - len(buffer))
            if not more:
                eof = True
            else:
                buffer.extend(more)
        if not buffer:
            return
        length = cut(buffer, 0, len(buffer))
        yield bytes(buffer[:length])
        del buffer[:length]
