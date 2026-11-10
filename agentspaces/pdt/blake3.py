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
"""BLAKE3 in pure Python (srad/agentspaces-pdt2.md §3.5; PDT 2 phase 7, P2-C-01 group B, P2-B-01 to P2-B-04): the
hash, the chaining value of a chunk group as a non-root subtree, and the parent compression, which a verified window
needs and the ``blake3`` package does not expose. A blob's identity is the BLAKE3 of its content; the Bao outboard of
§3.5 holds the chaining values of its 16 KiB chunk groups and the parents above them, so a reader checks a window
group by group. The suites checked this code against Java's ``bo`` and identity vectors since PDT 2 phase 0, when it
lived beside them as their reference; phase 7 made it the library's, and the vectors still pin it. Pure Python hashes
about 1.7 MiB a second on the reference laptop, enough for windows; Java hashes whole blobs at publish (P2-B-05)."""

import struct

CHUNK_BYTES = 1024
BLOCK_BYTES = 64
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_MASK = 0xFFFFFFFF


def _schedule():
    rounds = [tuple(range(16))]
    for _ in range(6):
        rounds.append(tuple(rounds[-1][p] for p in _PERMUTATION))
    return tuple(rounds)


_SCHEDULE = _schedule()


def _compress(cv, m, counter, block_length, flags):
    """The first eight words of the compression of one block: the next chaining value."""
    s0, s1, s2, s3, s4, s5, s6, s7 = cv
    s8, s9, s10, s11 = IV[0], IV[1], IV[2], IV[3]
    s12, s13, s14, s15 = counter & _MASK, (counter >> 32) & _MASK, block_length, flags
    M = _MASK
    for w in _SCHEDULE:
        # columns
        s0 = (s0 + s4 + m[w[0]]) & M; x = s12 ^ s0; s12 = (x >> 16) | (x << 16) & M
        s8 = (s8 + s12) & M; x = s4 ^ s8; s4 = (x >> 12) | (x << 20) & M
        s0 = (s0 + s4 + m[w[1]]) & M; x = s12 ^ s0; s12 = (x >> 8) | (x << 24) & M
        s8 = (s8 + s12) & M; x = s4 ^ s8; s4 = (x >> 7) | (x << 25) & M
        s1 = (s1 + s5 + m[w[2]]) & M; x = s13 ^ s1; s13 = (x >> 16) | (x << 16) & M
        s9 = (s9 + s13) & M; x = s5 ^ s9; s5 = (x >> 12) | (x << 20) & M
        s1 = (s1 + s5 + m[w[3]]) & M; x = s13 ^ s1; s13 = (x >> 8) | (x << 24) & M
        s9 = (s9 + s13) & M; x = s5 ^ s9; s5 = (x >> 7) | (x << 25) & M
        s2 = (s2 + s6 + m[w[4]]) & M; x = s14 ^ s2; s14 = (x >> 16) | (x << 16) & M
        s10 = (s10 + s14) & M; x = s6 ^ s10; s6 = (x >> 12) | (x << 20) & M
        s2 = (s2 + s6 + m[w[5]]) & M; x = s14 ^ s2; s14 = (x >> 8) | (x << 24) & M
        s10 = (s10 + s14) & M; x = s6 ^ s10; s6 = (x >> 7) | (x << 25) & M
        s3 = (s3 + s7 + m[w[6]]) & M; x = s15 ^ s3; s15 = (x >> 16) | (x << 16) & M
        s11 = (s11 + s15) & M; x = s7 ^ s11; s7 = (x >> 12) | (x << 20) & M
        s3 = (s3 + s7 + m[w[7]]) & M; x = s15 ^ s3; s15 = (x >> 8) | (x << 24) & M
        s11 = (s11 + s15) & M; x = s7 ^ s11; s7 = (x >> 7) | (x << 25) & M
        # diagonals
        s0 = (s0 + s5 + m[w[8]]) & M; x = s15 ^ s0; s15 = (x >> 16) | (x << 16) & M
        s10 = (s10 + s15) & M; x = s5 ^ s10; s5 = (x >> 12) | (x << 20) & M
        s0 = (s0 + s5 + m[w[9]]) & M; x = s15 ^ s0; s15 = (x >> 8) | (x << 24) & M
        s10 = (s10 + s15) & M; x = s5 ^ s10; s5 = (x >> 7) | (x << 25) & M
        s1 = (s1 + s6 + m[w[10]]) & M; x = s12 ^ s1; s12 = (x >> 16) | (x << 16) & M
        s11 = (s11 + s12) & M; x = s6 ^ s11; s6 = (x >> 12) | (x << 20) & M
        s1 = (s1 + s6 + m[w[11]]) & M; x = s12 ^ s1; s12 = (x >> 8) | (x << 24) & M
        s11 = (s11 + s12) & M; x = s6 ^ s11; s6 = (x >> 7) | (x << 25) & M
        s2 = (s2 + s7 + m[w[12]]) & M; x = s13 ^ s2; s13 = (x >> 16) | (x << 16) & M
        s8 = (s8 + s13) & M; x = s7 ^ s8; s7 = (x >> 12) | (x << 20) & M
        s2 = (s2 + s7 + m[w[13]]) & M; x = s13 ^ s2; s13 = (x >> 8) | (x << 24) & M
        s8 = (s8 + s13) & M; x = s7 ^ s8; s7 = (x >> 7) | (x << 25) & M
        s3 = (s3 + s4 + m[w[14]]) & M; x = s14 ^ s3; s14 = (x >> 16) | (x << 16) & M
        s9 = (s9 + s14) & M; x = s4 ^ s9; s4 = (x >> 12) | (x << 20) & M
        s3 = (s3 + s4 + m[w[15]]) & M; x = s14 ^ s3; s14 = (x >> 8) | (x << 24) & M
        s9 = (s9 + s14) & M; x = s4 ^ s9; s4 = (x >> 7) | (x << 25) & M
    return (s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11, s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15)


def _chunk(data: memoryview, counter: int, root: bool):
    cv = IV
    blocks = max(1, -(-len(data) // BLOCK_BYTES))
    for b in range(blocks):
        block = bytes(data[b * BLOCK_BYTES:(b + 1) * BLOCK_BYTES])
        flags = (CHUNK_START if b == 0 else 0) | ((CHUNK_END | (ROOT if root else 0)) if b == blocks - 1 else 0)
        cv = _compress(cv, struct.unpack("<16I", block.ljust(BLOCK_BYTES, b"\0")), counter, len(block), flags)
    return cv


def _parent_words(left, right, root: bool):
    return _compress(IV, left + right, 0, BLOCK_BYTES, PARENT | (ROOT if root else 0))


def _subtree(data: memoryview, first_chunk: int, root: bool):
    chunks = max(1, -(-len(data) // CHUNK_BYTES))
    if chunks == 1:
        return _chunk(data, first_chunk, root)
    left_chunks = 1 << ((chunks - 1).bit_length() - 1)
    split = left_chunks * CHUNK_BYTES
    left = _subtree(data[:split], first_chunk, False)
    right = _subtree(data[split:], first_chunk + left_chunks, False)
    return _parent_words(left, right, root)


def _bytes(words) -> bytes:
    return struct.pack("<8I", *words)


def digest(data: bytes) -> bytes:
    """The 32-byte BLAKE3 hash of ``data``."""
    return _bytes(_subtree(memoryview(data), 0, True))


def group_cv(data: bytes, first_chunk: int) -> bytes:
    """The chaining value of the chunks in ``data`` as a non-root subtree whose first chunk is
    chunk ``first_chunk`` of its blob."""
    return _bytes(_subtree(memoryview(data), first_chunk, False))


def parent(left: bytes, right: bytes, root: bool) -> bytes:
    """The chaining value of a parent of two chaining values, or the hash when it is the root."""
    return _bytes(_parent_words(struct.unpack("<8I", left), struct.unpack("<8I", right), root))
