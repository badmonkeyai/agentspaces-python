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

"""Store reconciliation (srad/agentspaces-pdt2.md §3.6; PDT 2 phase 7, P2-C-01 group K, P2-K-01, P2-K-02, P2-K-04,
P2-K-05): the Python port of Java's ``tree.sync`` package.

- ``Negentropy`` speaks the v1 protocol of the reference implementation (hoytech/negentropy) byte for byte, with
  64-bit varints and refusals by name, over a ``Storage`` of (timestamp, 32-byte id) items.
- ``RibltEncoder`` and ``RibltDecoder`` are rateless invertible Bloom lookup tables (Yang, Gilad and Alizadeh,
  SIGCOMM 2024): a coded symbol is the XOR of the ids mapped to it, the XOR of their SipHash-2-4 checksums under the
  session key, and their count; an id maps to symbol 0 and then to the indexes its checksum's generator draws at the
  density α = 0.5, by arithmetic every port computes alike (IEEE 754 rounds the square root and the division
  exactly).
- ``SketchSet`` is a set of CIDs as items, each digest at timestamp 0 (choice 1 of §10.13); ``SketchServer`` is the
  holder's answer to a sketch ``TREE_WANT``, chosen by the sketch's leading byte (P2-F-01); ``SketchSession`` is the
  asker's round loop under one request id.

The bounds of P2-K-04 and P2-Q-SEC-04 hold as in Java: 64 KiB per sketch, 64 rounds per session, at most 4 RIBLT
sessions of 16,384 symbols on a holder, 30 s idle, and a decoder refuses a stream that peels more ids than it has
symbols, which no coding of a set does (the phase 5 adversary's A1)."""

from __future__ import annotations

import hashlib
import heapq
import math
import os
import time

from . import cids

PROTOCOL_VERSION = 0x61
ID_SIZE = 32
FINGERPRINT_SIZE = 16
MIN_FRAME_SIZE_LIMIT = 4096
BUCKETS = 16
FRAME_MARGIN = 200
MODE_SKIP, MODE_FINGERPRINT, MODE_ID_LIST = 0, 1, 2
INFINITY = (1 << 63) - 1
_MOD = 1 << 256


# ------------------------------------------------------------------ varints and reading

def write_varint(out: bytearray, value: int) -> None:
    """A negentropy varint: base 128, most significant group first, every group but the last with the top bit."""
    if value < 0:
        raise ValueError(f"a varint is not negative, got {value}")
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    for i in range(len(groups) - 1, -1, -1):
        out.append(groups[i] | (0x80 if i else 0))


class Reader:
    """Reads a message from the front, refusing by name a message that ends early or a varint past 63 bits."""

    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    def remaining(self) -> int:
        return len(self.data) - self.at

    def next(self) -> int:
        if self.at >= len(self.data):
            raise ValueError("the message ends prematurely")
        b = self.data[self.at]
        self.at += 1
        return b

    def bytes(self, n: int) -> bytes:
        if n > self.remaining():
            raise ValueError("the message ends prematurely")
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def varint(self) -> int:
        value = 0
        while True:
            b = self.next()
            if value > INFINITY >> 7:
                raise ValueError("a varint passes 63 bits")
            value = (value << 7) | (b & 0x7F)
            if not b & 0x80:
                return value


# ------------------------------------------------------------------ negentropy

class Storage:
    """Items sorted by timestamp, then id unsigned, with sums of the ids before each index for the fingerprints."""

    def __init__(self, items):
        checked = []
        for timestamp, item_id in items:
            if len(item_id) != ID_SIZE:
                raise ValueError(f"an id is {ID_SIZE} bytes, got {len(item_id)}")
            if timestamp < 0 or timestamp >= INFINITY:
                raise ValueError(f"a timestamp is in [0, 2^63 - 1), got {timestamp}")
            checked.append((timestamp, bytes(item_id)))
        checked.sort()
        for i in range(1, len(checked)):
            if checked[i] == checked[i - 1]:
                raise ValueError("duplicate item")
        self.timestamps = [t for t, _ in checked]
        self.ids = [i for _, i in checked]
        self.sums = [0]
        for item_id in self.ids:
            self.sums.append((self.sums[-1] + int.from_bytes(item_id, "little")) % _MOD)

    def size(self) -> int:
        return len(self.ids)

    def _before(self, index: int, bound: tuple) -> bool:
        timestamp, prefix = bound
        if self.timestamps[index] != timestamp:
            return self.timestamps[index] < timestamp
        return self.ids[index][:len(prefix)] < prefix

    def lower_bound(self, begin: int, end: int, bound: tuple) -> int:
        lo, hi = begin, end
        while lo < hi:
            mid = (lo + hi) >> 1
            if self._before(mid, bound):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def fingerprint(self, begin: int, end: int) -> bytes:
        data = bytearray(((self.sums[end] - self.sums[begin]) % _MOD).to_bytes(ID_SIZE, "little"))
        write_varint(data, end - begin)
        return hashlib.sha256(data).digest()[:FINGERPRINT_SIZE]


class Negentropy:
    """One side of a negentropy session. The initiator calls ``initiate`` and then ``reconcile_initiator`` with each
    reply, which collects the ids it holds that the other lacks (``have``) and the ids it lacks (``need``) and returns
    the next query, or None once the sets agree; the responder answers each query with ``reconcile``."""

    def __init__(self, storage: Storage, frame_size_limit: int):
        if frame_size_limit != 0 and frame_size_limit < MIN_FRAME_SIZE_LIMIT:
            raise ValueError(f"frameSizeLimit is 0 or at least {MIN_FRAME_SIZE_LIMIT}, got {frame_size_limit}")
        self.storage = storage
        self.frame_size_limit = frame_size_limit
        self.initiator = False
        self._last_in = 0
        self._last_out = 0

    def initiate(self) -> bytes:
        if self.initiator:
            raise ValueError("already initiated")
        self.initiator = True
        out = bytearray([PROTOCOL_VERSION])
        self._split_range(0, self.storage.size(), (INFINITY, b""), out)
        return bytes(out)

    def reconcile(self, query: bytes) -> bytes:
        if self.initiator:
            raise ValueError("the initiator reconciles with have and need lists")
        return self._answer(query, None, None)

    def reconcile_initiator(self, reply: bytes, have: list, need: list) -> bytes | None:
        if not self.initiator:
            raise ValueError("the responder reconciles without have and need lists")
        out = self._answer(reply, have, need)
        return None if len(out) == 1 else out

    def _answer(self, query: bytes, have, need) -> bytes:
        storage = self.storage
        reader = Reader(query)
        self._last_in = self._last_out = 0
        full = bytearray([PROTOCOL_VERSION])
        version = reader.next()
        if version < 0x60 or version > 0x6F:
            raise ValueError(f"invalid negentropy protocol version byte 0x{version:x}")
        if version != PROTOCOL_VERSION:
            if self.initiator:
                raise ValueError(f"unsupported negentropy protocol version {version - 0x60}")
            return bytes(full)
        size = storage.size()
        prev_bound, prev_index, skip = (0, b""), 0, False
        while reader.remaining() > 0:
            o = bytearray()
            curr_bound = self._decode_bound(reader)
            mode = reader.varint()
            lower = prev_index
            upper = storage.lower_bound(prev_index, size, curr_bound)
            if mode == MODE_SKIP:
                skip = True
            elif mode == MODE_FINGERPRINT:
                theirs = reader.bytes(FINGERPRINT_SIZE)
                if theirs != storage.fingerprint(lower, upper):
                    if skip:
                        skip = False
                        self._encode_bound(prev_bound, o)
                        write_varint(o, MODE_SKIP)
                    self._split_range(lower, upper, curr_bound, o)
                else:
                    skip = True
            elif mode == MODE_ID_LIST:
                count = reader.varint()
                if count > reader.remaining() // ID_SIZE:
                    raise ValueError(f"an id list of {count} ids runs past the message")
                theirs = {}
                for _ in range(count):
                    item_id = reader.bytes(ID_SIZE)
                    if self.initiator:
                        theirs[item_id] = None
                if self.initiator:
                    skip = True
                    for i in range(lower, upper):
                        if storage.ids[i] in theirs:
                            del theirs[storage.ids[i]]
                        else:
                            have.append(storage.ids[i])
                    need.extend(theirs)
                else:
                    if skip:
                        skip = False
                        self._encode_bound(prev_bound, o)
                        write_varint(o, MODE_SKIP)
                    ids = bytearray()
                    listed = 0
                    end_bound = curr_bound
                    for i in range(lower, upper):
                        if self._exceeded(len(full) + len(ids)):
                            end_bound = (storage.timestamps[i], storage.ids[i])
                            upper = i  # the rest of the range goes into the closing fingerprint
                            break
                        ids.extend(storage.ids[i])
                        listed += 1
                    self._encode_bound(end_bound, o)
                    write_varint(o, MODE_ID_LIST)
                    write_varint(o, listed)
                    o.extend(ids)
                    full.extend(o)
                    o = bytearray()
            else:
                raise ValueError(f"unexpected mode {mode}")
            if self._exceeded(len(full) + len(o)):
                rest = storage.fingerprint(upper, size)
                self._encode_bound((INFINITY, b""), full)
                write_varint(full, MODE_FINGERPRINT)
                full.extend(rest)
                break
            full.extend(o)
            prev_index, prev_bound = upper, curr_bound
        return bytes(full)

    def _split_range(self, lower: int, upper: int, upper_bound: tuple, o: bytearray) -> None:
        storage = self.storage
        count = upper - lower
        if count < BUCKETS * 2:
            self._encode_bound(upper_bound, o)
            write_varint(o, MODE_ID_LIST)
            write_varint(o, count)
            for i in range(lower, upper):
                o.extend(storage.ids[i])
            return
        per_bucket, with_extra = divmod(count, BUCKETS)
        curr = lower
        for bucket in range(BUCKETS):
            bucket_size = per_bucket + (1 if bucket < with_extra else 0)
            fingerprint = storage.fingerprint(curr, curr + bucket_size)
            curr += bucket_size
            self._encode_bound(upper_bound if curr == upper else self._minimal_bound(curr - 1, curr), o)
            write_varint(o, MODE_FINGERPRINT)
            o.extend(fingerprint)

    def _minimal_bound(self, prev: int, curr: int) -> tuple:
        storage = self.storage
        if storage.timestamps[curr] != storage.timestamps[prev]:
            return storage.timestamps[curr], b""
        a, b = storage.ids[prev], storage.ids[curr]
        shared = 0
        while shared < ID_SIZE and a[shared] == b[shared]:
            shared += 1
        return storage.timestamps[curr], b[:shared + 1]

    def _exceeded(self, size: int) -> bool:
        return self.frame_size_limit != 0 and size > self.frame_size_limit - FRAME_MARGIN

    def _decode_bound(self, reader: Reader) -> tuple:
        timestamp = self._decode_timestamp(reader)
        length = reader.varint()
        if length > ID_SIZE:
            raise ValueError(f"bound key too long: {length} bytes")
        return timestamp, reader.bytes(length)

    def _decode_timestamp(self, reader: Reader) -> int:
        coded = reader.varint()
        timestamp = INFINITY if coded == 0 else coded - 1
        if self._last_in == INFINITY or timestamp == INFINITY:
            self._last_in = INFINITY
            return INFINITY
        if timestamp >= INFINITY - self._last_in:
            raise ValueError("a bound's timestamp passes 2^63 - 1")
        timestamp += self._last_in
        self._last_in = timestamp
        return timestamp

    def _encode_bound(self, bound: tuple, out: bytearray) -> None:
        timestamp, prefix = bound
        if timestamp == INFINITY:
            self._last_out = INFINITY
            write_varint(out, 0)
        else:
            offset = timestamp - self._last_out
            self._last_out = timestamp
            write_varint(out, offset + 1)
        write_varint(out, len(prefix))
        out.extend(prefix)


# ------------------------------------------------------------------ RIBLT

RIBLT_ENCODING = 0x62
KEY_BYTES = 16
RIBLT_MORE, RIBLT_DECODED, RIBLT_TOO_MANY = 0, 1, 2
_MULTIPLIER = 0xDA942042E4DD58B5
_M64 = (1 << 64) - 1
LAST_INDEX = 1 << 62
_NO_INDEX = (1 << 63) - 1


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _M64


def siphash24(key: bytes, message: bytes) -> int:
    """SipHash-2-4 of a message under a 16-byte key (Aumasson and Bernstein, 2012), as an unsigned 64-bit integer."""
    k0, k1 = int.from_bytes(key[:8], "little"), int.from_bytes(key[8:16], "little")
    v0, v1 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D
    v2, v3 = k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rounds(n, v0, v1, v2, v3):
        for _ in range(n):
            v0 = (v0 + v1) & _M64
            v1 = _rotl(v1, 13) ^ v0
            v0 = _rotl(v0, 32)
            v2 = (v2 + v3) & _M64
            v3 = _rotl(v3, 16) ^ v2
            v0 = (v0 + v3) & _M64
            v3 = _rotl(v3, 21) ^ v0
            v2 = (v2 + v1) & _M64
            v1 = _rotl(v1, 17) ^ v2
            v2 = _rotl(v2, 32)
        return v0, v1, v2, v3

    whole = len(message) - len(message) % 8
    for at in range(0, whole, 8):
        m = int.from_bytes(message[at:at + 8], "little")
        v3 ^= m
        v0, v1, v2, v3 = rounds(2, v0, v1, v2, v3)
        v0 ^= m
    last = ((len(message) & 0xFF) << 56) | int.from_bytes(message[whole:], "little")
    v3 ^= last
    v0, v1, v2, v3 = rounds(2, v0, v1, v2, v3)
    v0 ^= last
    v2 ^= 0xFF
    v0, v1, v2, v3 = rounds(4, v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


def _checked_key(key: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError(f"a session key is {KEY_BYTES} bytes, got {len(key)}")
    return bytes(key)


class Symbol:
    """One coded symbol as it travels: the 32-byte sum, the checksum as 8 little-endian bytes, the count as a varint."""
    __slots__ = ("sum", "checksum", "count")

    def __init__(self, total: bytes, checksum: int, count: int):
        if len(total) != ID_SIZE or count < 0:
            raise ValueError("a symbol holds a 32-byte sum and a count of at least 0")
        self.sum, self.checksum, self.count = bytes(total), checksum & _M64, count

    def encode(self) -> bytes:
        out = bytearray(self.sum)
        out.extend(self.checksum.to_bytes(8, "little"))
        write_varint(out, self.count)
        return bytes(out)

    @staticmethod
    def read(reader: Reader) -> "Symbol":
        total = reader.bytes(ID_SIZE)
        checksum = int.from_bytes(reader.bytes(8), "little")
        return Symbol(total, checksum, reader.varint())

    def __eq__(self, other) -> bool:
        return isinstance(other, Symbol) and (self.sum, self.checksum, self.count) == (other.sum, other.checksum, other.count)

    def __repr__(self) -> str:
        return f"Symbol({self.sum.hex()[:16]}..., {self.checksum:016x}, {self.count})"


class _Mapping:
    """The indexes one id maps to, in order, and the sign it carries in a decoder."""
    __slots__ = ("id", "value", "checksum", "sign", "state", "index")

    def __init__(self, item_id: bytes, checksum: int, sign: int):
        self.id, self.value = item_id, int.from_bytes(item_id, "big")
        self.checksum, self.sign, self.state, self.index = checksum, sign, checksum, 0

    def advance(self) -> None:
        self.state = (self.state * _MULTIPLIER) & _M64
        x = float(self.state >> 11) * 2048.0
        step = max(1.0, math.ceil((self.index + 1.5) * (4294967296.0 / math.sqrt(x + 1) - 1)))
        following = self.index + step
        self.index = _NO_INDEX if following >= LAST_INDEX else int(following)

    def __lt__(self, other) -> bool:
        return self.index < other.index


class RibltEncoder:
    """Produces the coded symbols of a set, index after index."""

    def __init__(self, key: bytes, ids):
        key = _checked_key(key)
        self.queue = []
        for item_id in ids:
            if len(item_id) != ID_SIZE:
                raise ValueError(f"an id is {ID_SIZE} bytes, got {len(item_id)}")
            self.queue.append(_Mapping(bytes(item_id), siphash24(key, item_id), 1))
        heapq.heapify(self.queue)
        self.produced = 0

    def next(self, count: int) -> list[Symbol]:
        out = []
        for _ in range(count):
            at = self.produced
            self.produced += 1
            total = checksum = n = 0
            while self.queue and self.queue[0].index == at:
                m = heapq.heappop(self.queue)
                total ^= m.value
                checksum ^= m.checksum
                n += 1
                m.advance()
                if m.index != _NO_INDEX:
                    heapq.heappush(self.queue, m)
            out.append(Symbol(total.to_bytes(ID_SIZE, "big"), checksum, n))
        return out


class RibltDecoder:
    """Subtracts the local set's symbols from a remote stream and peels the difference out as symbols arrive."""

    def __init__(self, key: bytes, ids):
        self.key = _checked_key(key)
        self.local = RibltEncoder(self.key, ids)
        self.cells: list[list] = []        # [sum as an integer, checksum, count]
        self.recovered: list[_Mapping] = []
        self.remote_only: list[bytes] = []
        self.local_only: list[bytes] = []

    def add(self, remote: Symbol) -> None:
        """Adds the next remote symbol and peels what it frees; ValueError, and the decoder is unusable, when the
        stream peels more ids than it has symbols (P2-Q-SEC-04)."""
        mine = self.local.next(1)[0]
        cell = [int.from_bytes(remote.sum, "big") ^ int.from_bytes(mine.sum, "big"), remote.checksum ^ mine.checksum,
                remote.count - mine.count]
        at = len(self.cells)
        while self.recovered and self.recovered[0].index == at:
            m = heapq.heappop(self.recovered)
            cell[0] ^= m.value
            cell[1] ^= m.checksum
            cell[2] -= m.sign
            m.advance()
            if m.index != _NO_INDEX:
                heapq.heappush(self.recovered, m)
        self.cells.append(cell)
        self._peel(at)

    def _peel(self, start: int) -> None:
        pending = [start]
        while pending:
            cell = self.cells[pending.pop()]
            if cell[2] not in (1, -1):
                continue
            item_id = cell[0].to_bytes(ID_SIZE, "big")
            if siphash24(self.key, item_id) != cell[1]:
                continue
            if len(self.remote_only) + len(self.local_only) >= len(self.cells):
                raise ValueError(f"the stream peels more ids than its {len(self.cells)} symbols")
            m = _Mapping(item_id, cell[1], cell[2])
            (self.remote_only if m.sign == 1 else self.local_only).append(item_id)
            while m.index < len(self.cells):
                target = self.cells[m.index]
                target[0] ^= m.value
                target[1] ^= m.checksum
                target[2] -= m.sign
                pending.append(m.index)
                m.advance()
            if m.index != _NO_INDEX:
                heapq.heappush(self.recovered, m)

    def decoded(self) -> bool:
        """Whether symbol 0, which every id maps to, is empty."""
        return bool(self.cells) and self.cells[0] == [0, 0, 0]

    def symbols(self) -> int:
        return len(self.cells)


# ------------------------------------------------------------------ sketches over CIDs

MAX_SKETCH_BYTES = 64 * 1024
MAX_ROUNDS = 64
MAX_RIBLT_SYMBOLS = 16_384
RIBLT_SESSIONS = 4
RIBLT_IDLE_S = 30.0
SET_CACHE_S = 10.0
SESSIONS_COUNTED = 1024
ROUND_TIMEOUT_S = 10.0
SYMBOLS_PER_QUERY = (MAX_SKETCH_BYTES - 64) // (ID_SIZE + 8 + 10)
MIN_SYMBOL_CAP = 64
REASON_OVER_BUDGET, REASON_POLICY = 2, 3


class SketchSet:
    """A set of CIDs as reconciliation items: each digest at timestamp 0 (choice 1 of §10.13)."""

    def __init__(self, cid_list):
        self.by_digest: dict[bytes, str] = {}
        for cid in cid_list:
            if cids.is_cid(cid):
                self.by_digest.setdefault(cids.parse(cid).digest, cid)
        self.ids = list(self.by_digest)
        self.storage = Storage((0, i) for i in self.ids)


class SketchServer:
    """The holder's answer to a sketch: a negentropy reply, or a RIBLT status after the symbols a session brought.
    ``answer`` returns ``("reply", bytes)``, ``("refuse", reason, why)``, or ``("drop", why)``."""

    def __init__(self, source, clock=time.monotonic):
        self.source = source
        self.clock = clock
        self._cached = None
        self.rounds: dict[tuple, int] = {}
        self.riblt: dict[tuple, list] = {}   # (asker, key) -> [decoder, last use]

    def _set(self, now: float) -> SketchSet:
        if self._cached is None or now - self._cached[0] >= SET_CACHE_S:
            self._cached = (now, SketchSet(self.source()))
        return self._cached[1]

    def answer(self, asker: str, req: int, sketch: bytes, budget: int) -> tuple:
        if not sketch:
            return "drop", "an empty sketch"
        if len(sketch) > MAX_SKETCH_BYTES:
            return "drop", f"a sketch of {len(sketch)} bytes passes {MAX_SKETCH_BYTES}"
        encoding = sketch[0]
        negentropy = 0x60 <= encoding <= 0x6F and encoding != RIBLT_ENCODING
        if not negentropy and encoding != RIBLT_ENCODING:
            return "drop", f"unknown sketch encoding 0x{encoding:x}"
        taken = self.rounds.pop((asker, req), 0)
        self.rounds[(asker, req)] = taken + 1
        while len(self.rounds) > SESSIONS_COUNTED:
            del self.rounds[next(iter(self.rounds))]
        if taken >= MAX_ROUNDS:
            return "refuse", REASON_OVER_BUDGET, f"a session takes at most {MAX_ROUNDS} rounds"
        limit = max(MIN_FRAME_SIZE_LIMIT, min(budget, MAX_SKETCH_BYTES))
        now = self.clock()
        try:
            if negentropy:
                return "reply", Negentropy(self._set(now).storage, limit).reconcile(sketch)
            return self._riblt(asker, sketch, limit, now)
        except ValueError as malformed:
            return "drop", str(malformed)

    def _riblt(self, asker: str, sketch: bytes, limit: int, now: float) -> tuple:
        reader = Reader(sketch)
        reader.next()
        key = reader.bytes(KEY_BYTES)
        start, count = reader.varint(), reader.varint()
        if count > reader.remaining() // (ID_SIZE + 9):
            raise ValueError(f"{count} symbols run past the sketch")
        symbols = [Symbol.read(reader) for _ in range(count)]
        if reader.remaining():
            raise ValueError(f"{reader.remaining()} bytes trail the symbols")
        for name in [n for n, s in self.riblt.items() if now - s[1] > RIBLT_IDLE_S]:
            del self.riblt[name]
        name = (asker, key)
        session = self.riblt.get(name)
        if session is None:
            if start != 0:
                return "drop", f"a RIBLT stream starts at index 0, got index {start}"
            if len(self.riblt) >= RIBLT_SESSIONS:
                return "refuse", REASON_OVER_BUDGET, f"this holder runs {RIBLT_SESSIONS} RIBLT sessions already"
            session = [RibltDecoder(key, self._set(now).ids), now]
            self.riblt[name] = session
        decoder = session[0]
        session[1] = now
        if start != decoder.symbols():
            return "drop", f"the next RIBLT symbol is index {decoder.symbols()}, got index {start}"
        try:
            for symbol in symbols:
                decoder.add(symbol)
        except ValueError as forged:
            self.riblt.pop(name, None)  # a decoder that peeled a forged stream holds nothing usable
            return "drop", str(forged)
        out = bytearray([RIBLT_ENCODING])
        if not decoder.decoded():
            if decoder.symbols() <= MAX_RIBLT_SYMBOLS:
                out.append(RIBLT_MORE)
                return "reply", bytes(out)
            out.append(RIBLT_TOO_MANY)
        elif 3 + 20 + (len(decoder.remote_only) + len(decoder.local_only)) * ID_SIZE > limit:
            out.append(RIBLT_TOO_MANY)
        else:
            out.append(RIBLT_DECODED)
            for ids in (decoder.remote_only, decoder.local_only):
                write_varint(out, len(ids))
                for item_id in ids:
                    out.extend(item_id)
        self.riblt.pop(name, None)
        return "reply", bytes(out)


class SketchSession:
    """The asker's side of one reconciliation with a holder, under one request id: RIBLT first when the expected
    difference is above 0, falling back to negentropy, else negentropy alone. ``send(sketch)`` sends one round;
    ``on_reply`` and ``on_reject`` feed the answers; ``outcome`` holds ``(have, need)`` as CIDs once done, and
    ``failure`` names why it ended otherwise."""

    def __init__(self, holder: str, req: int, cid_list, send, expected: int = 0, clock=time.monotonic):
        if expected < 0:
            raise ValueError("the expected difference is at least 0")
        self.holder, self.req, self.set, self.send_round = holder, req, SketchSet(cid_list), send
        self.expected, self.clock = expected, clock
        self.have: list[bytes] = []
        self.need: list[bytes] = []
        self.negentropy = None
        self.encoder = None
        self.key = None
        self.encoding = None
        self.rounds = 0
        self.sent_at = 0.0
        self.outcome = None
        self.failure = None

    @property
    def done(self) -> bool:
        return self.outcome is not None or self.failure is not None

    def symbol_cap(self) -> int:
        return min(MAX_RIBLT_SYMBOLS, max(MIN_SYMBOL_CAP, 2 * self.expected))

    def start(self) -> None:
        if self.expected > 0:
            self.encoding = "riblt"
            self.key = os.urandom(KEY_BYTES)
            self.encoder = RibltEncoder(self.key, self.set.ids)
            self._symbols(min(self.symbol_cap(), math.ceil(self.expected * 1.4)))
        else:
            self._negentropy()

    def _negentropy(self) -> None:
        self.encoding = "negentropy" if self.encoding is None else self.encoding + ",negentropy"
        self.encoder = None
        self.negentropy = Negentropy(self.set.storage, MAX_SKETCH_BYTES)
        self._send(self.negentropy.initiate())

    def _symbols(self, count: int) -> None:
        n = min(max(count, 1), SYMBOLS_PER_QUERY)
        out = bytearray([RIBLT_ENCODING])
        out.extend(self.key)
        write_varint(out, self.encoder.produced)
        write_varint(out, n)
        for symbol in self.encoder.next(n):
            out.extend(symbol.encode())
        self._send(bytes(out))

    def _send(self, sketch: bytes) -> None:
        if self.rounds >= MAX_ROUNDS:
            self.failure = f"no agreement within {MAX_ROUNDS} rounds"
            return
        self.rounds += 1
        self.sent_at = self.clock()
        self.send_round(sketch)

    def on_reply(self, reply: bytes) -> None:
        if self.done:
            return
        if not reply:
            self.failure = "an empty answer"
            return
        if len(reply) > MAX_SKETCH_BYTES:
            self.failure = f"an answer of {len(reply)} bytes passes {MAX_SKETCH_BYTES}"
            return
        try:
            if self.encoder is not None:
                self._on_riblt(reply)
            else:
                if reply[0] != PROTOCOL_VERSION:
                    raise ValueError(f"a negentropy round answered with 0x{reply[0]:x}")
                following = self.negentropy.reconcile_initiator(reply, self.have, self.need)
                if following is None:
                    self._complete()
                else:
                    self._send(following)
        except ValueError as malformed:
            self.failure = f"an answer outside its grammar: {malformed}"

    def _on_riblt(self, reply: bytes) -> None:
        reader = Reader(reply)
        if reader.next() != RIBLT_ENCODING:
            raise ValueError("a RIBLT round answered with another encoding")
        status = reader.next()
        if status == RIBLT_MORE:
            if self.encoder.produced >= self.symbol_cap():
                self._negentropy()
            else:
                self._symbols(min(self.symbol_cap() - self.encoder.produced, max(8, self.expected // 4)))
        elif status == RIBLT_TOO_MANY:
            self._negentropy()
        elif status == RIBLT_DECODED:
            for into in (self.have, self.need):
                count = reader.varint()
                if count > reader.remaining() // ID_SIZE:
                    raise ValueError(f"{count} ids run past the answer")
                into.extend(reader.bytes(ID_SIZE) for _ in range(count))
            if reader.remaining():
                raise ValueError(f"{reader.remaining()} bytes trail the lists")
            self._complete()
        else:
            raise ValueError(f"unknown RIBLT status {status}")

    def on_reject(self, reason: int) -> None:
        if not self.done:
            self.failure = f"{self.holder} refused the round with REJECT reason {reason}"

    def tick(self) -> None:
        if not self.done and self.clock() - self.sent_at > ROUND_TIMEOUT_S:
            self.failure = f"no answer within {ROUND_TIMEOUT_S:.0f} s"

    def _complete(self) -> None:
        have = []
        for item_id in self.have:
            cid = self.set.by_digest.get(item_id)
            if cid is None:
                self.failure = "a have id this member does not hold"
                return
            have.append(cid)
        self.outcome = (have, [cids.of_digest(item_id, cids.DAG_CBOR) for item_id in self.need])
