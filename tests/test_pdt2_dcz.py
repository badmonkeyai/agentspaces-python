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
"""PDT 2 phase 7, P2-C-01 group Z (P2-Z-01, P2-Z-04, P2-Q-SEC-05; srad/agentspaces-pdt2.md §3.8, §10.12
decision 4): the Python reader of a ``dcz`` field opens the zstd frame over its base as a raw dictionary
and refuses, each by name and before it decompresses, what Java's ``Dcz.decode`` refuses. The frames
here come from the standard library's zstd, as a writer of another port would make them."""

import hashlib

import pytest

from agentspaces.pdt import dcz
from test_pdt_vectors import java_random_bytes

zstd = pytest.importorskip("compression.zstd")

BASE = java_random_bytes(42, 4096)


def _zstd(target: bytes, content_size: bool = True, window_log: int = 0, base: bytes = BASE) -> bytes:
    options = {zstd.CompressionParameter.content_size_flag: int(content_size),
               zstd.CompressionParameter.checksum_flag: 0, zstd.CompressionParameter.dict_id_flag: 0}
    if window_log:
        options[zstd.CompressionParameter.window_log] = window_log
    compressor = zstd.ZstdCompressor(options=options, zstd_dict=zstd.ZstdDict(base, is_raw=True))
    return compressor.compress(target, zstd.ZstdCompressor.FLUSH_FRAME)


def _field(frame: bytes, base: bytes = BASE) -> bytes:
    return b"d" + bytes.fromhex("5e2a4d1820000000") + hashlib.sha256(base).digest() + frame


def test_a_one_byte_edit_opens_over_its_base_and_names_the_base_by_sha256():
    target = bytearray(BASE)
    target[1000] ^= 0xFF
    field = _field(_zstd(bytes(target)))
    assert len(field) < 100
    assert dcz.decode(BASE, field) == bytes(target)
    other = java_random_bytes(7, 4096)
    with pytest.raises(dcz.DczRefused, match="another base"):
        dcz.decode(other, field)


def test_the_format_byte_and_the_header_are_read_by_name():
    field = _field(_zstd(b"x" * 100))
    with pytest.raises(dcz.DczRefused, match="VCDIFF"):
        dcz.decode(BASE, b"v" + field[1:])
    with pytest.raises(dcz.DczRefused, match="unknown format byte 0x7a"):
        dcz.decode(BASE, b"z" + field[1:])
    with pytest.raises(dcz.DczRefused, match="RFC 9842"):
        dcz.decode(BASE, field[:1] + b"\0" * 8 + field[9:])
    with pytest.raises(dcz.DczRefused, match="holds no format byte"):
        dcz.decode(BASE, field[:20])


def test_a_bomb_past_the_chunk_bound_is_refused_before_it_decompresses():
    bomb = _field(_zstd(bytes(1 << 20)))
    assert len(bomb) < 200
    with pytest.raises(dcz.DczRefused, match="content size of 1048576 bytes.*262144"):
        dcz.decode(BASE, bomb)
    with pytest.raises(dcz.DczRefused, match="262144"):
        dcz.decode(BASE, _field(_zstd(bytes(dcz.MAX_OUTPUT + 1))))
    assert len(dcz.decode(BASE, _field(_zstd(bytes(dcz.MAX_OUTPUT))))) == dcz.MAX_OUTPUT


def test_a_frame_without_a_content_size_a_wide_window_or_a_dictionary_id_is_refused():
    with pytest.raises(dcz.DczRefused, match="no content size"):
        dcz.decode(BASE, _field(_zstd(java_random_bytes(12, 2000), content_size=False)))
    windowed = bytearray(_zstd(java_random_bytes(13, 2048), window_log=10))
    assert windowed[4] & 0x20 == 0, "no single segment: a window descriptor follows"
    assert len(dcz.decode(BASE, _field(bytes(windowed)))) == 2048
    windowed[5] = 9 << 3
    with pytest.raises(dcz.DczRefused, match="window of 524288 bytes"):
        dcz.decode(BASE, _field(bytes(windowed)))
    frame = _zstd(java_random_bytes(15, 300))
    named = frame[:4] + bytes([(frame[4] & 0xFC) | 1, 7]) + frame[5:]
    with pytest.raises(dcz.DczRefused, match="dictionary id"):
        dcz.decode(BASE, _field(named))
    reserved = frame[:4] + bytes([frame[4] | 0x08]) + frame[5:]
    with pytest.raises(dcz.DczRefused, match="reserved bit"):
        dcz.decode(BASE, _field(reserved))


def test_a_frame_that_writes_more_than_it_declares_or_holds_two_frames_is_refused():
    frame = bytearray(_zstd(java_random_bytes(14, 2000)))
    assert frame[4] >> 6 == 1, "a two-byte content size, which counts from 256"
    frame[5], frame[6] = (1000 - 256) & 0xFF, 0
    with pytest.raises(dcz.DczRefused):
        dcz.decode(BASE, _field(bytes(frame)))
    one = _zstd(java_random_bytes(19, 300))
    with pytest.raises(dcz.DczRefused, match="more than one zstd frame"):
        dcz.decode(BASE, _field(one + one))
    with pytest.raises(dcz.DczRefused, match="more than one zstd frame"):
        dcz.decode(BASE, _field(one + bytes([0x50, 0x2A, 0x4D, 0x18, 1, 0, 0, 0, 9])))
    with pytest.raises(dcz.DczRefused):
        dcz.decode(BASE, _field(one[:-3]))


def test_a_base_past_the_bound_or_with_the_dictionary_magic_opens_nothing():
    with pytest.raises(dcz.DczRefused, match="base of 262145 bytes"):
        dcz.decode(java_random_bytes(16, dcz.MAX_OUTPUT + 1), _field(_zstd(bytes(10))))
    magic = bytes.fromhex("37a430ec") + BASE[4:]
    with pytest.raises(dcz.DczRefused, match="dictionary magic"):
        dcz.decode(magic, _field(_zstd(b"hello"), base=magic))


def test_a_python_without_zstd_refuses_every_frame_by_name(monkeypatch):
    monkeypatch.setattr(dcz, "_zstd", None)
    with pytest.raises(dcz.DczRefused, match="zstd is not available"):
        dcz.decode(BASE, _field(_zstd(b"hello")))
