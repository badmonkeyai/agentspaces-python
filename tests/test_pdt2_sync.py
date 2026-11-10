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
"""PDT 2 phase 7, P2-C-01 group K (P2-K-01, P2-K-04, P2-K-05; srad/agentspaces-pdt2.md §3.6, §10.13): the Python
negentropy reproduces every message of every round that the reference implementation wrote into
``agentspaces-spec/negentropy-vectors.json``, with 64-bit varints, and the Python RIBLT reproduces the coded symbols
of ``pdt_riblt_symbols`` byte for byte and decodes a difference in one pass. The cases mirror Java's
``NegentropyConformanceTest`` and ``RibltTest``."""

import hashlib
import json
import pathlib
import random

import pytest

from agentspaces.pdt import sync

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "agentspaces-spec" / "negentropy-vectors.json"
TIMESTAMP_BASE = 1792320000
KEY = bytes(range(16))


@pytest.fixture(scope="module")
def vectors():
    if not VECTORS.exists():
        pytest.skip("agentspaces-spec/negentropy-vectors.json is not beside this checkout")
    return json.loads(VECTORS.read_text())


def _members(vectors, case, side):
    universe = case["universe"]
    per = next(u["perTimestamp"] for u in vectors["recipe"]["universes"] if u["name"] == universe)
    items = []
    for lo, hi in case[side]:
        for i in range(lo, hi):
            items.append((TIMESTAMP_BASE + i // per, hashlib.sha256(f"aspace:negentropy:{universe}:{i}".encode()).digest()))
    return sync.Storage(items)


def _run(vectors, case):
    limit = case["frameSizeLimit"]
    client = sync.Negentropy(_members(vectors, case, "client"), limit)
    server = sync.Negentropy(_members(vectors, case, "server"), limit)
    messages, have, need = [], [], []
    query = client.initiate()
    while True:
        assert len(messages) // 2 < 64, "within the 64 rounds of P2-K-04"
        messages.append(query)
        reply = server.reconcile(query)
        messages.append(reply)
        query = client.reconcile_initiator(reply, have, need)
        if query is None:
            return messages, sorted(i.hex() for i in have), sorted(i.hex() for i in need)


def test_every_message_of_every_case_matches_the_reference(vectors):
    assert len(vectors["cases"]) == 10
    for case in vectors["cases"]:
        messages, have, need = _run(vectors, case)
        assert [m.hex() for m in messages] == [m["hex"] for m in case["messages"]], case["name"]
        assert len(messages) // 2 == case["rounds"] and sum(map(len, messages)) == case["bytes"], case["name"]
        assert (have, need) == (case["have"], case["need"]), case["name"]


def test_the_measurements_at_the_scale_of_p2_k_02_match_the_reference(vectors):
    for case in vectors["measurements"]:
        messages, have, need = _run(vectors, case)
        assert len(messages) // 2 == case["rounds"] and sum(map(len, messages)) == case["bytes"], case["name"]
        assert (len(have), len(need)) == (case["have"], case["need"]), case["name"]
        assert max(map(len, messages)) == case["largestMessage"], case["name"]


def test_a_responder_answers_the_upstream_protocol_version_vectors(vectors):
    for case in vectors["upgrade"]:
        server = sync.Negentropy(sync.Storage([(t, bytes.fromhex(i)) for t, i in case["server"]]), 0)
        assert server.reconcile(bytes.fromhex(case["message"])).hex() == case["reply"], case["name"]


def test_malformed_messages_are_refused_by_name():
    server = sync.Negentropy(sync.Storage([]), 0)
    for message, why in ((b"\x61\x00", "prematurely"), (b"\x70", "version byte"), (b"\x61\x00\x21", "bound key too long"),
                         (b"\x61\x00\x00\x07", "unexpected mode"), (b"\x61\x00\x00\x02\x05", "runs past"),
                         (b"\x61" + b"\xff" * 10 + b"\x00", "63 bits")):
        with pytest.raises(ValueError, match=why):
            server.reconcile(message)
    client = sync.Negentropy(sync.Storage([]), 0)
    client.initiate()
    with pytest.raises(ValueError, match="unsupported negentropy protocol version 2"):
        client.reconcile_initiator(b"\x62", [], [])
    with pytest.raises(ValueError, match="at least 4096"):
        sync.Negentropy(sync.Storage([]), 100)


def _id(universe, i):
    return hashlib.sha256(f"{universe}:{i}".encode()).digest()


def test_siphash_matches_the_reference_vector_of_its_authors():
    # Aumasson and Bernstein, "SipHash: a fast short-input PRF", appendix A: key 00..0f, message 00..0e
    assert sync.siphash24(KEY, bytes(range(15))) == 0xA129CA6149BE45E5


def test_a_difference_decodes_in_one_pass_well_under_twice_its_size():
    rng = random.Random(42)
    n = 20_000
    picked = rng.sample(range(n), 200)
    client_only, server_only = set(picked[:100]), set(picked[100:])
    client = [_id("k", i) for i in range(n) if i not in server_only]
    server = [_id("k", i) for i in range(n) if i not in client_only]
    encoder, decoder = sync.RibltEncoder(KEY, client), sync.RibltDecoder(KEY, server)
    while not decoder.decoded():
        for symbol in encoder.next(50):
            decoder.add(symbol)
    assert decoder.symbols() < 400, "P2-K-05: under twice the difference"
    assert sorted(decoder.remote_only) == sorted(_id("k", i) for i in client_only)
    assert sorted(decoder.local_only) == sorted(_id("k", i) for i in server_only)


def test_equal_sets_decode_at_the_first_symbol_and_another_key_finds_the_same_difference():
    both = [_id("same", i) for i in range(1000)]
    decoder = sync.RibltDecoder(KEY, both)
    decoder.add(sync.RibltEncoder(KEY, both).next(1)[0])
    assert decoder.decoded() and decoder.remote_only == [] and decoder.local_only == []
    a = [_id("x", i) for i in range(300)]
    b = [x for i, x in enumerate(a) if i % 50]
    other = bytes.fromhex("f0e0d0c0b0a090807060504030201000")
    assert sync.RibltEncoder(other, a).next(1)[0].checksum != sync.RibltEncoder(KEY, a).next(1)[0].checksum
    encoder, decoder = sync.RibltEncoder(other, a), sync.RibltDecoder(other, b)
    while not decoder.decoded():
        decoder.add(encoder.next(1)[0])
    assert len(decoder.remote_only) == 6 and decoder.local_only == []


def test_a_symbol_round_trips_its_wire_form_and_a_short_one_is_refused():
    symbols = sync.RibltEncoder(KEY, [_id("w", i) for i in (1, 2, 3)]).next(4)
    wire = b"".join(s.encode() for s in symbols)
    reader = sync.Reader(wire)
    assert [sync.Symbol.read(reader) for _ in symbols] == symbols and reader.remaining() == 0
    assert symbols[0].count == 3, "symbol 0 holds every id"
    with pytest.raises(ValueError, match="prematurely"):
        sync.Symbol.read(sync.Reader(bytes(39)))
    with pytest.raises(ValueError, match="16 bytes"):
        sync.RibltEncoder(bytes(8), [])


def test_a_stream_that_peels_an_id_back_and_forth_is_refused():
    """The phase 5 adversary's A1: an asker that knows the key forges a pure symbol whose id its other indexes
    lack, and a decoder that went on peeling it would never stop."""
    forged = _id("forged", 0)
    checksum = sync.siphash24(KEY, forged)
    decoder = sync.RibltDecoder(KEY, [])
    with pytest.raises(ValueError, match="peels more ids than its"):
        decoder.add(sync.Symbol(forged, checksum, 1))
        for _ in range(1000):  # the forged id comes back at its next index
            decoder.add(sync.Symbol(bytes(32), 0, 0))
