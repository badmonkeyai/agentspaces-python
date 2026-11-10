#
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

"""HLC round seven, 2026-11-08: the six gaps SPEC §9.3 left after round six, as they bind this
client, settled by the reference rule (Java's behaviour unless it breaks F1 or F3).

1. A bignum holds at most 1000 bytes, alone or as a decimal's mantissa (S9): Jackson reads no
   longer number, so every decoder refuses one and every encoder writes none.
5. A stamp is one definite text of at most 3996 UTF-16 units: a longer text travels only in
   Jackson's chunks and is no stamp anywhere, a ``pdt.issued`` included, and a clock's node
   leaves room for the longest physical and logical parts.
6. The records that travel inside a capability pipe frame (aggregate, semantic discovery, Raft)
   decode under their annex I schemas and the canonical-bytes rule, as Java's ``fromWire`` reads
   them; a ``double`` field takes any float64, as Java's does.
8. A beacon document that carries a signature arrives as exactly its canonical JSON, so the
   signature covers the bytes received (the ``beacon-document`` vectors)."""

import json
import math
import pathlib
from decimal import Decimal

import pytest

from agentspaces import beacon, cbor, records, wire
from agentspaces.capabilities import Aggregate, Semantic
from agentspaces.capabilities import ordered

HERE = pathlib.Path(__file__).parent
VECTORS = json.loads((HERE / "wire_encoding_vectors.json").read_text())["vectors"]


# 1. A bignum holds at most 1000 bytes ------------------------------------------------------------

def test_the_encoder_writes_no_bignum_past_1000_bytes():
    widest = (1 << 7991) + 1
    assert len(cbor.dumps(widest)) == 1004 and cbor.loads(cbor.dumps(widest)) == widest
    for value in (1 << 7999, -(1 << 7999), Decimal((0, (1,) * 2409, -1))):
        with pytest.raises(ValueError):
            cbor.dumps(value)


# 5. A stamp is at most 3996 UTF-16 units ---------------------------------------------------------

PREFIX = "1800000000000:0:"


def test_a_stamp_past_3996_utf16_units_is_no_stamp_whatever_type_holds_its_text():
    edge = PREFIX + "n" * (3996 - len(PREFIX))
    assert wire.parse_hlc(edge) is not None
    assert wire.parse_hlc(edge + "n") is None
    pairs = PREFIX + "\U0001F600" * ((3996 - len(PREFIX)) // 2)
    assert wire.parse_hlc(pairs) is not None and wire.parse_hlc(pairs + "n") is None
    assert wire.parse_hlc(cbor.loads(cbor.dumps(edge + "n"))) is None


def test_a_clock_refuses_a_node_that_could_carry_a_stamp_past_3996_units():
    longest = "n" * 3965
    assert len(f"{(1 << 63) - 1}:{(1 << 31) - 1}:{longest}") == 3996
    wire.hlc_now(longest, 1_800_000_000_000)
    with pytest.raises(ValueError):
        wire.hlc_now(longest + "n", 1_800_000_000_000)


# 6. Pipe payloads decode under their schemas -----------------------------------------------------

class _Identity:
    peer_id = "zSelf"


class _Peer:
    identity = _Identity()
    ads: dict = {}

    def _now_ms(self):
        return 1_800_000_000_000


class _Pipes:
    """Capability pipes that hand a test the handler and keep what the capability sends."""

    def __init__(self):
        self.peer = _Peer()
        self.handlers = {}
        self.sent = []

    def on_capability(self, capability, handler):
        self.handlers[capability] = handler

    def send(self, target, capability, payload):
        self.sent.append((target, capability, payload))

    def members(self):
        return []


def _frame(**variant) -> bytes:
    fields = {"share": None, "extremum": None, "histogram": None, "roster": None}
    fields.update(variant)
    return cbor.dumps(fields)


def _aggregate_hears(payload: bytes) -> bool:
    pipes = _Pipes()
    aggregate = Aggregate(pipes, advertise=False)
    pipes.handlers["aspace:cap/aggregate"]("zPeer", payload)
    return aggregate.exchanged


def test_an_aggregate_frame_decodes_under_its_schema():
    # Java writes an extremum of NaN before its node holds a value, and reads any float64 there
    assert _aggregate_hears(_frame(extremum={"epochId": "e", "max": True, "value": math.nan}))
    assert _aggregate_hears(_frame(share={"epochId": "e", "value": 1.0, "weight": 0.5}))
    assert _aggregate_hears(_frame(roster={"epochId": "e", "members": [-5, 7]}))
    assert not _aggregate_hears(_frame(share={"epochId": "e", "value": 1, "weight": 0.5}))
    assert not _aggregate_hears(_frame(share={"epochId": "e", "value": cbor.Float32(1.0), "weight": 0.5}))
    assert not _aggregate_hears(_frame(share={"epochId": "e", "value": 1.0, "weight": 0.5, "x": 1}))
    assert not _aggregate_hears(_frame(roster={"epochId": "e", "members": [1.0]}))
    assert not _aggregate_hears(cbor.dumps({"share": {"epochId": "e", "value": 1.0, "weight": 0.5}}))
    assert not _aggregate_hears(_frame(histogram={"epochId": "e", "lo": 0.0, "hi": 1.0, "buckets": [1]}))


def test_a_semantic_query_and_response_decode_under_their_schemas():
    pipes = _Pipes()
    Semantic(pipes)
    hear = pipes.handlers["aspace:cap/semantic-discovery"]
    hear("zPeer", cbor.dumps({"nonce": 3, "text": "tasks", "limit": 4}))
    assert len(pipes.sent) == 1
    for relabel in ({"nonce": 3, "text": "tasks", "limit": 4.0}, {"nonce": "3", "text": "tasks", "limit": 4},
                    {"nonce": 3, "text": "tasks", "limit": 4, "x": 1}, {"text": "tasks", "nonce": 3, "limit": 4}):
        hear("zPeer", cbor.dumps(relabel))
    assert len(pipes.sent) == 1


def test_a_raft_frame_decodes_under_its_schema():
    assert ordered.parse_frame(ordered.client_submit_frame(b"cmd")) == {"clientSubmit": {"command": b"cmd"}}
    vote = {"term": 2, "candidate": "zPeer", "lastLogIndex": 0, "lastLogTerm": 0}
    assert ordered.parse_frame(ordered.raft_frame(requestVote=vote)) == {"requestVote": vote}
    assert ordered.parse_frame(ordered.raft_frame(requestVote=dict(vote, term=2.0))) is None
    assert ordered.parse_frame(cbor.dumps({"clientSubmit": {"command": b"cmd"}})) is None
    assert ordered.parse_frame(ordered.raft_frame(clientSubmit={"command": "cmd"})) is None


def test_a_take_claim_keeps_its_finite_bid_while_a_double_field_takes_any_float64():
    assert records.conforms({"epochId": "e", "max": False, "value": math.inf}, "PushSumAggregate.Extremum")
    claim = {"entryId": "e", "spaceId": "s", "epoch": 1, "stamp": "1:0:n", "holder": "zPeer/w",
             "bid": math.nan, "expiresAtMillis": 5}
    assert not records.conforms(claim, "TakeClaim")
    assert records.conforms(dict(claim, bid=-0.0), "TakeClaim")


# 8. A signed beacon document arrives canonical ---------------------------------------------------

BEACONS = [v for v in VECTORS if v["carrier"] == "beacon-document"]


def test_the_beacon_vectors_ship():
    assert len(BEACONS) == 40


@pytest.mark.parametrize("vector", BEACONS, ids=[v["id"] for v in BEACONS])
def test_a_beacon_document_reads_exactly_as_its_vector_says(vector):
    body = bytes.fromhex(vector["hex"])
    if vector["verdict"] == "accept":
        assert beacon.verify_document(beacon.parse_document(body)) == vector["signer"]
    else:
        with pytest.raises(ValueError):
            beacon.verify_document(beacon.parse_document(body))


def test_a_fetch_refuses_a_signed_document_that_is_not_its_canonical_json(monkeypatch):
    canonical = bytes.fromhex(BEACONS[0]["hex"])
    monkeypatch.setattr(beacon, "_http_get", lambda url, timeout, allow_plain: canonical + b"\n")
    with pytest.raises(ValueError):
        beacon.fetch_beacon_document("https://beacon.example/.well-known/agentspaces/beacon.json")
    monkeypatch.setattr(beacon, "_http_get", lambda url, timeout, allow_plain: canonical)
    assert beacon.fetch_beacon_document("https://beacon.example/x")["issuer"] == BEACONS[0]["signer"]
