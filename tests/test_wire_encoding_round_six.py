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

"""The wire encoding of HLC round six, 2026-11-08, as it binds this client.

F1. A protocol record field of the wrong CBOR type makes its carrier undecodable.
F2. Tags 2, 3 and 4 decode to ``int`` and ``decimal.Decimal`` in application values and
    re-encode to the identical bytes; a protocol field refuses them.
F3. A carrier decodes only when re-encoding what it decoded gives back exactly the bytes
    received (rules S1 to S12 for every item, P1 to P4 for every protocol record).
F4. An agent-signed state's ``signedAt`` meets the far-future rule.
R5. An agent id's local name holds no ``/`` and no ``:``.
R6. A claim that predates its entry, or a far-past claim contesting a held entry, never folds.
R8. A state without its lease stamp merges nothing and counts nothing.
Reference rule. A carrier holding a record that Java's record constructor refuses (a null
    Java requires, a dot counter or lease expiry that is not positive) is undecodable.

``wire_encoding_vectors.json`` is the definition stage's vector file (155 vectors, 196 with the
41 of HLC round seven, 2026-11-08), copied byte for byte from
``agentspaces/tools/wire-encoding/vectors.json``."""

import json
import math
import pathlib
from decimal import Decimal

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity

VECTORS = json.loads((pathlib.Path(__file__).parent / "wire_encoding_vectors.json").read_text())["vectors"]


def _vectors(carrier: str) -> list:
    return [vector for vector in VECTORS if vector["carrier"] == carrier]


def _ids(vectors: list) -> list:
    return [vector["id"] for vector in vectors]


# S1 to S12: every document ------------------------------------------------------------------

DOCUMENTS = _vectors("document")


@pytest.mark.parametrize("vector", DOCUMENTS, ids=_ids(DOCUMENTS))
def test_a_document_decodes_exactly_when_the_encoding_accepts_it(vector):
    raw = bytes.fromhex(vector["hex"])
    if vector["verdict"] == "accept":
        assert cbor.dumps(cbor.loads(raw)) == raw
    else:
        with pytest.raises(ValueError):
            cbor.loads(raw)


# The encoder writes each value in its one encoding (F2, S4, S9, S10) --------------------------

ENCODINGS = {
    "a long is a plain integer": (2**63 - 1, "1b7fffffffffffffff"),
    "2^63 is a bignum": (2**63, "c249008000000000000000"),
    "2^64 - 1 is a bignum": (2**64 - 1, "c24900ffffffffffffffff"),
    "-2^63 - 1 is a bignum": (-(2**63) - 1, "c349008000000000000001"),
    "a decimal drops its trailing zeros": (Decimal("1.50"), "c482200f"),
    "a decimal zero is [0, 0]": (Decimal("0.000"), "c4820000"),
    "a negative decimal zero is [0, 0]": (Decimal("-0"), "c4820000"),
    "a decimal past 28 digits stays exact": (Decimal("100000000000000000000000000000001"),
                                             "c48200c24e04ee2d6d415b85acef8100000001"),
    "1E+3 is [3, 1]": (Decimal("1E+3"), "c4820301"),
    "a float32 is FA": (cbor.Float32(1.5), "fa3fc00000"),
    "a NaN is Java's NaN": (math.nan, "fb7ff8000000000000"),
    "a float32 NaN is Java's NaN": (cbor.Float32(math.nan), "fa7fc00000"),
    "a negative NaN is Java's NaN": (-math.nan, "fb7ff8000000000000"),
}


@pytest.mark.parametrize("name", sorted(ENCODINGS))
def test_the_encoder_writes_the_one_encoding_of_a_value(name):
    value, expected = ENCODINGS[name]
    assert cbor.dumps(value).hex() == expected


@pytest.mark.parametrize("value", [{1: 2}, {b"k": 1}, {None: 1}, {("a",): 1}],
                         ids=["integer", "bytes", "null", "array"])
def test_the_encoder_refuses_a_map_key_that_is_not_text(value):
    with pytest.raises(TypeError):
        cbor.dumps(value)


@pytest.mark.parametrize("value", [Decimal("1E+2147483648"), Decimal("1E-2147483648"), Decimal("NaN"),
                                   Decimal("Infinity")], ids=["exponent above", "exponent below", "NaN",
                                                              "infinity"])
def test_the_encoder_refuses_a_decimal_the_encoding_cannot_hold(value):
    with pytest.raises(ValueError):
        cbor.dumps(value)


def test_a_float32_holds_the_value_a_java_float_holds_and_decodes_as_one():
    assert cbor.Float32(0.1) == 0.10000000149011612
    decoded = cbor.loads(bytes.fromhex("fa3fc00000"))
    assert isinstance(decoded, cbor.Float32) and decoded == 1.5
    assert type(cbor.loads(bytes.fromhex("fb3ff8000000000000"))) is float


def test_big_numbers_decode_into_exact_types_that_re_encode_to_the_same_bytes():
    # F2: an application reads Java's BigInteger and BigDecimal as int and Decimal.
    for hex_ in ("c249010000000000000000", "c349008000000000000001", "c482200f", "c4823a7ffffffe01",
                 "c48200c24e04ee2d6d415b85acef8100000001"):
        raw = bytes.fromhex(hex_)
        value = cbor.loads(raw)
        assert isinstance(value, (int, Decimal)) and cbor.dumps(value) == raw


# F3 over carriers: frames, space deltas, signed peer advertisements ---------------------------

FRAMES = _vectors("frame")


def _frame_decodes(raw: bytes) -> bool:
    """Whether a frame decodes and verifies, and its body decodes as its kind's record. This
    client never acts on a DIGEST (it counts one in ``ignored_kinds``), so it never decodes
    one; for the DIGEST vectors the check is the canonical order of the digests map that
    this client's own pulls now write (``wire.digest_body``)."""
    decoded = wire.decode_frame_detailed(raw)
    if decoded is None:
        return False
    env = decoded[0]
    if env["kind"] == "DIGEST":
        return cbor.is_canonical_map(cbor.loads(env["body"])["digests"])
    return wire.decode_body(env["kind"], env["body"]) is not None


@pytest.mark.parametrize("vector", FRAMES, ids=_ids(FRAMES))
def test_a_frame_decodes_exactly_when_the_encoding_accepts_it(vector):
    assert _frame_decodes(bytes.fromhex(vector["hex"])) == (vector["verdict"] == "accept")


DELTAS = _vectors("space-delta")


def _delta_verifies(raw: bytes) -> bool:
    """Whether a space delta decodes and each signature it carries verifies: the record and
    the state for a state delta, the proof for a claim delta."""
    from test_hlc_logical_limit import CapturingPeer
    delta = wire.decode_delta(raw)
    if delta is None:
        return False
    if delta["state"] is not None:
        state = delta["state"]
        return CapturingPeer()._verify_state(state, state["record"])
    return wire.verify_claim_proof(delta["claim"])


@pytest.mark.parametrize("vector", DELTAS, ids=_ids(DELTAS))
def test_a_space_delta_decodes_and_verifies_exactly_when_the_encoding_accepts_it(vector):
    assert _delta_verifies(bytes.fromhex(vector["hex"])) == (vector["verdict"] == "accept")


PEER_ADS = _vectors("signed-peer-ad")


@pytest.mark.parametrize("vector", PEER_ADS, ids=_ids(PEER_ADS))
def test_a_signed_peer_advertisement_decodes_exactly_when_the_encoding_accepts_it(vector):
    ad = wire.decode_signed_peer_ad(bytes.fromhex(vector["hex"]))
    assert (ad is not None) == (vector["verdict"] == "accept")


def test_a_bid_of_minus_zero_wins_over_a_bid_of_zero_as_javas_double_compare_orders_them():
    # Vector claim-20: Java's Double.compare puts -0.0 below 0.0, and the lowest bid wins.
    claim = wire.take_claim("e", "s", 1, "5:0:n", "p/w", 0.0, 10)
    minus = dict(claim, bid=-0.0)
    assert wire.claim_sort_key(minus) < wire.claim_sort_key(claim)
    a, b = {"claim": claim}, {"claim": minus}
    assert wire.merge_claims(a, b) is b and wire.merge_claims(b, a) is b


# What this client writes is what it reads -----------------------------------------------------

def test_a_digest_lists_its_streams_in_the_canonical_order():
    # Vector frame-28: a pull built "space:<name>" before "peers", which no strict receiver
    # decodes; frame-29 holds the same DIGEST in the RFC 8949 order.
    body = cbor.loads(wire.digest_body({"space:tasks": b"", "peers": b"", "credentials": b""}))
    assert list(body["digests"]) == ["peers", "credentials", "space:tasks"]


def test_a_bare_frame_writes_its_key_and_signature_null_as_java_writes_them():
    host = Identity.generate()
    env = wire.envelope("g", "PING", host.peer_id, f"5:0:{host.peer_id}", wire.ping_body(1))
    frame = wire.encode_bare_frame(env)
    assert cbor.loads(frame) == {"envelope": env, "senderPublicKey": None, "signature": None}
    assert wire.decode_frame_detailed(frame, attested=host.peer_id) == (env, "attested")


def test_a_frame_signed_over_an_unknown_envelope_field_does_not_decode():
    # Rule P1: the receiver re-encodes only the fields it knows, so an extra one never verifies.
    host = Identity.generate()
    env = dict(wire.envelope("g", "PING", host.peer_id, f"5:0:{host.peer_id}", wire.ping_body(1)), extra=1)
    assert wire.decode_frame(wire.encode_frame(env, host)) is None


# R5: an agent id's local name ---------------------------------------------------------------

@pytest.mark.parametrize("name", ["a/b", "a:b", ":", "/", ""], ids=["slash", "colon", "colon alone",
                                                                   "slash alone", "empty"])
def test_identity_agent_refuses_a_local_name_outside_javas_grammar(name):
    with pytest.raises(ValueError):
        Identity.generate().agent(name)


@pytest.mark.parametrize("text,expected", [("p/w", True), ("p/w-1.x", True), ("p/w:x", False), ("p/w/x", False),
                                           ("/w", False), ("p/", False), ("pw", False), (None, False)])
def test_the_agent_id_grammar_is_javas(text, expected):
    assert wire.is_agent_id(text) is expected


def test_a_record_whose_issuer_holds_a_colon_makes_its_delta_undecodable():
    from test_hlc_round_four import _counts, _receiver
    from test_hlc_logical_limit import T, _write
    host = Identity.generate()
    write = _write(host, T)
    record = dict(write["record"], issuer=write["record"]["issuer"] + ":x")
    record["sig"] = host.sign(cbor.dumps(wire.sign_view_of(record)))
    receiver, link, _ = _receiver(host)
    link.rumor(dict(write, record=record))
    assert receiver.states == {} and _counts(receiver) == {"deltasUndecodable": 1}


# R6: Java's two claim checks ------------------------------------------------------------------

def _entry(host: Identity, issued_ms: int, receiver_ms: int):
    """A write issued at ``issued_ms`` whose lease outlives the receiver's wall, as a receiver
    at ``receiver_ms`` holds it, and the link that delivers to that receiver."""
    from test_hlc_round_four import _receiver
    _, body = wire.entry_delta("tasks", "zPyHlcLogical", "T#v1", cbor.dumps({"x": 1}), host, "w",
                               receiver_ms - issued_ms + 600_000, now_ms=issued_ms)
    state = cbor.loads(cbor.loads(body)["payload"])["state"]
    receiver, link, _ = _receiver(host, receiver_ms)
    link.rumor(state)
    assert state["record"]["entryId"] in receiver.states
    return state["record"], receiver, link


def _claim_by(holder: Identity, record: dict, stamp_ms: int, expires_ms: int) -> dict:
    claim = wire.take_claim(record["entryId"], record["spaceId"], 1, f"{stamp_ms}:0:{holder.agent('t')}",
                            holder.agent("t"), 0.0, expires_ms)
    return wire.signed_claim(claim, holder)


def test_a_claim_that_predates_its_entry_by_more_than_the_drift_bound_never_folds():
    from test_hlc_logical_limit import DRIFT, T
    from test_hlc_round_four import _counts
    record, receiver, link = _entry(Identity.generate(), T, T)
    taker = Identity.generate()
    link.rumor(claim=(record["entryId"], _claim_by(taker, record, T - DRIFT - 1, T + 60_000)))
    assert receiver.claims == {} and _counts(receiver) == {}
    on_the_line = _claim_by(taker, record, T - DRIFT, T + 60_000)
    link.rumor(claim=(record["entryId"], on_the_line))
    assert receiver.claims[record["entryId"]] == on_the_line


def test_a_far_past_claim_contesting_another_holders_claim_never_folds():
    from test_hlc_logical_limit import DRIFT, T
    from test_hlc_round_four import _counts
    record, receiver, link = _entry(Identity.generate(), T - 2 * DRIFT, T)
    first, jumper = Identity.generate(), Identity.generate()
    held = _claim_by(first, record, T - DRIFT - 50, T + 60_000)
    link.rumor(claim=(record["entryId"], held))
    assert receiver.claims[record["entryId"]] == held
    # Older than the drift bound and Java's 200 ms settle window: a queue-jump.
    link.rumor(claim=(record["entryId"], _claim_by(jumper, record, T - DRIFT - 201, T + 60_000)))
    assert receiver.claims[record["entryId"]] == held and _counts(receiver) == {}
    # Inside the window it is an honest race, and its lower stamp wins it.
    racer = _claim_by(jumper, record, T - DRIFT - 199, T + 60_000)
    link.rumor(claim=(record["entryId"], racer))
    assert receiver.claims[record["entryId"]] == racer


# A founding carried in a beacon document ------------------------------------------------------

def test_a_beacon_founding_outside_the_record_rules_does_not_verify():
    # Owner rulings F1 and F3: the founding is a SignedGroupAdvertisement in the wire encoding,
    # so an extra field, or a period Java does not print (PT1.0S for PT1S), does not decode.
    import base64
    from agentspaces import beacon
    from agentspaces.identity import found_group
    signed = found_group(Identity.generate(), "fleet", "OPEN", "LEASE_RACE", 3, "PT1S",
                         "2026-10-14T00:00:00Z", "PT8760H")
    group_id = signed["advertisement"]["group"]

    def group(founding: dict) -> dict:
        return {"name": "fleet", "id": group_id, "founding": base64.b64encode(cbor.dumps(founding)).decode()}
    assert beacon.verified_group_id(group(signed)) == group_id
    gossip = dict(signed["advertisement"]["gossip"], period="PT1.0S")
    for hostile in (dict(signed, extra=1), dict(signed, advertisement=dict(signed["advertisement"], gossip=gossip))):
        with pytest.raises(ValueError):
            beacon.verified_group_id(group(hostile))


# A payload outside the encoding: the entry replicates, and every read skips its value ----------

def test_a_read_skips_an_entry_whose_payload_is_outside_the_encoding():
    # Section 3.1 of the definition: the record signature covers the payload's bytes, so the
    # entry still replicates, and no read hands its value to an application. The payload is
    # what Java wrote for BigInteger.ONE before the round six encoder change (vector doc-01).
    from agentspaces.space import Space, Template
    from test_hlc_round_four import _receiver
    from test_hlc_logical_limit import T
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    for payload in (bytes.fromhex("bf616ec24101ff"), cbor.dumps({"n": 1})):
        _, body = wire.entry_delta("tasks", "zPyHlcLogical", "T#v1", payload, host, "w", 60_000, now_ms=T)
        link.rumor(cbor.loads(cbor.loads(body)["payload"])["state"])
    assert len(receiver.states) == 2
    assert receiver.find("T#v1") == [{"n": 1}]
    assert [entry.value for entry in Space(receiver, "tasks").entries(Template("T#v1"))] == [{"n": 1}]


def test_the_advertisements_this_client_publishes_obey_the_record_rules():
    # A peer caches its own advertisement through the same rule as a received one, so one
    # that broke the record rules would never reach its own cache or anyone else's.
    from agentspaces import records
    from test_hlc_round_four import _receiver
    host = Identity.generate()
    receiver, _, _ = _receiver(host)
    agent = receiver.identity.subordinate("w", "2027-01-15T08:00:00Z", "PT24H")
    card = wire.agent_card(receiver.group, receiver.identity, "w", "2027-01-15T08:00:00.120Z", "PT10M",
                           "does work", ["g"], ["T#v1"], ["R#v1"], {"zeta": "1", "a": "2"}, {"tasks": "T#v1"},
                           agent_public_raw=agent.certificate["agentPublicKey"],
                           actions=[wire.card_action("act", "acts", ["T#v1"], ["R#v1"], "TAKE", space="tasks")],
                           agent_certificate=agent.certificate,
                           ui=wire.ui_declaration([wire.ui_component("c", "cat", "Card", "T#v1")]))
    peer_ad = wire.peer_advertisement(receiver.group, receiver.identity, "2027-01-15T08:00:00Z",
                                      resource_hints={"wire.batch": "1", "aspace:join": "x"})
    assert records.conforms(card, "AgentCard") and records.conforms(peer_ad, "PeerAdvertisement")
    receiver.publish_ad("AgentCard", card)
    receiver.publish_ad("PeerAdvertisement", peer_ad)
    assert {entry["type"] for entry in receiver.ads.values()} == {"AgentCard", "PeerAdvertisement"}


# The adversary pass of HLC round six, 2026-11-08 ----------------------------------------------

def test_a_definite_text_past_3996_utf16_units_does_not_decode():
    # Rule S6: Jackson writes such a text in its chunks, so the definite form is no encoding of
    # it, in an application value as in a protocol field.
    text = "a" * 3997
    with pytest.raises(ValueError):
        cbor.loads(b"\x79" + len(text).to_bytes(2, "big") + text.encode())
    assert cbor.loads(cbor.dumps(text)) == text


def test_a_signed_map_field_out_of_the_rfc_8949_order_does_not_decode():
    # Rule P2: the issuer signed resourceHints with the longer key first, which no Java peer
    # writes, so the advertisement does not decode though its signature holds.
    host = Identity.generate()
    ad = wire.peer_advertisement("g", host, "2027-01-15T08:00:00Z", resource_hints={"wire.batch": "1"})
    ad["resourceHints"] = {"wire.batch": "1", "a": "2"}
    assert wire.decode_signed_peer_ad(wire.signed_peer_ad(ad, host)) is None
    ad["resourceHints"] = {"a": "2", "wire.batch": "1"}
    assert wire.decode_signed_peer_ad(wire.signed_peer_ad(ad, host)) == ad


def test_a_ping_whose_body_breaks_its_record_counts_as_malformed_and_gets_no_ack():
    # Rules P1 and F3: the sender signed a Ping with a field the record does not name; the frame
    # is undecodable, so the receiver answers nothing and counts it.
    from test_hlc_round_four import _receiver
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    receiver._receive(link.frame("PING", cbor.dumps({"nonce": 7, "extra": 1})))
    assert receiver.malformed_frames == 1 and receiver.sent == []
    receiver._receive(link.frame("PING", wire.ping_body(7)))
    assert receiver.malformed_frames == 1 and [kind for kind, _, _ in receiver.sent] == ["ACK"]


def _envelope_without(field: str, host: Identity, receiver) -> bytes:
    from test_hlc_logical_limit import GROUP
    env = wire.envelope(GROUP, "PING", host.peer_id, f"{receiver._now_ms()}:1:{host.peer_id}", wire.ping_body(7),
                        receiver.identity.peer_id)
    env[field] = None
    return wire.encode_frame(env, host)


@pytest.mark.parametrize("field", ["group", "kind", "from", "stamp", "body"])
def test_a_signed_envelope_with_a_null_java_requires_counts_as_malformed(field):
    # Java's Envelope refuses a null group, kind, sender, stamp or body as it decodes, so its
    # codec drops such a frame as undecodable whoever signed it (HLC round six, 2026-11-08,
    # reference rule); this client counts it as malformed and acts on nothing in it.
    from test_hlc_round_four import _receiver
    host = Identity.generate()
    receiver, _, _ = _receiver(host)
    receiver._receive(_envelope_without(field, host, receiver))
    assert receiver.malformed_frames == 1 and receiver.sent == [] and receiver.members == {}


def _record_change(**fields):
    return lambda state: dict(state, record=dict(state["record"], **fields))


def _lease(**fields):
    return lambda state: dict(state, leaseValue=dict(state["leaseValue"], **fields))


def _record_lease(**fields):
    return lambda state: dict(state, record=dict(state["record"], lease=dict(state["record"]["lease"], **fields)))


def _certificate(**fields):
    return lambda state: dict(state, agentCertificate=dict(state["agentCertificate"], **fields))


# Each breaks an invariant of a Java record's constructor (EntryRecord, LeaseInfo, Dot,
# AgentCertificate), so Java's codec refuses the delta before any signature check.
JAVA_RECORD_INVARIANTS = {
    "record type null": _record_change(type=None),
    "record space null": _record_change(spaceId=None),
    "record entry null": _record_change(entryId=None),
    "record issuer null": _record_change(issuer=None),
    "record lease null": _record_change(lease=None),
    "record tags null": _record_change(tags=None),
    "record payload and payloadRef both null": _record_change(payload=None),
    "record payload and payloadRef both set": _record_change(payloadRef="z" + "a" * 52),
    "record payload past 64 KiB": _record_change(payload=b"\x00" * (64 * 1024 + 1)),
    "record keyEpoch 0": _record_change(keyEpoch=0),
    "record lease expiry 0": _record_lease(expiresAtMillis=0),
    "lease holder null": _lease(holder=None),
    "lease kind null": _lease(kind=None),
    "lease expiry 0": _lease(expiresAtMillis=0),
    "lease expiry negative": _lease(expiresAtMillis=-1),
    "dot counter 0": lambda state: dict(state, adds=[dict(state["adds"][0], counter=0)]),
    "dot replica null": lambda state: dict(state, adds=[dict(state["adds"][0], replica=None)]),
    "certificate ttl zero": _certificate(ttl="PT0S"),
    "certificate agent null": _certificate(agent=None),
    "certificate issued null": _certificate(issued=None),
    "certificate encryption key of 31 bytes": _certificate(encryptionPublicKey=b"\x01" * 31),
}


@pytest.mark.parametrize("name", sorted(JAVA_RECORD_INVARIANTS))
def test_a_state_breaking_a_java_record_invariant_is_undecodable(name):
    # HLC round six, 2026-11-08 (reference rule, owner ruling F1): what Java's record refuses to
    # hold, this client does not decode either; it counts the delta, by gossip and by pull, and
    # merges nothing, so its replica holds what a Java replica holds.
    from test_hlc_round_four import _counts, _receiver
    from test_hlc_logical_limit import T, _write
    host = Identity.generate()
    state = _write(host, T, agent=host.subordinate("w", "2027-01-15T08:00:00Z", "PT24H"))
    receiver, link, _ = _receiver(host)
    hostile = JAVA_RECORD_INVARIANTS[name](state)
    link.rumor(hostile)
    link.pull_resp([hostile], {})
    assert receiver.states == {} and _counts(receiver) == {"deltasUndecodable": 2}
    link.rumor(state)
    assert list(receiver.states) == [state["record"]["entryId"]]


@pytest.mark.parametrize("field", ["id", "issuer", "group", "issued", "ttl"])
def test_an_advertisement_with_a_null_java_requires_is_refused_and_the_rest_of_the_pull_folds(field):
    # Every Java advertisement record refuses a null id, issuer, group, issue instant or period
    # as it decodes (HLC round six, 2026-11-08, reference rule): such an ad decodes nowhere, and
    # the ads after it in the same anti-entropy delta still reach the cache.
    from test_hlc_round_four import _receiver
    host, other = Identity.generate(), Identity.generate()
    receiver, link, _ = _receiver(host)
    hostile = dict(wire.peer_advertisement(receiver.group, host, "2027-01-15T08:00:00Z"), **{field: None})
    honest = wire.peer_advertisement(receiver.group, other, "2027-01-15T08:00:00Z")
    ads = [wire.stored_ad("PeerAdvertisement", ad, signer) for ad, signer in ((hostile, host), (honest, other))]
    receiver._receive(link.frame("PULL_RESP", cbor.dumps({"deltas": {"ads": cbor.dumps({"ads": ads})}})))
    assert receiver.malformed_frames == 0 and list(receiver.ads) == [honest["id"]]


@pytest.mark.parametrize("field", ["id", "issuer", "group", "issued", "ttl"])
def test_a_revocation_with_a_null_java_requires_is_refused(field):
    from agentspaces import revocation
    from test_hlc_round_four import _receiver
    from test_hlc_logical_limit import T
    founder = Identity.generate()
    receiver, _, _ = _receiver(founder)
    ad = {"id": "r", "issuer": founder.peer_id, "group": receiver.group, "issued": "2027-01-15T08:00:00Z",
          "ttl": "PT24H", "revoked": Identity.generate().peer_id, "reason": "retired", "successor": None}
    ad[field] = None
    ad_bytes = cbor.dumps(ad)
    signed = cbor.dumps({"adBytes": ad_bytes, "publicKey": founder.public_raw, "signature": founder.sign(ad_bytes)})
    assert receiver.revocations.accept(revocation.PEER_STREAM, signed, T) is False
