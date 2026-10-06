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

"""Cross-language golden tests: the Java codec produced every expected byte
string in golden.json (tools/golden/GoldenVectors.java regenerates it), and
these tests prove the Python encoder reproduces each one exactly. Ed25519 is
deterministic (RFC 8032), so even the signatures must match byte for byte."""

import json
import pathlib
import struct

import pytest

from agentspaces import cbor, vote, wire
from agentspaces.identity import (
    Identity,
    certificate_body,
    derive_id,
    group_id_from_founding,
    parse_duration_millis,
    parse_instant_millis,
    space_id_local,
    verify_agent_certificate,
)
from agentspaces.peer import Peer
from agentspaces.identity import group_id_from_founding_document

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent / "golden.json").read_text())


def _hex(name: str) -> bytes:
    return bytes.fromhex(GOLDEN[name])


def _identity() -> Identity:
    return Identity.from_pkcs8(_hex("private_key_pkcs8"))


def test_identity_and_derivations_match_java():
    identity = _identity()
    assert identity.public_raw == _hex("public_key_raw")
    assert identity.peer_id == GOLDEN["peer_id"]
    assert derive_id(_hex("public_key_raw")) == GOLDEN["peer_id"]
    assert group_id_from_founding(b"research-fleet-demo-v1") == GOLDEN["group_id"]
    assert space_id_local(GOLDEN["group_id"] + "/tasks") == GOLDEN["space_id"]


def test_ping_envelope_bytes_and_signature_match_java():
    identity = _identity()
    assert wire.ping_body(42) == _hex("ping_body_cbor")
    env = wire.envelope(GOLDEN["group_id"], "PING", GOLDEN["peer_id"],
                        GOLDEN["hlc_encoded"], _hex("ping_body_cbor"),
                        to=GOLDEN["peer_id"])
    assert cbor.dumps(env) == _hex("ping_envelope_cbor")
    # RFC 8032 signing is deterministic: same key, same bytes, same signature.
    assert identity.sign(cbor.dumps(env)) == _hex("ping_envelope_signature")
    assert wire.encode_frame(env, identity) == _hex("ping_frame_cbor")


def test_python_verifies_and_reencodes_java_frames():
    env = wire.decode_frame(_hex("ping_frame_cbor"))
    assert env is not None
    assert env["kind"] == "PING"
    assert env["from"] == GOLDEN["peer_id"]
    # A tampered frame is rejected.
    tampered = bytearray(_hex("ping_frame_cbor"))
    tampered[-1] ^= 0x01
    assert wire.decode_frame(bytes(tampered)) is None


def test_membership_intro_matches_java():
    identity = _identity()
    ad = wire.peer_advertisement(GOLDEN["group_id"], identity,
                                 "2026-01-01T00:00:00Z")
    ad["endpoints"] = [{"transport": "tcp", "address": "127.0.0.1:7460",
                        "priority": 0}]
    assert cbor.dumps(ad) == _hex("peer_ad_cbor")
    assert wire.signed_peer_ad(ad, identity) == _hex("signed_peer_ad_cbor")
    item_id = f"peer:{identity.peer_id}:1767225600000"
    assert wire.rumor_body("peers", item_id, 6,
                           _hex("signed_peer_ad_cbor")) \
        == _hex("intro_rumor_body_cbor")


def test_space_write_matches_java():
    identity = _identity()
    payload = cbor.dumps({"topic": "golden vectors", "priority": 3})
    assert payload == _hex("task_payload_cbor")

    view = wire.sign_view("11111111-2222-3333-4444-555555555555",
                          GOLDEN["space_id"], "GoldenVectors$ResearchTask#v1",
                          payload, identity.agent("python"),
                          GOLDEN["hlc_encoded"])
    assert cbor.dumps(view) == _hex("sign_view_cbor")
    assert identity.sign(cbor.dumps(view)) == _hex("record_signature")

    record = {
        "entryId": "11111111-2222-3333-4444-555555555555",
        "spaceId": GOLDEN["space_id"],
        "type": "GoldenVectors$ResearchTask#v1",
        "payload": payload, "payloadRef": None,
        "issuer": identity.agent("python"),
        "issued": GOLDEN["hlc_encoded"],
        "lease": {"holder": identity.agent("python"),
                  "expiresAtMillis": 1735693200000, "kind": "WRITE"},
        "tags": {}, "sig": _hex("record_signature"),
    }
    lease_value = {"holder": identity.agent("python"),
                   "expiresAtMillis": 1735693200000, "kind": "WRITE"}
    adds = [{"replica": identity.peer_id, "counter": 1}]
    # The state signature the actor produces (SPEC §11a).
    state_view = wire.state_sign_view(GOLDEN["space_id"],
                                      "11111111-2222-3333-4444-555555555555",
                                      adds, [], GOLDEN["hlc_encoded"], lease_value, False)
    assert cbor.dumps(state_view) == _hex("state_sign_view_cbor")
    state_sig = identity.sign(cbor.dumps(state_view))
    assert state_sig == _hex("state_signature")

    dto = {
        "record": record, "issuerPublicKey": identity.public_raw,
        "adds": adds, "removes": [], "leaseStamp": GOLDEN["hlc_encoded"],
        "leaseValue": lease_value, "completed": False, "stateSig": state_sig,
    }
    assert cbor.dumps(dto) == _hex("entry_state_dto_cbor")
    assert cbor.dumps({"state": dto, "claimEntry": None, "claim": None}) \
        == _hex("delta_cbor")


def test_subordinate_agent_certificate_and_record_match_java():
    # SPEC §4.2 / §11a.3, TECH-SPEC §7.2 (QA4 A4-7 phase 1): the peer certifies
    # an agent key; the agent key signs the record; the DTO carries both.
    identity = _identity()
    issued = GOLDEN["certificate_verify_at"]
    agent = identity.subordinate("python", issued, "PT24H",
                                 key=Identity.from_pkcs8(_hex("agent_private_key_pkcs8")))
    assert agent.agent_id == identity.agent("python")
    assert agent.public_raw == _hex("agent_public_key_raw")
    assert cbor.dumps(certificate_body(agent.certificate)) \
        == _hex("agent_certificate_unsigned_cbor")
    assert agent.certificate["peerSignature"] == _hex("agent_certificate_signature")
    assert cbor.dumps(agent.certificate) == _hex("agent_certificate_cbor")
    now_ms = parse_instant_millis(issued)
    assert verify_agent_certificate(cbor.loads(_hex("agent_certificate_cbor")),
                                    identity.public_raw, identity.agent("python"), now_ms)
    # Expiry is inclusive: issued + ttl is the first refused instant.
    assert verify_agent_certificate(agent.certificate, identity.public_raw,
                                    identity.agent("python"),
                                    now_ms + parse_duration_millis("PT24H") - 1)
    assert not verify_agent_certificate(agent.certificate, identity.public_raw,
                                        identity.agent("python"),
                                        now_ms + parse_duration_millis("PT24H"))

    view = _hex("sign_view_cbor")
    sig = agent.sign(view)
    assert sig == _hex("record_signature_agent_key")
    assert Identity.verify(agent.public_raw, view, sig)
    assert not Identity.verify(identity.public_raw, view, sig)  # not the peer's

    lease_value = {"holder": identity.agent("python"),
                   "expiresAtMillis": 1735693200000, "kind": "WRITE"}
    record = {
        "entryId": "11111111-2222-3333-4444-555555555555",
        "spaceId": GOLDEN["space_id"],
        "type": "GoldenVectors$ResearchTask#v1",
        "payload": _hex("task_payload_cbor"), "payloadRef": None,
        "issuer": identity.agent("python"),
        "issued": GOLDEN["hlc_encoded"],
        "lease": lease_value, "tags": {}, "sig": sig,
    }
    dto = {
        "record": record, "issuerPublicKey": identity.public_raw,
        "adds": [{"replica": identity.peer_id, "counter": 1}], "removes": [],
        "leaseStamp": GOLDEN["hlc_encoded"], "leaseValue": lease_value,
        "completed": False, "stateSig": _hex("state_signature"),
        "agentCertificate": agent.certificate,
    }
    assert cbor.dumps(dto) == _hex("entry_state_with_certificate_cbor")
    assert cbor.dumps({"state": dto, "claimEntry": None, "claim": None}) \
        == _hex("delta_with_certificate_cbor")
    assert wire.verify_record(record, identity.public_raw, agent.certificate, now_ms)

    # SPEC §11a.4 v0.1.13 (A6): that state is peer-signed on an agent-attested
    # entry, so a peer refuses it; the agent-signed state (the agent signs its
    # own transition, naming itself and the signing time) is what lands.
    peer = Peer(identity, GOLDEN["group_id"], clock=lambda: now_ms / 1000)
    peer._fold(cbor.loads(_hex("delta_with_certificate_cbor"))["state"])
    assert peer.states == {}
    signer, signed_at = identity.agent("python"), GOLDEN["hlc_encoded"]
    state_view = wire.state_sign_view(record["spaceId"], record["entryId"], dto["adds"], [],
                                      signed_at, lease_value, False, signer, signed_at)
    assert cbor.dumps(state_view) == _hex("state_sign_view_agent_cbor")
    agent_state_sig = agent.sign(cbor.dumps(state_view))
    assert agent_state_sig == _hex("state_signature_agent_key")
    agent_dto = {**{k: v for k, v in dto.items() if k != "agentCertificate"},
                 "stateSig": agent_state_sig, "agentCertificate": agent.certificate,
                 "stateCertificate": agent.certificate, "signer": signer, "signedAt": signed_at}
    assert cbor.dumps(agent_dto) == _hex("entry_state_agent_signed_cbor")
    assert cbor.dumps({"state": agent_dto, "claimEntry": None, "claim": None}) \
        == _hex("delta_agent_signed_cbor")
    peer._fold(cbor.loads(_hex("delta_agent_signed_cbor"))["state"])
    peer._fold(cbor.loads(_hex("delta_cbor"))["state"])
    assert set(peer.states) == {"11111111-2222-3333-4444-555555555555"}


def test_three_names_from_one_peer_tally_as_one_voter():
    # SPEC §8 QUORUM, QA4 A4-7 phase 2: the counted identity follows the
    # authorizer's granularity. Three peer-signed ballots under three names from
    # the golden peer are one voter per peer, and nobody per agent.
    identity = _identity()
    peer = Peer(identity, GOLDEN["group_id"],
                clock=lambda: parse_instant_millis(GOLDEN["certificate_verify_at"]) / 1000)
    for i in (1, 2, 3):
        peer._fold(cbor.loads(_hex(f"vote_three_names_one_peer_delta_{i}"))["state"])
    assert len(peer.states) == 3
    proposal = GOLDEN["vote_three_names_one_peer_proposal"]
    assert vote.tally(peer.states, proposal, ["approve", "reject"]) == {"approve": 1, "reject": 0}
    assert vote.tally(peer.states, proposal, ["approve", "reject"], vote.AGENT) \
        == {"approve": 0, "reject": 0}
    # A permits() answer narrows further; a forged voter field never counts.
    assert vote.tally(peer.states, proposal, permits=lambda agent: False) == {}
    forged = dict(peer.states)
    first = next(iter(forged))
    forged[first] = {**forged[first], "record": {**forged[first]["record"],
                                                 "issuer": identity.agent("someone-else")}}
    assert vote.tally(forged, proposal)["approve"] == 1  # the other two still make one peer


def test_digest_body_matches_java():
    assert wire.digest_body({"peers": b"x"}) == _hex("digest_body_cbor")


def test_decoder_round_trips_every_golden_vector():
    # Deltas too: the adversarial ``*_delta`` vectors are well-formed CBOR whose
    # content (not encoding) is hostile, so they round-trip like the rest.
    names = [name for name in GOLDEN if name.endswith(("_cbor", "_delta"))]
    assert len(names) >= 35, "the v0.1.10 vectors are present"
    for name in names:
        if name == "adv_deep_nesting_cbor":
            continue  # a hostile input proven refused in test_adversarial.py
        raw = bytes.fromhex(GOLDEN[name])
        decoded = cbor.loads(raw)
        assert decoded is not None
        # Canonical form is a fixed point: re-encoding reproduces Java's
        # exact bytes for every vector (SPEC v0.1.8, definite-length arrays),
        # including the adversarial GROUP_ADs (which decode but never verify),
        # negative int64 roster tokens, and float64 histogram buckets.
        assert cbor.dumps(decoded) == raw, name


def test_wire_version_matches_java():
    assert wire.WIRE_VERSION == GOLDEN["wire_version"] == 2
    assert wire.envelope("g", "PING", "p", "1:0:p", b"")["ver"] == 2


# ------------------------------------------------------- advertisements (§6.1)

def test_agent_card_and_stored_ad_match_java():
    identity = _identity()
    task = "GoldenVectors$ResearchTask#v1"
    card = {
        "id": f"aspace://{GOLDEN['group_id']}/agent/{identity.peer_id}/python",
        "issuer": identity.peer_id, "group": GOLDEN["group_id"],
        "issued": "2026-01-01T00:00:00Z", "ttl": "PT15M",
        "agent": identity.agent("python"),
        "description": "Researches a topic and writes a finding",
        "goals": ["research"], "consumes": [task],
        "produces": ["GoldenVectors$Finding#v1"],
        "costHints": {"tokens": "low"}, "spaceBindings": {task: "tasks"},
    }
    assert cbor.dumps(card) == _hex("agent_card_cbor")
    # QA4 A4-7 phase 3: an attested agent's card appends its own public key; the
    # field is absent, not null, on a peer-signed agent's card, so the bytes above hold.
    keyed = {**card, "agentPublicKey": _hex("agent_public_key_raw")}
    assert cbor.dumps(keyed) == _hex("agent_card_with_key_cbor")
    assert identity.sign(cbor.dumps(keyed)) == _hex("agent_card_with_key_signature")
    signature = identity.sign(cbor.dumps(card))
    assert signature == _hex("agent_card_signature")
    # AdCache.StoredAd: the `ads`-stream / QUERY_HIT wire form.
    stored = {"adType": "AgentCard", "adBytes": cbor.dumps(card),
              "publicKey": identity.public_raw, "signature": signature}
    assert cbor.dumps(stored) == _hex("signed_agent_card_cbor")
    assert derive_id(stored["publicKey"]) == card["issuer"]


def test_space_advertisement_and_space_id_match_java():
    space_ad = {
        "id": f"aspace://{GOLDEN['group_id']}/tasks",
        "issuer": GOLDEN["peer_id"], "group": GOLDEN["group_id"],
        "issued": "2026-01-01T00:00:00Z", "ttl": "PT15M",
        "spaceName": "tasks", "schemaHints": ["GoldenVectors$ResearchTask#v1"],
        "strategy": "LEASE_RACE", "admission": "ALLOWLIST",
        "replication": "TAG_SHARDED",
    }
    assert cbor.dumps(space_ad) == _hex("space_ad_cbor")
    # SpaceId.fromFounding(space_ad_cbor): a SpaceID is the hash of its
    # founding document (SPEC §4.4), the same derivation as a GroupID.
    assert derive_id(cbor.dumps(space_ad)) == GOLDEN["space_ad_space_id"]
    assert group_id_from_founding_document(_hex("space_ad_cbor")) \
        == GOLDEN["space_ad_space_id"]


# ------------------------------------------------- capability payloads (§8)

def test_aggregate_frames_match_java():
    assert cbor.dumps(wire.aggregate_frame(
        share={"epochId": "golden", "value": 4.5, "weight": 0.5})) \
        == _hex("aggregate_share_frame_cbor")
    assert cbor.dumps(wire.aggregate_frame(
        extremum={"epochId": "golden", "max": True, "value": 4.5})) \
        == _hex("aggregate_extremum_frame_cbor")
    assert cbor.dumps(wire.aggregate_frame(
        histogram={"epochId": "golden", "lo": 0.0, "hi": 10.0,
                   "buckets": [1.0, 0.0, 2.0, 0.5]})) \
        == _hex("aggregate_histogram_frame_cbor")
    token = wire.aggregate_roster_token(GOLDEN["peer_id"])
    assert token == int(GOLDEN["aggregate_roster_token"]) == -7559124713570419099
    assert cbor.dumps(wire.aggregate_frame(
        roster={"epochId": "golden", "members": [token]})) \
        == _hex("aggregate_roster_frame_cbor")
    # A negative int64 is CBOR major type 1 over 8 bytes, never an unsigned
    # two's-complement value.
    assert bytes.fromhex("3b68e767e0853dc19a") in _hex("aggregate_roster_frame_cbor")
    assert cbor.loads(_hex("aggregate_roster_frame_cbor"))["roster"]["members"] == [token]
    with pytest.raises(ValueError):
        wire.aggregate_frame()


def test_gossip_learn_exchanges_match_java():
    encoding = _hex("learn_model_encoding")
    # WeightAveraging.encode: big-endian IEEE-754 doubles, no CBOR.
    assert encoding == struct.pack(">3d", 1.0, 2.5, -3.0)
    assert wire.learn_content_id(encoding) == GOLDEN["learn_content_id"] \
        == "zJ4br3ZyuAyY2TZosJ1fKJurayY1eRqJdUAFacKQta9Dh"
    assert cbor.dumps(wire.learn_exchange("golden-model", 7, "OFFER", 2,
                                          inline=encoding)) \
        == _hex("learn_exchange_offer_cbor")
    assert cbor.dumps(wire.learn_exchange("golden-model", 7, "ACCEPT", 3,
                                          inline=encoding)) \
        == _hex("learn_exchange_accept_cbor")
    assert cbor.dumps(wire.learn_exchange("golden-model", 7, "BUSY", 0)) \
        == _hex("learn_exchange_busy_cbor")
    busy = cbor.loads(_hex("learn_exchange_busy_cbor"))
    assert busy["inline"] is None and busy["cid"] is None and busy["round"] == 0


def test_take_claims_match_java():
    identity = _identity()
    claim = wire.take_claim("11111111-2222-3333-4444-555555555555",
                            GOLDEN["space_id"], 1, GOLDEN["hlc_encoded"],
                            identity.agent("python"), 0.0, 1735693200000)
    assert cbor.dumps(claim) == _hex("take_claim_cbor")
    assert identity.sign(cbor.dumps(claim)) == _hex("take_claim_signature")
    signed = wire.signed_claim(claim, identity)
    assert wire.claim_delta("11111111-2222-3333-4444-555555555555", signed) \
        == _hex("claim_delta_cbor")


def test_agent_signed_claims_match_java():
    # QA4 A4-7 phase 3: a claim taken through a subordinate identity is signed by
    # the agent key, holderKey stays the peer key, and the certificate rides along.
    identity = _identity()
    agent = identity.subordinate("python", GOLDEN["certificate_verify_at"], "PT24H",
                                 key=Identity.from_pkcs8(_hex("agent_private_key_pkcs8")))
    claim = cbor.loads(_hex("take_claim_cbor"))
    assert agent.sign(_hex("take_claim_cbor")) == _hex("take_claim_agent_signature")
    signed = wire.signed_claim(claim, identity, agent)
    assert cbor.dumps(wire.signed_claim(claim, identity)) == cbor.dumps(
        cbor.loads(_hex("claim_delta_cbor"))["claim"])  # no agent: unchanged
    assert wire.claim_delta("11111111-2222-3333-4444-555555555555", signed) \
        == _hex("claim_delta_with_certificate_cbor")
    now_ms = parse_instant_millis(GOLDEN["certificate_verify_at"])
    assert wire.verify_claim_proof(signed, now_ms)
    assert not wire.verify_claim_proof({**signed, "holderCertificate": None} | {
        "signature": signed["signature"]}, now_ms)  # agent signature without its certificate


def test_claim_lattice_order_matches_the_java_merge():
    e, s = "entry-1", "space-1"
    base = wire.take_claim(e, s, 1, "100:0:node-a", "peer/a", 0.0, 1000)
    higher_epoch = wire.take_claim(e, s, 2, "200:0:node-b", "peer/b", 0.0, 1000)
    cheaper = wire.take_claim(e, s, 1, "200:0:node-b", "peer/b", -1.0, 1000)
    earlier = wire.take_claim(e, s, 1, "50:0:node-b", "peer/b", 0.0, 1000)

    def winner(a, b):
        return wire.merge_claims({"claim": a}, {"claim": b})["claim"]

    assert winner(base, higher_epoch) == higher_epoch  # epoch descending
    assert winner(base, cheaper) == cheaper            # bid ascending
    assert winner(base, earlier) == earlier            # stamp ascending
    assert winner(base, base) == base


# ----------------------------------------------------------------- v0.1.13

def test_a_record_sealed_under_epoch_two_names_its_epoch():
    # SPEC §11a.1/§11a.3 v0.1.13: keyEpoch is appended to the sign view and the
    # record only from epoch 1; the AAD appends the epoch.
    identity = _identity()
    record = cbor.loads(_hex("entry_record_key_epoch_cbor"))
    assert record["keyEpoch"] == 2
    view = wire.sign_view(record["entryId"], record["spaceId"], record["type"],
                          record["payload"], record["issuer"], record["issued"], 2)
    assert cbor.dumps(view) == _hex("sign_view_key_epoch_cbor")
    assert cbor.dumps(wire.sign_view_of(record)) == _hex("sign_view_key_epoch_cbor")
    assert wire.verify_record(record, identity.public_raw, None, 0)
    assert GOLDEN["content_key_aad_epoch_2"] == \
        f"{GOLDEN['space_id']}|{record['entryId']}|2"
    # A record without an epoch signs the v0.1.12 view, byte for byte.
    plain = cbor.loads(_hex("entry_state_dto_cbor"))["record"]
    assert cbor.dumps(wire.sign_view_of(plain)) == _hex("sign_view_cbor")


def test_a_certificate_can_certify_the_agents_encryption_key():
    # SPEC §11a.2a v0.1.13: encryptionPublicKey is appended to the body.
    identity = _identity()
    certificate = cbor.loads(_hex("agent_certificate_with_encryption_cbor"))
    assert certificate["encryptionPublicKey"] == _hex("agent_encryption_public_key_raw")
    assert cbor.dumps(certificate_body(certificate)) \
        == _hex("agent_certificate_with_encryption_unsigned_cbor")
    at = parse_instant_millis(GOLDEN["certificate_verify_at"])
    assert verify_agent_certificate(certificate, identity.public_raw,
                                    identity.agent("python"), at)
    assert cbor.dumps(certificate_body(cbor.loads(_hex("agent_certificate_cbor")))) \
        == _hex("agent_certificate_unsigned_cbor")


def test_credential_revocations_from_the_agents_own_peer_apply_the_freeze_rule():
    # SPEC §5.6 v0.1.13: the golden peer revokes its own agent (retired, an
    # hour before issue) and the agent's key (key-compromise).
    from agentspaces import revocation
    identity = _identity()
    registry = revocation.Registry(lambda: None, lambda: GOLDEN["group_id"])
    now = parse_instant_millis("2026-06-01T00:00:00Z")
    for kind in ("agent", "agent_key"):
        assert registry.accept(revocation.CREDENTIAL_STREAM,
                               _hex(f"signed_credential_revocation_{kind}_cbor"), now), kind
    issued = parse_instant_millis("2026-01-01T00:00:00Z")
    agent = identity.agent("python")
    assert not registry.refuses(agent, None, issued - 90 * 60 * 1000)
    assert registry.refuses(agent, None, issued - 30 * 60 * 1000)
    assert registry.refuses(agent, None, None)
    assert registry.refuses(agent, _hex("agent_public_key_raw"), 0)
    assert not registry.refuses(identity.agent("sibling"), None, issued)
    # A stranger cannot revoke the agent; the same bytes re-signed by another key fail.
    stranger = Identity.generate()
    ad = _hex("credential_revocation_agent_cbor")
    fresh = revocation.Registry(lambda: None, lambda: GOLDEN["group_id"])
    assert not fresh.accept_signed(revocation.CREDENTIAL_STREAM,
                                   {"adBytes": ad, "publicKey": stranger.public_raw,
                                    "signature": stranger.sign(ad)}, now)


def test_a_card_declares_its_actions_and_carries_its_certificate():
    # SPEC §6.1 v0.1.13: actions and agentCertificate append after agentPublicKey.
    identity = _identity()
    task = "GoldenVectors$ResearchTask#v1"
    certificate = cbor.loads(_hex("agent_certificate_cbor"))
    card = wire.agent_card(GOLDEN["group_id"], identity, "python",
                           GOLDEN["certificate_verify_at"], "PT15M",
                           "Researches a topic and writes a finding", ["research"], [task],
                           ["GoldenVectors$Finding#v1"], {"tokens": "low"}, {task: "tasks"},
                           agent_public_raw=_hex("agent_public_key_raw"),
                           actions=[wire.card_action("research",
                                                     "Researches a topic and writes a finding",
                                                     [task], ["GoldenVectors$Finding#v1"],
                                                     "take", "tasks")],
                           agent_certificate=certificate)
    assert cbor.dumps(card) == _hex("agent_card_with_actions_cbor")
    assert identity.sign(cbor.dumps(card)) == _hex("agent_card_with_actions_signature")


def test_epoch_commitment_and_wrap_binding_reencode():
    for name in ("epoch_commitment_cbor", "wrap_binding_v2_cbor"):
        raw = _hex(name)
        assert cbor.dumps(cbor.loads(raw)) == raw
    identity = _identity()
    assert Identity.verify(identity.public_raw, _hex("epoch_commitment_cbor"),
                           _hex("epoch_proof_signature"))



# ------------------------------------------- v0.1.13 transitions (audit item 10)

ENTRY = "11111111-2222-3333-4444-555555555555"


def _agent():
    return _identity().subordinate("python", GOLDEN["certificate_verify_at"], "PT24H",
                                   key=Identity.from_pkcs8(_hex("agent_private_key_pkcs8")))


def _stamp(offset_ms: int, logical: int = 0) -> str:
    return f"{wire.hlc_physical(GOLDEN['hlc_encoded']) + offset_ms}:{logical}:{GOLDEN['peer_id']}"


def _peer_at(iso_or_ms, founder=None) -> Peer:
    now_ms = parse_instant_millis(iso_or_ms) if isinstance(iso_or_ms, str) else iso_or_ms
    return Peer(_identity(), GOLDEN["group_id"], clock=lambda: now_ms / 1000, founder=founder)


def _agent_dto(adds, removes, lease_stamp, lease_value, completed, signed_at) -> dict:
    """An agent-signed transition on the certified golden record, built from scratch."""
    identity, agent = _identity(), _agent()
    record = cbor.loads(_hex("entry_state_agent_signed_cbor"))["record"]
    signer = identity.agent("python")
    view = wire.state_sign_view(GOLDEN["space_id"], ENTRY, adds, removes, lease_stamp,
                                lease_value, completed, signer, signed_at)
    return view, {"record": record, "issuerPublicKey": identity.public_raw, "adds": adds,
                  "removes": removes, "leaseStamp": lease_stamp, "leaseValue": lease_value,
                  "completed": completed, "stateSig": agent.sign(cbor.dumps(view)),
                  "agentCertificate": agent.certificate, "stateCertificate": agent.certificate,
                  "signer": signer, "signedAt": signed_at}


def test_agent_signed_renew_cancel_and_complete_match_java_and_fold():
    # SPEC §11a.4 v0.1.13: the agent signs each transition of its own entry.
    identity = _identity()
    python = identity.agent("python")
    adds = [{"replica": identity.peer_id, "counter": 1}]
    write_lease = {"holder": python, "expiresAtMillis": 1735693200000, "kind": "WRITE"}
    t0 = wire.hlc_physical(GOLDEN["hlc_encoded"])
    cases = {
        "renew": (adds, [], _stamp(60_000), {"holder": python, "expiresAtMillis": t0 + 7_200_000,
                                              "kind": "WRITE"}, False, _stamp(60_000, 1)),
        "cancel": (adds, adds, GOLDEN["hlc_encoded"], write_lease, False, _stamp(120_000)),
        "complete": (adds, [], GOLDEN["hlc_encoded"], write_lease, True, _stamp(180_000)),
    }
    claim_proof = cbor.loads(_hex("claim_delta_with_certificate_cbor"))["claim"]
    for name, args in cases.items():
        view, dto = _agent_dto(*args)
        assert cbor.dumps(view) == _hex(f"state_sign_view_agent_{name}_cbor"), name
        assert cbor.dumps(dto) == _hex(f"entry_state_agent_{name}_cbor"), name
        delta = ({"state": dto, "claimEntry": ENTRY, "claim": claim_proof} if name == "complete"
                 else {"state": dto, "claimEntry": None, "claim": None})
        assert cbor.dumps(delta) == _hex(f"delta_agent_{name}_cbor"), name

        peer = _peer_at(GOLDEN["certificate_verify_at"])
        peer._fold(cbor.loads(_hex("delta_agent_signed_cbor"))["state"])
        decoded = cbor.loads(_hex(f"delta_agent_{name}_cbor"))
        if decoded["claim"] is not None:
            peer._fold_claim(decoded["claimEntry"], decoded["claim"])
        peer._fold(decoded["state"])
        held = peer.states[ENTRY]
        if name == "renew":
            assert held["leaseStamp"] == _stamp(60_000)
            assert held["leaseValue"]["expiresAtMillis"] == t0 + 7_200_000
        elif name == "cancel":
            assert held["removes"] == adds
        else:
            assert held["completed"] is True
            assert held["stateCertificate"] == _agent().certificate


def test_a_completion_without_its_claim_is_refused():
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    peer._fold(cbor.loads(_hex("delta_agent_signed_cbor"))["state"])
    peer._fold(cbor.loads(_hex("delta_agent_complete_cbor"))["state"])  # claim not folded
    assert peer.states[ENTRY]["completed"] is False


def test_a_state_signed_outside_its_window_or_beyond_the_drift_ceiling_is_refused():
    for name, offset in (("adv_agent_state_out_of_window_delta", -3_600_000),
                         ("adv_agent_state_drift_delta", 600_000 + 60_000)):
        state = cbor.loads(_hex(name))["state"]
        assert state["signedAt"] == _stamp(offset), name
        peer = _peer_at(GOLDEN["certificate_verify_at"])
        peer._fold(state)
        assert peer.states == {}, name
    # The drift vector is inside the window: a receiver whose clock has caught up accepts it.
    caught_up = _peer_at(wire.hlc_physical(GOLDEN["hlc_encoded"]) + 60_000)
    caught_up._fold(cbor.loads(_hex("adv_agent_state_drift_delta"))["state"])
    assert set(caught_up.states) == {ENTRY}


def test_an_out_of_window_agent_claim_is_refused():
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    delta = cbor.loads(_hex("adv_claim_cert_out_of_window_delta"))
    assert delta["claim"]["claim"]["stamp"] == _stamp(-3_600_000)
    assert not wire.verify_claim_proof(delta["claim"], parse_instant_millis(GOLDEN["certificate_verify_at"]))
    peer._fold_claim(delta["claimEntry"], delta["claim"])
    assert peer.claims == {}
    control = cbor.loads(_hex("claim_delta_with_certificate_cbor"))
    peer._fold_claim(control["claimEntry"], control["claim"])
    assert set(peer.claims) == {ENTRY}


def test_a_relabelled_key_epoch_never_verifies():
    identity = _identity()
    relabelled = cbor.loads(_hex("adv_key_epoch_relabelled_record_cbor"))
    genuine = cbor.loads(_hex("entry_record_key_epoch_cbor"))
    assert relabelled["keyEpoch"] == 3 and relabelled["sig"] == genuine["sig"]
    assert {k: v for k, v in relabelled.items() if k != "keyEpoch"} == \
        {k: v for k, v in genuine.items() if k != "keyEpoch"}
    assert wire.verify_record(genuine, identity.public_raw, None, 0)
    assert not wire.verify_record(relabelled, identity.public_raw, None, 0)
    assert cbor.loads(_hex("delta_key_epoch_cbor"))["state"]["record"] == genuine
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    peer._fold(cbor.loads(_hex("adv_key_epoch_relabelled_delta"))["state"])
    assert peer.states == {}
    peer._fold(cbor.loads(_hex("delta_key_epoch_cbor"))["state"])
    assert peer.states[ENTRY]["record"]["keyEpoch"] == 2


def test_leaf_and_join_credential_revocations_need_the_founder():
    # SPEC §5.6 v0.1.13: only the founder revokes an X.509 leaf or a join credential.
    import hashlib
    from agentspaces import revocation
    now = parse_instant_millis("2026-06-01T00:00:00Z")
    expected = {
        "x509_leaf": {"kind": "X509_LEAF", "x509Issuer": "CN=golden-leaf,O=Bad Monkey",
                      "x509Serial": "0a1b2c3d",
                      "certificateFingerprint": hashlib.sha256(b"golden-leaf-der").digest()},
        "join_credential": {"kind": "JOIN_CREDENTIAL",
                            "credentialHash": hashlib.sha256(b"golden-join-credential").digest()},
    }
    founded = revocation.Registry(lambda: GOLDEN["peer_id"], lambda: GOLDEN["group_id"])
    stranger = revocation.Registry(lambda: Identity.generate().peer_id, lambda: GOLDEN["group_id"])
    for kind, target in expected.items():
        ad = cbor.loads(_hex(f"credential_revocation_{kind}_cbor"))
        assert ad["target"] == target, kind
        assert ad["id"] == revocation.revocation_id(GOLDEN["group_id"], target)
        assert ad["issuer"] == GOLDEN["peer_id"]
        signed = _hex(f"signed_credential_revocation_{kind}_cbor")
        assert founded.accept(revocation.CREDENTIAL_STREAM, signed, now), kind
        assert not stranger.accept(revocation.CREDENTIAL_STREAM, signed, now), kind
    assert set(founded.credentials) == {
        "X509_LEAF:" + expected["x509_leaf"]["certificateFingerprint"].hex(),
        "JOIN_CREDENTIAL:" + expected["join_credential"]["credentialHash"].hex()}


def test_a_cross_issuer_revocation_is_refused():
    # adv_forger revokes peer_id/python, an agent it does not host.
    from agentspaces import revocation
    signed = cbor.loads(_hex("adv_credential_revocation_cross_issuer_cbor"))
    ad = cbor.loads(signed["adBytes"])
    assert ad["issuer"] == derive_id(_hex("adv_forger_public_key_raw"))
    assert ad["target"] == {"kind": "AGENT", "agent": _identity().agent("python")}
    assert Identity.verify(signed["publicKey"], signed["adBytes"], signed["signature"])
    now = parse_instant_millis("2026-06-01T00:00:00Z")
    for founder in (GOLDEN["peer_id"], None):
        registry = revocation.Registry(lambda f=founder: f, lambda: GOLDEN["group_id"])
        assert not registry.accept(revocation.CREDENTIAL_STREAM,
                                   _hex("adv_credential_revocation_cross_issuer_cbor"), now)
        assert not registry.refuses(_identity().agent("python"), _hex("agent_public_key_raw"), 0)


def test_a_record_under_a_renewed_certificate_matches_java_and_is_judged_at_signing_time():
    # SPEC §4.2 v0.1.13: the renewing agent re-issues at half-life; the record's
    # certificate is the one covering its stamp, judged there by receivers.
    from agentspaces.identity import verify_agent_certificate_at
    identity = _identity()
    verify_at = parse_instant_millis(GOLDEN["certificate_verify_at"])
    signed_at = parse_instant_millis(GOLDEN["renewed_certificate_signed_at"])
    now = [verify_at]
    agent = identity.renewing_subordinate("python", "PT24H",
                                          key=Identity.from_pkcs8(_hex("agent_private_key_pkcs8")),
                                          clock=lambda: now[0] / 1000)
    assert cbor.dumps(agent.certificate) == _hex("agent_certificate_cbor")
    now[0] = verify_at + 13 * 3600 * 1000
    assert agent.renew_if_due()
    now[0] = signed_at
    renewed = agent.certificate_covering(signed_at)
    assert cbor.dumps(renewed) == _hex("renewed_agent_certificate_cbor")

    python = identity.agent("python")
    stamp, state_stamp = f"{signed_at}:0:{identity.peer_id}", f"{signed_at}:1:{identity.peer_id}"
    entry = "44444444-5555-6666-7777-888888888888"
    view = wire.sign_view(entry, GOLDEN["space_id"], "GoldenVectors$ResearchTask#v1",
                          _hex("task_payload_cbor"), python, stamp)
    assert cbor.dumps(view) == _hex("sign_view_renewed_certificate_cbor")
    lease = {"holder": python, "expiresAtMillis": signed_at + 3_600_000, "kind": "WRITE"}
    record = {"entryId": entry, "spaceId": GOLDEN["space_id"], "type": "GoldenVectors$ResearchTask#v1",
              "payload": _hex("task_payload_cbor"), "payloadRef": None, "issuer": python,
              "issued": stamp, "lease": lease, "tags": {}, "sig": agent.sign(cbor.dumps(view))}
    adds = [{"replica": identity.peer_id, "counter": 21}]
    state_view = wire.state_sign_view(GOLDEN["space_id"], entry, adds, [], stamp, lease, False,
                                      python, state_stamp)
    dto = {"record": record, "issuerPublicKey": identity.public_raw, "adds": adds, "removes": [],
           "leaseStamp": stamp, "leaseValue": lease, "completed": False,
           "stateSig": agent.sign(cbor.dumps(state_view)), "agentCertificate": renewed,
           "stateCertificate": renewed, "signer": python, "signedAt": state_stamp}
    assert cbor.dumps(dto) == _hex("entry_state_renewed_certificate_cbor")
    assert cbor.dumps({"state": dto, "claimEntry": None, "claim": None}) \
        == _hex("delta_renewed_certificate_cbor")

    long_after = signed_at + 30 * 3600 * 1000
    first = cbor.loads(_hex("agent_certificate_cbor"))
    assert verify_agent_certificate_at(renewed, identity.public_raw, python, signed_at, long_after)
    assert not verify_agent_certificate(renewed, identity.public_raw, python, long_after)
    assert not verify_agent_certificate_at(first, identity.public_raw, python, signed_at, signed_at)
    peer = _peer_at(GOLDEN["renewed_certificate_signed_at"])
    peer._fold(cbor.loads(_hex("delta_renewed_certificate_cbor"))["state"])
    assert set(peer.states) == {entry}
    behind = _peer_at(GOLDEN["certificate_verify_at"])  # the stamp leads it beyond the drift ceiling
    behind._fold(cbor.loads(_hex("delta_renewed_certificate_cbor"))["state"])
    assert behind.states == {}
