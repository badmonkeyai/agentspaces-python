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

"""Adversarial conformance: every adv_* vector in golden.json is a hostile
input this client must reject — by failed decode, failed verification, or a
bounds check — without crashing its reader. The same vectors gate the Java and
TypeScript implementations, so all three reject identically (security review
§6 / remediation plan Workstream 1)."""

import json
import pathlib

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import (
    Identity,
    parse_instant_millis,
    verify_signed_group_ad,
)
from agentspaces.peer import Peer

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent / "golden.json").read_text())


def _hex(name: str) -> bytes:
    return bytes.fromhex(GOLDEN[name])


def _peer() -> Peer:
    return Peer(Identity.from_pkcs8(_hex("private_key_pkcs8")),
                GOLDEN["group_id"])


@pytest.mark.parametrize("name", [
    "adv_claim_bad_signature_delta",
    "adv_claim_transplanted_delta",
    "adv_claim_nan_bid_delta",
    "adv_claim_epoch_zero_delta",
    "adv_claim_epoch_jump_delta",
    "adv_claim_eternal_delta",
])
def test_hostile_claims_never_enter_the_lattice(name):
    peer = _peer()
    delta = cbor.loads(_hex(name))
    peer._fold_claim(delta["claimEntry"], delta["claim"])
    assert peer.claims == {}


def test_deep_nesting_is_refused_bounded():
    with pytest.raises(ValueError):
        cbor.loads(_hex("adv_deep_nesting_cbor"))


def test_a_tampered_frame_signature_never_verifies():
    assert wire.decode_frame(_hex("adv_frame_bad_signature")) is None


def test_a_misaddressed_frame_fails_the_reader_filter():
    env = wire.decode_frame(_hex("adv_frame_wrong_destination"))
    assert env is not None  # the signature itself is valid
    assert env["to"] == GOLDEN["adv_frame_wrong_destination_to"]
    # The reader honors an addressed frame only when it is the recipient:
    # the same signed PING addressed to us passes, the misaddressed one fails.
    peer = _peer()
    assert peer._accepts(wire.decode_frame(_hex("ping_frame_cbor")))
    assert not peer._accepts(env)


def test_a_frame_for_a_foreign_group_fails_the_reader_filter():
    # SPEC section 9: receivers reject envelopes whose group they do not belong to.
    env = wire.decode_frame(_hex("ping_frame_cbor"))
    assert _peer()._accepts(env)
    assert not Peer(Identity.from_pkcs8(_hex("private_key_pkcs8")),
                    "zSomeOtherGroup")._accepts(env)
    assert not _peer()._accepts(None)  # an unverifiable frame never reaches a handler


def test_frame_cap_matches_the_shared_constant():
    assert wire.MAX_FRAME_BYTES == GOLDEN["max_frame_bytes"]


@pytest.mark.parametrize("name", [
    "adv_group_ad_wrong_id_cbor",
    "adv_group_ad_forged_signature_cbor",
])
def test_hostile_founding_documents_never_verify(name):
    # SPEC §5.1's four checks: a genuine signature under the wrong GroupID, and
    # the right GroupID under a forged signature, are both refused. The bytes
    # decode cleanly, so the refusal is verification, not a parse failure.
    signed = cbor.loads(_hex(name))
    assert isinstance(signed, dict)
    assert verify_signed_group_ad(signed) is None
    # And the join path drops the answer without completing the join.
    peer = Peer(Identity.from_pkcs8(_hex("private_key_pkcs8")),
                GOLDEN["founding_group_id"])
    peer._on_group_ad(_hex(name))
    assert peer.founding is None


def test_a_frame_of_another_wire_version_is_dropped():
    # SPEC §9: ver != 2 is dropped before signature verification. Re-sign the
    # golden PING envelope under ver 1 so the signature itself is valid.
    identity = Identity.from_pkcs8(_hex("private_key_pkcs8"))
    env = wire.decode_frame(_hex("ping_frame_cbor"))
    assert env is not None and env["ver"] == GOLDEN["wire_version"] == 2
    stale = wire.encode_frame({**env, "ver": 1}, identity)
    assert cbor.loads(stale)["envelope"]["ver"] == 1
    assert wire.decode_frame(stale) is None
    assert not _peer()._accepts(wire.decode_frame(stale))


def _peer_at(iso: str) -> Peer:
    now_ms = parse_instant_millis(iso)
    return Peer(Identity.from_pkcs8(_hex("private_key_pkcs8")), GOLDEN["group_id"],
                clock=lambda: now_ms / 1000)


@pytest.mark.parametrize("name", [
    "adv_cert_wrong_peer_delta",
    "adv_cert_wrong_agent_delta",
    "adv_cert_expired_delta",
    "adv_cert_uncertified_key_delta",
    "adv_cert_peer_signed_record_delta",
])
def test_hostile_certificates_never_authenticate_a_record(name):
    # TECH-SPEC §7.2's two-key rule (QA4 A4-7): each delta decodes and differs
    # from the certified golden delta in exactly one respect, and each is
    # dropped before it reaches the joined view. The control (v0.1.13: the
    # agent-signed one, since an attested entry's state must be agent-signed) folds.
    control = _peer_at(GOLDEN["certificate_verify_at"])
    control._fold(cbor.loads(_hex("delta_agent_signed_cbor"))["state"])
    assert len(control.states) == 1
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    delta = cbor.loads(_hex(name))
    assert isinstance(delta["state"]["agentCertificate"], dict)
    peer._fold(delta["state"])
    assert peer.states == {}


def test_an_expired_certificate_is_refused_whatever_the_receivers_clock():
    # SPEC §4.2 v0.1.13: a certificate is judged at the record's signing time,
    # not at receipt. adv_cert_expired_delta's certificate lapsed before the
    # record's stamp, so no receiver clock, even one inside the certificate's
    # own window, makes it authenticate.
    for at in ("2024-12-31T00:30:00Z", GOLDEN["certificate_verify_at"]):
        peer = _peer_at(at)
        peer._fold(cbor.loads(_hex("adv_cert_expired_delta"))["state"])
        assert peer.states == {}, at


@pytest.mark.parametrize("name", [
    "adv_legacy_state_on_attested_entry_delta_cbor",
    "delta_with_certificate_cbor",
    "adv_agent_state_peer_key_delta",
    "adv_agent_state_wrong_signer_delta",
])
def test_an_attested_entrys_state_must_be_signed_by_its_agent(name):
    # SPEC §11a.4 v0.1.13 (A6): a peer-signed state on an agent-attested entry,
    # agent-signer fields under a peer-key signature, and a signer other than
    # the issuer are each refused; the agent-signed control folds.
    control = _peer_at(GOLDEN["certificate_verify_at"])
    control._fold(cbor.loads(_hex("delta_agent_signed_cbor"))["state"])
    assert len(control.states) == 1
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    peer._fold(cbor.loads(_hex(name))["state"])
    assert peer.states == {}


@pytest.mark.parametrize("name", [
    "adv_claim_cert_peer_signed_delta",
    "adv_claim_cert_expired_delta",
    "adv_claim_cert_wrong_holder_delta",
])
def test_hostile_certified_claims_never_enter_the_lattice(name):
    # TECH-SPEC §7.6's two-key rule for claims (QA4 A4-7 phase 3): the control
    # (agent-signed, certificate attached) merges; each hostile proof is dropped.
    control = _peer_at(GOLDEN["certificate_verify_at"])
    good = cbor.loads(_hex("claim_delta_with_certificate_cbor"))
    control._fold_claim(good["claimEntry"], good["claim"])
    assert set(control.claims) == {good["claimEntry"]}
    peer = _peer_at(GOLDEN["certificate_verify_at"])
    delta = cbor.loads(_hex(name))
    peer._fold_claim(delta["claimEntry"], delta["claim"])
    assert peer.claims == {}
