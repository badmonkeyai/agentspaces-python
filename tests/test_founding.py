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

"""Self-certifying groups (SPEC §4.4, §5.1) and the join-by-GroupID bootstrap
(SPEC §9, §10.1; TECH-SPEC §3.1) against the v0.1.10 golden vectors: the
Python founder reproduces Java GroupFounding.found byte for byte, the four
receiver checks accept the genuine document and refuse both adversarial ones,
the GROUP_AD_WANT / GROUP_AD frames match the Java wire, and the Peer's join
path accepts exactly the verified answer."""

import json
import pathlib

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import (
    Identity,
    found_group,
    founding_document,
    founding_fields,
    group_id_from_founding_document,
    verify_signed_group_ad,
)
from agentspaces.peer import Peer

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent / "golden.json").read_text())


def _hex(name: str) -> bytes:
    return bytes.fromhex(GOLDEN[name])


def _identity() -> Identity:
    return Identity.from_pkcs8(_hex("private_key_pkcs8"))


def _found() -> dict:
    # Java: GroupFounding.found(identity, "golden-fleet", OPEN, LEASE_RACE,
    # GossipParameters(3, PT1S), issued 2026-01-01T00:00:00Z, ttl P1D).
    return found_group(_identity(), "golden-fleet", "OPEN", "LEASE_RACE", 3,
                       "PT1S", "2026-01-01T00:00:00Z", "PT24H")


# ------------------------------------------------------------ founding (§4.4, §5.1)

def test_founding_fields_and_signature_match_java():
    fields = founding_fields("golden-fleet", GOLDEN["peer_id"],
                             "2026-01-01T00:00:00Z", "PT24H", "OPEN",
                             "LEASE_RACE", 3, "PT1S")
    assert cbor.dumps(fields) == _hex("founding_fields_cbor")
    signature = _identity().sign(cbor.dumps(fields))
    assert signature == _hex("founding_signature")
    document = founding_document(fields, signature)
    assert cbor.dumps(document) == _hex("founding_document_cbor")
    assert group_id_from_founding_document(cbor.dumps(document)) \
        == GOLDEN["founding_group_id"]


def test_found_group_reproduces_the_java_advertisement():
    signed = _found()
    ad = signed["advertisement"]
    assert ad["group"] == GOLDEN["founding_group_id"]
    assert ad["id"] == GOLDEN["founding_ad_id"] == "aspace://" + ad["group"]
    assert cbor.dumps(ad) == _hex("group_ad_cbor")
    assert signed["signature"] == _hex("founding_signature")
    assert signed["founderPublicKey"] == _hex("public_key_raw")
    assert cbor.dumps(signed) == _hex("signed_group_ad_cbor")
    assert wire.group_ad_body(signed) == _hex("signed_group_ad_cbor")


def test_the_four_checks_accept_the_genuine_founding_document():
    assert verify_signed_group_ad(_found()) == GOLDEN["founding_group_id"]
    # The same document decoded from Java's bytes verifies identically.
    assert verify_signed_group_ad(cbor.loads(_hex("signed_group_ad_cbor"))) \
        == GOLDEN["founding_group_id"]


def test_the_wrong_id_document_still_derives_to_the_real_group():
    # SPEC §4.4: the substitution is detected because the founding document
    # the attacker was forced to carry derives to the real GroupID, not the
    # one the advertisement claims.
    signed = cbor.loads(_hex("adv_group_ad_wrong_id_cbor"))
    ad = signed["advertisement"]
    assert ad["group"] == GOLDEN["group_id"]
    assert ad["id"] == "aspace://" + GOLDEN["group_id"]
    fields = founding_fields(ad["name"], ad["issuer"], ad["issued"], ad["ttl"],
                             ad["membershipPolicy"], ad["defaultStrategy"],
                             ad["gossip"]["fanout"], ad["gossip"]["period"])
    assert cbor.dumps(fields) == _hex("founding_fields_cbor")
    assert Identity.verify(signed["founderPublicKey"], cbor.dumps(fields),
                           signed["signature"])
    derived = group_id_from_founding_document(
        cbor.dumps(founding_document(fields, signed["signature"])))
    assert derived == GOLDEN["founding_group_id"] != ad["group"]


def test_the_forged_signature_document_fails_only_the_signature_check():
    signed = cbor.loads(_hex("adv_group_ad_forged_signature_cbor"))
    ad = signed["advertisement"]
    assert ad["group"] == GOLDEN["founding_group_id"]
    assert signed["founderPublicKey"] == _hex("public_key_raw")
    assert signed["signature"] != _hex("founding_signature")
    assert not Identity.verify(signed["founderPublicKey"],
                               _hex("founding_fields_cbor"), signed["signature"])
    # A forger cannot repair it by claiming its own key either: the key would
    # no longer hash to the advertisement's issuer.
    forged_key = _hex("adv_forger_public_key_raw")
    assert Identity.verify(forged_key, _hex("founding_fields_cbor"),
                           signed["signature"])
    assert verify_signed_group_ad({**signed, "founderPublicKey": forged_key}) is None


def test_verification_tolerates_malformed_shapes():
    signed = _found()
    assert verify_signed_group_ad(None) is None
    assert verify_signed_group_ad({}) is None
    assert verify_signed_group_ad({**signed, "founderPublicKey": b"\x00" * 31}) is None
    assert verify_signed_group_ad({**signed, "signature": "not bytes"}) is None
    ad = dict(signed["advertisement"])
    del ad["gossip"]
    assert verify_signed_group_ad({**signed, "advertisement": ad}) is None
    ad = dict(signed["advertisement"])
    ad["gossip"] = {"fanout": "3", "period": "PT1S"}
    assert verify_signed_group_ad({**signed, "advertisement": ad}) is None
    ad = dict(signed["advertisement"])
    ad["id"] = "aspace://" + GOLDEN["group_id"]
    assert verify_signed_group_ad({**signed, "advertisement": ad}) is None


# ----------------------------------------------- bootstrap frames (§9, TECH-SPEC §3.1)

def test_group_ad_want_frame_matches_java():
    identity = _identity()
    env = wire.group_ad_want_envelope(GOLDEN["founding_group_id"],
                                      GOLDEN["peer_id"], GOLDEN["hlc_encoded"],
                                      to=GOLDEN["peer_id"])
    assert env["body"] == b""
    assert cbor.dumps(env) == _hex("group_ad_want_envelope_cbor")
    assert wire.encode_frame(env, identity) == _hex("group_ad_want_frame_cbor")
    decoded = wire.decode_frame(_hex("group_ad_want_frame_cbor"))
    assert decoded is not None
    assert decoded["ver"] == wire.WIRE_VERSION == GOLDEN["wire_version"]
    assert decoded["kind"] == wire.KIND_GROUP_AD_WANT
    assert decoded["group"] == GOLDEN["founding_group_id"]
    assert decoded["body"] == b""
    # The real request is unaddressed: the seed's PeerID is not yet known.
    assert wire.group_ad_want_envelope("g", "p", "1:0:p")["to"] is None


def test_group_ad_frame_matches_java():
    identity = _identity()
    body = wire.group_ad_body(_found())
    env = wire.envelope(GOLDEN["founding_group_id"], wire.KIND_GROUP_AD,
                        GOLDEN["peer_id"], GOLDEN["hlc_encoded"], body,
                        to=GOLDEN["peer_id"])
    assert cbor.dumps(env) == _hex("group_ad_envelope_cbor")
    assert wire.encode_frame(env, identity) == _hex("group_ad_frame_cbor")
    decoded = wire.decode_frame(_hex("group_ad_frame_cbor"))
    assert decoded is not None
    assert decoded["kind"] == wire.KIND_GROUP_AD
    assert decoded["group"] == GOLDEN["founding_group_id"]
    assert decoded["body"] == _hex("signed_group_ad_cbor")
    assert verify_signed_group_ad(cbor.loads(decoded["body"])) \
        == GOLDEN["founding_group_id"]


def test_a_frame_of_another_wire_version_is_dropped_before_verification():
    identity = _identity()
    env = wire.group_ad_want_envelope(GOLDEN["founding_group_id"],
                                      GOLDEN["peer_id"], GOLDEN["hlc_encoded"],
                                      to=GOLDEN["peer_id"])
    assert wire.decode_frame(wire.encode_frame(env, identity)) is not None
    for bad in (1, 3, "2", None, True):
        stale = wire.encode_frame({**env, "ver": bad}, identity)  # validly signed
        assert wire.decode_frame(stale) is None, bad


# --------------------------------------------------------- the Peer join path (§10.1)

def _joiner() -> Peer:
    """A Peer mid join_by_group_id: it holds the wanted GroupID and nothing
    else, exactly the state in which GROUP_AD answers arrive."""
    peer = Peer(_identity(), GOLDEN["founding_group_id"])
    return peer


def _drive(peer: Peer, frame: bytes) -> None:
    env = wire.decode_frame(frame)
    assert env is not None
    if peer._accepts(env):
        peer._handle(env)


def test_the_join_path_accepts_the_verified_group_ad():
    peer = _joiner()
    assert peer.founding is None
    _drive(peer, _hex("group_ad_frame_cbor"))
    assert peer._founding_ready.is_set()
    assert peer.founding == cbor.loads(_hex("signed_group_ad_cbor"))
    assert peer.founding["advertisement"]["group"] == peer.group


def test_group_ad_frames_reach_the_handler_before_membership():
    # The reader filter keys on the wanted group alone (no membership state),
    # so the bootstrap answer is accepted while the peer is not yet a member.
    peer = _joiner()
    env = wire.decode_frame(_hex("group_ad_frame_cbor"))
    assert peer._accepts(env)
    assert not Peer(_identity(), GOLDEN["group_id"])._accepts(env)


@pytest.mark.parametrize("name", [
    "adv_group_ad_wrong_id_cbor",
    "adv_group_ad_forged_signature_cbor",
])
def test_the_join_path_ignores_hostile_group_ads(name):
    peer = _joiner()
    hostile = wire.envelope(GOLDEN["founding_group_id"], wire.KIND_GROUP_AD,
                            GOLDEN["peer_id"], GOLDEN["hlc_encoded"], _hex(name),
                            to=GOLDEN["peer_id"])
    _drive(peer, wire.encode_frame(hostile, _identity()))
    assert peer.founding is None
    assert not peer._founding_ready.is_set()
    # The genuine answer still completes the join afterwards.
    _drive(peer, _hex("group_ad_frame_cbor"))
    assert peer.founding is not None


def test_a_genuine_document_for_another_group_does_not_complete_the_join():
    # A seed answering with a valid founding document for a different group
    # is ignored: the joiner holds the GroupID and verifies against exactly it.
    other = found_group(_identity(), "other-fleet", "OPEN", "LEASE_RACE", 3,
                        "PT1S", "2026-01-01T00:00:00Z", "PT24H")
    assert verify_signed_group_ad(other) not in (None, GOLDEN["founding_group_id"])
    peer = _joiner()
    peer._on_group_ad(wire.group_ad_body(other))
    assert peer.founding is None


def test_group_ad_want_is_sent_unaddressed():
    sent = []
    peer = _joiner()

    class FakeSocket:
        def sendall(self, data):
            sent.append(data)

    peer._socket = FakeSocket()
    peer._running = True
    peer._send(wire.KIND_GROUP_AD_WANT, b"")
    frame = sent[0][4:]
    env = wire.decode_frame(frame)
    assert env is not None
    assert env["kind"] == wire.KIND_GROUP_AD_WANT
    assert env["group"] == GOLDEN["founding_group_id"]
    assert env["to"] is None
    assert env["body"] == b""


def test_join_by_group_id_times_out_without_a_verified_answer(monkeypatch):
    import socket as socket_module

    class FakeSocket:
        def settimeout(self, value):
            pass

        def sendall(self, data):
            pass

        def recv(self, count):
            raise OSError("closed")

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "create_connection",
                        lambda address, timeout=None: FakeSocket())
    peer = Peer(_identity(), None)
    with pytest.raises(TimeoutError):
        peer.join_by_group_id("127.0.0.1", 1, GOLDEN["founding_group_id"],
                              timeout=0.05)
    assert peer.group == GOLDEN["founding_group_id"]
    assert not peer.connected
