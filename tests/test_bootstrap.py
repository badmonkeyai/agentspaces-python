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

"""The peer's bootstrap paths (SRAD DB-X-01, DB-X-07): connect_any dials seeds
in order and fails over to the next on a lost socket; bootstrap joins through
a served document; join_invite derives the credential from the golden key,
carries it under aspace:join, and verifies the founding against the
delegation's group. The seeds are the fake seed of test_robustness."""

import base64
import json
import pathlib
import socket
import time

import pytest

from agentspaces import beacon, cbor, social, wire
from agentspaces.identity import Identity, found_group, parse_instant_millis
from agentspaces.peer import Peer
from tests.test_beacon import Served
from tests.test_robustness import FakeSeed

GOLDEN = json.loads((pathlib.Path(__file__).parent / "social-golden.json").read_text())


def _dead_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _wait(predicate, seconds: float = 5.0) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline and not predicate():
        time.sleep(0.05)


def _self_ad(seed: FakeSeed) -> dict:
    rumor = cbor.loads(next(e for e in seed.envelopes if e["kind"] == "RUMOR")["body"])
    assert rumor["streamId"] == "peers"
    return cbor.loads(cbor.loads(rumor["payload"])["adBytes"])


# ------------------------------------------------------------- connect_any

def test_connect_any_dials_in_order_and_fails_over_to_the_next_seed():
    first, second = FakeSeed(), FakeSeed()
    dead = _dead_port()
    peer = Peer(Identity.generate(), "zBootstrap")
    peer.reconnect_interval_s = 0.1
    try:
        chosen = peer.connect_any([("127.0.0.1", dead), ("127.0.0.1", first.port), ("127.0.0.1", second.port)])
        assert chosen == ("127.0.0.1", first.port) == peer._seed
        _wait(lambda: len(first.frames) >= 2)
        assert [k for _, k in first.frames][:2] == ["RUMOR", "DIGEST"]
        assert second.frames == []
        # The first seed drops the link: the peer fails over to the next, not back to the first.
        first.connections[0].close()
        _wait(lambda: len(second.frames) >= 2)
        assert [k for _, k in second.frames][:2] == ["RUMOR", "DIGEST"], "re-introduced at the next seed"
        assert peer._seed == ("127.0.0.1", second.port)
        assert peer.reconnects == 1
        assert len(first.connections) == 1
        assert peer.connected
    finally:
        peer.close()
        first.close()
        second.close()


def test_connect_any_raises_when_no_seed_accepts_and_tries_each_once(monkeypatch):
    dialed = []

    def refuse(address, timeout=None):
        dialed.append(address)
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", refuse)
    peer = Peer(Identity.generate(), "zBootstrap")
    with pytest.raises(OSError):
        peer.connect_any([("127.0.0.1", 1), ("127.0.0.1", 2), ("127.0.0.1", 1)])
    assert dialed == [("127.0.0.1", 1), ("127.0.0.1", 2)], "in order, duplicates folded"
    assert not peer.connected
    with pytest.raises(OSError):
        peer.connect_any([])


def test_a_hostname_seed_is_resolved_to_its_addresses():
    expanded = Peer._expand_seeds([("localhost", 7500)])
    assert ("127.0.0.1", 7500) in expanded
    assert all(port == 7500 for _, port in expanded)
    assert Peer._expand_seeds([("no-such-host.invalid.", 1)]) == [("no-such-host.invalid.", 1)]


# --------------------------------------------------------------- bootstrap

def _served_document(issuer: Identity, founder: Identity, seed: FakeSeed, **extra):
    signed = found_group(founder, "research-fleet", "OPEN", "LEASE_RACE", 3, "PT1S",
                         "2026-10-14T00:00:00Z", "PT8760H")
    group = beacon.document_group(
        "research-fleet", signed["advertisement"]["group"],
        base64.b64encode(cbor.dumps(signed)).decode(),
        [("tls", "seed-a.corp.example:7500"), ("tcp", f"127.0.0.1:{seed.port}")], **extra)
    doc = beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group])
    return signed, Served(beacon.to_json(doc))


def test_bootstrap_joins_through_a_served_document():
    issuer, founder = Identity.generate(), Identity.generate()
    seed = FakeSeed()
    signed, served = _served_document(issuer, founder, seed)
    group_id = signed["advertisement"]["group"]
    peer = Peer(Identity.generate(), None)
    try:
        founding = peer.bootstrap(served.url, group_id=group_id, allow_plain=True, beacon_peer=issuer.peer_id)
        assert founding == signed == peer.founding
        assert peer.group == group_id
        assert peer._founder() == founder.peer_id, "the founder is known for revocations"
        assert peer._seeds == [("127.0.0.1", seed.port)], "the tls seed is not this client's"
        _wait(lambda: len(seed.frames) >= 2)
        assert [k for _, k in seed.frames][:2] == ["RUMOR", "DIGEST"]
        assert _self_ad(seed)["group"] == group_id
        assert peer._refresh_seeds() == [("127.0.0.1", seed.port)]
    finally:
        peer.close()
        served.close()
        seed.close()


def test_bootstrap_refuses_a_founding_for_another_group_before_dialing():
    issuer, founder = Identity.generate(), Identity.generate()
    seed = FakeSeed()
    signed, served = _served_document(issuer, founder, seed)
    peer = Peer(Identity.generate(), None)
    try:
        with pytest.raises(ValueError):
            peer.bootstrap(served.url, group_id="zNotThisGroup", allow_plain=True)
        with pytest.raises(ValueError):
            peer.bootstrap(served.url, group_id=signed["advertisement"]["group"])  # http, no allow_plain
        with pytest.raises(ValueError):
            peer.bootstrap(served.url, allow_plain=True, beacon_peer=Identity.generate().peer_id)
        time.sleep(0.2)
        assert seed.connections == [] and not peer.connected
    finally:
        peer.close()
        served.close()
        seed.close()


def test_bootstrap_without_a_group_id_takes_the_only_group():
    issuer, founder = Identity.generate(), Identity.generate()
    seed = FakeSeed()
    signed, served = _served_document(issuer, founder, seed)
    peer = Peer(Identity.generate(), None)
    try:
        peer.bootstrap(served.url, allow_plain=True)
        assert peer.group == signed["advertisement"]["group"]
        _wait(lambda: len(seed.frames) >= 1)
        assert seed.frames[0][1] == "RUMOR"
    finally:
        peer.close()
        served.close()
        seed.close()


# ------------------------------------------------------------- join_invite

def _social_document(issuer: Identity, seed: FakeSeed, delegation=None, founding=None) -> dict:
    group = beacon.document_group(
        "weekend-hack", GOLDEN["group_id"], founding or GOLDEN["founding_cbor_base64"],
        [("tcp", f"127.0.0.1:{seed.port}")], invite=delegation)
    return beacon.sign_document(issuer, GOLDEN["founding_issued"], 300, [group])


def _stub_fetch(monkeypatch, doc: dict) -> list:
    urls = []

    def fake_get(url, timeout, allow_plain):
        urls.append(url)
        return beacon.to_json(doc)

    monkeypatch.setattr(beacon, "_http_get", fake_get)
    return urls


def test_join_invite_derives_the_golden_credential_and_carries_it_as_the_join_hint(monkeypatch):
    seed = FakeSeed()
    issued_s = parse_instant_millis(GOLDEN["founding_issued"]) / 1000
    candidate = Identity.from_seed(bytes.fromhex(GOLDEN["candidate_seed_hex"]))
    # The compact key carries no delegation: it comes from the document's invite field.
    urls = _stub_fetch(monkeypatch, _social_document(Identity.generate(), seed, GOLDEN["delegation_base64"]))
    peer = Peer(candidate, None, clock=lambda: issued_s)
    try:
        content_key, group_id = peer.join_invite(GOLDEN["invite_key_compact"])
        assert urls == ["https://s.agentspaces.dev/j/" + GOLDEN["code"]]
        assert group_id == GOLDEN["group_id"] == peer.group
        assert content_key.hex() == GOLDEN["content_key_hex"]
        assert peer.resource_hints == {"aspace:join": GOLDEN["credential"]}
        assert peer.delegation == GOLDEN["delegation_base64"]
        assert peer.founding == cbor.loads(base64.b64decode(GOLDEN["founding_cbor_base64"]))
        _wait(lambda: len(seed.frames) >= 2)
        ad = _self_ad(seed)
        assert ad["resourceHints"] == {"aspace:join": GOLDEN["credential"]}
        assert ad["issuer"] == GOLDEN["candidate_peer_id"] and ad["group"] == GOLDEN["group_id"]
        # The hint is bound into the signed advertisement bytes.
        signed = cbor.loads(cbor.loads(next(e for e in seed.envelopes if e["kind"] == "RUMOR")["body"])["payload"])
        assert Identity.verify(signed["publicKey"], signed["adBytes"], signed["signature"])
    finally:
        peer.close()
        seed.close()


def test_join_invite_takes_the_delegation_from_the_key_and_the_host_from_it(monkeypatch):
    seed = FakeSeed()
    issued_s = parse_instant_millis(GOLDEN["founding_issued"]) / 1000
    candidate = Identity.from_seed(bytes.fromhex(GOLDEN["candidate_seed_hex"]))
    urls = _stub_fetch(monkeypatch, _social_document(Identity.generate(), seed))  # no invite field
    peer = Peer(candidate, None, clock=lambda: issued_s)
    try:
        content_key, group_id = peer.join_invite(GOLDEN["invite_key_url_with_delegation"], allow_plain=True)
        assert urls == ["http://beacon.example.org/j/" + GOLDEN["code"]]
        assert group_id == GOLDEN["group_id"]
        assert peer.resource_hints["aspace:join"] == GOLDEN["credential"]
        assert len(content_key) == 32
    finally:
        peer.close()
        seed.close()


def test_join_invite_after_the_window_still_presents_the_credential_and_pins_the_key(monkeypatch):
    """Past the delegation's window a restarted friend still joins: the members that
    admitted it re-admit it from memory (SPEC §5.1, v0.1.20), so the client does not
    refuse an expired delegation, and it exposes the key pinned to the delegation so
    the next start presents the same credential."""
    seed = FakeSeed()
    late_s = (parse_instant_millis(GOLDEN["delegation_not_after"]) + 86_400_000) / 1000
    candidate = Identity.from_seed(bytes.fromhex(GOLDEN["candidate_seed_hex"]))
    _stub_fetch(monkeypatch, _social_document(Identity.generate(), seed, GOLDEN["delegation_base64"]))
    peer = Peer(candidate, None, clock=lambda: late_s)
    try:
        peer.join_invite(GOLDEN["invite_key_compact"])
        assert peer.resource_hints == {"aspace:join": GOLDEN["credential"]}
        pinned = social.InviteKey.parse(peer.pinned_invite)
        assert pinned.delegation == GOLDEN["delegation_base64"] and pinned.code == GOLDEN["code"]
    finally:
        peer.close()
        seed.close()


def test_join_invite_refuses_a_document_whose_founding_is_not_the_delegations_group(monkeypatch):
    seed = FakeSeed()
    issued_s = parse_instant_millis(GOLDEN["founding_issued"]) / 1000
    other = found_group(Identity.generate(), "weekend-hack", "INVITE", "LEASE_RACE", 3, "PT1S",
                        GOLDEN["founding_issued"], "PT8760H")
    doc = _social_document(Identity.generate(), seed, GOLDEN["delegation_base64"],
                           founding=base64.b64encode(cbor.dumps(other)).decode())
    doc["groups"][0]["id"] = "aspace://" + other["advertisement"]["group"]
    doc = beacon.sign_document(Identity.generate(), GOLDEN["founding_issued"], 300, doc["groups"])
    _stub_fetch(monkeypatch, doc)
    peer = Peer(Identity.generate(), None, clock=lambda: issued_s)
    try:
        with pytest.raises(ValueError):
            peer.join_invite(GOLDEN["invite_key_compact"])
        assert "aspace:join" not in peer.resource_hints
        assert not peer.connected and seed.connections == []
    finally:
        peer.close()
        seed.close()


def test_join_invite_leaves_an_expired_delegation_to_the_members_and_refuses_a_document_without_one(monkeypatch):
    # Since SPEC v0.1.20 an expired delegation is the members' call, not the client's:
    # they re-admit a peer they admitted in time and refuse a newcomer. The client
    # still refuses what can never admit: a document and a key with no delegation.
    seed = FakeSeed()
    _stub_fetch(monkeypatch, _social_document(Identity.generate(), seed))
    peer = Peer(Identity.generate(), None)
    try:
        with pytest.raises(ValueError):
            peer.join_invite(GOLDEN["invite_key_compact"])
    finally:
        peer.close()
        seed.close()


def test_the_self_advertisement_carries_canonical_resource_hints():
    identity = Identity.generate()
    ad = wire.peer_advertisement("zG", identity, "2026-10-14T00:00:00Z",
                                 resource_hints={"zz": "1", "aspace:join": "d1:x", "a": "2"})
    assert list(ad["resourceHints"]) == ["a", "zz", "aspace:join"], "shorter keys first, then bytewise"
    assert wire.peer_advertisement("zG", identity, "2026-10-14T00:00:00Z")["resourceHints"] == {}
