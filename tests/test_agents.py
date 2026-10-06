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

"""v0.1.13 agent behaviour in the Python client (TODO-9-10-11 Phase 4):
agent-signed records, claims, and states that a second peer folds; renewal
judged at signing time; the keystore's layout and checks; and revocation
applied at merge under the freeze rule."""

import os
import stat

import pytest

from agentspaces import cbor, revocation, wire
from agentspaces.identity import Identity, instant_iso, parse_instant_millis
from agentspaces.peer import Peer

GROUP = "zPythonAgents"
T0 = parse_instant_millis("2026-03-01T00:00:00Z")


class Clock:
    def __init__(self, millis):
        self.millis = millis

    def __call__(self):
        return self.millis / 1000

    def advance(self, millis):
        self.millis += millis


def _delta_state(body: bytes) -> dict:
    return cbor.loads(cbor.loads(body)["payload"])["state"]


def _peer(clock, identity=None, founder=None):
    return Peer(identity or Identity.generate(), GROUP, clock=clock, founder=founder)


def test_an_agent_signed_write_folds_at_another_peer_as_the_agents_own():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT24H", clock=clock)
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", cbor.dumps({"x": 1}), host, "ignored",
                               60_000, agent=agent, now_ms=clock.millis)
    state = _delta_state(body)
    assert state["record"]["issuer"] == agent.agent_id
    assert state["signer"] == agent.agent_id and state["stateCertificate"] is not None
    receiver = _peer(clock)
    receiver._fold(state)
    assert len(receiver.states) == 1
    # Peer-signing the same transition on the attested entry is refused (A6).
    forged = wire.sign_state({k: v for k, v in state.items()}, host, None, clock.millis)
    other = _peer(clock)
    other._fold(forged)
    assert other.states == {}


def test_a_renewing_agent_stays_verifiable_after_its_first_certificate_lapses():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT1H", clock=clock)
    first = agent.certificate
    _, early = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 600_000,
                                agent=agent, now_ms=clock.millis)
    clock.advance(31 * 60 * 1000)  # past half-life: the next signature renews
    _, later = wire.entry_delta("tasks", GROUP, "T#v1", b"\x02", host, "x", 600_000,
                                agent=agent, now_ms=clock.millis)
    assert agent.certificate is not first
    assert agent.certificate_covering(T0) is first
    clock.advance(4 * 60 * 60 * 1000)  # both certificates have lapsed at receipt
    receiver = _peer(clock)
    receiver._fold(_delta_state(early))
    receiver._fold(_delta_state(later))
    assert len(receiver.states) == 2, "judged at signing time, not at receipt"


def test_an_agent_signed_take_and_completion_land_and_a_peer_signed_completion_does_not():
    clock = Clock(T0)
    writer, host = Identity.generate(), Identity.generate()
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", writer, "w", 600_000,
                               now_ms=clock.millis)
    state = _delta_state(body)
    worker = host.renewing_subordinate("worker", "PT24H", clock=clock)
    claim = wire.take_claim(state["record"]["entryId"], state["record"]["spaceId"], 1,
                            wire.hlc_now(worker.agent_id, clock.millis), worker.agent_id, 0.0,
                            clock.millis + 60_000)
    signed = wire.signed_claim(claim, host, worker)
    receiver = _peer(clock)
    receiver._fold(state)
    receiver._fold_claim(claim["entryId"], signed)
    assert claim["entryId"] in receiver.claims
    peer_signed = wire.sign_state({**state, "completed": True}, host, None, clock.millis)
    receiver._fold(peer_signed)
    assert not receiver.states[claim["entryId"]]["completed"], "A6 for the holder too"
    receiver._fold(wire.sign_state({**state, "completed": True}, host, worker, clock.millis))
    assert receiver.states[claim["entryId"]]["completed"]


def _signed_revocation(issuer: Identity, target: dict, reason: str, issued_ms: int,
                       effective_ms=None) -> dict:
    ad = {"id": revocation.revocation_id(GROUP, target), "issuer": issuer.peer_id,
          "group": GROUP, "issued": instant_iso(issued_ms), "ttl": "PT720H",
          "target": target, "reason": reason}
    if effective_ms is not None:
        ad["effectiveFrom"] = instant_iso(effective_ms)
    ad_bytes = cbor.dumps(ad)
    return {"adBytes": ad_bytes, "publicKey": issuer.public_raw, "signature": issuer.sign(ad_bytes)}


def test_a_retired_agents_history_folds_while_its_later_writes_and_claims_do_not():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT24H", clock=clock)
    _, before = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 600_000,
                                 agent=agent, now_ms=clock.millis)
    clock.advance(60_000)
    retired_at = clock.millis
    clock.advance(60_000)
    _, after = wire.entry_delta("tasks", GROUP, "T#v1", b"\x02", host, "x", 600_000,
                                agent=agent, now_ms=clock.millis)
    receiver = _peer(clock)
    assert receiver.revocations.accept_signed(revocation.CREDENTIAL_STREAM, _signed_revocation(
        host, {"kind": "AGENT", "agent": agent.agent_id}, "retired", clock.millis, retired_at),
        clock.millis)
    receiver._fold(_delta_state(before))
    receiver._fold(_delta_state(after))
    assert len(receiver.states) == 1, "history before the effect, nothing after"
    entry = next(iter(receiver.states))
    claim = wire.take_claim(entry, receiver.states[entry]["record"]["spaceId"], 1,
                            wire.hlc_now(agent.agent_id, retired_at - 1), agent.agent_id, 0.0,
                            clock.millis + 60_000)
    receiver._fold_claim(entry, wire.signed_claim(claim, host, agent))
    assert receiver.claims == {}, "a claim is refused whatever its stamp"
    local = Peer(host, GROUP, clock=clock)
    local.revocations = receiver.revocations
    with pytest.raises(ValueError, match="revoked"):
        local.write_entry("tasks", "T#v1", {"x": 3}, agent=agent)


def test_only_the_agents_peer_or_the_founder_may_revoke_it():
    clock = Clock(T0)
    founder, host, stranger = Identity.generate(), Identity.generate(), Identity.generate()
    target = {"kind": "AGENT", "agent": host.agent("planner")}
    registry = revocation.Registry(lambda: founder.peer_id, lambda: GROUP)
    assert not registry.accept_signed(revocation.CREDENTIAL_STREAM,
                                      _signed_revocation(stranger, target, "retired", T0), T0)
    assert registry.accept_signed(revocation.CREDENTIAL_STREAM,
                                  _signed_revocation(founder, target, "retired", T0), T0)
    # A lower-ranked, newer statement never replaces the founder's.
    registry.accept_signed(revocation.CREDENTIAL_STREAM,
                           _signed_revocation(host, target, "key-compromise", T0 + 1000), T0)
    assert registry.credentials["AGENT:" + host.agent("planner")][3]["reason"] == "retired"
    # A peer revocation is the founder's alone.
    peer_ad = {"id": f"aspace://{GROUP}/revocation/{host.peer_id}", "issuer": founder.peer_id,
               "group": GROUP, "issued": instant_iso(T0), "ttl": "PT720H",
               "revoked": host.peer_id, "reason": "compromised", "successor": None}
    ad_bytes = cbor.dumps(peer_ad)
    assert registry.accept_signed(revocation.PEER_STREAM, {
        "adBytes": ad_bytes, "publicKey": founder.public_raw,
        "signature": founder.sign(ad_bytes)}, T0)
    assert registry.refuses(host.agent("anyone"), None, T0)


def test_the_keystore_matches_javas_layout_and_refuses_damage(tmp_path):
    first = Identity.load_or_create(str(tmp_path))
    assert Identity.load_or_create(str(tmp_path)).peer_id == first.peer_id
    key_file, pub_file = tmp_path / "peer.key", tmp_path / "peer.pub"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert pub_file.read_bytes() == first.public_raw
    agent = Identity.agent_keys(str(tmp_path / "agents"), first.peer_id, "planner")
    assert (tmp_path / "agents" / first.peer_id / "planner" / "agent.key").exists()
    assert Identity.agent_keys(str(tmp_path / "agents"), first.peer_id, "planner").public_raw \
        == agent.public_raw
    with pytest.raises(ValueError):
        Identity.agent_keys(str(tmp_path / "agents"), first.peer_id, "../escape")
    pub_file.write_bytes(Identity.generate().public_raw)
    with pytest.raises(ValueError, match="does not belong"):
        Identity.load_or_create(str(tmp_path))
    os.remove(pub_file)
    with pytest.raises(ValueError, match="does not"):
        Identity.load_or_create(str(tmp_path))


def _capture(peer) -> list:
    """Records what a socketless peer would send, as (kind, body) pairs."""
    sent = []
    peer._send = lambda kind, body: sent.append((kind, body))
    return sent


def test_a_pull_names_the_revocation_streams_and_a_join_pulls_them_once():
    import socket
    clock = Clock(T0)
    peer = _peer(clock)
    sent = _capture(peer)
    peer.pull_space("tasks")
    kind, body = sent[-1]
    assert kind == "DIGEST"
    assert cbor.loads(body)["digests"] == {
        "space:tasks": b"", "revocations": b"", "credential-revocations": b""}
    # A late joiner asks for the revocation streams as soon as it connects.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    sent.clear()
    try:
        peer.connect("127.0.0.1", server.getsockname()[1])
    finally:
        peer.close()
        server.close()
    digests = [cbor.loads(body)["digests"] for kind, body in sent if kind == "DIGEST"]
    assert digests == [{"revocations": b"", "credential-revocations": b""}]


def test_a_pull_response_carrying_a_credential_revocation_applies_it():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT24H", clock=clock)
    receiver = _peer(clock)
    signed = _signed_revocation(host, {"kind": "AGENT", "agent": agent.agent_id},
                                revocation.KEY_COMPROMISE, clock.millis)
    resp = cbor.dumps({"deltas": {revocation.CREDENTIAL_STREAM: cbor.dumps([signed])}})
    receiver._handle({"kind": "PULL_RESP", "body": resp,
                      "stamp": wire.hlc_now(host.peer_id, clock.millis)})
    assert receiver.revocations.refuses(agent.agent_id, agent.public_raw, clock.millis)
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 600_000,
                               agent=agent, now_ms=clock.millis)
    receiver._fold(_delta_state(body))
    assert receiver.states == {}


def test_a_peer_signed_renewal_after_the_effective_instant_is_not_merged():
    clock = Clock(T0)
    host = Identity.generate()
    writer = Peer(host, GROUP, clock=clock)
    entry_id, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 600_000,
                                      now_ms=clock.millis)
    original = _delta_state(body)
    writer.states[entry_id] = original
    receiver = _peer(clock)
    receiver._fold(original)
    clock.advance(60_000)
    retired_at = clock.millis
    assert receiver.revocations.accept_signed(revocation.CREDENTIAL_STREAM, _signed_revocation(
        host, {"kind": "AGENT", "agent": host.agent("x")}, "retired", retired_at, retired_at),
        clock.millis)
    clock.advance(60_000)
    sent = _capture(writer)
    writer.renew_entry("tasks", entry_id)
    renewal = _delta_state(sent[-1][1])
    assert renewal.get("signedAt") is None, "the peer signs its own renewal"
    receiver._fold(renewal)
    assert receiver.states[entry_id] == original, "the held state stays as held"
    # The original history still folds at a replica that learns it late.
    late = _peer(clock)
    late.revocations = receiver.revocations
    late._fold(original)
    assert late.states[entry_id] == original


def test_a_revoked_holders_completion_is_refused_though_its_claim_came_first():
    clock = Clock(T0)
    writer, host = Identity.generate(), Identity.generate()
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", writer, "w", 600_000,
                               now_ms=clock.millis)
    state = _delta_state(body)
    worker = host.renewing_subordinate("worker", "PT24H", clock=clock)
    claim = wire.take_claim(state["record"]["entryId"], state["record"]["spaceId"], 1,
                            wire.hlc_now(worker.agent_id, clock.millis), worker.agent_id, 0.0,
                            clock.millis + 600_000)
    receiver = _peer(clock)
    receiver._fold(state)
    receiver._fold_claim(claim["entryId"], wire.signed_claim(claim, host, worker))
    assert claim["entryId"] in receiver.claims
    clock.advance(60_000)
    assert receiver.revocations.accept_signed(revocation.CREDENTIAL_STREAM, _signed_revocation(
        host, {"kind": "AGENT", "agent": worker.agent_id}, "retired", clock.millis,
        clock.millis), clock.millis)
    clock.advance(60_000)
    receiver._fold(wire.sign_state({**state, "completed": True}, host, worker, clock.millis))
    assert not receiver.states[claim["entryId"]]["completed"]


def test_the_peer_clock_judges_skew_and_stamps_the_introduction():
    clock = Clock(T0)  # months behind wall time
    peer = _peer(clock)
    sent = _capture(peer)
    hostile = T0 + wire.MAX_HLC_SKEW_MILLIS + 60_000  # still behind wall time
    peer._handle({"kind": "PING", "body": wire.ping_body(1),
                  "stamp": f"{hostile}:0:{Identity.generate().peer_id}"})
    assert wire.hlc_physical(wire.hlc_now(peer.identity.peer_id, clock.millis)) == T0
    # A caller's clock ahead of wall time admits a stamp within skew of it.
    node, ahead = Identity.generate().peer_id, T0 + 10 * 365 * 86_400_000
    wire.hlc_observe(node, f"{ahead + 1000}:0:x", ahead)
    assert wire.hlc_physical(wire.hlc_now(node, ahead)) == ahead + 1000
    sent.clear()
    clock.advance(1234)
    peer.introduce()
    rumor = cbor.loads(sent[-1][1])
    assert rumor["itemId"] == f"peer:{peer.identity.peer_id}:{clock.millis}"
    ad = cbor.loads(cbor.loads(rumor["payload"])["adBytes"])
    assert ad["issued"] == instant_iso(clock.millis - clock.millis % 1000)


def test_save_pkcs8_writes_the_key_owner_only(tmp_path):
    identity = Identity.generate()
    path = tmp_path / "keys" / "peer.key"
    identity.save_pkcs8(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert Identity.from_pkcs8(path.read_bytes()).peer_id == identity.peer_id
    Identity.generate().save_pkcs8(str(path))  # an atomic replace
    assert Identity.from_pkcs8(path.read_bytes()).peer_id != identity.peer_id
    assert os.listdir(path.parent) == ["peer.key"], "no temporary file is left"


def test_an_agent_signed_renewal_folds_at_another_peer_with_a_later_lease():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT24H", clock=clock)
    writer = Peer(host, GROUP, clock=clock)
    entry_id, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 60_000,
                                      agent=agent, now_ms=clock.millis)
    original = _delta_state(body)
    writer.states[entry_id] = original
    receiver = _peer(clock)
    receiver._fold(original)
    clock.advance(30_000)
    sent = _capture(writer)
    writer.renew_entry("tasks", entry_id, 60_000, agent=agent)
    receiver._fold(_delta_state(sent[-1][1]))
    held = receiver.states[entry_id]
    assert held["leaseValue"]["expiresAtMillis"] == clock.millis + 60_000
    assert wire._hlc_tuple(held["leaseStamp"]) > wire._hlc_tuple(original["leaseStamp"])


def test_a_renewal_under_the_wrong_agent_raises_locally():
    clock = Clock(T0)
    host = Identity.generate()
    agent = host.renewing_subordinate("planner", "PT24H", clock=clock)
    sibling = host.renewing_subordinate("sibling", "PT24H", clock=clock)
    writer = Peer(host, GROUP, clock=clock)
    sent = _capture(writer)
    entry_id, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 60_000,
                                      agent=agent, now_ms=clock.millis)
    writer.states[entry_id] = _delta_state(body)
    with pytest.raises(ValueError, match="not"):
        writer.renew_entry("tasks", entry_id, agent=sibling)
    # Without an agent, only an entry this peer's own agent names wrote renews.
    foreign_id, foreign = wire.entry_delta("tasks", GROUP, "T#v1", b"\x02", Identity.generate(),
                                           "x", 60_000, now_ms=clock.millis)
    writer.states[foreign_id] = _delta_state(foreign)
    with pytest.raises(ValueError, match="not by this peer"):
        writer.renew_entry("tasks", foreign_id)
    assert sent == []


def test_a_state_whose_signed_at_is_not_a_stamp_is_judged_without_raising():
    clock = Clock(T0)
    host = Identity.generate()
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", b"\x01", host, "x", 600_000,
                               now_ms=clock.millis)
    state = _delta_state(body)
    record = state["record"]
    # Peer-signed (no signer) yet naming a signedAt: the signature covers it.
    view = wire.state_sign_view(record["spaceId"], record["entryId"], state["adds"],
                                state["removes"], state["leaseStamp"], state["leaseValue"],
                                False, None, "not-a-stamp")
    odd = {**state, "signedAt": "not-a-stamp", "stateSig": host.sign(cbor.dumps(view))}
    receiver = _peer(clock)
    receiver._fold(odd)
    assert len(receiver.states) == 1
