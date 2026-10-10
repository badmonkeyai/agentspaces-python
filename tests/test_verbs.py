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
"""The 0.3.0 return conventions and cues from Python (L3L4-COVERAGE.md §6.4,
ISSUE-WorkflowVerbs, ISSUE-Motion, ISSUE-Propose, issue #16): a tagged
result, the fork, a motion opening a vote, the propose cue once per key, and
the LOCAL join firing once per key when every required part is present."""

import time
from dataclasses import dataclass

from agentspaces import cbor, vote, wire
from agentspaces.agents import Binder, Joined, Part, agent, propose, space_join, space_notify, space_take
from agentspaces.identity import Identity
from agentspaces.peer import Peer
from agentspaces.space import Motion, Space, Tagged, Template, entry

GROUP = "zPythonVerbs"


@entry("com.acme.Claim#v1")
@dataclass
class Claim:
    claim_id: str
    amount: int


@entry("com.acme.Fraud#v1")
@dataclass
class Fraud:
    claim_id: str
    score: int


@entry("com.acme.Coverage#v1")
@dataclass
class Coverage:
    claim_id: str
    covered: bool


@entry("com.acme.Assessment#v1")
@dataclass
class Assessment:
    claim_id: str
    verdict: str


class StubPeer(Peer):
    def __init__(self):
        super().__init__(Identity.generate(), GROUP)
        self.sent = []
        self._running = True
        self._socket = object()

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body))
        if kind == "RUMOR":
            rumor = cbor.loads(body)
            if str(rumor.get("streamId", "")).startswith("space:"):
                delta = cbor.loads(rumor.get("payload") or b"\xf6")
                if delta.get("claimEntry") and isinstance(delta.get("claim"), dict):
                    self._fold_claim(delta["claimEntry"], delta["claim"])
                if isinstance(delta.get("state"), dict):
                    self._fold(delta["state"])

    def pull_space(self, space):
        pass

    def pull_revocations(self):
        pass


def _fold_from(other, space, schema, payload, into, tags=None):
    _, body = wire.entry_delta(space, GROUP, schema, cbor.dumps(payload), other.identity, "writer", 600_000,
                               now_ms=into._now_ms(), tags=tags)
    into._fold(cbor.loads(cbor.loads(body)["payload"])["state"])


def _await(timeout, condition):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


@agent("assessor")
class Assessor:
    @space_notify("claims")
    def tag(self, claim: Claim) -> Tagged:
        return Tagged(Assessment(claim.claim_id, "tagged"), {"region": "eu"})

    @space_take("intake", poll_timeout="300ms", result_space="fanout")
    def fork(self, claim: Claim) -> list:
        return [Fraud(claim.claim_id, 1), Coverage(claim.claim_id, True)]

    @space_take("motions", poll_timeout="300ms")
    def move(self, claim: Claim) -> Motion:
        return Motion("claim:" + claim.claim_id, "pay " + claim.claim_id + "?", ["yes", "no"], 2)


def test_tagged_fork_and_motion_returns_dispatch_as_java_does():
    peer, other = StubPeer(), StubPeer()
    bound = Binder(peer, publish_card=False, vote_space="votes").bind(Assessor())
    try:
        _fold_from(other, "claims", "com.acme.Claim#v1", {"claim_id": "c1", "amount": 5}, peer)
        assert _await(5, lambda: Space(peer, "claims").entries(Template(Assessment)) != [])
        e = Space(peer, "claims").entries(Template(Assessment))[0]
        assert e.value.verdict == "tagged" and e.tags == {"region": "eu"}
        _fold_from(other, "intake", "com.acme.Claim#v1", {"claim_id": "c2", "amount": 7}, peer)
        assert _await(10, lambda: Space(peer, "fanout").read_all(Template(Fraud)) != []
                      and Space(peer, "fanout").read_all(Template(Coverage)) != [])
        assert peer.states and any(dto.get("completed") for dto in peer.states.values())
        _fold_from(other, "motions", "com.acme.Claim#v1", {"claim_id": "c3", "amount": 9}, peer)
        assert _await(10, lambda: "claim:c3" in vote.proposals(peer.states))
        assert vote.proposals(peer.states)["claim:c3"]["question"] == "pay c3?"
    finally:
        bound.close()


@agent("lead")
class Lead:
    def __init__(self):
        self.asked = []

    @propose("claims", vote="votes", options=["approve", "deny"], quorum=2, prefix="claim:", key=["claim_id"])
    def ask(self, claim: Claim) -> str | None:
        self.asked.append(claim.claim_id)
        return None if claim.amount == 0 else f"approve claim {claim.claim_id}?"


def test_a_propose_cue_opens_one_vote_per_key():
    peer, other = StubPeer(), StubPeer()
    lead = Lead()
    bound = Binder(peer, publish_card=False).bind(lead)
    try:
        _fold_from(other, "claims", "com.acme.Claim#v1", {"claim_id": "c1", "amount": 5}, peer)
        assert _await(5, lambda: "claim:c1" in vote.proposals(peer.states))
        proposal = vote.proposals(peer.states)["claim:c1"]
        assert proposal["question"] == "approve claim c1?" and proposal["options"] == ["approve", "deny"]
        assert proposal["quorum"] == 2
        # A second cue of the same key asks nothing more; a zero amount asks nothing at all.
        _fold_from(other, "claims", "com.acme.Claim#v1", {"claim_id": "c1", "amount": 6}, peer)
        _fold_from(other, "claims", "com.acme.Claim#v1", {"claim_id": "c2", "amount": 0}, peer)
        time.sleep(0.5)
        assert lead.asked == ["c1", "c2"]
        assert set(vote.proposals(peer.states)) == {"claim:c1"}
    finally:
        bound.close()


@agent("assembler")
class Assembler:
    def __init__(self):
        self.fired = []

    @space_join("intake", key="claim_id", parts=[Part(Fraud), Part(Coverage), Part(Claim, optional=True)],
                result_space="assessments")
    def assemble(self, j: Joined) -> Assessment:
        self.fired.append(j.key)
        verdict = "pay" if j.get(Coverage).covered and j.get(Fraud).score < 5 else "hold"
        return Assessment(j.key, verdict + ("" if j.has(Claim) else " (no claim)"))


def test_a_local_join_fires_once_per_key_when_every_required_part_is_present():
    peer, other = StubPeer(), StubPeer()
    assembler = Assembler()
    bound = Binder(peer, publish_card=False).bind(assembler)
    try:
        _fold_from(other, "intake", "com.acme.Fraud#v1", {"claim_id": "c1", "score": 1}, peer)
        time.sleep(0.3)
        assert assembler.fired == []
        _fold_from(other, "intake", "com.acme.Coverage#v1", {"claim_id": "c1", "covered": True}, peer)
        assert _await(5, lambda: Space(peer, "assessments").read_all(Template(Assessment)) != [])
        assert Space(peer, "assessments").read_all(Template(Assessment))[0] == Assessment("c1", "pay (no claim)")
        # A late optional part does not fire the key again; another key fires on its own.
        _fold_from(other, "intake", "com.acme.Claim#v1", {"claim_id": "c1", "amount": 3}, peer)
        _fold_from(other, "intake", "com.acme.Coverage#v1", {"claim_id": "c2", "covered": False}, peer)
        _fold_from(other, "intake", "com.acme.Fraud#v1", {"claim_id": "c2", "score": 9}, peer)
        assert _await(5, lambda: len(Space(peer, "assessments").read_all(Template(Assessment))) == 2)
        time.sleep(0.3)
        assert sorted(assembler.fired) == ["c1", "c2"]
        assert {a.claim_id: a.verdict for a in Space(peer, "assessments").read_all(Template(Assessment))} == \
            {"c1": "pay (no claim)", "c2": "hold (no claim)"}
    finally:
        bound.close()


# -------------------------------------------- notify kinds, contribution, produces

from agentspaces.capabilities import Aggregate, Pipes
from agentspaces.space import COMPLETED, Contribution, EXPIRED, REAPPEARED, WRITTEN


@agent("watcher")
class Watcher:
    def __init__(self):
        self.kinds = []

    @space_notify("timers", on=[WRITTEN, EXPIRED, REAPPEARED, COMPLETED])
    def seen(self, claim: Claim) -> None:
        self.kinds.append(claim.claim_id)
        return None


def test_a_notify_reacts_to_several_kinds_including_expired_and_reappeared():
    peer, other = StubPeer(), StubPeer()
    watcher = Watcher()
    kinds = []
    space = Space(peer, "timers")
    space.watch(Template(Claim), lambda e: kinds.append((e.kind, e.entry.value.claim_id)))
    bound = Binder(peer, publish_card=False).bind(watcher)
    try:
        # A short write lease lapses: EXPIRED fires once, the timer pattern.
        _, body = wire.entry_delta("timers", GROUP, "com.acme.Claim#v1", cbor.dumps({"claim_id": "t1", "amount": 1}),
                                   other.identity, "writer", 400, now_ms=peer._now_ms())
        peer._fold(cbor.loads(cbor.loads(body)["payload"])["state"])
        assert _await(3, lambda: (EXPIRED, "t1") in kinds)
        time.sleep(0.6)
        assert kinds.count((EXPIRED, "t1")) == 1
        # A take claim that lapses: REAPPEARED fires once per lapsed claim.
        _fold_from(other, "timers", "com.acme.Claim#v1", {"claim_id": "t2", "amount": 2}, peer)
        taken = space.take(Template(Claim, where={"claim_id": "t2"}), lease="400ms", timeout="3s")
        assert taken is not None
        assert _await(3, lambda: (REAPPEARED, "t2") in kinds)
        time.sleep(0.6)
        assert kinds.count((REAPPEARED, "t2")) == 1
        assert _await(3, lambda: watcher.kinds.count("t2") == 2)  # WRITTEN and REAPPEARED; TAKEN is not wanted
    finally:
        bound.close()


@agent("sensor")
class Sensor:
    @space_take("readings", poll_timeout="300ms", produces=[Fraud, Coverage])
    def sense(self, claim: Claim) -> Contribution:
        return Contribution("load", float(claim.amount))


def test_a_contribution_return_starts_the_epoch_and_produces_names_the_card_types():
    peer, other = StubPeer(), StubPeer()
    aggregate = Aggregate(Pipes(peer))
    bound = Binder(peer, aggregate=aggregate).bind(Sensor())
    try:
        assert bound.card["produces"] == ["com.acme.Fraud#v1", "com.acme.Coverage#v1"]
        _fold_from(other, "readings", "com.acme.Claim#v1", {"claim_id": "r1", "amount": 12}, peer)
        assert _await(10, lambda: "load" in aggregate.epochs())
        assert any(dto.get("completed") for dto in peer.states.values())
    finally:
        bound.close()
