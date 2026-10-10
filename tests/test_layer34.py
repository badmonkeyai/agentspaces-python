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
"""Layers 3 and 4 from Python without a socket (L3L4-COVERAGE.md §6.4): the
space verbs over typed entries, templates on fields and tags, events from
the fold, the decorated agent over a stubbed peer, ballots and decisions.
Deltas a second peer would send are folded directly, as the golden tests do."""

import threading
import time
from dataclasses import dataclass

from agentspaces import cbor, vote, wire
from agentspaces.agents import Binder, Decision, Proposal, agent, ballot, bid_function, on_decision, \
    space_notify, space_take
from agentspaces.identity import Identity
from agentspaces.peer import Peer
from agentspaces.space import COMPLETED, Space, TAKEN, TakeContext, Template, WRITTEN, contains, entry, gte, \
    in_, not_null

GROUP = "zPythonLayer34"


@entry("com.acme.Task#v1")
@dataclass
class Task:
    topic: str
    priority: int


@entry("com.acme.Finding#v1")
@dataclass
class Finding:
    topic: str
    summary: str


@entry("com.acme.Verdict#v1")
@dataclass
class Verdict:
    proposal_id: str
    winner: str


class StubPeer(Peer):
    """A peer whose sends are captured and whose own deltas fold locally, so a
    loop that writes, claims, and completes runs with no socket."""

    def __init__(self, identity=None):
        super().__init__(identity or Identity.generate(), GROUP)
        self.sent = []
        self._running = True
        self._socket = object()

    def _send(self, kind, body):
        self.sent.append((kind, body))
        if kind == "RUMOR":
            rumor = cbor.loads(body)
            if str(rumor.get("streamId", "")).startswith("space:"):
                delta = cbor.loads(rumor.get("payload") or b"\xf6")
                if isinstance(delta, dict):
                    if delta.get("claimEntry") and isinstance(delta.get("claim"), dict):
                        self._fold_claim(delta["claimEntry"], delta["claim"])
                    if isinstance(delta.get("state"), dict):
                        self._fold(delta["state"])

    def pull_space(self, space):
        pass

    def pull_revocations(self):
        pass


def _fold_from(other: Peer, space: str, schema: str, payload: dict, into: Peer, tags=None, lease_ms=600_000):
    """A write another peer made, folded here."""
    _, body = wire.entry_delta(space, GROUP, schema, cbor.dumps(payload), other.identity, "writer", lease_ms,
                               now_ms=into._now_ms(), tags=tags)
    into._fold(cbor.loads(cbor.loads(body)["payload"])["state"])


def _await(timeout, condition):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


# ----------------------------------------------------------------- templates

def test_templates_match_fields_and_tags_with_the_java_matcher_semantics():
    t = Template(Task, where={"priority": gte(3), "topic": contains("index")}, tags={"region": in_("eu", "uk")})
    assert t.schema == "com.acme.Task#v1"
    assert t.matches({"topic": "indexing", "priority": 3}, {"region": "eu"})
    assert not t.matches({"topic": "indexing", "priority": 2}, {"region": "eu"})
    assert not t.matches({"topic": "indexing", "priority": 3}, {"region": "us"})
    assert Template(Task, tags={"region": not_null()}).matches({}, {"region": "x"})
    assert not Template(Task, tags={"region": not_null()}).matches({}, {})
    assert Template(Task, where={"topic": "exact"}).matches({"topic": "exact"})
    assert Template(Task, where={"priority": lambda p: p % 2 == 1}).matches({"priority": 3})


# --------------------------------------------------------------- the space

def test_tags_ride_inside_the_signed_record_and_filter_reads():
    writer = StubPeer()
    reader = StubPeer()
    space = Space(writer, "tasks")
    space.write(Task("eu-task", 1), lease="10m", tags={"region": "eu"})
    space.write(Task("us-task", 2), lease="10m", tags={"region": "us"})
    # What the writer sent folds at a second peer with the signature over the tags intact.
    for kind, body in writer.sent:
        if kind == "RUMOR":
            delta = cbor.loads(cbor.loads(body)["payload"])
            reader._fold(delta["state"])
    assert len(reader.states) == 2
    view = Space(reader, "tasks")
    assert [t.topic for t in view.read_all(Template(Task, tags={"region": "eu"}))] == ["eu-task"]
    assert sorted(t.topic for t in view.read_all(Template(Task, tags={"region": not_null()}))) == ["eu-task", "us-task"]
    assert view.read(Template(Task, where={"priority": 2})).topic == "us-task"
    assert view.entries(Template(Task))[0].tags in ({"region": "eu"}, {"region": "us"})
    # A tampered tag breaks the signature and the record is dropped.
    _, body = wire.entry_delta("tasks", GROUP, "com.acme.Task#v1", cbor.dumps({"topic": "t", "priority": 1}),
                               writer.identity, "writer", 60_000, tags={"region": "eu"})
    state = cbor.loads(cbor.loads(body)["payload"])["state"]
    state["record"]["tags"] = {"region": "us"}
    before = len(reader.states)
    reader._fold(state)
    assert len(reader.states) == before


def test_take_completes_with_a_result_in_the_take_space_and_the_context_is_set():
    peer = StubPeer()
    other = StubPeer()
    _fold_from(other, "tasks", "com.acme.Task#v1", {"topic": "index", "priority": 5}, peer)
    space = Space(peer, "tasks")
    events = []
    space.watch(Template(Task), lambda e: events.append(e.kind))
    taken = space.take(Template(Task, where={"priority": gte(5)}), lease="1m", timeout="3s")
    assert taken is not None and taken.value.topic == "index"
    assert TakeContext.current() is None
    token = TakeContext.bind(taken)
    assert TakeContext.current() is taken
    TakeContext.unbind(token)
    result_id = taken.complete(Finding("index", "done"))
    assert result_id in peer.states
    assert peer.states[taken.entry_id]["completed"] is True
    assert space.read_all(Template(Finding))[0].summary == "done"
    assert space.read_all(Template(Task)) == []
    assert events == [TAKEN, COMPLETED]
    # Nothing left to take: the poll returns None at its timeout.
    assert space.take(Template(Task), timeout="1s") is None


def test_watch_delivers_each_entry_once_per_kind():
    peer = StubPeer()
    other = StubPeer()
    space = Space(peer, "tasks")
    seen = []
    sub = space.watch(Template(Task, tags={"region": "eu"}), lambda e: seen.append((e.kind, e.entry.value.topic)))
    _fold_from(other, "tasks", "com.acme.Task#v1", {"topic": "a", "priority": 1}, peer, tags={"region": "eu"})
    _fold_from(other, "tasks", "com.acme.Task#v1", {"topic": "b", "priority": 1}, peer, tags={"region": "us"})
    # A redelivery of the same state folds again and is not delivered twice.
    first = next(dto for dto in peer.states.values() if cbor.loads(dto["record"]["payload"])["topic"] == "a")
    peer._fold(dict(first))
    assert seen == [(WRITTEN, "a")]
    sub.close()
    _fold_from(other, "tasks", "com.acme.Task#v1", {"topic": "c", "priority": 1}, peer, tags={"region": "eu"})
    assert seen == [(WRITTEN, "a")]


# ----------------------------------------------------------------- the binder

@agent("researcher", description="Researches topics", goals=["research"])
class Researcher:
    def __init__(self):
        self.seen = []
        self.audited = []

    @space_take("tasks", lease="1m", poll_timeout="500ms", where={"priority": gte(1)})
    def research(self, task: Task) -> Finding:
        self.seen.append(task.topic)
        assert TakeContext.current() is not None
        return Finding(task.topic, "researched " + task.topic)

    @space_notify("tasks")
    def audit(self, finding: Finding) -> None:
        self.audited.append(finding.summary)
        return None

    @bid_function("tasks")
    def price(self, task: Task) -> float:
        return 1.0 if task.priority > 3 else 10.0


def test_a_decorated_agent_takes_notifies_bids_and_publishes_its_card():
    peer = StubPeer()
    other = StubPeer()
    binder = Binder(peer, agent=peer.identity.renewing_subordinate("py-worker", "PT24H"))
    researcher = Researcher()
    bound = binder.bind(researcher)
    try:
        assert bound.card["agent"].endswith("/py-worker")
        assert bound.card["description"] == "Researches topics" and bound.card["goals"] == ["research"]
        assert sorted(bound.card["consumes"]) == ["com.acme.Finding#v1", "com.acme.Task#v1"]
        assert bound.card["produces"] == ["com.acme.Finding#v1"]
        assert bound.card["spaceBindings"] == {"com.acme.Task#v1": "tasks"}
        assert [a["name"] for a in bound.card["actions"]] == ["audit", "research"]
        assert bound.card["agentCertificate"] is not None
        ads = [cbor.loads(body) for kind, body in peer.sent if kind == "RUMOR" and cbor.loads(body)["streamId"] == "ads"]
        assert len(ads) == 1 and cbor.loads(ads[0]["payload"])["adType"] == "AgentCard"
        _fold_from(other, "tasks", "com.acme.Task#v1", {"topic": "crdts", "priority": 5}, peer)
        assert _await(10, lambda: researcher.audited == ["researched crdts"])
        assert researcher.seen == ["crdts"]
        findings = Space(peer, "tasks").read_all(Template(Finding))
        assert [f.summary for f in findings] == ["researched crdts"]
        # The bid priced the claim: the signed claim carries 1.0 for priority 5.
        claims = [c for c in peer.claims.values()]
        assert claims and claims[0]["claim"]["bid"] == 1.0
        # The take and the result are the agent's own attested records.
        done = [dto for dto in peer.states.values() if dto.get("completed")]
        assert done and done[0].get("signer", "").endswith("/py-worker")
    finally:
        bound.close()


@agent("panelist", description="Votes", goals=["decide"])
class Panelist:
    def __init__(self):
        self.decided = []

    @ballot("votes", prefix="rel:")
    def judge(self, proposal: Proposal) -> str | None:
        return "yes" if "ship" in proposal.question else None

    @on_decision("votes", prefix="rel:", result_space="ledger")
    def record(self, decision: Decision) -> Verdict:
        self.decided.append(decision.proposal_id)
        return Verdict(decision.proposal_id, decision.winner)


def test_a_ballot_casts_once_per_proposal_and_a_decision_fires_once_at_quorum():
    peer = StubPeer()
    other = StubPeer()
    panelist = Panelist()
    bound = Binder(peer, publish_card=False).bind(panelist)
    try:
        # Another peer opens two proposals; the prefix admits one, the question decides the option.
        vote.propose(other, "votes", "rel:1", "ship 1.0?", ["yes", "no"], 2)
        for kind, body in other.sent:
            peer._fold(cbor.loads(cbor.loads(body)["payload"])["state"])
        other.sent.clear()
        vote.propose(other, "votes", "ops:2", "ship?", ["yes", "no"], 1)
        for kind, body in other.sent:
            peer._fold(cbor.loads(cbor.loads(body)["payload"])["state"])
        assert _await(5, lambda: vote.tally(peer.states, "rel:1").get("yes") == 1)
        assert vote.ballots(peer.states, "ops:2") == []
        assert vote.decision(peer.states, "rel:1") is None
        # The other peer's ballot closes the quorum; the decision fires once and writes the verdict.
        other.sent.clear()
        vote.cast(other, "votes", "rel:1", "no")
        for kind, body in other.sent:
            peer._fold(cbor.loads(cbor.loads(body)["payload"])["state"])
        assert _await(5, lambda: panelist.decided == ["rel:1"])
        decided = vote.decision(peer.states, "rel:1")
        assert decided["winner"] == "no" and decided["tally"] == {"yes": 1, "no": 1}
        assert _await(5, lambda: Space(peer, "ledger").read_all(Template(Verdict)) != [])
        assert Space(peer, "ledger").read_all(Template(Verdict))[0].winner == "no"
        # A redelivered ballot does not fire the decision again.
        for dto in list(peer.states.values()):
            peer._fold(dict(dto))
        time.sleep(0.3)
        assert panelist.decided == ["rel:1"]
        # A second proposal under the prefix is judged again, independently.
        vote.propose(other, "votes", "rel:2", "hold?", ["yes", "no"], 1)
        for kind, body in other.sent[-1:]:
            peer._fold(cbor.loads(cbor.loads(body)["payload"])["state"])
        time.sleep(0.3)
        assert vote.ballots(peer.states, "rel:2") == []
    finally:
        bound.close()
