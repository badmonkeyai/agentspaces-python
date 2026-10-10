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
"""Layer 4 from Python without a socket (L3L4-COVERAGE.md §6.4): the
capability pipes between two peers on an in-memory network, push-sum and
rosters, the hashing embedder matching Java, semantic queries local and
remote, remote actions through a bound agent, and the estimate decorator."""

import threading
import time
from dataclasses import dataclass

from agentspaces import cbor, wire
from agentspaces.agents import Binder, agent, on_estimate, space_take
from agentspaces.capabilities import Aggregate, HashingEmbedder, Pipes, Semantic, Settle, actions, invoke
from agentspaces.capabilities.semantic import java_hash
from agentspaces.identity import Identity
from agentspaces.peer import Peer
from agentspaces.space import Space, Template, entry

GROUP = "zPythonLayer4"


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


@entry("com.acme.Report#v1")
@dataclass
class Report:
    epoch: str
    value: float


class Network:
    """Peers by id; an addressed frame goes to its peer, a rumor to every other."""

    def __init__(self):
        self.peers: dict[str, "NetPeer"] = {}

    def add(self, peer: "NetPeer"):
        self.peers[peer.identity.peer_id] = peer
        return peer


class NetPeer(Peer):
    def __init__(self, network: Network):
        super().__init__(Identity.generate(), GROUP)
        self.network = network
        self._running = True
        self._socket = object()
        network.add(self)

    def _send(self, kind, body, to=None):
        env = wire.envelope(self.group, kind, self.identity.peer_id,
                            wire.hlc_now(self.identity.peer_id, self._now_ms()), body, to)
        targets = [self.network.peers[to]] if to else [p for pid, p in self.network.peers.items()
                                                       if pid != self.identity.peer_id]
        for target in targets:
            if target._accepts(env):
                target._handle(env)
        # A rumor of our own folds here as well (gossip hands it back to us).
        if kind == "RUMOR" and to is None:
            rumor = cbor.loads(body)
            if str(rumor.get("streamId", "")).startswith("space:"):
                delta = cbor.loads(rumor["payload"])
                if delta.get("claimEntry") and isinstance(delta.get("claim"), dict):
                    self._fold_claim(delta["claimEntry"], delta["claim"])
                if isinstance(delta.get("state"), dict):
                    self._fold(delta["state"])

    def pull_space(self, space):
        pass

    def pull_revocations(self):
        pass


def _await(timeout, condition):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


def _fleet(n=2):
    network = Network()
    peers = [NetPeer(network) for _ in range(n)]
    for p in peers:
        p.introduce()  # each learns the others from the peers stream
    return peers


# ----------------------------------------------------------------- aggregate

def test_push_sum_converges_to_the_fleet_mean_and_rosters_count_members():
    a, b = _fleet()
    assert set(a.members) == {b.identity.peer_id} and set(b.members) == {a.identity.peer_id}
    agg_a, agg_b = Aggregate(Pipes(a)), Aggregate(Pipes(b))
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_a.start("n", 0.0, mode="count")
    agg_b.start("n", 0.0, mode="count")
    agg_a.start("peak", 10.0, mode="max")
    agg_b.start("peak", 30.0, mode="max")
    agg_a.start("total", 10.0, mode="sum")
    agg_b.start("total", 30.0, mode="sum")
    assert agg_a.estimate("load") is None  # nothing exchanged yet
    for _ in range(12):
        agg_a.tick()
        agg_b.tick()
    assert abs(agg_a.estimate("load") - 20.0) < 0.01 and abs(agg_b.estimate("load") - 20.0) < 0.01
    assert agg_a.estimate("n") == 2.0 and agg_b.estimate("n") == 2.0
    assert agg_a.estimate("peak") == 30.0 and agg_b.estimate("peak") == 30.0
    assert abs(agg_a.estimate("total") - 40.0) < 0.05
    # The share frames on the wire are the Java Frame union, plain doubles.
    frame = wire.aggregate_frame(share={"epochId": "load", "value": 5.0, "weight": 0.5})
    assert cbor.loads(cbor.dumps(frame))["share"]["weight"] == 0.5


def test_await_settled_and_on_estimate_fire_on_the_tick():
    a, b = _fleet()
    agg_a, agg_b = Aggregate(Pipes(a)), Aggregate(Pipes(b))
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    fired = []
    closer = agg_a.on_estimate(lambda e: e == "load", Settle.after(2, 0.01), lambda est: fired.append(est))
    agg_a.run(interval_seconds=0.05)
    agg_b.run(interval_seconds=0.05)
    try:
        settled = agg_a.await_settled("load", Settle.after(2, 0.01), timeout_seconds=10)
        assert settled is not None and abs(settled - 20.0) < 0.5
        assert _await(5, lambda: len(fired) == 1)
        time.sleep(0.3)
        assert len(fired) == 1 and fired[0].epoch_id == "load" and fired[0].ticks >= 3
        assert agg_a.await_settled("missing", Settle.FIRST, timeout_seconds=0.3) is None
    finally:
        closer()
        agg_a.close()
        agg_b.close()


# ------------------------------------------------------------------ semantic

def test_the_hashing_embedder_matches_java():
    assert java_hash("hello") == 99162322
    assert java_hash("") == 0
    assert java_hash("polygenelubricants") == -2147483648  # the int32 wrap
    e = HashingEmbedder()
    v = e.embed("Researches topics research com.acme.Task#v1")
    assert len(v) == 256 and abs(sum(x * x for x in v) - 1.0) < 1e-9
    assert e.embed(None) == [0.0] * 256
    # "hello" hashes to 99162322: bucket floorMod(99162322, 256), positive sign.
    assert e.embed("hello")[99162322 % 256] == 1.0


@agent("researcher", description="Researches topics and writes findings", goals=["research", "summarize"])
class Researcher:
    @space_take("tasks", lease="30s", poll_timeout="300ms", description="Researches one topic")
    def research(self, task: Task) -> Finding:
        return Finding(task.topic, "researched " + task.topic)


def test_semantic_queries_rank_cards_locally_and_fetch_them_remotely():
    a, b = _fleet()
    sem_a, sem_b = Semantic(Pipes(a)), Semantic(Pipes(b))
    bound = Binder(a).bind(Researcher())
    try:
        # A's card is in A's cache and reached B on the ads stream.
        assert [m.ad["agent"] for m in sem_a.query("research topics findings")] == [bound.card["agent"]]
        assert sem_b.query("research topics")[0].score > 0.2
        assert sem_a.query("quantum chromodynamics") == []
        # A newcomer with an empty cache learns the card through the query pipe.
        c = NetPeer(a.network)
        c.introduce()
        a.introduce()  # the group's members reach the newcomer on the peers stream
        b.introduce()
        sem_c = Semantic(Pipes(c))
        assert sem_c.query("research topics") == []
        hits = sem_c.remote_query("research topics", limit=5, timeout_seconds=2)
        assert [m.ad["agent"] for m in hits] == [bound.card["agent"]]
        assert c.cards()[0]["id"] == bound.card["id"]
    finally:
        bound.close()


# -------------------------------------------------------------------- remote

def test_a_remote_action_from_a_card_is_invoked_through_the_task_space():
    a, b = _fleet()
    researcher = Researcher()
    bound = Binder(a).bind(researcher)
    try:
        found = actions(b)
        assert [(x.name, x.consumes, x.produces, x.space) for x in found] == \
            [("research", "com.acme.Task#v1", "com.acme.Finding#v1", "tasks")]
        assert found[0].description == "Researches one topic"
        result = invoke(b, found[0], Task("crdts", 2), result_type=Finding, timeout_seconds=15)
        assert result == Finding("crdts", "researched crdts")
        # The result correlated on the shared field: a second call with another topic gets its own.
        assert invoke(b, found[0], Task("raft", 1), result_type=Finding, timeout_seconds=15) == Finding("raft", "researched raft")
    finally:
        bound.close()


# ------------------------------------------------------------ the decorator

@agent("supervisor")
class Supervisor:
    def __init__(self):
        self.reports = []

    @on_estimate("load", ticks=2, tolerance=0.01, result_space="reports")
    def settled(self, estimate) -> Report:
        self.reports.append(estimate)
        return Report(estimate.epoch_id, estimate.value)


def test_the_estimate_decorator_reacts_once_when_the_epoch_settles():
    a, b = _fleet()
    agg_a, agg_b = Aggregate(Pipes(a)), Aggregate(Pipes(b))
    supervisor = Supervisor()
    bound = Binder(a, publish_card=False, aggregate=agg_a).bind(supervisor)
    try:
        agg_a.start("load", 10.0)
        agg_b.start("load", 30.0)
        agg_a.run(0.05)
        agg_b.run(0.05)
        assert _await(10, lambda: Space(b, "reports").read_all(Template(Report)) != [])
        report = Space(b, "reports").read_all(Template(Report))[0]
        assert report.epoch == "load" and abs(report.value - 20.0) < 0.5
        time.sleep(0.3)
        assert len(supervisor.reports) == 1
    finally:
        bound.close()
        agg_a.close()
        agg_b.close()


# ---------------------------------------------------------- hardening (2026-10-09)

def test_shares_go_only_to_members_that_advertise_the_aggregate():
    a, b = _fleet()
    bystander = NetPeer(a.network)  # a member with no aggregate
    bystander.introduce()
    a.introduce()
    b.introduce()
    agg_a, agg_b = Aggregate(Pipes(a)), Aggregate(Pipes(b))
    assert sorted(agg_a.participants()) == [b.identity.peer_id]
    assert bystander.identity.peer_id in Pipes(a).members()
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    for _ in range(40):
        agg_a.tick()
        agg_b.tick()
    assert abs(agg_a.estimate("load") - 20.0) < 0.01 and abs(agg_b.estimate("load") - 20.0) < 0.01
    assert "load" not in Aggregate(Pipes(bystander), advertise=False).epochs()


def test_a_node_nobody_pushes_to_does_not_settle_and_a_lone_node_does():
    a, b, c = _fleet(3)
    agg_a, agg_b, agg_c = Aggregate(Pipes(a)), Aggregate(Pipes(b)), Aggregate(Pipes(c))
    # A pushes to B, B and C push to each other: nobody ever pushes to A.
    agg_a.participants = lambda: [b.identity.peer_id]
    agg_b.participants = lambda: [c.identity.peer_id]
    agg_c.participants = lambda: [b.identity.peer_id]
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_c.start("load", 20.0)
    fired_a, fired_b = [], []
    agg_a.on_estimate(lambda e: e == "load", Settle.after(2, 0.01), lambda est: fired_a.append(est.value))
    agg_b.on_estimate(lambda e: e == "load", Settle.after(2, 0.01), lambda est: fired_b.append(est.value))
    for _ in range(30):
        agg_a.tick()
        agg_b.tick()
        agg_c.tick()
    assert agg_a.estimate("load") == 10.0  # the hazard: stable by construction, far from the fleet
    assert _await(2, lambda: len(fired_b) == 1) and fired_a == []
    # A node with nobody to exchange with settles on its own ticks.
    lone = NetPeer(Network())
    agg = Aggregate(Pipes(lone))
    agg.start("load", 12.5)
    fired = []
    agg.on_estimate(lambda e: e == "load", Settle.after(2, 0.01), lambda est: fired.append(est.value))
    for _ in range(5):
        agg.tick()
    assert _await(2, lambda: fired == [12.5])
