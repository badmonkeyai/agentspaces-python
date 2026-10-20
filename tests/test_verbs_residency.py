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
"""The fleet verbs of srad/agentspaces-js.md JS-V-13 in Python: the leased
push subscription (JS-V-01), the fold-driven take that pulls at most once per
settle window (JS-V-02), MAJORITY_GOSSIP's preference epochs and their shares
over a fleet (JS-V-04), and the mixed-scheme fleet a tcp-only client still
reaches (JS-N-05)."""

import threading
import time
from dataclasses import dataclass

from agentspaces import beacon, cbor, vote, wire
from agentspaces.agents import Binder, agent, space_notify
from agentspaces.capabilities import Aggregate, Pipes
from agentspaces.identity import Identity, instant_iso, parse_instant_millis
from agentspaces.peer import Peer
from agentspaces.space import Space, Template, entry
from fleet import Clock, fleet, until

GROUP = "zPyVerbsResidency"
T0 = parse_instant_millis("2026-03-01T00:00:00Z")


@entry("com.acme.Task#v1")
@dataclass
class Task:
    topic: str
    priority: int


class CapturingPeer(Peer):
    """A peer whose sends are recorded, pulls included, and whose own claims
    stay local: what a take sends is what the seed would see."""

    def __init__(self, clock=None):
        super().__init__(Identity.generate(), GROUP, clock=clock)
        self.sent = []
        self._running = True
        self._socket = object()

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body))

    def pull_revocations(self):
        pass

    def digests(self) -> int:
        return sum(1 for kind, _ in self.sent if kind == "DIGEST")


def _written(other: Peer, space: str, payload: dict, into: Peer, lease_ms=600_000):
    """A write another peer made, folded here."""
    _, body = wire.entry_delta(space, GROUP, "com.acme.Task#v1", cbor.dumps(payload), other.identity, "writer",
                               lease_ms, now_ms=into._now_ms())
    into._fold(cbor.loads(cbor.loads(body)["payload"])["state"])


# ----------------------------------------------------------- JS-V-01: notify

def test_a_leased_subscription_lapses_unless_renewed():
    clock = Clock(T0)
    peer, other = CapturingPeer(clock), CapturingPeer(clock)
    space = Space(peer, "tasks")
    seen, closes = [], []
    short = space.notify(Template(Task), lambda e: seen.append(e.entry.value.topic), lease="150ms")
    renewed = space.notify(Template(Task), lambda e: None, lease="150ms")
    short.on_close(closes.append)
    _written(other, "tasks", {"topic": "one", "priority": 1}, peer)
    assert seen == ["one"]
    clock.advance(100)
    renewed.renew()
    clock.advance(100)
    assert until(2.0, lambda: not short.open), "the unrenewed subscription lapsed on the sweep"
    assert closes == ["lapsed"] and short.reason == "lapsed"
    assert renewed.open, "the renewed one is still open"
    _written(other, "tasks", {"topic": "two", "priority": 1}, peer)
    assert seen == ["one"], "a lapsed subscription delivers nothing"
    renewed.close()
    assert not renewed.open and renewed.reason == "closed"
    renewed.renew()  # a closed subscription stays closed
    assert not renewed.open
    # A plain watch has no lease and never lapses.
    watch = space.watch(Template(Task), lambda e: None)
    clock.advance(3_600_000)
    space._sweep()
    assert watch.open


@agent("auditor")
class Auditor:
    def __init__(self):
        self.seen = []

    @space_notify("tasks", lease="400ms")
    def audit(self, task: Task) -> None:
        self.seen.append(task.topic)


def test_the_binder_renews_its_notify_subscription_at_half_lease():
    peer, other = CapturingPeer(), CapturingPeer()
    space = Space(peer, "tasks")
    lone = space.notify(Template(Task), lambda e: None, lease="400ms")
    auditor = Auditor()
    bound = Binder(peer, publish_card=False).bind(auditor)
    subscription = bound._subscriptions[0]
    assert subscription.open
    time.sleep(1.0)  # past two leases: the binder's renewal kept its subscription alive
    assert subscription.open
    assert until(2.0, lambda: not lone.open) and lone.reason == "lapsed", "the unrenewed one lapsed"
    _written(other, "tasks", {"topic": "late", "priority": 1}, peer)
    assert until(2.0, lambda: auditor.seen == ["late"])
    bound.close()
    assert not subscription.open and subscription.reason == "closed"


# ------------------------------------------------- JS-V-02: fold-driven take

def test_a_waiting_take_pulls_at_most_once_per_settle_window_and_wakes_on_a_fold():
    peer, other = CapturingPeer(), CapturingPeer()
    space = Space(peer, "tasks")
    before = peer.digests()
    result = []
    started = time.monotonic()
    thread = threading.Thread(target=lambda: result.append(space.take(Template(Task), lease="1m", timeout="10s")),
                              daemon=True)
    thread.start()
    # While nothing folds, the take waits: a settle window (600 ms) passes with one DIGEST per window.
    time.sleep(1.3)
    while_waiting = peer.digests() - before
    assert 2 <= while_waiting <= 3, f"one pull per settle window, saw {while_waiting}"
    # The entry folds from another peer: the take wakes at once, claims, settles, and holds it.
    _written(other, "tasks", {"topic": "index", "priority": 5}, peer)
    thread.join(5.0)
    assert result and result[0] is not None, "taken after the fold"
    assert result[0].value.topic == "index"
    assert time.monotonic() - started < 5.0, "the take did not wait for its timeout"
    # After the fold: one claim went out, and at most one pull followed the settle window.
    claims = [body for kind, body in peer.sent if kind == "RUMOR" and cbor.loads(body)["itemId"].startswith("c:")]
    assert len(claims) == 1
    assert peer.digests() - before - while_waiting <= 1, "none while folds arrive, one after the settle window"


def test_a_read_with_a_timeout_wakes_on_the_fold_it_waits_for():
    peer, other = CapturingPeer(), CapturingPeer()
    space = Space(peer, "tasks")
    result = []
    started = time.monotonic()
    thread = threading.Thread(target=lambda: result.append(space.read(Template(Task), timeout="10s")), daemon=True)
    thread.start()
    time.sleep(0.2)
    _written(other, "tasks", {"topic": "now", "priority": 1}, peer)
    thread.join(5.0)
    assert result and result[0].topic == "now"
    assert time.monotonic() - started < 2.0
    assert space.read(Template(Task, where={"priority": 9}), timeout="300ms") is None


# ------------------------------------------------- JS-V-04: MAJORITY_GOSSIP

def test_majority_gossip_casts_over_the_votes_preference_epochs_and_reads_the_leader():
    started = {}

    class FakeAggregate:
        def start(self, epoch_id, value, mode="avg"):
            started[epoch_id] = value

        def estimate(self, epoch_id):
            return started.get(epoch_id)

    aggregate = FakeAggregate()
    vote.cast_preference(aggregate, "lunch", ["pizza", "sushi", "salad"], "sushi")
    assert list(started.items()) == [("vote:lunch:pizza", 0.0), ("vote:lunch:sushi", 1.0), ("vote:lunch:salad", 0.0)], \
        "VoteCapability.epoch names"
    assert vote.leader(aggregate, "lunch", ["pizza", "sushi", "salad"]) == "sushi"
    assert vote.leader(aggregate, "dinner", ["a"]) is None


def test_preference_shares_agree_across_a_fleet_and_travel_as_the_java_share_frame():
    options = ["pizza", "sushi", "salad"]
    # The first share a caster pushes is Java's PushSumAggregate.tick: half its mass, half its weight.
    a, b = fleet(GROUP, 2)
    agg_a = Aggregate(Pipes(a))
    Aggregate(Pipes(b))
    pushed = []
    agg_a.pipes.send = lambda to, capability, payload: pushed.append(cbor.loads(payload))
    vote.cast_preference(agg_a, "lunch", options, "sushi")
    agg_a.tick()
    shares = {f["share"]["epochId"]: f["share"] for f in pushed if "share" in f}
    assert shares[vote.preference_epoch("lunch", "sushi")] == {"epochId": "vote:lunch:sushi", "value": 0.5, "weight": 0.5}
    assert shares[vote.preference_epoch("lunch", "pizza")] == {"epochId": "vote:lunch:pizza", "value": 0.0, "weight": 0.5}
    # Over a fleet of three, two for sushi and one for pizza: every member's estimate is the share.
    peers = fleet(GROUP, 3)
    aggregates = [Aggregate(Pipes(p)) for p in peers]
    for aggregate, preference in zip(aggregates, ["sushi", "sushi", "pizza"]):
        vote.cast_preference(aggregate, "lunch", options, preference)
    for _ in range(30):
        for aggregate in aggregates:
            aggregate.tick()
    for aggregate in aggregates:
        assert abs(aggregate.estimate("vote:lunch:sushi") - 2 / 3) < 0.02
        assert abs(aggregate.estimate("vote:lunch:pizza") - 1 / 3) < 0.02
        assert abs(aggregate.estimate("vote:lunch:salad")) < 0.02
        assert vote.leader(aggregate, "lunch", options) == "sushi"


# ----------------------------------------------- JS-N-05: the mixed fleet

SCHEMES = ["wss", "webrtc", "https", "dtls", "ws", "http", "tcp"]


def test_a_fleet_advertising_every_scheme_still_works_with_the_tcp_only_client():
    """JS-N-05: members whose advertisements list ws, wss, http, https, webrtc, and dtls endpoints
    beside tcp are ordinary members to this client; it dials tcp alone and skips the rest."""
    python, *others = fleet(GROUP, 3)
    for i, member in enumerate(others):
        now_ms = member._now_ms()
        ad = wire.peer_advertisement(GROUP, member.identity, instant_iso(now_ms - now_ms % 1000))
        ad["endpoints"] = [{"transport": scheme, "address": f"10.0.0.{i + 1}:{7500 + n}", "priority": n}
                           for n, scheme in enumerate(SCHEMES)]
        python._accept_peer_ad(wire.signed_peer_ad(ad, member.identity))
    for member in others:
        endpoints = python.members[member.identity.peer_id]["endpoints"]
        assert [e["transport"] for e in endpoints] == SCHEMES
        dialable = beacon.seeds_of({"seeds": endpoints})
        assert len(dialable) == 1 and dialable[0][1] == 7506, "tcp alone is dialed"
    assert beacon.CLIENT_TRANSPORTS == ("tcp",)
    # The verbs run over whatever those members dial among themselves: a job a wss member
    # wrote is taken and completed here, and every member sees the completion.
    writer = others[0]
    job = writer.write_entry("jobs", "com.acme.Task#v1", {"topic": "mixed", "priority": 1})
    space = Space(python, "jobs")
    taken = space.take(Template(Task), lease="1m", timeout="5s")
    assert taken is not None and taken.entry_id == job
    taken.complete()
    assert all(m.states[job]["completed"] for m in others)
