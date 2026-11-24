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
"""The Python client's half of the core's event-loop program (SPEC v0.1.36; srad/agentspaces-event-loop.md,
srad/agentspaces-event-loop-parity-notes.md; .parity-wt/PARITY-python.md lists the rows).

Every test runs on a virtual or pinned clock: nothing here waits out a real timer. A test that hands work
to a thread (the sweep, the aggregate's rounds) waits only for that thread to answer, which takes
milliseconds."""

import logging
import threading
import time
from dataclasses import dataclass

import pytest

from agentspaces import cbor, wire
from agentspaces.agents import Binder, agent, on_estimate, space_notify
from agentspaces.capabilities import Aggregate, Pipes, Settle
from agentspaces.capabilities.aggregate import ROUND_PERIOD_S
from agentspaces.identity import Identity, parse_instant_millis
from agentspaces.peer import KEEPALIVE_TTL_MS, REOFFER_MAX, Peer
from agentspaces.seed import Seed
from agentspaces.space import EXPIRED, Space, Taken, Template, entry
from agentspaces.timesource import SystemTime, VirtualTime, wait_until
from agentspaces.ttl import OVERRIDDEN, REFUSED, WARNED, TtlFloor, TtlFloorError
from agentspaces.watchdog import Watchdog
from test_hlc_logical_limit import GROUP, T, _write
from fleet import Clock
from test_hlc_round_four import Link

TYPE = "T#v1"


class _Socket:
    def close(self):
        pass


class VPeer(Peer):
    """A peer on a time source with its frames captured, as if linked: running, with a socket."""

    def __init__(self, source=None, clock=None, identity=None):
        super().__init__(identity or Identity.generate(), GROUP, clock=clock, time_source=source)
        self.sent = []
        self.sent_event = threading.Event()
        self._running = True
        self._socket = _Socket()

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body, to))
        self.sent_event.set()


def _until(condition, seconds=2.0) -> bool:
    """Waits for another thread's answer (not a timer): polls ``condition`` for up to ``seconds``."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.002)
    return condition()


def _frame(sender: Identity, receiver: Peer, kind: str, body: bytes, to=None, logical=1) -> bytes:
    stamp = f"{receiver._now_ms()}:{logical}:{sender.peer_id}"
    return wire.encode_frame(wire.envelope(GROUP, kind, sender.peer_id, stamp, body, to), sender)


def _peer_ads(peer: VPeer) -> list:
    """The self-advertisements a peer sent: (item id, advertisement)."""
    out = []
    for kind, body, _ in peer.sent:
        if kind != "RUMOR":
            continue
        rumor = cbor.loads(body)
        if rumor["streamId"] == "peers":
            out.append((rumor["itemId"], wire.decode_signed_peer_ad(rumor["payload"])))
    return out


# --------------------------------------------------- answer every PING, to its prober

def test_a_ping_from_the_seed_is_acknowledged_to_the_seed_with_its_nonce():
    me, seed = VPeer(VirtualTime(start_wall_ms=T)), Identity.generate()
    me._seed = Seed("seed", 1, "tcp")
    nonce = (1 << 62) + 12345  # Java's probe nonces are random longs past 2^53
    me._receive(_frame(seed, me, "PING", wire.ping_body(nonce), me.identity.peer_id))
    acks = [(body, to) for kind, body, to in me.sent if kind == "ACK"]
    assert len(acks) == 1
    body, to = acks[0]
    assert to == seed.peer_id, "addressed to the prober, as Java answers send(group, from, ACK)"
    assert cbor.loads(body)["nonce"] == nonce


def test_a_relayed_ping_is_acknowledged_back_through_the_seed_to_its_origin():
    me, seed, origin = VPeer(VirtualTime(start_wall_ms=T)), Identity.generate(), Identity.generate()
    me._seed = Seed("seed", 1, "tcp")
    me._receive(_frame(seed, me, "PING", wire.ping_body(1), me.identity.peer_id))  # the seed is known
    me.sent.clear()
    inner = _frame(origin, me, "PING", wire.ping_body(77), me.identity.peer_id)
    me._receive(_frame(seed, me, "RELAY_FRAME", wire.relay_frame_body(me.identity.peer_id, inner),
                       me.identity.peer_id, logical=2))
    assert [kind for kind, _, _ in me.sent] == ["RELAY_FRAME"], "not an ACK to the seed, which never asked"
    _, body, to = me.sent[0]
    assert to == seed.peer_id
    relay = cbor.loads(body)
    assert relay["target"] == origin.peer_id
    ack = wire.decode_frame(relay["frame"])
    assert ack["kind"] == "ACK" and ack["from"] == me.identity.peer_id and ack["to"] == origin.peer_id
    assert cbor.loads(ack["body"])["nonce"] == 77


# --------------------------------------------- relay.via names the member this peer dialled

def test_a_tls_link_names_its_attested_seed_in_the_first_introduction():
    me = VPeer(VirtualTime(start_wall_ms=T))
    seed = Identity.generate()
    me._attested = seed.peer_id
    me._note_dialled(Seed("s", 1, "tls"))
    me.introduce()
    (_, ad), = _peer_ads(me)
    assert ad["resourceHints"]["relay.via"] == seed.peer_id and me.seed_peer == seed.peer_id


def test_a_failover_to_another_tcp_seed_names_no_holder_until_the_new_seed_speaks():
    vt = VirtualTime(start_wall_ms=T)
    me, first, second = VPeer(vt), Identity.generate(), Identity.generate()
    me._seed = a = Seed("a", 1, "tcp")
    me._receive(_frame(first, me, "PING", wire.ping_body(1), me.identity.peer_id))
    assert me.resource_hints["relay.via"] == first.peer_id
    me._note_dialled(a)  # the same seed again: the hint stands
    assert me.resource_hints["relay.via"] == first.peer_id
    me._seed = b = Seed("b", 2, "tcp")
    me._note_dialled(b)
    assert "relay.via" not in me.resource_hints and me.seed_peer is None, \
        "a member this peer holds no link to is not named"
    me.introduce()
    vt.advance(0.001)
    me._receive(_frame(second, me, "ACK", wire.ack_body(1), me.identity.peer_id))
    ads = _peer_ads(me)
    assert ads[-1][1]["resourceHints"]["relay.via"] == second.peer_id and me.seed_peer == second.peer_id


# ---------------------------------------------- a changed self-advertisement is never lost

def test_a_changed_self_advertisement_in_the_same_millisecond_takes_a_new_item_and_a_later_instant():
    me = VPeer(clock=Clock(T + 400))  # a pinned clock: every introduction lands in one millisecond
    me.introduce()
    me.resource_hints["relay.via"] = "zSeed"
    me.introduce()
    me.introduce()  # the same content again
    (i1, a1), (i2, a2), (i3, a3) = _peer_ads(me)
    assert len({i1, i2, i3}) == 3, "a receiver never drops a new advertisement as a copy of the last"
    t1, t2, t3 = (parse_instant_millis(a["issued"]) for a in (a1, a2, a3))
    assert t1 == T and t2 == T + 1, "the changed advertisement is issued after the one before it"
    assert t3 == t2, "the same content keeps its instant"
    assert a2["resourceHints"]["relay.via"] == "zSeed"


def test_a_changed_advertisement_published_in_the_same_second_is_issued_a_millisecond_later():
    me = VPeer(clock=Clock(T))
    ad = {"id": f"aspace://{GROUP}/cap/x/{me.identity.peer_id}", "issuer": me.identity.peer_id, "group": GROUP,
          "issued": "2027-01-15T08:00:00Z", "ttl": "PT15M", "capabilityType": "aspace:cap/x", "version": "0.1",
          "binding": "pipe", "parameters": {"k": "1"}, "costHints": {}}
    first = me.publish_ad("CapabilityAdvertisement", ad)
    again = me.publish_ad("CapabilityAdvertisement", ad)
    changed = me.publish_ad("CapabilityAdvertisement", {**ad, "parameters": {"k": "2"}})
    assert first["issued"] == again["issued"] == ad["issued"]
    assert parse_instant_millis(changed["issued"]) == parse_instant_millis(ad["issued"]) + 1
    held = me.ads[ad["id"]]["ad"]
    assert held["parameters"] == {"k": "2"}, "this peer's own cache, which keeps a strictly newer one, holds it"


# --------------------------------------------------------------- the time source

def test_virtual_time_wakes_a_waiter_when_it_passes_the_deadline_and_never_before():
    vt = VirtualTime()
    condition = threading.Condition()
    done = threading.Event()
    result = []

    def waiter():
        with condition:
            result.append(wait_until(vt, condition, lambda: False, 10.0))
        done.set()

    threading.Thread(target=waiter, daemon=True).start()
    vt.advance(9.0)
    assert not done.wait(0.05)
    vt.advance(1.0)
    assert done.wait(2.0) and result == [False]
    sleeper = threading.Thread(target=vt.sleep, args=(3.0,), daemon=True)
    sleeper.start()
    vt.advance(3.0)
    sleeper.join(2.0)
    assert not sleeper.is_alive()


def test_the_system_time_source_reads_the_process_clocks():
    source = SystemTime()
    assert abs(source.wall_ms() - time.time() * 1000) < 1000
    assert source.monotonic() <= time.monotonic()
    assert source.wait(threading.Condition(), 0) is False


# ------------------------------------------------------------ the sweep as due work

def test_the_sweep_waits_for_the_next_lapse_and_raises_expired_when_virtual_time_reaches_it():
    vt = VirtualTime(start_wall_ms=T)
    peer, host = VPeer(vt), Identity.generate()
    space = Space(peer, "tasks")
    expired = threading.Event()
    space.watch(Template(TYPE), lambda e: e.kind == EXPIRED and expired.set())
    Link(host, peer).rumor(_write(host, T, lease_millis=5_000))
    sweeper = peer._sweeper
    assert abs(sweeper.next_wait() - 5.0) < 1e-6, "it sleeps to the lapse, not for 250 ms"
    vt.advance(4.0)
    assert abs(sweeper.next_wait() - 1.0) < 1e-6 and not expired.is_set()
    vt.advance(1.0)
    assert expired.wait(2.0), "the advance woke the sweep at the lapse"


def test_with_nothing_due_the_sweep_waits_for_its_backstop_and_a_burst_of_changes_wakes_it_once():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    Space(peer, "tasks")
    sweeper = peer._sweeper
    assert sweeper.next_wait() == pytest.approx(30.0)
    vt.advance(0.25)
    assert _until(lambda: sweeper.runs >= 2)
    vt.advance(1.0)  # a while since the last run
    runs = sweeper.runs
    for _ in range(200):
        peer._wake_fold_waiters()  # a pull that folds 200 states
    assert _until(lambda: sweeper.runs >= runs + 1), "the first change runs it at once"
    vt.advance(0.25)
    vt.advance(0.25)
    assert _until(lambda: sweeper.runs >= runs + 1)
    assert not _until(lambda: sweeper.runs > runs + 2, 0.05), "a burst costs at most two runs, not one per fold"
    settled = sweeper.runs
    vt.advance(29.0)
    assert not _until(lambda: sweeper.runs > settled, 0.05), "and nothing runs before the backstop"
    vt.advance(1.0)
    assert _until(lambda: sweeper.runs == settled + 1)


def test_the_next_collection_is_a_held_states_horizon():
    vt = VirtualTime(start_wall_ms=T)
    peer, host = VPeer(vt), Identity.generate()
    write = _write(host, T, lease_millis=5_000)
    Link(host, peer).rumor(write)
    due = peer.next_collection_ms()
    assert due is not None and due >= T + 5_000, "never before the lease lapses"
    vt.advance((due - T) / 1000)
    peer._collected_at = None
    assert write["record"]["entryId"] in peer.collect_tombstones(), "collected at the deadline it named"


def test_the_sweep_ends_when_the_peer_closes_and_lives_through_a_lost_socket():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    Space(peer, "tasks")
    sweeper = peer._sweeper
    peer._socket = None  # a lost link: not a closed peer
    peer._wake_fold_waiters()
    vt.advance(0.25)
    assert _until(lambda: sweeper.runs >= 2) and sweeper.alive()
    peer.close()
    assert _until(lambda: not sweeper.alive())


# -------------------------------------------------- local periods judged on monotonic time

def test_a_subscription_lease_moves_with_a_wall_step_and_lapses_on_its_length():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    space = Space(peer, "tasks")
    sub = space.notify(Template(TYPE), lambda e: None, lease="10m")
    vt.step_wall(3_600_000)  # an hour's suspend, or NTP: the wall clock alone moves
    space._sweep()
    assert sub.open, "a step of the wall clock does not lapse a local lease"
    assert peer.wall_steps == 1
    vt.advance(599)
    space._sweep()
    assert sub.open
    vt.advance(2)
    space._sweep()
    assert not sub.open and sub.reason == "lapsed"


def test_a_peer_with_a_bare_wall_clock_judges_no_wall_steps():
    clock = Clock(T)
    peer = VPeer(clock=clock)
    space = Space(peer, "tasks")
    sub = space.notify(Template(TYPE), lambda e: None, lease="10m")
    peer._judge_wall_step()
    clock.advance(3_600_000)
    peer._judge_wall_step()
    space._sweep()
    assert peer.wall_steps == 0 and not sub.open, "the clock the test pins is the clock the lease reads"


# ----------------------------------------------------- the resume after a suspend

def test_a_forward_wall_step_past_the_keepalive_introduces_the_peer_again_and_pulls():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._pulled_spaces.add("tasks")
    peer._judge_wall_step()
    vt.step_wall(KEEPALIVE_TTL_MS - 5_000)
    peer._judge_wall_step()
    assert peer.wall_steps == 1 and peer.resumes == 0, "a short step re-judges deadlines, nothing more"
    vt.step_wall(KEEPALIVE_TTL_MS + 1)
    peer._judge_wall_step()
    assert peer.resumes == 1
    assert _until(lambda: len(_peer_ads(peer)) == 1 and any(kind == "DIGEST" for kind, _, _ in peer.sent))
    (_, ad), = _peer_ads(peer)
    assert parse_instant_millis(ad["issued"]) >= T + 2 * KEEPALIVE_TTL_MS - 5_000 - 1_000, \
        "issued after any drop, so a member that dropped it admits it again"


# --------------------------------------------------------------------- the watchdog

def test_the_watchdog_starts_a_dead_reader_again():
    peer = VPeer(VirtualTime(start_wall_ms=T))
    peer._seed = Seed("seed", 1, "tcp")
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    peer._reader = dead
    started, stop = threading.Event(), threading.Event()
    peer._read_loop = lambda: (started.set(), stop.wait(5.0))
    dog = Watchdog()
    dog.watch(peer)
    try:
        dog.check()
        assert peer.reader_restarts == 1 and started.wait(2.0)
        dog.check()
        assert peer.reader_restarts == 1, "a live reader is left alone"
    finally:
        stop.set()


def test_the_watchdog_names_a_wedged_frame_once_and_the_reader_counts_slow_frames(caplog):
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._frame_started, peer._frame_kind = vt.monotonic(), "RUMOR"
    vt.advance(6.0)
    with caplog.at_level(logging.WARNING, logger="agentspaces.peer"):
        peer._watch()
        peer._watch()
    assert peer.frames_wedged == 1 and "RUMOR frame has held the reader" in caplog.text
    peer._frame_done()
    assert peer.slow_frames == {"RUMOR": 1} and peer.loop_health()["frameInHand"] == ""


def test_the_watchdog_starts_a_dead_sweep_again_and_ignores_a_closed_peer():
    peer = VPeer(VirtualTime(start_wall_ms=T))
    Space(peer, "tasks")
    sweeper = peer._sweeper
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    original = sweeper._thread
    sweeper._thread = dead
    peer._watch()
    assert sweeper.restarts == 1 and sweeper.alive()
    original.join(0)  # the first thread still runs; both end with the peer
    peer.close()
    dog = Watchdog()
    dog.watch(peer)
    assert dog.watched() == []


# ----------------------------------------- the settle guarantee's second rule, losing side

class _BothClocks:
    """A pinned wall clock (``clock``, which the certificates read) and a virtual monotonic clock (``vt``), moved
    together by ``advance`` or the wall alone by ``step_wall``, as an NTP correction or a suspend moves it."""

    def __init__(self):
        self.clock, self.vt = Clock(T), VirtualTime(start_wall_ms=T)

    def advance(self, millis: int) -> None:
        self.clock.advance(millis)
        self.vt.advance(millis / 1000)

    def step_wall(self, millis: int) -> None:
        self.clock.advance(millis)


def _completed_then_displaced():
    """This peer takes and completes an entry; a rival's earlier claim reaches it afterwards."""
    clock = _BothClocks()
    host, rival = Identity.generate(), Identity.generate()
    peer = VPeer(clock.vt, clock=clock.clock)
    link = Link(host, peer)
    space = Space(peer, "tasks")
    write = _write(host, T, lease_millis=600_000)
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    link.rumor(write)
    holder = peer.identity.agent("python")
    mine = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T + 10}:0:{holder}", holder, 0.0,
                                             T + 300_000), peer.identity)
    peer.claims[entry_id] = mine
    Taken(space, entry_id, {"x": 1}, 300_000).complete()
    rival_holder = rival.agent("worker")
    better = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T}:0:{rival_holder}", rival_holder,
                                               0.0, T + 300_000), rival)
    peer.sent.clear()
    Link(rival, peer).rumor(None, claim=(entry_id, better))
    return peer, link, write, mine, clock


def _reoffers(peer, mine) -> int:
    count = 0
    for kind, body, _ in peer.sent:
        if kind == "RUMOR":
            rumor = cbor.loads(body)
            delta = cbor.loads(rumor["payload"])
            if rumor["itemId"].startswith("c:") and delta.get("claim") == mine:
                count += 1
    return count


def test_a_displaced_holder_that_completed_offers_its_claim_again_with_a_doubling_backoff():
    peer, link, write, mine, clock = _completed_then_displaced()
    assert _reoffers(peer, mine) == 1, "offered at once when the better claim arrives"
    link.rumor(write)  # a replica that has not heard of the completion offers the entry present
    assert _reoffers(peer, mine) == 1, "no sooner than 1 s after the previous offer"
    for backoff in (1_000, 2_000, 4_000, 8_000, 16_000):
        clock.advance(backoff)
        link.rumor(write)
    assert _reoffers(peer, mine) == REOFFER_MAX
    clock.advance(32_000)
    link.rumor(write)
    assert _reoffers(peer, mine) == REOFFER_MAX and peer.displaced_reoffers == REOFFER_MAX
    assert peer._displaced_own == {}, "spent: the line goes"


def test_a_displaced_claim_is_not_offered_once_it_lapsed():
    peer, link, write, mine, clock = _completed_then_displaced()
    clock.advance(300_001)
    link.rumor(write)
    assert _reoffers(peer, mine) == 1 and peer._displaced_own == {}


def test_a_displaced_claim_this_peer_never_completed_under_is_not_offered():
    clock = Clock(T)
    host, rival = Identity.generate(), Identity.generate()
    peer = VPeer(clock=clock)
    Space(peer, "tasks")
    write = _write(host, T)
    Link(host, peer).rumor(write)
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    holder = peer.identity.agent("python")
    peer.claims[entry_id] = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T + 10}:0:{holder}",
                                                              holder, 0.0, T + 60_000), peer.identity)
    rival_holder = rival.agent("worker")
    better = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T}:0:{rival_holder}", rival_holder,
                                               0.0, T + 60_000), rival)
    peer.sent.clear()
    Link(rival, peer).rumor(None, claim=(entry_id, better))
    assert peer.sent == [] and peer.displaced_reoffers == 0, "rule one: it does not complete, and offers nothing"


# ------------------------------------------------------- aggregate rounds and settle spans

def test_a_settle_span_counts_rounds_of_one_second_as_java_does():
    assert ROUND_PERIOD_S == 1.0
    assert Settle.after("8s", 0.01) == Settle.after(8, 0.01) == Settle.after("PT8S", 0.01)
    assert Settle.after("1500ms", 0.0).ticks == 2, "rounded up"
    assert Settle.after(0.0, 0.0) == Settle.FIRST
    with pytest.raises(ValueError):
        Settle.after(-1.0, 0.0)

    @agent("settler")
    class Settler:
        @on_estimate(epochs="load", settle="PT40S")
        def settled(self, estimate):
            return None

    from agentspaces.agents import _META
    assert getattr(Settler.settled, _META)["settle"] == "PT40S"
    with pytest.raises(ValueError):
        on_estimate(ticks=4, settle="4s")


def test_aggregate_rounds_run_at_one_second_deadlines_and_sleep_while_no_epoch_is_known():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    aggregate = Aggregate(Pipes(peer), advertise=False)
    aggregate.run()
    try:
        vt.advance(10.0)
        assert _until(lambda: vt.advances and aggregate._thread.is_alive())
        assert aggregate.rounds == 0, "nothing known: no rounds"
        aggregate.start("load", 4.0)
        assert _until(lambda: aggregate.rounds == 1), "the epoch woke it"
        vt.advance(0.5)
        vt.advance(0.4)
        assert not _until(lambda: aggregate.rounds > 1, 0.05)
        vt.advance(0.1)
        assert _until(lambda: aggregate.rounds == 2)
        peer._socket = None  # a lost link: the rounds wait and go on
        vt.advance(1.0)
        assert _until(lambda: aggregate._thread.is_alive())
        peer._socket = _Socket()
        vt.advance(1.0)
        assert _until(lambda: aggregate.rounds >= 3)
    finally:
        aggregate.close()


# --------------------------------------------------------- loops outlive a reconnect gap

def test_binder_loops_go_on_through_a_lost_socket_and_end_with_the_peer():
    peer = VPeer(VirtualTime(start_wall_ms=T))
    binder = Binder(peer, publish_card=False)
    from agentspaces.agents import Bound
    bound = Bound(binder, "x", None)
    peer._socket = None
    assert binder._running(bound), "a peer between links is not closed"
    peer.close()
    assert not binder._running(bound)


# ------------------------------------------------------------------------ the TTL floor

@entry("com.acme.Note#v1")
@dataclass
class Note:
    text: str


def test_the_ttl_floor_warns_refuses_under_strict_and_passes_defaults_and_overrides(caplog):
    floor = TtlFloor()
    with caplog.at_level(logging.WARNING, logger="agentspaces.ttl"):
        floor.check("binder.card-ttl", 30_000, 600_000)
        floor.check("binder.card-ttl", 30_000, 600_000)
    assert [f.verdict for f in floor.findings] == [WARNED] and caplog.text.count("binder.card-ttl") == 1
    floor.check("x", 600_000, 600_000)
    floor.check("y", 10_000, 10_000)  # its own registered default
    floor.check("z", 120_000)
    assert len(floor.findings) == 1
    strict = TtlFloor(strict=True, overrides={"binder.A.m.lease": "a one-shot timer, renewed by nobody"})
    with pytest.raises(TtlFloorError, match="binder.card-ttl"):
        strict.check("binder.card-ttl", 30_000, 600_000)
    strict.check("binder.A.m.lease", 5_000, 3_600_000)
    assert [f.verdict for f in strict.findings] == [REFUSED, OVERRIDDEN]
    with pytest.raises(ValueError):
        TtlFloor(overrides={"k": " "})


def test_the_binder_checks_its_card_ttl_and_each_bindings_leases():
    peer = VPeer(VirtualTime(start_wall_ms=T))
    with pytest.raises(TtlFloorError, match="binder.card-ttl"):
        Binder(peer, card_ttl="PT20S", ttl_floor=TtlFloor(strict=True))

    @agent("noter")
    class Noter:
        @space_notify("notes", lease="10s")
        def seen(self, note: Note) -> None:
            return None

    floor = TtlFloor()
    bound = Binder(peer, publish_card=False, ttl_floor=floor).bind(Noter())
    try:
        assert [(f.key, f.verdict) for f in floor.findings] == [("binder.Noter.seen.lease", WARNED)]
    finally:
        bound.close()


def test_a_resume_renews_the_binders_leases_at_once():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)

    @agent("watcher")
    class Watcher:
        @space_notify("notes")
        def seen(self, note: Note) -> None:
            return None

    bound = Binder(peer, publish_card=False).bind(Watcher())
    try:
        subscription = bound._subscriptions[0]
        before = subscription._expires_ms
        vt.advance(600)  # ten minutes: the renewal is not due before thirty
        assert subscription._expires_ms == before
        peer._resume()
        assert _until(lambda: subscription._expires_ms == before + 600_000), "renewed at once"
    finally:
        bound.close()
    assert bound.nudge not in peer._resume_listeners


# ---------------------------------------------------- over a real socket, against a fake seed

def test_over_tcp_the_seeds_ping_and_a_relayed_ping_are_answered_to_their_probers_and_relay_via_follows():
    import struct
    from test_robustness import FakeSeed
    seed, seed_id, origin = FakeSeed(), Identity.generate(), Identity.generate()
    peer = Peer(Identity.generate(), GROUP)
    try:
        peer.connect("127.0.0.1", seed.port)
        assert _until(lambda: len(seed.connections) == 1 and seed.envelopes)
        conn = seed.connections[0]

        def push(frame: bytes):
            conn.sendall(struct.pack(">i", len(frame)) + frame)

        push(_frame(seed_id, peer, "PING", wire.ping_body(41), peer.identity.peer_id))
        assert _until(lambda: any(e["kind"] == "ACK" for e in seed.envelopes))
        ack = next(e for e in seed.envelopes if e["kind"] == "ACK")
        assert ack["to"] == seed_id.peer_id and cbor.loads(ack["body"])["nonce"] == 41
        assert _until(lambda: any(e["kind"] == "RUMOR" and cbor.loads(e["body"])["streamId"] == "peers"
                                  and wire.decode_signed_peer_ad(cbor.loads(e["body"])["payload"])
                                  ["resourceHints"].get("relay.via") == seed_id.peer_id for e in seed.envelopes)), \
            "re-introduced naming the seed it dialled"
        inner = _frame(origin, peer, "PING", wire.ping_body(42), peer.identity.peer_id)
        push(_frame(seed_id, peer, "RELAY_FRAME", wire.relay_frame_body(peer.identity.peer_id, inner),
                    peer.identity.peer_id, logical=2))
        assert _until(lambda: any(e["kind"] == "RELAY_FRAME" for e in seed.envelopes))
        relay = next(e for e in seed.envelopes if e["kind"] == "RELAY_FRAME")
        assert relay["to"] == seed_id.peer_id
        carried = wire.decode_frame(cbor.loads(relay["body"])["frame"])
        assert carried["kind"] == "ACK" and carried["to"] == origin.peer_id
        assert cbor.loads(carried["body"])["nonce"] == 42
        assert peer.loop_health()["readerAlive"] and peer.loop_health()["frameInHand"] == ""
    finally:
        peer.close()
        seed.close()


# ------------------------------- feature interactions: a suspend while backing off, a silent relay holder

class _DialPeer(VPeer):
    """A VPeer whose link is lost and whose dials fail until ``allow`` is set (the seed unreachable)."""

    def __init__(self, source):
        super().__init__(source)
        self._seed = Seed("seed", 1, "tcp")
        self._socket = None
        self._link_since = source.monotonic() - 600  # a long-lived link ended: no quick-drop pause
        self.dials = 0
        self.allow = threading.Event()

    def _dial(self, seed, timeout):
        self.dials += 1
        if not self.allow.is_set():
            raise OSError("unreachable")
        self._link_since = self.time.monotonic()
        return _Socket()


def test_a_suspend_while_backing_off_dials_again_at_once_rather_than_sitting_out_the_pause():
    vt = VirtualTime(start_wall_ms=T)
    peer = _DialPeer(vt)
    peer._judge_wall_step()  # anchor
    done = threading.Event()
    threading.Thread(target=lambda: (peer._reconnect(), done.set()), daemon=True).start()
    assert _until(lambda: peer.dials == 1), "the first round of dials failed"
    assert not _until(lambda: peer.dials > 1, 0.1), "and it pauses (5 s of virtual time) before the next"
    peer.allow.set()
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)  # the laptop slept through the pause
    peer._judge_wall_step()
    assert peer.resumes == 1
    assert _until(done.is_set), "the resume dials again at once, with no virtual time passing"
    assert peer.dials == 2 and peer.reconnects == 1
    assert _peer_ads(peer), "and introduces itself on the new link"
    peer._running = False


class _ShutSocket(_Socket):
    def __init__(self):
        self.shut = 0

    def shutdown(self, how):
        self.shut += 1


def test_a_silent_link_asks_its_seed_then_is_dropped_so_the_peer_fails_over():
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    vt = VirtualTime(start_wall_ms=T)
    peer, seed = VPeer(vt), Identity.generate()
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))  # heard; relay.via named
    assert peer.resource_hints["relay.via"] == seed.peer_id
    peer.sent.clear()
    vt.advance(LINK_QUIET_S - 1)
    peer._watch()
    assert not [k for k, _, _ in peer.sent if k == "PING"], "a link heard within the quiet bound is left alone"
    vt.advance(2)
    peer._watch()
    assert _until(lambda: any(k == "PING" for k, _, _ in peer.sent)), "the ask's thread sends the PING"
    pings = [(body, to) for kind, body, to in peer.sent if kind == "PING"]
    assert len(pings) == 1 and pings[0][1] == seed.peer_id, "the silent link is asked: a PING to the seed"
    peer._watch()
    assert len([k for k, _, _ in peer.sent if k == "PING"]) == 1, "asked once, not on every check"
    # the seed answers: the link is alive and nothing is dropped
    peer._receive(_frame(seed, peer, "ACK", wire.ack_body(cbor.loads(pings[0][0])["nonce"]),
                         peer.identity.peer_id, logical=2))
    vt.advance(LINK_ANSWER_S + 1)
    peer._watch()
    assert sock.shut == 0 and peer.links_silent == 0
    # the holder vanished without a FIN (power loss, a moved laptop): asked and never answered
    vt.advance(LINK_QUIET_S)
    peer._watch()
    vt.advance(LINK_ANSWER_S + 0.5)
    peer._watch()
    assert sock.shut == 1 and peer.links_silent == 1, \
        "the dead link is shut so the reader reconnects, failing over to the next seed"
    assert peer.loop_health()["linksSilent"] == 1


def test_a_resume_asks_the_link_so_a_link_that_died_in_the_suspend_is_dropped_within_the_answer_window():
    from agentspaces.peer import LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._heard_at = vt.monotonic()
    peer._judge_wall_step()
    vt.step_wall(KEEPALIVE_TTL_MS + 10_000)  # a suspend: monotonic time did not move
    peer._judge_wall_step()
    assert _until(lambda: any(kind == "PING" for kind, _, _ in peer.sent)), "the resume asks the link at once"
    vt.advance(LINK_ANSWER_S + 0.5)
    peer._watch()
    assert sock.shut == 1, "no answer: the link died in the suspend and is dropped, not waited on"


def test_over_tcp_a_seed_that_goes_silent_is_left_for_the_next_and_relay_via_follows():
    import struct
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    from test_robustness import FakeSeed
    vt = VirtualTime(start_wall_ms=T)
    a, b, a_id, b_id = FakeSeed(), FakeSeed(), Identity.generate(), Identity.generate()
    peer = Peer(Identity.generate(), GROUP, time_source=vt)
    try:
        chosen = peer.connect_any([("127.0.0.1", a.port), ("127.0.0.1", b.port)])
        if chosen.port == b.port:  # both answer at once and the first wins: name the winner a
            a, b = b, a
        assert _until(lambda: a.envelopes)
        assert not b.envelopes, "the seed that answered later was closed with nothing sent"
        frame = _frame(a_id, peer, "PING", wire.ping_body(5), peer.identity.peer_id)
        a.connections[0].sendall(struct.pack(">i", len(frame)) + frame)
        assert _until(lambda: peer.resource_hints.get("relay.via") == a_id.peer_id)
        # seed a stops answering anything and sends no FIN: the link is half open
        vt.advance(LINK_QUIET_S + 1)
        peer._watch()
        assert _until(lambda: any(e["kind"] == "PING" and e["to"] == a_id.peer_id for e in a.envelopes))
        vt.advance(LINK_ANSWER_S)  # no watchdog check: the ask's own wait judges the link at the ping timeout
        assert _until(lambda: any(
            e["kind"] == "RUMOR" and cbor.loads(e["body"])["streamId"] == "peers" for e in b.envelopes)), \
            "the peer failed over to the next seed and introduced itself there"
        assert peer.links_silent == 1 and peer.reconnects == 1
        assert "relay.via" not in peer.resource_hints, "the silent holder is no longer named"
        frame = _frame(b_id, peer, "PING", wire.ping_body(6), peer.identity.peer_id)
        b.connections[-1].sendall(struct.pack(">i", len(frame)) + frame)  # after the closed loser, if any
        assert _until(lambda: peer.resource_hints.get("relay.via") == b_id.peer_id), "the new holder is named"
    finally:
        peer.close()
        a.close()
        b.close()


def test_a_heard_epoch_that_went_quiet_settles_on_its_rounds_as_a_java_watch_does():
    """A 0.7.0 Java member stops sharing an epoch whose estimate has not moved for 30 s (quiet). A watch here
    whose span is longer must still settle: as Java's R1 rule (2026-11-14), every round counts once the epoch was
    heard at all, not only a round that brought a new frame, which would starve the streak at the quiet."""
    peer = VPeer(VirtualTime(start_wall_ms=T))
    aggregate = Aggregate(Pipes(peer), advertise=False)
    aggregate.participants = lambda: ["a-java-member"]
    fired = []
    aggregate.on_estimate(lambda e: e == "load", Settle.after("PT40S", 0.01), fired.append)
    share = wire.aggregate_frame(share={"epochId": "load", "value": 2.0, "weight": 1.0})
    aggregate._on_frame(Identity.generate().peer_id, cbor.dumps(share))  # heard once; then Java went quiet
    for _ in range(39):
        aggregate.tick()
    assert not _until(lambda: fired, 0.05), "not before the span"
    for _ in range(2):
        aggregate.tick()
    assert _until(lambda: fired), "the watch settles after 40 rounds with no further frame"
    assert fired[0].value == pytest.approx(2.0)


def test_a_settle_span_counts_the_rounds_the_aggregate_actually_runs():
    """``Settle.after("8s")`` is a span of time: under ``run(interval_seconds=0.5)`` it takes 16 rounds, not 8."""
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    aggregate = Aggregate(Pipes(peer), advertise=False)
    fired = []
    aggregate.start("load", 3.0)
    aggregate.on_estimate(lambda e: e == "load", Settle.after("8s", 0.01), fired.append)
    aggregate.run(interval_seconds=0.5)
    try:
        for _ in range(14):
            vt.advance(0.5)
            target = aggregate.rounds + 1
            assert _until(lambda: aggregate.rounds >= target)
        assert not _until(lambda: fired, 0.05), "8 rounds of 0.5 s are 4 s, not the 8 s asked for"
        for _ in range(4):
            vt.advance(0.5)
            target = aggregate.rounds + 1
            assert _until(lambda: aggregate.rounds >= target)
        assert _until(lambda: fired)
    finally:
        aggregate.close()


def test_over_tcp_a_new_link_asks_its_unknown_seed_so_relay_via_names_it_within_one_round_trip():
    """On tcp the seed's PeerID is known only from a frame it addresses here. Its own probe of this peer may be a
    whole quiet cycle away (about 196 s at fifty members), and until then every member's targeted relay has no
    holder to ask. A PING on the new link is answered at once with an ACK addressed here (SPEC §5.2)."""
    import struct
    from test_robustness import FakeSeed
    seed, seed_id = FakeSeed(), Identity.generate()
    peer = Peer(Identity.generate(), GROUP)
    try:
        peer.connect("127.0.0.1", seed.port)
        assert _until(lambda: any(e["kind"] == "PING" for e in seed.envelopes)), "the unknown seed is asked"
        ping = next(e for e in seed.envelopes if e["kind"] == "PING")
        ack = _frame(seed_id, peer, "ACK", wire.ack_body(cbor.loads(ping["body"])["nonce"]), peer.identity.peer_id)
        seed.connections[0].sendall(struct.pack(">i", len(ack)) + ack)
        assert _until(lambda: peer.resource_hints.get("relay.via") == seed_id.peer_id)
    finally:
        peer.close()
        seed.close()


def test_a_wedged_frame_handler_is_not_taken_for_a_silent_seed():
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._heard_at = vt.monotonic()
    peer._frame_started, peer._frame_kind = vt.monotonic(), "RUMOR"  # our own handler holds the reader
    vt.advance(LINK_QUIET_S + LINK_ANSWER_S + 5)
    peer._watch()
    peer._watch()
    assert sock.shut == 0 and not [k for k, _, _ in peer.sent if k == "PING"], \
        "no frame can be read while the handler runs; the link is not judged"


def _shares_sent(peer) -> int:
    count = 0
    for kind, body, _ in peer.sent:
        if kind == "PIPE_DATA":
            frame = cbor.loads(cbor.loads(body)["payload"])
            count += frame.get("share") is not None
    return count


def test_an_unchanged_epoch_goes_quiet_after_30_rounds_wakes_on_a_move_and_is_forgotten_after_an_hour():
    """Java's push-sum quiet and evict (SPEC v0.1.36 §8, §9.5): an estimate unchanged for 30 s stops being shared
    until a share moves it, and one unchanged for an hour is forgotten."""
    from agentspaces.capabilities.aggregate import EVICT_AFTER_ROUNDS, QUIET_AFTER_ROUNDS
    assert (QUIET_AFTER_ROUNDS, EVICT_AFTER_ROUNDS) == (30, 3600)
    peer = VPeer(VirtualTime(start_wall_ms=T))
    aggregate = Aggregate(Pipes(peer), advertise=False)
    aggregate.participants = lambda: [Identity.generate().peer_id]
    aggregate.start("load", 4.0)
    for _ in range(QUIET_AFTER_ROUNDS):
        aggregate.tick()
    assert _shares_sent(peer) == QUIET_AFTER_ROUNDS, "shared every round while it might still move"
    for _ in range(10):
        aggregate.tick()
    assert _shares_sent(peer) == QUIET_AFTER_ROUNDS, "quiet: nothing more to say"
    share = wire.aggregate_frame(share={"epochId": "load", "value": 3.0, "weight": 0.5})
    aggregate._on_frame(Identity.generate().peer_id, cbor.dumps(share))  # a share that moves the estimate
    aggregate.tick()
    assert _shares_sent(peer) == QUIET_AFTER_ROUNDS + 1, "a moved estimate is shared again"
    for _ in range(EVICT_AFTER_ROUNDS + 1):
        aggregate.tick()
    assert "load" not in aggregate.epochs() and aggregate.estimate("load") is None, "forgotten after an hour"


# ------------------------------- round 2a (owner decisions 2026-11-23): the dead-seed rule, DIGEST, monotonic re-offers

def _asked_link():
    """A peer whose seed is known and was last heard now, on a socket the test can see shut."""
    vt = VirtualTime(start_wall_ms=T)
    peer, seed = VPeer(vt), Identity.generate()
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))
    peer.sent.clear()
    return peer, seed, sock, vt


def _pings(peer) -> list:
    return [(body, to) for kind, body, to in peer.sent if kind == "PING"]


def test_the_dead_seed_rule_pings_a_seed_silent_45_s_and_fails_over_at_the_ping_timeout():
    """One rule for every dial-only client: nothing heard from the seed for 45 s (1.5 times the 30 s keepalive
    bound) asks it with a PING; no answer within the ping timeout (2 s, SPEC §9.4) drops the link, and the reader
    dials the next seed. The timeout is judged when it falls due, not on the watchdog's next check."""
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    assert (LINK_QUIET_S, LINK_ANSWER_S) == (45.0, 2.0)
    peer, seed, sock, vt = _asked_link()
    vt.advance(44.5)
    peer._watch()
    assert _pings(peer) == [], "heard within 45 s: not asked"
    vt.advance(0.5)
    peer._watch()
    assert _until(lambda: len(_pings(peer)) == 1) and _pings(peer)[0][1] == seed.peer_id, \
        "silent 45 s: a PING to the seed"
    vt.advance(LINK_ANSWER_S - 0.5)
    assert not _until(lambda: sock.shut, 0.05), "within the ping timeout the seed may still answer"
    vt.advance(0.5)
    assert _until(lambda: sock.shut == 1), "no answer at the ping timeout: the link is shut, with no watchdog check"
    assert peer.links_silent == 1
    peer._watch()
    assert len(_pings(peer)) == 1 and sock.shut == 1, "a link judged dead is not asked or shut again"


def test_the_dead_seed_rule_keeps_a_seed_that_answers_and_takes_bytes_still_arriving_as_an_answer():
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    peer, seed, sock, vt = _asked_link()
    vt.advance(LINK_QUIET_S)
    peer._watch()
    assert _until(lambda: len(_pings(peer)) == 1)
    (ping, _), = _pings(peer)
    vt.advance(1.0)
    peer._receive(_frame(seed, peer, "ACK", wire.ack_body(cbor.loads(ping)["nonce"]), peer.identity.peer_id, logical=2))
    vt.advance(LINK_ANSWER_S + 1)
    peer._watch()
    assert sock.shut == 0 and peer.links_silent == 0, "an answering seed is kept"
    # Asked again after another 45 s; a large frame is arriving on a slow link when the timeout falls due.
    vt.advance(LINK_QUIET_S)
    peer._watch()
    assert _until(lambda: len(_pings(peer)) == 2)
    vt.advance(1.0)
    peer._bytes_at = vt.monotonic()  # the reader took a chunk of a frame not yet complete
    vt.advance(LINK_ANSWER_S)
    peer._watch()
    assert sock.shut == 0 and peer.links_silent == 0, "the seed is writing: a slow link is no dead seed"


def _seed_linked():
    vt = VirtualTime(start_wall_ms=T)
    me, seed = VPeer(vt), Identity.generate()
    me._seed = Seed("seed", 1, "tcp")
    me._receive(_frame(seed, me, "PING", wire.ping_body(1), me.identity.peer_id))  # the seed is known
    me.sent.clear()
    return me, seed, vt


def _pull_resps(peer) -> list:
    return [(body, to) for kind, body, to in peer.sent if kind == "PULL_RESP"]


def test_a_dial_only_peer_answers_its_seeds_digest_so_its_own_rumor_lost_on_the_link_is_repaired():
    me, seed, vt = _seed_linked()
    entry_id = me.write_entry("tasks", TYPE, {"x": 1})
    record = me.states[entry_id]["record"]
    holder = me.identity.agent("python")
    claim = wire.signed_claim(wire.take_claim(entry_id, record["spaceId"], 1, f"{T + 10}:0:{holder}", holder, 0.0,
                                              T + 300_000), me.identity)
    me.claims[entry_id] = claim
    me.sent.clear()  # the write's and the claim's RUMORs were lost on the only link
    me._receive(_frame(seed, me, "DIGEST", wire.digest_body({"ads": b"", "space:other": b"", "space:tasks": b""}),
                       me.identity.peer_id, logical=2))
    (body, to), = _pull_resps(me)
    assert to == seed.peer_id and me.pulls_answered == 1 and me.ignored_kinds == {}
    deltas = cbor.loads(body)["deltas"]
    assert list(deltas) == ["space:tasks"], "only the spaces this peer holds; ads, view and revocations are not served"
    # The seed's replica folds the answer: the lost write and claim are repaired there.
    replica = VPeer(vt)
    replica._receive(_frame(me.identity, replica, "PULL_RESP", body, replica.identity.peer_id))
    assert entry_id in replica.states and replica.claims[entry_id] == claim
    # Its next round names both: nothing is missing, nothing is sent.
    me.sent.clear()
    me._receive(_frame(seed, me, "DIGEST", wire.digest_body({"space:tasks": replica.space_digest("tasks")}),
                       me.identity.peer_id, logical=3))
    assert _pull_resps(me) == [] and me.pulls_answered == 1


def test_a_digest_other_than_the_seeds_text_round_is_ignored_and_counted_as_before():
    me, seed, vt = _seed_linked()
    me.write_entry("tasks", TYPE, {"x": 1})
    me.sent.clear()
    # annex I.6's budget and the hashed round go only toward a card advertising them, which this peer's does not
    me._receive(_frame(seed, me, "DIGEST", wire.digest_body({"space:tasks": b""}, budget=1024), me.identity.peer_id,
                       logical=2))
    me._receive(_frame(seed, me, "DIGEST", cbor.dumps({"digests": None, "hashes": {"space:tasks": b"x" * 32}}),
                       me.identity.peer_id, logical=3))
    # a DIGEST a relay carried from another member: anti-entropy runs between linked members alone
    inner = _frame(Identity.generate(), me, "DIGEST", wire.digest_body({"space:tasks": b""}), me.identity.peer_id)
    me._receive(_frame(seed, me, "RELAY_FRAME", wire.relay_frame_body(me.identity.peer_id, inner),
                       me.identity.peer_id, logical=4))
    me._receive(_frame(seed, me, "DIGEST", b"\xa1\x01\x02", me.identity.peer_id, logical=5))  # not a Bodies.Digest
    assert me.sent == [] and me.pulls_answered == 0
    assert me.ignored_kinds == {"DIGEST": 4}


def test_a_join_that_equals_neither_input_is_answered_with_its_most_advanced_signed_input():
    """A withdrawal and a renewal that crossed join to a state nobody signed: removes from one, the later lease from
    the other. The answer forwards the withdrawal (more removes), which verifies at the seed; the join would not."""
    from test_hlc_logical_limit import _with_lease_stamp
    clock = Clock(T + 5_000)
    host = Identity.generate()
    me = VPeer(VirtualTime(start_wall_ms=T + 5_000), clock=clock)
    link = Link(host, me)
    write = _write(host, T)
    issuer = write["record"]["issuer"]
    renewal = _with_lease_stamp(write, host, f"{T + 2_000}:0:{issuer}", T + 2_000)
    withdrawal = wire.sign_state(dict(write, removes=write["adds"]), host)
    for state in (write, renewal, withdrawal):
        link.rumor(state)
    entry_id = write["record"]["entryId"]
    held = me.states[entry_id]
    assert held["removes"] and held["leaseStamp"] == renewal["leaseStamp"], "the join holds both"
    sync = cbor.loads(me.space_delta_for("tasks", b""))
    assert sync["states"] == [withdrawal]
    for forwarded, verifies in ((withdrawal, True), (held, False)):
        replica = VPeer(clock=Clock(T + 5_000))
        Link(host, replica).pull_resp([forwarded], {})
        assert (entry_id in replica.states) is verifies


def test_the_re_offer_backoff_is_judged_on_the_monotonic_clock_so_a_wall_step_neither_fires_nor_holds_it():
    peer, link, write, mine, clock = _completed_then_displaced()
    assert _reoffers(peer, mine) == 1
    clock.step_wall(60_000)  # a minute forward on the wall alone: on wall time every backoff to 32 s had passed
    link.rumor(write)
    assert _reoffers(peer, mine) == 1, "a forward wall step fires no offer"
    clock.advance(1_000)
    link.rumor(write)
    assert _reoffers(peer, mine) == 2, "a second of monotonic time does"
    clock.step_wall(-30_000)  # back half a minute: on wall time the next offer would wait 30 s more
    clock.advance(2_000)
    link.rumor(write)
    assert _reoffers(peer, mine) == 3, "a backward wall step holds none back"


# ------------------------------- round 2a review: a send stuck behind a dead seed, and the answer's frame bound

class _StuckSendPeer(VPeer):
    """A peer whose PING send blocks, as ``sendall`` does behind a full send buffer to a seed that died
    without a FIN (another thread's write holds the send lock until TCP gives up)."""

    def __init__(self, source):
        super().__init__(source)
        self.release = threading.Event()

    def _send(self, kind, body, to=None):
        if kind == "PING":
            self.release.wait(5)
        super()._send(kind, body, to)


def test_the_dead_seed_rule_holds_when_the_ping_itself_is_stuck_behind_a_full_send_buffer():
    from agentspaces.peer import LINK_ANSWER_S, LINK_QUIET_S
    vt = VirtualTime(start_wall_ms=T)
    peer, seed = _StuckSendPeer(vt), Identity.generate()
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))
    try:
        vt.advance(LINK_QUIET_S)
        checked = threading.Event()
        threading.Thread(target=lambda: (peer._watch(), checked.set()), daemon=True).start()
        assert _until(checked.is_set, 1.0), "the watchdog is not held by the PING it asks with"
        vt.advance(LINK_ANSWER_S)
        peer._watch()
        assert sock.shut == 1 and peer.links_silent == 1, \
            "no answer within the ping timeout: the link is shut (which also frees the stuck send), not left to TCP"
    finally:
        peer.release.set()


def test_the_digest_answer_keeps_its_claims_inside_the_frame_bound_too():
    me, seed, vt = _seed_linked()
    holder = me.identity.agent("python")
    for n in range(40):
        entry_id = me.write_entry("tasks", TYPE, {"x": n})
        record = me.states[entry_id]["record"]
        me.claims[entry_id] = wire.signed_claim(wire.take_claim(
            entry_id, record["spaceId"], 1, f"{T + 10}:{n}:{holder}", holder, 0.0, T + 300_000), me.identity)
    one_claim = len(cbor.dumps(next(iter(me.claims.values()))))
    room = 5 * one_claim
    delta = me.space_delta_for("tasks", b"", room)
    assert len(delta) <= room + 1024, "states and claims together stay within the room the answer was given"
    sync = cbor.loads(delta)
    assert sync["states"] or sync["claims"], "something still goes, and the rest waits for the next round"


# ------------------------- round 2b part 1: one redial table, concurrent seed dials (owner, 2026-11-23)

class _Even:
    """A spread source that always draws the middle, so a wait is exactly the table's."""

    def uniform(self, lo, hi):
        return (lo + hi) / 2


class _TablePeer(VPeer):
    """A VPeer whose link is lost, whose dials fail ``fail`` times then answer, and whose waits are
    recorded and passed on virtual time at once (no wait is sat out)."""

    def __init__(self, source, fail=0):
        super().__init__(source)
        self._seed = Seed("seed", 1, "tcp")
        self._socket = None
        self._link_since = source.monotonic() - 600
        self._redial_random = _Even()
        self.fail, self.dials, self.waits = fail, 0, []

    def _dial(self, seed, timeout):
        self.dials += 1
        if self.fail > 0:
            self.fail -= 1
            raise OSError("unreachable")
        self._link_since = self.time.monotonic()
        return _Socket()

    def _pause_redial(self, seconds):
        self.waits.append(seconds)
        self.time.advance(seconds)
        return False


def test_the_redial_table_is_5_10_20_30_s_then_wraps_to_5_s():
    from agentspaces.peer import REDIAL_TABLE_S
    assert REDIAL_TABLE_S == (5.0, 10.0, 20.0, 30.0)
    peer = VPeer(VirtualTime(start_wall_ms=T))
    peer._redial_random = _Even()
    assert [peer._next_redial_wait() for _ in range(10)] == [5, 10, 20, 30, 5, 10, 20, 30, 5, 10]
    assert peer._redial_at == 2, "the position advances once per wait and wraps after the last"
    peer.reconnect_interval_s = 0.5  # the table scales with its first wait, as the tests run it faster
    peer._redial_at = 0
    assert [peer._next_redial_wait() for _ in range(5)] == [0.5, 1.0, 2.0, 3.0, 0.5]


def test_each_wait_of_the_redial_table_has_a_spread_of_plus_or_minus_ten_percent():
    import random
    peer = VPeer(VirtualTime(start_wall_ms=T))
    peer._redial_random = random.Random(23)
    for step in (5.0, 10.0, 20.0, 30.0) * 2:
        draws = []
        for _ in range(400):
            peer._redial_at = (5.0, 10.0, 20.0, 30.0).index(step)
            draws.append(peer._next_redial_wait())
        assert all(0.9 * step <= d <= 1.1 * step for d in draws), (step, min(draws), max(draws))
        assert min(draws) < 0.93 * step and max(draws) > 1.07 * step, "the spread goes both ways"

    class _Edges:
        def __init__(self):
            self.asked = []

        def uniform(self, lo, hi):
            self.asked.append((lo, hi))
            return lo

    peer._redial_random = edges = _Edges()
    peer._redial_at = 3
    assert peer._next_redial_wait() == pytest.approx(27.0)
    assert edges.asked == [(pytest.approx(0.9), pytest.approx(1.1))]


def test_failed_rounds_walk_the_table_a_quick_drop_goes_on_and_a_link_that_held_resets_it():
    vt = VirtualTime(start_wall_ms=T)
    peer = _TablePeer(vt, fail=2)
    assert peer._reconnect() is True
    assert peer.waits == [5, 10] and peer.dials == 3, "two failed rounds wait 5 s then 10 s"
    assert peer._redial_at == 2
    # the new link ends within the table's first wait (a seed that accepts and drops): a failed round
    peer.fail = 1
    assert peer._reconnect() is True
    assert peer.waits == [5, 10, 20, 30], "the quick drop waits 20 s, the next failed round 30 s"
    assert peer._redial_at == 0, "and the table wrapped"
    peer.fail = 2
    peer._redial_at = 3
    vt.advance(5.1)  # the link held past the table's first wait: a successful link
    del peer.waits[:]
    dials = peer.dials
    assert peer._reconnect() is True
    assert peer.dials == dials + 3, "the first dial after a link that held goes at once"
    assert peer.waits == [5, 10], "and the table starts again from its first wait"


def test_a_wake_while_backing_off_dials_at_once_and_starts_the_table_again():
    vt = VirtualTime(start_wall_ms=T)
    peer = _DialPeer(vt)
    peer._redial_random = _Even()
    waits = []
    table = peer._next_redial_wait

    def recorded():
        waits.append(table())
        return waits[-1]

    peer._next_redial_wait = recorded
    peer._judge_wall_step()  # anchor
    done = threading.Event()
    threading.Thread(target=lambda: (peer._reconnect(), done.set()), daemon=True).start()
    assert _until(lambda: peer.dials == 1 and waits == [5])
    vt.advance(5.01)
    assert _until(lambda: peer.dials == 2 and waits == [5, 10])
    vt.advance(10.01)
    assert _until(lambda: peer.dials == 3 and waits == [5, 10, 20]), "backing off 20 s now"
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)  # the laptop slept
    peer._judge_wall_step()
    assert _until(lambda: peer.dials == 4 and waits == [5, 10, 20, 5]), \
        "the wake dials at once, and the failed round after it waits the table's first wait again"
    vt.advance(5.01)
    assert _until(lambda: peer.dials == 5 and waits == [5, 10, 20, 5, 10])
    peer.allow.set()
    vt.advance(10.01)
    assert _until(done.is_set) and peer.reconnects == 1
    peer._running = False


def test_a_wake_with_the_link_up_resets_the_table_position():
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._redial_at = 3
    peer._judge_wall_step()
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert _until(lambda: peer._redial_at == 0)
    peer.close()


class _HeldSocket(_Socket):
    def __init__(self, name):
        self.name, self.closed = name, False

    def close(self):
        self.closed = True


class _RacePeer(VPeer):
    """A VPeer whose dials (``_open``) are scripted per seed: ``answer`` (at once), ``refuse`` (at once),
    or ``hold`` (no answer until the test releases it, as a black-holed seed's connect timeout)."""

    def __init__(self, source, script):
        super().__init__(source)
        self.script = script
        self.started, self.opened = [], {}
        self.release = {name: threading.Event() for name in script}
        self._lock_started = threading.Lock()

    def _open(self, seed, timeout):
        with self._lock_started:
            self.started.append(seed.host)
        how = self.script[seed.host]
        if how == "hold":
            self.release[seed.host].wait(5)
            how = "answer-late"
        if how == "refuse":
            raise OSError(f"{seed.host} refused")
        sock = self.opened[seed.host] = _HeldSocket(seed.host)
        return sock, None

    def _start_reader(self):
        pass


def _in_thread(call):
    """Runs ``call`` on its own thread (a dial that waits on virtual time the test moves); returns the done
    event and a box holding the result or the exception."""
    done, box = threading.Event(), {}

    def run():
        try:
            box["result"] = call()
        except Exception as e:  # noqa: BLE001
            box["error"] = e
        done.set()

    threading.Thread(target=run, daemon=True).start()
    return done, box


def test_a_silent_first_seed_costs_the_250_ms_stagger_and_a_late_connection_is_closed():
    """Owner decision 2026-11-23 (RFC 8305): the seeds go in list order, each start 250 ms after the one
    before. A black-holed first seed costs the stagger, not its connect timeout; the second answers and
    wins; the third is never started; the first's connection, answering late, is closed at once."""
    from agentspaces.peer import DIAL_STAGGER_S
    assert DIAL_STAGGER_S == 0.25
    vt = VirtualTime(start_wall_ms=T)
    peer = _RacePeer(vt, {"dead": "hold", "live": "answer", "spare": "answer"})
    began = vt.monotonic()
    done, box = _in_thread(lambda: peer.connect_any(
        [Seed("dead", 1, "tcp"), Seed("live", 1, "tcp"), Seed("spare", 1, "tcp")], dial_timeout=10))
    assert _until(lambda: peer.started == ["dead"])
    vt.advance(DIAL_STAGGER_S - 0.001)
    assert not _until(lambda: len(peer.started) > 1, 0.05), "the next seed waits out the stagger"
    vt.advance(0.001)
    assert _until(done.is_set) and "error" not in box
    chosen = box["result"]
    assert chosen.host == "live" and peer._seed == chosen and peer._socket is peer.opened["live"]
    assert vt.monotonic() - began == pytest.approx(DIAL_STAGGER_S), "the silent seed cost 250 ms"
    assert peer.started == ["dead", "live"], "in list order; the seed after the winner is not started"
    assert _peer_ads(peer), "the peer introduced itself on the link that answered"
    vt.advance(5)
    assert not _until(lambda: "spare" in peer.started, 0.05), "and never is"
    peer.release["dead"].set()  # the black-holed seed answers late
    assert _until(lambda: "dead" in peer.opened and peer.opened["dead"].closed), \
        "a connection that answers after the winner is closed at once"
    assert not peer.opened["live"].closed
    peer._running = False


def test_a_refused_dial_starts_the_next_at_once_and_the_first_seed_up_wins():
    vt = VirtualTime(start_wall_ms=T)
    peer = _RacePeer(vt, {"a": "refuse", "b": "answer", "c": "answer"})
    chosen = peer.connect_any([Seed(h, 1, "tcp") for h in "abc"])
    assert chosen.host == "b" and peer.started == ["a", "b"], \
        "the refusal started the next with no virtual time passing, and the first seed up won"
    peer._running = False


def test_connect_any_raises_once_every_staggered_dial_has_failed():
    vt = VirtualTime(start_wall_ms=T)
    peer = _RacePeer(vt, {"a": "refuse", "b": "refuse", "c": "refuse"})
    with pytest.raises(OSError, match="no seed accepted") as raised:
        peer.connect_any([Seed(h, 1, "tcp") for h in "abc"])
    assert peer.started == ["a", "b", "c"], "each dialled once, in list order"
    assert "refused" in str(raised.value.__cause__)
    assert not isinstance(peer._socket, _HeldSocket) and not _peer_ads(peer), "no link was taken"


def test_at_most_sixteen_dials_are_out_at_once():
    from agentspaces.peer import DIALS_IN_FLIGHT_MAX
    vt = VirtualTime(start_wall_ms=T)
    names = [f"s{i}" for i in range(DIALS_IN_FLIGHT_MAX + 2)]
    script = {name: "hold" for name in names}
    script[names[-1]] = "answer"
    peer = _RacePeer(vt, script)
    done, box = _in_thread(lambda: peer.connect_any([Seed(n, 1, "tcp") for n in names]))
    try:
        for count in range(1, DIALS_IN_FLIGHT_MAX + 1):
            assert _until(lambda: len(peer.started) == count)
            vt.advance(0.25)
        assert not _until(lambda: len(peer.started) > DIALS_IN_FLIGHT_MAX, 0.05), "sixteen out: the next waits"
        assert not done.is_set()
    finally:
        for event in peer.release.values():
            event.set()  # the held dials answer: the first to do so wins, the rest are closed
    assert _until(done.is_set) and "error" not in box
    peer._running = False


class _RoundsPeer(_RacePeer):
    """A _RacePeer whose script per seed is a list of behaviours, one per dial (the last repeats), and
    whose redial waits pass on virtual time at once."""

    def _open(self, seed, timeout):
        steps = self.script[seed.host]
        how = steps.pop(0) if len(steps) > 1 else steps[0]
        with self._lock_started:
            self.started.append(seed.host)
        if how == "hold":
            self.release[seed.host].wait(5)
        if how == "refuse":
            raise OSError(f"{seed.host} refused")
        sock = self.opened[seed.host] = _HeldSocket(seed.host)
        return sock, None

    def _pause_redial(self, seconds):
        self.time.advance(seconds)
        return False


def test_the_lost_seed_is_dialled_last_in_every_round_behind_the_stagger():
    """Owner decision 2026-11-23: a lost link dials the seeds in list order with the one just lost last,
    in every round of the reconnect, so a black-holed other seed delays its return by the stagger only."""
    vt = VirtualTime(start_wall_ms=T)
    lost, other, next_ = Seed("lost", 1, "tcp"), Seed("other", 1, "tcp"), Seed("next", 1, "tcp")
    peer = _RoundsPeer(vt, {"lost": ["refuse", "answer"], "other": ["refuse", "hold"], "next": ["refuse"]})
    peer._seeds = [lost, other, next_]
    peer._seed, peer._socket = lost, None
    peer._link_since = vt.monotonic() - 600  # the link held: the first round goes at once
    assert peer._dial_order() == [other, next_, lost]
    done, box = _in_thread(peer._reconnect)
    try:
        # round 1: all three refuse, at once, the lost one last; then the table's first wait (5 s)
        assert _until(lambda: peer.started[:3] == ["other", "next", "lost"])
        # round 2 (after the pause, which passes on virtual time at once): other is black-holed
        assert _until(lambda: peer.started[3:] == ["other"])
        began = vt.monotonic()
        vt.advance(0.25)  # the stagger: next starts and refuses, so the lost seed starts at once
        assert _until(done.is_set) and box.get("result") is True
        assert peer.started[3:] == ["other", "next", "lost"] and peer._seed == lost
        assert vt.monotonic() - began == pytest.approx(0.25), "the black-holed seed cost the stagger"
    finally:
        peer.release["other"].set()
        peer._running = False


# ------------------------- harmonization (owner decisions 2026-11-23): one rule for every client

def test_a_link_that_held_4_s_waits_the_next_step_and_one_that_held_6_s_resets_the_table():
    vt = VirtualTime(start_wall_ms=T)
    peer = _TablePeer(vt)
    peer._redial_at = 2
    peer._link_since = vt.monotonic() - 4  # the link ended after 4 s: a failed round
    assert peer._reconnect() is True
    assert peer.waits == [20], "a 4 s link waits the table's next step (20 s at position 2)"
    assert peer._redial_at == 3
    peer._link_since = vt.monotonic() - 6  # the link ended after 6 s: it held
    assert peer._reconnect() is True
    assert peer.waits == [20] and peer._redial_at == 0, "a 6 s link resets the table and dials at once"
    peer._link_since = vt.monotonic() - 5  # exactly 5 s held: at least 5 s resets
    peer._redial_at = 3
    peer.fail = 1
    assert peer._reconnect() is True
    assert peer.waits == [20, 5], "reset: the next failed round waits the first step"


def test_a_wake_with_the_link_up_pings_the_seed_keeps_an_answering_one_and_fails_over_from_a_silent_one():
    """Owner decision 2026-11-23: a wake while linked PINGs the seed and applies the dead-seed rule. An answer
    keeps the link; no answer within the 2 s ping timeout drops it, and the reconnect fails over to the next
    seed at once (the link held, so the table starts again), the seed lost tried last."""
    from agentspaces.peer import LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    lost, next_ = Seed("lost", 1, "tcp"), Seed("next", 1, "tcp")
    peer, seed = _RacePeer(vt, {"lost": "answer", "next": "answer"}), Identity.generate()
    peer._seeds, peer._seed = [lost, next_], lost
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))  # seed known
    peer._link_since = vt.monotonic() - 600
    peer._redial_at = 3
    peer.sent.clear()
    peer._judge_wall_step()  # anchor
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)  # the laptop slept with the link up
    peer._judge_wall_step()
    assert _until(lambda: len(_pings(peer)) == 1) and _pings(peer)[0][1] == seed.peer_id, \
        "the wake PINGs the seed"
    assert _until(lambda: peer._redial_at == 0), "and resets the redial table"
    # the seed answers within the ping timeout: the link stays
    nonce = cbor.loads(_pings(peer)[0][0])["nonce"]
    peer._receive(_frame(seed, peer, "ACK", wire.ack_body(nonce), peer.identity.peer_id, logical=2))
    vt.advance(LINK_ANSWER_S + 1)
    peer._watch()
    assert sock.shut == 0 and peer.links_silent == 0
    # a second sleep, and this time the seed died in it: silent for the ping timeout
    peer.sent.clear()
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert _until(lambda: len(_pings(peer)) == 1)
    vt.advance(LINK_ANSWER_S - 0.5)
    assert not _until(lambda: sock.shut, 0.05), "within the ping timeout the seed may still answer"
    vt.advance(0.5)
    assert _until(lambda: sock.shut == 1) and peer.links_silent == 1, "no answer in 2 s: the link is dropped"
    # the reader's reconnect: the link held, so it dials at once, the lost seed last
    peer._socket = None
    assert peer._reconnect() is True
    assert peer.started == ["next"] and peer._seed == next_, "it failed over to the next seed"
    peer._running = False


def test_a_wake_fails_over_at_once_even_from_a_young_link():
    """Owner decision 2026-11-23, rule 3, the same in every client: a wake's PING left unanswered for the 2 s
    ping timeout fails over at once even when the link is younger than 5 s on the monotonic clock (which does
    not count the sleep). The wake already started the table again, so its verdict is no quick drop."""
    from agentspaces.peer import LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    lost, next_ = Seed("lost", 1, "tcp"), Seed("next", 1, "tcp")
    peer, seed = _RacePeer(vt, {"lost": "answer", "next": "answer"}), Identity.generate()
    peer._seeds, peer._seed = [lost, next_], lost
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))  # seed known
    peer._link_since = vt.monotonic() - 1  # the link came up a second before the sleep
    peer._redial_at = 3
    peer.sent.clear()
    peer._judge_wall_step()  # anchor
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert _until(lambda: len(_pings(peer)) == 1)
    vt.advance(LINK_ANSWER_S)
    assert _until(lambda: sock.shut == 1), "no answer in 2 s: the link is dropped"
    peer._socket = None
    done, box = _in_thread(peer._reconnect)
    assert _until(lambda: peer.started == ["next"]), "a 3 s link the wake's verdict closed fails over at once"
    assert _until(done.is_set) and box.get("result") is True and peer._redial_at == 0
    peer._running = False


def test_a_wake_with_a_ping_waiting_adopts_it_and_fails_over_at_once():
    """A wake that finds a PING to the seed already waiting sends no second one (as every client); that PING
    becomes the wake's, so its verdict fails over at once however young the link."""
    from agentspaces.peer import LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    lost, next_ = Seed("lost", 1, "tcp"), Seed("next", 1, "tcp")
    peer, seed = _RacePeer(vt, {"lost": "answer", "next": "answer"}), Identity.generate()
    peer._seeds, peer._seed = [lost, next_], lost
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))
    peer._link_since = vt.monotonic() - 1
    peer.sent.clear()
    peer._judge_wall_step()
    peer._ask_link()
    assert _until(lambda: len(_pings(peer)) == 1)
    vt.advance(0.5)
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert not _until(lambda: len(_pings(peer)) > 1, 0.05), "the PING waiting is not sent again"
    vt.advance(LINK_ANSWER_S - 0.5)
    assert _until(lambda: sock.shut == 1)
    peer._socket = None
    done, box = _in_thread(peer._reconnect)
    assert _until(lambda: peer.started == ["next"]), "the wake's verdict fails over at once"
    assert _until(done.is_set) and box.get("result") is True
    peer._running = False


# ---------------------------------------------- round 2b part 2: the owner's decisions of 2026-11-23

def test_an_unruled_on_estimate_waits_eight_seconds_as_javas_default_and_settle_0s_fires_at_once():
    """DRIFT-FROM-PHASE6 item 4: Java's ``@OnEstimate`` with no rule waits 8 s (``settle = ""``); before this an
    unruled ``@on_estimate`` here fired on the first estimate present. ``settle="0s"`` is the opt-in."""
    from agentspaces.agents import _META, ESTIMATE_SETTLE_DEFAULT
    assert ESTIMATE_SETTLE_DEFAULT == "8s"
    peer = VPeer(VirtualTime(start_wall_ms=T))
    aggregate = Aggregate(Pipes(peer), advertise=False)
    unruled, at_once = [], []

    @agent("estimator")
    class Estimator:
        @on_estimate(epochs="load")
        def settled(self, estimate):
            unruled.append(estimate)

        @on_estimate(epochs="load", settle="0s")
        def first(self, estimate):
            at_once.append(estimate)

    assert getattr(Estimator.settled, _META)["ticks"] is None and getattr(Estimator.settled, _META)["settle"] is None
    on_estimate(ticks=0)  # an explicit count of none is still a rule (fire at once), not both
    with pytest.raises(ValueError):
        on_estimate(ticks=0, settle="4s")
    bound = Binder(peer, publish_card=False, aggregate=aggregate).bind(Estimator())
    try:
        aggregate.start("load", 3.0)
        aggregate.tick()
        assert _until(lambda: at_once), "settle='0s' fires on the first estimate present"
        for _ in range(6):
            aggregate.tick()
        assert not _until(lambda: unruled, 0.05), "no rule is 8 s, not at once"
        for _ in range(3):
            aggregate.tick()
        assert _until(lambda: unruled), "settled after eight rounds of one second"
        assert len(at_once) == 1 and len(unruled) == 1
    finally:
        bound.close()
        aggregate.close()


def _bound_take(vt, handler, lease_millis=900_000, writer=None):
    """A ``@space_take`` binding on a VPeer whose space hands the binder one held take (claim to T + 600 s),
    then nothing. Returns (peer, bound, taken); ``writer``, a list, receives (the writer, its write)."""
    from agentspaces.agents import space_take
    peer = VPeer(vt)
    host = Identity.generate()
    write = _write(host, T, lease_millis=3_600_000)
    if writer is not None:
        writer.append((host, write))
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    Link(host, peer).rumor(write)
    holder = peer.identity.agent("python")
    peer.claims[entry_id] = wire.signed_claim(
        wire.take_claim(entry_id, space_id, 1, f"{T + 10}:0:{holder}", holder, 0.0, T + 600_000), peer.identity)

    @agent("worker")
    class Worker:
        @space_take("tasks", lease="15m")
        def work(self, task: Note):
            return handler()

    binder = Binder(peer, publish_card=False)
    space = binder.space("tasks")
    taken = Taken(space, entry_id, {"x": 1}, lease_millis)
    handed, idle = [taken], threading.Event()

    def take(template, lease=None, timeout=None):
        if handed:
            return handed.pop()
        idle.wait(0.02)
        return None

    space.take = take
    return peer, binder.bind(Worker()), taken


def _renewals(peer) -> int:
    return sum(1 for kind, body, _ in peer.sent if kind == "RUMOR" and ":renew:" in cbor.loads(body)["itemId"])


def test_a_handler_renewing_through_its_take_context_stops_renewing_once_its_agent_is_unbound_or_revoked():
    """DRIFT-FROM-PHASE6 item 11, the unbound half (the core's I-05): a handler (an LLM stream's keepalive)
    renewing through ``TakeContext`` renews only while the binder would, so a hung handler cannot keep the
    entry past the unbind. A revoked holder's renewal is refused, as before."""
    from agentspaces.space import TakeContext
    vt = VirtualTime(start_wall_ms=T)
    renewed, go, results = threading.Event(), threading.Event(), []

    def handler():
        context = TakeContext.current()
        results.append(context.renew())
        renewed.set()
        go.wait(5)
        results.append(context.renew(lease=1_200_000))  # would move the hold again, were it renewable
        return None

    peer, bound, taken = _bound_take(vt, handler)
    closer = threading.Thread(target=bound.close, daemon=True)
    try:
        assert _until(lambda: renewed.is_set())
        assert results == [True] and _renewals(peer) == 1, "bound: the context renews"
        closer.start()  # the unbind; close() waits for the handler
        assert _until(lambda: not bound._running)
        go.set()
        closer.join(5)
        assert results == [True, False] and _renewals(peer) == 1, "unbound: nothing is renewed or sent"
        assert taken._renewable is not None and not taken._renewable()
    finally:
        go.set()
        bound.close()
    # a revoked holder's renewal: refused before anything is sent
    taken._renewable = None
    peer.revocations.refuses = lambda *args: True
    with pytest.raises(ValueError, match="revoked"):
        taken.renew(lease=1_500_000)
    assert _renewals(peer) == 1


def test_a_wake_rechecks_held_takes_so_a_lapsed_one_stops_renewing_and_its_result_is_late():
    """Owner decision C05 (2026-11-23): the lease is wall time another peer reads, so on every wake or wall
    step the binder judges each held take at once. One whose lease lapsed in the sleep renews no more, even
    after the wall clock steps back, and its result is late: written nowhere and not completed."""
    vt = VirtualTime(start_wall_ms=T)
    started, woke, results = threading.Event(), threading.Event(), []

    def handler():
        started.set()
        woke.wait(5)
        from agentspaces.space import TakeContext
        results.append(TakeContext.current().renew(lease=3_600_000))
        return {"answer": 42}

    peer, bound, taken = _bound_take(vt, handler)
    try:
        assert _until(lambda: started.is_set())
        peer._judge_wall_step()  # anchor
        vt.step_wall(300_000)  # five minutes: the claim (to T + 600 s) still holds
        peer._judge_wall_step()
        assert not taken.late and bound.late_takes == 0, "a step within the lease keeps the take"
        vt.step_wall(KEEPALIVE_TTL_MS + 600_000)  # the laptop slept past the lease
        peer._judge_wall_step()
        assert taken.late and bound.late_takes == 1, "the wake judged the held take at once"
        vt.step_wall(-(KEEPALIVE_TTL_MS + 600_000))  # NTP steps the wall back inside the old lease
        peer._judge_wall_step()
        assert bound.late_takes == 1
        sent_before = len(peer.sent)
        woke.set()
        assert _until(lambda: results) and results == [False], "a late take renews no more"
        bound.close()
        assert _renewals(peer) == 0
        assert not (peer.states[taken.entry_id].get("completed")), "the late result did not complete the entry"
        assert not [k for k, body, _ in peer.sent[sent_before:]
                    if k == "RUMOR" and cbor.loads(body)["streamId"] == "space:tasks"], "and wrote nothing"
        with pytest.raises(ValueError, match="slept"):
            taken.complete({"answer": 42})
    finally:
        woke.set()
        bound.close()
    assert bound.recheck_holds not in peer._wall_step_listeners


def test_the_redial_and_seed_counters_read_under_the_shared_names():
    """Owner decision 2026-11-23: one set of counter names in every client (snake_case here): seed_pings,
    wake_pings, links_silent, resumes, seed_dials and late_seed_channels, in ``loop_health()`` too; the
    earlier ``linksSilent`` key stays as an alias for one release."""
    from agentspaces.peer import DIAL_STAGGER_S, LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    peer = _RacePeer(vt, {"dead": "hold", "live": "answer", "spare": "answer"})
    done, box = _in_thread(lambda: peer.connect_any(
        [Seed("dead", 1, "tcp"), Seed("live", 1, "tcp"), Seed("spare", 1, "tcp")], dial_timeout=10))
    assert _until(lambda: peer.started == ["dead"])
    vt.advance(DIAL_STAGGER_S)
    assert _until(done.is_set) and "error" not in box
    assert peer.seed_dials == 2 and peer.late_seed_channels == 0
    peer.release["dead"].set()
    assert _until(lambda: peer.late_seed_channels == 1), "the black-holed seed's late connection, closed"
    # a wake with the link up: one PING, the wake's; no answer, so the link is dropped for silence
    seed = Identity.generate()
    peer._socket = _ShutSocket()
    peer._receive(_frame(seed, peer, "PING", wire.ping_body(1), peer.identity.peer_id))
    peer._judge_wall_step()
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert _until(lambda: peer.wake_pings == 1)
    vt.advance(LINK_ANSWER_S)
    assert _until(lambda: peer.links_silent == 1)
    health = peer.loop_health()
    assert {k: health[k] for k in ("seed_pings", "wake_pings", "links_silent", "resumes", "seed_dials",
                                   "late_seed_channels")} == {
        "seed_pings": 1, "wake_pings": 1, "links_silent": 1, "resumes": 1, "seed_dials": 2,
        "late_seed_channels": 1}
    assert health["linksSilent"] == health["links_silent"], "the old key, an alias for one release"
    peer._running = False


# ------------------------------------------------ final round: the owner's decisions of 2026-11-23 ("on 1, I'm good")

def _holder_behind_a_seed(complete=True):
    """A dial-only peer behind its seed (``host``) that completed one entry of ``tasks`` under its own claim (unless
    ``complete`` is false), and then a rival's earlier claim displaced it; a second entry of ``tasks`` it merely
    holds. Returns (peer, seed, rival, clock, entry id, its state, its displaced claim, the other entry id)."""
    clock = _BothClocks()
    host, rival = Identity.generate(), Identity.generate()
    peer = VPeer(clock.vt, clock=clock.clock)
    link = Link(host, peer)
    space = Space(peer, "tasks")
    write, other = _write(host, T, lease_millis=600_000), _write(host, T + 1, lease_millis=600_000)
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    link.rumor(write)
    link.rumor(other)
    holder = peer.identity.agent("python")
    mine = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T + 10}:0:{holder}", holder, 0.0,
                                             T + 300_000), peer.identity)
    peer.claims[entry_id] = mine
    if complete:
        Taken(space, entry_id, {"x": 1}, 300_000).complete()
    completed = peer.states[entry_id]
    rival_holder = rival.agent("worker")
    better = wire.signed_claim(wire.take_claim(entry_id, space_id, 1, f"{T}:0:{rival_holder}", rival_holder,
                                               0.0, T + 300_000), rival)
    Link(rival, peer).rumor(None, claim=(entry_id, better))
    peer._seed, peer.seed_peer = Seed("seed", 1, "tcp"), host.peer_id  # linked behind its seed from here
    peer.sent.clear()
    return peer, host, rival, clock, entry_id, completed, mine, other["record"]["entryId"]


_RELAYED = [1000]


def _relayed_digest(seed: Identity, asker: Identity, peer: Peer, digests: dict) -> None:
    """A DIGEST from ``asker`` addressed to ``peer``, carried by ``peer``'s seed in a RELAY_FRAME."""
    _RELAYED[0] += 2
    inner = _frame(asker, peer, "DIGEST", wire.digest_body(digests), peer.identity.peer_id, logical=_RELAYED[0])
    peer._receive(_frame(seed, peer, "RELAY_FRAME", wire.relay_frame_body(peer.identity.peer_id, inner),
                         peer.identity.peer_id, logical=_RELAYED[0] + 1))


def _relayed_answers(peer: Peer, to: str) -> list:
    """The PULL_RESPs ``peer`` sent back through its seed to ``to``: each its decoded deltas."""
    out = []
    for kind, body, _ in peer.sent:
        if kind == "RELAY_FRAME":
            relay = cbor.loads(body)
            inner = wire.decode_frame(relay["frame"])
            if relay["target"] == to and inner["kind"] == "PULL_RESP" and inner["to"] == to:
                out.append(cbor.loads(inner["body"])["deltas"])
    return out


def test_a_dial_only_holder_answers_a_relayed_digest_with_only_its_displaced_entries_back_through_the_seed():
    """Owner decision 1 (2026-11-23): a dial-only peer answers a relayed DIGEST only for the spaces where it holds a
    displaced claim or completion, sending only those entries, back through its seed, so a winner's targeted round
    toward it brings the completion and its claim; the seed's own DIGEST is answered as before."""
    peer, seed, rival, clock, entry_id, completed, mine, other_id = _holder_behind_a_seed()
    _relayed_digest(seed, rival, peer, {"space:tasks": b"", "space:notes": b"", "ads": b""})
    (deltas,), = [_relayed_answers(peer, rival.peer_id)]
    assert list(deltas) == ["space:tasks"], "only a space where it holds a displaced claim"
    sync = cbor.loads(deltas["space:tasks"])
    assert sync["claims"] == {entry_id: mine}, "the displaced claim, not the kept one"
    assert [s["record"]["entryId"] for s in sync["states"]] == [entry_id] and sync["states"][0]["completed"]
    assert other_id not in {s["record"]["entryId"] for s in sync["states"]}, "only those entries"
    assert [kind for kind, _, _ in peer.sent] == ["RELAY_FRAME"] and peer.sent[0][2] == seed.peer_id
    assert peer.displaced_digest_answers == 1 and peer.pulls_answered == 0 and \
        peer.loop_health()["displaced_digest_answers"] == 1
    # The winner folds it: the completion and the displaced claim reach a replica through the answer.
    replica = VPeer(clock.vt, clock=clock.clock)
    Space(replica, "tasks")
    replica._receive(_frame(peer.identity, replica, "PULL_RESP",
                            cbor.dumps({"deltas": cbor.canonical_map(deltas)}), replica.identity.peer_id))
    assert replica.states[entry_id]["completed"]
    # A winner that already holds both lines is sent nothing; a space with nothing displaced is ignored and counted.
    peer.sent.clear()
    _relayed_digest(seed, rival, peer, {"space:tasks": replica.space_digest("tasks")})
    _relayed_digest(seed, rival, peer, {"space:notes": b""})
    assert peer.sent == [] and peer.ignored_kinds.get("DIGEST") == 1
    # The seed's own round is answered as before, whole.
    _seed_round = _frame(seed, peer, "DIGEST", wire.digest_body({"space:tasks": b""}), peer.identity.peer_id,
                         logical=9_000)
    peer._receive(_seed_round)
    (body, to), = _pull_resps(peer)
    assert to == seed.peer_id and peer.pulls_answered == 1
    assert {s["record"]["entryId"] for s in cbor.loads(cbor.loads(body)["deltas"]["space:tasks"])["states"]} == \
        {entry_id, other_id}


def test_final_alignment_a_relayed_digest_draws_a_displaced_claim_made_here_with_no_completion():
    """Owner decision 1, aligned with the core (``ReplicatedSpace.displacedFor``): a relayed DIGEST draws each entry
    whose claim made here a better claim displaced, with or without a completion under it, and nothing else: the
    displaced claim, and the entry's state where the asker lacks it."""
    peer, seed, rival, clock, entry_id, state, mine, other_id = _holder_behind_a_seed(complete=False)
    assert not state.get("completed")
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    answers = _relayed_answers(peer, rival.peer_id)
    assert len(answers) == 1, "a displaced claim with no completion under it draws an answer"
    sync = cbor.loads(answers[0]["space:tasks"])
    assert sync["claims"] == {entry_id: mine}, "the displaced claim"
    assert [s["record"]["entryId"] for s in sync["states"]] == [entry_id], "that entry alone"
    assert peer.displaced_digest_answers == 1


def test_final_cross_check_a_member_flooding_relayed_digests_cannot_starve_another_winners_answer():
    """Cross-client check of decision 1 (2026-11-23): the answer bucket is per asker, as in every client, so a member
    that keeps sending relayed DIGESTs spends only its own bucket and a winner's targeted round is still answered."""
    from agentspaces.peer import RELAYED_ANSWER_ASKERS, RELAYED_ANSWER_BURST
    peer, seed, rival, clock, entry_id, completed, mine, other_id = _holder_behind_a_seed()
    flooder = Identity.generate()
    for _ in range(4 * RELAYED_ANSWER_BURST):
        _relayed_digest(seed, flooder, peer, {"space:tasks": b""})
    assert len(_relayed_answers(peer, flooder.peer_id)) == RELAYED_ANSWER_BURST
    assert peer.relayed_answers_paced == 3 * RELAYED_ANSWER_BURST
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})  # the winner's round, in the middle of the flood
    assert len(_relayed_answers(peer, rival.peer_id)) == 1, "the flood spent only the flooder's own bucket"
    assert peer.displaced_digest_answers == RELAYED_ANSWER_BURST + 1
    assert peer.loop_health()["displaced_digest_answers"] == RELAYED_ANSWER_BURST + 1
    assert RELAYED_ANSWER_ASKERS == 1024


def test_the_relayed_digest_answer_is_paced_and_lasts_while_the_displaced_claim_lives():
    """Decision 1's bounds: each asker's answers to relayed DIGESTs take a token bucket (16 at once, 4 a second, on
    the monotonic clock), which never holds back the seed's own round; and the displaced claim is answered for while
    it lives, after its re-offers are spent, and no longer once it lapses."""
    from agentspaces.peer import RELAYED_ANSWER_BURST
    peer, seed, rival, clock, entry_id, completed, mine, other_id = _holder_behind_a_seed()
    for _ in range(RELAYED_ANSWER_BURST + 1):
        _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    assert len(_relayed_answers(peer, rival.peer_id)) == RELAYED_ANSWER_BURST and peer.relayed_answers_paced == 1
    peer._receive(_frame(seed, peer, "DIGEST", wire.digest_body({"space:tasks": b""}), peer.identity.peer_id,
                         logical=9_000))
    assert len(_pull_resps(peer)) == 1, "the seed's round is not paced"
    clock.advance(250)  # one token back
    peer.sent.clear()
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    assert len(_relayed_answers(peer, rival.peer_id)) == 1 and peer.relayed_answers_paced == 2
    # Past every re-offer: the re-offer line is spent, the claim (to T + 300 s) still lives.
    for _ in range(REOFFER_MAX):
        clock.advance(32_000)
        peer._offer_displaced()
    assert peer._displaced_own == {} and peer.displaced_reoffers == REOFFER_MAX
    peer.sent.clear()
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    (deltas,), = [_relayed_answers(peer, rival.peer_id)]
    assert cbor.loads(deltas["space:tasks"])["claims"] == {entry_id: mine}
    clock.advance(300_000)  # the displaced claim lapsed: nothing is held to answer for
    peer.sent.clear()
    _relayed_digest(seed, rival, peer, {"space:tasks": b""})
    assert peer.sent == []


def test_a_result_arriving_after_its_take_lapsed_completes_nothing_and_counts_as_a_late_take():
    """Owner decision 2 (C05, 2026-11-23): a take has lapsed when its claim is no longer ours or its wall-time lease
    has expired. A result arriving after the lapse completes nothing, writes nothing and counts in late_takes,
    with no wake between (the lease ran out while the handler worked)."""
    vt = VirtualTime(start_wall_ms=T)
    go, results = threading.Event(), []

    def handler():
        go.wait(5)
        results.append(True)
        return {"answer": 42}

    peer, bound, taken = _bound_take(vt, handler)
    try:
        vt.advance(601)  # the claim (to T + 600 s) ran out while the handler worked; no wall step, no wake
        sent_before = len(peer.sent)
        go.set()
        assert _until(lambda: bound.late_takes == 1), "the late result is counted"
        assert taken.late and not peer.states[taken.entry_id].get("completed")
        assert not [k for k, body, _ in peer.sent[sent_before:]
                    if k == "RUMOR" and cbor.loads(body)["streamId"] == "space:tasks"], "and wrote nothing"
    finally:
        go.set()
        bound.close()


def test_a_result_arriving_after_a_better_claim_displaced_its_take_counts_as_a_late_take():
    """C05's other half: the claim is no longer ours (a better claim reached this replica after the settle window)."""
    vt = VirtualTime(start_wall_ms=T)
    go = threading.Event()

    def handler():
        go.wait(5)
        return {"answer": 42}

    peer, bound, taken = _bound_take(vt, handler)
    try:
        rival = Identity.generate()
        claim = peer.claims[taken.entry_id]["claim"]
        rival_holder = rival.agent("worker")
        better = wire.signed_claim(wire.take_claim(taken.entry_id, claim["spaceId"], 1, f"{T}:0:{rival_holder}",
                                                   rival_holder, 0.0, T + 600_000), rival)
        Link(rival, peer).rumor(None, claim=(taken.entry_id, better))
        assert peer.claims[taken.entry_id]["claim"]["holder"] == rival_holder
        go.set()
        assert _until(lambda: bound.late_takes == 1)
        assert not peer.states[taken.entry_id].get("completed")
    finally:
        go.set()
        bound.close()


def test_final_alignment_a_take_whose_entry_was_withdrawn_under_it_counts_as_a_late_take():
    """Owner decision 2, aligned with the core and the other clients: an entry withdrawn (or completed by another)
    while this replica still holds the take's claim is a lapse, since the claim is gone with the entry (Java's
    ``TakenEntry.held()``, Rust's ``held_claim`` asks the entry present). The take is marked late and counted once in
    ``late_takes``, and its result completes nothing; before, Python refused that result uncounted."""
    vt = VirtualTime(start_wall_ms=T)
    go, writer = threading.Event(), []
    peer, bound, taken = _bound_take(vt, lambda: go.wait(5) and {"answer": 42}, writer=writer)
    try:
        assert _until(lambda: taken in bound._held), "the handler holds the take"
        (host, write), = writer
        link = Link(host, peer)
        link.logical = 100  # past the write's frame, which the filter would take for a replay
        link.rumor(wire.sign_state(dict(write, removes=write["adds"]), host))
        assert peer.states[taken.entry_id]["removes"], "withdrawn by its writer"
        assert peer.claims[taken.entry_id]["claim"]["holder"].startswith(peer.identity.peer_id + "/"), \
            "the claim in the map is still ours"
        bound.recheck_holds()
        assert taken.late and bound.late_takes == 1, "a lapse, counted"
        bound.recheck_holds()
        assert bound.late_takes == 1, "once"
    finally:
        go.set()
        bound.close()


def test_a_loop_wake_more_than_30_s_late_with_no_wall_step_is_a_wake():
    """Owner decision 3 (2026-11-23): a watchdog check that comes back more than 30 s late with no wall step (a
    frozen process: SIGSTOP, a long pause) is a wake: the seed is PINGed, the held takes are judged at once, and a
    member card that lapsed only because this peer was frozen is asked for again (the view pull leaves it out), not
    dropped. 29 s late is load, not a freeze."""
    from agentspaces.identity import instant_iso
    from agentspaces.watchdog import PERIOD_S, Watchdog
    vt = VirtualTime(start_wall_ms=T)
    go = threading.Event()
    peer, bound, taken = _bound_take(vt, lambda: go.wait(5))
    try:
        member, fresh = Identity.generate(), Identity.generate()
        peer.members[member.peer_id] = wire.peer_advertisement(GROUP, member, instant_iso(T))
        dog = Watchdog(clock=vt.monotonic)
        dog.watch(peer)
        dog.check()  # the anchor
        vt.advance(PERIOD_S + 29)
        dog.check()
        assert peer.late_wakes == 0 and peer.resumes == 0, "29 s late: load, not a freeze"
        vt.advance(PERIOD_S + 571)  # frozen 9.5 min more: the member's card (to T + 600 s) lapsed meanwhile
        peer.members[fresh.peer_id] = wire.peer_advertisement(GROUP, fresh, instant_iso(T + 600_000))
        peer.sent.clear()
        dog.check()
        assert peer.late_wakes == 1 and peer.resumes == 1 and peer.wall_steps == 0 and dog.late_checks == 1
        assert peer.loop_health()["late_wakes"] == 1
        assert _until(lambda: peer.wake_pings == 1), "the seed is asked under the dead-seed rule"
        assert _until(lambda: taken.late and bound.late_takes == 1), "the held take is judged at once"
        assert _until(lambda: any(kind == "DIGEST" and "view" in cbor.loads(body)["digests"]
                                  for kind, body, _ in peer.sent))
        views = [cbor.loads(body)["digests"]["view"].decode().split() for kind, body, _ in peer.sent
                 if kind == "DIGEST" and "view" in cbor.loads(body)["digests"]]
        assert all(member.peer_id not in view and fresh.peer_id in view for view in views), \
            "the lapsed card is asked for again, the fresh one is named"
        assert member.peer_id in peer.members, "a probe, not a drop"
        dog.check()
        assert peer.late_wakes == 1, "the next on-time check is no wake"
    finally:
        go.set()
        bound.close()


def test_final_cross_check_a_member_whose_card_lapsed_in_a_freeze_counts_until_the_reprobe_ends():
    """Cross-client check of decision 3 (2026-11-23): after a wake a member whose card lapsed only during the absence
    is re-probed before it is judged by its card's age. Until the view answer folds, or VIEW_REPROBE_S (11.25 s, as
    Ruby and Rust) passes, it stays in the horizon's view as lacking the hint (the cautious side): a frozen peer must
    not collect past the horizon because the one member lacking the hint aged out while it was frozen."""
    from agentspaces.identity import instant_iso
    from agentspaces.peer import VIEW_REPROBE_S
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    member = Identity.generate()
    peer.members[member.peer_id] = wire.peer_advertisement(GROUP, member, instant_iso(T))  # to T + 600 s, no hint
    assert peer.view_advertises_horizon() is False, "a member lacking the hint"
    vt.advance(700)  # frozen: both clocks moved, the card lapsed meanwhile
    peer._resume()
    assert peer.view_reprobes == 1 and peer.loop_health()["view_reprobes"] == 1
    assert peer.view_advertises_horizon() is False, "re-probed, not dropped: still lacking the hint"
    vt.advance(VIEW_REPROBE_S - 0.5)
    assert peer.view_advertises_horizon() is False, "still waiting on the seed's answer"
    vt.advance(1.0)
    assert peer.view_advertises_horizon() is True, "no answer by the bound: judged by its card"
    # A view answer ends the re-probe at once.
    peer._resume()
    assert peer.view_advertises_horizon() is False
    peer._receive(_frame(member, peer, "PULL_RESP",  # any sender already in view: no new member is heard of
                         cbor.dumps({"deltas": cbor.canonical_map({"view": cbor.dumps([])})}),
                         peer.identity.peer_id))
    assert peer.view_advertises_horizon() is True, "the seed answered without the card: the member is gone"
    assert VIEW_REPROBE_S == 11.25


def test_a_wakes_ping_is_answered_by_bytes_of_a_frame_still_arriving():
    """Owner decision 4 (2026-11-23): bytes of a frame still arriving answer every ask of the seed, a wake's too."""
    from agentspaces.peer import LINK_ANSWER_S
    vt = VirtualTime(start_wall_ms=T)
    peer = VPeer(vt)
    peer._seed = Seed("seed", 1, "tcp")
    peer._socket = sock = _ShutSocket()
    peer._receive(_frame(Identity.generate(), peer, "PING", wire.ping_body(1), peer.identity.peer_id))
    peer._judge_wall_step()
    vt.step_wall(KEEPALIVE_TTL_MS + 5_000)
    peer._judge_wall_step()
    assert _until(lambda: peer.wake_pings == 1)
    vt.advance(1.0)
    peer._bytes_at = vt.monotonic()  # a large frame is arriving on a slow link
    vt.advance(LINK_ANSWER_S)
    peer._watch()
    assert sock.shut == 0 and peer.links_silent == 0, "the seed is writing: the wake's ask is answered"
    peer._running = False
