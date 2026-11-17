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

"""Replication by entry, phase 8 (srad/replication-by-entry.md RE-L-03; SPEC v0.1.35), as it
binds this client.

- The renewal rule of SPEC §7.2: issuer only, present and unexpired, never shorter; a take's
  renewal moves its claim, not the write lease (matrix P19); a subscription's never shortens.
- The horizons of SPEC §7.3: the lapse horizon, the drift floor, the per-entry horizon under
  ``wire.horizon=1`` with Java's hysteresis and the writer's half, the door that refuses a
  collected tombstone and acknowledges the refusal.
- The budgeted pull of annex I.6: a budget only toward a seed whose card carries ``wire.ae=2``,
  a short answer continued at once with this replica's own text digest, the 8 MiB frame kept.
- Completed on arrival (SPEC §7.2, decision 21): COMPLETED and never WRITTEN for an entry first
  learned completed, and a WRITTEN that waits for its payload only while the entry is live."""

import json
import pathlib

import pytest

from agentspaces import cbor, digests, horizon, peer as peer_module, wire
from agentspaces.identity import Identity, instant_iso, space_id_local
from agentspaces.space import COMPLETED, EXPIRED, TAKEN, WRITTEN, Space, Taken, Template
from test_cancel_events import _cancel, _completion, _kinds, _member
from test_hlc_logical_limit import GROUP, T, _write
from test_hlc_round_four import CapturingPeer, Clock, Link, _receiver

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
TYPE = "T#v1"
MINUTE = 60 * 1000
HOUR = 60 * MINUTE
SPACE_ID = space_id_local(f"{GROUP}/tasks")


class _Peer(peer_module.Peer):
    """A capturing peer built with the constructor's options."""

    def __init__(self, clock=None, **options):
        super().__init__(Identity.generate(), GROUP, clock=clock, **options)
        self.sent = []

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body, to))


def _rumors(peer) -> list:
    return [cbor.loads(body) for kind, body, _ in peer.sent if kind == "RUMOR"]


def _digests(peer) -> list:
    return [cbor.loads(body) for kind, body, _ in peer.sent if kind == "DIGEST"]


def _signed_ad(identity: Identity, now_ms: int, hints: dict, ttl: str = "PT24H") -> bytes:
    ad = wire.peer_advertisement(GROUP, identity, instant_iso(now_ms - now_ms % 1000), ttl, hints)
    return wire.signed_peer_ad(ad, identity)


# ----------------------------------------------------------------- the golden cases

def test_every_renew_clamp_case_gives_the_golden_expiry():
    cases = GOLDEN["renew_clamp_cases"]
    assert len(cases) == 5
    for case in cases:
        assert horizon.renewed_expiry(case["current"], case["now"], case["extension"]) == case["expiry"], case


def _state_of(kind: str, expiry: int) -> dict:
    adds = [{"replica": "zWriter", "counter": 1}]
    return {"adds": adds, "removes": adds if kind.startswith("withdrawn") else [],
            "completed": kind.endswith("completed"), "leaseValue": {"expiresAtMillis": expiry}}


def test_every_lapse_horizon_case_gives_the_golden_horizon():
    cases = GOLDEN["lapse_horizon_cases"]
    assert len(cases) == 12
    for case in cases:
        state = _state_of(case["state"], case["expiry"])
        assert horizon.collection_horizon(state, case["max_lease"]) == case["horizon"], case


def test_every_horizon_mode_case_gives_the_golden_horizon_and_verdict():
    cases = GOLDEN["horizon_mode_cases"]
    assert len(cases) == 64
    for case in cases:
        rule = {"legacy": horizon.LEGACY, "per-entry": horizon.PER_ENTRY}[case["mode"]]
        state = _state_of(case["state"], case["expiry"])
        assert horizon.collection_horizon(state, case["max_lease"], rule) == case["horizon"], case
        assert horizon.collectable(state, case["now"], case["max_lease"], rule) is case["collectable"], case


def test_the_text_digest_hashes_match_java_on_the_golden_vectors():
    state = cbor.loads(bytes.fromhex(GOLDEN["delta_cbor"]))["state"]
    assert digests.state_hash(state) == GOLDEN["space_state_hash"]
    claim = cbor.loads(bytes.fromhex(GOLDEN["claim_delta_cbor"]))["claim"]["claim"]
    assert digests.claim_hash(claim) == GOLDEN["space_claim_hash"]
    for text, expected in GOLDEN["java_double_strings"].items():
        assert digests.java_double_string(float(text)) == expected, text
    # A dot set hashes by membership, and each component of the state counts.
    assert digests.state_hash(dict(state, adds=state["adds"] * 2)) == GOLDEN["space_state_hash"]
    assert digests.state_hash(dict(state, completed=True)) != GOLDEN["space_state_hash"]
    assert digests.digest_text({"e:b": "1", "c:a": "2", "e:a": "3"}, ["e:z=9"]) == b"c:a=2\ne:a=3\ne:b=1\na:e:z=9\n"


def test_the_budgeted_get_space_body_is_the_golden_one():
    body = wire.digest_body({"space:tasks": b""}, budget=peer_module.DEFAULT_PULL_BUDGET)
    assert body.hex() == GOLDEN["digest_get_space_budget_body_cbor"]
    assert wire.digest_body({"space:tasks": b""}).hex() == "bf6764696765737473bf6b73706163653a7461736b7340ffff"
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            wire.digest_body({"space:tasks": b""}, budget=bad)


# ----------------------------------------------------------------- the renewal rule (SPEC §7.2)

def test_a_renewal_never_shortens_the_lease_and_a_no_op_sends_nothing():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    entry_id = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=10 * MINUTE)
    clock.millis = T + 1000
    sent = len(peer.sent)
    assert peer.renew_entry("tasks", entry_id, MINUTE) is False
    assert peer.renew_entry("tasks", entry_id, 0) is False
    assert len(peer.sent) == sent, "a renewal the rule leaves unchanged publishes nothing"
    assert peer.states[entry_id]["leaseValue"]["expiresAtMillis"] == T + 10 * MINUTE
    assert peer.renew_entry("tasks", entry_id, 20 * MINUTE) is True
    assert peer.states[entry_id]["leaseValue"]["expiresAtMillis"] == T + 1000 + 20 * MINUTE
    (rumor,) = [r for r in _rumors(peer) if r["itemId"].startswith("r:")]
    assert rumor["itemId"] == f"r:{entry_id}:{T + 1000}"
    assert cbor.loads(rumor["payload"])["state"]["leaseValue"]["expiresAtMillis"] == T + 1000 + 20 * MINUTE


def test_a_renewal_of_an_entry_withdrawn_completed_lapsed_or_unknown_fails_and_sends_nothing():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    cancelled = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=10 * MINUTE)
    peer.cancel_entry("tasks", cancelled)
    lapsed = peer.write_entry("tasks", TYPE, {"x": 2}, lease_millis=MINUTE)
    completed = peer.write_entry("tasks", TYPE, {"x": 3}, lease_millis=10 * MINUTE)
    peer.states[completed] = dict(peer.states[completed], completed=True)
    clock.millis = T + 2 * MINUTE
    sent = len(peer.sent)
    for entry_id in (cancelled, lapsed, completed, "no-such-entry"):
        with pytest.raises(ValueError):
            peer.renew_entry("tasks", entry_id, HOUR)
    assert len(peer.sent) == sent


def test_only_the_issuer_renews_a_write():
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    write = _write(host, T)
    link.rumor(write)
    with pytest.raises(ValueError, match="written by"):
        receiver.renew_entry("tasks", write["record"]["entryId"], HOUR)


def _held_take(receiver, write: dict, expires: int) -> Taken:
    """A take the receiver won on another member's entry: its own claim, then a Taken over it."""
    entry_id = write["record"]["entryId"]
    holder = receiver.identity.agent("python")
    signed = wire.signed_claim(wire.take_claim(entry_id, SPACE_ID, 1, f"{T}:0:{holder}", holder, 0.0, expires),
                               receiver.identity)
    receiver.claims[entry_id] = signed
    return Taken(Space(receiver, "tasks"), entry_id, {"x": 1}, MINUTE)


def test_a_non_issuer_takers_renewal_moves_its_claim_and_not_the_write_lease():
    # Matrix P19: Taken.renew renews the take, as Java's TakenEntry.renew, never the write lease,
    # which only the issuer renews.
    host = Identity.generate()
    receiver, link, clock = _receiver(host)
    write = _write(host, T, lease_millis=HOUR)
    link.rumor(write)
    entry_id = write["record"]["entryId"]
    taken = _held_take(receiver, write, T + MINUTE)
    original = dict(receiver.claims[entry_id]["claim"])
    clock.millis = T + 1000
    assert taken.renew("5m") is True
    renewed = receiver.claims[entry_id]["claim"]
    assert renewed["expiresAtMillis"] == T + 1000 + 5 * MINUTE
    assert {k: v for k, v in renewed.items() if k != "expiresAtMillis"} == \
        {k: v for k, v in original.items() if k != "expiresAtMillis"}, "same epoch, stamp, holder and bid"
    assert receiver.states[entry_id]["leaseValue"]["expiresAtMillis"] == T + HOUR, "the write lease is the issuer's"
    rumor = _rumors(receiver)[-1]
    assert rumor["itemId"] == f"c:{entry_id}:renew:{T + 1000}"
    delta = cbor.loads(rumor["payload"])
    assert delta["state"] is None and delta["claimEntry"] == entry_id

    # Every other replica keeps the holder and takes the later expiry from the lattice.
    other, other_link, _ = _receiver(host)
    other._fold(dict(write))
    holder_link = Link(receiver.identity, other)
    holder_link.rumor(claim=(entry_id, wire.signed_claim(original, receiver.identity)))
    holder_link.rumor(claim=(entry_id, delta["claim"]))
    assert other.claims[entry_id]["claim"]["expiresAtMillis"] == T + 1000 + 5 * MINUTE

    # Shorter is a no-op that sends nothing; a lapsed take fails.
    sent = len(receiver.sent)
    assert taken.renew("10s") is False and len(receiver.sent) == sent
    clock.millis = T + HOUR
    with pytest.raises(ValueError, match="take lease lapsed"):
        taken.renew("5m")


def test_a_subscription_renewal_never_shortens_its_lease():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    space = Space(peer, "tasks")
    subscription = space.notify(Template(TYPE), lambda event: None, lease="10m")
    clock.millis = T + 1000
    subscription.renew("1m")
    assert subscription._expires_ms == T + 10 * MINUTE
    subscription.renew("20m")
    assert subscription._expires_ms == T + 1000 + 20 * MINUTE
    subscription.close()


# ----------------------------------------------------------------- the horizons (SPEC §7.3)

def test_a_lapsed_entry_is_collected_at_its_lapse_horizon_and_never_later_than_five_minutes():
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    short = _write(host, T)  # a 60 s lease: the lapse horizon is two leases, 120 s
    link.rumor(short)
    entry_id = short["record"]["entryId"]
    assert receiver.max_lease_of(SPACE_ID) == MINUTE
    assert receiver.collect_tombstones(T + MINUTE + 2 * MINUTE - 1) == []
    assert receiver.collect_tombstones(T + 3 * MINUTE) == [entry_id]
    assert receiver.states == {} and receiver.tombstones_collected == 1

    long_lease = _write(host, T, lease_millis=HOUR)  # the space's longest lease is an hour now
    link.rumor(long_lease)
    lapsing = _write(host, T)
    link.rumor(lapsing)
    lapsed_id = lapsing["record"]["entryId"]
    assert receiver.collect_tombstones(T + MINUTE + 5 * MINUTE - 1) == []
    assert receiver.collect_tombstones(T + MINUTE + 5 * MINUTE) == [lapsed_id]


def test_a_withdrawal_keeps_the_drift_floor_whatever_the_longest_lease():
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    withdrawn = _write(host, T)  # the longest lease is 60 s, so 2 x maxLease would be two minutes
    link.rumor(withdrawn)
    link.rumor(_cancel(withdrawn, host))
    lease_end = T + MINUTE
    # The host is in view without the hint (heard, no card), so the legacy rule holds.
    assert receiver.horizon_rule(lease_end) == horizon.LEGACY
    assert receiver.collect_tombstones(lease_end + 10 * MINUTE - 1) == []
    assert receiver.collect_tombstones(lease_end + 10 * MINUTE) == [withdrawn["record"]["entryId"]]


def test_a_completion_keeps_two_of_the_longest_leases_a_claim_counting_as_one():
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    completed = _write(host, T)
    taker_link, claim, done = _completion(completed, receiver)  # a ten-minute hold
    link.rumor(completed)
    taker_link.rumor(claim=(completed["record"]["entryId"], claim))
    taker_link.rumor(done)
    lease_end = T + MINUTE
    assert receiver.collect_tombstones(lease_end + 20 * MINUTE - 1) == []
    assert receiver.max_lease_of(SPACE_ID) == 10 * MINUTE, "the hold the claim grants is observed"
    assert receiver.collect_tombstones(lease_end + 20 * MINUTE) == [completed["record"]["entryId"]]


def test_a_collected_tombstone_offered_again_is_refused_at_the_door_and_acknowledged_for_a_while():
    host = Identity.generate()
    receiver, link, clock = _receiver(host)
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    cancel = _cancel(write, host)
    link.rumor(write)
    link.rumor(cancel)
    clock.millis = T + MINUTE + 10 * MINUTE
    assert receiver.collect_tombstones() == [entry_id]

    link.pull_resp([cancel], {})  # a lagging partner, whose own horizon is later
    link.pull_resp([write], {})
    assert receiver.states == {} and receiver.collected_reoffers_refused == 2
    text = receiver.space_digest("tasks").decode()
    assert f"a:e:{entry_id}={digests.state_hash(cancel)}\n" in text
    clock.millis += peer_module.COLLECTED_ACK_HOLD_MILLIS
    assert "a:" not in receiver.space_digest("tasks").decode(), "forgotten five minutes after the last refusal"


def _engage(peer, clock, start: int) -> None:
    """Judges the rule once per round until the hysteresis engages (WAITING, then SETTLING)."""
    for round_ in range(peer_module.DEFAULT_HORIZON_ENGAGE_ROUNDS + 1):
        clock.millis = start + round_ * peer_module.HORIZON_ROUND_MILLIS
        peer.horizon_rule()


def test_the_per_entry_horizon_engages_after_three_hinted_rounds_and_the_settle_then_collects_early():
    clock = Clock(T)
    hinted = CapturingPeer(clock=clock)
    assert hinted.wire_hints["wire.horizon"] == "1"
    entry_id = hinted.write_entry("tasks", TYPE, {"x": 1}, lease_millis=HOUR)
    hinted.cancel_entry("tasks", entry_id)
    assert hinted.horizon_rule() == horizon.LEGACY and hinted.horizon_mode == "WAITING"
    _engage(hinted, clock, T)
    assert hinted.horizon_mode == "SETTLING" and hinted.horizon_engagements == 1
    engaged = clock.millis
    clock.millis = engaged + HOUR + 5 * MINUTE - 1
    assert hinted.horizon_rule() == horizon.LEGACY
    clock.millis = engaged + HOUR + 5 * MINUTE
    assert hinted.horizon_rule() == horizon.PER_ENTRY
    assert hinted.horizon_mode == "PER_ENTRY" and hinted.horizon_settlements == 1
    # Its own withdrawal goes at L + max(5 min, MAX_DRIFT), ten minutes, not at L + 2 x maxLease.
    lease_end = T + HOUR
    assert hinted.collect_tombstones(lease_end + 10 * MINUTE - 1) == []
    assert hinted.collect_tombstones(lease_end + 10 * MINUTE) == [entry_id]

    unhinted = _Peer(clock=Clock(T), horizon_hint=False)
    assert "wire.horizon" not in unhinted.wire_hints
    entry_id = unhinted.write_entry("tasks", TYPE, {"x": 1}, lease_millis=HOUR)
    unhinted.cancel_entry("tasks", entry_id)
    _engage(unhinted, unhinted.clock, T)
    assert unhinted.horizon_mode == "LEGACY" and unhinted.horizon_engagements == 0
    assert unhinted.collect_tombstones(lease_end + 2 * HOUR - 1) == []
    assert unhinted.collect_tombstones(lease_end + 2 * HOUR) == [entry_id]


def test_a_member_without_the_hint_disengages_the_per_entry_horizon_at_once():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    entry_id = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=HOUR)
    peer.cancel_entry("tasks", entry_id)
    _engage(peer, clock, T)
    clock.millis += HOUR + 5 * MINUTE
    assert peer.horizon_rule() == horizon.PER_ENTRY
    stranger = Identity.generate()
    peer._accept_peer_ad(_signed_ad(stranger, clock.millis, {"wire.recordless": "1"}))
    assert peer.horizon_rule() == horizon.LEGACY
    assert peer.horizon_mode == "LEGACY" and peer.horizon_disengagements == 1
    assert peer.collect_tombstones(T + HOUR + 10 * MINUTE) == [], "the legacy horizon again"
    # A member heard from whose card has not arrived counts as lacking the hint too.
    lone = CapturingPeer(clock=Clock(T))
    lone.members[Identity.generate().peer_id] = {}
    assert lone.view_advertises_horizon() is False


@pytest.mark.parametrize("card_at, collected_early", [(0, True), (30 * MINUTE, False)])
def test_a_withdrawal_uses_the_per_entry_horizon_only_from_a_writer_in_view_long_enough(card_at, collected_early):
    # The writer's half of SPEC §7.3: a withdrawal whose writer has been a hinted member of the
    # view for one maximum lease plus the grace goes at L + 10 min; one whose writer came into view
    # later keeps the later of the two horizons, L + 2 x maxLease here.
    host = Identity.generate()
    clock = Clock(T)
    receiver = CapturingPeer(clock=clock)
    write = _write(host, T, lease_millis=HOUR)
    receiver._fold(dict(write))
    _engage(receiver, clock, T)
    clock.millis = T + card_at
    receiver._accept_peer_ad(_signed_ad(host, clock.millis, {"wire.horizon": "1"}))
    clock.millis = T + 2 * MINUTE
    receiver._fold(_cancel(write, host))
    entry_id = write["record"]["entryId"]
    lease_end = T + HOUR
    clock.millis = lease_end + 10 * MINUTE
    assert receiver.horizon_rule() == horizon.PER_ENTRY
    assert (receiver.collect_tombstones() == [entry_id]) is collected_early
    if not collected_early:
        # The writer becomes one this replica vouches for once its stay reaches the wait, and the
        # withdrawal goes then, judged afresh, still before the legacy horizon.
        trusted_at = T + card_at + HOUR + 5 * MINUTE
        assert receiver.collect_tombstones(trusted_at - 1) == []
        assert receiver.collect_tombstones(trusted_at) == [entry_id]


def test_engage_rounds_are_settable_within_their_bounds():
    peer = CapturingPeer(clock=Clock(T))
    peer.set_horizon_engage_rounds(1)
    assert peer.horizon_engage_rounds == 1
    for bad in (0, 65):
        with pytest.raises(ValueError):
            peer.set_horizon_engage_rounds(bad)


# ----------------------------------------------------------------- the budgeted pull (annex I.6)

class StandInSeed:
    """A seed that answers a DIGEST as Java's GossipBus.answerPull does: the states whose lines the
    asker's text digest lacks, present before tombstones, newest first, cut to the smaller of the
    asker's budget and its own cap, the first item always carried, with ``remainder`` when the
    body named a budget."""

    def __init__(self, identity: Identity, states: list, cap: int):
        self.identity, self.states, self.cap = identity, states, cap

    def answer(self, body: dict) -> bytes:
        text = body["digests"]["space:tasks"]
        remote = set(text.decode().split("\n"))
        offers = [s for s in self.states
                  if f"e:{s['record']['entryId']}={digests.state_hash(s)}" not in remote
                  and f"a:e:{s['record']['entryId']}={digests.state_hash(s)}" not in remote]
        offers.sort(key=lambda s: s["record"]["entryId"].encode())
        offers.sort(key=lambda s: wire.hlc_tuple(s["leaseStamp"]), reverse=True)
        offers.sort(key=lambda s: not peer_module.present(s))
        budget = body.get("budget")
        chosen = offers
        if budget is not None:
            room, chosen = min(budget, self.cap), []
            for s in offers:
                size = len(cbor.dumps(s))
                if chosen and size > room:
                    break
                chosen.append(s)
                room -= size
        answer = {"deltas": {"space:tasks": cbor.dumps({"states": chosen, "claims": {}})}}
        if budget is not None:
            answer["remainder"] = {"space:tasks": len(offers) - len(chosen)}
        return cbor.dumps(answer)


def _budgeted_receiver(seed: Identity, ae: str | None = "2"):
    """A receiver whose current connection reached ``seed``, which addressed it a frame, and whose
    card for the seed carries ``wire.ae`` when given."""
    receiver, link, clock = _receiver(seed)
    receiver._seed, receiver._socket = object(), object()  # a connection, as connect() leaves one
    hints = {"wire.recordless": "1"} if ae is None else {"wire.ae": ae}
    receiver._accept_peer_ad(_signed_ad(seed, clock.millis, hints))
    link.receiver._receive(link.frame("PING", wire.ping_body(1)))  # the seed addresses us: confirmed
    assert receiver.seed_peer == seed.peer_id
    receiver.sent.clear()
    return receiver, link, clock


def test_a_pull_toward_a_seed_without_wire_ae_is_the_unbudgeted_empty_digest():
    receiver, _, _ = _budgeted_receiver(Identity.generate(), ae=None)
    receiver.pull_space("tasks")
    (body,) = _digests(receiver)
    assert "budget" not in body and body["digests"]["space:tasks"] == b""


def test_a_pull_toward_a_seed_on_wire_ae_2_names_the_budget_and_offers_its_own_digest():
    seed = Identity.generate()
    receiver, link, _ = _budgeted_receiver(seed)
    receiver.pull_space("tasks")
    (body,) = _digests(receiver)
    assert body["budget"] == peer_module.DEFAULT_PULL_BUDGET and body["digests"]["space:tasks"] == b""
    assert set(body["digests"]) == {"space:tasks", *peer_module.revocations.STREAMS}
    write = _write(seed, T)
    link.rumor(write)
    receiver.sent.clear()
    receiver.pull_space("tasks")
    (body,) = _digests(receiver)
    assert body["digests"]["space:tasks"] == f"e:{write['record']['entryId']}={digests.state_hash(write)}\n".encode()

    # A connection to another seed, not yet confirmed, sends the empty digest without a budget.
    receiver._socket = object()
    receiver.sent.clear()
    receiver.pull_space("tasks")
    (body,) = _digests(receiver)
    assert "budget" not in body and body["digests"]["space:tasks"] == b""


def _drive(receiver, link, seed: StandInSeed, drop=(), duplicate=()) -> int:
    """Answers each DIGEST the receiver sends as the seed would, until it sends none; ``drop`` and
    ``duplicate`` name answers (by their index) that are lost or delivered twice. Returns how many
    DIGESTs went out."""
    asked = 0
    while True:
        pending = [body for kind, body, _ in receiver.sent if kind == "DIGEST"]
        receiver.sent.clear()
        if not pending:
            return asked
        for body in pending:
            index = asked
            asked += 1
            if index in drop:
                continue
            answer = seed.answer(cbor.loads(body))
            for _ in range(2 if index in duplicate else 1):
                receiver._receive(link.frame("PULL_RESP", answer))


def _many(host: Identity, count: int) -> list:
    return [_write(host, T + i, lease_millis=HOUR) for i in range(count)]


def test_a_short_answer_is_continued_at_once_until_the_space_is_whole():
    host = Identity.generate()
    states = _many(host, 60)
    seed = StandInSeed(host, states, cap=8 * 1024)  # the partner caps the budget at its own maximum
    receiver, link, _ = _budgeted_receiver(host)
    receiver.pull_space("tasks")
    asked = _drive(receiver, link, seed)
    assert set(receiver.states) == {s["record"]["entryId"] for s in states}
    assert asked > 3 and receiver.pull_continuations == asked - 1
    assert receiver._budgeted_pulls == {}, "the last answer left nothing out"
    # The newest went first: the first answer held the latest writes.
    receiver.sent.clear()
    receiver.pull_space("tasks")
    assert _drive(receiver, link, seed) == 1, "a pull of a whole space draws nothing more"


def test_a_lost_answer_ends_the_pull_and_the_next_pull_resumes_from_what_is_held():
    host = Identity.generate()
    states = _many(host, 40)
    seed = StandInSeed(host, states, cap=6 * 1024)
    receiver, link, _ = _budgeted_receiver(host)
    receiver.pull_space("tasks")
    _drive(receiver, link, seed, drop={2})
    held = len(receiver.states)
    assert 0 < held < len(states)
    receiver.pull_space("tasks")
    _drive(receiver, link, seed)
    assert len(receiver.states) == len(states)


def test_a_duplicated_answer_neither_stalls_nor_repeats_the_pull():
    host = Identity.generate()
    states = _many(host, 40)
    seed = StandInSeed(host, states, cap=6 * 1024)
    receiver, link, _ = _budgeted_receiver(host)
    receiver.pull_space("tasks")
    asked = _drive(receiver, link, seed, duplicate={0, 1})
    assert len(receiver.states) == len(states)
    single = _budgeted_receiver(host)
    single[0].pull_space("tasks")
    assert asked == _drive(single[0], single[1], seed), "a duplicate sends no extra DIGEST"


def test_an_answer_that_changes_nothing_sends_nothing_more():
    host = Identity.generate()
    receiver, link, _ = _budgeted_receiver(host)
    receiver.pull_space("tasks")
    receiver.sent.clear()
    # A remainder for the space, but no state this replica can take (an empty delta).
    receiver._receive(link.frame("PULL_RESP", cbor.dumps({
        "deltas": {"space:tasks": cbor.dumps({"states": [], "claims": {}})}, "remainder": {"space:tasks": 5}})))
    assert _digests(receiver) == []
    # A remainder for a space this replica did not pull is not a reason to ask.
    receiver._receive(link.frame("PULL_RESP", cbor.dumps({
        "deltas": {"space:other": cbor.dumps({"states": [], "claims": {}})}, "remainder": {"space:other": 5}})))
    assert _digests(receiver) == []


def test_the_digest_stays_under_the_frame_ceiling_keeping_what_the_partner_sends_first(monkeypatch):
    host = Identity.generate()
    receiver, link, _ = _receiver(host)
    states = _many(host, 20)
    for state in states:
        link.rumor(state)
    line = len(f"e:{states[0]['record']['entryId']}={digests.state_hash(states[0])}\n")
    monkeypatch.setattr(peer_module, "MAX_DIGEST_TEXT_BYTES", 5 * line + 10)
    text = receiver.space_digest("tasks")
    assert len(text) <= peer_module.MAX_DIGEST_TEXT_BYTES
    kept = {row.split("=")[0][2:] for row in text.decode().splitlines()}
    newest = {s["record"]["entryId"] for s in sorted(states, key=lambda s: wire.hlc_tuple(s["leaseStamp"]))[-5:]}
    assert kept == newest


# ----------------------------------------------------------------- completed on arrival (SPEC §7.2)

def test_an_entry_first_learned_completed_raises_completed_and_never_written():
    host = Identity.generate()
    receiver, space, events, link, _ = _member(host)
    write = _write(host, T)
    taker_link, claim, done = _completion(write, receiver)
    taker_link.pull_resp([done], {write["record"]["entryId"]: claim})
    space._sweep()
    assert _kinds(events, write["record"]["entryId"]) == [COMPLETED]


def test_an_entry_learned_lapsed_raises_no_written():
    host = Identity.generate()
    receiver, space, events, link, clock = _member(host)
    write = _write(host, T)
    clock.millis = T + MINUTE + 1
    link.rumor(write)
    assert _kinds(events, write["record"]["entryId"]) == []


def test_a_claim_that_came_before_its_entry_raises_taken_after_written():
    host = Identity.generate()
    receiver, space, events, link, _ = _member(host)
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    taker_link, claim, _ = _completion(write, receiver)
    taker_link.pull_resp([write], {entry_id: claim})
    assert _kinds(events, entry_id) == [WRITTEN, TAKEN]


def _block_write(host: Identity) -> tuple:
    data = cbor.dumps({"x": "y" * (wire.INLINE_PAYLOAD_LIMIT + 1)})
    cid = wire.block_cid(data)
    _, body = wire.entry_delta("tasks", GROUP, TYPE, None, host, "w", HOUR, now_ms=T, payload_ref=cid)
    return cbor.loads(cbor.loads(body)["payload"])["state"], cid, data


def _wants(peer) -> list:
    return [body for kind, body, _ in peer.sent if kind in ("BLOCK_WANT", "RELAY_FRAME")]


def test_a_block_entry_first_learned_completed_fetches_nothing_and_raises_nothing_without_its_block():
    host = Identity.generate()
    receiver, space, events, link, _ = _member(host)
    write, cid, data = _block_write(host)
    taker_link, claim, done = _completion(write, receiver)
    taker_link.pull_resp([done], {write["record"]["entryId"]: claim})
    assert _wants(receiver) == [], "an entry that arrived completed starts no fetch"
    receiver.blocks[cid] = data
    space._sweep()
    assert _kinds(events, write["record"]["entryId"]) == []


@pytest.mark.parametrize("meanwhile, expected", [(None, [WRITTEN]), ("completed", [COMPLETED]),
                                                 ("withdrawn", [])])
def test_a_written_deferred_for_its_block_reads_the_entry_again_when_the_block_lands(meanwhile, expected):
    host = Identity.generate()
    receiver, space, events, link, _ = _member(host)
    write, cid, data = _block_write(host)
    entry_id = write["record"]["entryId"]
    link.rumor(write)
    assert _kinds(events, entry_id) == [] and _wants(receiver), "the merge asks for the block"
    if meanwhile == "completed":
        taker_link, claim, done = _completion(write, receiver)
        taker_link.rumor(claim=(entry_id, claim))
        taker_link.rumor(done)
    elif meanwhile == "withdrawn":
        link.rumor(_cancel(write, host))
    receiver.blocks[cid] = data
    space._sweep()
    space._sweep()
    assert _kinds(events, entry_id) == expected
    assert EXPIRED not in _kinds(events, entry_id)
