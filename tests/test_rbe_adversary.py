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

"""The adversarial review of replication by entry on the Python peer (SPEC v0.1.35 §7.2 to §7.4;
srad/replication-by-entry.md phase 8, deferred to the combined testing round).

- ``Taken`` read its holder back from the lattice after the take returned, so a rival's better
  claim that folded in between became the claim the completion checked, and the completion
  passed: a result written and a completion signed for an entry another member holds.
- The per-entry horizon's hysteresis counted a fixed second as a round, which cuts SPEC §7.3's
  three rounds of anti-entropy short in a group whose gossip period is longer.
- Guards for what the review found sound here: a renewal and a cancel from two threads leave the
  entry withdrawn, since both run under the state lock, and a reordered older card never brings
  back a hint the member dropped."""

import threading
from dataclasses import dataclass

import pytest

from agentspaces import horizon, peer as peer_module, wire
from agentspaces.identity import Identity, instant_iso
from agentspaces.space import Taken, entry
from test_cancel_events import _completion, _member
from test_hlc_logical_limit import GROUP, T, _write
from test_hlc_round_four import CapturingPeer, Clock

TYPE = "T#v1"
MINUTE = 60 * 1000
HOUR = 60 * MINUTE


@entry("com.acme.AdvOutcome#v1")
@dataclass
class Outcome:
    n: int


def test_taken_holds_the_claim_its_take_won_not_a_rival_that_folded_after():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, _, link, _ = _member(host)
    link.rumor(write)
    holder = receiver.identity.agent("python")
    receiver.claims[entry_id] = wire.signed_claim(
        wire.take_claim(entry_id, write["record"]["spaceId"], 1, f"{T + 10}:0:{holder}", holder, 0.0, T + 600_000),
        receiver.identity)
    # The take judged its win; the rival's earlier claim folds before Taken reads the lattice.
    rival_link, rival_claim, _ = _completion(write, receiver)
    rival_link.rumor(None, claim=(entry_id, rival_claim))
    taken = Taken(space, entry_id, {"x": 1}, 60_000)
    assert taken.holder == holder, "the take's own holder, not the rival's"
    sent = len(receiver.sent)
    with pytest.raises(ValueError, match="displaced"):
        taken.complete(Outcome(1))
    assert len(receiver.sent) == sent, "neither a result nor a completion goes out"
    assert receiver.states[entry_id].get("completed") is not True


def test_the_hysteresis_round_is_the_groups_gossip_period():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    assert peer.horizon_round_millis() == peer_module.HORIZON_ROUND_MILLIS, "Java's default period, unknown here"
    peer.founding = {"advertisement": {"gossip": {"fanout": 3, "period": "PT5S"}}}
    assert peer.horizon_round_millis() == 5000
    for second in range(peer_module.DEFAULT_HORIZON_ENGAGE_ROUNDS * 5):
        clock.millis = T + second * 1000
        peer.horizon_rule()
    assert peer.horizon_mode == "WAITING", "three judged seconds are not three rounds of a five-second period"
    clock.millis = T + peer_module.DEFAULT_HORIZON_ENGAGE_ROUNDS * 5000
    peer.horizon_rule()
    assert peer.horizon_mode == "SETTLING"


def test_a_renewal_and_a_cancel_from_two_threads_leave_the_entry_withdrawn(monkeypatch):
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    entry_id = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=10 * MINUTE)
    original = wire.sign_state
    canceller = threading.Thread(target=peer.cancel_entry, args=("tasks", entry_id))

    def signing(*args, **kwargs):
        # The cancel starts while the renewal signs, as a caller on another thread would.
        if not canceller.is_alive() and canceller.ident is None:
            canceller.start()
            canceller.join(0.2)
        return original(*args, **kwargs)

    monkeypatch.setattr(wire, "sign_state", signing)
    peer.renew_entry("tasks", entry_id, HOUR)
    canceller.join(10)
    state = peer.states[entry_id]
    assert not peer_module.present(state), "the cancel stands, whichever ran first"
    assert horizon.lease_expiry(state) == T + HOUR, "the withdrawal carries the latest lease, its L"


def test_a_reordered_older_card_never_brings_back_a_hint_the_member_dropped():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    member = Identity.generate()

    def card(hints):
        ad = wire.peer_advertisement(GROUP, member, instant_iso(clock.millis - clock.millis % 1000), "PT10M", hints)
        return wire.signed_peer_ad(ad, member)

    older = card({"wire.horizon": "1"})
    clock.millis += 2000
    newer = card({})
    peer._accept_peer_ad(newer)
    peer._accept_peer_ad(older)
    assert "wire.horizon" not in peer.members[member.peer_id].get("resourceHints", {})
    assert peer.view_advertises_horizon() is False
