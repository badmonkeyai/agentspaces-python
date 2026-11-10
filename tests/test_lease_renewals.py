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

"""Lease renewals, 2026-11-09 (SPEC §7.3), as they bind this client.

A renewal is a later stamp in the state's lease register, re-signed by the issuer. The register
supersedes the lease the record was written with, as Java's EntryState and the TypeScript client
read it, so reads, takes, the sweep and an event's expiry all follow the renewed lease. Before this
fix a renewed entry vanished, and raised EXPIRED, at its first lease."""

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.space import EXPIRED, WRITTEN, Space, Template
from test_hlc_logical_limit import T, _with_lease_stamp, _write
from test_hlc_round_four import CapturingPeer, Clock, _receiver

TYPE = "T#v1"


def _kinds(events: list, entry_id: str) -> list:
    return [event.kind for event in events if event.entry.entry_id == entry_id]


def _ids(space: Space) -> list:
    return [entry.entry_id for entry in space.entries(Template(TYPE))]


def _takeable(peer) -> list:
    return [entry_id for entry_id, _ in peer._available(TYPE, peer._now_ms())]


def test_a_renewal_from_the_issuer_keeps_the_entry_past_its_first_lease():
    host = Identity.generate()
    write = _write(host, T)  # a 60 s lease
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    space = Space(receiver, "tasks")
    events = []
    space.watch(Template(TYPE), events.append)
    link.rumor(write)

    renewed_at = T + 30_000
    clock.millis = renewed_at
    link.rumor(_with_lease_stamp(write, host, wire.hlc_now(write["record"]["issuer"], renewed_at), renewed_at))
    clock.millis = T + 90_000  # past the first lease, inside the renewed one

    assert _ids(space) == [entry_id]
    assert _takeable(receiver) == [entry_id]
    assert space.entries(Template(TYPE))[0].expires_at_millis == renewed_at + 600_000
    space._sweep()
    assert _kinds(events, entry_id) == [WRITTEN]

    clock.millis = renewed_at + 600_000 + 1  # past the renewed lease
    assert _ids(space) == []
    assert _takeable(receiver) == []
    space._sweep()
    space._sweep()
    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]


def test_this_peers_own_renewal_keeps_its_entry_past_its_first_lease():
    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    space = Space(peer, "tasks")
    events = []
    space.watch(Template(TYPE), events.append)
    entry_id = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=1_000)

    clock.millis = T + 500
    peer.renew_entry("tasks", entry_id, 60_000)
    clock.millis = T + 5_000  # past the first lease, inside the renewed one

    assert _ids(space) == [entry_id]
    assert _takeable(peer) == [entry_id]
    space._sweep()
    assert EXPIRED not in _kinds(events, entry_id)


def test_an_older_renewal_arriving_late_moves_nothing():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    space = Space(receiver, "tasks")
    link.rumor(write)

    clock.millis = T + 40_000
    # stamped in order (hlc_now never runs backwards), delivered out of order
    earlier = _with_lease_stamp(write, host, wire.hlc_now(write["record"]["issuer"], T + 20_000), T + 20_000)
    later = _with_lease_stamp(write, host, wire.hlc_now(write["record"]["issuer"], T + 40_000), T + 40_000)
    link.rumor(later)
    link.rumor(earlier)  # last writer wins by stamp, not by arrival

    assert space.entries(Template(TYPE))[0].expires_at_millis == T + 40_000 + 600_000
    clock.millis = T + 20_000 + 600_000 + 1  # past the earlier renewal, inside the later one
    assert _ids(space) == [entry_id]


def test_a_renewal_that_lands_while_a_fold_of_the_entry_runs_is_kept():
    from test_cancel_events import _LandsDuringFold

    clock = Clock(T)
    peer = CapturingPeer(clock=clock)
    space = Space(peer, "tasks")
    entry_id = peer.write_entry("tasks", TYPE, {"x": 1}, lease_millis=1_000)
    write = dict(peer.states[entry_id])
    clock.millis = T + 500
    peer.states = _LandsDuringFold(peer.states, entry_id, lambda: peer.renew_entry("tasks", entry_id, 60_000))

    peer._fold(write)  # a partner offers the first write again
    peer.states.thread.join(5)
    clock.millis = T + 5_000  # past the first lease, inside the renewed one

    assert _ids(space) == [entry_id], "the fold kept the renewal"
