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

"""Core cancel events, 2026-11-09 (SPEC §7.2, v0.1.32 draft note), as they bind this client.

A cancel travels as the issuer's signed state whose removes cover its adds. Once it folds here the
entry is gone from reads and takes, and every watch hears EXPIRED, the kind a lapse raises, as Java's
ReplicatedSpace and LocalSpace raise it. A redelivered cancel raises nothing more, a cancel and a
lapse raise one EXPIRED between them, completion dominates a concurrent cancel, a holder whose replica
merged the withdrawal cannot complete, and an entry learned first as withdrawn raises nothing."""

import sys
import threading
import time

import pytest

from agentspaces import wire
from agentspaces.identity import Identity
from agentspaces.space import COMPLETED, EXPIRED, TAKEN, WRITTEN, Space, Template
from test_hlc_logical_limit import T, _write
from test_hlc_round_four import Link, _receiver

TYPE = "T#v1"


def _member(host: Identity):
    """A receiver of ``host``'s writes with a watch on the space, its link from ``host``, and its clock."""
    receiver, link, clock = _receiver(host)
    space = Space(receiver, "tasks")
    events = []
    space.watch(Template(TYPE), events.append)
    return receiver, space, events, link, clock


def _cancel(write: dict, host: Identity) -> dict:
    return wire.sign_state(dict(write, removes=list(write["adds"])), host)


def _kinds(events: list, entry_id: str) -> list:
    return [event.kind for event in events if event.entry.entry_id == entry_id]


def _gone(receiver, space: Space) -> None:
    """Nothing to read, and nothing among the candidates a take claims from."""
    assert space.entries(Template(TYPE)) == []
    assert list(receiver._available(TYPE, receiver._now_ms())) == []


def _completion(write: dict, receiver) -> tuple:
    """Another member's won take of ``write`` and its completion, both signed by the taker."""
    taker = Identity.generate()
    record = write["record"]
    holder = taker.agent("worker")
    claim = wire.signed_claim(wire.take_claim(record["entryId"], record["spaceId"], 1, f"{T}:0:{holder}", holder,
                                              0.0, T + 600_000), taker)
    completed = wire.sign_state(dict(write, completed=True), taker)
    return Link(taker, receiver), claim, completed


def test_a_folded_cancel_raises_expired_once_and_the_entry_is_gone():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    assert _kinds(events, entry_id) == [WRITTEN]

    link.rumor(_cancel(write, host))

    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]
    assert events[1].entry.value == {"x": 1}
    assert events[1].entry.issuer == write["record"]["issuer"]
    _gone(receiver, space)


def test_a_redelivered_cancel_raises_no_second_expired():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    cancel = _cancel(write, host)
    link.rumor(cancel)
    link.rumor(cancel)
    link.pull_resp([cancel], {})
    link.rumor(dict({k: v for k, v in cancel.items() if k != "record"}, issuerPublicKey=None, entryId=entry_id))
    space._sweep()
    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]
    _gone(receiver, space)


@pytest.mark.parametrize("order", ["lapse first", "cancel first", "lapsed, unswept"])
def test_a_cancel_and_a_lapse_raise_one_expired_between_them(order):
    host = Identity.generate()
    write = _write(host, T)  # a one-minute lease
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, clock = _member(host)
    link.rumor(write)
    if order == "lapse first":
        clock.millis = T + 120_000
        space._sweep()
        link.rumor(_cancel(write, host))
    elif order == "cancel first":
        link.rumor(_cancel(write, host))
        clock.millis = T + 120_000
        space._sweep()
    else:
        clock.millis = T + 120_000
        link.rumor(_cancel(write, host))
        space._sweep()
    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]
    _gone(receiver, space)


def test_a_holder_whose_replica_merged_the_withdrawal_cannot_complete():
    host = Identity.generate()
    write = _write(host, T)
    record = write["record"]
    entry_id = record["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    holder = receiver.identity.agent("python")
    receiver.claims[entry_id] = wire.signed_claim(
        wire.take_claim(entry_id, record["spaceId"], 1, f"{T}:0:{holder}", holder, 0.0, T + 600_000), receiver.identity)
    link.rumor(_cancel(write, host))
    sent = len(receiver.sent)
    with pytest.raises(ValueError, match="withdrawn"):
        receiver.complete_entry("tasks", entry_id)
    assert len(receiver.sent) == sent, "no completion goes out"
    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]


def test_a_cancel_that_folds_during_the_takers_settle_window_leaves_the_take_empty():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    receiver._running = True  # as a connected peer's take runs
    link.rumor(write)
    taken = []
    taking = threading.Thread(target=lambda: taken.append(
        receiver.take_entry("tasks", TYPE, settle_seconds=0.3, timeout_seconds=0.8)))
    taking.start()
    deadline = time.monotonic() + 5
    while not any(kind == "RUMOR" for kind, _, _ in receiver.sent) and time.monotonic() < deadline:
        time.sleep(0.005)  # until the claim went out: the take now waits out its settle window
    link.rumor(_cancel(write, host))
    taking.join(5)
    assert taken == [None], "the take found the entry withdrawn"
    assert _kinds(events, entry_id) == [WRITTEN, EXPIRED]


@pytest.mark.parametrize("cancel_first", [True, False])
def test_completion_dominates_a_concurrent_cancel(cancel_first):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    taker_link, claim, completed = _completion(write, receiver)
    taker_link.rumor(None, claim=(entry_id, claim))
    if cancel_first:
        link.rumor(_cancel(write, host))
        taker_link.rumor(completed, claim=(entry_id, claim))
        expected = [WRITTEN, TAKEN, EXPIRED, COMPLETED]
    else:
        taker_link.rumor(completed, claim=(entry_id, claim))
        link.rumor(_cancel(write, host))
        expected = [WRITTEN, TAKEN, COMPLETED]
    assert receiver.states[entry_id]["completed"] is True
    assert _kinds(events, entry_id) == expected
    _gone(receiver, space)


def test_an_entry_learned_first_withdrawn_raises_nothing():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.pull_resp([_cancel(write, host)], {})
    link.rumor(write)
    assert entry_id in receiver.states, "the tombstone is held"
    assert events == [], "a withdrawn entry learned late is history"
    _gone(receiver, space)


def test_a_watch_hears_one_expired_when_a_watch_before_it_closes_between_the_lapse_and_the_cancel():
    """Each watch keeps its own delivery marks, whatever other watches the space holds (core cancel events,
    2026-11-09): a watch registered first that closes after the lapse leaves the second watch's mark as it was,
    so the cancel that folds next raises no second EXPIRED there."""
    host = Identity.generate()
    write = _write(host, T)  # a one-minute lease
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    space = Space(receiver, "tasks")
    first, second = [], []
    opened = space.watch(Template(TYPE), first.append)
    space.watch(Template(TYPE), second.append)
    link.rumor(write)
    clock.millis = T + 120_000
    space._sweep()
    opened.close()
    link.rumor(_cancel(write, host))
    space._sweep()
    assert _kinds(first, entry_id) == [WRITTEN, EXPIRED]
    assert _kinds(second, entry_id) == [WRITTEN, EXPIRED]


def test_a_cancel_that_another_member_signs_withdraws_nothing_and_raises_nothing():
    """Only the entry's issuer may cancel it (SPEC §11a.4, core cancel events, 2026-11-09)."""
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    other = Identity.generate()
    Link(other, receiver).rumor(wire.sign_state(dict(write, removes=list(write["adds"])), other))
    space._sweep()
    assert _kinds(events, entry_id) == [WRITTEN]
    assert [entry.entry_id for entry in space.entries(Template(TYPE))] == [entry_id], "the entry stays"


class _LandsDuringFold(dict):
    """The peer's state map, which runs ``land`` on another thread right after ``_fold`` reads
    ``entry_id`` to join it, and gives it a moment to finish before the fold writes the join. Without one
    critical section around a fold's read and write, what lands there is overwritten."""

    def __init__(self, states: dict, entry_id: str, land):
        super().__init__(states)
        self.entry_id, self.land, self.thread = entry_id, land, None

    def get(self, key, default=None):
        value = super().get(key, default)
        if key == self.entry_id and self.thread is None and sys._getframe(1).f_code.co_name == "_fold":
            self.thread = threading.Thread(target=self.land)  # lands after the read, before the write
            self.thread.start()
            self.thread.join(0.3)
        return value


def test_a_completion_that_lands_while_a_fold_of_the_entry_runs_stays_completed():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    receiver.states = _LandsDuringFold(receiver.states, entry_id,
                                       lambda: receiver.complete_entry("tasks", entry_id))

    link.rumor(write)  # a partner offers the write again
    receiver.states.thread.join(5)

    assert receiver.states[entry_id]["completed"] is True, "the fold kept the holder's completion"
    _gone(receiver, space)
