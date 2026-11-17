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

"""The settle guarantee, SPEC §7.4 (v0.1.35, 2026-11-15), as it binds this client.

A take wins an entry only while every rival claim reaches it within the settle window. A claim that
arrives later can displace a take that already won its window, and a holder that learns of the better
claim before it completes MUST NOT complete: ``Taken.complete`` raises, and neither its result nor its
completion goes out. Before, the result was written first and the completion was sent regardless."""

import time
from dataclasses import dataclass

import pytest

from agentspaces import wire
from agentspaces.identity import Identity
from agentspaces.peer import take_judged_within_millis
from agentspaces.space import Taken, entry
from test_cancel_events import TYPE, _completion, _member
from test_hlc_logical_limit import T, _write


@entry("com.acme.Outcome#v1")
@dataclass
class Outcome:
    n: int


def _won(receiver, space, write: dict, stamp_ms: int) -> Taken:
    """This replica's take of ``write``, won in its window with a claim stamped at ``stamp_ms``."""
    record = write["record"]
    holder = receiver.identity.agent("python")
    receiver.claims[record["entryId"]] = wire.signed_claim(
        wire.take_claim(record["entryId"], record["spaceId"], 1, f"{stamp_ms}:0:{holder}", holder, 0.0,
                        T + 600_000), receiver.identity)
    return Taken(space, record["entryId"], {"x": 1}, 60_000)


def test_a_take_displaced_by_an_earlier_claim_after_its_window_writes_no_result_and_does_not_complete():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    taken = _won(receiver, space, write, T + 10)
    # The rival's claim, stamped before this one, reaches this replica after the window.
    rival_link, rival_claim, _ = _completion(write, receiver)
    rival_link.rumor(None, claim=(entry_id, rival_claim))
    assert receiver._claim_of(entry_id)["holder"] != taken.holder, "the earlier claim displaced the take"
    sent = len(receiver.sent)
    with pytest.raises(ValueError, match="displaced"):
        taken.complete(Outcome(1))
    assert len(receiver.sent) == sent, "neither a result nor a completion goes out"
    assert receiver.states[entry_id].get("completed") is not True


def test_a_take_whose_rivals_completion_arrived_first_writes_no_result():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    taken = _won(receiver, space, write, T + 10)
    rival_link, rival_claim, completed = _completion(write, receiver)
    rival_link.rumor(completed, claim=(entry_id, rival_claim))
    sent = len(receiver.sent)
    with pytest.raises(ValueError):
        taken.complete(Outcome(1))
    assert len(receiver.sent) == sent, "the entry is done: nothing goes out"


def test_a_take_whose_claim_lapsed_writes_no_result():
    host = Identity.generate()
    write = _write(host, T)
    receiver, space, events, link, clock = _member(host)
    link.rumor(write)
    taken = _won(receiver, space, write, T)
    clock.millis = T + 600_001  # past the claim's expiry
    sent = len(receiver.sent)
    with pytest.raises(ValueError, match="lapsed"):
        taken.complete(Outcome(1))
    assert len(receiver.sent) == sent


def test_a_take_that_still_holds_writes_its_result_and_completes():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    link.rumor(write)
    taken = _won(receiver, space, write, T)
    sent = len(receiver.sent)
    assert taken.complete(Outcome(1)) is not None
    assert [kind for kind, _, _ in receiver.sent[sent:]] == ["RUMOR", "RUMOR"], "the result, then the completion"
    assert receiver.states[entry_id]["completed"] is True


# The take lease and the live claim (SPEC §7.4, 2026-11-15) --------------------------------------

def test_take_judged_within_is_the_window_and_its_follow_up_wait():
    assert take_judged_within_millis(600) == 900
    assert take_judged_within_millis(200) == 400, "a short window's follow-up wait is the window itself"
    assert take_judged_within_millis(0) == 0


@pytest.mark.parametrize("lease", [600, 800, 900])
def test_a_take_whose_lease_cannot_outlast_its_window_and_follow_up_wait_is_refused_at_once(lease):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    receiver._running = True  # as a connected peer's take runs
    link.rumor(write)
    sent = len(receiver.sent)
    started = time.monotonic()
    with pytest.raises(ValueError, match="must exceed 900 ms"):
        receiver.take_entry("tasks", TYPE, lease_millis=lease, settle_seconds=0.6, timeout_seconds=30.0)
    # Refused before any work: the 30 s timeout is the ceiling a doomed take used to run to.
    assert time.monotonic() - started < 5.0, "refused at once, not after the take's timeout"
    assert entry_id not in receiver.claims, f"no doomed {lease} ms claim was taken"
    assert len(receiver.sent) == sent, f"no doomed {lease} ms claim went out"


def test_a_take_whose_lease_outlasts_its_window_wins():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, _ = _member(host)
    receiver._running = True
    link.rumor(write)
    started = time.monotonic()
    assert receiver.take_entry("tasks", TYPE, lease_millis=1_500, settle_seconds=0.6, timeout_seconds=30.0) == entry_id
    # Measured, not bounded: a quiet take is judged after about 0.9 s.
    print(f"won in {time.monotonic() - started:.3f} s")


def test_a_take_whose_claim_lapsed_before_it_was_judged_does_not_win():
    """A late wake (a busy interpreter, a laptop that slept) can judge the race after the take's own
    claim lapsed. That claim is free for any taker already, so the take must not return the entry as
    held, as Java's tryTakeOnce and the TypeScript take judge only a live claim. The take's clock here
    jumps past each claim's expiry while it waits, so every claim it makes has lapsed when judged."""
    host = Identity.generate()
    write = _write(host, T, lease_millis=3_600_000)  # the entry outlives every jump below
    entry_id = write["record"]["entryId"]
    receiver, space, events, link, clock = _member(host)
    receiver._running = True
    link.rumor(write)
    lease = 1_000
    waited = receiver.await_fold
    epochs = []

    def late_wake(*args, **kwargs):
        claim = receiver._claim_of(entry_id)
        if claim is not None and claim["holder"].startswith(receiver.identity.peer_id + "/"):
            epochs.append(int(claim["epoch"]))
            clock.millis = int(claim["expiresAtMillis"]) + 1  # woke after the claim's expiry
        return waited(*args, **kwargs)

    receiver.await_fold = late_wake
    assert receiver.take_entry("tasks", TYPE, lease_millis=lease, settle_seconds=0.05, timeout_seconds=1.0) is None
    assert epochs, "the take claimed and was judged at least once"
    assert all(epoch == n + 1 for n, epoch in enumerate(epochs)), "each lapsed claim was succeeded, never kept"
