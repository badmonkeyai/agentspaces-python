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

"""The client-side CRDT conformance items: states join (ASF-017) so a replayed
early state cannot roll anything back, and the HLC is a real hybrid logical
clock with a skew clamp (ASF-043/020)."""

import time

from agentspaces import wire
from agentspaces.peer import Peer


def _tuple(stamp: str):
    physical, logical, node = stamp.split(":", 2)
    return int(physical), int(logical), node


def test_hlc_is_monotonic_within_one_millisecond():
    a = wire.hlc_now("hlc-test")
    b = wire.hlc_now("hlc-test")
    assert _tuple(b) > _tuple(a), "same-millisecond stamps must not collide"


def test_observed_stamps_order_later_local_stamps_after_them():
    ahead = f"{int(time.time() * 1000) + 5_000}:7:remote"
    wire.hlc_observe("hlc-test-2", ahead)
    assert _tuple(wire.hlc_now("hlc-test-2")) > _tuple(ahead)


def test_far_future_stamps_are_clamped_away():
    evil = f"{int(time.time() * 1000) + wire.MAX_HLC_SKEW_MILLIS + 60_000}:0:evil"
    wire.hlc_observe("hlc-clamped", evil)
    physical, _, _ = _tuple(wire.hlc_now("hlc-clamped"))
    assert physical < int(time.time() * 1000) + wire.MAX_HLC_SKEW_MILLIS


def test_a_replayed_early_state_cannot_roll_back_the_joined_view():
    newer = {
        "adds": [{"replica": "r1", "counter": 1}, {"replica": "r2", "counter": 1}],
        "removes": [{"replica": "r1", "counter": 1}],
        "leaseStamp": "200:0:r2",
        "leaseValue": {"holder": "r2/agent"},
        "completed": False,
    }
    replayed_initial = {
        "adds": [{"replica": "r1", "counter": 1}],
        "removes": [],
        "leaseStamp": "100:0:r1",
        "leaseValue": {"holder": "r1/agent"},
        "completed": False,
    }
    merged = Peer._join(newer, replayed_initial)
    assert merged["removes"] == [{"replica": "r1", "counter": 1}]
    assert len(merged["adds"]) == 2
    assert merged["leaseStamp"] == "200:0:r2"
    assert merged["leaseValue"] == {"holder": "r2/agent"}

    # Completion is monotone through the join.
    completed = Peer._join({**newer, "completed": True}, replayed_initial)
    assert completed["completed"] is True
