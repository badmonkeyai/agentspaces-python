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
"""PDT 2 phase 7, P2-X-05 (srad/agentspaces-pdt2.md §4.11): this client cancels the entries it wrote
(``cancel_entry``, as Java's ``EntryHandle.cancel``), and a ref writer cancels its own superseded head
once the cancel grace has passed, where it used to renew every head it ever wrote for the life of the
process. A head stays while a fork still walks through it, as Java's ``Refs.cancellable`` keeps it."""

import pytest

from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import NodeStore, Pdt
from agentspaces.pdt.refs import CANCEL_GRACE_MS, PREF_TYPE
from agentspaces.peer import present
from agentspaces.space import EXPIRED, Space, Template
from fleet import Clock, Network, NetPeer
from test_hlc_logical_limit import T
from test_pdt_swarm import HeldPeer, HoldingNetwork, release

GROUP = "zPythonCancel"


def _node(network, clock, kind=NetPeer):
    peer = kind(network, GROUP, clock=clock)
    content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
    return peer, Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1, head_lease="10m")


def _pair():
    clock = Clock(T)
    network = Network()
    (pa, a), (pb, b) = _node(network, clock), _node(network, clock)
    for peer in (pa, pb):
        peer.introduce()
    for pdt in (a, b):
        pdt.trees.advertise()
    return clock, (pa, a), (pb, b)


def _head_entries(peer, root=None) -> dict:
    """The live head entries a peer holds, by entry id, with their root tag."""
    return {entry_id: (dto["record"].get("tags") or {}).get("root") for entry_id, dto in peer.states.items()
            if (dto.get("record") or {}).get("type") == PREF_TYPE and present(dto)
            and (root is None or (dto["record"].get("tags") or {}).get("root") == root)}


def test_cancel_entry_withdraws_an_own_entry_on_every_member_and_only_the_issuer_cancels():
    clock = Clock(T)
    network = Network()
    a, b = NetPeer(network, GROUP, clock=clock), NetPeer(network, GROUP, clock=clock)
    events = []
    Space(b, "tasks").watch(Template("T#v1"), events.append)
    entry_id = a.write_entry("tasks", "T#v1", {"x": 1}, lease_millis=60_000)
    assert present(b.states[entry_id])
    with pytest.raises(ValueError, match="not by this peer"):
        b.cancel_entry("tasks", entry_id)
    a.cancel_entry("tasks", entry_id)
    assert not present(a.states[entry_id]) and not present(b.states[entry_id])
    assert [e.kind for e in events if e.entry.entry_id == entry_id][-1] == EXPIRED
    renewed_at = a.states[entry_id]["leaseStamp"]
    a.cancel_entry("tasks", entry_id)  # a withdrawn entry stays as it is and nothing goes out
    assert a.states[entry_id]["leaseStamp"] == renewed_at


def test_a_writer_cancels_its_superseded_head_after_the_grace_and_renews_only_its_live_head():
    clock, (pa, a), (pb, _b) = _pair()
    facts = a.map_ref("facts")
    first = facts.swap(lambda m: m.assoc("k", 1)).root()
    second = facts.swap(lambda m: m.assoc("k", 2)).root()
    (old_id,) = _head_entries(pa, first)
    a.tick()
    clock.advance(CANCEL_GRACE_MS - 1)
    a.tick()
    assert _head_entries(pa, first) and _head_entries(pb, first), "the grace keeps it for a lagging reader"
    clock.advance(2)
    a.tick()
    assert not _head_entries(pa, first) and not _head_entries(pb, first)
    assert set(_head_entries(pa).values()) == {second}
    assert old_id not in facts.own
    clock.advance(5 * 60_000)  # past half the head lease: the live head renews, the cancelled one stays gone
    a.tick()
    assert not present(pa.states[old_id])
    (live_id,) = _head_entries(pa, second)
    assert pa.states[live_id]["leaseValue"]["expiresAtMillis"] == clock.millis + 600_000


def test_a_head_its_writer_renewed_stays_live_past_its_first_lease_on_every_member():
    """PDT 2 phase 7 gate (P2-X-05, PD-R-08): a reader judges a head by its entry's lease register, which a renewal
    moves (SPEC §7.3), as Java's ``EntryState`` and the Ruby reader do. A reader that judged the lease its record was
    written with dropped the renewed head at that first lease on every member, the writer included."""
    clock, (pa, a), (pb, b) = _pair()
    root = a.map_ref("facts").swap(lambda m: m.assoc("k", 1)).root()
    assert b.map_ref("facts").deref().to_dict() == {"k": 1}
    (entry_id,) = _head_entries(pb, root)
    clock.advance(5 * 60_000)
    a.tick()  # half the head lease: the writer renews its live head
    assert pb.states[entry_id]["leaseValue"]["expiresAtMillis"] == clock.millis + 600_000
    clock.advance(5 * 60_000 + 1)  # past the lease the record was written with
    for pdt in (a, b):
        assert [h.entry_id for h in pdt.map_ref("facts")._live_entries()] == [entry_id]
        assert pdt.map_ref("facts").deref().to_dict() == {"k": 1}


def test_a_head_two_forked_heads_merge_against_stays_until_a_merge_supersedes_it():
    clock = Clock(T)
    network = HoldingNetwork()
    (pa, a), (pb, b) = [_node(network, clock, HeldPeer) for _ in range(2)]
    for peer in (pa, pb):
        peer.introduce()
    for pdt in (a, b):
        pdt.trees.advertise()
    base = a.map_ref("facts").swap(lambda m: m.assoc("base", 0)).root()
    assert b.map_ref("facts").deref().to_dict() == {"base": 0}
    network.holding = True  # a partition: each writer forks from base
    first = a.map_ref("facts").swap(lambda m: m.assoc("a", 1)).root()
    b.map_ref("facts").swap(lambda m: m.assoc("b", 1))
    release(network)
    for _ in range(3):
        clock.advance(CANCEL_GRACE_MS)
        a.tick()
    assert _head_entries(pa, base), "the lowest common base of two live heads stays"
    assert a.map_ref("facts").deref().to_dict() == {"base": 0, "a": 1, "b": 1}
    a.map_ref("facts").swap(lambda m: m.assoc("merged", True))
    for _ in range(2):
        clock.advance(CANCEL_GRACE_MS)
        a.tick()
    assert not _head_entries(pa, base) and not _head_entries(pa, first), "the merge superseded both"
