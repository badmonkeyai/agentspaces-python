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
"""The tree exchange and refs over the in-process fleet (srad/agentspaces-pdt.md
PD-X-03 to PD-X-07, PD-R-02 to PD-R-07, PD-P-03, PD-C-04): a delta fetch with a
held base receives only the delta, a swap on one peer derefs on the other with
an inline delta, a 100-key concurrent swap converges on both peers, sealed
``NODES`` in group-key mode, and a linear ref over the take."""

import os
import random
import threading
import time

from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import NodeStore, PMap, Pdt, cids
from agentspaces.pdt.refs import LATER_HLC, PREF_TYPE
from agentspaces.space import Space
from agentspaces import cbor
from agentspaces.peer import Peer
from fleet import Network, NetPeer

GROUP = "zPythonPdt"


class HoldingNetwork(Network):
    """A network whose deliveries can be held back (a partition) and released."""

    def __init__(self):
        super().__init__()
        self.holding = False
        self.queue = []


class HeldPeer(NetPeer):
    def _send(self, kind, body, to=None):
        if self.network.holding:
            self.network.queue.append((self, kind, body, to))
            return
        super()._send(kind, body, to)


def release(network: HoldingNetwork):
    network.holding = False
    queued, network.queue = network.queue, []
    for peer, kind, body, to in queued:
        NetPeer._send(peer, kind, body, to)


def _node(network, **options):
    peer = HeldPeer(network, GROUP)
    content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
    pdt = Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1, **options)
    return peer, content, pdt


def _fleet(n, **options):
    network = HoldingNetwork()
    nodes = [_node(network, **options) for _ in range(n)]
    for peer, _c, _p in nodes:
        peer.introduce()
    for _peer, _c, pdt in nodes:          # the advertisements with the trees parameter reach everyone
        pdt.trees.advertise()
    return network, nodes


def _ticks(nodes, rounds=3):
    for _ in range(rounds):
        for _peer, content, _pdt in nodes:
            content.tick()
            _pdt.tick()


def _delta(store, new_root, old_root):
    return {c: store.get(c) for c in store.reachable(new_root) - store.reachable(old_root)}


# ------------------------------------------------------------------ PD-X-03, PD-X-06

def test_a_delta_fetch_with_a_held_base_receives_only_the_delta():
    _network, nodes = _fleet(2)
    (pa, ca, a), (pb, cb, b) = nodes
    assert b.trees.advertises_trees(pa.identity.peer_id) and a.trees.advertises_trees(pb.identity.peer_id)
    m0 = PMap.empty(a.store)
    for i in range(2000):
        m0 = m0.assoc(f"key-{i}", f"value {i} " + "x" * 100)
    root0 = m0.root()
    a.trees.hold(root0)
    tree_bytes = sum(len(a.store.get(c)) for c in a.store.reachable(root0))
    whole = b.trees.fetch_tree(root0)
    _ticks(nodes)
    assert whole.wait(5), whole.trace
    assert b.store.complete(root0)
    assert whole.bytes_received == tree_bytes
    assert PMap.load(b.store, root0).get("key-7") == m0.get("key-7")
    # one assoc on a: the delta is the changed path alone
    m1 = m0.assoc("key-7", "changed")
    root1 = m1.root()
    a.trees.hold(root1)
    delta = _delta(a.store, root1, root0)
    delta_bytes = sum(len(d) for d in delta.values())
    assert 0 < delta_bytes < 8 * 1024
    fetch = b.trees.fetch_tree(root1, haves=[root0])
    _ticks(nodes)
    assert fetch.wait(5), fetch.trace
    assert b.store.complete(root1)
    assert fetch.bytes_received == delta_bytes, (fetch.bytes_received, delta_bytes, fetch.trace)
    assert fetch.round_trips <= 2 and fetch.requests <= 4
    assert PMap.load(b.store, root1).get("key-7") == "changed"
    assert ca.trees.nodes_served == whole.progress()["nodesVerified"] + len(delta)
    print(f"\nPD-Q-PRF-01 shape: {tree_bytes} bytes in {len(a.store.reachable(root0))} nodes whole; one assoc = "
          f"{len(delta)} nodes, {delta_bytes} bytes; the delta fetch received {fetch.bytes_received} bytes in "
          f"{fetch.requests} requests and {fetch.round_trips} round trips")
    # a catch-up without a held base: the fetcher asks for what it lacks from its store's view
    _pc, cc, c = _node(_network)
    _pc.introduce()
    for _p, _c, x in nodes + [(_pc, cc, c)]:   # the sim network has no anti-entropy: the late joiner learns
        x.trees.advertise()                      # advertisements and holdings published after it arrived
    a.trees.hold(root1)
    _ticks(nodes + [(_pc, cc, c)])
    catch_up = c.trees.fetch_tree(root1, haves=[root0])
    _ticks(nodes + [(_pc, cc, c)])
    assert catch_up.wait(5), catch_up.trace
    assert c.store.complete(root1) and catch_up.bytes_received == sum(len(a.store.get(x)) for x in a.store.reachable(root1))
    assert cb.trees.tree_messages_dropped == 0 and ca.trees.tree_requests_rejected == 0


# ------------------------------------------------------------------ PD-R-02, PD-R-03, PD-X-07

def test_a_swap_on_one_peer_derefs_on_the_other_with_an_inline_delta():
    _network, nodes = _fleet(2)
    (pa, _ca, a), (pb, _cb, b) = nodes
    facts = a.map_ref("facts")
    seen = []
    b.map_ref("facts").watch(lambda value: seen.append(value.to_dict()))
    facts.swap(lambda m: m.assoc("alpha", 1).assoc("beta", [1, 2, 3]))
    heads = [d for d in pb.states.values() if (d.get("record") or {}).get("type") == PREF_TYPE]
    assert len(heads) == 1
    assert b.map_ref("facts").deref().to_dict() == {"alpha": 1, "beta": [1, 2, 3]}
    assert b.stats()["deltasInline"] == 1 and b.stats()["deltasFetched"] == 0
    assert _cb.trees.nodes_received == 0 and _ca.trees.nodes_served == 0   # the delta travelled on the head
    _ticks(nodes)
    assert seen == [{"alpha": 1, "beta": [1, 2, 3]}]
    facts.swap(lambda m: m.dissoc("alpha").assoc("gamma", "g"))
    _ticks(nodes)
    assert seen[-1] == {"beta": [1, 2, 3], "gamma": "g"}
    assert b.map_ref("facts").deref().root() == facts.deref().root()
    assert [h.seq for h in b.map_ref("facts").heads()] == [2]
    history = b.map_ref("facts").history(5)
    assert [h.seq for h in history] == [1]
    assert b.map_ref("facts").at(history[0].root).to_dict() == {"alpha": 1, "beta": [1, 2, 3]}
    # a large swap travels by request: the head carries no nodes and b fetches the delta
    facts.swap(lambda m: m.assoc_many({f"k{i}": "v" * 200 for i in range(300)}))
    head = next(d for d in pb.states.values() if (d.get("record") or {}).get("type") == PREF_TYPE
                and (d["record"].get("tags") or {}).get("root") == facts.deref().root())
    assert "nodes" not in cbor.loads(head["record"]["payload"])
    value = b.map_ref("facts").deref()
    assert value.count() == 302 and value.get("k7") == "v" * 200
    assert b.stats()["deltasFetched"] == 1 and _cb.trees.nodes_received > 0
    assert len([h for h in a.trees.holders(facts.deref().root())]) >= 1


# ------------------------------------------------------------------ PD-R-05, PD-R-06

def test_a_hundred_key_concurrent_swap_converges_on_both_peers():
    network, nodes = _fleet(2)
    (pa, _ca, a), (pb, _cb, b) = nodes
    ra, rb = a.map_ref("counts"), b.map_ref("counts")
    ra.swap(lambda m: m.assoc("shared", 0).assoc("base", True))
    assert rb.deref().to_dict() == {"shared": 0, "base": True}
    conflicts_a, conflicts_b = [], []
    ra.on_conflict(conflicts_a.append)
    rb.on_conflict(conflicts_b.append)
    rnd = random.Random(99)
    keys = [f"key-{i}" for i in range(100)]
    rnd.shuffle(keys)
    # a partition: both peers swap from the same base and neither sees the other's head
    network.holding = True
    ra.swap(lambda m: m.assoc_many({k: f"a:{k}" for k in keys[:50]}).assoc("shared", "a"))
    rb.swap(lambda m: m.assoc_many({k: f"b:{k}" for k in keys[50:]}).assoc("shared", "b"))
    assert ra.deref().count() == 52 and rb.deref().count() == 52
    release(network)
    heads_a, heads_b = ra.heads(), rb.heads()
    assert len(heads_a) == 2 and [h.root for h in heads_a] == [h.root for h in heads_b]
    merged_a, merged_b = ra.deref(), rb.deref()
    assert merged_a.count() == 102 and merged_b.count() == 102
    assert merged_a.root() == merged_b.root()
    expected = {k: f"a:{k}" for k in keys[:50]}
    expected.update({k: f"b:{k}" for k in keys[50:]})
    expected["base"] = True
    later = heads_a[-1]
    expected["shared"] = "a" if later.issuer.startswith(pa.identity.peer_id) else "b"
    assert merged_a.to_dict() == expected
    assert [c.reason for c in conflicts_a] == [LATER_HLC] and [c.key for c in conflicts_a] == ["shared"]
    assert conflicts_a == conflicts_b
    # the next swap persists the merge with both heads as bases and both peers agree
    ra.swap(lambda m: m.assoc("after", "merge"))
    persisted = rb.deref()
    assert persisted.count() == 103 and persisted.root() == ra.deref().root()
    assert [len(h.base) for h in rb.heads()] == [2] and rb.heads()[0].seq == 3
    assert b.stats()["conflicts"] == 1 and a.stats()["conflicts"] == 2   # a merged twice: its deref and its swap
    print(f"\nconcurrent swap: 2 heads at seq 2 merged to {merged_a.count()} keys on both peers with "
          f"{len(conflicts_b)} conflict ({conflicts_b[0].reason} on '{conflicts_a[0].key}'); the persisting swap "
          f"reached seq 3 with 2 bases")


# ------------------------------------------------------------------ PD-P-03

def test_group_key_mode_seals_the_nodes_and_a_keyless_holder_refuses():
    key = os.urandom(32)
    network = HoldingNetwork()
    pa, ca, a = _node(network, keys={0: key})
    pb, cb, b = _node(network, keys={0: key})
    pc, cc, c = _node(network)                     # keyless
    for p in (pa, pb, pc):
        p.introduce()
    for x in (a, b, c):
        x.trees.advertise()
    m = PMap.empty(a.store).assoc_many({f"k{i}": i for i in range(500)})
    root = m.root()
    a.trees.hold(root)
    fetch = b.trees.fetch_tree(root)
    _ticks([(pa, ca, a), (pb, cb, b), (pc, cc, c)])
    assert fetch.wait(5), fetch.trace
    assert b.store.complete(root) and fetch.bytes_received == sum(len(a.store.get(x)) for x in a.store.reachable(root))
    # the keyless member cannot open a sealed answer and the keyed holder refuses nothing it can serve
    refused = c.trees.fetch_tree(root, timeout=0.5)
    _ticks([(pa, ca, a), (pb, cb, b), (pc, cc, c)])
    deadline = time.monotonic() + 3
    while not refused.done.is_set() and time.monotonic() < deadline:
        _ticks([(pa, ca, a), (pb, cb, b), (pc, cc, c)])
        time.sleep(0.05)
    assert not c.store.complete(root)
    # a keyless holder in a sealing group refuses with reason 3 (PD-P-03)
    other = PMap.empty(c.store).assoc("plain", 1).root()
    c.trees.hold(other)
    asked = a.trees.fetch_tree(other, timeout=0.5)
    _ticks([(pa, ca, a), (pb, cb, b), (pc, cc, c)])
    assert cc.trees.tree_requests_rejected >= 1 and not a.store.has(other)
    asked.cancel()


# ------------------------------------------------------------------ PD-R-04

def test_a_linear_ref_advances_under_the_take_and_a_second_writer_waits():
    _network, nodes = _fleet(2, take_settle=0.05, take_timeout="3s", mode={"log": "linear"})
    (pa, _ca, a), (pb, _cb, b) = nodes
    la, lb = a.vector_ref("log"), b.vector_ref("log")
    assert la.mode == "linear" and lb.mode == "linear"
    la.swap(lambda v: v.conj("first"))
    assert lb.deref().to_list() == ["first"]
    results = []

    def writer(ref, label):
        for i in range(3):
            ref.swap(lambda v, label=label, i=i: v.conj(f"{label}{i}"))
            results.append(label)
    ta = threading.Thread(target=writer, args=(la, "a"))
    tb = threading.Thread(target=writer, args=(lb, "b"))
    ta.start()
    tb.start()
    deadline = time.monotonic() + 30
    while (ta.is_alive() or tb.is_alive()) and time.monotonic() < deadline:
        _ticks(nodes, 1)
        time.sleep(0.02)
    ta.join(1)
    tb.join(1)
    assert len(results) == 6
    final = la.deref().to_list()
    assert final[0] == "first" and sorted(final[1:]) == ["a0", "a1", "a2", "b0", "b1", "b2"]
    assert lb.deref().root() == la.deref().root()
    assert [h.seq for h in la.heads()] == [7] and a.stats()["conflicts"] == 0
    assert all((d.get("record") or {}).get("type") != PREF_TYPE or d.get("completed")
               for d in pa.states.values() if (d.get("record") or {}).get("tags", {}).get("root") != la.heads()[0].root)


# ------------------------------------------------------------------ the lazy follow (PD-X-10)

def test_a_lazy_follower_loads_nodes_on_access_only():
    _network, nodes = _fleet(2, follow="lazy")
    (pa, _ca, a), (pb, _cb, b) = nodes
    big = a.map_ref("big")
    big.swap(lambda m: m.assoc_many({f"k{i}": "v" * 300 for i in range(2000)}))
    root = big.deref().root()
    assert not b.store.has(root)
    value = b.map_ref("big").deref()
    assert b.store.has(root) and not b.store.complete(root)
    assert value.get("k77") == "v" * 300
    assert 0 < b.store.count() < 40
    assert _cb.trees.nodes_received == b.store.count()
    assert value.count() == 2000


def test_a_lazy_follower_loads_the_nodes_of_an_inline_head_from_its_issuer():
    # PDT 2 phase 8, P2-O-03: a head whose delta rode inline has no holding, and in linear mode the take removed the
    # head before it, so no followed root has a holder; a lazy read asks the heads' issuers for the unchanged nodes, as
    # the Java reader prefers the issuer (PD-S-06)
    _network, nodes = _fleet(2, follow="lazy", mode={"big": "linear"})
    (pa, _ca, a), (pb, _cb, b) = nodes
    big = a.map_ref("big")
    big.swap(lambda m: m.assoc_many({f"k{i}": "v" * 300 for i in range(2000)}))
    small = big.swap(lambda m: m.assoc("k1", "changed"))
    assert not _ca.holdings(small.root()), "the inline head writes no holding"
    value = b.map_ref("big").deref()
    assert value.root() == small.root()
    assert value.get("k77") == "v" * 300
    assert value.get("k1") == "changed"


# ------------------------------------------------------------------ the record-free renew (PD-L-02, PD-L-04)

def test_a_recordless_state_merges_when_the_record_is_held_and_waits_otherwise():
    _network, nodes = _fleet(2)
    (pa, _ca, a), (pb, _cb, b) = nodes
    assert pa.wire_hints == {"wire.recordless": "1", "wire.appcard": "2"}
    entry_id = a.map_ref("facts").swap(lambda m: m.assoc("k", 1)) and next(
        e for e, d in pa.states.items() if (d.get("record") or {}).get("type") == PREF_TYPE)
    pa.renew_entry("pdt", entry_id, 1_200_000)
    renewed = dict(pa.states[entry_id])
    recordless = {k: v for k, v in renewed.items() if k != "record"}
    recordless["record"] = None
    recordless["entryId"] = entry_id
    before = int(pb.states[entry_id]["leaseValue"]["expiresAtMillis"])
    # b holds the record: the state merges (the later lease stamp wins)
    pb._fold(dict(recordless))
    assert int(pb.states[entry_id]["leaseValue"]["expiresAtMillis"]) == int(renewed["leaseValue"]["expiresAtMillis"]) >= before
    # a peer without the record keeps it pending, with no entry and no event, until the record arrives
    pc = HeldPeer(_network, GROUP)
    events = []
    pc.on_state = events.append
    pc._fold(dict(recordless))
    assert entry_id not in pc.states and entry_id in pc.pending_states and events == []
    pc._fold(dict(pa.states[entry_id], leaseValue=pb.states[entry_id]["leaseValue"]))
    assert entry_id in pc.states and entry_id not in pc.pending_states and len(events) >= 1
    assert int(pc.states[entry_id]["leaseValue"]["expiresAtMillis"]) == int(renewed["leaseValue"]["expiresAtMillis"])
    # the rumor item id names the entry when the DTO does not
    unnamed = {k: v for k, v in recordless.items() if k != "entryId"}
    pa._name_recordless(unnamed, f"r:{entry_id}:123")
    assert unnamed["entryId"] == entry_id


# ------------------------------------------------------------------ the ref space's past heads (PDT 2 phase 2)

class PullingPeer(NetPeer):
    """A peer whose anti-entropy pull goes out as a connected Peer's does, recording each digest it sends."""
    pull_space = Peer.pull_space

    def __init__(self, network, group):
        super().__init__(network, group)
        self.digests = []

    def _send(self, kind, body, to=None):
        if kind == "DIGEST":
            self.digests.append(set(cbor.loads(body)["digests"]))
        super()._send(kind, body, to)


def test_a_facade_asks_for_its_ref_space_past_heads_when_it_starts():
    # PDT 2 phase 2 (§10.6 open item): the facade pulls its ref space when it starts, as the TypeScript and
    # Ruby facades do, so a late reader's seed answers with the heads written before it came, and no
    # program pulls the space by hand
    peer = PullingPeer(Network(), GROUP)
    Pdt(Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1), Space(peer, "refs"), NodeStore(), seed=1)
    assert any("space:refs" in digest for digest in peer.digests)
    assert "refs" in peer._pulled_spaces, "the peer pulls the space again after a reconnect"
