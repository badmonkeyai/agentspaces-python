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
"""Swarm retries (ROBUSTNESS.md §10.3, E1, E4, E5): lateness is normal in the swarm. A holder that
lacked a node is asked again after a bench, a late head is counted late and fetched again by the
tick with no read, and a lost seed is dialed with backoff until the owner closes the peer."""

import socket
import threading
import time

from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.identity import Identity
from agentspaces.pdt import NodeStore, PMap, Pdt
from agentspaces.pdt import refs as refs_module
from agentspaces.pdt import tree as tree_module
from agentspaces.pdt.refs import pref_record
from agentspaces.peer import Peer
from agentspaces.space import Space
from fleet import Network, NetPeer

GROUP = "zPythonSwarmRetries"


def _fleet(n, **options):
    network = Network()
    nodes = []
    for _ in range(n):
        peer = NetPeer(network, GROUP)
        content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
        nodes.append((peer, content, Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1, **options)))
    for peer, _c, _p in nodes:
        peer.introduce()
    for _peer, _c, pdt in nodes:
        pdt.trees.advertise()
    return nodes


def _ticks(nodes, rounds=1):
    for _ in range(rounds):
        for _peer, content, pdt in nodes:
            content.tick()
            pdt.tick()


def _until(nodes, done, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not done():
        _ticks(nodes)
        time.sleep(0.02)
    return done()


def test_a_holder_that_lacked_a_node_is_asked_again_after_its_bench(monkeypatch):
    """E4 (as B6): a missing answer benches the holder for that node alone; once the holder has it, the fetch
    completes instead of waiting out its timeout."""
    monkeypatch.setattr(tree_module, "MISSING_BENCH_S", 0.05, raising=False)
    nodes = _fleet(2)
    (_pa, _ca, a), (_pb, _cb, b) = nodes
    value = PMap.empty(a.store).assoc_many({f"k{i}": "v" * 200 for i in range(300)})
    root = value.root()
    a.trees.hold(root)
    lacked = next(c for c in sorted(a.store.reachable(root)) if c != root)
    data = a.store.get(lacked)
    a.store.remove(lacked)
    fetch = b.trees.fetch_tree(root, timeout=10.0)
    _ticks(nodes, 3)
    assert not fetch.done.is_set(), "the holder lacks a node: the fetch waits"
    a.store.put_verified(lacked, data)  # the holder's own fetch ran on and brought it
    assert _until(nodes, lambda: fetch.done.is_set(), 3.0), fetch.trace
    assert fetch.complete and b.store.complete(root)


def test_a_late_head_is_counted_late_and_fetched_again_by_the_tick(monkeypatch):
    """E1 (as P1 and P2): a head whose root does not load within the timeout is late, never ignored for good; the
    tick fetches it again after a backoff, from a member that holds it now, and the next read includes it."""
    monkeypatch.setattr(refs_module, "RETRY_BASE_S", 0.05, raising=False)
    nodes = _fleet(3, load_timeout=0.3)
    (_pa, _ca, a), (_pb, _cb, b), (_pc, _cc, c) = nodes
    a.map_ref("late").swap(lambda m: m.assoc("k1", "v1"))
    base = b.map_ref("late").deref()
    assert base.to_dict() == {"k1": "v1"}
    entries = {f"k{i}": "v" * 200 for i in range(300)}
    later = PMap.empty(NodeStore()).assoc_many(entries)
    a.write_head(pref_record("late", "map", later.root(), [base.root()], 2, len(entries)))
    assert b.map_ref("late").deref().root() == base.root(), "no member holds the new version yet"
    stats = b.stats()
    assert stats["headsIgnored"] == 0 and stats["headsLate"] >= 1
    c.map_ref("mirror").swap(lambda m: m.assoc_many(entries))
    assert c.map_ref("mirror").deref().root() == later.root()
    assert _until(nodes, lambda: b.store.complete(later.root()), 5.0), "the tick fetched the head again with no read"
    assert b.map_ref("late").deref().root() == later.root()


def test_reconnect_rounds_back_off_and_go_on_past_the_window():
    """E5: rounds of seed dials back off from the interval to six times it with a spread, and go on past the old
    window until the owner closes the peer."""
    peer = Peer(Identity.generate(), GROUP)
    peer.reconnect_interval_s = 0.02
    peer.reconnect_window_s = 0.1
    peer._seed = ("127.0.0.1", 9, "tcp")
    peer._running = True
    dials = []

    def refused(seed, timeout):
        dials.append(time.monotonic())
        if len(dials) >= 8:
            peer._running = False  # the owner closes the peer
        raise OSError("refused")

    peer._dial = refused
    assert peer._reconnect() is False
    assert len(dials) == 8, "the dials went on past the window"
    gaps = [b - a for a, b in zip(dials, dials[1:])]
    assert gaps[0] >= 0.02 and gaps[2] >= 0.08, gaps
    assert all(g <= 0.12 * 1.25 + 0.05 for g in gaps), gaps
    assert dials[-1] - dials[0] > peer.reconnect_window_s


def test_a_seed_that_drops_each_link_at_once_gets_the_backoff_and_no_dial_loop():
    """E5, the gate's adversarial review (ROBUSTNESS.md §10.5): a seed that accepts every dial and closes it at once,
    as a seed that refuses this peer or one still starting does, gets the paused rounds of a refused dial. A link
    that ends within the reconnect interval counts as a failed round, where the client used to dial again at once,
    thousands of times a second."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(64)
    dials = []

    def accept():
        while True:
            try:
                link, _ = server.accept()
            except OSError:
                return
            dials.append(time.monotonic())
            link.close()

    threading.Thread(target=accept, daemon=True).start()
    peer = Peer(Identity.generate(), GROUP)
    peer.reconnect_interval_s = 0.1
    try:
        peer.connect("127.0.0.1", server.getsockname()[1])
        time.sleep(1.5)
    finally:
        peer.close()
        server.close()
    assert 2 <= len(dials) <= 8, f"{len(dials)} dials in 1.5 s"
    gaps = [b - a for a, b in zip(dials, dials[1:])]
    assert all(g >= 0.09 for g in gaps), gaps
