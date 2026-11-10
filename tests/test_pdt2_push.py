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
"""PDT 2 phase 7, P2-C-01 push reception (P2-P-01, P2-P-02, P2-Q-SEC-03; srad/agentspaces-pdt2.md §3.4, §10.13,
§10.16): the Python follower reads each ``PushBundle`` strictly, holds its nodes aside until a live head announces
the push (``pdt.push``), stores only what the announced root reaches, sends no request when the bundles complete the
root, and fetches what is missing once the grace, sized for lateness (ROBUSTNESS.md §10), has passed. The bounds
mirror Java's ``PushReceiver`` and the phase 5 adversary's findings."""

import json
import pathlib

from agentspaces import cbor, wire
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import NodeStore, PMap, Pdt, cids, push
from agentspaces.pdt.refs import pref_record
from agentspaces.space import Space
from fleet import Clock, Network, NetPeer
from test_hlc_logical_limit import T

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPythonPush"


def _bundle(root, nodes, seq=1, part=0, parts=1) -> bytes:
    return cbor.dumps({"v": 1, "root": root, "seq": seq, "part": part, "parts": parts, "nodes": list(nodes)})


def _tree(entries: int, width: int = 200):
    """A map large enough to travel by request, and its nodes parents first."""
    store = NodeStore()
    value = PMap.empty(store).assoc_many({f"k{i}": "v" * width for i in range(entries)})
    root = value.root()
    order, seen, queue = [], set(), [root]
    while queue:
        cid = queue.pop(0)
        if cid in seen:
            continue
        seen.add(cid)
        order.append(store.get(cid))
        queue.extend(store.links(cid))
    return root, order


# ------------------------------------------------------------------ the record (P2-P-01, rule 16)

def test_the_bundle_vector_reads_strictly_and_a_bundle_outside_its_grammar_or_bounds_is_refused():
    raw = bytes.fromhex(GOLDEN["pdt_push_bundle_cbor"])
    bundle = push.decode_bundle(raw)
    assert bundle == {"v": 1, "root": cids.of(bytes.fromhex(GOLDEN["pdt_map_small"])), "seq": 3, "part": 0, "parts": 1,
                      "nodes": [bytes.fromhex(GOLDEN["pdt_map_small"])]}
    assert cbor.dumps(bundle) == raw and push.bundle_violation(bundle) is None
    extra = dict(bundle, more=1)
    assert push.decode_bundle(cbor.dumps(extra)) is None, "a field the schema does not name"
    assert push.decode_bundle(cbor.dumps({k: bundle[k] for k in ("root", "v", "seq", "part", "parts", "nodes")})) is None
    assert push.decode_bundle(cbor.dumps(dict(bundle, seq="3"))) is None
    for change, why in (({"v": 2}, "version 2"), ({"root": "x"}, "not a CID"), ({"seq": -1}, "seq -1"),
                        ({"part": 1}, "part 1 of 1"), ({"parts": 65}, "65"), ({"nodes": []}, "at least one node"),
                        ({"nodes": [b""]}, "empty node"), ({"nodes": [bytes(push.MAX_BYTES + 1)]}, "at most 1048576")):
        assert why in push.bundle_violation(dict(bundle, **change))


def test_the_announced_parts_are_canonical_decimal_from_1_to_64():
    assert push.announced({"pdt.push": "3"}) == 3 and push.announced({"pdt.push": "64"}) == 64
    for text in ("0", "03", "65", "1.0", "", " 1", None):
        assert push.announced({"pdt.push": text}) == 0
    assert push.announced({}) == 0 and push.announced(None) == 0


# ------------------------------------------------------------------ the receiver (P2-P-02, P2-Q-SEC-03)

def _receiver(clock=None):
    store = NodeStore()
    clock = clock or Clock(T)
    receiver = push.PushReceiver(store, clock=lambda: clock.millis)
    receiver.follow("pdt:pdt:facts")
    return store, receiver, clock


def test_bundles_wait_for_a_head_then_store_what_its_root_reaches_and_drop_the_rest():
    store, receiver, _clock = _receiver()
    root, nodes = _tree(300)
    stray = cbor.dumps({"k": "m", "stray": True})
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, nodes[:len(nodes) // 2] + [stray], parts=2))
    assert store.count() == 0, "nothing is stored before a live head announces the push"
    receiver.expect("pdt:pdt:facts", root, 2)
    assert receiver.check("pdt:pdt:facts", root) == push.WAIT
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, nodes[len(nodes) // 2:], part=1, parts=2))
    assert store.complete(root)
    assert receiver.check("pdt:pdt:facts", root) == push.NONE
    assert not store.has(cids.of(stray)), "a node the root does not reach was never part of the delta"
    assert receiver.stats()["nodesDropped"] >= 1 and receiver.stats()["bundlesReceived"] == 2


def test_a_bundle_outside_the_bounds_or_the_budget_is_dropped_and_counted():
    store, receiver, clock = _receiver()
    root, nodes = _tree(50)
    receiver.on_bundle("pdt:pdt:facts", b"\xa0")
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, [b"x"] * (receiver.max_nodes + 1)))
    assert receiver.stats()["bundlesDropped"] == 2
    receiver.on_bundle("pdt:pdt:other", _bundle(root, nodes))
    assert receiver.stats()["bundlesReceived"] == 0, "a stream this follower does not follow is not taken"
    big = [bytes([i % 251]) * 1000 for i in range(1000)]  # about 1 MB a bundle against an 8 MiB bucket
    taken = 0
    for i in range(12):
        receiver.on_bundle("pdt:pdt:facts", _bundle(cids.of(f"r{i}".encode()), big))
        taken = receiver.stats()["bundlesReceived"]
    assert taken < 12, "the stream's token bucket bounds what one stream takes at once"


def test_a_root_no_head_announced_never_displaces_an_announced_one():
    store, receiver, _clock = _receiver()
    root, nodes = _tree(300)
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, nodes[:3], parts=2))
    receiver.expect("pdt:pdt:facts", root, 2)
    for i in range(push.PENDING_ROOTS + 2):
        receiver.on_bundle("pdt:pdt:facts", _bundle(cids.of(f"made-up {i}".encode()), [b"\x01"]))
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, nodes[3:], part=1, parts=2))
    assert store.complete(root), "the announced root kept its held nodes"


def test_an_announced_root_waits_its_grace_then_goes_late_and_its_late_bundles_still_store():
    store, receiver, clock = _receiver()
    root, nodes = _tree(300)
    receiver.expect("pdt:pdt:facts", root, 1)
    grace = receiver.grace(1)
    assert push.GRACE_MS <= grace <= push.MAX_GRACE_MS
    clock.advance(grace - 1)
    assert receiver.check("pdt:pdt:facts", root) == push.WAIT
    clock.advance(1)
    assert receiver.check("pdt:pdt:facts", root) == push.LATE
    assert receiver.stats()["fallbacks"] == 1
    receiver.on_bundle("pdt:pdt:facts", _bundle(root, nodes))
    assert store.complete(root), "a bundle that is merely late still stores its nodes"
    clock.advance(push.ORPHAN_GRACES * grace + 1)
    receiver.expire()
    assert receiver.check("pdt:pdt:facts", root) == push.NONE


# ------------------------------------------------------------------ over the fleet (P2-P-02)

def _fleet():
    clock = Clock(T)
    network = Network()
    out = []
    for _ in range(2):
        peer = NetPeer(network, GROUP, clock=clock)
        content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
        out.append((peer, content, Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1, push=True)))
    for peer, _c, _p in out:
        peer.introduce()
    for _peer, _c, pdt in out:
        pdt.trees.advertise()
    return clock, out


def _push_head(writer_peer, writer, name, root, nodes, parts_sent):
    """What a Java writer with push on does: the head first, announcing the bundles, then the bundles on the stream."""
    writer.store.put_all({cids.of(n): n for n in nodes})
    writer.trees.hold(root)
    record = pref_record(name, "map", root, [], seq=1, size=300, attrs={"pdt.push": "2"})
    writer.write_head(record)
    half = len(nodes) // 2
    for part, chunk in enumerate((nodes[:half], nodes[half:])):
        if part in parts_sent:
            writer_peer._send("RUMOR", wire.rumor_body(f"pdt:pdt:{name}", f"{root}:{part}", 6,
                                                       _bundle(root, chunk, part=part, parts=2)))


def test_a_follower_takes_a_pushed_delta_with_no_request():
    _clock, [(pa, _ca, a), (_pb, cb, b)] = _fleet()
    facts = b.map_ref("facts")
    root, nodes = _tree(300)
    _push_head(pa, a, "facts", root, nodes, {0, 1})
    value = facts.deref()
    assert value.count() == 300 and value.root() == root
    assert cb.trees.stats()["nodesReceived"] == 0 and not cb.trees.fetches, "the push carried every node"
    assert b.push.stats()["nodesStored"] == len(nodes)


def test_a_follower_fetches_what_a_lost_bundle_left_missing_after_the_grace():
    clock, [(pa, _ca, a), (_pb, cb, b)] = _fleet()
    facts = b.map_ref("facts")
    root, nodes = _tree(300)
    _push_head(pa, a, "facts", root, nodes, {0})
    assert facts.heads(wait=False) == [], "the head waits for its push within the grace"
    clock.advance(b.push.grace(2))
    value = facts.deref()
    assert value.count() == 300
    assert 0 < cb.trees.stats()["nodesReceived"] < len(nodes), "the fetch asked for what the push left missing"
    assert b.push.stats()["fallbacks"] == 1
