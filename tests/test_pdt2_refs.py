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
"""PDT 2 phase 7, P2-C-01 (groups D, R, T, V) and P2-F-06 (srad/agentspaces-pdt2.md §6.10.3 rules 1 to 9): the Python
ref engine at level 2. It reads ``PRef.v`` 1 and 2 heads and heads of kind ``db``; a ``db`` ref derefs to a lazy
``DbReader``; a head over a relaxed vector reads; a writer puts a value that holds a text under a ``v`` 2 head and
every other value under ``v`` 1; two writers' texts in one key merge by union with no conflict; every head names its
``vg`` node by ``pdt.ancestry``, and a base walk reads the chain past versions whose entries are gone."""

import json
import pathlib

import pytest

from agentspaces import cbor
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import DbReader, NodeStore, Pdt, PMap, PVector, cids, nodes, refs
from agentspaces.pdt.ancestry import ANCESTRY_ATTR, ancestry_cid, read_ancestry
from agentspaces.pdt.kinds import VgNode
from agentspaces.pdt.refs import CANCEL_GRACE_MS, PREF_TYPE, decode_pref, pref_record, pref_violation
from agentspaces.pdt.text import PText
from agentspaces.peer import present
from agentspaces.space import Space
from fleet import Clock
from test_hlc_logical_limit import T
from test_pdt_swarm import HeldPeer, HoldingNetwork, release

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPythonRefs2"


def _fleet(n=2, clock=None):
    clock = clock or Clock(T)
    network = HoldingNetwork()
    out = []
    for _ in range(n):
        peer = HeldPeer(network, GROUP, clock=clock)
        content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
        out.append((peer, content, Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1)))
    for peer, _c, _p in out:
        peer.introduce()
    for _peer, _c, pdt in out:
        pdt.trees.advertise()
    return clock, network, out


def _heads(peer, name) -> list[dict]:
    return [decode_pref(peer.payload_of(d)) for d in peer.states.values()
            if (d.get("record") or {}).get("type") == PREF_TYPE and present(d)
            and (d["record"].get("tags") or {}).get("name") == name]


def _write_head(pdt, name, kind, root, nodes_held, version):
    """A head another port writes: its nodes held and served, the record at the version its tree needs."""
    pdt.store.put_all({cids.of(n): n for n in nodes_held})
    pdt.trees.hold(root)
    record = pref_record(name, kind, root, seq=1, size=len(nodes_held))
    record["v"] = version
    assert pref_violation(record) is None
    pdt.write_head(record)


# ------------------------------------------------------------------ the record (P2-F-06, rule 8)

def test_a_level2_reader_takes_version_1_and_2_heads_and_a_db_head_only_at_version_2():
    head = pref_record("facts", refs.KIND_MAP, cids.of(b"r"))
    assert pref_violation(head) is None
    assert pref_violation(dict(head, v=2)) is None
    assert pref_violation(dict(head, v=3)) == "unsupported PRef version 3"
    db = dict(pref_record("graph", refs.KIND_DB, cids.of(b"r")), v=2)
    assert pref_violation(db) is None
    assert pref_violation(dict(db, v=1)) == "a db head is version 2, found 1"
    v2 = decode_pref(bytes.fromhex(GOLDEN["pdt_ref_v2_cbor"]))
    assert pref_violation(v2) is None and v2["kind"] == refs.KIND_DB


# ------------------------------------------------------------------ group D (P2-D-09 over a ref)

def test_a_db_ref_derefs_to_a_lazy_reader_of_the_head_another_port_wrote():
    _clock, _network, [(_pa, _ca, a), (_pb, _cb, b)] = _fleet()
    root, *parts = GOLDEN["pdt_db_sample"].split(",")
    _write_head(a, "graph", refs.KIND_DB, root, [bytes.fromhex(p) for p in parts], 2)
    graph = b.db_ref("graph")
    db = graph.deref()
    assert isinstance(db, DbReader) and db.max_eid == 126
    local = DbReader(root, refs.StoreLoader(a.store))
    assert db.entity(42) == local.entity(42) and list(db.datoms("eavt", 7)) == list(local.datoms("eavt", 7))
    with pytest.raises(ValueError, match="writes none; write db refs with DataScript through agentspaces-datascript"):
        graph.swap(lambda d: d)


# ------------------------------------------------------------------ group R (a head over an rr root, rule 2)

def test_a_vector_head_over_a_relaxed_tree_reads_and_a_python_swap_writes_the_packed_form_at_version_1():
    _clock, _network, [(pa, _ca, a), (pb, _cb, b)] = _fleet()
    root, packed, *node_hex = GOLDEN["pdt_rr_splice"].split(",")
    _write_head(a, "seq", refs.KIND_VECTOR, root, [bytes.fromhex(h) for h in node_hex], 2)
    v = b.vector_ref("seq").deref()
    assert v.relaxed() and v.count() == 1101 and v.nth(500) == -1
    grown = b.vector_ref("seq").swap(lambda x: x.conj(1100))
    assert not grown.relaxed() and grown.count() == 1102
    latest = max(_heads(pb, "seq"), key=lambda h: h["seq"])
    assert latest["v"] == 1 and latest["base"] == [root]
    assert list(a.vector_ref("seq").deref())[498:503] == [498, 499, -1, 500, 501]


# ------------------------------------------------------------------ group T (rule 3, P2-T-03)

def test_a_map_that_holds_a_text_writes_a_version_2_head_and_every_other_value_version_1():
    _clock, _network, [(pa, _ca, a), (pb, _cb, b)] = _fleet()
    a.map_ref("plain").swap(lambda m: m.assoc("k", "v"))
    a.map_ref("doc").swap(lambda m: m.assoc("title", PText.empty(a.replica).insert(0, "short")))
    a.map_ref("long").swap(lambda m: m.assoc("body", PText.empty(a.replica).insert(0, "x" * 2000)))
    assert [h["v"] for h in _heads(pb, "plain")] == [1]
    assert [h["v"] for h in _heads(pb, "doc")] == [2], "an inline text value"
    assert [h["v"] for h in _heads(pb, "long")] == [2], "a spilled t node"
    assert str(b.map_ref("long").deref().get("body")) == "x" * 2000


def test_two_writers_texts_in_one_key_merge_by_union_and_raise_no_conflict():
    _clock, network, [(pa, _ca, a), (pb, _cb, b)] = _fleet()
    a.map_ref("doc").swap(lambda m: m.assoc("body", PText.empty(a.replica).insert(0, "hello world")))
    assert str(b.map_ref("doc").deref().get("body")) == "hello world"
    network.holding = True
    a.map_ref("doc").swap(lambda m: m.assoc("body", m.get("body").with_replica(a.replica).insert(0, "A: ")))
    b.map_ref("doc").swap(lambda m: m.assoc("body", m.get("body").with_replica(b.replica).insert(11, "!")))
    release(network)
    conflicts = []
    b.map_ref("doc").on_conflict(conflicts.append)
    assert str(b.map_ref("doc").deref().get("body")) == "A: hello world!"
    assert str(a.map_ref("doc").deref().get("body")) == "A: hello world!"
    assert conflicts == []


# ------------------------------------------------------------------ group V (P2-V-01, P2-V-02)

def test_every_head_names_its_vg_node_which_links_the_vg_node_of_its_base():
    _clock, _network, [(pa, _ca, a), (pb, _cb, b)] = _fleet()
    facts = a.map_ref("facts")
    first = facts.swap(lambda m: m.assoc("k", 1)).root()
    second = facts.swap(lambda m: m.assoc("k", 2)).root()
    head = max(_heads(pb, "facts"), key=lambda h: h["seq"])
    vg_cid = ancestry_cid(head)
    assert vg_cid is not None and not b.store.has(vg_cid), "the vg node rides on no head"
    node = read_ancestry(head, b.trees.load(vg_cid, prefer=[pa.identity.peer_id], timeout=2.0))
    assert node.root == second and node.bases == (first,) and node.issuer == a.space_agent_id()
    first_head = min(_heads(pb, "facts"), key=lambda h: h["seq"])
    assert [link.cid for link in node.previous] == [ancestry_cid(first_head)]
    assert nodes.kind_of(a.store.get(vg_cid)) == nodes.KIND_VG


def test_a_base_walk_reads_the_chain_past_versions_whose_entries_are_gone():
    clock, _network, [(pa, _ca, a), (pb, _cb, b)] = _fleet()
    facts = a.map_ref("facts")
    roots = [facts.swap(lambda m, i=i: m.assoc("k", i)).root() for i in range(3)]
    for _ in range(3):
        clock.advance(CANCEL_GRACE_MS)
        a.tick()
    assert [h["root"] for h in _heads(pb, "facts")] == [roots[2]], "the writer cancelled its superseded heads"
    reader = b.map_ref("facts")
    assert reader.deref().get("k") == 2
    walk, ends_at_first = reader._walk(roots[2], [pa.identity.peer_id])
    assert walk == roots[::-1] and ends_at_first, "the chain gives the bases the memory never saw"
    assert b.stats()["chainNodesRead"] >= 2


def test_a_vg_node_nobody_holds_is_asked_for_again_only_after_a_backoff():
    """Swarm retries (ROBUSTNESS.md §10.2): a merge that cannot fetch a version's vg node walks on without it, and the
    next walks within the backoff ask nobody for it, so a head naming a node nobody holds costs one ask per backoff."""
    _clock, _network, [(pa, _ca, a), (_pb, _cb, b)] = _fleet()
    b.load_timeout = 0.2
    root = a.map_ref("facts").swap(lambda m: m.assoc("k", 1)).root()
    ghost = cids.of(b"a vg node nobody holds")
    reader = b.map_ref("facts")
    reader.deref()
    reader.ancestry["a base nobody saw"] = ghost
    reader.known[root] = reader.known[root].__class__(**{**reader.known[root].__dict__, "base": ("a base nobody saw",)})
    asked = []
    original = b.trees.load
    b.trees.load = lambda cid, **kw: asked.append(cid) or original(cid, **kw)
    for _ in range(3):
        walk, ends = reader._walk(root, [pa.identity.peer_id])
        assert walk == [root, "a base nobody saw"] and not ends
    assert asked == [ghost], "one ask, then the backoff"
    assert b.stats()["chainNodesMissed"] == 1
    reader.chain_misses[ghost][1] = 0.0  # the backoff ends
    reader._walk(root, [pa.identity.peer_id])
    assert asked == [ghost, ghost] and reader.chain_misses[ghost][0] == 2


def test_a_walk_asks_the_heads_writers_first_and_then_the_writer_of_every_version_it_knows():
    """Chain walk sources (srad/agentspaces-pdt2.md §10.20): a tree session takes at most ``max_sessions`` sources, the
    preferred ones first, so the walk lists the heads' writers first and then the writer of every version this reader
    knows, as Java's Refs.chainSources does. It listed the writers of the versions it knew in the order it met them,
    and the session took the last of them first, so the writers met before and after the heads filled the session,
    the walk never asked the one head writer that held a head's vg node, and the merge had no base."""
    _clock, _network, [(_pa, _ca, a), (_pb, _cb, b), (_pe, _ce, e), (_pf, _cf, f), (_pr, _cr, r)] = _fleet(5)
    reader = r.map_ref("facts")
    r.load_timeout = 0.5
    r.trees.max_sessions = 2
    base = PMap.empty(r.store).assoc("k", "base")
    p, q = base.assoc("p", "b"), base.assoc("q", "b")
    roots = {"base": base.root(), "p": p.root(), "q": q.root(), "x": p.assoc("x", "a").root(), "y": q.assoc("y", "b").root()}

    def vg(holders, root, bases, links, step):
        data = VgNode(root, bases, holders[0].space_agent_id(), f"{T + step}:0:golden", [nodes.Link(c) for c in links])
        for holder in holders:
            holder.store.put(data.encode())
        return cids.of(data.encode())
    vg_base = vg([b, a], roots["base"], (), [], 0)
    vg_p = vg([b, a], roots["p"], (roots["base"],), [vg_base], 1)
    vg_q = vg([b], roots["q"], (roots["base"],), [vg_base], 1)
    def version(writer, name, step):
        root = PMap.empty(r.store).assoc(name, step).root()
        reader.known[root] = refs.Head(root, (), 1, 1, refs.KIND_MAP, refs.MODE_MULTI, writer.space_agent_id(),
                                       (T + step, 0, "n"), f"e-{name}", T + 600_000)
    # the reader meets a version of e, which holds none of the chain, then the heads x, by a over p, and y, by b over
    # q, and never the entries of p, q or the base; a alone holds x's vg node, and b alone y's
    version(e, "e", 1)
    heads = []
    for step, (writer, name, under, link) in enumerate([(a, "x", "p", vg_p), (b, "y", "q", vg_q)], start=2):
        head = refs.Head(roots[name], (roots[under],), step, 2, refs.KIND_MAP, refs.MODE_MULTI, writer.space_agent_id(),
                         (T + step, 0, "n"), f"e-{name}", T + 600_000)
        reader.known[head.root] = head
        reader.ancestry[head.root] = vg([writer], head.root, (roots[under],), [link], step)
        heads.append(head)
    version(f, "f", 4)  # then a version of f, which holds none of the chain either
    assert reader._common_base(heads) == roots["base"]
    assert r.stats()["chainNodesMissed"] == 0
