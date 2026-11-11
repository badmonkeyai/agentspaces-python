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
"""PDT 2 phase 7, P2-C-01 and P2-F-05 (srad/agentspaces-pdt2.md §6.10.2 to 6.10.4, §10.12, §10.13): the Python tree
exchange at feature level 2. It reads every level-2 schema of 6.10.4 strictly, applies ``NODES.deltas`` in a
``TREE_WANT`` answer by the rules of Java's ``TreeFetchSession``, answers ``CHALLENGE`` (tag 12) and sketch rounds,
reconciles its held roots with a level-2 holder, advertises ``pdt`` = ``"2"``, and sends a level-2 form only to a
member whose advertisement carries a canonical decimal level of 2 or above."""

import hashlib
import json
import pathlib

import pytest

from agentspaces import cbor
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.capabilities import content as swarm
from agentspaces.identity import derive_id
from agentspaces.pdt import NodeStore, PMap, cids, sync, tree
from agentspaces.pdt.blob import BlobTree, Entry
from agentspaces.pdt.tree import Trees
from agentspaces.space import Space
from fleet import Network, NetPeer
from test_pdt_vectors import java_random_bytes

zstd = pytest.importorskip("compression.zstd")

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPythonLevel2"
HOLDER = derive_id(bytes(range(32)))
LEVEL_TWO = {"trees": "1", "pdt": "2"}


def _wire(ads=None):
    peer = NetPeer(Network(), GROUP)
    content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
    store = NodeStore()
    trees = Trees(content, store, advertisements={HOLDER: LEVEL_TWO} if ads is None else ads, advertise=False)
    sent = []
    content.send = lambda to, msg, via=None: sent.append((to, msg))
    return content, trees, store, sent


def _in(content, msg, sender=HOLDER):
    content._on_frame(sender, cbor.dumps(msg))


# ------------------------------------------------------------------ the schemas of 6.10.4

@pytest.mark.parametrize("name", ["content_nodes_deltas_cbor", "content_challenge_cbor",
                                  "content_tree_want_sketch_cbor", "content_tree_end_sketch_cbor"])
def test_every_level2_message_vector_reads_strictly_and_re_encodes(name):
    raw = bytes.fromhex(GOLDEN[name])
    msg = tree.read_message(raw)
    assert msg is not None and tree.violation(msg) is None, name
    assert cbor.dumps(msg) == raw


def test_a_level2_form_with_a_field_its_schema_does_not_name_or_out_of_order_is_undecodable():
    nodes_msg = tree.read_message(bytes.fromhex(GOLDEN["content_nodes_deltas_cbor"]))
    assert tree.read_message(cbor.dumps(dict(nodes_msg, more=1))) is None
    assert tree.read_message(cbor.dumps({**nodes_msg, "deltas": [dict(nodes_msg["deltas"][0], x=1)]})) is None
    reordered = {k: nodes_msg[k] for k in ("t", "req", "nodes", "sealed", "missing", "epoch", "deltas")}
    assert tree.read_message(cbor.dumps(reordered)) is None
    challenge = tree.read_message(bytes.fromhex(GOLDEN["content_challenge_cbor"]))
    assert tree.read_message(cbor.dumps({**challenge, "picks": [{"cid": challenge["root"], "size": 1}]})) is None
    assert tree.read_message(cbor.dumps({**challenge, "picks": [{"length": 1, "cid": challenge["root"]}]})) is None
    end = tree.read_message(bytes.fromhex(GOLDEN["content_tree_end_sketch_cbor"]))
    assert tree.read_message(cbor.dumps(dict(end, sketch="text"))) is None
    content, trees, _store, sent = _wire()
    content._on_frame(HOLDER, cbor.dumps(dict(nodes_msg, more=1)))
    assert trees.tree_messages_dropped == 1 and sent == [] and trees.nodes_struck == 0


def test_the_level2_bounds_name_what_they_refuse():
    end = tree.read_message(bytes.fromhex(GOLDEN["content_tree_end_sketch_cbor"]))
    assert tree.violation(dict(end, reason=1)) == "a TREE_END carries a sketch exactly when its reason is 5"
    assert tree.violation(dict(end, frontier=[end_cid := cids.of(b"x")])) == "a sketch TREE_END carries an empty frontier"
    assert tree.violation(tree.tree_end(1, [end_cid], 5)) == "a TREE_END carries a sketch exactly when its reason is 5"
    want = tree.read_message(bytes.fromhex(GOLDEN["content_tree_want_sketch_cbor"]))
    assert tree.violation(dict(want, haves=[end_cid])) == "a sketch TREE_WANT names no haves"
    assert tree.violation(dict(want, sketch=None)) == "root is not a cid"
    challenge = tree.read_message(bytes.fromhex(GOLDEN["content_challenge_cbor"]))
    assert "at most 16 picks" in tree.violation(dict(challenge, picks=challenge["picks"][:1] * 17))
    assert "at least one pick" in tree.violation(dict(challenge, picks=[]))
    assert "BLAKE3 identity" in tree.violation(dict(challenge, picks=[{"cid": end_cid, "offset": 0, "length": 1}]))
    assert tree.violation(dict(challenge, picks=[{"cid": end_cid, "length": 1}])) \
        == "a pick carries both or neither of offset and length"
    deltas = tree.read_message(bytes.fromhex(GOLDEN["content_nodes_deltas_cbor"]))
    assert "at most 256 deltas" in tree.violation(dict(deltas, deltas=deltas["deltas"] * 257))
    assert tree.violation(dict(deltas, deltas=[dict(deltas["deltas"][0], base="x")])) \
        == "deltas holds an entry without a CID, a base CID, and a frame"


# ------------------------------------------------------------------ the level (P2-F-05)

def test_this_port_advertises_level_2_and_reads_a_member_by_its_newest_advertisement():
    _content, trees, _store, _sent = _wire({"a": LEVEL_TWO, "b": {"trees": "1", "pdt": "3"}, "c": {"trees": "1"},
                                            "d": {"trees": "1", "pdt": "02"}, "e": {"trees": "1", "pdt": "2.0"},
                                            "f": {"trees": "1", "pdt": ""}})
    params = trees.describe()["parameters"]
    assert params[tree.TREES_PARAMETER] == "1" and params[tree.PDT_PARAMETER] == "2"
    assert [p for p in "abcdefg" if trees.reads_level_two(p)] == ["a", "b"]


# ------------------------------------------------------------------ NODES.deltas (P2-Z-01)

def _frame(base: bytes, target: bytes) -> bytes:
    frame = zstd.ZstdCompressor(options={zstd.CompressionParameter.checksum_flag: 0,
                                         zstd.CompressionParameter.dict_id_flag: 0},
                                zstd_dict=zstd.ZstdDict(base, is_raw=True)).compress(target, zstd.ZstdCompressor.FLUSH_FRAME)
    return b"d" + bytes.fromhex("5e2a4d1820000000") + hashlib.sha256(base).digest() + frame


class _Blobs:
    """Two versions of a two-chunk blob: the second edits one byte of the second chunk."""

    def __init__(self):
        self.a, self.b1 = java_random_bytes(1, 4096), java_random_bytes(2, 4096)
        edited = bytearray(self.b1)
        edited[100] ^= 0xFF
        self.b2 = bytes(edited)
        self.ca, self.cb1, self.cb2 = (cids.of(x, cids.RAW) for x in (self.a, self.b1, self.b2))
        self.v1 = BlobTree.encode_node(1, [Entry(self.ca, 4096), Entry(self.cb1, 4096)])
        self.v2 = BlobTree.encode_node(1, [Entry(self.ca, 4096), Entry(self.cb2, 4096)])
        self.r1, self.r2 = cids.of(self.v1), cids.of(self.v2)


def _fetch_to_the_delta(blobs: _Blobs):
    """A fetch of the second version by a peer that holds the first, run to the TREE_WANT for the edited chunk."""
    content, trees, store, sent = _wire()
    for data, codec in ((blobs.v1, cids.DAG_CBOR), (blobs.a, cids.RAW), (blobs.b1, cids.RAW)):
        store.put(data, codec)
    f = trees.fetch_tree(blobs.r2, haves=[blobs.r1], prefer=[HOLDER])
    (_to, want_root), = sent
    assert want_root["t"] == tree.NODE_WANT and want_root["cids"] == [blobs.r2]
    sent.clear()
    _in(content, tree.nodes_message(want_root["req"], [blobs.v2], None, None, None))
    (_to, want), = [m for m in sent if m[1]["t"] == tree.TREE_WANT]
    assert want["root"] == blobs.cb2 and want["haves"] == [blobs.r1]
    sent.clear()
    return content, trees, store, sent, f, want["req"]


def _deltas(req, entries) -> dict:
    return dict(tree.nodes_message(req, [], None, None, None), deltas=entries)


def test_a_delta_in_a_tree_answer_rebuilds_the_chunk_over_its_base_and_stores_the_chunk():
    blobs = _Blobs()
    content, trees, store, _sent, f, req = _fetch_to_the_delta(blobs)
    _in(content, _deltas(req, [{"cid": blobs.cb2, "base": blobs.cb1, "dcz": _frame(blobs.b1, blobs.b2)}]))
    _in(content, tree.tree_end(req, [], tree.END_DONE))
    assert f.complete and store.get(blobs.cb2) == blobs.b2
    assert trees.deltas_applied == 1 and f.bytes_received < 200


def test_a_frame_that_does_not_open_costs_no_strike_and_the_source_opens_no_later_frame():
    blobs = _Blobs()
    content, trees, store, sent, f, req = _fetch_to_the_delta(blobs)
    broken = _frame(blobs.b1, blobs.b2)[:-4] + b"\0\0\0\0"
    _in(content, _deltas(req, [{"cid": blobs.cb2, "base": blobs.cb1, "dcz": broken}]))
    _in(content, tree.tree_end(req, [], tree.END_DONE))
    assert trees.nodes_struck == 0 and trees.deltas_refused == 1
    asked = [m for _to, m in sent if m["t"] == tree.NODE_WANT]
    assert asked and blobs.cb2 in asked[0]["cids"], "the chunk is asked for whole"
    assert f.sources[HOLDER].frames_refused
    _in(content, tree.nodes_message(asked[0]["req"], [blobs.b2], None, None, None))
    assert f.complete and store.get(blobs.cb2) == blobs.b2


def test_a_frame_that_rebuilds_other_bytes_or_names_a_chunk_no_node_links_strikes_its_sender():
    blobs = _Blobs()
    content, trees, _store, _sent, _f, req = _fetch_to_the_delta(blobs)
    _in(content, _deltas(req, [{"cid": blobs.cb2, "base": blobs.cb1, "dcz": _frame(blobs.b1, blobs.b2[:-1] + b"?")}]))
    assert trees.nodes_struck == 1
    blobs = _Blobs()
    content, trees, _store, _sent, _f, req = _fetch_to_the_delta(blobs)
    stranger = cids.of(b"stranger", cids.RAW)
    _in(content, _deltas(req, [{"cid": stranger, "base": blobs.cb1, "dcz": _frame(blobs.b1, b"stranger")}]))
    assert trees.nodes_struck == 1


def test_a_delta_over_a_base_this_store_lacks_asks_for_the_chunk_by_node_want():
    blobs = _Blobs()
    content, trees, _store, sent, _f, req = _fetch_to_the_delta(blobs)
    missing_base = cids.of(b"a base held elsewhere", cids.RAW)
    _in(content, _deltas(req, [{"cid": blobs.cb2, "base": missing_base, "dcz": _frame(b"x" * 64, blobs.b2)}]))
    _in(content, tree.tree_end(req, [], tree.END_DONE))
    assert trees.nodes_struck == 0 and trees.deltas_applied == 0
    assert any(m["t"] == tree.NODE_WANT and blobs.cb2 in m["cids"] for _to, m in sent)


# ------------------------------------------------------------------ CHALLENGE (P2-S-07)

def test_a_challenge_is_answered_with_the_picks_held_and_the_rest_missing():
    content, trees, store, sent = _wire()
    node = cbor.dumps({"k": "m", "a": 1})
    held = store.put(node)
    root, gone = cids.of(b"root"), cids.of(b"gone")
    identity = "b" + cids.base32_lower(bytes([0x01, cids.RAW, 0x1E, 0x20]) + bytes(32))
    picks = [{"cid": held}, {"cid": gone}, {"cid": identity, "offset": 0, "length": 1024}]
    _in(content, {"t": tree.CHALLENGE, "req": 9, "root": root, "picks": picks})
    (_to, answer), = sent
    assert answer["t"] == tree.NODES and answer["req"] == 9 and answer["nodes"] == [node]
    assert answer["missing"] == [gone, identity]
    sent.clear()
    _in(content, {"t": tree.CHALLENGE, "req": 10, "root": root, "picks": [{"cid": gone}]})
    assert sent == [(HOLDER, swarm.reject(root, tree.TREE_INDEX, swarm.REASON_NOT_HELD))]


# ------------------------------------------------------------------ sketches (P2-K-02)

def _sketch_cids(lo, hi):
    return [cids.of(f"aspace:sketch:{i}".encode()) for i in range(lo, hi)]


def test_a_holder_answers_a_sketch_from_a_level2_member_and_refuses_one_it_reads_at_level_1():
    content, trees, _store, sent = _wire({HOLDER: LEVEL_TWO, "old": {"trees": "1"}})
    trees.reconcile_set = lambda: _sketch_cids(0, 30) + _sketch_cids(40, 50)
    want = tree.read_message(bytes.fromhex(GOLDEN["content_tree_want_sketch_cbor"]))
    _in(content, want)
    (_to, end), = sent
    assert cbor.dumps(end) == bytes.fromhex(GOLDEN["content_tree_end_sketch_cbor"])
    sent.clear()
    _in(content, want, sender="old")
    assert sent == [("old", swarm.reject("", tree.TREE_INDEX, swarm.REASON_POLICY))]
    sent.clear()
    _in(content, dict(want, sketch=b"\x99"))
    assert sent == [] and trees.tree_messages_dropped == 1
    for _ in range(sync.MAX_ROUNDS):
        _in(content, dict(want, req=77))
    sent.clear()
    _in(content, dict(want, req=77))
    assert sent == [(HOLDER, swarm.reject("", tree.TREE_INDEX, swarm.REASON_OVER_BUDGET))]


def _pair():
    network = Network()
    out = []
    for _ in range(2):
        peer = NetPeer(network, GROUP)
        content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
        out.append((peer, Trees(content, NodeStore())))
    for peer, _t in out:
        peer.introduce()
    for _peer, trees in out:
        trees.advertise()
    return out


def _hold(trees, keys):
    roots = []
    for key in keys:
        root = PMap.empty(trees.store).assoc(key, 1).root()
        trees.hold(root)
        roots.append(root)
    return roots


@pytest.mark.parametrize("expected", [0, 10])
def test_two_level2_members_reconcile_their_held_roots(expected):
    (pa, a), (pb, b) = _pair()
    shared = _hold(a, [f"s{i}" for i in range(40)])
    _hold(b, [f"s{i}" for i in range(40)])
    only_a = _hold(a, ["a1", "a2", "a3"])
    only_b = _hold(b, ["b1", "b2"])
    session = a.reconcile_held(pb.identity.peer_id, expected)
    assert session.done and session.failure is None, session.failure
    have, need = session.outcome
    assert sorted(have) == sorted(only_a) and sorted(need) == sorted(only_b)
    assert shared and session.encoding == ("riblt" if expected else "negentropy")


def test_a_member_sends_no_sketch_to_a_member_it_reads_at_level_1():
    _content, trees, _store, sent = _wire({"old": {"trees": "1"}})
    with pytest.raises(ValueError, match=r"level 1.*check reads_level_two\(holder\) before reconcile_held"):
        trees.reconcile_held("old")
    assert sent == []


def test_an_undecodable_nodes_releases_its_request_so_the_fetch_asks_again():
    blobs = _Blobs()
    content, trees, _store, sent, f, req = _fetch_to_the_delta(blobs)
    _in(content, dict(tree.nodes_message(req, [blobs.b2], None, None, None), extra=1))
    assert trees.tree_messages_dropped == 1 and req not in f.outstanding
    _in(content, {"t": tree.NODES, "req": [req], "nodes": []})
    assert trees.tree_messages_dropped == 2, "a req that is no integer is dropped and names no request"
