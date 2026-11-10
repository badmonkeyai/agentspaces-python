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
"""PDT 2 phase 0 in Python (srad/agentspaces-pdt2.md §3, §6.10, §8): the seven level-2 node
kinds in the node codec and their typed readers (P2-D-01, P2-R-01, P2-T-01, P2-V-01, P2-B-02),
the reserved kinds (P2-F-04), the ``StorePin`` and ``StoreReceipt`` records read strictly
(P2-S-02, P2-F-08), the ``pdt.ancestry`` attribute (§6.10.3 rule 9), and this port's feature
level on the content swarm (P2-F-05, P2-C-01). Each refusal mirrors the Java build's tests."""

import time
import uuid

import pytest

from agentspaces import cbor
from agentspaces.identity import Identity
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import NodeStore, Pdt, ancestry, cids, content_store, nodes, refs, tree
from agentspaces.pdt.items import CharId, Datom, Tagged, TextRun
from agentspaces.pdt.kinds import BoNode, DbRoot, DnNode, RrRoot, RvNode, TextLeaf, VgNode
from agentspaces.pdt.nodes import Embedded, Link, NodeFormatError
from agentspaces.space import Space
from fleet import Network, NetPeer


def link_to(name: str) -> Link:
    return Link(cids.of(name.encode()))


def leaf(datoms) -> dict:
    return {"k": "dn", "l": 0, "x": "eavt", "e": list(datoms)}


def refused(data_hex: str, message: str):
    with pytest.raises(NodeFormatError) as e:
        nodes.decode(bytes.fromhex(data_hex.replace(" ", "")))
    assert message in str(e.value), str(e.value)


# ------------------------------------------------------------------ kinds (P2-F-04)

def test_the_level2_kinds_have_schemas_and_s_tm_ec_stay_reserved():
    assert {"db", "dn", "rr", "rv", "t", "vg", "bo"} <= nodes.KINDS
    assert nodes.RESERVED_KINDS == {"s", "tm", "ec"}
    for kind in ("s", "tm", "ec"):
        with pytest.raises(NodeFormatError, match=f"kind '{kind}' is reserved"):
            nodes.decode(bytes([0xA1, 0x61, 0x6B, 0x60 + len(kind)]) + kind.encode())
        with pytest.raises(NodeFormatError, match="reserved"):
            nodes.encode({"k": kind})
    assert nodes.decode(bytes.fromhex("a1616b627272")) == {"k": "rr"}, "rr has a schema now"


def test_a_header_above_the_java_long_range_is_refused():
    # {"k": "x", "v": 0} with the key "v" holding... a dn level of 2^63 instead: {"k":"dn","l":2^63}
    refused("a2 616b 62646e 616c 1b8000000000000000", "above 2^63 - 1")
    with pytest.raises(NodeFormatError, match="2\\^63"):
        nodes.encode({"k": "dn", "l": 1 << 63})


# ------------------------------------------------------------------ datoms (P2-D-01)

def test_a_datom_leaf_encodes_as_the_canonical_bytes():
    encoded = nodes.encode(leaf([Datom(1, ":a", 2, 3)]))
    # {"e": [[1, ":a", 2, 3]], "k": "dn", "l": 0, "x": "eavt"}
    assert encoded.hex() == "a4" "6165" "81" "8401623a610203" "616b" "62646e" "616c" "00" "6178" "6465617674"
    assert nodes.decode(encoded)["e"] == [Datom(1, ":a", 2, 3)]


def test_every_datom_value_form_round_trips_and_a_spilled_value_is_a_link():
    spilled = Link(cids.of(bytes(5000), cids.RAW))
    datoms = [Datom(3, ":v/bigint", Tagged.bigint(2 ** 70), 536870913),
              Datom(3, ":v/bool", True, 536870913),
              Datom(3, ":v/bytes", b"\x00\x01\x02", 536870913),
              Datom(3, ":v/float", 1.5, 536870913),
              Datom(3, ":v/instant", Tagged.instant(1792320000000), 536870913),
              Datom(3, ":v/int", -7, 536870913),
              Datom(3, ":v/keyword", ":status/active", 536870913),
              Datom(3, ":v/spill", spilled, 536870913),
              Datom(3, ":v/text", "Ada ✓", 536870913),
              Datom(3, ":v/uuid", Tagged.uuid(uuid.UUID("0123456789abcdeffedcba9876543210")), -536870914)]
    encoded = nodes.encode(leaf(datoms))
    assert nodes.decode(encoded)["e"] == datoms
    assert nodes.encode(nodes.decode(encoded)) == encoded
    assert nodes.links(encoded) == [spilled.cid]
    assert "3a20000001" in encoded.hex() and "fb3ff8000000000000" in encoded.hex()


@pytest.mark.parametrize("value, message", [
    ("f97e00", "half"), ("fa3fc00000", "float32"), ("fb7ff8000000000000", "not finite"),
    ("fb7ff0000000000000", "not finite"), ("1802", "shortest"), ("f6", "null"), ("bf616101ff", "major type 5"),
    ("a1616101", "major type 5"), ("82617101", "unknown value tag 'q'"), ("82617543010203", "16 bytes"),
    ("826169 6178", "integer"), ("82616e420001", "minimal"), ("82616e40", "minimal"), ("8361690102", "two items"),
    ("c24101", "tag 2"), ("7f6161ff", "indefinite"), ("62c328", "UTF-8"), ("f7", "simple value"),
])
def test_the_datom_value_grammar_refuses_every_other_item(value, message):
    refused("a4 6165 81 84 01 62 3a61" + value + "03 616b 62646e 616c 00 6178 6465617674", message)


def test_a_datom_holds_four_items_and_a_text_attribute():
    refused("a4 6165 81 83 01 62 3a61 02 616b 62646e 616c 00 6178 6465617674", "four items")
    refused("a4 6165 81 84 01 01 02 03 616b 62646e 616c 00 6178 6465617674", "major type 3")


def test_a_datom_refuses_a_value_outside_the_grammar_on_the_way_in():
    with pytest.raises(ValueError, match="finite"):
        Datom(1, ":a", float("nan"), 1)
    with pytest.raises(ValueError, match="a datom value"):
        Datom(1, ":a", None, 1)
    with pytest.raises(ValueError, match="a datom value"):
        Datom(1, ":a", cbor.Float32(1.5), 1)
    with pytest.raises(ValueError, match="long"):
        Datom(1, ":a", 1 << 63, 1)
    with pytest.raises(ValueError, match="16 bytes"):
        Tagged("u", bytes(15))
    with pytest.raises(ValueError, match="minimal"):
        Tagged("n", b"\x00\x01")
    with pytest.raises(ValueError, match="unknown value tag"):
        Tagged("q", 1)
    assert Tagged.bigint(-129).inner == b"\xff\x7f"
    assert Tagged.bigint(-128).inner == b"\x80", "BigInteger.toByteArray: no redundant sign byte"
    assert Tagged.bigint(128).inner == b"\x00\x80"
    assert Tagged.bigint(-129).integer() == -129
    assert Datom(1, ":a", True, 1) != Datom(1, ":a", 1, 1), "a boolean is no integer"
    assert Datom(1, ":a", 1.0, 1) != Datom(1, ":a", 1, 1), "a float is no integer"
    assert Datom(1, ":a", -0.0, 1) != Datom(1, ":a", 0.0, 1), "two floats of different bytes"


def test_a_datom_carries_a_signed_entity_and_a_non_zero_transaction():
    negative = Datom(-5, ":a", 1, 3)
    encoded = nodes.encode(leaf([negative]))
    assert "8424623a610103" in encoded.hex()
    assert nodes.decode(encoded)["e"] == [negative]
    with pytest.raises(ValueError, match="tx"):
        Datom(1, ":a", 1, 0)
    zero_tx = bytearray(nodes.encode(leaf([Datom(1, ":a", 1, 3)])))
    zero_tx[zero_tx.hex().index("8401623a610103") // 2 + 6] = 0x00
    with pytest.raises(NodeFormatError, match="tx"):
        nodes.decode(bytes(zero_tx))
    with pytest.raises(NodeFormatError, match="datoms"):
        nodes.encode(leaf([[1, ":a", 1, 3]]))


# ------------------------------------------------------------------ text runs (P2-T-01)

def test_text_runs_round_trip_and_refuse_their_own_rules():
    first = TextRun("alice", 0, None, TextRun.RIGHT, 4, False, "Ab\U0001F600c")
    deleted = TextRun("alice", 4, CharId("alice", 1), TextRun.LEFT, 2, True, "")
    encoded = nodes.encode({"k": "t", "r": [first, deleted], "v": 1})
    assert nodes.decode(encoded)["r"] == [first, deleted]
    assert nodes.links(encoded) == []
    assert nodes.decode(bytes.fromhex("a3616b6174617281876561" "6c69636504826561" "6c69636501614c02f5606176" "01"))["r"] \
        == [deleted]
    for args, message in (((("alice", 0, None, "X", 1, False, "a")), "side"),
                          ((("alice", 0, None, "R", 1, True, "a")), "deleted run"),
                          ((("alice", 0, None, "R", 2, False, "\U0001F600")), "code points"),
                          ((("", 0, None, "R", 1, False, "a")), "replica"),
                          ((("alice", 0, None, "R", 0, False, "")), "length"),
                          ((("alice", 0, None, "L", 1, False, "a")), "document root"),
                          ((("alice", 0, None, "R", 1, False, "\ud800")), "lone surrogate"),
                          ((("alice", (1 << 63) - 1, None, "R", 2, False, "ab")), "pass 2\\^63")):
        with pytest.raises(ValueError, match=message):
            TextRun(*args)
    refused("a3 616b 6174 6172 81 87 65616c696365 04 83 65616c696365 01 01 614c 02 f5 60 6176 01", "parent")
    refused("a3 616b 6174 6172 81 87 65616c696365 04 f6 6158 02 f5 60 6176 01", "side")
    refused("a3 616b 6174 6172 81 86 65616c696365 04 f6 6152 02 f5 6176 01", "seven items")


# ------------------------------------------------------------------ db, cid text, bo fields

def test_the_db_index_map_holds_exactly_the_three_index_links_in_order():
    index = {"eavt": link_to("eavt"), "aevt": link_to("aevt"), "avet": link_to("avet")}
    node = {"k": "db", "v": 1, "s": Embedded(cbor.dumps({})), "me": 2, "mt": 536870914, "bf": 128, "i": index,
            "t": link_to("tail")}
    encoded = nodes.encode(node)
    decoded = nodes.decode(encoded)
    assert list(decoded["i"]) == ["aevt", "avet", "eavt"]
    assert nodes.links(encoded) == [link_to("aevt").cid, link_to("avet").cid, link_to("eavt").cid, link_to("tail").cid]
    assert nodes.encode(decoded) == encoded
    with pytest.raises(NodeFormatError, match="aevt, avet and eavt"):
        nodes.encode({**node, "i": {"eavt": link_to("e"), "aevt": link_to("a")}})
    with pytest.raises(NodeFormatError, match="aevt, avet and eavt"):
        nodes.encode({**node, "i": {**index, "vaet": link_to("v")}})
    link = "d82a5825" "00" + cids.binary(link_to("x").cid).hex()
    refused("a2 6169 a3 6461766574" + link + "6461657674" + link + "6465617674" + link + " 616b 626462",
            "aevt, avet and eavt")


def test_cid_text_fields_and_strict_text_refuse_what_they_cannot_hold():
    vg = {"k": "vg", "r": "not-a-cid"}
    with pytest.raises(NodeFormatError, match="'r' must hold a CID"):
        nodes.encode(vg)
    vg = {"k": "vg", "r": link_to("root").cid, "b": [link_to("base").cid], "i": "peer/writer",
          "t": "1792320000000:0:golden", "p": [link_to("vg")]}
    encoded = nodes.encode(vg)
    assert nodes.decode(encoded) == vg
    assert nodes.links(encoded) == [link_to("vg").cid], "a vg node links only earlier vg nodes (6.10, rule 4)"
    refused("a2 616b 62646e 6178 61ff", "UTF-8")
    with pytest.raises(NodeFormatError, match="UTF-8"):
        nodes.encode({"k": "dn", "x": "\udc00"})
    # a CID text in a non-canonical base32 form (a set padding bit) is no CID
    cid = link_to("root").cid
    loose = cid[:-1] + cids._B32[cids._B32_INDEX[cid[-1]] | 1]
    assert loose != cid
    with pytest.raises(NodeFormatError, match="must hold a CID"):
        nodes.encode({"k": "vg", "r": loose})


def test_a_bao_node_carries_its_chaining_values_as_one_byte_string():
    encoded = nodes.encode({"k": "bo", "g": 4, "n": 32768, "p": bytes(64), "c": []})
    assert encoded.hex().startswith("a5616380616704") and "61705840" in encoded.hex()
    assert nodes.links(encoded) == []


# ------------------------------------------------------------------ typed readers

def raw(node: dict) -> bytes:
    return nodes.encode(node)


def db(tail) -> DbRoot:
    return DbRoot(Embedded(cbor.dumps({":person/name": {":db/index": True}})), 2, 536870914, DbRoot.BRANCHING,
                  link_to("eavt"), link_to("aevt"), link_to("avet"), tail)


def test_a_db_root_round_trips_and_links_its_indexes_and_its_tail():
    root = db(link_to("tail"))
    assert DbRoot.decode(None, root.encode()) == root
    assert nodes.links(root.encode()) == [link_to("aevt").cid, link_to("avet").cid, link_to("eavt").cid,
                                          link_to("tail").cid]
    assert DbRoot.decode(None, db(None).encode()).tail is None


def test_a_db_root_refuses_another_version_a_missing_key_and_a_tiny_branching_factor():
    node = nodes.decode(db(None).encode())
    with pytest.raises(NodeFormatError, match="db root version 2"):
        DbRoot.decode(None, raw({**node, "v": 2}))
    with pytest.raises(NodeFormatError, match="lacks 't'"):
        DbRoot.decode(None, raw({k: v for k, v in node.items() if k != "t"}))
    with pytest.raises(NodeFormatError, match="branching factor"):
        DbRoot.decode(None, raw({**node, "bf": 1}))
    with pytest.raises(NodeFormatError, match="kind 'dn' where a 'db' node belongs"):
        DbRoot.decode(None, raw({"k": "dn", "l": 0, "x": "eavt", "e": []}))
    with pytest.raises(ValueError, match="non-negative"):
        DbRoot(Embedded(cbor.dumps({})), -1, 0, 128, link_to("e"), link_to("a"), link_to("v"), None)


def test_a_db_schema_is_a_map_with_text_keys_or_a_spilled_link():
    with pytest.raises(ValueError, match="schema"):
        DbRoot(Embedded(cbor.dumps("schema")), 0, 0, DbRoot.BRANCHING, link_to("e"), link_to("a"), link_to("v"), None)
    with pytest.raises(ValueError, match="schema"):
        DbRoot(Embedded(b"\xbf\x01\xf5\xff"), 0, 0, DbRoot.BRANCHING, link_to("e"), link_to("a"), link_to("v"), None)
    node = nodes.decode(db(None).encode())
    with pytest.raises(NodeFormatError, match="schema"):
        DbRoot.decode(None, raw({**node, "s": Embedded(cbor.dumps("schema"))}))
    spilled = DbRoot(Embedded(nodes.link_item(link_to("schema").cid)), 0, 0, DbRoot.BRANCHING, link_to("e"),
                     link_to("a"), link_to("v"), None)
    assert link_to("schema").cid in nodes.links(spilled.encode())
    assert DbRoot.decode(None, spilled.encode()) == spilled


def test_dn_leaves_branches_and_tails_keep_their_shapes():
    a = Datom(1, ":person/age", 36, 536870913)
    b = Datom(1, ":person/name", "Ada", 536870913)
    lf = DnNode.leaf(DnNode.EAVT, [a, b])
    assert DnNode.decode(None, lf.encode()) == lf
    assert "c" not in nodes.decode(lf.encode())
    branch = DnNode.branch(1, DnNode.EAVT, [b], [Link(cids.of(lf.encode()))])
    assert DnNode.decode(None, branch.encode()) == branch
    tail = DnNode.tail([Datom(1, ":person/age", 36, -536870914), Datom(1, ":person/age", 37, 536870914)])
    assert DnNode.decode(None, tail.encode()) == tail
    for node, message in (({"k": "dn", "l": 0, "x": "vaet", "e": [a]}, "index 'vaet'"),
                          ({"k": "dn", "l": 1, "x": "eavt", "e": [a, b], "c": [link_to("one")]}, "one link per key"),
                          ({"k": "dn", "l": 0, "x": "eavt", "e": [a], "c": [link_to("one")]}, "a leaf carries no 'c'"),
                          ({"k": "dn", "l": 0, "x": "eavt", "e": [a], "c": []}, "a leaf carries no 'c'"),
                          ({"k": "dn", "l": 1, "x": "eavt", "e": [a]}, "lacks 'c'"),
                          ({"k": "dn", "l": 1, "x": "tail", "e": [a], "c": [link_to("one")]}, "a tail is a leaf"),
                          ({"k": "dn", "l": 0, "x": "tail", "e": []}, "an empty tail"),
                          ({"k": "dn", "l": 0, "e": [a]}, "lacks 'x'")):
        with pytest.raises(NodeFormatError, match=message):
            DnNode.decode(None, raw(node))


def test_rr_roots_and_rv_nodes_round_trip_and_check_their_sizes():
    tail = [Embedded(cbor.dumps(i)) for i in range(96, 100)]
    root = RrRoot(100, 5, link_to("rv"), tail)
    assert RrRoot.decode(None, root.encode()) == root
    relaxed = RvNode([link_to("a"), link_to("b"), link_to("c"), link_to("d")], [32, 40, 72, 96])
    assert RvNode.decode(None, relaxed.encode()) == relaxed
    dense = RvNode([link_to("a"), link_to("b")], None)
    assert "z" not in nodes.decode(dense.encode())
    assert RvNode.decode(None, dense.encode()) == dense
    for make, message in ((lambda: RvNode([link_to("a"), link_to("b")], [40, 40]), "strictly increasing"),
                          (lambda: RvNode([link_to("a")], [0]), "strictly increasing"),
                          (lambda: RvNode([link_to("a")], [1, 2]), "one size per child"),
                          (lambda: RvNode([], None), "1 to 32 children"),
                          (lambda: RvNode([link_to(str(i)) for i in range(33)], None), "1 to 32 children"),
                          (lambda: RrRoot(3, 5, None, tail), "tail"),
                          (lambda: RrRoot(4, 5, link_to("rv"), tail), "trie"),
                          (lambda: RrRoot(133, 5, link_to("rv"), [Embedded(cbor.dumps(i)) for i in range(33)]),
                           "at most 32"),
                          (lambda: RrRoot(100, 7, link_to("rv"), tail), "shift"),
                          (lambda: RrRoot(100, 0, link_to("rv"), tail), "shift")):
        with pytest.raises(ValueError, match=message):
            make()
    with pytest.raises(NodeFormatError, match="lacks 'c'"):
        RvNode.decode(None, raw({"k": "rv", "z": [1]}))


def test_a_vg_node_round_trips_and_refuses_a_bad_issuer_or_stamp():
    writer = "zQ3shPeer/writer"
    first = VgNode(link_to("r1").cid, [], writer, "1792320000000:0:golden", [])
    second = VgNode(link_to("r2").cid, [link_to("r1").cid], writer, "1792320000001:0:golden",
                    [Link(cids.of(first.encode()))])
    assert VgNode.decode(None, second.encode()) == second
    assert nodes.links(second.encode()) == [cids.of(first.encode())]
    r = link_to("r").cid
    for make, message in ((lambda: VgNode(r, [], "no-slash", "1:0:n", []), "issuer"),
                          (lambda: VgNode(r, [], writer, "01:0:n", []), "issued"),
                          (lambda: VgNode("not-a-cid", [], writer, "1:0:n", []), "by CID"),
                          (lambda: VgNode(r, [link_to(f"b{i}").cid for i in range(9)], writer, "1:0:n", []), "8 bases"),
                          (lambda: VgNode(r, [], writer, "1:0:n", [link_to("p")]), "one earlier vg node per base"),
                          (lambda: VgNode(r, [link_to("b").cid], writer, "1:0:n", [Link(cids.of(b"\0", cids.RAW))]),
                           "dag-cbor")):
        with pytest.raises(ValueError, match=message):
            make()


def test_a_bo_node_holds_the_parents_its_size_implies():
    single = BoNode(5000, b"", [])
    assert BoNode.decode(None, single.encode()) == single
    seven = BoNode(100 * 1024, bytes(6 * BoNode.PARENT_BYTES), [])
    assert BoNode.decode(None, seven.encode()) == seven
    assert (BoNode.groups(0), BoNode.groups(16384), BoNode.groups(16385)) == (1, 1, 2)
    with pytest.raises(ValueError, match="7 groups take 6 parents"):
        BoNode(100 * 1024, bytes(5 * BoNode.PARENT_BYTES), [])
    split = BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES + 1
    with pytest.raises(ValueError, match="2 children"):
        BoNode(split, b"", [])
    upper = BoNode(split, bytes(BoNode.PARENT_BYTES), [link_to("l"), link_to("r")])
    assert BoNode.decode(None, upper.encode()) == upper
    assert BoNode.child_sizes(split) == [BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES, 1]
    # exactly one fan-out of full leaves stays one level: 2^13 groups cut into 16 leaves of 8 MiB
    full = BoNode.LEAF_GROUPS * BoNode.FANOUT * BoNode.GROUP_BYTES
    assert BoNode.child_sizes(full) == [BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES] * BoNode.FANOUT
    # an uneven count of blocks above one fan-out: 2^13 + 3 * 2^9 groups cut into 2^13-group blocks
    big = (BoNode.LEAF_GROUPS * BoNode.FANOUT + 3 * BoNode.LEAF_GROUPS) * BoNode.GROUP_BYTES
    assert BoNode.child_sizes(big) == [BoNode.LEAF_GROUPS * BoNode.FANOUT * BoNode.GROUP_BYTES,
                                       3 * BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES]
    with pytest.raises(NodeFormatError, match="group size 2\\^6"):
        BoNode.decode(None, raw({**nodes.decode(single.encode()), "g": 6}))


def test_a_full_bo_leaf_fits_the_node_bound():
    size = BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES
    encoded = BoNode(size, bytes((BoNode.LEAF_GROUPS - 1) * BoNode.PARENT_BYTES), []).encode()
    # 1 + 3 (c) + 3 (g) + 5 (k) + 7 (n) + 2 + 3 + 32,704 (p), as BoNode.java states: a leaf covers 8 MiB
    # (PDT 2 phase 4 measures, P2-Q-PRF-05)
    assert len(encoded) == 32728 <= nodes.MAX_NODE_BYTES


# ------------------------------------------------------------------ the text leaf

def run(replica, counter, parent, side, length, deleted, text):
    return TextRun(replica, counter, parent, side, length, deleted, text)


def test_two_concurrent_inserts_merge_without_interleaving_and_a_delete_sticks():
    base = TextLeaf([run("alice", 0, None, "R", 2, False, "ac")])
    alice = TextLeaf([run("alice", 0, None, "R", 2, False, "ac"), run("alice", 2, CharId("alice", 1), "L", 1, False, "b")])
    bob = TextLeaf([run("alice", 0, None, "R", 1, True, ""), run("alice", 1, CharId("alice", 0), "R", 1, False, "c"),
                    run("bob", 0, CharId("alice", 1), "L", 2, False, "XY")])
    assert (base.text(), alice.text(), bob.text()) == ("ac", "abc", "XYc")
    merged = alice.union(bob)
    assert merged.text() == "bXYc"
    assert bob.union(alice) == merged and merged.union(merged) == merged
    assert list(merged.runs) == [run("alice", 0, None, "R", 1, True, ""),
                                 run("alice", 1, CharId("alice", 0), "R", 1, False, "c"),
                                 run("alice", 2, CharId("alice", 1), "L", 1, False, "b"),
                                 run("bob", 0, CharId("alice", 1), "L", 2, False, "XY")]


def test_of_compresses_characters_into_maximal_runs():
    split = TextLeaf.of([run("alice", 0, None, "R", 1, False, "a"), run("alice", 1, CharId("alice", 0), "R", 1, False, "b")])
    assert list(split.runs) == [run("alice", 0, None, "R", 2, False, "ab")]


def test_the_leaf_refuses_every_form_but_the_canonical_one():
    for runs, message in (([run("alice", 0, None, "R", 1, False, "a"), run("alice", 1, CharId("alice", 0), "R", 1, False, "b")],
                           "canonical"),
                          ([run("bob", 0, None, "R", 1, False, "b"), run("alice", 0, None, "R", 1, False, "a")], "canonical"),
                          ([run("alice", 0, None, "R", 2, False, "ab"), run("alice", 1, None, "R", 1, False, "x")], "twice"),
                          ([run("alice", 0, CharId("carol", 9), "R", 1, False, "a")], "parent carol:9"),
                          ([run("alice", 0, CharId("bob", 0), "R", 1, False, "a"), run("bob", 0, CharId("alice", 0), "R", 1, False, "b")],
                           "cycle")):
        with pytest.raises(ValueError, match=message):
            TextLeaf(runs)
    with pytest.raises(NodeFormatError, match="text leaf version 2"):
        TextLeaf.decode(None, raw({"k": "t", "r": [run("alice", 0, None, "R", 1, False, "a")], "v": 2}))
    with pytest.raises(ValueError, match="alice:0"):
        TextLeaf([run("alice", 0, None, "R", 1, False, "a")]).union(TextLeaf([run("alice", 0, None, "R", 1, False, "z")]))


def test_a_child_of_the_document_root_hangs_on_its_right():
    data = bytearray(raw({"k": "t", "r": [run("alice", 0, None, "R", 1, False, "a")], "v": 1}))
    data[data.index(b"\x61\x52") + 1] = 0x4C
    with pytest.raises(NodeFormatError, match="document root"):
        TextLeaf.decode(None, bytes(data))


def test_replicas_sort_by_their_utf8_bytes():
    # U+FFFD sorts before U+1F600 in UTF-8 (EF.. before F0..) and after it in UTF-16
    leaf = TextLeaf.of([run("\U0001F600", 0, None, "R", 1, False, "y"), run("�", 0, None, "R", 1, False, "x")])
    assert leaf.runs[0].replica == "�"
    assert leaf.text() == "xy"


def test_a_leaf_holds_at_most_the_node_byte_bound_of_characters():
    # PDT 2 phase 0 (P2-T-01, gate finding G1): a deleted run costs no text bytes, so without a bound a
    # 29-byte node naming one deleted run of 2^40 characters would expand forever in every port; a leaf
    # holds at most MAX_CHARS characters, live and deleted, checked before expansion, as Java does
    assert TextLeaf.MAX_CHARS == nodes.MAX_NODE_BYTES
    full = TextLeaf([run("alice", 0, None, "R", TextLeaf.MAX_CHARS, True, "")])
    assert full.text() == ""
    with pytest.raises(ValueError, match="at most 1048576 characters"):
        TextLeaf([run("alice", 0, None, "R", TextLeaf.MAX_CHARS + 1, True, "")])
    with pytest.raises(ValueError, match="at most 1048576 characters"):
        TextLeaf.of([run("alice", 0, None, "R", TextLeaf.MAX_CHARS, True, ""), run("bob", 0, None, "R", 1, False, "b")])
    with pytest.raises(ValueError, match="at most 1048576 characters"):
        full.union(TextLeaf([run("bob", 0, None, "R", 1, False, "b")]))
    hostile = raw({"k": "t", "r": [run("a", 0, None, "R", 1 << 40, True, "")], "v": 1})
    assert len(hostile) == 29
    started = time.monotonic()
    with pytest.raises(NodeFormatError, match="at most 1048576 characters"):
        TextLeaf.decode(None, hostile)
    assert time.monotonic() - started < 1


def test_a_long_run_reads_without_recursion():
    text = "a" * 50_000
    assert TextLeaf([run("alice", 0, None, "R", len(text), False, text)]).text() == text


# ------------------------------------------------------------------ StorePin and StoreReceipt (P2-S-02)

PEER = "zQ3shPeerRequester"


def test_a_pin_writes_java_field_order_with_canonical_attrs_and_omits_null_attrs():
    pin = content_store.store_pin(link_to("r").cid, "tree", 60, 1, PEER, None, {"zz": "1", "a": "2"})
    assert list(pin) == ["v", "root", "kind", "lease", "copies", "requester", "haves", "attrs"]
    assert list(pin["attrs"]) == ["a", "zz"] and pin["haves"] == []
    bare = content_store.store_pin(link_to("r").cid, "artifact", 60, 1, PEER)
    assert "attrs" not in bare
    assert content_store.decode_store_pin(cbor.dumps(bare)) == bare
    assert content_store.STORE_PIN_TYPE == "ai.badmonkey.agentspaces.agent.content.StorePin#v1"
    assert content_store.STORE_RECEIPT_TYPE == "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1"


def test_a_pin_or_receipt_with_a_field_its_schema_does_not_name_is_undecodable():
    pin = content_store.store_pin(link_to("r").cid, "tree", 60, 1, PEER)
    receipt = content_store.store_receipt(link_to("r").cid, PEER, 10, 20, False)
    assert content_store.decode_store_pin(cbor.dumps({**pin, "extra": 1})) is None
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "extra": 1})) is None
    assert content_store.decode_store_receipt(cbor.dumps(receipt)) == receipt
    # a field missing, a field out of its place, a null attrs, attrs out of order, a non-text attr value
    assert content_store.decode_store_pin(cbor.dumps({k: v for k, v in pin.items() if k != "haves"})) is None
    assert content_store.decode_store_pin(cbor.dumps({"root": pin["root"], **pin})) is None
    assert content_store.decode_store_pin(cbor.dumps({**pin, "attrs": None})) is None
    assert content_store.decode_store_pin(cbor.dumps({**pin, "attrs": {"b": "1", "a": "2"}})) is None
    assert content_store.decode_store_pin(cbor.dumps({**pin, "attrs": {"a": 1}})) is None
    # a Java int holds v and copies; a boolean is no integer and an integer no boolean
    assert content_store.decode_store_pin(cbor.dumps({**pin, "copies": 1 << 31})) is None
    assert content_store.decode_store_pin(cbor.dumps({**pin, "lease": True})) is None
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "blind": 1})) is None
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "until": 1 << 63})) is None
    assert content_store.decode_store_receipt(b"\x00") is None
    # a PeerId is non-empty text, as Java's PeerId refuses an empty value
    assert content_store.decode_store_pin(cbor.dumps({**pin, "requester": ""})) is None
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "holder": ""})) is None
    assert content_store.decode_store_receipt(cbor.dumps(receipt) + b"\x00") is None


def test_the_pin_and_receipt_bounds():
    root = link_to("r").cid
    ok = content_store.store_pin(root, "tree", 60, 1, PEER, [link_to("h").cid], {"a": "b"})
    assert content_store.store_pin_violation(ok) is None
    for change, message in (({"v": 2}, "unsupported StorePin version 2"), ({"root": "x"}, "root is not a CID"),
                            ({"kind": "box"}, "unknown kind box"), ({"lease": 0}, "lease of 0 seconds"),
                            ({"copies": 0}, "copies below 1"),
                            ({"haves": [link_to(str(i)).cid for i in range(9)]}, "more than 8 haves"),
                            ({"haves": ["x"]}, "have is not a CID"),
                            ({"attrs": {f"k{i}": "v" for i in range(33)}}, "more than 32 attrs"),
                            ({"attrs": {"k": "v" * 4096}}, "attrs larger than 4096 bytes")):
        assert content_store.store_pin_violation({**ok, **change}) == message
    receipt = content_store.store_receipt(root, PEER, 0, 0, True)
    assert content_store.store_receipt_violation(receipt) is None
    for change, message in (({"v": 2}, "unsupported StoreReceipt version 2"), ({"root": "x"}, "root is not a CID"),
                            ({"bytes": -1}, "negative bytes"), ({"until": -1}, "negative until")):
        assert content_store.store_receipt_violation({**receipt, **change}) == message
    with pytest.raises(ValueError):
        content_store.store_pin(root, "tree", 60, 1, PEER, None, {"a": 1})


# ------------------------------------------------------------------ SignedPin (PDT 2 follow-ups, 2026-11-09, F1)

def _terms(requester, copies=1, **change):
    pin = content_store.store_pin(link_to("r").cid, "tree", 86400, copies, requester.peer_id, None, {"pdt.stores": "zA"})
    return {**pin, **change}


def test_a_signed_pin_carries_its_requesters_consent_for_its_group_and_deadline():
    alice = Identity.generate()
    signed = content_store.sign_pin(_terms(alice, 2), "zStores", 1792406400000, alice)
    assert list(signed) == ["v", "pin", "left", "notAfter", "key", "sig"]
    assert signed["left"] == 2 and signed["key"] == alice.public_raw and len(signed["sig"]) == 64
    assert content_store.signed_pin_violation(signed) is None
    assert content_store.signed_pin_consented(signed, "zStores")
    assert not content_store.signed_pin_consented(signed, "zOther")
    assert content_store.decode_signed_pin(cbor.dumps(signed)) == signed
    with pytest.raises(ValueError, match="requester"):
        content_store.sign_pin(_terms(alice), "zStores", 1792406400000, Identity.generate())


def test_a_pin_its_requester_did_not_sign_is_no_consent():
    alice, mallory = Identity.generate(), Identity.generate()
    forged = content_store.sign_pin(_terms(mallory), "zStores", 1792406400000, mallory)
    renamed = {**forged, "pin": _terms(alice)}
    assert content_store.signed_pin_violation(renamed) is None
    assert not content_store.signed_pin_consented(renamed, "zStores"), "the key is not the requester's"
    assert not content_store.signed_pin_consented({**renamed, "key": alice.public_raw}, "zStores")
    # mallory's own key over the very consent bytes of terms naming alice verifies, so the key binding refuses it
    consent = content_store.consent_bytes(_terms(alice), "zStores", forged["notAfter"])
    own_key = {**renamed, "sig": mallory.sign(consent)}
    assert Identity.verify(mallory.public_raw, consent, own_key["sig"])
    assert not content_store.signed_pin_consented(own_key, "zStores"), "a forger's own key over terms naming alice"
    honest = content_store.sign_pin(_terms(alice), "zStores", 1792406400000, alice)
    assert not content_store.signed_pin_consented({**honest, "pin": _terms(alice, 3)}, "zStores"), "changed terms"
    assert not content_store.signed_pin_consented({**honest, "notAfter": honest["notAfter"] + 1}, "zStores")
    assert content_store.signed_pin_consented({**honest, "left": 1}, "zStores"), "a store counts the copies down"


def test_a_signed_pin_reads_strictly_and_names_every_bound_it_breaks():
    alice = Identity.generate()
    ok = content_store.sign_pin(_terms(alice, 2), "zStores", 1792406400000, alice)
    decode = content_store.decode_signed_pin
    assert decode(cbor.dumps({**ok, "holder": "zForger"})) is None
    assert decode(cbor.dumps({k: v for k, v in ok.items() if k != "left"})) is None
    assert decode(cbor.dumps({"pin": ok["pin"], **ok})) is None
    assert decode(cbor.dumps({**ok, "left": True})) is None
    assert decode(cbor.dumps({**ok, "left": 1 << 31})) is None
    assert decode(cbor.dumps({**ok, "notAfter": 1 << 63})) is None
    assert decode(cbor.dumps({**ok, "key": alice.public_raw.hex()})) is None
    assert decode(cbor.dumps({**ok, "pin": {**ok["pin"], "extra": 1}})) is None
    assert decode(cbor.dumps({**ok, "pin": None})) is None
    assert decode(cbor.dumps(ok) + b"\x00") is None
    violation = content_store.signed_pin_violation
    assert violation({**ok, "v": 2}) == "unsupported SignedPin version 2"
    assert violation({**ok, "left": 3}) == "left 3 is outside 1 to 2 copies"
    assert violation({**ok, "left": 0}) == "left 0 is outside 1 to 2 copies"
    assert violation({**ok, "notAfter": -1}) == "negative notAfter"
    assert violation({**ok, "key": bytes(31)}) == "key is not 32 bytes"
    assert violation({**ok, "sig": bytes(63)}) == "sig is not 64 bytes"
    assert violation({**ok, "pin": {**ok["pin"], "root": "root"}}) == "root is not a CID"


# ------------------------------------------------------------------ pdt.ancestry (rule 9)

def test_an_ancestry_attribute_a_reader_cannot_use_reads_as_no_ancestry():
    vg = VgNode(link_to("root").cid, [], "zQ3shPeer/writer", "1:0:n", [])
    vg_bytes = vg.encode()
    head = refs.pref_record("facts", refs.KIND_MAP, vg.root, attrs={ancestry.ANCESTRY_ATTR: cids.of(vg_bytes)})
    assert ancestry.read_ancestry(head, vg_bytes) == vg
    other_root = refs.pref_record("facts", refs.KIND_MAP, link_to("other").cid,
                                  attrs={ancestry.ANCESTRY_ATTR: cids.of(vg_bytes)})
    assert ancestry.read_ancestry(other_root, vg_bytes) is None, "a vg node of another root"
    assert ancestry.read_ancestry(head, vg_bytes + b"\x00") is None, "bytes that hash elsewhere"
    not_vg = nodes.encode({"k": "x", "v": cbor.dumps(1)})
    named_not_vg = refs.pref_record("facts", refs.KIND_MAP, vg.root, attrs={ancestry.ANCESTRY_ATTR: cids.of(not_vg)})
    assert ancestry.read_ancestry(named_not_vg, not_vg) is None, "a node that is no vg node"
    for value in ("not-a-cid", cids.of(vg_bytes, cids.RAW)):
        unusable = refs.pref_record("facts", refs.KIND_MAP, vg.root, attrs={ancestry.ANCESTRY_ATTR: value})
        assert ancestry.ancestry_cid(unusable) is None
        assert refs.pref_violation(unusable) is None, "the attribute is advisory: nothing is refused"
    assert ancestry.ancestry_cid(refs.pref_record("facts", refs.KIND_MAP, vg.root)) is None


# ------------------------------------------------------------------ the feature level (P2-F-05, P2-C-01)

def _content_node():
    peer = NetPeer(Network(), "zPythonPdt2")
    content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
    Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1)
    return content


def test_this_port_advertises_level_2_once_its_decoders_carry_every_level2_schema():
    # P2-C-01, P2-F-05: PDT 2 phase 7 brought every decoder of 6.10.4 (tree, push, content_store), so the
    # advertisement carries pdt = "2" beside trees = "1", which keeps its meaning (6.10.2)
    params = _content_node().trees.describe()["parameters"]
    assert params[tree.TREES_PARAMETER] == "1"
    assert params[tree.PDT_PARAMETER] == "2"


def test_a_level2_form_from_a_member_read_at_level_1_gets_the_level1_answer_and_strikes_nobody():
    content = _content_node()
    sent = []
    content.send = lambda to, msg, via=None: sent.append((to, msg))
    # 6.10.3 rule 12 and the phase 5 adversary's A6: a sketch from a member this holder reads at level 1 (it
    # advertises no pdt) gets REJECT reason 3 and no sketch TREE_END
    content._on_frame("zSender", cbor.dumps(tree.tree_want(7, "", [], 1024, b"\x61\x00")))
    assert sent == [("zSender", {"t": 5, "root": "", "index": -1, "reason": 3})]
    sent.clear()
    # rule 15: a level-2 holder answers tag 12; holding none of the picks, it refuses with reason 1
    root = link_to("r").cid
    content._on_frame("zSender", cbor.dumps({"t": 12, "req": 8, "root": root, "picks": [{"cid": link_to("n").cid}]}))
    assert sent == [("zSender", {"t": 5, "root": root, "index": -1, "reason": 1})]
    assert content.trees.nodes_struck == 0
