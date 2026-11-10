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
"""PDT 2 phase 0 in Python against hostile bytes (srad/agentspaces-pdt2.md §6.10; P2-D-01, P2-T-01,
P2-V-01, P2-V-02, P2-B-02, P2-S-02): the refusals that a differential run against Java's readers and
a mutation run over the port showed untested. A receiver checks a node a peer serves by its CID
alone, so the codec meets every malformed node with a ``NodeFormatError``, which the tree walk and
the ancestry reader catch. A record field that Java reads as a typed value makes the record
undecodable in any other form."""

import pytest

from agentspaces import cbor
from agentspaces.pdt import NodeStore, ancestry, cids, content_store, nodes, refs
from agentspaces.pdt.items import CharId, Datom, Tagged
from agentspaces.pdt.kinds import BoNode, DnNode, VgNode
from agentspaces.pdt.nodes import Link, NodeFormatError

PEER = "zQ3shPeer"


def link_to(name: str) -> Link:
    return Link(cids.of(name.encode()))


# ------------------------------------------------------------------ text the node codec cannot read

#: ``{k: "dn", <key 0xff>: 0}`` and ``{k: <text 0xff 0xfe>}``: a key and a kind that are no UTF-8.
BAD_KEY = bytes.fromhex("a2616b62646e61ff00")
BAD_KIND = bytes.fromhex("a1616b62fffe")


@pytest.mark.parametrize("data", (BAD_KEY, BAD_KIND), ids=("key", "kind"))
def test_a_key_or_kind_that_is_no_utf8_is_a_node_format_refusal(data):
    # P2-D-01: Java reads these bytes as a key outside the schema or an unknown kind and refuses them
    # with a NodeFormatException; every caller of the codec catches the NodeFormatError alone
    with pytest.raises(NodeFormatError, match="UTF-8"):
        nodes.decode(data)
    with pytest.raises(NodeFormatError):
        nodes.links(data)
    with pytest.raises(NodeFormatError):
        DnNode.decode(None, data)


def test_the_tree_walk_reads_a_node_with_a_key_that_is_no_utf8_as_a_leaf():
    store = NodeStore()
    cid = cids.of(BAD_KEY)
    assert store.links(cid, BAD_KEY) == []


def test_an_ancestry_node_with_a_key_that_is_no_utf8_reads_as_no_ancestry():
    # rule 9: the attribute is advisory, so a node that does not decode refuses and raises nothing
    data = BAD_KEY
    head = refs.pref_record("facts", refs.KIND_MAP, link_to("root").cid, attrs={ancestry.ANCESTRY_ATTR: cids.of(data)})
    assert ancestry.read_ancestry(head, data) is None


def test_an_ancestry_reader_refuses_another_vg_node_of_the_same_root():
    # P2-V-02: the node must hash to the CID the head names; a well-formed vg node of the head's root
    # under another CID is a node the head does not name
    root = link_to("root").cid
    named = VgNode(root, [], "zQ3shPeer/writer", "1:0:n", []).encode()
    other = VgNode(root, [], "zQ3shPeer/writer", "2:0:n", []).encode()
    head = refs.pref_record("facts", refs.KIND_MAP, root, attrs={ancestry.ANCESTRY_ATTR: cids.of(named)})
    assert ancestry.read_ancestry(head, named) is not None
    assert ancestry.read_ancestry(head, other) is None


# ------------------------------------------------------------------ the codec's own field checks

def test_the_codec_refuses_a_vg_node_whose_root_or_base_is_no_cid():
    # P2-V-01: the node codec checks CID text itself, so the tree walk (nodes.links) refuses the node
    # before any typed reader runs
    root, base = link_to("r").cid, link_to("b").cid
    node = nodes.encode({"k": "vg", "r": root, "b": [base], "i": "zQ3shPeer/w", "t": "1:0:n", "p": []})
    for field, cid in (("r", root), ("b", base)):
        hostile = node.replace(cid.encode(), b"x" * len(cid))
        with pytest.raises(NodeFormatError, match=f"'{field}' must hold a CID as text"):
            nodes.links(hostile)


def test_a_bo_leaf_carries_no_child_link():
    # P2-B-02: a node over at most LEAF_GROUPS groups is a leaf, its parents count alone is not enough
    with pytest.raises(ValueError, match="has 0 children, found 1"):
        BoNode(BoNode.GROUP_BYTES * 2, b"\x00" * BoNode.PARENT_BYTES, [link_to("child")])


# ------------------------------------------------------------------ the items' constructors

def test_a_datom_refuses_an_entity_past_the_long_range_and_text_with_a_lone_surrogate():
    for e in (1 << 63, -(1 << 63) - 1):
        with pytest.raises(ValueError, match="entity"):
            Datom(e, ":a/b", 1, 1)
    with pytest.raises(ValueError, match="attribute holds a lone surrogate"):
        Datom(1, ":a/\ud800", 1, 1)
    with pytest.raises(ValueError, match="text holds a lone surrogate"):
        Datom(1, ":a/b", "\udfff", 1)


def test_an_instant_holds_an_integer_and_a_character_counter_is_non_negative():
    for inner in ("1", 1.0, True, 1 << 63):
        with pytest.raises(ValueError, match="an instant value holds an integer"):
            Tagged(Tagged.INSTANT, inner)
    with pytest.raises(ValueError, match="a character counter is non-negative"):
        CharId("a", -1)


# ------------------------------------------------------------------ the store records (P2-S-02)

def test_a_record_field_java_reads_as_a_long_or_text_is_undecodable_in_another_form():
    root = link_to("r").cid
    pin = content_store.store_pin(root, "tree", 60, 1, PEER, [link_to("h").cid])
    receipt = content_store.store_receipt(root, PEER, 10, 20, False)
    # a bignum past 2^63 - 1 is no Java long
    assert content_store.decode_store_pin(cbor.dumps({**pin, "lease": 1 << 63})) is None
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "bytes": 1 << 63})) is None
    # Java coerces a number to text and re-encodes it as text, so the bytes differ and it refuses
    for change in ({"root": 1}, {"kind": 1}, {"haves": [1]}, {"haves": [None]}):
        assert content_store.decode_store_pin(cbor.dumps({**pin, **change})) is None, change
    assert content_store.decode_store_receipt(cbor.dumps({**receipt, "root": 1})) is None
