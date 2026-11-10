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
"""The PDT 2 golden vectors (srad/agentspaces-pdt2.md §8, P2-O-02; P2-D-01, P2-S-02, P2-B-02, P2-R-01, P2-T-01,
P2-V-01, and PDT 2 phase 7's P2-C-01): every PDT 2 vector of golden.json, produced by the Java build, rebuilt from
its inputs by the Python port byte for byte, decoded by its typed reader, and round-tripped. The inputs are the ones
``PdtVectors.java`` documents."""

import hashlib
import json
import pathlib
import uuid

from test_pdt_vectors import java_random_bytes

from agentspaces import cbor
from agentspaces.capabilities import content
from agentspaces.identity import Identity, derive_id
from agentspaces.pdt import PMap, PVector, NodeStore, ancestry, bao, blake3, cids, content_store, dcz, nodes, push, refs, sync, text
from agentspaces.pdt.items import Datom, Tagged, TextRun, CharId
from agentspaces.pdt.kinds import BoNode, DbRoot, DnNode, RrRoot, RvNode, TextLeaf, VgNode
from agentspaces.pdt.nodes import Embedded, Link
from agentspaces.pdt.text import PText

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())

#: The vectors PDT 2 added, in the order golden.json lists them: phase 0's sixteen, phase 1's merge
#: version (PDT 2 phase 1, P2-V-01), phase 2's version 2 head and sample database (P2-D-03, P2-D-09),
#: the signed pin, its consent, and the table-less tree manifest (PDT 2 follow-ups, 2026-11-09, F1 and F3),
#: phase 6's relaxed vector and texts (§10.10), phase 4's dcz frame (§10.12), and phase 5's push bundle and
#: RIBLT symbols (§10.13).
PDT2_VECTORS = ("pdt_db_root", "pdt_dn_leaf", "pdt_dn_branch", "pdt_dn_tail", "pdt_datom_values",
                "pdt_store_pin_cbor", "pdt_store_receipt_cbor", "pdt_blake3_identity", "pdt_bo_small",
                "pdt_bo_split", "pdt_rr_relaxed", "pdt_rr_packed", "pdt_text_runs", "pdt_text_merge",
                "pdt_vg_chain", "pdt_ref_ancestry_cbor", "pdt_vg_merge", "pdt_ref_v2_cbor", "pdt_db_sample",
                "pdt_db_sample_answers", "pdt_signed_pin_cbor", "pdt_signed_pin_consent_cbor",
                "pdt_manifest_tree_cbor", "pdt_rr_splice", "pdt_text_edits", "pdt_text_value", "pdt_text_spill",
                "pdt_text_replica", "pdt_dcz_frame", "pdt_push_bundle_cbor", "pdt_riblt_symbols")

TX1, TX2 = 536870913, 536870914
AGE_1 = Datom(1, ":person/age", 36, TX1)
NAME_1 = Datom(1, ":person/name", "Ada", TX1)
AGE_2 = Datom(2, ":person/age", 45, TX1)
NAME_2 = Datom(2, ":person/name", "Grace", TX1)
REQUESTER = derive_id(bytes(range(32)))
HOLDER = derive_id(bytes(range(32, 64)))
WRITER = REQUESTER + "/writer"
DEEP_ROOT = cids.of(bytes.fromhex(GOLDEN["pdt_map_deep"]))
SMALL_ROOT = cids.of(bytes.fromhex(GOLDEN["pdt_map_small"]))
EMPTY_ROOT = cids.of(bytes.fromhex(GOLDEN["pdt_map_empty"]))


def _parts(name):
    return GOLDEN[name].split(",")


def _hex(name, part=0):
    return bytes.fromhex(_parts(name)[part])


def _link(data: bytes) -> Link:
    return Link(cids.of(data))


def test_the_suite_reads_every_pdt2_vector_and_golden_json_lists_them_after_the_first_design():
    keys = list(GOLDEN)
    start = keys.index("pdt_sealed_node") + 1
    assert tuple(k for k in keys[start:] if k.startswith("pdt_")) == PDT2_VECTORS
    # PDT 2 phase 7 (P2-C-01, P2-T-05) read the last vectors that waited for a Python reader, so the list of them ended
    # empty and is gone: every PDT 2 vector golden.json holds has a test below that reads it
    assert _COVERED == set(PDT2_VECTORS), "every PDT 2 vector has a test below that reads it"


#: The vectors the tests below read, marked by ``_covers``.
_COVERED = set()


def _covers(*names):
    def mark(test):
        _COVERED.update(names)
        return test
    return mark


# ------------------------------------------------------------------ P2-D-01

def _golden_index(index: str) -> DnNode:
    order = {DnNode.EAVT: [AGE_1, NAME_1, AGE_2, NAME_2], DnNode.AEVT: [AGE_1, AGE_2, NAME_1, NAME_2],
             DnNode.AVET: [NAME_1, NAME_2]}[index]
    return DnNode.leaf(index, order)


def _golden_tail() -> DnNode:
    return DnNode.tail([Datom(2, ":person/age", 45, -TX2), Datom(2, ":person/age", 46, TX2)])


@_covers("pdt_db_root", "pdt_dn_leaf", "pdt_dn_tail")
def test_the_database_vectors_rebuild_from_the_golden_database_and_read_back():
    eavt, aevt, avet, tail = (_golden_index(DnNode.EAVT), _golden_index(DnNode.AEVT), _golden_index(DnNode.AVET),
                              _golden_tail())
    assert eavt.encode() == _hex("pdt_dn_leaf")
    assert tail.encode() == _hex("pdt_dn_tail")
    assert aevt.encode() == _hex("pdt_db_root", 1)
    assert avet.encode() == _hex("pdt_db_root", 2)
    schema = Embedded(cbor.dumps({":person/name": {":db/index": True}}))
    root = DbRoot(schema, 2, TX2, DbRoot.BRANCHING, _link(eavt.encode()), _link(aevt.encode()), _link(avet.encode()),
                  _link(tail.encode()))
    assert root.encode() == _hex("pdt_db_root")
    read = DbRoot.decode(None, _hex("pdt_db_root"))
    assert read == root
    assert cbor.loads(read.schema.bytes) == {":person/name": {":db/index": True}}
    # the root links aevt, avet, eavt, then the tail, as NodeCodec.links lists them
    assert nodes.links(_hex("pdt_db_root")) == [cids.of(_hex("pdt_db_root", 1)), cids.of(_hex("pdt_db_root", 2)),
                                                 cids.of(_hex("pdt_dn_leaf")), cids.of(_hex("pdt_dn_tail"))]
    assert DnNode.decode(None, _hex("pdt_dn_leaf")) == eavt
    assert DnNode.decode(None, _hex("pdt_dn_tail")).datoms[0].tx == -TX2
    for name, part in (("pdt_db_root", 0), ("pdt_db_root", 1), ("pdt_db_root", 2), ("pdt_dn_leaf", 0), ("pdt_dn_tail", 0)):
        assert nodes.encode(nodes.decode(_hex(name, part))) == _hex(name, part)


@_covers("pdt_dn_branch")
def test_the_branch_vector_keys_each_child_by_its_largest_datom():
    first = DnNode.leaf(DnNode.EAVT, [AGE_1, NAME_1])
    second = DnNode.leaf(DnNode.EAVT, [AGE_2, NAME_2])
    branch = DnNode.branch(1, DnNode.EAVT, [NAME_1, NAME_2], [_link(first.encode()), _link(second.encode())])
    assert [p for p in _parts("pdt_dn_branch")] == [branch.encode().hex(), first.encode().hex(), second.encode().hex()]
    read = DnNode.decode(None, _hex("pdt_dn_branch"))
    assert read == branch
    assert nodes.links(_hex("pdt_dn_branch")) == [cids.of(_hex("pdt_dn_branch", 1)), cids.of(_hex("pdt_dn_branch", 2))]


@_covers("pdt_datom_values")
def test_the_datom_values_vector_holds_one_datom_per_value_form():
    spill = Link(cids.of(bytes(5000), cids.RAW))
    datoms = [Datom(3, ":v/bigint", Tagged.bigint(2 ** 70), TX1),
              Datom(3, ":v/bool", True, TX1),
              Datom(3, ":v/bytes", b"\x00\x01\x02", TX1),
              Datom(3, ":v/float", 1.5, TX1),
              Datom(3, ":v/instant", Tagged.instant(1792320000000), TX1),
              Datom(3, ":v/int", -7, TX1),
              Datom(3, ":v/keyword", ":status/active", TX1),
              Datom(3, ":v/ref", 2, TX1),
              Datom(3, ":v/spill", spill, TX1),
              Datom(3, ":v/text", "Ada ✓", TX1),
              Datom(3, ":v/uuid", Tagged.uuid(uuid.UUID("0123456789abcdeffedcba9876543210")), -TX2)]
    leaf = DnNode.leaf(DnNode.EAVT, datoms)
    assert leaf.encode() == _hex("pdt_datom_values")
    read = DnNode.decode(None, _hex("pdt_datom_values"))
    assert list(read.datoms) == datoms
    assert type(read.datoms[1].v) is bool and type(read.datoms[7].v) is int and type(read.datoms[3].v) is float
    assert read.datoms[0].v.integer() == 2 ** 70
    assert read.datoms[10].v.as_uuid() == uuid.UUID("0123456789abcdeffedcba9876543210")
    assert nodes.links(_hex("pdt_datom_values")) == [spill.cid]
    assert nodes.encode(nodes.decode(_hex("pdt_datom_values"))) == _hex("pdt_datom_values")


# ------------------------------------------------------------------ P2-S-02

@_covers("pdt_store_pin_cbor", "pdt_store_receipt_cbor")
def test_the_store_record_vectors_rebuild_read_strictly_and_re_encode():
    pin = content_store.store_pin(DEEP_ROOT, content_store.KIND_TREE, 86400, 2, REQUESTER, [SMALL_ROOT],
                                  {"purpose": "golden"})
    assert cbor.dumps(pin) == _hex("pdt_store_pin_cbor")
    read = content_store.decode_store_pin(_hex("pdt_store_pin_cbor"))
    assert read == pin and content_store.store_pin_violation(read) is None
    assert cbor.dumps(read) == _hex("pdt_store_pin_cbor")
    assert content_store.store_pin_tags(read) == {"root": DEEP_ROOT, "requester": REQUESTER}
    receipt = content_store.store_receipt(DEEP_ROOT, HOLDER, 12345, 1792406400000, True)
    assert cbor.dumps(receipt) == _hex("pdt_store_receipt_cbor")
    read = content_store.decode_store_receipt(_hex("pdt_store_receipt_cbor"))
    assert read == receipt and content_store.store_receipt_violation(read) is None
    assert content_store.store_receipt_tags(read) == {"root": DEEP_ROOT, "holder": HOLDER}


# ------------------------------------------------------------------ P2-B-02

def _identity(digest: bytes) -> str:
    """The identity CID of a BLAKE3 hash: 0x01 0x55 0x1e 0x20 and the digest, base32 (§3.5)."""
    return "b" + cids.base32_lower(bytes([0x01, cids.RAW, 0x1E, 0x20]) + digest)


def _outboard_leaf(data: bytes) -> bytes:
    """The parents of a leaf ``bo`` node over ``data`` (at most ``BoNode.LEAF_GROUPS`` groups), in pre-order."""
    group = BoNode.GROUP_BYTES
    cvs = [blake3.group_cv(data[i:i + group], (i // group) << BoNode.GROUP_LOG)
           for i in range(0, max(1, len(data)), group)]
    out = bytearray()

    def pre_order(lo, hi):
        if hi - lo == 1:
            return cvs[lo]
        at = len(out)
        out.extend(bytes(BoNode.PARENT_BYTES))
        mid = lo + (1 << ((hi - lo - 1).bit_length() - 1))
        left, right = pre_order(lo, mid), pre_order(mid, hi)
        out[at:at + BoNode.PARENT_BYTES] = left + right
        return blake3.parent(left, right, False)

    pre_order(0, len(cvs))
    return bytes(out)


# ------------------------------------------------------------------ PDT 2 follow-ups, 2026-11-09, F1

SIGNED_PIN_GROUP = "zGolden"
SIGNED_PIN_NOT_AFTER = 1792323600000


@_covers("pdt_signed_pin_cbor", "pdt_signed_pin_consent_cbor")
def test_the_signed_pin_vector_rebuilds_from_its_requesters_seed_and_carries_its_consent():
    requester = Identity.from_seed(bytes(range(64, 96)))
    pin = content_store.store_pin(DEEP_ROOT, content_store.KIND_TREE, 86400, 2, requester.peer_id, [SMALL_ROOT],
                                  {"pdt.stores": HOLDER})
    assert content_store.consent_bytes(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER) == _hex("pdt_signed_pin_consent_cbor")
    signed = content_store.sign_pin(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER, requester)
    assert cbor.dumps(signed) == _hex("pdt_signed_pin_cbor")
    read = content_store.decode_signed_pin(_hex("pdt_signed_pin_cbor"))
    assert read == signed and content_store.signed_pin_violation(read) is None
    assert cbor.dumps(read) == _hex("pdt_signed_pin_cbor")
    assert read["left"] == read["pin"]["copies"] == 2
    assert content_store.signed_pin_consented(read, SIGNED_PIN_GROUP)
    assert not content_store.signed_pin_consented(read, "zOther"), "a consent in one group is none in another"
    assert content_store.signed_pin_tags(read) == {"root": DEEP_ROOT, "requester": requester.peer_id}
    assert content_store.SIGNED_PIN_TYPE == "ai.badmonkey.agentspaces.agent.content.SignedPin#v1"


@_covers("pdt_manifest_tree_cbor")
def test_the_tree_manifest_vector_carries_no_piece_table_and_passes_the_manifest_check():
    m = cbor.loads(_hex("pdt_manifest_tree_cbor"))
    assert m["layout"] == "tree" and m["table"] is None and m["tableRef"] is None
    assert m["root"] == _parts("pdt_blob_small")[0] and cids.codec_of(m["root"]) == cids.DAG_CBOR
    assert m["size"] == 100 * 1024 and m["pieces"] == 2
    assert content.manifest_violation(m) is None
    assert cbor.dumps(m) == _hex("pdt_manifest_tree_cbor")
    assert content.manifest_violation({**m, "layout": None}) == "exactly one of table and tableRef must be present"


@_covers("pdt_blake3_identity")
def test_the_identity_vector_is_the_blake3_of_the_cut_stream():
    stream = java_random_bytes(42, 8 * 1024 * 1024)
    assert GOLDEN["pdt_blake3_identity"] == _identity(blake3.digest(stream)) == bao.identity_of(stream)


@_covers("pdt_bo_small")
def test_the_small_outboard_vector_holds_the_parents_of_its_seven_groups_and_reaches_its_identity():
    data = java_random_bytes(42, 100 * 1024)
    node = BoNode.decode(None, _hex("pdt_bo_small"))
    assert node == BoNode(100 * 1024, _outboard_leaf(data), [])
    assert BoNode.groups(node.size) == 7 and len(node.parents) == 6 * BoNode.PARENT_BYTES
    assert node.encode() == _hex("pdt_bo_small")
    assert _parts("pdt_bo_small")[1] == _identity(blake3.digest(data))
    root_pair = node.parents[:BoNode.PARENT_BYTES]
    assert _identity(blake3.parent(root_pair[:32], root_pair[32:], True)) == _parts("pdt_bo_small")[1]
    assert nodes.links(_hex("pdt_bo_small")) == []


@_covers("pdt_bo_split")
def test_the_split_outboard_vector_links_a_full_leaf_and_a_one_group_leaf_that_python_rebuilds():
    # PDT 2 phase 4 measures, P2-Q-PRF-05 (owner ruling of 2026-11-09): a leaf covers 8 MiB, so this suite rebuilds
    # both children of the split root, and the parent pair above them, with its own BLAKE3
    leaf = BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES
    assert leaf == 8 * 1024 * 1024
    node = BoNode.decode(None, _hex("pdt_bo_split"))
    size = leaf + 5000
    assert node.size == size
    assert BoNode.child_sizes(size) == [leaf, 5000]
    data = java_random_bytes(42, size)
    full = BoNode(leaf, _outboard_leaf(data[:leaf]), [])
    last = BoNode(5000, b"", [])
    assert len(full.encode()) == 32728
    assert [cids.of(full.encode()), cids.of(last.encode())] == _parts("pdt_bo_split")[2:]
    assert [c.cid for c in node.children] == _parts("pdt_bo_split")[2:]
    left = blake3.parent(full.parents[:32], full.parents[32:64], False)
    right = blake3.group_cv(data[leaf:], BoNode.LEAF_GROUPS << BoNode.GROUP_LOG)
    assert node.parents == left + right
    assert _identity(blake3.parent(left, right, True)) == _parts("pdt_bo_split")[1]
    assert node.encode() == _hex("pdt_bo_split")
    assert nodes.links(_hex("pdt_bo_split")) == _parts("pdt_bo_split")[2:]


# ------------------------------------------------------------------ P2-R-01

def _v_leaf(lo, hi) -> bytes:
    return nodes.encode({"k": nodes.KIND_V, "e": [cbor.dumps(i) for i in range(lo, hi)]})


@_covers("pdt_rr_relaxed", "pdt_rr_packed")
def test_the_rrb_vectors_hold_the_elements_relaxed_and_packed():
    leaves = [(0, 32), (32, 40), (40, 72), (72, 96)]
    rv = RvNode([_link(_v_leaf(lo, hi)) for lo, hi in leaves], [hi for _lo, hi in leaves])
    rr = RrRoot(100, RrRoot.BITS, _link(rv.encode()), [Embedded(cbor.dumps(i)) for i in range(96, 100)])
    assert _parts("pdt_rr_relaxed") == [rr.encode().hex(), rv.encode().hex()]
    assert RrRoot.decode(None, _hex("pdt_rr_relaxed")) == rr
    assert RvNode.decode(None, _hex("pdt_rr_relaxed", 1)) == rv
    assert nodes.links(_hex("pdt_rr_relaxed", 1)) == [_link(_v_leaf(lo, hi)).cid for lo, hi in leaves]
    store = NodeStore()
    packed = PVector.empty(store).conj_many(range(100))
    assert store.get(packed.root()) == _hex("pdt_rr_packed")
    assert nodes.kind_of(_hex("pdt_rr_packed")) == nodes.KIND_VR
    for part in (0, 1):
        assert nodes.encode(nodes.decode(_hex("pdt_rr_relaxed", part))) == _hex("pdt_rr_relaxed", part)


# ------------------------------------------------------------------ P2-T-01

@_covers("pdt_text_runs", "pdt_text_merge")
def test_the_text_vectors_read_and_merge_in_fugue_order():
    runs = TextLeaf([TextRun("alice", 0, None, TextRun.RIGHT, 4, False, "Ab\U0001F600c"),
                     TextRun("alice", 4, CharId("alice", 1), TextRun.LEFT, 2, True, ""),
                     TextRun("bob", 0, CharId("alice", 3), TextRun.RIGHT, 2, False, "é!")])
    assert runs.encode() == _hex("pdt_text_runs")
    assert TextLeaf.decode(None, _hex("pdt_text_runs")) == runs
    assert runs.text() == "Ab\U0001F600cé!"
    alice = TextLeaf([TextRun("alice", 0, None, TextRun.RIGHT, 2, False, "ac"),
                      TextRun("alice", 2, CharId("alice", 1), TextRun.LEFT, 1, False, "b")])
    bob = TextLeaf([TextRun("alice", 0, None, TextRun.RIGHT, 1, True, ""),
                    TextRun("alice", 1, CharId("alice", 0), TextRun.RIGHT, 1, False, "c"),
                    TextRun("bob", 0, CharId("alice", 1), TextRun.LEFT, 2, False, "XY")])
    merged = alice.union(bob)
    assert _parts("pdt_text_merge") == [alice.encode().hex(), bob.encode().hex(), merged.encode().hex(), "bXYc"]
    assert bob.union(alice) == merged and merged.text() == "bXYc"
    assert TextLeaf.decode(None, _hex("pdt_text_merge", 0)).union(TextLeaf.decode(None, _hex("pdt_text_merge", 1))) \
        == TextLeaf.decode(None, _hex("pdt_text_merge", 2))


# ------------------------------------------------------------------ P2-V-01

@_covers("pdt_vg_chain", "pdt_ref_ancestry_cbor")
def test_the_version_graph_vectors_chain_and_the_head_names_its_node():
    small = VgNode(SMALL_ROOT, [], WRITER, "1792320000000:0:golden", [])
    deep = VgNode(DEEP_ROOT, [SMALL_ROOT], WRITER, "1792320000001:0:golden", [_link(small.encode())])
    assert _parts("pdt_vg_chain") == [deep.encode().hex(), small.encode().hex()]
    assert VgNode.decode(None, _hex("pdt_vg_chain")) == deep
    assert nodes.links(_hex("pdt_vg_chain")) == [cids.of(_hex("pdt_vg_chain", 1))]
    vg = cids.of(deep.encode())
    head = refs.pref_record("facts", refs.KIND_MAP, DEEP_ROOT, [SMALL_ROOT], seq=2, size=100,
                            attrs={ancestry.ANCESTRY_ATTR: vg})
    assert cbor.dumps(head) == _hex("pdt_ref_ancestry_cbor")
    read = refs.decode_pref(_hex("pdt_ref_ancestry_cbor"))
    assert read == head and refs.pref_violation(read) is None
    assert ancestry.ancestry_cid(read) == vg
    assert ancestry.read_ancestry(read, _hex("pdt_vg_chain")) == deep


@_covers("pdt_vg_merge")
def test_the_merge_version_links_each_base_node_in_the_order_of_its_bases():
    """PDT 2 phase 1, P2-V-01: a merge version's chain node names both bases and links each base's
    ``vg`` node in the same order, as the Java ``Refs`` writes it."""
    deep, small = _hex("pdt_vg_chain"), _hex("pdt_vg_chain", 1)
    merge = VgNode(EMPTY_ROOT, [DEEP_ROOT, SMALL_ROOT], WRITER, "1792320000002:0:golden",
                   [_link(deep), _link(small)])
    assert merge.encode() == _hex("pdt_vg_merge")
    assert VgNode.decode(None, _hex("pdt_vg_merge")) == merge
    assert nodes.links(_hex("pdt_vg_merge")) == [cids.of(deep), cids.of(small)]
    head = refs.pref_record("facts", refs.KIND_MAP, EMPTY_ROOT, [DEEP_ROOT, SMALL_ROOT], seq=3,
                            attrs={ancestry.ANCESTRY_ATTR: cids.of(merge.encode())})
    assert ancestry.read_ancestry(head, _hex("pdt_vg_merge")) == merge


# ------------------------------------------------------------------ PDT 2 phase 2

@_covers("pdt_ref_v2_cbor")
def test_a_db_head_is_version_2_and_this_level_2_reader_takes_it():
    """PDT 2 phase 2, P2-D-03 (rule 8 of §6.10.3): every head of a db ref is version 2 of kind db. PDT 2 phase 7
    (P2-F-06) made this client a level-2 reader, so it takes the head it refused at level 1."""
    root = cids.of(_hex("pdt_db_root"))
    head = refs.pref_record("graph", "db", root, seq=1, size=TX2 - 0x20000000, mode=refs.MODE_LINEAR)
    head["v"] = 2
    assert cbor.dumps(head) == _hex("pdt_ref_v2_cbor")
    read = refs.decode_pref(_hex("pdt_ref_v2_cbor"))
    assert read == head
    assert refs.pref_violation(read) is None
    assert refs.pref_violation(dict(read, v=1)) == "a db head is version 2, found 1"


@_covers("pdt_db_sample", "pdt_db_sample_answers")
def test_the_sample_database_reencodes_byte_for_byte_and_its_answers_are_leaves():
    """PDT 2 phase 2, P2-D-09: the sample's first part is its root CID, every node re-encodes to its bytes,
    and each answer is a dn leaf of the index it names (test_pdt2_db_reader reads them against the reader)."""
    root, *parts = _parts("pdt_db_sample")
    blobs = [bytes.fromhex(p) for p in parts]
    assert cids.of(blobs[0]) == root
    assert DbRoot.decode(root, blobs[0]).max_eid == 126
    for blob in blobs[1:]:
        assert nodes.encode(nodes.decode(blob)) == blob
    answers = dict(pair.split("=", 1) for pair in GOLDEN["pdt_db_sample_answers"].split(","))
    assert list(answers) == ["eavt_7", "eavt_126", "aevt_name", "avet_name_ada", "avet_friend_9", "entity_42",
                             "lookup_email_p42", "avet_name_person7"]
    for name, leaf in answers.items():
        node = DnNode.decode(None, bytes.fromhex(leaf))
        assert (node.level, node.index) == (0, name.split("_")[0].replace("entity", "eavt").replace("lookup", "avet"))


# ------------------------------------------------------------------ PDT 2 phase 7: group Z

@_covers("pdt_dcz_frame")
def test_the_dcz_frame_opens_over_its_base_to_the_target():
    """PDT 2 phase 7, P2-Z-01 and P2-Z-04: Java's frame opens in Python over the base as a raw dictionary;
    the target is the base with ``PDT2`` at offset 1,000 and ``phase four`` appended."""
    base, target, field = (_hex("pdt_dcz_frame", i) for i in range(3))
    assert base == java_random_bytes(42, 4096)
    expected = bytearray(base)
    expected[1000:1004] = b"PDT2"
    assert target == bytes(expected) + b"phase four"
    assert dcz.decode(base, field) == target


# ------------------------------------------------------------------ PDT 2 phase 7: group K

@_covers("pdt_riblt_symbols")
def test_the_riblt_vector_holds_the_first_twelve_symbols_of_ten_ids_under_its_key():
    """PDT 2 phase 7, P2-K-05: the key 00..0f, the ids sha-256("aspace:riblt:<i>") for i in 0 to 9, and the first 12
    coded symbols, which Python encodes byte for byte and reads back; a decoder over nine of the ids finds the tenth."""
    key, ids, symbols = (_hex("pdt_riblt_symbols", i) for i in range(3))
    assert key == bytes(range(16))
    expected = [hashlib.sha256(f"aspace:riblt:{i}".encode()).digest() for i in range(10)]
    assert ids == b"".join(expected)
    coded = sync.RibltEncoder(key, expected).next(12)
    assert b"".join(s.encode() for s in coded) == symbols
    reader = sync.Reader(symbols)
    assert [sync.Symbol.read(reader) for _ in range(12)] == coded and reader.remaining() == 0
    decoder = sync.RibltDecoder(key, expected[1:])
    for symbol in coded:
        decoder.add(symbol)
    assert decoder.decoded() and decoder.remote_only == [expected[0]] and decoder.local_only == []


# ------------------------------------------------------------------ PDT 2 phase 7: push

@_covers("pdt_push_bundle_cbor")
def test_the_push_bundle_vector_reads_strictly_as_seq_3_part_0_of_1_carrying_the_small_map():
    """PDT 2 phase 7, P2-P-01 and P2-P-02 (rule 16): the strict reader takes the bundle, which re-encodes to its
    bytes, and a follower that the head announced it to stores the one node its root names."""
    raw = _hex("pdt_push_bundle_cbor")
    bundle = push.decode_bundle(raw)
    small = bytes.fromhex(GOLDEN["pdt_map_small"])
    assert bundle == {"v": 1, "root": SMALL_ROOT, "seq": 3, "part": 0, "parts": 1, "nodes": [small]}
    assert push.bundle_violation(bundle) is None and cbor.dumps(bundle) == raw
    store = NodeStore()
    receiver = push.PushReceiver(store)
    receiver.follow("pdt:pdt:facts")
    receiver.on_bundle("pdt:pdt:facts", raw)
    receiver.expect("pdt:pdt:facts", SMALL_ROOT, 1)
    assert store.get(SMALL_ROOT) == small and store.complete(SMALL_ROOT)


# ------------------------------------------------------------------ PDT 2 phase 7: group T

def _text_runs() -> TextLeaf:
    return TextLeaf.decode(None, _hex("pdt_text_runs"))


@_covers("pdt_text_edits")
def test_the_text_edits_replay_fugues_insert_rule_byte_for_byte():
    """PDT 2 phase 7, P2-T-01 and P2-T-05: alice types "Hello world" at 0 and ";" at 5, deletes 1 at 0 and types "J"
    at 0; bob, from the same base, types "!" at 12 and "big " at 7. Both leaves and their union match Java's bytes."""
    base = PText.empty("alice").insert(0, "Hello world").insert(5, ";")
    alice = base.delete(0, 1).insert(0, "J")
    bob = base.with_replica("bob").insert(12, "!").insert(7, "big ")
    union = alice.merge(bob)
    assert _parts("pdt_text_edits") == [alice.leaf().encode().hex(), bob.leaf().encode().hex(),
                                         union.leaf().encode().hex(), "Jello; big world!"]
    assert str(union) == "Jello; big world!" and bob.merge(alice) == union
    assert PText.of(TextLeaf.decode(None, _hex("pdt_text_edits", 2)), "carol").leaf() == union.leaf()


@_covers("pdt_text_value")
def test_the_text_value_form_of_the_runs_vector_reads_strictly():
    """PDT 2 phase 7, P2-T-02: the value form is the wire encoding of {k:"t", r:[run...], v:1}, the map indefinite."""
    form = text.to_wire(PText.of(_text_runs(), "alice").leaf())
    assert form == _hex("pdt_text_value")
    assert text.from_wire(_hex("pdt_text_value")) == _text_runs() and text.is_text(form)
    assert cbor.dumps(cbor.loads(form)) == form


@_covers("pdt_text_spill")
def test_a_map_of_texts_spills_the_long_one_to_a_t_node_as_java_writes_it():
    """PDT 2 phase 7, P2-T-02: {"doc": 1,100 times "x" typed by alice, "note": the text of pdt_text_runs}; the doc
    value spills to a t node, and the note stays inline in its value form."""
    store = NodeStore()
    m = PMap.empty(store).assoc("doc", PText.empty("alice").insert(0, "x" * 1100)) \
        .assoc("note", PText.of(_text_runs(), "alice"))
    root = m.root()
    assert [store.get(root).hex(), store.get(nodes.links(store.get(root))[0]).hex()] == _parts("pdt_text_spill")
    read = PMap.load(store, cids.of(_hex("pdt_text_spill")))
    assert str(read.get("doc")) == "x" * 1100 and read.get("note").leaf() == _text_runs()


@_covers("pdt_text_replica")
def test_the_replica_of_the_golden_writer_is_the_first_five_bytes_of_its_sha256_in_base32():
    writer, replica = _parts("pdt_text_replica")
    assert text.replica_of(writer) == replica


# ------------------------------------------------------------------ PDT 2 phase 7: group R

@_covers("pdt_rr_splice")
def test_the_spliced_vector_reads_through_its_size_tables_and_packs_to_its_vr_root():
    """PDT 2 phase 7, P2-R-03 and P2-R-04: the elements 0..1099 with -1 inserted before index 500, as a relaxed tree
    two levels deep. Python reads every element by index and in order, and its packed form has Java's root."""
    root, packed, *node_hex = _parts("pdt_rr_splice")
    store = NodeStore()
    for h in node_hex:
        store.put(bytes.fromhex(h))
    assert cids.of(bytes.fromhex(node_hex[0])) == root and nodes.kind_of(bytes.fromhex(node_hex[0])) == nodes.KIND_RR
    v = PVector.load(store, root)
    expected = list(range(500)) + [-1] + list(range(500, 1100))
    assert v.count() == 1101 and v.relaxed() and list(v) == expected
    assert [v.nth(i) for i in (0, 499, 500, 501, 1100)] == [0, 499, -1, 500, 1099]
    assert v.packed().root() == packed
    assert PVector.empty(NodeStore()).conj_many(expected).root() == packed
