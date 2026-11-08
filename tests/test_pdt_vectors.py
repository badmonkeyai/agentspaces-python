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
"""The persistent-tree golden vectors (srad/agentspaces-pdt.md PD-N-07, PD-O-02,
PD-C-04): every ``pdt_*`` and ``content_*`` tree vector of golden.json, produced
by the Java build, reproduced byte for byte by the Python port, decoded by kind,
and round-tripped."""

import hashlib
import json
import pathlib

import pytest

from agentspaces import cbor
from agentspaces.capabilities import content as swarm
from agentspaces.pdt import NodeStore, PBlob, PMap, PVector, Raw, cids, fastcdc, nodes
from agentspaces.pdt import refs, tree
from agentspaces.pdt.champ import ChampNode
from agentspaces.pdt.vector import VecRoot

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())


def _hex(name):
    return bytes.fromhex(GOLDEN[name])


def java_random_bytes(seed: int, n: int) -> bytes:
    """``new java.util.Random(seed).nextBytes(new byte[n])``: the 48-bit LCG and the
    little-endian byte order of ``nextBytes``."""
    mask = (1 << 48) - 1
    s = (seed ^ 0x5DEECE66D) & mask
    out = bytearray(n)
    i = 0
    while i < n:
        s = (s * 0x5DEECE66D + 0xB) & mask
        rnd = s >> 16
        for _ in range(min(4, n - i)):
            out[i] = rnd & 0xFF
            rnd >>= 8
            i += 1
    return bytes(out)


def _deep_map(store):
    m = PMap.empty(store)
    for i in range(100):
        m = m.assoc(f"k{i}", i)
    return m


# ------------------------------------------------------------------ maps

def test_the_map_vectors_encode_byte_for_byte_and_decode_by_kind():
    store = NodeStore()
    empty = PMap.empty(store)
    assert store.get(empty.root()) == _hex("pdt_map_empty")
    small = PMap.empty(store).assoc("a", 1).assoc("b", "two")
    assert store.get(small.root()) == _hex("pdt_map_small")
    assert _hex("pdt_node_dagcbor") == _hex("pdt_map_small")
    deep = _deep_map(store)
    assert store.get(deep.root()) == _hex("pdt_map_deep")
    for name, root in (("pdt_map_empty", empty.root()), ("pdt_map_small", small.root()), ("pdt_map_deep", deep.root())):
        data = _hex(name)
        node = nodes.decode(data, root)
        assert node["k"] == "m" and "cnt" in node
        assert nodes.encode(node) == data                       # round trip through the codec
        assert ChampNode.load_root(root, data).cnt == node["cnt"]
        assert cids.of(data) == root
    assert nodes.decode(_hex("pdt_map_deep"))["cnt"] == 100
    assert len(nodes.links(_hex("pdt_map_deep"))) > 0
    # the vector decodes into a map the port reads back
    reread = PMap.load(store, deep.root())
    assert reread.count() == 100 and reread.get("k42") == 42
    assert sorted(reread.keys()) == sorted(f"k{i}" for i in range(100))


def test_the_embedded_node_vector_keeps_the_java_forms_of_a_map_and_a_float():
    store = NodeStore()
    m = PMap.empty(store).assoc("rec", {"x": 1, "y": "two"}).assoc("f", Raw(bytes.fromhex("fa3fc00000")))
    assert store.get(m.root()) == _hex("pdt_node_embedded")
    node = nodes.decode(_hex("pdt_node_embedded"))
    items = [e.bytes for e in node["e"]]
    assert bytes.fromhex("bf61780161796374776fff") in items     # the indefinite-length map CborCodec writes
    assert bytes.fromhex("fa3fc00000") in items                 # the 32-bit float
    assert nodes.encode(node) == _hex("pdt_node_embedded")
    assert m.get("rec") == {"x": 1, "y": "two"} and m.get("f") == 1.5


# ------------------------------------------------------------------ vectors

def test_the_vector_vectors_encode_byte_for_byte_and_decode():
    store = NodeStore()
    tail = PVector.empty(store).conj_many(range(10))
    assert store.get(tail.root()) == _hex("pdt_vector_tail")
    deep = PVector.empty(store).conj_many(range(1100))
    assert store.get(deep.root()) == _hex("pdt_vector_deep")
    for name, root in (("pdt_vector_tail", tail.root()), ("pdt_vector_deep", deep.root())):
        data = _hex(name)
        node = nodes.decode(data, root)
        assert node["k"] == "vr"
        assert nodes.encode(node) == data
        assert VecRoot.decode(root, data).n == node["n"]
    t = nodes.decode(_hex("pdt_vector_tail"))
    assert t["n"] == 10 and t["s"] == 5 and t["r"] is None and len(t["t"]) == 10
    d = nodes.decode(_hex("pdt_vector_deep"))
    assert d["n"] == 1100 and d["s"] == 10 and d["r"] is not None and len(d["t"]) == 1100 - 1088
    reread = PVector.load(store, deep.root())
    assert reread.count() == 1100 and reread.nth(1057) == 1057 and list(reread)[:3] == [0, 1, 2]


# ------------------------------------------------------------------ blobs

def test_the_small_blob_vector_names_the_root_and_every_chunk():
    store = NodeStore()
    blob = PBlob.of(java_random_bytes(42, 100 * 1024), store)
    expected = GOLDEN["pdt_blob_small"].split(",")
    assert blob.root() == expected[0]
    assert [c.cid for c in blob.chunks()] == expected[1:]
    assert cids.codec_of(blob.root()) == cids.DAG_CBOR
    assert all(cids.codec_of(c) == cids.RAW for c in expected[1:])
    node = nodes.decode(store.get(blob.root()), blob.root())
    assert node["k"] == "b" and node["h"] == 1 and sum(node["z"]) == 100 * 1024
    assert PBlob.load(store, blob.root()).read_all() == java_random_bytes(42, 100 * 1024)


def test_the_fastcdc_cuts_vector_is_cut_at_the_same_offsets():
    data = java_random_bytes(42, 8 * 1024 * 1024)
    cuts = fastcdc.cuts(data)
    assert ",".join(str(c) for c in cuts[:20]) == GOLDEN["pdt_fastcdc_cuts"]
    assert cuts[-1] == len(data)
    assert fastcdc.GEAR[0] == 0x6E340B9CFFB37A98 and fastcdc.GEAR[255] == 0xA8100AE6AA1940D0
    assert all(fastcdc.MIN_SIZE <= b - a <= fastcdc.MAX_SIZE for a, b in zip([0] + cuts[:-1], cuts[:-1]))
    # the streaming chunker agrees with the array chunker
    import io
    streamed = list(fastcdc.chunks(io.BytesIO(data[:1_500_000])))
    assert [len(c) for c in streamed] == [b - a for a, b in zip([0] + fastcdc.cuts(data[:1_500_000])[:-1],
                                                                 fastcdc.cuts(data[:1_500_000]))]


# ------------------------------------------------------------------ refs

def test_the_ref_vectors_round_trip_through_the_record_helpers():
    store = NodeStore()
    deep = _deep_map(store)
    deep_root = deep.root()
    deep_node = store.get(deep_root)
    first_child = nodes.links(deep_node, deep_root)[0]
    small_root = PMap.empty(store).assoc("a", 1).assoc("b", "two").root()
    record = refs.pref_record("facts", "map", deep_root, [small_root], 2, 100, [deep_node, store.get(first_child)],
                              "multi", "none", 3, {"origin": "golden"})
    assert cbor.dumps(record) == _hex("pdt_ref_cbor")
    assert refs.pref_violation(record) is None
    decoded = cbor.loads(_hex("pdt_ref_cbor"))
    assert refs.pref_violation(decoded) is None
    assert refs.PRef.of(decoded).record() == record
    assert cbor.dumps(refs.PRef.of(decoded).record()) == _hex("pdt_ref_cbor")
    assert refs.pref_tags(decoded) == {"name": "facts", "root": deep_root}
    assert refs.inline_bytes(decoded) == len(deep_node) + len(store.get(first_child))
    minimal = refs.pref_record("facts", "map", PMap.empty(store).root(), [], 1, 0)
    assert cbor.dumps(minimal) == _hex("pdt_ref_min_cbor")
    decoded_min = cbor.loads(_hex("pdt_ref_min_cbor"))
    assert "nodes" not in decoded_min and "keyEpoch" not in decoded_min and "attrs" not in decoded_min
    assert refs.pref_violation(decoded_min) is None
    # the bounds
    assert refs.pref_violation(dict(decoded_min, root="not-a-cid")) == "root is not a CID"
    assert refs.pref_violation(dict(decoded_min, seq=refs.MAX_SEQ + 1)).startswith("seq above")
    assert refs.pref_violation(dict(decoded_min, base=[deep_root] * 9)) == "more than 8 bases"
    assert refs.pref_violation(dict(decoded_min, kind="tuple")) == "unknown kind tuple"
    assert refs.pref_violation(dict(decoded_min, mode="x" * 33)) == "mode longer than 32 bytes"
    assert refs.pref_violation(dict(decoded_min, mode="later")) is None   # an open set


# ------------------------------------------------------------------ messages

def test_the_tree_message_vectors_encode_byte_for_byte():
    want = cbor.loads(_hex("content_node_want_cbor"))
    assert cbor.dumps(tree.node_want(want["req"], want["cids"])) == _hex("content_node_want_cbor")
    assert tree.violation(want) is None
    answer = cbor.loads(_hex("content_nodes_cbor"))
    assert cbor.dumps(tree.nodes_message(answer["req"], answer["nodes"], None, None, answer["missing"])) \
        == _hex("content_nodes_cbor")
    assert answer["sealed"] is None and answer["epoch"] is None
    assert tree.violation(answer) is None
    tw = cbor.loads(_hex("content_tree_want_cbor"))
    assert cbor.dumps(tree.tree_want(tw["req"], tw["root"], tw["haves"], tw["budget"])) == _hex("content_tree_want_cbor")
    assert tw["budget"] == tree.MAX_TREE_BUDGET and tw["sketch"] is None
    assert tree.violation(tw) is None
    te = cbor.loads(_hex("content_tree_end_cbor"))
    assert cbor.dumps(tree.tree_end(te["req"], te["frontier"], te["reason"])) == _hex("content_tree_end_cbor")
    assert te["reason"] == tree.END_BUDGET
    assert tree.violation(te) is None
    # bounds (PD-X-02)
    assert tree.violation(dict(want, cids=[])) is not None
    assert tree.violation(dict(want, cids=want["cids"] * 200)) is not None
    assert tree.violation(dict(tw, budget=0)) is not None
    assert tree.violation(dict(tw, haves=tw["haves"] * 65)) is not None
    assert tree.violation(dict(te, reason=9)) is not None
    assert tree.violation(dict(answer, nodes=None)) is not None
    assert cbor.dumps(swarm.reject(tw["root"], tree.TREE_INDEX, swarm.REASON_POLICY))[:10]


def test_the_tree_layout_manifest_vector_decodes_and_reencodes():
    m = cbor.loads(_hex("content_manifest_tree_cbor"))
    assert m["layout"] == "tree"
    assert cids.codec_of(m["root"]) == cids.DAG_CBOR
    assert cbor.dumps(m) == _hex("content_manifest_tree_cbor")
    assert _hex("content_manifest_tree_cbor").hex().endswith("666c61796f75746474726565ff")


def test_cids_parse_and_refuse_by_name():
    root = GOLDEN["pdt_blob_small"].split(",")[0]
    parsed = cids.parse(root)
    assert parsed.codec == cids.DAG_CBOR and len(parsed.digest) == 32
    assert cids.from_binary(cids.binary(root)) == root
    assert cids.is_cid(root) and not cids.is_cid(root[:-1]) and not cids.is_cid("z" + root[1:])
    bad_codec = "b" + cids.base32_lower(bytes([0x01, 0x70, 0x12, 0x20]) + parsed.digest)
    try:
        cids.parse(bad_codec)
        assert False, "an unknown codec is refused"
    except ValueError as e:
        assert "unknown codec" in str(e)
    bad_hash = "b" + cids.base32_lower(bytes([0x01, 0x71, 0x1E, 0x20]) + parsed.digest)
    try:
        cids.parse(bad_hash)
        assert False, "an unknown multihash is refused"
    except ValueError as e:
        assert "multihash" in str(e)


def test_the_sealed_node_vector_walks_as_an_envelope_and_opens_under_the_test_key():
    """PD-P-05 (srad/agentspaces-pdt.md 10.2, SPEC annex H): ``pdt_sealed_node`` is the ``sn``
    envelope of ``pdt_map_small``'s root under the test key 0x00..0x1f at epoch 3. The
    envelope decodes with its links in the clear (what a keyless holder walks), its nonce
    is the keyed digest HMAC-SHA256(node key, plaintext)[:12] (so the nonce in the clear
    confirms no guess without the key), and AES-256-GCM-SIV opens it under the HKDF key."""
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    sealed = _hex("pdt_sealed_node")
    plain = _hex("pdt_map_small")
    node = nodes.decode(sealed)
    assert node["k"] == nodes.KIND_SN
    assert node["ep"] == 3
    assert node["ln"] == []
    assert len(node["nc"]) == 12
    assert len(node["ct"]) == len(plain) + 16
    assert nodes.links(sealed) == []
    assert nodes.encode(node) == sealed
    assert nodes.kind_of(sealed) == nodes.KIND_SN
    node_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"aspace:pdt:node").derive(bytes(range(32)))
    mac = hmac.HMAC(node_key, hashes.SHA256())
    mac.update(plain)
    assert node["nc"] == mac.finalize()[:12]
    assert node["nc"] != hashlib.sha256(plain).digest()[:12], "the nonce is keyed, not the bare digest"
    opened = AESGCMSIV(node_key).decrypt(node["nc"], node["ct"], b"aspace:pdt:node|3")
    assert opened == plain
    with pytest.raises(Exception):
        AESGCMSIV(node_key).decrypt(node["nc"], node["ct"], b"aspace:pdt:node|4")
    # a sealed envelope may pass the 1 MiB bound by its tag, nonce, and links; every other kind may not
    assert nodes.MAX_SEALED_NODE_BYTES == 1024 * 1024 + 48 * 1024
    with pytest.raises(nodes.NodeFormatError):
        nodes.decode(bytes.fromhex("a1616b6173"))  # reserved kind s
    with pytest.raises(nodes.NodeFormatError):
        nodes.decode(bytes.fromhex("a1616b627272"))  # reserved kind rr
