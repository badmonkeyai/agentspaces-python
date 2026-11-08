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
"""The persistent values in Python (srad/agentspaces-pdt.md PD-V-01 to
PD-V-04, PD-V-07, PD-V-09, PD-B-03, PD-N-05, PD-S-01): the canonical layout
property over 2,000 random orders, the vector tail rules, spills, the store
walks, and the blob insert cost at 8 MiB."""

import random
import statistics
import time

from agentspaces.pdt import NodeStore, PBlob, PMap, PSet, PVector, cids, nodes
from agentspaces.pdt import fastcdc
from agentspaces.pdt.values import Raw


# ------------------------------------------------------------------ canonical layout (PD-V-01)

def test_a_map_reached_in_two_thousand_random_orders_has_one_root():
    rnd = random.Random(2026)
    store = NodeStore()
    keys = [f"key-{i}" for i in range(300)]
    reference = PMap.empty(store)
    for k in keys:
        reference = reference.assoc(k, len(k))
    expected = reference.root()
    seen_depths = set()
    for case in range(2000):
        order = list(keys)
        rnd.shuffle(order)
        m = PMap.empty(store)
        # a random prefix of extra keys that are removed again, so removals compact the trie
        extra = [f"extra-{case}-{j}" for j in range(rnd.randrange(0, 6))]
        for k in order[:150] + extra:
            m = m.assoc(k, len(k))
        for k in extra:
            m = m.dissoc(k)
        for k in order[150:]:
            m = m.assoc(k, len(k))
        assert m.root() == expected, f"case {case} reached a different root"
        assert m.count() == 300
        seen_depths.add(m.depth())
    assert len(seen_depths) == 1
    # removing everything in a random order returns to the empty root
    m = reference
    order = list(keys)
    rnd.shuffle(order)
    for k in order:
        m = m.dissoc(k)
    assert m.root() == PMap.empty(store).root() and m.count() == 0


def test_a_set_and_a_map_offer_the_verbs_and_never_change_the_receiver():
    store = NodeStore()
    m0 = PMap.empty(store).assoc("a", 1).assoc("b", {"x": [1, 2]})
    m1 = m0.assoc("c", 3)
    assert m0.count() == 2 and m1.count() == 3 and "c" not in m0 and m1.get("c") == 3
    assert m1.dissoc("zzz") is m1                       # a missing key changes nothing
    assert m1.assoc("a", 1) is m1                       # an equal value changes nothing
    m2 = m1.update("a", lambda v: v + 10).update_in(["b", "x", 0], lambda v: v * 5)
    assert m2.get("a") == 11 and m2.get("b") == {"x": [5, 2]}
    assert m2.update_in(["new", "path"], lambda v: "leaf").get("new") == {"path": "leaf"}
    assert sorted(m2.keys()) == ["a", "b", "c"] and dict(m2.items())["c"] == 3
    assert PMap.load(store, m2.root()).to_dict() == m2.to_dict()
    assert m2 == PMap.load(store, m2.root()) and m2 != m1
    s0 = PSet.empty(store).conj("x").conj("y")
    assert s0.contains("x") and not s0.contains("z") and s0.count() == 2
    assert s0.disj("x").to_set() == {"y"} and s0.to_set() == {"x", "y"}
    assert s0.conj("x") is s0
    assert PSet.load(store, s0.root()).to_set() == {"x", "y"}
    # a set's root is the null-valued map's root
    assert s0.root() == PMap.empty(store).assoc_raw(b"ax", b"\xf6").assoc_raw(b"ay", b"\xf6").root()
    try:
        m0.assoc("none", None)
        assert False, "a None value is refused"
    except ValueError:
        pass
    # keys of every CBOR type
    typed = PMap.empty(store).assoc(1, "int").assoc(b"\x01", "bytes").assoc((1, 2), "list").assoc(True, "bool")
    assert typed.get(1) == "int" and typed.get(b"\x01") == "bytes" and typed.get([1, 2]) == "list" and typed.get(True) == "bool"


def test_diff_and_merge3_follow_the_key_wise_rule():
    store = NodeStore()
    base = PMap.empty(store)
    for i in range(500):
        base = base.assoc(f"k{i}", i)
    mine = base.assoc("k1", "mine").assoc("only-mine", 1).dissoc("k2")
    theirs = base.assoc("k1", "theirs").assoc("only-theirs", 2).dissoc("k3").assoc("k4", 4)   # k4 unchanged
    assert mine.diff(base) == {"k1": (1, "mine"), "only-mine": (None, 1), "k2": (2, None)}
    assert theirs.diff(base) == {"k1": (1, "theirs"), "only-theirs": (None, 2), "k3": (3, None)}
    assert base.diff(base) == {}
    decisions = []

    def resolver(key, b, m, t):
        decisions.append((key, b, m, t))
        return t
    merged = mine.merge3(base, theirs, resolver)
    assert decisions == [("k1", 1, "mine", "theirs")]
    assert merged.get("k1") == "theirs" and merged.get("only-mine") == 1 and merged.get("only-theirs") == 2
    assert "k2" not in merged and "k3" not in merged and merged.count() == 500 - 2 + 2
    # the same outcome on both sides needs no decision
    asked = []
    same = mine.assoc("k9", "same").merge3(base, theirs.assoc("k9", "same"), lambda key, b, m, t: asked.append(key) or t)
    assert same.get("k9") == "same" and asked == ["k1"]
    # the merge is deterministic: the other order with the same rule gives the same root when both keep theirs
    merged_back = theirs.merge3(base, mine, lambda key, b, m, t: "theirs" if key == "k1" else t)
    assert merged_back.root() == merged.root()


# ------------------------------------------------------------------ vectors (PD-V-03)

def test_the_vector_tail_rules_write_one_root_until_the_tail_fills():
    store = NodeStore()
    v = PVector.empty(store).conj_many(range(1000))
    v.root()
    store.nodes_written = 0
    v1 = v.conj(1000)
    v1.root()
    assert store.nodes_written == 1                     # the vr root alone: the tail took it
    assert v1.count() == 1001 and v1.nth(1000) == 1000 and v1.peek() == 1000
    store.nodes_written = 0
    v2 = v1.pop()
    assert v2.root() == v.root() and store.nodes_written == 0
    store.nodes_written = 0
    v3 = v.assoc(999, "edited")                          # in the tail: the root alone
    v3.root()
    assert store.nodes_written == 1 and v3.nth(999) == "edited" and v.nth(999) == 999
    store.nodes_written = 0
    v4 = v.assoc(0, "deep")                              # in the trie: shift / 5 + 2 nodes
    v4.root()
    assert store.nodes_written == v4.depth() and v4.nth(0) == "deep"
    v5 = PVector.empty(store).conj_many(range(1024))
    v5.root()
    store.nodes_written = 0
    v5.conj(1024).root()
    assert store.nodes_written == 3                      # the tail pushed into the trie: leaf, path, root
    full = PVector.empty(store).conj_many(range(1056))
    full.root()
    store.nodes_written = 0
    full.conj(1056).root()
    assert store.nodes_written == 4                      # the root overflows: a new level
    popped = full
    for _ in range(1056):
        popped = popped.pop()
    assert popped.root() == PVector.empty(store).root() and popped.count() == 0
    assert full.conj(1056).pop().root() == full.root()
    assert PVector.load(store, full.root()).to_list() == list(range(1056))
    grown = PVector.empty(store)
    for i in range(40_000):
        grown = grown.conj(i)
    assert grown.depth() == 5 and grown.nth(39_999) == 39_999
    other = PVector.empty(store).conj_many(range(40_000))
    assert other.root() == grown.root()


# ------------------------------------------------------------------ spills (PD-N-05)

def test_large_values_spill_into_x_nodes_sub_trees_and_blobs_and_read_back_byte_identical():
    from agentspaces import cbor
    store = NodeStore()
    big_text = "t" * 2000                                   # above 1 KiB: an x node
    big_map = {f"field{i}": f"value number {i}" for i in range(400)}   # above 4 KiB: an m sub-tree
    big_list = list(range(3000))                           # above 4 KiB: a vr sub-tree
    big_bytes = bytes(range(256)) * 100                    # above 4 KiB: a blob
    m = PMap.empty(store).assoc("text", big_text).assoc("map", big_map).assoc("list", big_list).assoc("bytes", big_bytes)
    root = m.root()
    kinds = {}
    for cid in store.reachable(root):
        kinds.setdefault("raw" if cids.codec_of(cid) == cids.RAW else nodes.kind_of(store.get(cid)), 0)
        kinds["raw" if cids.codec_of(cid) == cids.RAW else nodes.kind_of(store.get(cid))] += 1
    assert kinds["x"] >= 1 and kinds["m"] >= 2 and kinds["vr"] == 1 and kinds["raw"] >= 1
    assert m.get_raw(cbor.dumps("map")) == cbor.dumps(big_map)        # byte-identical reassembly
    assert m.get_raw(cbor.dumps("list")) == cbor.dumps(big_list)
    assert m.get_raw(cbor.dumps("bytes")) == cbor.dumps(big_bytes)
    reread = PMap.load(store, root)
    assert reread.get("text") == big_text and reread.get("map") == big_map and reread.get("list") == big_list
    assert reread.get("bytes") == big_bytes
    # editing one nested field of the spilled map adds a short path only
    before = store.count()
    edited = reread.update_in(["map", "field7"], lambda v: "changed")
    edited.root()
    assert 1 <= store.count() - before <= 5
    assert edited.get("map")["field7"] == "changed" and reread.get("map")["field7"] == "value number 7"
    # a bare link item is never a value or a key
    try:
        PMap.empty(store).assoc("k", Raw(nodes.link_item(root)))
        assert False
    except ValueError:
        pass


# ------------------------------------------------------------------ the store (PD-S-01)

def test_the_store_walks_pins_and_collects(tmp_path):
    for store in (NodeStore(), NodeStore(tmp_path / "nodes")):
        m = PMap.empty(store)
        for i in range(400):
            m = m.assoc(f"k{i}", i)
        root = m.root()
        reach = store.reachable(root)
        assert store.complete(root) and not store.missing(root) and len(reach) > 10
        victim = next(c for c in reach if c != root)
        store.remove(victim)
        assert not store.complete(root) and store.missing(root) == {victim}
        store.put_verified(victim, store.get(victim) or _rebuild(store, m, victim))
        assert store.complete(root)
        assert store.pin(root) == 1 and store.pin(root) == 2 and store.unpin(root) == 1
        other = PMap.empty(store).assoc("gone", 1).root()
        removed = store.collect()
        assert removed >= 1 and not store.has(other) and store.complete(root)
        assert store.unpin(root) == 0
        corrupt = next(iter(reach))
        data = store.get(corrupt)
        store.backend.remove(corrupt)
        store.backend.put(corrupt, data + b"x")
        assert store.get(corrupt) is None                 # a block that no longer hashes to its CID reads as absent
    reopened = NodeStore(tmp_path / "nodes")
    assert reopened.count() > 10


def _rebuild(store, m, cid):
    fresh = NodeStore()
    PMap.empty(fresh).assoc_many(list(m.items())).root()
    return fresh.get(cid)


# ------------------------------------------------------------------ blobs (PD-B-03, PD-B-06 at 8 MiB)

def test_blob_inserts_at_eight_mebibytes_cost_about_one_chunk_each():
    rnd = random.Random(42)
    data = bytearray(rnd.randbytes(8 * 1024 * 1024))
    store = NodeStore()
    blob = PBlob.of(bytes(data), store)
    assert blob.size() == len(data) and blob.read(1000, 20) == bytes(data[1000:1020])
    chunk_count = len(blob.chunks())
    assert 20 <= chunk_count <= 200 and blob.tree.height >= 1
    costs, rewritten = [], []
    started = time.monotonic()
    for i in range(40):
        offset = rnd.randrange(0, len(data))
        insert = bytes(rnd.randbytes(100))
        old_chunks = {c.cid for c in blob.chunks()}
        blob = blob.splice(offset, 0, insert)
        data[offset:offset] = insert
        costs.append(blob.written_bytes)
        rewritten.append(sum(1 for c in blob.chunks() if c.cid not in old_chunks))
        assert blob.size() == len(data)
        assert blob.read(max(0, offset - 50), min(len(data), offset + 150) - max(0, offset - 50)) == \
            bytes(data[max(0, offset - 50):min(len(data), offset + 150)])
    elapsed = time.monotonic() - started
    scratch = PBlob.of(bytes(data), NodeStore())
    assert scratch.root() == blob.root()                 # the layout stays canonical after 40 inserts
    median = statistics.median(costs)
    print(f"\nPD-B-06 at 8 MiB, 40 inserts of 100 bytes: median {median:.0f} bytes, mean {statistics.mean(costs):.0f}, "
          f"max {max(costs)}, chunks rewritten per insert {statistics.mean(rewritten):.2f}, "
          f"{sum(1 for r in rewritten if r == 1)} of 40 rewrote exactly one chunk, {elapsed:.2f} s")
    assert median < 160 * 1024 and max(costs) < 1024 * 1024
    assert sum(1 for r in rewritten if r <= 2) >= 36
    # append rewrites the old last chunk and the path above it
    appended = blob.append(b"tail" * 1000)
    assert appended.read(appended.size() - 4, 4) == b"tail"
    assert PBlob.of(bytes(data) + b"tail" * 1000, NodeStore()).root() == appended.root()
    assert appended.written_bytes < 4000 + fastcdc.MAX_SIZE + 8 * 1024
    # a removal and a replacement
    cut = blob.splice(4_000_000, 1000, b"")
    assert cut.size() == len(data) - 1000 and cut.read(4_000_000 - 10, 10) == bytes(data[4_000_000 - 10:4_000_000])
    assert cut.read(4_000_000, 10) == bytes(data[4_001_000:4_001_010])
    assert PBlob.of(bytes(data[:4_000_000] + data[4_001_000:]), NodeStore()).root() == cut.root()


def test_small_blobs_are_single_chunks_and_a_file_chunks_within_a_bounded_buffer(tmp_path):
    store = NodeStore()
    empty = PBlob.of(b"", store)
    assert empty.size() == 0 and empty.root() == cids.of(b"", cids.RAW)
    one = PBlob.of(b"hello", store)
    assert cids.codec_of(one.root()) == cids.RAW and one.read_all() == b"hello"
    path = tmp_path / "data.bin"
    content = random.Random(7).randbytes(700 * 1024)
    path.write_bytes(content)
    from_file = PBlob.of(path, store)
    assert from_file.root() == PBlob.of(content, NodeStore()).root() and from_file.read_all() == content
    assert PBlob.load(store, from_file.root()).read(600 * 1024, 100) == content[600 * 1024:600 * 1024 + 100]
