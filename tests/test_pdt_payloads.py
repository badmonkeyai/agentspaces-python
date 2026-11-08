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
"""Escalated space payloads as trees (srad/agentspaces-pdt.md group E, PD-E-01 to
PD-E-03, PD-C-04): the Python ``write_payload`` and ``read_payload`` mirror the Java
``PayloadTree`` byte for byte (the roots below were printed by the Java build over
the same payload bytes), the peer routes a dag-cbor ``payloadRef`` to the facade and a
raw one to the content swarm, and pending recordless states stay bounded (PD-L-02)."""

import time
from types import SimpleNamespace

import pytest

from agentspaces import peer as peer_module
from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.pdt import NodeStore, cids, nodes
from agentspaces.pdt.values import Ctx, StoreLoader, read_payload, write_payload
from agentspaces.peer import Peer


def _head(major: int, n: int) -> bytes:
    m = major << 5
    if n < 24:
        return bytes([m | n])
    if n < 256:
        return bytes([m | 24, n])
    if n < 65536:
        return bytes([m | 25]) + n.to_bytes(2, "big")
    return bytes([m | 26]) + n.to_bytes(4, "big")


def _text(s: str) -> bytes:
    b = s.encode("utf-8")
    return _head(3, len(b)) + b


def _bytes(b: bytes) -> bytes:
    return _head(2, len(b)) + b


def _uint(n: int) -> bytes:
    return _head(0, n)


def _imap(entries) -> bytes:
    return b"\xbf" + b"".join(k + v for k, v in entries) + b"\xff"


def _array(items) -> bytes:
    return _head(4, len(items)) + b"".join(items)


def _seeded(n: int, seed: int) -> bytes:
    out = bytearray(n)
    x = seed
    for i in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = x >> 56
    return bytes(out)


# The Java roots (PayloadTree.write over these exact bytes, 2026-11-08) and the root kinds.
JAVA_ROOTS = {
    "small": ("bafyreifdj6bnlsvnuvib4x4p4vgirarvrisn3plvlyomyugqfyeicfkltq", "x"),
    "map-canonical": ("bafyreifzgezfiu7ndlurbsev4uxyu2u7whvoyuq3zx2sew2wpo2wnpww2q", "m"),
    "map-ordered": ("bafyreibtfzos5dom6344mc7sbfl5sr7si7kbgenuyot5bhkujylizsp6qe", "x"),
    "array": ("bafyreiarn7mcsbtu7syoxfeakjizgezl7g6ud54ugzmm5o5plrtfcgoybu", "vr"),
    "bytes-300k": ("bafyreihjqlkrs6dzaqqvx7ykotng7y3xretlvnzvdl4wmcdsae5ldqzfae", "b"),
    "bytes-20k": ("bafyreifqxcwx5mht4xy27i65viihmrqjkkdizac4dbb4kuxuht7uwiln6y", "x"),
    "nested": ("bafyreibpy5wseon2rhp22favy6doyeffb2ntzifauhyc254demoil3x7ge", "m"),
}


def payloads() -> dict[str, bytes]:
    canon = [(_text(f"k{i:04d}"), _uint(i)) for i in range(3000)]
    return {
        "small": _imap([(_text("a"), _uint(1)), (_text("b"), _text("two"))]),
        "map-canonical": _imap(canon),
        "map-ordered": _imap(list(reversed(canon))),
        "array": _array([_text(f"item-{i}") for i in range(2000)]),
        "bytes-300k": _bytes(_seeded(300_000, 7)),
        "bytes-20k": _bytes(_seeded(20_000, 11)),
        "nested": _imap([(_text("blob"), _bytes(_seeded(100_000, 3))), (_text("list"), _array([_uint(i) for i in range(5000)]))]),
    }


def test_payload_trees_match_the_java_roots_and_round_trip():
    for name, item in payloads().items():
        store = NodeStore()
        root, written = write_payload(item, store)
        expected_root, expected_kind = JAVA_ROOTS[name]
        assert root == expected_root, name
        assert nodes.kind_of(store.get(root)) == expected_kind, name
        assert cids.codec_of(root) == cids.DAG_CBOR
        assert store.complete(root), name
        assert read_payload(root, Ctx(StoreLoader(store), store)) == item, name


def test_an_ordered_map_keeps_its_written_order_and_a_canonical_one_becomes_a_champ():
    store = NodeStore()
    ordered_root, _ = write_payload(payloads()["map-ordered"], store)
    canonical_root, _ = write_payload(payloads()["map-canonical"], store)
    assert ordered_root != canonical_root
    x = nodes.decode(store.get(ordered_root), ordered_root)
    assert x["k"] == "x" and nodes.is_link_shaped(x["v"].bytes)
    inner = nodes.link_cid(x["v"].bytes)
    assert nodes.kind_of(store.get(inner)) == "vr"


def test_a_text_above_the_node_bound_is_refused_as_in_java():
    with pytest.raises(ValueError, match="1048569"):
        write_payload(_text("x" * (2 * 1024 * 1024)), NodeStore())
    with pytest.raises(ValueError):
        write_payload(b"", NodeStore())


def test_the_peer_routes_a_tree_root_to_the_facade_and_a_raw_root_to_the_swarm():
    peer = Peer(Identity.generate(), group_id_from_founding(b"pdt-payloads-test"))
    store = NodeStore()
    item = payloads()["array"]
    root, _ = write_payload(item, store)
    raw_root = cids.of(b"pieces", cids.RAW)
    asked = []
    peer.content = SimpleNamespace(local=lambda r: b"flat" if r == raw_root else None, ensure=asked.append)
    # no facade: a tree root is invisible and never sent to the flat seam
    assert peer.payload_of({"record": {"payloadRef": root}}) is None
    assert asked == []
    assert peer.payload_of({"record": {"payloadRef": raw_root}}) == b"flat"
    fetched = []
    peer.pdt = SimpleNamespace(payload=lambda r: (fetched.append(r) or read_payload(r, Ctx(StoreLoader(store), store))))
    assert peer.payload_of({"record": {"payloadRef": root}}) == item
    assert fetched == [root]
    assert asked == []
    assert peer.payload_of({"record": {"payload": b"\x01"}}) == b"\x01"
    assert peer.payload_of({"record": {}}) == b"\xf6"


def test_pending_recordless_states_are_bounded_and_age_out():
    peer = Peer(Identity.generate(), group_id_from_founding(b"pdt-payloads-test"))
    for i in range(2000):
        peer._fold_recordless({"entryId": f"e-{i}", "leaseStamp": {"physical": 1, "logical": 0, "node": "n"}})
    assert len(peer.pending_states) == peer_module.MAX_PENDING_STATES == 1024
    assert "e-0" not in peer.pending_states and "e-1999" in peer.pending_states
    # the TTL: a state older than ten minutes is dropped when the next one arrives
    peer._pending_since = {k: time.monotonic() - peer_module.PENDING_STATE_TTL_S - 1 for k in peer.pending_states}
    peer._fold_recordless({"entryId": "fresh", "leaseStamp": {"physical": 1, "logical": 0, "node": "n"}})
    assert set(peer.pending_states) == {"fresh"}
