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
"""The content swarm and relay paths in Python (SPEC v0.1.23 §5.4, §7.1, §8,
annex G): the golden vectors byte for byte, a swarm over the in-memory fleet,
a file store that resumes, a space that escalates a large payload to an
artifact and a mid-sized one to a block, and the dial-only relay rule."""

import hashlib
import json
import pathlib
from dataclasses import dataclass

from agentspaces import cbor, wire
from agentspaces.capabilities import Content, FileStore, MemoryStore, Pipes
from agentspaces.capabilities import content as c
from agentspaces.identity import Identity
from agentspaces.peer import Peer
from agentspaces.space import Space, Template, entry
from fleet import Network, NetPeer

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPythonContent"
PIECE = 64 * 1024


def _hex(name):
    return bytes.fromhex(GOLDEN[name])


def _piece_table(pieces, piece_size, last_length):
    table = bytearray()
    for i in range(pieces):
        table += hashlib.sha256(bytes([i + 1]) * (last_length if i == pieces - 1 else piece_size)).digest()
    return bytes(table)


# ------------------------------------------------------------------ vectors

def test_records_and_messages_match_the_java_golden_vectors():
    identity = Identity.from_pkcs8(_hex("private_key_pkcs8"))
    me = identity.peer_id
    table = _piece_table(3, PIECE, 100)
    root = c.content_root(table)
    assert root == GOLDEN["content_root_cidv1"]
    assert root.startswith("bafkrei") and len(root) == 59
    inline = c.manifest(root, 2 * PIECE + 100, PIECE, table, me, 1735689600000, name="golden.bin",
                        media_type="application/octet-stream", attrs={"run": "42"})
    assert cbor.dumps(inline) == _hex("content_manifest_inline_cbor")
    assert c.manifest_violation(inline) is None
    assert c.manifest_violation(cbor.loads(_hex("content_manifest_inline_cbor"))) is None
    big = _piece_table(65, PIECE, PIECE)
    table_ref = wire.block_cid(big)
    referenced = c.manifest(c.content_root(big), 65 * PIECE, PIECE, None, me, 1735689600000,
                            table_ref=table_ref, sealing=c.SEALING_GROUP_KEY, key_epoch=3)
    assert cbor.dumps(referenced) == _hex("content_manifest_tableref_cbor")
    partial = c.holding(root, me, {0, 2}, 3, via=["zB"])
    assert partial["have"] == b"\x00\x01\x01\x01" and partial["count"] == 2
    assert cbor.dumps(partial) == _hex("content_holding_partial_cbor")
    assert c.decode_have(b"\x00\x01\x01\x01", 3) == {0, 2}
    assert cbor.dumps(c.holding(root, me, {0, 1, 2}, 3)) == _hex("content_holding_complete_cbor")
    assert c.decode_have(None, 3) == {0, 1, 2}
    assert cbor.dumps(c.piece_want(root, 2, PIECE, PIECE, 42)) == _hex("content_piece_want_cbor")
    assert cbor.dumps(c.piece(root, 2, PIECE, bytes(range(16)), 42)) == _hex("content_piece_cbor")
    assert cbor.dumps(c.have_message(root, b"\x00\x01\x01\x01", False)) == _hex("content_have_cbor")
    assert cbor.dumps(c.cancel(root, 2, 42)) == _hex("content_cancel_cbor")
    assert cbor.dumps(c.reject(root, 2, c.REASON_OVER_BUDGET)) == _hex("content_reject_cbor")
    assert cbor.dumps(c.manifest_want(root)) == _hex("content_manifest_want_cbor")
    assert cbor.dumps(c.manifest_reply(root, cbor.dumps(inline))) == _hex("content_manifest_cbor")


def test_relay_bodies_and_the_via_hint_match_java():
    identity = Identity.from_pkcs8(_hex("private_key_pkcs8"))
    inner = _hex("ping_frame_cbor")
    assert wire.relay_frame_body("zB", inner) == _hex("relay_frame_body_cbor")
    assert wire.relay_frame_body("zB", inner, ["zR1", "zR2"], 0) == _hex("relay_frame_with_path_cbor")
    assert wire.relay_signal_body("zB", "zR2", "unreachable") == _hex("relay_signal_unreachable_cbor")
    ad = wire.peer_advertisement(GOLDEN["group_id"], identity, "2026-01-01T00:00:00Z",
                                 resource_hints={"relay.via": "zR1,zR2"})
    assert cbor.dumps(ad) == _hex("peer_ad_with_via_hint_cbor")


def test_have_runs_round_trip_at_every_size():
    for pieces, have in [(1, set()), (1, {0}), (7, {1, 2, 5}), (300, set(range(0, 300, 3))), (1000, {999})]:
        assert c.decode_have(c.encode_have(have, pieces), pieces) == have


# -------------------------------------------------------------------- swarm

def _node(network, store=None, **options):
    peer = NetPeer(network, GROUP)
    space = Space(peer, "content")
    content = Content(Pipes(peer), space, store or MemoryStore(), **options)
    return peer, space, content


def _fleet(n, **options):
    network = Network()
    nodes = [_node(network, **options) for _ in range(n)]
    for peer, _space, _content in nodes:
        peer.introduce()
    return nodes


def _run(nodes, rounds=20):
    for _ in range(rounds):
        for _peer, _space, content in nodes:
            content.tick()


def test_two_peers_fetch_a_published_artifact_from_the_publisher_and_each_other():
    nodes = _fleet(3, piece_size=PIECE, seed=7)
    (_pa, _sa, publisher), (_pb, _sb, b), (_pc, _sc, cc) = nodes
    data = bytes((i * 31 + 7) & 0xFF for i in range(2 * PIECE + 100))
    manifest = publisher.publish(data, name="checkpoint.bin")
    assert manifest["pieces"] == 3 and manifest["table"] is not None
    assert b.describe(manifest["root"])["completeHolders"] == 1
    fb = b.fetch(manifest["root"])
    fc = cc.fetch(manifest["root"])
    _run(nodes)
    assert fb.wait(5) and fc.wait(5), (fb.trace, fc.trace)
    assert fb.read_bytes() == data and fc.read_bytes() == data
    assert fb.progress()["piecesVerified"] == 3
    assert publisher.bytes_served > 0
    _run(nodes, 2)
    assert b.describe(manifest["root"])["completeHolders"] == 3
    assert [m["root"] for m in cc.list_manifests()] == [manifest["root"]]
    assert b.fetch(manifest["root"]).complete  # already held: complete at once


def test_a_file_store_resumes_what_it_holds_and_a_holder_republishes(tmp_path):
    network = Network()
    _pa, _sa, publisher = _node(network, FileStore(tmp_path / "a"), piece_size=PIECE)
    pb, _sb, b = _node(network, FileStore(tmp_path / "b"), piece_size=PIECE)
    pb.introduce()
    data = bytes(range(256)) * (PIECE // 256) * 2 + b"tail"
    manifest = publisher.publish(data)
    assert b.fetch(manifest["root"]).wait(5)
    assert (tmp_path / "b").iterdir()
    reopened = FileStore(tmp_path / "b")
    assert reopened.roots() == {manifest["root"]}
    assert reopened.have(manifest["root"]) == {0, 1, 2}
    assert reopened.read_all(manifest["root"]) == data
    assert reopened.read(manifest["root"], 2, 0, 4) == b"tail"
    # a late member learns the root only from a holding: the holder restarts over its
    # store, republishes, and answers the newcomer's MANIFEST_WANT before the pieces
    _pc, _sc, late = _node(network, MemoryStore(), piece_size=PIECE)
    _pb2, _sb2, b2 = _node(network, reopened, piece_size=PIECE)
    assert [h["holder"] for h in late.holdings(manifest["root"])] == [_pb2.identity.peer_id]
    assert late.manifest_of(manifest["root"]) is None
    fetched = late.fetch(manifest["root"])
    _run([(None, None, late), (None, None, b2)])
    assert fetched.wait(5), fetched.trace
    assert fetched.read_bytes() == data
    assert fetched.progress()["bytesBySource"] == {_pb2.identity.peer_id: len(data)}


@entry("com.acme.Blob#v1")
@dataclass
class Blob:
    name: str
    data: bytes


def test_a_space_escalates_large_payloads_to_artifacts_and_mid_sized_ones_to_blocks():
    nodes = _fleet(2, piece_size=PIECE, escalate_above=1024 * 1024)
    (pa, sa, _ca), (pb, sb, _cb) = nodes
    big = bytes((i * 7) & 0xFF for i in range(1024 * 1024 + 5))
    sa.write(Blob("big", big))
    mid = b"m" * (100 * 1024)
    sa.write(Blob("mid", mid))
    refs = sorted((d["record"]["payloadRef"] or "")[0] for d in pb.states.values()
                  if d["record"]["type"] == "com.acme.Blob#v1")
    assert refs == ["b", "z"]
    found = {}
    for _ in range(10):
        for e in sb.read_all(Template(Blob)):
            found[e.name] = e.data
        if len(found) == 2:
            break
        _run(nodes, 2)
    assert found == {"big": big, "mid": mid}
    assert pb.blocks and all(ref.startswith("z") for ref in pb.blocks)
    assert sa.read_all(Template(Blob, where={"name": "big"}))[0].data == big


# ------------------------------------------------------------------- relays

class CapturePeer(Peer):
    def __init__(self):
        super().__init__(Identity.generate(), GROUP)
        self.sent = []
        self._running = True
        self._socket = object()

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body, to))


def test_a_dial_only_peer_sends_through_its_seed_and_unwraps_what_the_seed_carries():
    me = CapturePeer()
    me._seed = ("seed", 1)
    seed = Identity.generate()
    origin = Identity.generate()
    now = me._now_ms()
    ack = wire.envelope(GROUP, "ACK", seed.peer_id, wire.hlc_now(seed.peer_id, now), wire.ack_body(1),
                        me.identity.peer_id)
    me._handle(ack)
    assert me.seed_peer == seed.peer_id
    assert me.resource_hints["relay.via"] == seed.peer_id
    assert me.sent[-1][0] == "RUMOR"  # re-introduced with the hint
    me.sent.clear()
    me.send_pipe(seed.peer_id, "aspace:cap/x", b"direct")
    assert me.sent[-1][0] == "PIPE_DATA" and me.sent[-1][2] == seed.peer_id
    me.send_pipe(origin.peer_id, "aspace:cap/x", b"carried")
    kind, body, to = me.sent[-1]
    assert kind == "RELAY_FRAME" and to == seed.peer_id
    relayed = cbor.loads(body)
    assert relayed["target"] == origin.peer_id and "path" not in relayed
    inner = wire.decode_frame(relayed["frame"])
    assert inner["kind"] == "PIPE_DATA" and inner["to"] == origin.peer_id
    me.send_pipe(origin.peer_id, "aspace:cap/x", b"far", via=["zFar"])
    relayed = cbor.loads(me.sent[-1][1])
    assert relayed["path"] == [seed.peer_id, "zFar"] and relayed["hop"] == 0
    got = []
    me.pipe_handlers["aspace:cap/x"] = lambda sender, payload: got.append((sender, payload))
    inner_env = wire.envelope(GROUP, "PIPE_DATA", origin.peer_id, wire.hlc_now(origin.peer_id, now),
                              cbor.dumps({"capability": "aspace:cap/x", "payload": b"hello"}), me.identity.peer_id)
    carried = wire.envelope(GROUP, "RELAY_FRAME", seed.peer_id, wire.hlc_now(seed.peer_id, now + 1),
                            wire.relay_frame_body(me.identity.peer_id, wire.encode_frame(inner_env, origin)),
                            me.identity.peer_id)
    me._handle(carried)
    assert got == [(origin.peer_id, b"hello")]
    assert origin.peer_id not in me.reachable and seed.peer_id in me.reachable
    signal = wire.envelope(GROUP, "PIPE_DATA", seed.peer_id, wire.hlc_now(seed.peer_id, now + 2),
                           wire.relay_signal_body(origin.peer_id, "zFar"), me.identity.peer_id)
    me._handle(signal)
    assert me.relay_signals[-1]["failedHop"] == "zFar"
