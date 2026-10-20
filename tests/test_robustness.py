"""ROBUSTNESS.md from the client's side: replayed, stale and far-ahead frames are dropped and
counted; kinds this client does not speak are ignored; a malformed body never stops the reader;
a lost socket is reconnected to the seed and the peer re-introduces itself and re-pulls."""
import socket
import struct
import threading
import time

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.peer import Peer

GROUP = "zPyRobust"


class CapturingPeer(Peer):
    def __init__(self):
        super().__init__(Identity.generate(), GROUP)
        self.sent = []

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body, to))


def frame(sender: Identity, kind: str, body: bytes, to: str, stamp: str) -> dict:
    env = wire.envelope(GROUP, kind, sender.peer_id, stamp, body, to)
    return wire.decode_frame(wire.encode_frame(env, sender))


def stamp(ms: int, logical: int = 0, node: str = "other") -> str:
    return f"{ms}:{logical}:{node}"


def test_a_replayed_frame_is_dropped_and_counted():
    peer = CapturingPeer()
    other = Identity.generate()
    now = peer._now_ms()
    ping = frame(other, "PING", wire.ping_body(7), peer.identity.peer_id, stamp(now, 1))
    peer._handle(ping)
    assert [k for k, _, _ in peer.sent] == ["ACK"]
    peer._handle(ping)
    peer._handle(ping)
    assert [k for k, _, _ in peer.sent] == ["ACK"], "a replayed probe earns no second ACK"
    assert peer.frames.replayed == 2
    # A fresh stamp from the same sender is a new frame.
    peer._handle(frame(other, "PING", wire.ping_body(8), peer.identity.peer_id, stamp(now, 2)))
    assert [k for k, _, _ in peer.sent] == ["ACK", "ACK"]


def test_stale_and_far_ahead_frames_are_dropped_quietly():
    peer = CapturingPeer()
    other = Identity.generate()
    now = peer._now_ms()
    peer._handle(frame(other, "PING", wire.ping_body(1), peer.identity.peer_id,
                       stamp(now - wire.MAX_FRAME_AGE_MILLIS - 1000)))
    peer._handle(frame(other, "PING", wire.ping_body(2), peer.identity.peer_id,
                       stamp(now + wire.MAX_HLC_SKEW_MILLIS + 60_000)))
    assert peer.sent == []
    assert peer.frames.stale == 1 and peer.frames.ahead == 1
    # Within the bounds either way, answered.
    peer._handle(frame(other, "PING", wire.ping_body(3), peer.identity.peer_id,
                       stamp(now - wire.MAX_FRAME_AGE_MILLIS // 2)))
    peer._handle(frame(other, "PING", wire.ping_body(4), peer.identity.peer_id,
                       stamp(now + wire.MAX_HLC_SKEW_MILLIS // 2)))
    assert [k for k, _, _ in peer.sent] == ["ACK", "ACK"]


def test_kinds_this_client_does_not_speak_are_ignored_and_counted():
    peer = CapturingPeer()
    other = Identity.generate()
    now = peer._now_ms()
    for i, kind in enumerate(["HAVE", "GRAFT", "PRUNE", "BATCH", "SESSION_HELLO", "DIGEST", "CHANNEL_HELLO"]):
        peer._handle(frame(other, kind, cbor.dumps({"anything": i}), peer.identity.peer_id, stamp(now, i)))
    assert peer.sent == []
    assert sum(peer.ignored_kinds.values()) == 7
    assert peer.ignored_kinds["HAVE"] == 1
    peer._handle(frame(other, "PING", wire.ping_body(9), peer.identity.peer_id, stamp(now, 99)))
    assert [k for k, _, _ in peer.sent] == ["ACK"], "still answering afterwards"


def test_a_malformed_body_under_a_good_signature_never_stops_the_reader():
    peer = CapturingPeer()
    other = Identity.generate()
    now = peer._now_ms()
    for i, kind in enumerate(["RUMOR", "PULL_RESP", "PING", "PIPE_DATA"]):
        env = frame(other, kind, b"\xff\x01\x02", peer.identity.peer_id, stamp(now, i))
        try:
            peer._handle(env)
        except Exception:  # the reader catches this per frame; it must not corrupt state
            pass
    assert peer.states == {} and peer.claims == {}
    peer._handle(frame(other, "PING", wire.ping_body(5), peer.identity.peer_id, stamp(now, 50)))
    assert [k for k, _, _ in peer.sent] == ["ACK"]


class FakeSeed:
    """Accepts connections, decodes what the peer sends, and can close a connection on demand."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.connections = []
        self.frames = []  # (connection index, kind)
        self.envelopes = []  # every verified envelope, in arrival order
        self.closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed.is_set():
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            index = len(self.connections)
            self.connections.append(conn)
            threading.Thread(target=self._read, args=(conn, index), daemon=True).start()

    def _read(self, conn, index):
        try:
            while True:
                header = conn.recv(4)
                if len(header) < 4:
                    return
                length = struct.unpack(">i", header)[0]
                data = b""
                while len(data) < length:
                    chunk = conn.recv(length - len(data))
                    if not chunk:
                        return
                    data += chunk
                env = wire.decode_frame(data)
                if env is not None:
                    self.frames.append((index, env.get("kind")))
                    self.envelopes.append(env)
        except OSError:
            return

    def close(self):
        self.closed.set()
        self.server.close()
        for c in self.connections:
            try:
                c.close()
            except OSError:
                pass


def test_a_lost_socket_is_reconnected_and_the_peer_reintroduces_and_repulls():
    seed = FakeSeed()
    peer = Peer(Identity.generate(), GROUP)
    peer.reconnect_interval_s = 0.1
    try:
        peer.connect("127.0.0.1", seed.port)
        peer.pull_space("work")
        deadline = time.time() + 5
        while time.time() < deadline and len(seed.frames) < 3:
            time.sleep(0.05)
        assert [k for i, k in seed.frames if i == 0] == ["RUMOR", "DIGEST", "DIGEST"]
        # The seed drops the link: a network hiccup from the peer's point of view.
        seed.connections[0].close()
        deadline = time.time() + 5
        while time.time() < deadline and len([1 for i, _ in seed.frames if i == 1]) < 3:
            time.sleep(0.05)
        second = [k for i, k in seed.frames if i == 1]
        assert second[:3] == ["RUMOR", "DIGEST", "DIGEST"], "re-introduced, revocations and the space pulled again"
        assert peer.reconnects == 1
        assert peer.connected
    finally:
        peer.close()
        seed.close()
    assert not peer._running


def test_close_by_the_owner_is_final():
    seed = FakeSeed()
    peer = Peer(Identity.generate(), GROUP)
    peer.reconnect_interval_s = 0.1
    try:
        peer.connect("127.0.0.1", seed.port)
        time.sleep(0.2)
        peer.close()
        time.sleep(0.5)
        assert len(seed.connections) == 1, "no reconnect after the owner's close"
        assert peer.reconnects == 0
    finally:
        seed.close()


def test_a_seed_that_is_down_is_retried_until_it_listens_again():
    seed = FakeSeed()
    port = seed.port
    peer = Peer(Identity.generate(), GROUP)
    peer.reconnect_interval_s = 0.1
    try:
        peer.connect("127.0.0.1", port)
        deadline = time.time() + 5
        while time.time() < deadline and len(seed.frames) < 2:
            time.sleep(0.05)
        seed.close()
        time.sleep(0.3)  # several refused dials
        assert peer.reconnects == 0
        again = FakeSeed.__new__(FakeSeed)
        again.server = socket.socket()
        again.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        again.server.bind(("127.0.0.1", port))
        again.server.listen(4)
        again.port = port
        again.connections, again.frames, again.envelopes, again.closed = [], [], [], threading.Event()
        threading.Thread(target=again._accept, daemon=True).start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and len(again.frames) < 2:
                time.sleep(0.05)
            assert [k for _, k in again.frames][:2] == ["RUMOR", "DIGEST"], "the peer found the seed again"
            assert peer.reconnects == 1
        finally:
            again.close()
    finally:
        peer.close()
