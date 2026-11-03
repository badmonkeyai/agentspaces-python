"""The tls binding (SPEC §5.5, §5.6): a channel certificate the identity key endorses, a
TLS 1.3 dial that attests the seed from the certificate it presents and refuses one that
attests nobody, the CHANNEL_HELLO announced once per attested connection, and the bare
frames accepted from exactly the attested seed afterwards. A Python TLS server stands in
for the Java seed; the cross-language council test covers the real one."""
import socket
import ssl
import struct
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from agentspaces import beacon, cbor, tls, wire
from agentspaces.identity import Identity, multibase
from agentspaces.peer import Peer
from agentspaces.seed import Seed, parse_seed

GROUP = "zPyTls"


def _wait(predicate, seconds: float = 5.0) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


# ------------------------------------------------------- channel certificates

def test_a_channel_certificate_attests_its_identity():
    identity = Identity.generate()
    key, certificate = tls.generate_channel_certificate(identity)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert certificate.signature_algorithm_oid.dotted_string == tls.ED25519_SIG_OID
    cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == multibase(identity.public_raw) and certificate.issuer == certificate.subject
    der = certificate.public_bytes(serialization.Encoding.DER)
    assert tls.attest(der) == identity.peer_id
    assert tls.attest(certificate) == identity.peer_id
    assert tls.base58_decode(cn[1:]) == identity.public_raw


def test_attest_refuses_a_certificate_another_key_signed_and_one_no_identity_signed():
    identity, other = Identity.generate(), Identity.generate()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, multibase(identity.public_raw))])
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(7).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    forged = builder.sign(other._private, None)  # the CN names identity; other signed
    assert tls.attest(forged) is None
    plain = builder.sign(key, hashes.SHA256())  # an ordinary self-signed certificate
    assert tls.attest(plain) is None
    assert tls.attest(b"not a certificate") is None
    assert tls.attest(b"") is None


def test_credentials_are_generated_once_and_load_into_a_context():
    identity = Identity.generate()
    credentials = tls.ChannelCredentials(identity)
    assert credentials.pems() is credentials.pems()
    assert tls.attest(credentials.certificate_der()) == identity.peer_id
    context = tls.client_context(credentials)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_NONE and not context.check_hostname
    assert context.options & ssl.OP_NO_TICKET


# ------------------------------------------------------------- a TLS seed

class TlsSeed:
    """A seed over TLS 1.3 presenting a channel certificate, attesting the client's, and
    decoding its frames; on the client's CHANNEL_HELLO it sends a bare PING, as a Java
    node in ATTESTED mode would."""

    def __init__(self, trusted_client_pem: bytes | None = None, context: ssl.SSLContext | None = None):
        self.identity = Identity.generate()
        self.context = context or tls.server_context(tls.ChannelCredentials(self.identity))
        if trusted_client_pem is not None:
            # OpenSSL never treats a channel certificate as self-issued (its signature algorithm,
            # Ed25519, is not its key's, P-256), so it cannot be a chain's anchor the usual way; as
            # a trusted leaf under a partial chain it is accepted without that check. Java's
            # attest-later trust manager and Node's rejectUnauthorized=false accept anything.
            self.context.verify_mode = ssl.CERT_OPTIONAL
            self.context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            self.context.load_verify_locations(cadata=trusted_client_pem.decode())
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.connections = []
        self.attested = []  # the PeerID each connection's client certificate attests
        self.frames = []    # (connection index, kind, auth)
        self.envelopes = []
        self.handshake_errors = []
        self.closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed.is_set():
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            secured = self.context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.handshake_errors.append(e)
            conn.close()
            return
        index = len(self.connections)
        self.connections.append(secured)
        presented = secured.getpeercert(binary_form=True)
        self.attested.append(tls.attest(presented) if presented else None)
        try:
            while True:
                header = secured.recv(4)
                if len(header) < 4:
                    return
                length = struct.unpack(">i", header)[0]
                data = b""
                while len(data) < length:
                    chunk = secured.recv(length - len(data))
                    if not chunk:
                        return
                    data += chunk
                decoded = wire.decode_frame_detailed(data)
                if decoded is None:
                    continue
                env, auth = decoded
                self.frames.append((index, env.get("kind"), auth))
                self.envelopes.append(env)
                if env.get("kind") == "CHANNEL_HELLO":
                    hello = cbor.loads(env["body"])
                    assert hello == {"acceptsBare": True, "attestedRemote": self.identity.peer_id}
                    self.send_bare(secured, "PING", wire.ping_body(41), env["from"])
        except OSError:
            return

    def send_bare(self, secured, kind, body, to):
        env = wire.envelope(GROUP, kind, self.identity.peer_id,
                            wire.hlc_now(self.identity.peer_id, int(time.time() * 1000)), body, to)
        frame = wire.encode_bare_frame(env)
        secured.sendall(struct.pack(">i", len(frame)) + frame)

    def close(self):
        self.closed.set()
        self.server.close()
        for c in self.connections:
            try:
                c.close()
            except OSError:
                pass


def _plain_server_context() -> ssl.SSLContext:
    """A server with an ordinary self-signed ECDSA certificate: it attests nobody."""
    import datetime
    import os
    import tempfile
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "seed.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                   .sign(key, hashes.SHA256()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with tempfile.TemporaryDirectory() as directory:
        key_path, cert_path = os.path.join(directory, "k.pem"), os.path.join(directory, "c.pem")
        with open(key_path, "wb") as out:
            out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        with open(cert_path, "wb") as out:
            out.write(certificate.public_bytes(serialization.Encoding.PEM))
        context.load_cert_chain(cert_path, key_path)
    return context


def test_the_dial_attests_the_seed_and_presents_this_peers_certificate():
    client = Identity.generate()
    credentials = tls.ChannelCredentials(client)
    seed = TlsSeed(trusted_client_pem=credentials.pems()[1])
    try:
        secured, attested = tls.connect("127.0.0.1", seed.port, client, timeout=5, credentials=credentials)
        try:
            assert attested == seed.identity.peer_id
            assert secured.version() == "TLSv1.3"
            _wait(lambda: len(seed.attested) == 1)
            assert seed.attested == [client.peer_id], "the seed attested this peer from the certificate it presented"
        finally:
            secured.close()
    finally:
        seed.close()


def test_a_seed_that_attests_nobody_is_refused():
    seed = TlsSeed(context=_plain_server_context())
    client = Identity.generate()
    try:
        with pytest.raises(ssl.SSLError, match="no endorsed channel certificate"):
            tls.connect("127.0.0.1", seed.port, client, timeout=5)
        peer = Peer(client, GROUP)
        with pytest.raises(OSError):
            peer.connect("127.0.0.1", seed.port, scheme="tls")
        assert not peer.connected
    finally:
        seed.close()


def test_a_tls_seed_in_a_plain_listener_is_refused_as_a_failed_dial():
    plain = socket.socket()
    plain.bind(("127.0.0.1", 0))
    plain.listen(1)
    try:
        with pytest.raises(OSError):
            Peer(Identity.generate(), GROUP).connect(f"tls://127.0.0.1:{plain.getsockname()[1]}")
    finally:
        plain.close()


def test_the_peer_announces_the_channel_and_accepts_bare_frames_from_the_attested_seed():
    peer = Peer(Identity.generate(), GROUP)
    seed = TlsSeed(trusted_client_pem=peer._credentials.pems()[1])
    try:
        peer.connect(f"tls://127.0.0.1:{seed.port}")
        assert peer._seed == Seed("127.0.0.1", seed.port, "tls") and peer.connected
        assert peer._attested == seed.identity.peer_id
        # The introduction, then the announcement, then the pull: every one signed.
        _wait(lambda: len(seed.frames) >= 3)
        assert [(k, a) for _, k, a in seed.frames][:3] == [("RUMOR", "signed"), ("CHANNEL_HELLO", "signed"),
                                                            ("DIGEST", "signed")]
        hello = next(e for e in seed.envelopes if e["kind"] == "CHANNEL_HELLO")
        assert hello["to"] == seed.identity.peer_id
        # The seed's bare PING was accepted under the attestation and answered, signed.
        _wait(lambda: peer.attested_frames >= 1)
        _wait(lambda: any(k == "ACK" for _, k, _ in seed.frames))
        ack = next(e for e in seed.envelopes if e["kind"] == "ACK")
        assert cbor.loads(ack["body"])["nonce"] == 41
        assert peer.malformed_frames == 0
        assert seed.identity.peer_id in peer.reachable
        # A second introduction announces nothing more on the same connection.
        peer.introduce()
        _wait(lambda: len([1 for _, k, _ in seed.frames if k == "RUMOR"]) >= 2)
        assert len([1 for _, k, _ in seed.frames if k == "CHANNEL_HELLO"]) == 1
    finally:
        peer.close()
        seed.close()


def test_a_bare_frame_is_accepted_only_from_the_attested_sender():
    sender, other = Identity.generate(), Identity.generate()
    me = Identity.generate()
    env = wire.envelope(GROUP, "PING", sender.peer_id, wire.hlc_now(sender.peer_id), wire.ping_body(1), me.peer_id)
    bare = wire.encode_bare_frame(env)
    assert wire.decode_frame_detailed(bare, attested=sender.peer_id) == (env, "attested")
    assert wire.decode_frame_detailed(bare, attested=other.peer_id) is None, "attested as someone else"
    assert wire.decode_frame_detailed(bare) is None, "a plain tcp connection attests nobody"
    assert wire.decode_frame(bare) is None
    hello = wire.envelope(GROUP, "CHANNEL_HELLO", sender.peer_id, wire.hlc_now(sender.peer_id),
                          wire.channel_hello_body(True, me.peer_id), me.peer_id)
    assert wire.decode_frame_detailed(wire.encode_bare_frame(hello), attested=sender.peer_id) is None, \
        "a hello never travels bare"
    signed = wire.encode_frame(env, sender)
    assert wire.decode_frame_detailed(signed, attested=other.peer_id) == (env, "signed"), \
        "a signed frame from anyone still verifies by its signature"


def test_connect_any_fails_over_from_a_refusing_tls_seed_to_a_tcp_one():
    from tests.test_robustness import FakeSeed
    refusing = TlsSeed(context=_plain_server_context())
    accepting = FakeSeed()
    peer = Peer(Identity.generate(), GROUP)
    try:
        chosen = peer.connect_any([f"tls://127.0.0.1:{refusing.port}", ("127.0.0.1", accepting.port)])
        assert chosen == Seed("127.0.0.1", accepting.port, "tcp")
        assert peer._attested is None
        _wait(lambda: len(accepting.frames) >= 2)
        assert [k for _, k in accepting.frames][:2] == ["RUMOR", "DIGEST"], "no CHANNEL_HELLO on tcp"
    finally:
        peer.close()
        refusing.close()
        accepting.close()


def test_seeds_parse_from_text_tuples_and_documents():
    assert parse_seed("tls://seed.example:7500") == Seed("seed.example", 7500, "tls")
    assert parse_seed("seed.example:7500") == ("seed.example", 7500, "tcp")
    assert parse_seed("TCP://[::1]:7500") == Seed("::1", 7500, "tcp")
    assert str(Seed("::1", 7500, "tls")) == "tls://[::1]:7500"
    assert parse_seed(("h", "7", "tls")) == Seed("h", 7, "tls")
    with pytest.raises(ValueError):
        parse_seed("wss://seed.example:443/aspace")
    with pytest.raises(ValueError):
        parse_seed("seed.example")
    group = beacon.document_group("g", seeds=[("tls", "a.example:7500"), ("tcp", "b.example:7500"),
                                              ("wss", "c.example:443/aspace")])
    assert beacon.seeds_of(group) == [Seed("a.example", 7500, "tls"), Seed("b.example", 7500, "tcp")]
