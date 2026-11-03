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

"""The ``tls`` binding (SPEC §5.5, §5.6): length-prefixed frames inside TLS 1.3,
each end presenting a channel certificate.

A channel certificate is a fresh EC P-256 key for TLS in a self-signed X.509
certificate whose signature is the peer's Ed25519 identity signature over the
TBSCertificate (id-Ed25519, RFC 8410), with the raw identity key in the subject
CN as multibase base58btc. The TLS handshake proves possession of the P-256
key; the endorsement binds the channel to PeerID = multibase(sha-256(identity
key)). No CA participates: the only trust decision is :func:`attest`, run on
the certificate the remote end presented, after the handshake. No session
resumption and no early data, so every attestation rests on a full handshake.
Mirrors Java ``ChannelCertificate`` and ``TlsTcpTransport``."""

import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

from .identity import Identity, derive_id, multibase

ED25519_SIG_OID = "1.3.101.112"
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


def base58_decode(text: str) -> bytes:
    """The inverse of ``identity.base58btc``; ValueError on a foreign character."""
    number = 0
    for char in text:
        try:
            number = number * 58 + _INDEX[char]
        except KeyError:
            raise ValueError(f"not base58: {char!r}") from None
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * zeros + body


# ------------------------------------------------------- channel certificates

def generate_channel_certificate(identity: Identity) -> tuple:
    """``(tls_key, certificate)`` for ``identity``, as Java ``ChannelCertificate.generate``:
    a P-256 key, a self-signed certificate naming the identity key in the CN, the
    signature the identity key's (id-Ed25519 over the TBSCertificate), valid from
    an hour ago for a year."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, multibase(identity.public_raw))])
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name)
                   .issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(int.from_bytes(os.urandom(9), "big") or 1)
                   .not_valid_before(now)
                   .not_valid_after(now + datetime.timedelta(days=365))
                   .sign(identity._private, None))  # noqa: SLF001 - the endorsement is the identity's
    return key, certificate


def attest(certificate) -> str | None:
    """The PeerID a presented certificate attests, or None: the signature algorithm
    is id-Ed25519, the CN decodes to a 32-byte key, and that key's signature over the
    TBSCertificate verifies (Java ``ChannelCertificate.attest``). ``certificate`` is
    the DER bytes or a parsed ``x509.Certificate``."""
    try:
        if isinstance(certificate, (bytes, bytearray, memoryview)):
            certificate = x509.load_der_x509_certificate(bytes(certificate))
        if certificate.signature_algorithm_oid != SignatureAlgorithmOID.ED25519:
            return None
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1:
            return None
        cn = names[0].value
        if not isinstance(cn, str) or len(cn) > 64 or not cn.startswith("z"):
            return None
        raw = base58_decode(cn[1:])
        if len(raw) != 32:
            return None
        Ed25519PublicKey.from_public_bytes(raw).verify(certificate.signature,
                                                       certificate.tbs_certificate_bytes)
        return derive_id(raw)
    except Exception:  # noqa: BLE001 - any defect in a presented certificate is "attests nobody"
        return None


class ChannelCredentials:
    """One identity's channel certificate, generated once and loaded into each
    dial's SSL context. The P-256 key lives only here and in the context."""

    def __init__(self, identity: Identity):
        self.identity = identity
        self._lock = threading.Lock()
        self._pems = None

    def pems(self) -> tuple:
        """``(key_pem, certificate_pem)``, generated on first use."""
        with self._lock:
            if self._pems is None:
                key, certificate = generate_channel_certificate(self.identity)
                self._pems = (key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()),
                              certificate.public_bytes(serialization.Encoding.PEM))
            return self._pems

    def certificate_der(self) -> bytes:
        return x509.load_pem_x509_certificate(self.pems()[1]).public_bytes(serialization.Encoding.DER)

    def load_into(self, context: ssl.SSLContext) -> None:
        """Loads the credential into ``context``. The standard library reads a
        certificate chain from files only, so the pair is written to an owner-only
        temporary directory for the duration of the call."""
        key_pem, cert_pem = self.pems()
        with tempfile.TemporaryDirectory(prefix="aspace-tls-") as directory:
            os.chmod(directory, 0o700)
            key_path = os.path.join(directory, "channel.key")
            cert_path = os.path.join(directory, "channel.crt")
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(key_pem)
            with open(cert_path, "wb") as out:
                out.write(cert_pem)
            context.load_cert_chain(cert_path, key_path)


# --------------------------------------------------------------- the dialer

def client_context(credentials: ChannelCredentials) -> ssl.SSLContext:
    """A TLS 1.3 client context presenting the channel certificate. The CA chain
    proves nothing here (no verification at the handshake); the endorsement is
    checked after it by :func:`attest`. Tickets are refused so no session can
    vouch for a later connection (ASF-021)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_TICKET
    credentials.load_into(context)
    return context


def server_context(credentials: ChannelCredentials) -> ssl.SSLContext:
    """A TLS 1.3 server context presenting the channel certificate and asking the
    client for its own, for tests and tools that stand in for a seed. The standard
    library cannot accept an arbitrary client certificate the way Java's
    attest-later trust manager does, so a server built here verifies no client
    chain; callers attest the presented certificate with :func:`attest` after
    the handshake when ``verify_mode`` lets one through."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_TICKET
    credentials.load_into(context)
    return context


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def connect(host: str, port: int, identity: Identity, *, timeout: float = 10.0,
            credentials: ChannelCredentials | None = None) -> tuple:
    """A TLS 1.3 connection to ``host:port`` presenting ``identity``'s channel
    certificate; returns ``(ssl_socket, attested_peer_id)``. The remote end must
    present an endorsed channel certificate: one that attests nobody is closed and
    refused with ``ssl.SSLError`` (an OSError, like a refused dial)."""
    credentials = credentials or ChannelCredentials(identity)
    context = client_context(credentials)
    plain = socket.create_connection((host, port), timeout=timeout)
    try:
        secured = context.wrap_socket(plain, server_hostname=None if _is_ip(host) else host)
    except BaseException:
        plain.close()
        raise
    try:
        presented = secured.getpeercert(binary_form=True)
        attested = attest(presented) if presented else None
        if attested is None:
            raise ssl.SSLError(f"tls://{host}:{port} presented no endorsed channel certificate")
        return secured, attested
    except BaseException:
        secured.close()
        raise
