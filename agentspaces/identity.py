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

"""Layer 0 in Python (spec §4): Ed25519 identity and the self-certifying id
derivations. A PeerID is multibase base58btc of sha-256 over the raw 32-byte
public key; GroupIDs and SpaceIDs derive the same way from their founding
bytes, so a Python peer computes identical names to every Java peer. The
founding-document half (spec §4.4, §5.1; Java GroupFounding) lives here too:
a self-certifying GroupID is the hash of the canonical founding document, and
``verify_signed_group_ad`` is the four-check receiver rule every GROUP_AD
answer must pass before a peer joins on it."""

import datetime
import hashlib
import os
import re
import time

from . import cbor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc(data: bytes) -> str:
    """Base58 (Bitcoin alphabet) with leading-zero preservation."""
    zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = _ALPHABET[digit] + encoded
    return "1" * zeros + encoded


def multibase(data: bytes) -> str:
    """The multibase form the Java side uses: 'z' + base58btc."""
    return "z" + base58btc(data)


def derive_id(material: bytes) -> str:
    """multibase(sha-256(material)): PeerIDs, GroupIDs, and SpaceIDs alike."""
    return multibase(hashlib.sha256(material).digest())


def group_id_from_founding(founding: bytes) -> str:
    """GroupId.fromFounding, in Python."""
    return derive_id(founding)


def space_id_local(name: str) -> str:
    """SpaceId.local, in Python: the hash of 'local:' + name."""
    return derive_id(("local:" + name).encode("utf-8"))


# ------------------------------------------------------- founding documents

# The URI scheme prefix a founding advertisement's ``id`` carries (§4.4).
URI_PREFIX = "aspace://"

# The two group-membership policies plus the pluggable one (§5.1), and the
# conflict strategies a group may default to (§7.4), as their Java enum names.
MEMBERSHIP_POLICIES = ("OPEN", "INVITE", "POLICY")
CONFLICT_STRATEGIES = ("LEASE_RACE", "AUCTION", "ORDERED")


def founding_fields(name: str, founder_peer_id: str, issued_iso: str,
                    ttl_iso: str, policy: str, strategy: str, fanout: int,
                    period_iso: str) -> dict:
    """GroupFounding.FoundingFields in canonical field order (§5.1): the
    immutable fields no later party may change. ``issued`` is ISO-8601 text
    ("2026-01-01T00:00:00Z"); ``ttl`` and ``period`` are java.time Duration
    strings as Java prints them ("PT24H", not "P1D"; "PT1S"), because the
    signature covers these exact bytes."""
    return {"name": name, "founder": founder_peer_id, "issued": issued_iso,
            "ttl": ttl_iso, "membershipPolicy": policy,
            "defaultStrategy": strategy,
            "gossip": {"fanout": int(fanout), "period": period_iso}}


def founding_document(fields: dict, signature: bytes) -> dict:
    """GroupFounding.FoundingDocument: the fields plus the founder's Ed25519
    signature over their canonical CBOR. Its canonical CBOR hashes to the
    GroupID (§4.4)."""
    return {"fields": fields, "signature": signature}


def group_id_from_founding_document(document_bytes: bytes) -> str:
    """GroupId.fromFounding over the canonical founding document bytes: the
    self-certifying GroupID (§4.4). Identical to ``derive_id``; the name
    records what the material is."""
    return derive_id(document_bytes)


def group_advertisement(group_id: str, fields: dict) -> dict:
    """A GroupAdvertisement (§5.1) in Java record order: id, issuer, group,
    issued, ttl, name, membershipPolicy, defaultStrategy, gossip. ``id`` is
    "aspace://<groupID>" and every other value is copied from the founding
    fields, which is what makes the advertisement re-derivable."""
    return {"id": URI_PREFIX + group_id, "issuer": fields["founder"],
            "group": group_id, "issued": fields["issued"], "ttl": fields["ttl"],
            "name": fields["name"],
            "membershipPolicy": fields["membershipPolicy"],
            "defaultStrategy": fields["defaultStrategy"],
            "gossip": {"fanout": fields["gossip"]["fanout"],
                       "period": fields["gossip"]["period"]}}


def found_group(identity: "Identity", name: str, policy: str, strategy: str,
                fanout: int, period_iso: str, issued_iso: str,
                ttl_iso: str) -> dict:
    """GroupFounding.found: signs the founding fields, derives the
    self-certifying GroupID, and returns the SignedGroupAdvertisement dict
    {advertisement, founderPublicKey, signature} to join with and to serve
    to newcomers as a GROUP_AD body (§5.1, §9). RFC 8032 signing is
    deterministic, so the same founder founding the same fields always
    derives the same id."""
    fields = founding_fields(name, identity.peer_id, issued_iso, ttl_iso,
                             policy, strategy, fanout, period_iso)
    signature = identity.sign(cbor.dumps(fields))
    group_id = group_id_from_founding_document(
        cbor.dumps(founding_document(fields, signature)))
    return {"advertisement": group_advertisement(group_id, fields),
            "founderPublicKey": identity.public_raw,
            "signature": signature}


def founding_fields_of(advertisement: dict) -> dict:
    """GroupFounding.fieldsOf: the founding fields an advertisement carries,
    rebuilt in canonical order from the (possibly decoded, possibly hostile)
    advertisement. Raises on a shape that cannot be a founding document."""
    gossip = advertisement["gossip"]
    fanout = gossip["fanout"]
    if not isinstance(fanout, int) or isinstance(fanout, bool):
        raise ValueError("gossip.fanout is not an integer")
    text = (advertisement["name"], advertisement["issuer"],
            advertisement["issued"], advertisement["ttl"],
            advertisement["membershipPolicy"],
            advertisement["defaultStrategy"], gossip["period"])
    if not all(isinstance(value, str) for value in text):
        raise ValueError("founding field is not text")
    return founding_fields(advertisement["name"], advertisement["issuer"],
                           advertisement["issued"], advertisement["ttl"],
                           advertisement["membershipPolicy"],
                           advertisement["defaultStrategy"], fanout,
                           gossip["period"])


def verify_signed_group_ad(signed) -> str | None:
    """GroupFounding.verify, the receiver rule of §5.1: returns the verified
    GroupID, or None. The four checks, in order: the founder key hashes to
    the advertisement's issuer; the signature verifies under that key over
    the canonical founding fields rebuilt from the advertisement; the
    founding document derives to the advertisement's ``group``; and the
    ``id`` URI names that group. A network-learned group advertisement MUST
    pass before a node joins or acts on it, and a hostile seed that fails
    any check can delay a join but never substitute a policy."""
    try:
        if not isinstance(signed, dict):
            return None
        ad = signed.get("advertisement")
        key = signed.get("founderPublicKey")
        signature = signed.get("signature")
        if (not isinstance(ad, dict) or not isinstance(key, (bytes, bytearray))
                or not isinstance(signature, (bytes, bytearray))):
            return None
        key, signature = bytes(key), bytes(signature)
        if len(key) != 32 or derive_id(key) != ad.get("issuer"):
            return None
        fields = founding_fields_of(ad)
        if not Identity.verify(key, cbor.dumps(fields), signature):
            return None
        group_id = group_id_from_founding_document(
            cbor.dumps(founding_document(fields, signature)))
        if group_id != ad.get("group") or ad.get("id") != URI_PREFIX + group_id:
            return None
        return group_id
    except (KeyError, TypeError, ValueError):
        return None


# ------------------------------------------------------ agent certificates
# Subordinate agent keys (SPEC §4.2, §11a.3; TECH-SPEC §7.2; QA4 A4-7). A peer
# may give an agent its own Ed25519 key and certify it: the certificate binds
# the agent's name and key to the peer for a validity window, and records the
# agent writes are then signed by the agent key. A receiver still sees the
# peer key in EntryStateDto.issuerPublicKey; the certificate rides beside it.

_INSTANT = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$")
_DURATION = re.compile(
    r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{1,9}))?S)?$")


def parse_instant_millis(iso: str) -> int:
    """java.time.Instant text ("2026-01-01T00:00:00Z", optional fraction) to
    epoch milliseconds. Java prints UTC with a 'Z' and up to nine fraction
    digits; anything else is not an Instant this wire carries."""
    match = _INSTANT.match(iso) if isinstance(iso, str) else None
    if not match:
        raise ValueError(f"not an ISO-8601 instant: {iso!r}")
    year, month, day, hour, minute, second, fraction = match.groups()
    moment = datetime.datetime(int(year), int(month), int(day), int(hour),
                               int(minute), int(second),
                               tzinfo=datetime.timezone.utc)
    millis = int(moment.timestamp()) * 1000
    if fraction:
        millis += int(fraction.ljust(9, "0")[:3])
    return millis


def parse_duration_millis(iso: str) -> int:
    """java.time.Duration text as Java prints it ("PT24H", "PT1H30M",
    "PT0.5S"; never days) to milliseconds."""
    match = _DURATION.match(iso) if isinstance(iso, str) else None
    if not match or iso == "PT":
        raise ValueError(f"not an ISO-8601 duration: {iso!r}")
    hours, minutes, seconds, fraction = match.groups()
    millis = (int(hours or 0) * 3600 + int(minutes or 0) * 60
              + int(seconds or 0)) * 1000
    if fraction:
        millis += int(fraction.ljust(9, "0")[:3])
    return millis


# How far a signing time may lead the receiver's clock (the HLC drift
# ceiling, HybridLogicalClock.MAX_DRIFT_MILLIS): a later stamp is refused.
MAX_DRIFT_MILLIS = 10 * 60 * 1000


def agent_certificate(agent: str, agent_public_raw: bytes, issued_iso: str,
                      ttl_iso: str, peer_signature=None,
                      encryption_public_raw=None) -> dict:
    """An AgentCertificate in Java record order: agent, agentPublicKey,
    issued, ttl, peerSignature, and (v0.1.13, SPEC §11a.2a) the agent's
    X25519 ``encryptionPublicKey``, appended and omitted when absent, so a
    certificate without it keeps its exact bytes. With ``peer_signature``
    None this is the body the peer signs (AgentCertificate.unsigned)."""
    certificate = {"agent": agent, "agentPublicKey": agent_public_raw,
                   "issued": issued_iso, "ttl": ttl_iso,
                   "peerSignature": peer_signature}
    if encryption_public_raw is not None:
        certificate["encryptionPublicKey"] = encryption_public_raw
    return certificate


def certificate_body(certificate: dict) -> dict:
    """The signed body of a (possibly decoded) certificate: the same fields
    in canonical order with the signature cleared."""
    return agent_certificate(certificate["agent"], certificate["agentPublicKey"],
                             certificate["issued"], certificate["ttl"], None,
                             certificate.get("encryptionPublicKey"))


def certificate_covers(certificate: dict, signing_ms: int) -> bool:
    """AgentCertificate.covers (SPEC §4.2, v0.1.13): ``signing_ms`` lies in
    ``[issued, issued + ttl)``, the issue instant taken at millisecond
    precision as HLC stamps are."""
    issued = parse_instant_millis(certificate.get("issued"))
    return issued <= signing_ms < issued + parse_duration_millis(certificate.get("ttl"))


def verify_agent_certificate_at(certificate, peer_public_raw: bytes,
                                expected_agent: str, signing_ms: int,
                                receiver_now_ms: int) -> bool:
    """AgentCertificates.verifyAt (SPEC §4.2, v0.1.13): a certificate is
    judged at the signing time of what it certifies (a record's issue stamp,
    a claim's stamp, a state's ``signedAt``), not at receipt. The window must
    cover the signing time, the signing time may lead the receiver's clock by
    at most the HLC drift ceiling, and every check of
    ``verify_agent_certificate`` must pass at that time. An agent's history
    therefore stays verifiable after its certificate lapses."""
    try:
        if (not isinstance(certificate, dict)
                or not certificate_covers(certificate, signing_ms)
                or signing_ms > receiver_now_ms + MAX_DRIFT_MILLIS):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return verify_agent_certificate(certificate, peer_public_raw, expected_agent,
                                    signing_ms)


def sign_agent_certificate(body: dict, peer: "Identity") -> dict:
    """AgentCertificates.sign: the peer signs the certificate body. Only the
    peer the agent name belongs to may certify it."""
    if not str(body["agent"]).startswith(peer.peer_id + "/"):
        raise ValueError(f"certificate for {body['agent']} cannot be issued by "
                         f"{peer.peer_id}")
    unsigned = certificate_body(body)
    return {**unsigned, "peerSignature": peer.sign(cbor.dumps(unsigned))}


def verify_agent_certificate(certificate, peer_public_raw: bytes,
                             expected_agent: str, now_ms: int) -> bool:
    """AgentCertificates.verify: the certificate carries a signature and a
    32-byte agent key, names exactly ``expected_agent``, that agent's peer is
    the peer ``peer_public_raw`` hashes to, it is unexpired at ``now_ms``
    (expiry is issued + ttl, inclusive), and the peer's signature verifies
    over the canonical body."""
    try:
        if not isinstance(certificate, dict):
            return False
        signature = certificate.get("peerSignature")
        agent_key = certificate.get("agentPublicKey")
        agent = certificate.get("agent")
        encryption_key = certificate.get("encryptionPublicKey")
        if (not isinstance(signature, (bytes, bytearray))
                or not isinstance(agent_key, (bytes, bytearray))
                or len(agent_key) != 32
                or (encryption_key is not None
                    and (not isinstance(encryption_key, (bytes, bytearray))
                         or len(encryption_key) != 32))
                or not isinstance(peer_public_raw, (bytes, bytearray))
                or len(peer_public_raw) != 32
                or not isinstance(agent, str) or agent != expected_agent
                or not agent.startswith(derive_id(bytes(peer_public_raw)) + "/")):
            return False
        expires = (parse_instant_millis(certificate.get("issued"))
                   + parse_duration_millis(certificate.get("ttl")))
        if now_ms >= expires:
            return False
        return Identity.verify(bytes(peer_public_raw),
                               cbor.dumps(certificate_body(certificate)),
                               bytes(signature))
    except (KeyError, TypeError, ValueError):
        return False


def instant_iso(millis: int) -> str:
    """Epoch milliseconds as java.time.Instant prints them: whole seconds bare,
    otherwise three fraction digits ("2026-01-01T00:00:00Z",
    "2026-01-01T00:00:00.250Z")."""
    seconds, fraction = divmod(int(millis), 1000)
    text = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S")
    return f"{text}.{fraction:03d}Z" if fraction else f"{text}Z"


class AgentIdentity:
    """A subordinate agent identity: the agent's own Ed25519 key plus the
    peer-signed certificate that vouches for it. Records the agent writes
    are signed with ``sign``; the certificate travels in the state DTO.

    A renewing identity (``Identity.renewing_subordinate``, SPEC §4.2,
    v0.1.13) also holds its peer, a lifetime, and a clock: it re-issues its
    certificate for the same key at half-life, lazily on every sign and
    lookup, and keeps up to ``RETAINED`` earlier certificates so a claim
    whose stamp a renewal kept stays certifiable."""

    RETAINED = 256

    def __init__(self, agent_id: str, key: "Identity", certificate: dict,
                 peer: "Identity | None" = None, ttl_iso: str | None = None,
                 clock=None, encryption_public_raw: bytes | None = None):
        self.agent_id = agent_id
        self._key = key
        self.public_raw = key.public_raw
        self.certificate = certificate
        self._peer = peer
        self._ttl_iso = ttl_iso
        self._clock = clock or time.time
        self._encryption_public_raw = encryption_public_raw
        self._issued = [certificate]

    @property
    def renewing(self) -> bool:
        return self._peer is not None

    def renew_if_due(self, now_ms: int | None = None) -> bool:
        """Re-issues the certificate when half its lifetime has passed at
        ``now_ms`` (default: this identity's clock). Returns whether it did."""
        if self._peer is None:
            return False
        now_ms = int(self._clock() * 1000) if now_ms is None else int(now_ms)
        issued = parse_instant_millis(self.certificate["issued"])
        ttl = parse_duration_millis(self.certificate["ttl"])
        if now_ms < issued + ttl // 2:
            return False
        body = agent_certificate(self.agent_id, self.public_raw, instant_iso(now_ms),
                                 self._ttl_iso, None, self._encryption_public_raw)
        self.certificate = sign_agent_certificate(body, self._peer)
        self._issued.append(self.certificate)
        del self._issued[:-self.RETAINED]
        return True

    def certificate_covering(self, signing_ms: int):
        """The newest held certificate whose window covers ``signing_ms``, or
        None: what a writer attaches so receivers can judge it at that time."""
        self.renew_if_due()
        for certificate in reversed(self._issued):
            try:
                if certificate_covers(certificate, int(signing_ms)):
                    return certificate
            except (KeyError, TypeError, ValueError):
                continue
        return None

    def sign(self, message: bytes) -> bytes:
        self.renew_if_due()
        return self._key.sign(message)


class Identity:
    """An Ed25519 peer identity with the Java-compatible PeerID."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private = private_key
        self.public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.peer_id = derive_id(self.public_raw)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        """An identity from a 32-byte Ed25519 seed (RFC 8032's private key),
        as Java Ed25519.fromSeed builds one: how the invite signing key is
        derived from a group secret."""
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes(seed)))

    @classmethod
    def from_pkcs8(cls, pkcs8: bytes) -> "Identity":
        key = serialization.load_der_private_key(pkcs8, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 PKCS#8 key")
        return cls(key)

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def agent(self, local_name: str) -> str:
        """The AgentID string form: '<peerId>/<localName>'."""
        return f"{self.peer_id}/{local_name}"

    def subordinate(self, local_name: str, issued_iso: str,
                    ttl_iso: str = "PT1H", key: "Identity | None" = None
                    ) -> AgentIdentity:
        """PeerIdentity.subordinate: certifies a fresh (or given) agent key
        for '<peerId>/<localName>' from ``issued_iso`` for ``ttl_iso``."""
        key = key or Identity.generate()
        body = agent_certificate(self.agent(local_name), key.public_raw,
                                 issued_iso, ttl_iso)
        return AgentIdentity(self.agent(local_name), key,
                             sign_agent_certificate(body, self))

    def renewing_subordinate(self, local_name: str, ttl_iso: str = "PT24H",
                             key: "Identity | None" = None, clock=None,
                             encryption_public_raw: bytes | None = None
                             ) -> AgentIdentity:
        """PeerIdentity.renewingSubordinate (SPEC §4.2, v0.1.13): an agent key
        whose certificate this peer re-issues at half-life, judged at signing
        time by receivers. ``encryption_public_raw`` certifies an X25519 key
        too (SPEC §11a.2a)."""
        clock = clock or time.time
        key = key or Identity.generate()
        now_ms = int(clock() * 1000)
        body = agent_certificate(self.agent(local_name), key.public_raw,
                                 instant_iso(now_ms), ttl_iso, None,
                                 encryption_public_raw)
        return AgentIdentity(self.agent(local_name), key,
                             sign_agent_certificate(body, self), peer=self,
                             ttl_iso=ttl_iso, clock=clock,
                             encryption_public_raw=encryption_public_raw)

    def pkcs8(self) -> bytes:
        """The private key as PKCS#8 DER, the form Java's keystore writes."""
        return self._private.private_bytes(serialization.Encoding.DER,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption())

    def save_pkcs8(self, path: str) -> None:
        """Writes the private key as PKCS#8 DER to ``path``: an atomic replace,
        owner-only (0600), as FileKeystore writes ``peer.key``."""
        write_key_file(path, self.pkcs8(), secret=True)

    @classmethod
    def load_or_create(cls, directory: str, private_name: str = "peer.key",
                       public_name: str = "peer.pub") -> "Identity":
        """FileKeystore.loadOrCreate (SPEC §4.1, v0.1.13): ``peer.key``
        (PKCS#8 DER, owner-only) and ``peer.pub`` (raw 32 bytes) in
        ``directory``, the layout a Java peer reads, minted when absent. A
        half-written pair, a public file of the wrong size, or a private key
        that does not sign for the public one is refused, naming the files."""
        private_path = os.path.join(directory, private_name)
        public_path = os.path.join(directory, public_name)
        has_private, has_public = os.path.exists(private_path), os.path.exists(public_path)
        if has_private != has_public:
            present, missing = ((private_path, public_path) if has_private
                                else (public_path, private_path))
            raise ValueError(f"corrupt keystore: {present} exists but {missing} does not")
        if not has_private:
            identity = cls.generate()
            write_key_file(private_path, identity.pkcs8(), secret=True)
            write_key_file(public_path, identity.public_raw, secret=False)
            return identity
        with open(private_path, "rb") as handle:
            identity = cls.from_pkcs8(handle.read())
        with open(public_path, "rb") as handle:
            public = handle.read()
        if len(public) != 32:
            raise ValueError(f"corrupt keystore: {public_path} is not a raw Ed25519 public key")
        probe = os.urandom(32)
        if not cls.verify(public, probe, identity.sign(probe)):
            raise ValueError(f"corrupt keystore: {private_path} does not belong to "
                             f"the public key in {public_path}")
        return identity

    @classmethod
    def agent_keys(cls, directory: str, peer_id: str, local_name: str) -> "Identity":
        """AgentKeystore.signingKeys: ``<dir>/<peer-id>/<local-name>/agent.key``
        and ``agent.pub``, the layout Java's agent keystore uses. Names that
        could escape the directory are refused, never sanitized."""
        for name, what in ((peer_id, "peer id"), (local_name, "agent name")):
            if (not isinstance(name, str) or not _SAFE_NAME.match(name)
                    or name in (".", "..")):
                raise ValueError(f"{what} {name!r} is not a safe file name")
        return cls.load_or_create(os.path.join(directory, peer_id, local_name),
                                  "agent.key", "agent.pub")

    @staticmethod
    def verify(public_raw: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
            return True
        except Exception:  # noqa: BLE001 - verification failure is one answer
            return False


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def write_key_file(path: str, data: bytes, secret: bool) -> None:
    """KeyFiles.write: an atomic replace through a temporary file in the same
    directory, owner-only (0600) for a secret, flushed to disk first."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp = os.path.join(directory, f".{'key' if secret else 'pub'}-{os.getpid()}-"
                                   f"{os.urandom(4).hex()}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600 if secret else 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.remove(temp)
