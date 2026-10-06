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

"""Revocations in Python (SPEC §5.6, v0.1.13): the ``revocations`` stream's
peer revocations and the ``credential-revocations`` stream's revocations of
agents, agent keys, X.509 leaves, and join credentials, verified exactly as a
Java member verifies them except for the CA-rooted path, which this client
does not carry (a CA-rooted record is ignored, never trusted). A registry
keeps one record per target, chosen by the same total order as Java's:
authority (founder, then the agent's own peer), then the newer ``issued``,
then the larger SHA-256 of the signed bytes."""

import hashlib

from . import cbor
from .identity import Identity, derive_id, parse_instant_millis

PEER_STREAM = "revocations"
CREDENTIAL_STREAM = "credential-revocations"
STREAMS = (PEER_STREAM, CREDENTIAL_STREAM)

KEY_COMPROMISE = "key-compromise"
REASONS = (KEY_COMPROMISE, "retired", "superseded", "privilege-withdrawn", "unspecified")
KINDS = ("AGENT", "AGENT_KEY", "X509_LEAF", "JOIN_CREDENTIAL")

FOUNDER, OWN_PEER = 3, 1
MAX_ISSUED_SKEW_MILLIS = 10 * 60 * 1000
MAX_RETAINED = 4096


def canonical_target(target: dict) -> str:
    """CredentialRevocation.Target.canonical: the target's text within its kind."""
    kind = target.get("kind")
    if kind == "AGENT":
        return target["agent"]
    if kind == "AGENT_KEY":
        return target["agent"] + "#" + bytes(target["keyFingerprint"]).hex()
    if kind == "X509_LEAF":
        return bytes(target["certificateFingerprint"]).hex()
    return bytes(target["credentialHash"]).hex()


def revocation_id(group: str, target: dict) -> str:
    """CredentialRevocation.idFor: aspace://<group>/revocation/<kind>/<canonical>."""
    return f"aspace://{group}/revocation/{target['kind'].lower()}/{canonical_target(target)}"


def _valid_target(target) -> bool:
    if not isinstance(target, dict) or target.get("kind") not in KINDS:
        return False
    def sized(key):
        value = target.get(key)
        return isinstance(value, (bytes, bytearray)) and len(value) == 32
    kind = target["kind"]
    if kind == "AGENT":
        return isinstance(target.get("agent"), str)
    if kind == "AGENT_KEY":
        return isinstance(target.get("agent"), str) and sized("keyFingerprint")
    if kind == "X509_LEAF":
        return sized("certificateFingerprint")
    return sized("credentialHash")


class Registry:
    """One group's accepted revocations as a client holds and applies them."""

    def __init__(self, founder, group=None):
        self._founder = founder  # callable returning the founder's PeerID, or None
        self._group = group      # callable returning the group id, or None (any)
        self.peers = {}          # revoked PeerID -> (rank, issued, hash, ad)
        self.credentials = {}    # "kind:canonical" -> (rank, issued, hash, ad)

    # ----------------------------------------------------------- acceptance

    def accept(self, stream: str, payload, now_ms: int) -> bool:
        """Verifies and accepts one rumor payload (a CBOR SignedRevocation)."""
        try:
            signed = cbor.loads(bytes(payload))
        except (ValueError, IndexError, TypeError, UnicodeDecodeError):
            return False
        return self.accept_signed(stream, signed, now_ms)

    def accept_signed(self, stream: str, signed, now_ms: int) -> bool:
        """Verifies and accepts one decoded SignedRevocation {adBytes,
        publicKey, signature}; returns whether it newly revoked its target."""
        if not isinstance(signed, dict):
            return False
        ad_bytes, key, signature = (signed.get("adBytes"), signed.get("publicKey"),
                                    signed.get("signature"))
        if (not isinstance(ad_bytes, (bytes, bytearray)) or not isinstance(key, (bytes, bytearray))
                or len(key) != 32 or not isinstance(signature, (bytes, bytearray))):
            return False
        try:
            ad = cbor.loads(bytes(ad_bytes))
            issued = parse_instant_millis(ad.get("issued"))
        except (ValueError, IndexError, TypeError, AttributeError, UnicodeDecodeError):
            return False
        if (not isinstance(ad, dict) or derive_id(bytes(key)) != ad.get("issuer")
                or not Identity.verify(bytes(key), bytes(ad_bytes), bytes(signature))
                or issued > now_ms + MAX_ISSUED_SKEW_MILLIS
                or (self._group is not None and self._group() not in (None, ad.get("group")))):
            return False
        digest = hashlib.sha256(bytes(ad_bytes)).hexdigest()
        if stream == PEER_STREAM:
            return self._accept_peer(ad, issued, digest)
        if stream == CREDENTIAL_STREAM:
            return self._accept_credential(ad, issued, digest)
        return False

    def _accept_peer(self, ad: dict, issued: int, digest: str) -> bool:
        founder = self._founder()
        revoked = ad.get("revoked")
        # Founder-rooted only: a CA-rooted record (evidence) is not trusted here,
        # and only the founder may name a successor.
        if not founder or ad.get("issuer") != founder or not isinstance(revoked, str):
            return False
        return _keep(self.peers, revoked, (FOUNDER, issued, digest, ad))

    def _accept_credential(self, ad: dict, issued: int, digest: str) -> bool:
        target = ad.get("target")
        if (not _valid_target(target) or ad.get("reason") not in REASONS
                or ad.get("id") != revocation_id(ad.get("group"), target)):
            return False
        effective = ad.get("effectiveFrom")
        try:
            if effective is not None and parse_instant_millis(effective) > issued:
                return False
        except (ValueError, TypeError):
            return False
        issuer = ad.get("issuer")
        if issuer == self._founder():
            rank = FOUNDER
        elif (target["kind"] in ("AGENT", "AGENT_KEY")
              and str(target.get("agent", "")).startswith(issuer + "/")):
            rank = OWN_PEER
        else:
            return False
        key = target["kind"] + ":" + canonical_target(target)
        return _keep(self.credentials, key, (rank, issued, digest, ad))

    # ---------------------------------------------------------- enforcement

    def peer_revoked(self, peer_id: str) -> bool:
        return peer_id in self.peers

    def refuses(self, agent_id, agent_key, signing_ms) -> bool:
        """RevocationView.refuses: a newly arriving signature by ``agent_id``
        is refused when its peer is revoked, or its agent-wide or (given the
        key) key revocation refuses ``signing_ms`` under the freeze rule:
        always under key-compromise or an unknown time, else at or after the
        revocation's effective instant."""
        if not isinstance(agent_id, str) or "/" not in agent_id:
            return False
        if self.peer_revoked(agent_id.split("/", 1)[0]):
            return True
        whole = self.credentials.get("AGENT:" + agent_id)
        if whole is not None and _refuses_at(whole[3], signing_ms):
            return True
        if isinstance(agent_key, (bytes, bytearray)):
            fingerprint = hashlib.sha256(bytes(agent_key)).hexdigest()
            one = self.credentials.get(f"AGENT_KEY:{agent_id}#{fingerprint}")
            if one is not None and _refuses_at(one[3], signing_ms):
                return True
        return False


def _refuses_at(ad: dict, signing_ms) -> bool:
    if ad.get("reason") == KEY_COMPROMISE or signing_ms is None:
        return True
    since = ad.get("effectiveFrom") or ad.get("issued")
    return int(signing_ms) >= parse_instant_millis(since)


def _keep(table: dict, key: str, candidate: tuple) -> bool:
    """One record per target under the total order (rank, issued, hash);
    returns whether the target is newly revoked."""
    held = table.get(key)
    if held is None:
        if len(table) >= MAX_RETAINED:
            return False
        table[key] = candidate
        return True
    if candidate[:3] > held[:3]:
        table[key] = candidate
    return False
