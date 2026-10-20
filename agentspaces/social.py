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

"""The invite key and the delegated credential (SRAD discovery §3.8, appendix
F; Java GroupSecret, InviteKey, Base32Crockford, JoinCredentials). One
128-bit group secret yields, by HKDF-SHA256 under the salt ``aspace-inv1``,
the invite signing key (``invite-sign``), the content key (``content-key``),
and the one-way lookup code (``lookup``, 80 bits). The founder signs a
delegation of the invite public key once; a holder of the secret then signs
its own PeerID under it and presents the result as the ``aspace:join`` hint.
Every derivation and every CBOR shape here is bit-identical to the Java
side, which ``tests/social-golden.json`` pins."""

import base64
import hashlib
import hmac
import os
from urllib.parse import urlsplit

from . import cbor
from .identity import Identity, derive_id

# The HKDF salt, also the key format's version tag.
SALT = b"aspace-inv1"
SECRET_LENGTH = 16
CODE_LENGTH = 10
# The built-in default social beacon, omitted from compact keys.
DEFAULT_HOST = "s.agentspaces.dev"
PREFIX = "aspace-inv1-"
# The resource-hint key a candidate carries its join credential under.
HINT_KEY = "aspace:join"
# The prefix of a delegated credential string (JoinCredentials.DELEGATED_PREFIX).
DELEGATED_PREFIX = "d1:"
# The clock skew a delegation's expiry is judged with, as advertisements allow.
EXPIRY_SKEW_MILLIS = 10 * 60 * 1000


# ------------------------------------------------------------------ HKDF

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with HMAC-SHA-256, as Java Hkdf.derive: an empty salt
    is a zero key of the hash length."""
    if length <= 0 or length > 255 * 32:
        raise ValueError(f"length out of range: {length}")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


# --------------------------------------------------------- Crockford base32

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(_ALPHABET)}
_DECODE.update({"O": 0, "I": 1, "L": 1})


def base32_encode(data: bytes) -> str:
    """Crockford base32, no padding: no I, L, O, U, so a key read aloud survives."""
    out, buffer, bits = [], 0, 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(_ALPHABET[(buffer >> (bits - 5)) & 31])
            bits -= 5
    if bits > 0:
        out.append(_ALPHABET[(buffer << (5 - bits)) & 31])
    return "".join(out)


def base32_decode(text: str) -> bytes:
    """Case-insensitive; dashes and spaces are ignored; O reads as 0 and I and
    L as 1. Any other character outside the alphabet is refused."""
    out, buffer, bits = bytearray(), 0, 0
    for char in text.upper():
        if char in "- ":
            continue
        value = _DECODE.get(char)
        if value is None:
            raise ValueError(f"not a Crockford base32 character: {char!r}")
        buffer = (buffer << 5) | value
        bits += 5
        if bits >= 8:
            out.append((buffer >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


# ---------------------------------------------------------- the group secret

class GroupSecret:
    """The 128 bits the creator draws and every holder derives from."""

    def __init__(self, secret: bytes):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) != SECRET_LENGTH:
            raise ValueError(f"a group secret is {SECRET_LENGTH} bytes")
        self._secret = bytes(secret)

    @classmethod
    def random(cls) -> "GroupSecret":
        return cls(os.urandom(SECRET_LENGTH))

    @property
    def bytes(self) -> bytes:
        return self._secret

    def _derive(self, info: str, length: int) -> bytes:
        return hkdf_sha256(self._secret, SALT, info.encode("utf-8"), length)

    def invite_private_seed(self) -> bytes:
        """The invite signing key's 32-byte Ed25519 seed (RFC 8032 private key)."""
        return self._derive("invite-sign", 32)

    def invite_key(self) -> Identity:
        """The invite signing key pair."""
        return Identity.from_seed(self.invite_private_seed())

    def invite_public_key(self) -> bytes:
        """The raw public half of the invite signing key."""
        return self.invite_key().public_raw

    def content_key(self) -> bytes:
        """The group's content key, epoch 0, 32 bytes."""
        return self._derive("content-key", 32)

    def content_key_base64(self) -> str:
        return base64.b64encode(self.content_key()).decode("ascii")

    def code(self) -> str:
        """The lookup code: 80 bits of a one-way derivation, 16 characters."""
        return base32_encode(self._derive("lookup", CODE_LENGTH))

    def __eq__(self, other) -> bool:
        return isinstance(other, GroupSecret) and hmac.compare_digest(self._secret, other._secret)

    def __hash__(self) -> int:
        return hash(self._secret)

    def __repr__(self) -> str:
        return f"GroupSecret[{self.code()}]"


# -------------------------------------------------------------- the invite key

class InviteKey:
    """One key, two renderings. Compact, for a text message:
    ``aspace-inv1-<code>-<secret>[-<delegation>][@host[:port]]``, the host
    present only when the beacon is not the default. URL, for a phone:
    ``https://<host>/j/<code>#<secret>[.<delegation>]``; the server receives
    the path only. ``delegation`` is the base64 delegation string (public
    data) or None, in which case the beacon document's ``invite`` carries it."""

    def __init__(self, host: str, code: str, secret: GroupSecret, delegation: str | None = None):
        self.host = host.strip().lower()
        self.code = code.strip().upper()
        self.secret = secret
        self.delegation = delegation

    @classmethod
    def of(cls, secret: GroupSecret, delegation: str | None = None,
           host: str = DEFAULT_HOST) -> "InviteKey":
        return cls(host, secret.code(), secret, delegation)

    def compact(self) -> str:
        out = PREFIX + self.code + "-" + base32_encode(self.secret.bytes)
        if self.delegation is not None:
            out += "-" + base32_encode(base64.b64decode(self.delegation))
        if self.host != DEFAULT_HOST:
            out += "@" + self.host
        return out

    def url(self) -> str:
        out = f"https://{self.host}/j/{self.code}#{base32_encode(self.secret.bytes)}"
        if self.delegation is not None:
            out += "." + base32_encode(base64.b64decode(self.delegation))
        return out

    def beacon(self, scheme: str = "https") -> str:
        """The beacon's base URL."""
        return f"{scheme}://{self.host}"

    def document_url(self, scheme: str = "https") -> str:
        """The document URL at the beacon: ``/j/<code>``."""
        return f"{scheme}://{self.host}/j/{self.code}"

    def with_delegation(self, delegation: str | None) -> "InviteKey":
        return InviteKey(self.host, self.code, self.secret, delegation)

    def with_host(self, host: str) -> "InviteKey":
        return InviteKey(host, self.code, self.secret, self.delegation)

    @classmethod
    def parse(cls, text: str) -> "InviteKey":
        """Parses either rendering; case and spaces inside segments are
        forgiven. Raises ValueError when the text is not an invite key or the
        code does not belong to the secret."""
        if not isinstance(text, str):
            raise ValueError("not an invite key")
        t = text.strip()
        if t.lower().startswith(("https://", "http://")):
            return cls._parse_url(t)
        t = t.replace(" ", "").replace("\n", "").replace("\t", "")
        if not t.lower().startswith(PREFIX):
            raise ValueError(f"not an invite key: it does not start with {PREFIX}")
        rest = t[len(PREFIX):]
        host = DEFAULT_HOST
        at = rest.rfind("@")
        if at >= 0:
            host, rest = rest[at + 1:].strip(), rest[:at]
        segments = rest.split("-")
        if len(segments) < 2 or len(segments) > 3:
            raise ValueError("not an invite key: expected code-secret[-delegation]")
        secret = cls._secret_of(segments[1])
        code = segments[0].upper()
        if code != secret.code():
            raise ValueError("not an invite key: the code does not belong to the secret")
        delegation = (base64.b64encode(base32_decode(segments[2])).decode("ascii")
                      if len(segments) == 3 else None)
        return cls(host, code, secret, delegation)

    @classmethod
    def _parse_url(cls, text: str) -> "InviteKey":
        parts = urlsplit(text.replace(" ", ""))
        path = parts.path or ""
        j = path.find("/j/")
        if j < 0 or not parts.fragment.strip():
            raise ValueError("not an invite link: expected https://host/j/<code>#<secret>")
        code = path[j + 3:].split("/", 1)[0]
        fragment = parts.fragment
        dot = fragment.find(".")
        secret = cls._secret_of(fragment if dot < 0 else fragment[:dot])
        if code.upper() != secret.code():
            raise ValueError("not an invite link: the code does not belong to the secret")
        delegation = (None if dot < 0
                      else base64.b64encode(base32_decode(fragment[dot + 1:])).decode("ascii"))
        hostname = parts.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        port = parts.port
        host = hostname + (f":{port}" if port and port != 443 else "")
        if not hostname:
            raise ValueError("not an invite link: no host")
        return cls(host, code, secret, delegation)

    @staticmethod
    def _secret_of(segment: str) -> GroupSecret:
        decoded = base32_decode(segment)
        if len(decoded) != SECRET_LENGTH:
            raise ValueError(f"not an invite key: the secret is {len(decoded)} bytes")
        return GroupSecret(decoded)

    def __repr__(self) -> str:
        return PREFIX + self.code + "-..." + ("" if self.host == DEFAULT_HOST else "@" + self.host)


# ------------------------------------------ delegations and credentials (CBOR)
# The Java records of JoinCredentials, as dicts in declared field order; a
# GroupId or PeerId is its string, a byte[] a byte string.

def delegation_view(invite_key: bytes, group: str, not_after_millis: int, label: str) -> dict:
    """DelegationView: the bytes a founder signs when delegating."""
    return {"inviteKey": invite_key, "group": group,
            "notAfterMillis": int(not_after_millis), "label": label}


def credential_view(candidate: str, group: str) -> dict:
    """CredentialView: the bytes the invite key (or a founder) signs per candidate."""
    return {"candidate": candidate, "group": group}


def _key_bytes(identity_or_seed) -> Identity:
    if isinstance(identity_or_seed, Identity):
        return identity_or_seed
    if isinstance(identity_or_seed, (bytes, bytearray)) and len(identity_or_seed) == 32:
        return Identity.from_seed(bytes(identity_or_seed))
    raise ValueError("an invite signing key is an Identity or its 32-byte seed")


def delegate(founder: Identity, group: str, invite_public_key: bytes,
             not_after_millis: int, label: str | None) -> str:
    """JoinCredentials.delegate: the founder signs the invite key bound to the
    group with an expiry and a label; returns the base64 delegation string."""
    if not isinstance(invite_public_key, (bytes, bytearray)) or len(invite_public_key) != 32:
        raise ValueError("an invite key is a raw 32-byte Ed25519 public key")
    text = label or ""
    view = delegation_view(bytes(invite_public_key), group, not_after_millis, text)
    delegation = {"founderKey": founder.public_raw, "inviteKey": bytes(invite_public_key),
                  "group": group, "notAfterMillis": int(not_after_millis), "label": text,
                  "signature": founder.sign(cbor.dumps(view))}
    return base64.b64encode(cbor.dumps(delegation)).decode("ascii")


def decode_delegation(delegation: str) -> dict:
    """The Delegation record a delegation string carries, in declared field
    order. Raises ValueError when the string is not a delegation."""
    try:
        parsed = cbor.loads(base64.b64decode(delegation.strip()))
    except Exception as e:  # noqa: BLE001 - every decoding failure is one answer
        raise ValueError("not a delegation string") from e
    if (not isinstance(parsed, dict)
            or not isinstance(parsed.get("founderKey"), bytes)
            or not isinstance(parsed.get("inviteKey"), bytes)
            or not isinstance(parsed.get("signature"), bytes)
            or not isinstance(parsed.get("group"), str)
            or not isinstance(parsed.get("notAfterMillis"), int)
            or isinstance(parsed.get("notAfterMillis"), bool)):
        raise ValueError("not a delegation string")
    return {"founderKey": parsed["founderKey"], "inviteKey": parsed["inviteKey"],
            "group": parsed["group"], "notAfterMillis": parsed["notAfterMillis"],
            "label": parsed.get("label") if isinstance(parsed.get("label"), str) else "",
            "signature": parsed["signature"]}


def delegation_info(delegation: str) -> dict:
    """JoinCredentials.describe: founder (PeerID), invite_key, group,
    not_after_millis, label."""
    d = decode_delegation(delegation)
    return {"founder": derive_id(d["founderKey"]), "invite_key": d["inviteKey"],
            "group": d["group"], "not_after_millis": d["notAfterMillis"], "label": d["label"]}


def delegation_group(delegation: str) -> str:
    """The GroupID a delegation names."""
    return decode_delegation(delegation)["group"]


def issue_delegated(delegation: str, invite_signing_key, candidate: str) -> str:
    """JoinCredentials.issueDelegated: the invite key's signature over
    (candidate, group) under the delegation, as the ``d1:`` credential string.
    ``invite_signing_key`` is the invite Identity or its 32-byte seed."""
    parsed = decode_delegation(delegation)
    key = _key_bytes(invite_signing_key)
    view = cbor.dumps(credential_view(candidate, parsed["group"]))
    credential = {"delegation": parsed, "signature": key.sign(view)}
    return DELEGATED_PREFIX + base64.b64encode(cbor.dumps(credential)).decode("ascii")


def decode_delegated(credential: str) -> dict:
    """The DelegatedCredential record of a ``d1:`` credential string."""
    if not isinstance(credential, str) or not credential.strip().startswith(DELEGATED_PREFIX):
        raise ValueError("not a delegated credential")
    try:
        parsed = cbor.loads(base64.b64decode(_strip_prefix(credential.strip())))
    except Exception as e:  # noqa: BLE001
        raise ValueError("not a delegated credential") from e
    if (not isinstance(parsed, dict) or not isinstance(parsed.get("delegation"), dict)
            or not isinstance(parsed.get("signature"), bytes)):
        raise ValueError("not a delegated credential")
    delegation = decode_delegation(base64.b64encode(cbor.dumps(parsed["delegation"])).decode("ascii"))
    return {"delegation": delegation, "signature": parsed["signature"]}


def _strip_prefix(encoded: str) -> str:
    return encoded[len(DELEGATED_PREFIX):] if encoded.startswith(DELEGATED_PREFIX) else encoded


def credential_hash(credential: str) -> bytes:
    """JoinCredentials.hash: SHA-256 of the credential's decoded bytes, which a
    JOIN_CREDENTIAL revocation names to refuse one holder."""
    return hashlib.sha256(base64.b64decode(_strip_prefix(credential.strip()))).digest()


def delegation_hash(delegation_or_credential: str) -> bytes:
    """JoinCredentials.delegationHash: SHA-256 of the delegation's bytes, from
    a delegation string or a delegated credential; revoking it refuses every
    credential issued under it."""
    text = delegation_or_credential.strip()
    delegation = (decode_delegated(text)["delegation"] if text.startswith(DELEGATED_PREFIX)
                  else decode_delegation(text))
    return hashlib.sha256(cbor.dumps(delegation)).digest()


def delegation_verifies(delegation: dict, group_ad_issuer: str, group_id: str, now_ms: int) -> bool:
    """The delegation half of JoinCredentials.verify: the founder key hashes
    to the founding's issuer, the delegation names the group, it has not
    expired at ``now_ms`` (ten minutes of skew allowed), and the founder's
    signature verifies over the DelegationView."""
    try:
        if (len(delegation["founderKey"]) != 32 or len(delegation["inviteKey"]) != 32
                or derive_id(delegation["founderKey"]) != group_ad_issuer
                or delegation["group"] != group_id
                or int(now_ms) - EXPIRY_SKEW_MILLIS > int(delegation["notAfterMillis"])):
            return False
        view = cbor.dumps(delegation_view(delegation["inviteKey"], delegation["group"],
                                          delegation["notAfterMillis"], delegation["label"]))
        return Identity.verify(delegation["founderKey"], view, delegation["signature"])
    except (KeyError, TypeError, ValueError):
        return False


def delegated_credential_admits(credential: str, candidate: str, group_ad_issuer: str,
                                group_id: str, now_ms: int) -> bool:
    """JoinCredentials.admits for the delegated shape, with public data only:
    the delegation verifies against the founding's issuer and group at
    ``now_ms``, and the invite key's signature verifies over
    (candidate, group). Revocation is the caller's (the peer's registry)."""
    try:
        parsed = decode_delegated(credential)
    except ValueError:
        return False
    delegation = parsed["delegation"]
    if not delegation_verifies(delegation, group_ad_issuer, group_id, now_ms):
        return False
    view = cbor.dumps(credential_view(candidate, group_id))
    return Identity.verify(delegation["inviteKey"], view, parsed["signature"])


def judge_delegated_credential(credential: str, candidate: str, group_ad_issuer: str,
                               group_id: str, now_ms: int) -> str:
    """JoinCredentials.judge for the delegated shape: ``"valid"``, ``"expired"``
    (every check but the expiry passes), or ``"invalid"``. A member admitted
    while the delegation was valid is re-admitted under the same credential
    after it expires (SPEC §5.1, v0.1.20), so expiry alone is not a refusal
    for a peer that joined in time."""
    try:
        parsed = decode_delegated(credential)
    except ValueError:
        return "invalid"
    delegation = parsed["delegation"]
    try:
        not_after = int(delegation["notAfterMillis"])
    except (KeyError, TypeError, ValueError):
        return "invalid"
    # Judge everything but the expiry by asking at an instant inside the window.
    if not delegation_verifies(delegation, group_ad_issuer, group_id, not_after):
        return "invalid"
    view = cbor.dumps(credential_view(candidate, group_id))
    if not Identity.verify(delegation["inviteKey"], view, parsed["signature"]):
        return "invalid"
    return "expired" if int(now_ms) - EXPIRY_SKEW_MILLIS > not_after else "valid"


def hints_for(key: InviteKey, delegation: str, self_peer_id: str) -> dict:
    """SocialGroups.hintsFor: the ``aspace:join`` hint a holder of a key presents."""
    return {HINT_KEY: issue_delegated(delegation, key.secret.invite_private_seed(), self_peer_id)}
