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

"""The beacon document (SRAD discovery §3.5, appendix C; Java
BeaconDocument, UrlLocator): one JSON document a beacon serves at
``/.well-known/agentspaces/beacon.json`` (or a social beacon under
``/j/<code>``) carrying, per group, the name, the ``aspace://`` id, the
founding advertisement (base64 CBOR), the seeds, the wire hints, and, at a
social beacon, the public delegation; document-wide the issuer PeerID, its
raw key, the issue time, a TTL, and the issuer's Ed25519 signature over the
canonical bytes: every field but ``signature``, in declared order, map keys
sorted, no whitespace, exactly as Jackson writes them. A reader ignores
unknown fields. The document never carries a content key, a credential, or
a membership hint."""

import base64
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import cbor
from .identity import Identity, derive_id, verify_signed_group_ad

VERSION = 1
WELL_KNOWN = "/.well-known/agentspaces/beacon.json"
# The largest document accepted (UrlLocator.Options.maxBytes).
MAX_DOCUMENT_BYTES = 64 * 1024
FORBIDDEN_PARAMETERS = ("content-key", "contentkey", "credential", "membership", "hints",
                        "secret", "invite-secret", "join-credential")
URI_PREFIX = "aspace://"
# The transports this client dials: plain TCP only.
CLIENT_TRANSPORTS = ("tcp",)


# ------------------------------------------------------------ the document

def document_group(name: str, group_id: str | None = None, founding: str | None = None,
                   seeds: list | None = None, wire: dict | None = None,
                   multicast: str | None = None, parameters: dict | None = None,
                   invite: str | None = None) -> dict:
    """BeaconDocument.Group: ``seeds`` are (transport, address) pairs or
    seed dicts, numbered by position. Parameters by a forbidden name are
    refused: a document never carries a secret."""
    for key in (parameters or {}):
        if str(key).lower() in FORBIDDEN_PARAMETERS:
            raise ValueError(f"a beacon document never carries {key!r}")
    group = {"name": name}
    if group_id is not None:
        group["id"] = group_id if group_id.startswith(URI_PREFIX) else URI_PREFIX + group_id
    if founding is not None:
        group["founding"] = founding
    group["seeds"] = [seed if isinstance(seed, dict)
                      else {"transport": seed[0], "address": seed[1], "priority": i}
                      for i, seed in enumerate(seeds or [])]
    if wire is not None:
        group["wire"] = dict(wire)
    if multicast is not None:
        group["multicast"] = multicast
    if parameters is not None:
        group["parameters"] = dict(parameters)
    if invite is not None:
        group["invite"] = invite
    return group


def _canonical_group(group: dict) -> dict:
    out = {"name": group.get("name")}
    for key in ("id", "founding"):
        if group.get(key) is not None:
            out[key] = group[key]
    seeds = []
    for seed in group.get("seeds") or []:
        seeds.append({"transport": seed.get("transport"), "address": seed.get("address"),
                      "priority": int(seed.get("priority") or 0)})
    out["seeds"] = seeds
    if group.get("wire") is not None:
        out["wire"] = {k: int(v) for k, v in sorted(group["wire"].items())}
    if group.get("multicast") is not None:
        out["multicast"] = group["multicast"]
    if group.get("parameters") is not None:
        out["parameters"] = {k: group["parameters"][k] for k in sorted(group["parameters"])}
    if group.get("invite") is not None:
        out["invite"] = group["invite"]
    return out


def _jackson_json(value) -> bytes:
    """Jackson's compact JSON: no whitespace, non-ASCII unescaped, control
    characters as short escapes or upper-case ``\\u00XX``."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    text = re.sub(r"\\u00([0-9a-f]{2})", lambda m: "\\u00" + m.group(1).upper(), text)
    return text.encode("utf-8")


def canonical_bytes(doc: dict) -> bytes:
    """The bytes the signature covers: every known field but ``signature``,
    in declared order (v, issuer, issuerKey, issued, ttl, groups), null
    fields omitted, map keys sorted, no whitespace."""
    body = {"v": int(doc.get("v") or 0)}
    for key in ("issuer", "issuerKey", "issued"):
        if doc.get(key) is not None:
            body[key] = doc[key]
    body["ttl"] = int(doc.get("ttl") or 0)
    body["groups"] = [_canonical_group(g) for g in (doc.get("groups") or [])]
    return _jackson_json(body)


def sign_document(issuer: Identity, issued_iso: str, ttl_seconds: int, groups: list) -> dict:
    """BeaconDocument.signed: a document issued and signed by ``issuer``."""
    doc = {"v": VERSION, "issuer": issuer.peer_id,
           "issuerKey": base64.b64encode(issuer.public_raw).decode("ascii"),
           "issued": issued_iso, "ttl": int(ttl_seconds), "groups": list(groups)}
    doc["signature"] = base64.b64encode(issuer.sign(canonical_bytes(doc))).decode("ascii")
    return doc


def to_json(doc: dict) -> bytes:
    """The document as one line of JSON, signature last."""
    body = json.loads(canonical_bytes(doc))
    if doc.get("signature") is not None:
        body["signature"] = doc["signature"]
    return _jackson_json(body)


def document_signer(doc: dict) -> str | None:
    """BeaconDocument.signer: the PeerID the carried key hashes to, when it
    equals ``issuer`` and the signature verifies under it; else None."""
    try:
        key = base64.b64decode(doc.get("issuerKey") or "")
        signature = base64.b64decode(doc.get("signature") or "")
        if len(key) != 32 or not signature or not isinstance(doc.get("issuer"), str):
            return None
        signer = derive_id(key)
        if signer != doc["issuer"]:
            return None
        return signer if Identity.verify(key, canonical_bytes(doc), signature) else None
    except (ValueError, TypeError):
        return None


def verify_document(doc: dict, beacon_peer: str | None = None) -> str | None:
    """UrlLocator.hint's two checks: a carried signature must verify, and a
    pinned ``beacon_peer`` must be the verified signer. Returns the signer
    (None for an unsigned, unpinned document); raises ValueError otherwise."""
    if not isinstance(doc, dict) or int(doc.get("v") or 0) < 1:
        raise ValueError("not a beacon document")
    signer = document_signer(doc)
    if doc.get("signature") is not None and signer is None:
        raise ValueError("the beacon document's signature does not verify")
    if beacon_peer is not None and signer != beacon_peer:
        raise ValueError(f"the beacon document is not signed by the pinned beacon {beacon_peer}")
    return signer


# -------------------------------------------------------------- fetching

def _http_get(url: str, timeout: float, allow_plain: bool) -> bytes:
    """One GET, at most two redirects each held to the same scheme policy,
    the body capped at MAX_DOCUMENT_BYTES. Tests stub this."""
    class Redirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if req.redirect_dict and len(req.redirect_dict) >= 2:
                raise urllib.error.HTTPError(newurl, code, "redirect limit", headers, fp)
            _check_scheme(newurl, allow_plain)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(Redirects)
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "agentspaces-python/1"})
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f"GET {url}: HTTP {response.status}")
        body = response.read(MAX_DOCUMENT_BYTES + 1)
    if len(body) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"GET {url}: the document exceeds {MAX_DOCUMENT_BYTES} bytes")
    return body


def _check_scheme(url: str, allow_plain: bool) -> None:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme != "https" and not (scheme == "http" and allow_plain):
        raise ValueError(f"refusing {url}: only https (allow_plain permits http)")
    if not parts.hostname:
        raise ValueError(f"refusing {url}: no host")


def fetch_beacon_document(url: str, *, allow_plain: bool = False, beacon_peer: str | None = None,
                          timeout: float = 3.0) -> dict:
    """Fetches, parses, and verifies a beacon document: https only unless
    ``allow_plain``; at most 64 KiB; a carried signature must verify under
    a key hashing to ``issuer``; with ``beacon_peer`` that signer is
    required. Raises ValueError (policy, shape, signature) or OSError."""
    _check_scheme(url, allow_plain)
    try:
        body = _http_get(url, timeout, allow_plain)
    except urllib.error.URLError as e:
        raise OSError(f"GET {url}: {e.reason}") from e
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"GET {url}: not a JSON document") from e
    verify_document(doc, beacon_peer)
    return doc


# -------------------------------------------------------------- selection

def parse_group_id(text: str | None) -> str | None:
    """The bare GroupID of an ``aspace://<id>`` URI or a bare id."""
    if not isinstance(text, str) or not text.strip():
        return None
    text = text.strip()
    return text[len(URI_PREFIX):] if text.startswith(URI_PREFIX) else text


def group_from_document(doc: dict, group_id: str | None = None, name: str | None = None) -> dict:
    """The group a document carries: by id when given, else by name, else
    the only group (a social beacon serves one per code). Raises ValueError
    when there is no such group."""
    groups = [g for g in (doc.get("groups") or []) if isinstance(g, dict)]
    if group_id is not None:
        wanted = parse_group_id(group_id)
        for group in groups:
            if parse_group_id(group.get("id")) == wanted:
                return group
        raise ValueError(f"the beacon document carries no group {group_id}")
    if name is not None:
        for group in groups:
            if group.get("name") == name:
                return group
        raise ValueError(f"the beacon document carries no group named {name!r}")
    if len(groups) == 1:
        return groups[0]
    raise ValueError(f"the beacon document carries {len(groups)} groups; name one")


def founding_of(group: dict) -> dict | None:
    """The decoded SignedGroupAdvertisement a group carries, or None."""
    founding = group.get("founding")
    if not founding:
        return None
    try:
        signed = cbor.loads(base64.b64decode(founding))
    except (ValueError, TypeError) as e:
        raise ValueError(f"the founding of {group.get('name')!r} is not base64 CBOR") from e
    return signed if isinstance(signed, dict) else None


def verified_group_id(group: dict, expected: str | None = None) -> str:
    """The GroupID the group's founding verifies to (the four checks of
    SPEC §5.1), which must also be the group's ``id`` and, when given, the
    ``expected`` id. Raises ValueError otherwise."""
    signed = founding_of(group)
    if signed is None:
        raise ValueError(f"the beacon document carries no founding for {group.get('name')!r}")
    derived = verify_signed_group_ad(signed)
    if derived is None:
        raise ValueError(f"the founding of {group.get('name')!r} does not verify")
    if group.get("id") is not None and parse_group_id(group["id"]) != derived:
        raise ValueError(f"the founding of {group.get('name')!r} derives to {derived}, not its id")
    if expected is not None and parse_group_id(expected) != derived:
        raise ValueError(f"the founding of {group.get('name')!r} derives to {derived}, "
                         f"not {expected}")
    return derived


def seed_address(address: str) -> tuple:
    """``host:port`` (``[v6]:port``) as (host, port)."""
    text = str(address).strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"not a seed address: {address!r}")
    return host, int(port)


def seeds_of(group: dict, transports: tuple = CLIENT_TRANSPORTS) -> list:
    """The group's seeds this client can dial, by priority, as (host, port)."""
    seeds = sorted((s for s in (group.get("seeds") or []) if isinstance(s, dict)),
                   key=lambda s: int(s.get("priority") or 0))
    out = []
    for seed in seeds:
        transport = seed.get("transport") or "tcp"
        if str(transport).lower() not in transports or not seed.get("address"):
            continue
        try:
            out.append(seed_address(seed["address"]))
        except ValueError:
            continue
    return out
