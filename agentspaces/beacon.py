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
sorted, no whitespace, exactly as Jackson writes them. A signed document
arrives as exactly its canonical JSON, signature last (HLC round seven,
2026-11-08); a reader ignores unknown fields of an unsigned one and refuses a named field of
another type (2026-11-09). The document
never carries a content key, a credential, or a membership hint."""

import base64
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import records
from .wire import utf16_order
from .identity import Identity, derive_id, verify_signed_group_ad
from . import seed as seed_module
from .seed import Seed

VERSION = 1
WELL_KNOWN = "/.well-known/agentspaces/beacon.json"
# The largest document accepted (UrlLocator.Options.maxBytes).
MAX_DOCUMENT_BYTES = 64 * 1024
FORBIDDEN_PARAMETERS = ("content-key", "contentkey", "credential", "membership", "hints",
                        "secret", "invite-secret", "join-credential")
URI_PREFIX = "aspace://"
# The transports this client dials (``agentspaces.seed``): tcp and tls.
CLIENT_TRANSPORTS = seed_module.CLIENT_TRANSPORTS


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


# Java's field types: an int (v, a seed's priority, a wire hint) and a long (ttl).
_INT = (-(1 << 31), (1 << 31) - 1)
_LONG = (-(1 << 63), (1 << 63) - 1)
# Jackson's short escapes; every other control character is \u00XX, upper-case.
_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _integer(value, bounds, what: str) -> int:
    """A JSON integer the Java field holds; None reads as Java's default 0."""
    if value is None:
        return 0
    if type(value) is not int or not bounds[0] <= value <= bounds[1]:
        raise ValueError(f"{what} is no integer a Java {'int' if bounds is _INT else 'long'} holds")
    return value


def _text(value, what: str):
    if value is not None and type(value) is not str:
        raise ValueError(f"{what} is not text")
    return value


def _sorted_map(mapping, value, what: str) -> dict:
    """A Map<String, X> as Jackson's ORDER_MAP_ENTRIES_BY_KEYS writes it: keys in String.compareTo
    order, UTF-16 code units (HLC round seven, 2026-11-08)."""
    if not isinstance(mapping, dict):
        raise ValueError(f"{what} is not an object")
    return {k: value(mapping[k], f"{what}.{k}") for k in sorted(mapping, key=utf16_order)}


def _canonical_group(group) -> dict:
    if not isinstance(group, dict) or type(group.get("name")) is not str:
        raise ValueError("a group is an object with a name")
    out = {"name": group["name"]}
    for key in ("id", "founding"):
        if group.get(key) is not None:
            out[key] = _text(group[key], key)
    seeds = [] if group.get("seeds") is None else group["seeds"]
    if not isinstance(seeds, list) or not all(isinstance(seed, dict) for seed in seeds):
        raise ValueError("seeds are a list of objects")
    out["seeds"] = [{"transport": _text(seed.get("transport"), "transport"),
                     "address": _text(seed.get("address"), "address"),
                     "priority": _integer(seed.get("priority"), _INT, "priority")} for seed in seeds]
    if group.get("wire") is not None:
        out["wire"] = _sorted_map(group["wire"], lambda v, w: None if v is None else _integer(v, _INT, w), "wire")
    if group.get("multicast") is not None:
        out["multicast"] = _text(group["multicast"], "multicast")
    if group.get("parameters") is not None:
        out["parameters"] = _sorted_map(group["parameters"], _text, "parameters")
    if group.get("invite") is not None:
        out["invite"] = _text(group["invite"], "invite")
    return out


def _json_string(text: str, signed: bool) -> str:
    """A string as Jackson writes it: ``"`` and ``\\`` escaped, the short escapes, any other
    control character as upper-case ``\\u00XX``, and everything else as is, except that the
    signed bytes come from Jackson's byte writer, which writes each UTF-16 surrogate as an
    upper-case ``\\uXXXX`` escape, so a code point past U+FFFF becomes its two surrogates
    (HLC round seven, 2026-11-08)."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif code < 0x20:
            out.append(f"\\u{code:04X}")
        elif signed and code > 0xFFFF:
            code -= 0x10000
            out.append(f"\\u{0xD800 + (code >> 10):04X}\\u{0xDC00 + (code & 0x3FF):04X}")
        elif signed and 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jackson_json(value, signed: bool) -> str:
    """Jackson's compact JSON of the canonical body: no whitespace, members in the order built."""
    if value is None:
        return "null"
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return _json_string(value, signed)
    if isinstance(value, list):
        return "[" + ",".join(_jackson_json(item, signed) for item in value) + "]"
    return "{" + ",".join(_json_string(k, signed) + ":" + _jackson_json(v, signed) for k, v in value.items()) + "}"


def _canonical_body(doc: dict) -> dict:
    """Every known field but ``signature``, in declared order (v, issuer, issuerKey, issued,
    ttl, groups), null fields omitted, each of its Java type or a ValueError."""
    body = {"v": _integer(doc.get("v"), _INT, "v")}
    for key in ("issuer", "issuerKey", "issued"):
        if doc.get(key) is not None:
            body[key] = _text(doc[key], key)
    body["ttl"] = _integer(doc.get("ttl"), _LONG, "ttl")
    groups = [] if doc.get("groups") is None else doc["groups"]
    if not isinstance(groups, list):
        raise ValueError("groups are a list")
    body["groups"] = [_canonical_group(g) for g in groups]
    return body


def canonical_bytes(doc: dict) -> bytes:
    """The bytes the signature covers: Java's ``canonicalBytes``, the canonical body as
    Jackson's byte writer writes it, map keys sorted, no whitespace."""
    return _jackson_json(_canonical_body(doc), signed=True).encode("utf-8")


def sign_document(issuer: Identity, issued_iso: str, ttl_seconds: int, groups: list) -> dict:
    """BeaconDocument.signed: a document issued and signed by ``issuer``."""
    doc = {"v": VERSION, "issuer": issuer.peer_id,
           "issuerKey": base64.b64encode(issuer.public_raw).decode("ascii"),
           "issued": issued_iso, "ttl": int(ttl_seconds), "groups": list(groups)}
    doc["signature"] = base64.b64encode(issuer.sign(canonical_bytes(doc))).decode("ascii")
    return doc


def to_json(doc: dict) -> bytes:
    """The document as one line of JSON, signature last: Java's ``toBytes``, which Jackson's
    text writer writes, so a code point past U+FFFF stays as it is."""
    body = _canonical_body(doc)
    if doc.get("signature") is not None:
        body["signature"] = _text(doc["signature"], "signature")
    return _jackson_json(body, signed=False).encode("utf-8")


def _canonical_base64(text) -> bool:
    """Whether ``text`` is absent or the padded standard base64 of the bytes it decodes to."""
    try:
        return text is None or base64.b64encode(base64.b64decode(text, validate=True)).decode("ascii") == text
    except (ValueError, TypeError):
        return False


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
        doc = parse_document(body)
    except ValueError as e:
        raise ValueError(f"GET {url}: {e}") from e
    verify_document(doc, beacon_peer)
    return doc


def _refuse_malformed_groups(doc: dict) -> None:
    """What Java's Group record refuses in a document signed or not: a group that is no object or
    has no name, a seed that is no object, and a parameter by a forbidden name (HLC round seven,
    2026-11-08)."""
    groups = doc.get("groups") or []
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict) or group.get("name") is None:
            raise ValueError("not a beacon document: a group is no object with a name")
        seeds = group.get("seeds") or []
        if isinstance(seeds, list) and not all(isinstance(seed, dict) for seed in seeds):
            raise ValueError("not a beacon document: a seed is no object")
        parameters = group.get("parameters")
        if isinstance(parameters, dict) and any(str(k).lower() in FORBIDDEN_PARAMETERS for k in parameters):
            raise ValueError("a beacon document never carries a secret")


def parse_document(body: bytes) -> dict:
    """The document the JSON bytes ``body`` hold. An unsigned document reads leniently in form,
    with whitespace, any member order, and unknown members, while every member it names holds
    its Java type, signed or not (SPEC v0.1.32 9.3, 2026-11-09): a group name sent as a number or
    a ttl sent as text refuses it, as Java's reader refuses it. A document that carries a
    signature must be exactly its canonical JSON, ``to_json`` of what it decodes to, as Java's
    BeaconDocument.parse requires (HLC round seven, 2026-11-08, owner ruling F3 applied to the
    beacon document): the signature covers ``canonical_bytes``, which
    are then the bytes received less the signature member, so whitespace, another member order,
    an unknown or repeated member, another escape, or a number in another form refuses the
    document instead of relabelling it. Raises ValueError for anything else."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("not a JSON document") from e
    if not isinstance(doc, dict):
        raise ValueError("not a beacon document")
    _refuse_malformed_groups(doc)
    _canonical_body(doc)
    if doc.get("signature") is not None and to_json(doc) != body:
        raise ValueError("a signed beacon document is not its canonical JSON")
    if doc.get("signature") is not None and not (_canonical_base64(doc["signature"])
                                                 and _canonical_base64(doc.get("issuerKey"))):
        raise ValueError("a signed beacon document's signature or key is not canonical base64")
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
    """The decoded SignedGroupAdvertisement a group carries, or None when it carries none.
    ValueError when the founding is no SignedGroupAdvertisement in the wire encoding (HLC
    round six, 2026-11-08, owner rulings F1 and F3)."""
    founding = group.get("founding")
    if not founding:
        return None
    try:
        raw = base64.b64decode(founding)
    except (ValueError, TypeError) as e:
        raise ValueError(f"the founding of {group.get('name')!r} is not base64") from e
    signed = records.decode(raw, "SignedGroupAdvertisement")
    if signed is None:
        raise ValueError(f"the founding of {group.get('name')!r} is no SignedGroupAdvertisement")
    return signed


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


seed_address = seed_module.seed_address


def seeds_of(group: dict, transports: tuple = CLIENT_TRANSPORTS) -> list:
    """The group's seeds this client can dial, by priority, as ``Seed(host, port,
    scheme)`` tuples; a seed of a scheme outside ``transports`` is skipped."""
    seeds = sorted((s for s in (group.get("seeds") or []) if isinstance(s, dict)),
                   key=lambda s: int(s.get("priority") or 0))
    out = []
    for seed in seeds:
        transport = str(seed.get("transport") or "tcp").lower()
        if transport not in transports or not seed.get("address"):
            continue
        try:
            host, port = seed_address(seed["address"])
        except ValueError:
            continue
        out.append(Seed(host, port, transport))
    return out
