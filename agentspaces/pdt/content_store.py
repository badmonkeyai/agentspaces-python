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

"""The content store's entry records (PDT 2 phase 0, P2-S-02; srad/agentspaces-pdt2.md §3.2.2,
§6.10.3 rule 18, §6.10.4): ``StorePin#v1``, a member's request that a store hold a root, and
``StoreReceipt#v1``, a store's statement that it holds one. Both are protocol records in the
annex I schemas of §6.10.4, written to the content space as ordinary signed, leased entries:

    StorePin { v: int, root: String, kind: String, lease: long, copies: int, requester: PeerId,
               haves: list<String>, attrs: map<String,String> ?null }
    StoreReceipt { v: int, root: String, holder: PeerId, bytes: long, until: long, blind: boolean }

A record is a dict in Java's field order (``attrs`` leaves the wire when None) and travels as its
``cbor.dumps`` bytes. ``decode_store_pin`` and ``decode_store_receipt`` read the wire encoding
alone and accept exactly the schema's fields in their places (owner rulings F1 and F3), so a
payload with a field the schema does not name is undecodable. The types travel ungated, since a
level-1 replica stores and replicates an entry of an unknown type without decoding it, and a
change of shape takes a new type name and never an added field (P2-F-08). ``lease`` counts
seconds and ``until`` holds epoch milliseconds.

Since the PDT 2 follow-ups of 2026-11-09 (F1) the pin entry a store takes is ``SignedPin#v1``, the
requester's ``StorePin`` terms under the requester's Ed25519 signature, so a store charges only the
member who signed them:

    SignedPin { v: int, pin: StorePin, left: int, notAfter: long, key: bytes, sig: bytes }

The signature covers ``consent_bytes``, the canonical CBOR of ``{purpose, group, pin, notAfter}``,
under ``key``, whose peer id is the pin's requester. ``left`` counts the copies still to place, which
a store that forwards a copy lowers by one without speaking for the requester, and no store takes
the pin after ``notAfter``, epoch milliseconds."""

from __future__ import annotations

from .. import cbor
from ..identity import Identity, derive_id
from ..peer import lease_of, present
from . import cids
from .nodes import NodeFormatError, kind_of

STORE_PIN_TYPE = "ai.badmonkey.agentspaces.agent.content.StorePin#v1"
STORE_RECEIPT_TYPE = "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1"
SIGNED_PIN_TYPE = "ai.badmonkey.agentspaces.agent.content.SignedPin#v1"
VERSION = 1
KIND_TREE, KIND_ARTIFACT = "tree", "artifact"
ROOT_TAG, REQUESTER_TAG, HOLDER_TAG = "root", "requester", "holder"
MAX_HAVES = 8
MAX_ATTRS, MAX_ATTRS_BYTES = 32, 4 * 1024
#: The text a pin's consent opens with, so the signature serves no other record of the requester's key.
PURPOSE = "agentspaces.store-pin"
KEY_BYTES, SIG_BYTES = 32, 64

PIN_FIELDS = ("v", "root", "kind", "lease", "copies", "requester", "haves", "attrs")
RECEIPT_FIELDS = ("v", "root", "holder", "bytes", "until", "blind")
SIGNED_PIN_FIELDS = ("v", "pin", "left", "notAfter", "key", "sig")


def _java_integer(value, bits: int) -> bool:
    """Whether ``value`` is an integer, a boolean excluded, that a Java integer of ``bits`` holds."""
    return type(value) is int and -(1 << (bits - 1)) <= value < (1 << (bits - 1))


def _peer_id(value) -> bool:
    """Whether a field holds a PeerId as Java reads one: non-empty text."""
    return isinstance(value, str) and bool(value)


# ------------------------------------------------------------------ StorePin

def store_pin(root: str, kind: str, lease: int, copies: int, requester: str, haves: list[str] | None = None,
              attrs: dict | None = None) -> dict:
    """A ``StorePin`` in Java field order: ``haves`` an empty list when None, ``attrs`` in canonical
    key order and off the wire when None. ValueError for attrs that are not text to text."""
    record = {"v": VERSION, "root": root, "kind": kind, "lease": int(lease), "copies": int(copies),
              "requester": requester, "haves": list(haves or [])}
    if attrs is not None:
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in attrs.items()):
            raise ValueError(f"StorePin attrs map text to text, got {attrs!r}")
        record["attrs"] = cbor.canonical_map(attrs)
    return record


def store_pin_tags(record: dict) -> dict:
    return {ROOT_TAG: record["root"], REQUESTER_TAG: record["requester"]}


def decode_store_pin(raw: bytes) -> dict | None:
    """The ``StorePin`` the bytes hold, or None when they are undecodable: bytes outside the wire
    encoding, a field missing, out of its place or outside the schema, or a field of another kind."""
    try:
        value = cbor.loads(raw)
    except ValueError:
        return None
    return _store_pin_value(value)


def _store_pin_value(value) -> dict | None:
    """The decoded value when it holds a ``StorePin`` under its schema, else None."""
    if not isinstance(value, dict) or list(value) != [f for f in PIN_FIELDS if f != "attrs" or f in value]:
        return None
    if not (_java_integer(value["v"], 32) and _java_integer(value["copies"], 32) and _java_integer(value["lease"], 64)):
        return None
    if not all(isinstance(value[f], str) for f in ("root", "kind")) or not _peer_id(value["requester"]):
        return None
    if not isinstance(value["haves"], list) or not all(isinstance(h, str) for h in value["haves"]):
        return None
    if "attrs" in value:
        attrs = value["attrs"]
        if not isinstance(attrs, dict) or not cbor.is_canonical_map(attrs):
            return None
        if not all(isinstance(v, str) for v in attrs.values()):
            return None
    return value


def store_pin_violation(r: dict) -> str | None:
    """The first broken bound of §3.2.2 that a store judges before it takes the pin, or None."""
    if r["v"] != VERSION:
        return f"unsupported StorePin version {r['v']}"
    if not cids.is_cid(r["root"]):
        return "root is not a CID"
    if r["kind"] not in (KIND_TREE, KIND_ARTIFACT):
        return f"unknown kind {r['kind']}"
    if r["lease"] < 1:
        return f"lease of {r['lease']} seconds"
    if r["copies"] < 1:
        return "copies below 1"
    if len(r["haves"]) > MAX_HAVES:
        return f"more than {MAX_HAVES} haves"
    if not all(cids.is_cid(h) for h in r["haves"]):
        return "have is not a CID"
    attrs = r.get("attrs")
    if attrs is not None:
        if len(attrs) > MAX_ATTRS:
            return f"more than {MAX_ATTRS} attrs"
        if sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) for k, v in attrs.items()) > MAX_ATTRS_BYTES:
            return f"attrs larger than {MAX_ATTRS_BYTES} bytes"
    return None


# ------------------------------------------------------------------ SignedPin (PDT 2 follow-ups, 2026-11-09, F1)

def consent_bytes(pin: dict, group: str, not_after: int) -> bytes:
    """What a requester signs: the canonical CBOR of ``{purpose, group, pin, notAfter}`` in that order."""
    return cbor.dumps({"purpose": PURPOSE, "group": group, "pin": pin, "notAfter": int(not_after)})


def sign_pin(pin: dict, group: str, not_after: int, requester: Identity) -> dict:
    """The ``SignedPin`` of a requester's terms for every copy they ask, in Java field order.
    ValueError when the terms name another requester, since only that member signs them."""
    if pin["requester"] != requester.peer_id:
        raise ValueError(f"the pin names requester {pin['requester']}, and only that member signs it")
    return {"v": VERSION, "pin": pin, "left": int(pin["copies"]), "notAfter": int(not_after),
            "key": requester.public_raw, "sig": requester.sign(consent_bytes(pin, group, not_after))}


def signed_pin_tags(record: dict) -> dict:
    """The tags a signed pin is written with: its pin's."""
    return store_pin_tags(record["pin"])


def decode_signed_pin(raw: bytes) -> dict | None:
    """The ``SignedPin`` the bytes hold, its pin read under the ``StorePin`` schema, or None when
    they are undecodable (as ``decode_store_pin``)."""
    try:
        value = cbor.loads(raw)
    except ValueError:
        return None
    if not isinstance(value, dict) or list(value) != list(SIGNED_PIN_FIELDS):
        return None
    if not (_java_integer(value["v"], 32) and _java_integer(value["left"], 32) and _java_integer(value["notAfter"], 64)):
        return None
    if not all(isinstance(value[f], bytes) for f in ("key", "sig")) or _store_pin_value(value["pin"]) is None:
        return None
    return value


def signed_pin_violation(r: dict) -> str | None:
    """The first broken rule of the version, the pin's bounds, the copies left, the deadline's
    sign, and the key and signature lengths, or None; ``signed_pin_consented`` checks the signature."""
    if r["v"] != VERSION:
        return f"unsupported SignedPin version {r['v']}"
    terms = store_pin_violation(r["pin"])
    if terms is not None:
        return terms
    if not 1 <= r["left"] <= r["pin"]["copies"]:
        return f"left {r['left']} is outside 1 to {r['pin']['copies']} copies"
    if r["notAfter"] < 0:
        return "negative notAfter"
    if len(r["key"]) != KEY_BYTES:
        return "key is not 32 bytes"
    if len(r["sig"]) != SIG_BYTES:
        return "sig is not 64 bytes"
    return None


def signed_pin_consented(r: dict, group: str) -> bool:
    """Whether the requester the terms name signed them for this group and deadline: the key's
    peer id is the requester's and the signature verifies over ``consent_bytes``."""
    key = r["key"]
    return (len(key) == KEY_BYTES and derive_id(key) == r["pin"]["requester"]
            and Identity.verify(key, consent_bytes(r["pin"], group, r["notAfter"]), r["sig"]))


# ------------------------------------------------------------------ StoreReceipt

def store_receipt(root: str, holder: str, size: int, until: int, blind: bool) -> dict:
    """A ``StoreReceipt`` in Java field order; ``size`` is the ``bytes`` the store holds for the root."""
    return {"v": VERSION, "root": root, "holder": holder, "bytes": int(size), "until": int(until), "blind": bool(blind)}


def store_receipt_tags(record: dict) -> dict:
    return {ROOT_TAG: record["root"], HOLDER_TAG: record["holder"]}


def decode_store_receipt(raw: bytes) -> dict | None:
    """The ``StoreReceipt`` the bytes hold, or None when they are undecodable (as ``decode_store_pin``)."""
    try:
        value = cbor.loads(raw)
    except ValueError:
        return None
    if not isinstance(value, dict) or list(value) != list(RECEIPT_FIELDS):
        return None
    if not (_java_integer(value["v"], 32) and _java_integer(value["bytes"], 64) and _java_integer(value["until"], 64)):
        return None
    if not isinstance(value["root"], str) or not _peer_id(value["holder"]) or type(value["blind"]) is not bool:
        return None
    return value


def store_receipt_violation(r: dict) -> str | None:
    """The first broken rule of the version, the root, and the signs of the counts, or None."""
    if r["v"] != VERSION:
        return f"unsupported StoreReceipt version {r['v']}"
    if not cids.is_cid(r["root"]):
        return "root is not a CID"
    if r["bytes"] < 0:
        return "negative bytes"
    if r["until"] < 0:
        return "negative until"
    return None


# ------------------------------------------------------------------ the content-store card (PDT 2 phase 7)

#: The ``access.kind`` of a content store's card, and the ``costHints`` key of its price per GiB-month (§3.2.1).
STORE_KIND = "content-store"
PRICE_HINT = "pricePerGibMonth"
_DECIMALS = ("capacity", "free", "maxObject", "leaseMax", "leaseDefault", "copiesMax")
_LISTS = ("codecs", "hashes", "sealing", "pin", "delegates")
_BOOLEANS = ("blind", "challenge")


def _decimal(text) -> int | None:
    """Canonical decimal text: no sign, no leading zero, within a Java long (rule 19 of §6.10.3)."""
    if not isinstance(text, str) or not text.isascii() or not text.isdigit() or (len(text) > 1 and text[0] == "0"):
        return None
    value = int(text)
    return value if value < 1 << 63 else None


def store_card(card: dict) -> dict | None:
    """The ``access`` and ``costHints`` of a ``content-store`` AssetCard read as rule 19 writes them (PDT 2 phase 7,
    P2-C-01, P2-F-03): integers in canonical decimal, booleans ``true`` or ``false``, lists comma-separated without
    spaces, and the price per GiB-month (0 without a hint). None for a card of another kind, or one whose ``free``,
    ``maxObject``, ``blind``, or price does not read, which a chooser skips as Java's ``StoreChooser`` does; another
    key that does not read reads as None, and keys this release does not name are ignored."""
    access = card.get("access") or {}
    if access.get("kind") != STORE_KIND:
        return None
    read = {"issuer": card.get("issuer"), "tier": access.get("tier"), "policy": access.get("policy"),
            "waiting": access.get("waiting")}
    for key in _DECIMALS:
        read[key] = _decimal(access.get(key))
    for key in _LISTS:
        text = access.get(key)
        read[key] = None if not isinstance(text, str) else [item for item in text.split(",") if item]
    for key in _BOOLEANS:
        read[key] = {"true": True, "false": False}.get(access.get(key))
    price = (card.get("costHints") or {}).get(PRICE_HINT)
    read["price"] = 0 if price is None else _decimal(price)
    if read["free"] is None or read["maxObject"] is None or read["blind"] is None or read["price"] is None:
        return None
    return read


def _card_expires_ms(card: dict) -> int:
    from ..identity import parse_duration_millis, parse_instant_millis
    try:
        return parse_instant_millis(card["issued"]) + parse_duration_millis(card["ttl"])
    except (KeyError, TypeError, ValueError):
        return 0


def choose(cards, size: int, copies: int, sealed: bool = False, tier: str | None = None, max_price: int | None = None,
           avoid=(), now_ms: int = 0) -> list[dict]:
    """The stores to ask, best first, as Java's ``StoreChooser.choose``: only an unexpired card of kind
    ``content-store`` with room for ``size`` bytes, a blind store only for sealed content, the tier and the highest
    price when given, and no store ``avoid`` names; ranked by price (no hint is free), then by free bytes, most first,
    then by issuer; one card per store, at most ``copies``."""
    if copies < 1 or size < 0:
        raise ValueError("a need asks for at least one copy of a non-negative size")
    fit = []
    for card in cards:
        read = store_card(card)
        if read is None or _card_expires_ms(card) <= now_ms or card.get("issuer") in avoid:
            continue
        if read["free"] < size or read["maxObject"] < size or (read["blind"] and not sealed):
            continue
        if (tier is not None and read["tier"] != tier) or (max_price is not None and read["price"] > max_price):
            continue
        fit.append((read["price"], -read["free"], str(card.get("issuer")), card))
    fit.sort(key=lambda r: r[:3])
    chosen: dict[str, dict] = {}
    for _price, _free, issuer, card in fit:
        if len(chosen) == copies:
            break
        chosen.setdefault(issuer, card)
    return list(chosen.values())


class Stores:
    """A requester's view of the group's content stores (PDT 2 phase 7, P2-C-01; srad/agentspaces-pdt2.md §3.2.2,
    S2 of §6.4), as Java's ``Stores`` writes pins: it chooses stores over the ``content-store`` cards the ads stream
    carried, skipping a store whose card says it waits for an authorizer, and writes one ``SignedPin`` naming them in
    ``pdt.stores``, signed by this peer as the pin's requester (F1 of §10.9), under an entry lease and a deadline of
    the pin's lease, at most ``PIN_ENTRY_LEASE_MS`` (an hour), so no store takes a copy later (R2 of §10.11). It
    holds a tree it pins, so the stores can fetch it. When no store fits it writes nothing (R1 of §10.11)."""

    STORES_ATTR = "pdt.stores"
    WAITING_ACCESS = "waiting"
    PIN_ENTRY_LEASE_MS = 3_600_000

    def __init__(self, content, store):
        self.content = content
        self.store = store

    def store_cards(self) -> list[dict]:
        from ..capabilities.connect import asset_cards
        return [c for c in asset_cards(self.content.peer)
                if (c.get("access") or {}).get("kind") == STORE_KIND and self.WAITING_ACCESS not in c["access"]]

    def store_for(self, root: str, copies: int, lease_s: int, tier: str | None = None, max_price: int | None = None,
                  avoid=()) -> dict:
        """Chooses stores for a tree this peer holds complete, or an artifact whose manifest it knows, and writes the
        signed pin; returns ``{"pin": signed pin, "chosen": cards}``. Pinning a root again renews it (P2-S-04)."""
        tree = cids.codec_of(root) == cids.DAG_CBOR
        if tree:
            if not self.store.complete(root):
                raise ValueError(f"tree root {root} is not complete in this peer's store")
            size = sum(len(self.store.get(c) or b"") for c in self.store.reachable(root))
            sealed = _kind(self.store.get(root)) == "sn"
            trees = self.content.trees
            if trees is not None and root not in trees.held_roots():
                trees.hold(root)
        else:
            manifest = self.content.manifest_of(root)
            if manifest is None:
                raise ValueError(f"no manifest for artifact root {root}")
            size, sealed = int(manifest["size"]), manifest.get("hashing") == "sealed"
        now = self.content.now_ms()
        chosen = choose(self.store_cards(), size, copies, sealed, tier, max_price, set(avoid), now)
        if not chosen:
            raise ValueError(f"no content store fits {size} bytes of {root}")
        attrs = {self.STORES_ATTR: ",".join(c["issuer"] for c in chosen)}
        pin = store_pin(root, KIND_TREE if tree else KIND_ARTIFACT, max(1, int(lease_s)), len(chosen),
                        self.content.peer.identity.peer_id, [], attrs)
        bad = store_pin_violation(pin)
        if bad is not None:
            raise ValueError(bad)
        entry_ms = min(pin["lease"] * 1000, self.PIN_ENTRY_LEASE_MS)
        signed = sign_pin(pin, self.content.peer.group, now + entry_ms, self.content.peer.identity)
        self.content._write(SIGNED_PIN_TYPE, signed, f"PT{entry_ms // 1000}S", signed_pin_tags(signed))
        return {"pin": signed, "chosen": chosen}

    def receipts(self, root: str) -> list[dict]:
        """The live receipts for a root, one per store: each signed by the holder it names, and unexpired."""
        now = self.content.now_ms()
        out: dict[str, dict] = {}
        peer = self.content.peer
        for dto in list(peer.states.values()):
            record = dto.get("record") or {}
            if record.get("type") != STORE_RECEIPT_TYPE or (record.get("tags") or {}).get(ROOT_TAG) != root:
                continue
            if not present(dto) or int(lease_of(dto).get("expiresAtMillis", 0)) <= now:
                continue
            raw = peer.payload_of(dto)
            receipt = None if raw is None else decode_store_receipt(raw)
            if receipt is None or store_receipt_violation(receipt) is not None or receipt["root"] != root:
                continue
            if receipt["until"] <= now or str(record.get("issuer")).split("/", 1)[0] != receipt["holder"]:
                continue
            kept = out.get(receipt["holder"])
            if kept is None or receipt["until"] > kept["until"]:
                out[receipt["holder"]] = receipt
        return list(out.values())


def _kind(data: bytes) -> str | None:
    try:
        return kind_of(data)
    except NodeFormatError:
        return None
