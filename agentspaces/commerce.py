"""The commerce records (SPEC §6.5a, §7.6; the open ``agentspaces-commerce``
module): a ``Mandate`` is an AP2 Checkout or Payment Mandate carried as an
entry of a group's ``commerce`` space, an ``Order`` the UCP order it led to.
The builders emit the Java field order, so a record built here encodes byte
for byte as the Java one; ``digest`` is the base64url SHA-256 the AP2
bindings use (``checkout_hash``, ``transaction_id``)."""

import base64
import hashlib

from .cbor import utf16_units

CAPABILITY_COMMERCE = "aspace:cap/commerce"
SPACE_COMMERCE = "commerce"
ROLES = ("merchant", "shopper", "payment")
KINDS = ("checkout", "payment")
STATES = ("issued", "settled", "refused", "expired")
ORDER_STATUSES = ("incomplete", "requires_escalation", "ready_for_complete", "complete_in_progress", "completed", "canceled")
VCT_CHECKOUT, VCT_CHECKOUT_OPEN, VCT_PAYMENT, VCT_PAYMENT_OPEN = "mandate.checkout.1", "mandate.checkout.open.1", "mandate.payment.1", "mandate.payment.open.1"


def item(sku: str, title: str, quantity: int, unit_price: int) -> dict:
    """One cart item: the UCP item id, the title, the quantity, the unit price in minor units."""
    if quantity < 1:
        raise ValueError("an item's quantity is at least one")
    return {"sku": sku, "title": title or "", "quantity": int(quantity), "unitPrice": int(unit_price)}


def cart(items, total: int, currency: str) -> dict:
    if len(items) > 64:
        raise ValueError("a cart carries at most 64 items")
    if utf16_units(currency) != 3:  # Java's String.length, in UTF-16 code units
        raise ValueError("the currency is an ISO 4217 code: " + currency)
    return {"items": list(items), "total": int(total), "currency": currency}


def basis(approval: str = "", decision: str = "") -> dict:
    return {"approval": approval or "", "decision": decision or ""}


def mandate(id: str, kind: str, role: str, cart_: dict, counterparty: str, basis_: dict, credential: dict, state: str, at) -> dict:
    if kind not in KINDS:
        raise ValueError("kind must be one of " + ", ".join(KINDS))
    if role not in ROLES:
        raise ValueError("role must be one of " + ", ".join(ROLES))
    if state not in STATES:
        raise ValueError("state must be one of " + ", ".join(STATES))
    return {"schemaVersion": 1, "id": id, "kind": kind, "role": role, "cart": cart_, "counterparty": counterparty or "",
            "basis": basis_ or basis(), "credential": dict(credential or {}), "state": state, "at": at}


def order(id: str, mandate_id: str, status: str, fulfillment: dict, permalink: str, at) -> dict:
    if status not in ORDER_STATUSES:
        raise ValueError("status must be one of " + ", ".join(ORDER_STATUSES))
    return {"schemaVersion": 1, "id": id, "mandate": mandate_id or "", "status": status, "fulfillment": dict(fulfillment or {}),
            "permalink": permalink or "", "at": at}


def items_total(cart_: dict) -> int:
    return sum(int(i["quantity"]) * int(i["unitPrice"]) for i in cart_.get("items", []))


def digest(s: str) -> str:
    """The base64url SHA-256 of a string's UTF-8 bytes, no padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")
