"""The commerce twins (SPEC §6.5a): the builders emit the Java field order and
the golden vectors of agentspaces-commerce round-trip byte for byte."""

import pathlib

import pytest

from agentspaces import cbor
from agentspaces.commerce import basis, cart, digest, item, items_total, mandate, order

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "agentspaces-commerce" / "src" / "test" / "resources" / "vectors"


def _vector(name):
    return bytes.fromhex((VECTORS / (name + ".hex")).read_text().strip())


def test_the_builders_emit_the_java_field_order():
    m = mandate("mnd-1", "checkout", "shopper", cart([item("claims.policies", "Policy data set, one month", 1, 19900)], 19900, "USD"),
                "https://merchant.example/.well-known/ucp", basis("apr-7"), {"issuerSignedJwt": "eyJ.a.b"}, "issued", "2026-11-05T12:00:00Z")
    assert list(m.keys()) == ["schemaVersion", "id", "kind", "role", "cart", "counterparty", "basis", "credential", "state", "at"]
    assert list(m["cart"].keys()) == ["items", "total", "currency"]
    assert list(m["cart"]["items"][0].keys()) == ["sku", "title", "quantity", "unitPrice"]
    assert items_total(m["cart"]) == 19900
    o = order("ord-1", "mnd-1", "completed", {"method": "digital"}, "https://merchant.example/orders/ord-1", "2026-11-05T12:00:00Z")
    assert list(o.keys()) == ["schemaVersion", "id", "mandate", "status", "fulfillment", "permalink", "at"]
    with pytest.raises(ValueError, match="kind"):
        mandate("m", "refund", "shopper", m["cart"], "", basis(), {}, "issued", "")
    with pytest.raises(ValueError, match="status"):
        order("o", "m", "shipped", {}, "", "")
    assert digest("abc") == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"


@pytest.mark.skipif(not VECTORS.exists(), reason="the agentspaces-commerce vectors are not beside this checkout")
def test_the_golden_vectors_round_trip_byte_for_byte():
    raw = _vector("mandate_cbor")
    m = cbor.loads(raw)
    assert cbor.dumps(m) == raw
    rebuilt = mandate(m["id"], m["kind"], m["role"], cart([item(i["sku"], i["title"], i["quantity"], i["unitPrice"]) for i in m["cart"]["items"]], m["cart"]["total"], m["cart"]["currency"]),
                      m["counterparty"], basis(m["basis"]["approval"], m["basis"]["decision"]), m["credential"], m["state"], m["at"])
    assert cbor.dumps(rebuilt) == raw, "the Python builder encodes the Java mandate byte for byte"
    raw = _vector("order_cbor")
    o = cbor.loads(raw)
    assert cbor.dumps(order(o["id"], o["mandate"], o["status"], o["fulfillment"], o["permalink"], o["at"])) == raw
    cap = cbor.loads(_vector("capability_commerce_cbor"))
    assert cap["capabilityType"] == "aspace:cap/commerce" and cap["parameters"]["role"] == "merchant"
