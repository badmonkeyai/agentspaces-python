"""SPEC §6.1a.4 (v0.1.28, spiral 5 S5-P-01): a published AppCard carries its host last; the Python builder encodes
the Java host group byte for byte; a card without the host keeps its bytes."""
import json
import pathlib

import pytest

from agentspaces import cbor, wire

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())


@pytest.mark.skipif("app_card_host_cbor" not in GOLDEN, reason="the host vector is not synced yet")
def test_the_golden_app_card_with_a_host_round_trips_byte_for_byte():
    raw = bytes.fromhex(GOLDEN["app_card_host_cbor"])
    card = cbor.loads(raw)
    assert list(card.keys())[-1] == "host", "host is the last key, appended after ui"
    assert cbor.dumps(card) == raw
    host = card["host"]
    rebuilt = wire.app_card_host(host["url"], host["port"], host["hostAgent"], host["path"], host["signOn"],
                                 host["publishedBy"], host["publishedAt"], host["status"])
    assert cbor.dumps(rebuilt) == cbor.dumps(host), "the Python builder encodes the Java host byte for byte"
    assert host["url"] == "https://chat.acme.example" and host["port"] == 7801 and host["signOn"] == "tenant"
    without = dict(card)
    del without["host"]
    assert "host" not in cbor.loads(cbor.dumps(without))


def test_the_builder_refuses_what_the_record_refuses():
    with pytest.raises(ValueError):
        wire.app_card_host("")
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", 70000)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", sign_on="password")
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", status="gone")
    assert wire.app_card_host("http://127.0.0.1:7801", 7801)["path"] == "/"
