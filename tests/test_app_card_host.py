"""SPEC §6.1a.4 (v0.1.28, ISSUE-AppHost; v0.1.32, AppCard origin and formats, 2026-11-09): a published AppCard
carries its host after ui; the Python builder encodes the Java host group byte for byte; ``signOn`` is ``idp`` (the
default) or ``none``, and a reader refuses ``tenant``; a card without the host keeps its bytes."""
import json
import pathlib

import pytest

from agentspaces import cbor, records, wire

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())


def test_the_golden_app_card_with_a_host_round_trips_byte_for_byte():
    raw = bytes.fromhex(GOLDEN["app_card_host_cbor"])
    card = cbor.loads(raw)
    assert list(card.keys())[-1] == "host", "host follows ui, and this card carries no origin, formats, or spill"
    assert cbor.dumps(card) == raw
    host = card["host"]
    rebuilt = wire.app_card_host(host["url"], host["port"], host["hostAgent"], host["path"], host["signOn"],
                                 host["publishedBy"], host["publishedAt"], host["status"])
    assert cbor.dumps(rebuilt) == cbor.dumps(host), "the Python builder encodes the Java host byte for byte"
    assert host["url"] == "https://chat.example.org" and host["port"] == 7801 and host["signOn"] == "idp"
    assert card["ui"]["catalogIds"] == ["example-widgets", "agentspaces-viz"]
    without = dict(card)
    del without["host"]
    assert "host" not in cbor.loads(cbor.dumps(without))


AT = "2026-11-09T09:00:00Z"


def test_the_builder_refuses_what_the_record_refuses():
    with pytest.raises(ValueError):
        wire.app_card_host("", published_at_iso=AT)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", 70000, published_at_iso=AT)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", sign_on="password", published_at_iso=AT)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", sign_on="tenant", published_at_iso=AT)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x", status="gone", published_at_iso=AT)
    with pytest.raises(ValueError):
        wire.app_card_host("http://x"), "a host names when it was published"
    assert wire.app_card_host("http://127.0.0.1:7801", 7801, published_at_iso=AT)["path"] == "/"
    host = wire.app_card_host("http://127.0.0.1:7801", published_at_iso=AT)
    assert host["signOn"] == "idp" and records.conforms(host, "AppCard.Host")
    assert wire.APP_CARD_SIGN_ONS == ("idp", "none")
