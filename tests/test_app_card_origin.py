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

"""SPEC §6.1a.2 and §6.1b (v0.1.32; AppCard origin and formats, 2026-11-09): the AppCard's closed kinds, its open
``origin`` and ``formats``, the closed values every reader checks at decode, the builders, and the discovery
predicates. The golden vectors are the contract: the accept vector decodes and re-encodes byte for byte, and every
refusal vector is undecodable here as it is in Java."""

import json
import pathlib

import pytest

from agentspaces import cbor, records, wire

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())

REFUSALS = [
    "adv_app_card_kind_realm_cbor",
    "adv_app_card_sign_on_tenant_cbor",
    "adv_app_card_formats_empty_cbor",
    "adv_app_card_origin_attrs_empty_cbor",
    "adv_app_card_formats_bound_cbor",
    "adv_app_card_formats_upper_cbor",
    "adv_app_card_formats_duplicate_cbor",
    "adv_app_card_formats_parameter_cbor",
    "adv_app_card_origin_system_cbor",
    "adv_app_card_origin_attrs_prefix_cbor",
    "adv_app_card_origin_ref_bound_cbor",
    "adv_app_card_spill_placeholder_cbor",
    "adv_app_card_spill_parts_order_cbor",
    "adv_app_card_spill_parts_unknown_cbor",
    "adv_app_card_spill_parts_empty_cbor",
    "adv_app_card_spill_root_codec_cbor",
    "adv_app_card_spill_size_zero_cbor",
]


def _hex(name: str) -> bytes:
    return bytes.fromhex(GOLDEN[name])


def _card() -> dict:
    return cbor.loads(_hex("app_card_origin_formats_cbor"))


def _decodes(card: dict) -> bool:
    return records.decode(cbor.dumps(card), "AppCard") is not None


def test_the_origin_and_formats_vector_decodes_and_its_origin_rebuilds_byte_for_byte():
    raw = _hex("app_card_origin_formats_cbor")
    card = records.decode(raw, "AppCard")
    assert card is not None and list(card)[-2:] == ["origin", "formats"], "origin, then formats, after host"
    origin = card["origin"]
    # the attrs keys travel in the SPEC §9.1 order of a map<String,String>: the shorter key first
    assert list(origin["attrs"]) == ["realm.reads", "realm.format", "realm.namespace"]
    rebuilt = wire.app_card_origin("realm", "example-realm/example-app", "",
                                   {"realm.namespace": "urn:realm:example-realm#", "realm.format": "1",
                                    "realm.reads": "Item,Order"})
    assert cbor.dumps(rebuilt) == cbor.dumps(origin)
    assert wire.app_card_formats(["Text/HTML", "application/geo+json", "text/html", "urn:realm:example-realm#"]) \
        == card["formats"], "media types lower-cased, the repeat dropped, the issuer's order kept"


@pytest.mark.parametrize("name", REFUSALS)
def test_every_app_card_refusal_vector_is_undecodable(name):
    raw = _hex(name)
    assert isinstance(cbor.loads(raw), dict), "the vector is a well-formed map; only the record rule refuses it"
    assert records.decode(raw, "AppCard") is None


def test_the_agent_card_stub_with_actions_written_is_undecodable():
    raw = _hex("adv_agent_card_spill_actions_cbor")
    assert records.decode(raw, "AgentCard") is None
    assert records.decode(_hex("agent_card_spill_cbor"), "AgentCard") is not None


def test_the_kinds_are_closed_and_no_kind_is_tied_to_an_origin():
    card = _card()
    for kind in ("peer", "fed", "gateway", "assembled"):
        assert _decodes({**card, "kind": kind}), kind
    assert not _decodes({**card, "kind": "realm"})
    assert not _decodes({**card, "kind": ""})
    console = {**card, "origin": wire.app_card_origin("console", "example-console/board")}
    assert _decodes({**console, "kind": "assembled"}) and _decodes({**console, "kind": "fed"})
    assert wire.APP_CARD_KINDS == ("peer", "fed", "gateway", "assembled")


def test_the_other_closed_values_are_checked_at_decode():
    host = _hex("app_card_host_cbor")
    card = records.decode(host, "AppCard")
    assert card is not None and card["host"]["signOn"] == "idp"
    assert not _decodes({**card, "shape": "mobile"})
    assert not _decodes({**card, "ui": {**card["ui"], "transport": "grpc"}})
    assert not _decodes({**card, "host": {**card["host"], "signOn": "tenant"}})
    assert not _decodes({**card, "host": {**card["host"], "status": "paused"}})
    component = wire.ui_component("c", "example-widgets", "ItemPanel")
    assert _decodes({**card, "ui": {**card["ui"], "components": [component]}})
    assert not _decodes({**card, "ui": {**card["ui"], "components": [{**component, "role": "sidebar"}]}})
    assert not _decodes({k: v for k, v in card.items() if k != "ui"}), "an a2ui app names its surfaces in ui"


def test_the_card_its_ui_and_its_host_keep_their_bounds_at_decode():
    """The constructor rules of Java's AppCard, Ui, and Host that a v0.1.32 reader also runs."""
    card = records.decode(_hex("app_card_host_cbor"), "AppCard")
    assert not _decodes({**card, "name": " "}) and not _decodes({**card, "version": ""})
    for field in ("reads", "actions", "views"):
        assert _decodes({**card, field: [f"g/s{i}" for i in range(64)]}), field
        assert not _decodes({**card, field: [f"g/s{i}" for i in range(65)]}), field
    assert _decodes({**card, "host": {**card["host"], "port": 65535}})
    assert not _decodes({**card, "host": {**card["host"], "port": 65536}})
    assert not _decodes({**card, "host": {**card["host"], "port": -1}})
    components = [wire.ui_component(f"c{i}", "example-widgets", "ItemPanel") for i in range(33)]
    assert _decodes({**card, "ui": {**card["ui"], "components": components[:32]}})
    assert not _decodes({**card, "ui": {**card["ui"], "components": components}})


def test_origin_bounds_and_grammar():
    card = _card()

    def origin(**fields):
        merged = {**card["origin"], **fields}
        return {**card, "origin": {k: v for k, v in merged.items() if v is not None}}

    assert _decodes(origin(system="com.example.catalog", attrs={"com.example.catalog.id": "7"}))
    assert _decodes(origin(system="a" * 64, attrs=None)) and not _decodes(origin(system="a" * 65, attrs=None))
    for bad in ("", "-realm", "realm-", "Realm", "realm two"):
        assert not _decodes(origin(system=bad, attrs=None)), bad
    assert _decodes(origin(ref="r" * 256)) and not _decodes(origin(ref="r" * 257)) and not _decodes(origin(ref=""))
    assert not _decodes(origin(ref="a\x01b")) and not _decodes(origin(ref="a\x7fb"))
    assert _decodes(origin(version="v" * 64)) and not _decodes(origin(version="v" * 65))
    assert not _decodes(origin(version="1\n"))
    nine = cbor.canonical_map({f"realm.k{i}": "v" for i in range(9)})
    assert not _decodes(origin(attrs=nine))
    long_key = "realm." + "k" * 122
    assert _decodes(origin(attrs={long_key: "v"})) and not _decodes(origin(attrs={long_key + "k": "v"}))
    assert not _decodes(origin(attrs={"realm.": "v"})) and not _decodes(origin(attrs={"realm.Key": "v"}))
    assert not _decodes(origin(attrs={"realm.k": "v" * 257})) and not _decodes(origin(attrs={"realm.k": "\x00"}))
    # a code unit is UTF-16's: a character outside the BMP takes two
    assert _decodes(origin(ref="\U0001F600" * 128)) and not _decodes(origin(ref="\U0001F600" * 128 + "x"))


def test_formats_bounds_and_grammar():
    card = _card()

    def formats(values):
        return {**card, "formats": values}

    assert _decodes(formats([f"text/x-{i}" for i in range(16)]))
    assert _decodes(formats(["application/vnd.example+json", "urn:x:y", "https://example.org/ns#"]))
    for bad in (["text"], ["text/"], ["/html"], ["text/html "], ["Text/html"], ["text/html;q=1"],
                ["1http://x"], ["ht tp:x"], ["urn:a b"], ["urn:a b"], ["x" * 257], [""]):
        assert not _decodes(formats(bad)), bad
    # a vocabulary IRI is 1 to 256 code units, as a media type is
    assert _decodes(formats(["urn:" + "x" * 252])) and not _decodes(formats(["urn:" + "x" * 253]))


def test_the_builders_refuse_what_the_record_refuses():
    assert wire.app_card_origin("realm", "r", None, {}) == {"system": "realm", "ref": "r", "version": ""}
    with pytest.raises(ValueError):
        wire.app_card_origin("Realm", "r")
    with pytest.raises(ValueError):
        wire.app_card_origin("realm", "r", "", {"namespace": "x"})
    assert wire.app_card_formats([]) is None and wire.app_card_formats(None) is None
    with pytest.raises(ValueError):
        wire.app_card_formats(["text/html;charset=utf-8"])


def test_the_discovery_predicates_read_origin_and_formats():
    card = _card()
    assert wire.from_origin(card, "realm") and not wire.from_origin(card, "console")
    assert wire.from_origin(card, "realm", "example-realm/example-app")
    assert wire.from_origin(card, "realm", "example-realm/*") and not wire.from_origin(card, "realm", "other/*")
    assert not wire.from_origin(card, "realm", "example-realm/")
    sibling = {**card, "origin": wire.app_card_origin("realm", "example-realmx/app")}
    assert not wire.from_origin(sibling, "realm", "example-realm/*"), "the prefix keeps its slash"
    assert wire.handles(card, "TEXT/HTML") and wire.handles(card, "application/*") and wire.handles(card, "text/*")
    assert not wire.handles(card, "image/*") and not wire.handles(card, "text/plain")
    assert wire.handles(card, "urn:realm:example-realm#") and not wire.handles(card, "URN:realm:example-realm#")
    bare = {k: v for k, v in card.items() if k not in ("origin", "formats")}
    assert not wire.from_origin(bare, "realm") and not wire.handles(bare, "text/html")
    stub = cbor.loads(_hex("app_card_spill_cbor"))
    assert wire.from_origin(stub, "console", "example-console/*"), "origin and formats never spill"


def test_the_builder_writes_the_golden_cards_byte_for_byte():
    """``wire.app_card`` writes Java's field order and defaults: both golden cards rebuild from their values."""
    from types import SimpleNamespace
    peer = SimpleNamespace(peer_id="zPeerA")
    card = _card()
    rebuilt = wire.app_card("zApps", peer, "example-app", card["issued"], "PT15M", kind="fed", shape="static",
                            owner="example-realm", url=card["url"], origin=card["origin"], formats=card["formats"])
    assert cbor.dumps(rebuilt) == _hex("app_card_origin_formats_cbor")
    host = cbor.loads(_hex("app_card_host_cbor"))
    rebuilt = wire.app_card("zApps", peer, "support-chat", host["issued"], "PT15M", name="Support chat",
                            kind="fed", shape="a2ui", owner="support", reads=host["reads"], actions=host["actions"],
                            views=host["views"], ui=host["ui"], host=host["host"])
    assert cbor.dumps(rebuilt) == _hex("app_card_host_cbor")
    with pytest.raises(ValueError):
        wire.app_card("zApps", peer, "x", card["issued"], kind="realm")
