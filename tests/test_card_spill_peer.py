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

"""SPEC §6.1a.2 and §6.1a.5 (v0.1.32; AppCard origin and formats, 2026-11-09) on the Python peer: the hint
``wire.appcard=2``, the gate an issuer applies to its view, the publisher's spill and soft warning, and ``resolve``,
over the in-memory fleet with a content swarm. A card of 65,536 bytes travels inline and one of 65,537 spills; a
level-1 member closes the gate, which reissues every shaped card at once, and its lapse reopens it."""

import logging

import pytest

from agentspaces import cbor, records, wire
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.capabilities import content as c
from agentspaces.identity import instant_iso, parse_instant_millis
from agentspaces.peer import HINT_APPCARD, appcard_level_of
from agentspaces.space import Space
from fleet import Clock, Network, NetPeer

GROUP = "zPythonSpill"
START_MS = 1_762_678_800_000  # 2025-11-09T09:00:00Z


def _node(network, clock, content=True, **options):
    peer = NetPeer(network, GROUP, clock=clock, **options)
    if content:
        Content(Pipes(peer), Space(peer, "content"), MemoryStore())
    return peer


def _fleet(*levels, content=True):
    network, clock = Network(), Clock(START_MS)
    peers = [_node(network, clock, content, appcard_level=level) for level in levels]
    for peer in peers:
        peer.introduce()
    return clock, peers


def _app(peer, app="board", views=(), **fields):
    return wire.app_card(GROUP, peer.identity, app, instant_iso(peer._now_ms()), "PT15M", views=list(views), **fields)


def _sized(peer, target: int, app="board", **fields) -> dict:
    """An AppCard whose encoding is exactly ``target`` bytes, its bulk in one view name."""
    length = target
    for _ in range(8):
        card = _app(peer, app, ["v" * length], **fields)
        size = len(cbor.dumps(card))
        if size == target:
            return card
        length += target - size
    raise AssertionError(f"no card of {target} bytes")


def _held(peer, card_id):
    return peer.ads[card_id]["ad"]


def test_the_peer_advertises_its_appcard_level_as_java_reads_it():
    _clock, (two, one) = _fleet(2, 1)
    assert two.wire_hints[HINT_APPCARD] == "2" and HINT_APPCARD not in one.wire_hints
    assert one.members[two.identity.peer_id]["resourceHints"][HINT_APPCARD] == "2"
    for text, level in (("2", 2), ("10", 10), ("9" * 12, 2 ** 31 - 1), (None, 1), ("", 1), ("02", 1), ("0", 1),
                        ("1", 1), ("two", 1), ("-2", 1), ("2 ", 1)):
        assert appcard_level_of(text) == level, text
    with pytest.raises(ValueError):
        NetPeer(Network(), GROUP, appcard_level=3)


def test_the_gate_opens_only_on_a_view_at_level_two():
    _clock, (a, b) = _fleet(2, 2)
    assert a.appcard_gate_open()
    _clock, (c, d) = _fleet(2, 1)
    assert not c.appcard_gate_open() and not d.appcard_gate_open()
    lone = NetPeer(Network(), GROUP)
    assert lone.appcard_gate_open(), "a view of this peer alone is at its own level"
    lone.members["zHeardOnly"] = {}
    assert not lone.appcard_gate_open(), "a member whose advertisement has not arrived counts as level 1"


def test_a_closed_gate_strips_origin_formats_and_an_idp_host():
    _clock, (a, _b) = _fleet(2, 1)
    host = wire.app_card_host("https://apps.example.org", 443, published_at_iso=instant_iso(START_MS))
    origin = wire.app_card_origin("console", "example-console/board")
    card = _app(a, "desk", origin=origin, formats=["text/html"], host=host)
    issued = a.publish_ad("AppCard", card)
    assert "origin" not in issued and "formats" not in issued and "host" not in issued
    assert a.app_cards_downgraded == 1
    none_host = wire.app_card_host("https://apps.example.org", 443, sign_on="none", published_at_iso=instant_iso(START_MS))
    kept = a.publish_ad("AppCard", _app(a, "open", host=none_host))
    assert kept["host"]["signOn"] == "none", "a host of sign-on none reads at level 1 and stays"
    assert a.app_cards_downgraded == 1


def test_a_card_of_the_threshold_travels_inline_and_one_byte_more_spills():
    _clock, (a, b) = _fleet(2, 2)
    inline = a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES, "edge"))
    assert "spill" not in inline and a.cards_spilled == 0 and a.cards_oversize_inline == 0
    full = _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1, "over")
    stub = a.publish_ad("AppCard", full)
    assert stub["spill"]["parts"] == ["views"] and stub["views"] == [] and a.cards_spilled == 1
    held = _held(b, full["id"])
    assert held == stub and records.conforms(held, "AppCard")
    assert b.resolve(held) == full, "the second member fetches the parts and completes the card"
    assert a.resolve(stub) == full
    assert b.resolve(inline) is inline


def test_the_soft_warning_fires_once_per_id_and_size(caplog):
    _clock, (a, _b) = _fleet(2, 2)
    caplog.set_level(logging.WARNING, logger="agentspaces.peer")
    a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_WARN_BYTES, "quiet"))
    assert not caplog.records
    card = _sized(a, wire.CARD_SPILL_WARN_BYTES + 1, "loud")
    a.publish_ad("AppCard", card)
    a.publish_ad("AppCard", {**card, "issued": instant_iso(START_MS + 1000)})  # a refresh at the same size
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert card["id"] in message and "57345" in message and "65536" in message
    assert "it travels inline until it passes the threshold" in message
    a.publish_ad("AppCard", {**_sized(a, wire.CARD_SPILL_WARN_BYTES + 2, "loud"), "issued": instant_iso(START_MS + 2000)})
    assert len(caplog.records) == 2


def test_a_large_card_travels_inline_when_the_gate_is_closed_or_no_swarm_serves_the_group():
    _clock, (a, _b) = _fleet(2, 1)
    big = _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 100)
    assert "spill" not in a.publish_ad("AppCard", big) and a.cards_oversize_inline == 1
    _clock, (c, _d) = _fleet(2, 2, content=False)
    assert "spill" not in c.publish_ad("AppCard", _sized(c, wire.CARD_SPILL_THRESHOLD_BYTES + 100))
    assert c.cards_oversize_inline == 1 and c.cards_spilled == 0


def test_a_large_card_with_nothing_to_move_or_a_document_the_swarm_refuses_travels_inline():
    _clock, (a, _b) = _fleet(2, 2)
    named = a.publish_ad("AppCard", _app(a, "named", owner="o" * (wire.CARD_SPILL_THRESHOLD_BYTES + 10)))
    assert "spill" not in named and a.cards_oversize_inline == 1
    # a parts document of more than 64 pieces needs a table this client cannot keep inline
    huge = _app(a, "huge", ["v" * 66_000 for _ in range(64)])
    assert "spill" not in a.publish_ad("AppCard", huge) and a.cards_oversize_inline == 2


def test_an_agent_card_spills_its_actions_and_ui():
    _clock, (a, b) = _fleet(2, 2)
    action = wire.card_action("research", "d" * (wire.CARD_SPILL_THRESHOLD_BYTES + 10), ["Task"], [], "take", "tasks")
    card = wire.agent_card(GROUP, a.identity, "researcher", instant_iso(a._now_ms()), "PT15M", "",
                           [], ["Task"], [], {}, {"Task": "tasks"}, actions=[action])
    stub = a.publish_ad("AgentCard", card)
    assert stub["spill"]["parts"] == ["actions"] and "actions" not in stub
    assert b.resolve(_held(b, card["id"])) == card


def test_a_level_one_joiner_reissues_the_cards_at_once_and_its_lapse_restores_them():
    clock, (a, b) = _fleet(2, 2)
    origin = wire.app_card_origin("console", "example-console/board")
    shaped = _app(a, "desk", origin=origin)
    big = _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1, "big")
    plain = _app(a, "plain")
    for card in (shaped, big, plain):
        a.publish_ad("AppCard", card)
    first = {card_id: parse_instant_millis(_held(b, card_id)["issued"]) for card_id in (shaped["id"], big["id"], plain["id"])}
    assert "origin" in _held(b, shaped["id"]) and "spill" in _held(b, big["id"])
    late = NetPeer(a.network, GROUP, clock=clock, appcard_level=1)
    late.introduce()
    assert not a.appcard_gate_open()
    assert "origin" not in _held(b, shaped["id"]) and "spill" not in _held(b, big["id"])
    assert "origin" not in _held(late, shaped["id"]) and "spill" not in _held(late, big["id"])
    assert parse_instant_millis(_held(b, shaped["id"])["issued"]) > first[shaped["id"]], "a strictly newer issue instant"
    assert parse_instant_millis(_held(b, plain["id"])["issued"]) == first[plain["id"]], "a card the gate does not shape stays"
    assert a.cards_oversize_inline == 1 and a.app_cards_downgraded == 1
    # the joiner's advertisement lapses: it has left the leased view, and the full cards return
    clock.advance(10 * 60 * 1000 + 1)
    b.introduce()
    assert a.appcard_gate_open()
    assert "origin" in _held(b, shaped["id"]) and "spill" in _held(b, big["id"])


def test_a_spilled_root_is_released_one_ttl_after_the_last_card_that_named_it():
    clock, (a, b) = _fleet(2, 2)
    stub = a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1))
    root = stub["spill"]["root"]
    assert root in a.content.store.roots()
    a.withdraw_ad(stub["id"])
    clock.advance(15 * 60 * 1000 - 1)
    b.introduce()
    assert root in a.content.store.roots()
    clock.advance(1)
    b.introduce()
    assert root not in a.content.store.roots() and root not in a.content.holder_state


def test_resolve_refuses_a_document_that_fails_a_check_and_keeps_the_stub():
    _clock, (a, b) = _fleet(2, 2)
    full = _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1)
    stub = a.publish_ad("AppCard", full)
    spill = stub["spill"]
    wrong_size = {**stub, "spill": {**spill, "size": spill["size"] - 1}}
    with pytest.raises(ValueError):
        b.resolve(wrong_size)
    assert b.spills_refused == 1

    def published(document):
        return a.content.put_spill("aspace://zPythonSpill/app/x", document)

    undecodable = published(b"\xff" * 10)
    with pytest.raises(ValueError):
        b.resolve({**stub, "spill": {**spill, "root": undecodable, "size": 10}})
    other = cbor.dumps({"reads": ["g/s"], "actions": [], "views": []})
    mismatched = published(other)
    with pytest.raises(ValueError):
        b.resolve({**stub, "spill": {**spill, "root": mismatched, "size": len(other)}})
    assert b.spills_refused == 3
    with pytest.raises(ValueError):
        b.resolve({**stub, "spill": {**spill, "size": wire.CARD_SPILL_MAX_FETCH_BYTES + 1}})
    assert b.spills_over_limit == 1 and b.spills_refused == 3
    assert _held(b, stub["id"]) == stub, "the cached stub stays"


def test_resolve_without_a_swarm_or_a_holder_fails_uncounted():
    _clock, (a, b) = _fleet(2, 2)
    stub = a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1))
    bare = NetPeer(Network(), GROUP)
    with pytest.raises(LookupError):
        bare.resolve(stub)
    unserved = c.content_root(c.hash_pieces(b"a document nobody serves", wire.CARD_SPILL_PIECE_SIZE))
    with pytest.raises(TimeoutError):
        b.resolve({**stub, "spill": {**stub["spill"], "root": unserved}}, timeout_s=0.2)
    assert b.spills_refused == 0 and b.content.fetches == {}, "the timed-out fetch is cancelled"


def test_a_misstated_size_fails_before_any_piece_arrives():
    _clock, (a, b) = _fleet(2, 2)
    stub = a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1))
    spill = stub["spill"]
    with pytest.raises(ValueError):
        b.resolve({**stub, "spill": {**spill, "size": spill["size"] + 1}})
    assert b.spills_refused == 1 and b.content.store.have(spill["root"]) == set(), "no piece was fetched"


def test_an_older_peer_advertisement_never_replaces_a_newer_one():
    clock, (a, b) = _fleet(2, 2)
    older = wire.peer_advertisement(GROUP, b.identity, instant_iso(START_MS - 1000),
                                    resource_hints={HINT_APPCARD: "2"})
    newer = wire.peer_advertisement(GROUP, b.identity, instant_iso(START_MS + 1000))
    a._accept_peer_ad(wire.signed_peer_ad(newer, b.identity))
    assert not a.appcard_gate_open()
    a._accept_peer_ad(wire.signed_peer_ad(older, b.identity))
    assert not a.appcard_gate_open(), "the member dropped the hint; a replayed older advertisement keeps it at level 1"


def test_a_card_the_record_refuses_is_never_signed():
    _clock, (a, _b) = _fleet(2, 2)
    with pytest.raises(ValueError):
        a.publish_ad("AppCard", {**_app(a), "kind": "realm"})
    with pytest.raises(ValueError):
        a.publish_ad("AppCard", {**_app(a), "formats": []})
    stub = wire.card_stub(_sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1), wire.card_spill(
        c.content_root(c.hash_pieces(b"parts", wire.CARD_SPILL_PIECE_SIZE)), 5, ["views"]))
    assert records.conforms(stub, "AppCard")
    with pytest.raises(ValueError):
        a.publish_ad("AppCard", stub)  # the peer spills a full card itself; it never signs a stub handed to it
    with pytest.raises(ValueError):
        wire.app_card_for_view(stub, False)
    assert a.ads == {} and a._cards == {}


def test_the_peer_lists_live_app_cards_and_a_closed_binding_stops_reissuing_its_card():
    from agentspaces.agents import Binder, agent

    @agent("desk")
    class Desk:
        pass

    clock, (a, b) = _fleet(2, 2)
    card = a.publish_ad("AppCard", _app(a, "desk", origin=wire.app_card_origin("realm", "ops/desk")))
    assert b.app_cards() == [card] and [x for x in b.app_cards() if wire.from_origin(x, "realm", "ops/*")] == [card]
    bound = Binder(a).bind(Desk())
    assert bound.card["id"] in a._cards
    bound.close()
    assert bound.card["id"] not in a._cards
    clock.advance(16 * 60 * 1000)
    assert b.app_cards() == [], "a card lapses at its ttl"


def test_a_fetch_another_caller_began_still_meets_the_length_check():
    _clock, (a, b) = _fleet(2, 2)
    stub = a.publish_ad("AppCard", _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1))
    spill = stub["spill"]
    # a fetch with no expected length, as a space read begins one, still waiting for its manifest
    b.content.fetches[spill["root"]] = c.Fetch(b.content, spill["root"])
    with pytest.raises(ValueError):
        b.resolve({**stub, "spill": {**spill, "size": spill["size"] + 1}})
    assert b.spills_refused == 1


def test_an_honest_resolve_that_joins_a_fetch_begun_under_a_misstated_size_still_completes():
    _clock, (a, b) = _fleet(2, 2)
    full = _sized(a, wire.CARD_SPILL_THRESHOLD_BYTES + 1)
    stub = a.publish_ad("AppCard", full)
    spill = stub["spill"]
    # a hostile stub naming the same root with another length began this fetch; its manifest has not arrived
    b.content.fetches[spill["root"]] = c.Fetch(b.content, spill["root"], expected_size=spill["size"] + 7)
    assert b.resolve(_held(b, stub["id"])) == full
    assert b.spills_refused == 0


def test_a_frame_before_its_advertisement_closes_the_gate_at_once_and_the_advertisement_reopens_it():
    clock, (a, b) = _fleet(2, 2)
    shaped = _app(a, "desk", origin=wire.app_card_origin("console", "example-console/board"))
    a.publish_ad("AppCard", shaped)
    quiet = NetPeer(a.network, GROUP, clock=clock)  # at level 2, and not yet introduced
    quiet.write_entry("notes", "urn:example:Note", {"n": 1})
    assert not a.appcard_gate_open() and "origin" not in _held(b, shaped["id"]), "heard, so level 1 until its ad"
    quiet.introduce()
    assert a.appcard_gate_open() and "origin" in _held(b, shaped["id"]), "its advertisement shows level 2"


def test_the_gate_looks_again_as_frames_arrive_once_a_lapse_leaves_no_view_change():
    clock, (a, b) = _fleet(2, 2)
    shaped = _app(a, "desk", origin=wire.app_card_origin("console", "example-console/board"))
    a.publish_ad("AppCard", shaped)
    NetPeer(a.network, GROUP, clock=clock, appcard_level=1).introduce()
    assert "origin" not in _held(b, shaped["id"])
    clock.advance(10 * 60 * 1000 + 1)  # every member's advertisement lapses; no advertisement arrives
    b.write_entry("notes", "urn:example:Note", {"n": 1})
    assert a.appcard_gate_open() and "origin" in _held(b, shaped["id"])


def test_a_lapsed_card_is_not_reissued_when_the_gate_closes():
    clock, (a, b) = _fleet(2, 2)
    a.publish_ad("AppCard", _app(a, "desk", origin=wire.app_card_origin("console", "example-console/board")))
    clock.advance(15 * 60 * 1000)
    NetPeer(a.network, GROUP, clock=clock, appcard_level=1).introduce()
    assert not a.appcard_gate_open() and a.app_cards_downgraded == 0


def test_a_root_two_cards_name_is_held_to_the_later_expiry():
    clock, (a, b) = _fleet(2, 2)
    views = ["v" * (wire.CARD_SPILL_THRESHOLD_BYTES + 1)]
    long_lived = a.publish_ad("AppCard", _app(a, "one", views))
    short_lived = a.publish_ad("AppCard", wire.app_card(GROUP, a.identity, "two", instant_iso(a._now_ms()), "PT5M",
                                                        views=views))
    root = long_lived["spill"]["root"]
    assert short_lived["spill"]["root"] == root, "the same parts give the same document"
    clock.advance(5 * 60 * 1000 + 1)
    b.introduce()
    assert root in a.content.store.roots(), "the first card still names it"
    clock.advance(10 * 60 * 1000)
    b.introduce()
    assert root not in a.content.store.roots()
