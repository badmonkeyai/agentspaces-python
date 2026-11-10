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
"""PDT 2 phase 7, P2-C-01 (srad/agentspaces-pdt2.md §3.2, §6.10.3 rule 19, §10.9 F1, §10.11 R1 and R2): the Python
client reads ``content-store`` cards, whose every value is text, chooses stores as Java's ``StoreChooser`` does, and
writes ``SignedPin`` entries, the requester's own consent to the pin's terms for this group, naming the stores it
chose. A store takes only a signed pin (§10.9), so this client writes no bare ``StorePin``."""

import json
import pathlib

import pytest

from agentspaces import cbor
from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.identity import instant_iso
from agentspaces.pdt import NodeStore, PMap, Pdt, cids, content_store
from agentspaces.pdt.content_store import Stores, choose, store_card
from agentspaces.space import Space
from fleet import Clock, Network, NetPeer
from test_hlc_logical_limit import T

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPythonStores"
CARD = cbor.loads(bytes.fromhex(GOLDEN["asset_card_content_store_cbor"]))


def _card(issuer: str, **access) -> dict:
    card = dict(CARD, issuer=issuer, id=f"aspace://{GROUP}/asset/content-store/site/{issuer}", group=GROUP,
                issued=instant_iso(T))
    card["access"] = {**CARD["access"], **access}
    return card


def test_the_golden_card_reads_as_text_values_parsed_by_rule_19():
    read = store_card(CARD)
    assert read["free"] == 2145336164352 and read["capacity"] == 2199023255552 and read["maxObject"] == 68719476736
    assert read["blind"] is False and read["challenge"] is True and read["tier"] == "hot" and read["policy"] == "grant"
    assert read["codecs"] == ["dag-cbor", "raw"] and read["sealing"] == ["none", "sealed-nodes"]
    assert read["pin"] == ["request", "invoke"] and read["delegates"] == []
    assert read["copiesMax"] == 3 and read["leaseMax"] == 31536000 and read["leaseDefault"] == 2592000
    assert read["price"] == 2 and read["issuer"] == CARD["issuer"] and read["waiting"] is None


@pytest.mark.parametrize("access", [{"free": "02"}, {"free": "-1"}, {"maxObject": "1e9"}, {"blind": "yes"},
                                    {"kind": "content-cache"}])
def test_a_card_with_a_value_it_cannot_read_is_no_store_card(access):
    assert store_card(_card("zA", **access)) is None


def test_the_chooser_ranks_by_price_then_free_bytes_and_keeps_one_card_per_store():
    cards = [_card("zCheap", free="1000"), _card("zRoomy", free="9000"), _card("zBlind", blind="true"),
             _card("zSmall", free="10"), _card("zCold", tier="cold", free="5000"), _card("zCheap", free="999999")]
    cards[1]["costHints"] = {"pricePerGibMonth": "5"}
    cards[0]["costHints"] = cards[5]["costHints"] = {}
    issuers = lambda chosen: [c["issuer"] for c in chosen]  # noqa: E731
    assert issuers(choose(cards, 100, 3, now_ms=T)) == ["zCheap", "zCold", "zRoomy"], \
        "no hint is free, a blind store holds only sealed content, and one card per store"
    assert issuers(choose(cards, 100, 1, sealed=True, avoid={"zCheap"}, now_ms=T)) == ["zBlind"]
    assert issuers(choose(cards, 100, 5, tier="cold", now_ms=T)) == ["zCold"]
    assert issuers(choose(cards, 100, 5, max_price=2, avoid={"zCheap"}, now_ms=T)) == ["zCold"]
    assert issuers(choose(cards, 100, 3, now_ms=T + 16 * 60_000)) == [], "an expired card is no store"


def _fleet():
    clock = Clock(T)
    network = Network()
    peers = [NetPeer(network, GROUP, clock=clock) for _ in range(3)]
    for peer in peers:
        peer.introduce()
    requester = peers[0]
    content = Content(Pipes(requester), Space(requester, "content"), MemoryStore(), seed=1)
    pdt = Pdt(content, Space(requester, "pdt"), NodeStore(), seed=1)
    return clock, peers, content, pdt


def test_store_for_writes_one_signed_pin_naming_the_chosen_stores_with_the_requesters_consent():
    clock, (requester, store_a, store_b), content, pdt = _fleet()
    store_a.publish_ad("AssetCard", _card(store_a.identity.peer_id, free="9000000"))
    store_b.publish_ad("AssetCard", _card(store_b.identity.peer_id, free="8000000", waiting="authorizer"))
    root = PMap.empty(pdt.store).assoc_many({f"k{i}": i for i in range(50)}).root()
    stores = Stores(content, pdt.store)
    pinning = stores.store_for(root, copies=2, lease_s=86400)
    assert [c["issuer"] for c in pinning["chosen"]] == [store_a.identity.peer_id], "a waiting store takes no pins"
    entries = [d for d in requester.states.values() if d["record"]["type"] == content_store.SIGNED_PIN_TYPE]
    (entry,) = entries
    signed = content_store.decode_signed_pin(requester.payload_of(entry))
    assert signed is not None and content_store.signed_pin_violation(signed) is None
    assert content_store.signed_pin_consented(signed, GROUP)
    pin = signed["pin"]
    assert pin["root"] == root and pin["kind"] == content_store.KIND_TREE and pin["requester"] == requester.identity.peer_id
    assert pin["copies"] == signed["left"] == 1 and pin["attrs"] == {Stores.STORES_ATTR: store_a.identity.peer_id}
    assert signed["notAfter"] == clock.millis + Stores.PIN_ENTRY_LEASE_MS
    assert entry["record"]["tags"] == {"root": root, "requester": requester.identity.peer_id}
    assert root in content.trees.held_roots(), "the requester holds the tree so a store can fetch it"
    assert not any(d["record"]["type"] == content_store.STORE_PIN_TYPE for d in requester.states.values())


def test_store_for_writes_nothing_when_no_store_fits_or_the_tree_is_not_held():
    _clock, (_requester, store_a, _b), content, pdt = _fleet()
    store_a.publish_ad("AssetCard", _card(store_a.identity.peer_id, free="10"))
    root = PMap.empty(pdt.store).assoc_many({f"k{i}": "v" * 50 for i in range(50)}).root()
    stores = Stores(content, pdt.store)
    with pytest.raises(ValueError, match="no content store fits"):
        stores.store_for(root, copies=1, lease_s=60)
    with pytest.raises(ValueError, match="not complete"):
        stores.store_for(cids.of(b"a root this peer never held"), copies=1, lease_s=60)
    assert not [d for d in content.peer.states.values() if d["record"]["type"] == content_store.SIGNED_PIN_TYPE]


def test_receipts_count_only_unexpired_receipts_their_holder_signed():
    clock, (_requester, store_a, store_b), content, pdt = _fleet()
    root = cids.of(b"pinned")
    until = clock.millis + 60_000
    for writer, holder in ((store_a, store_a), (store_b, store_a), (store_b, store_b)):
        receipt = content_store.store_receipt(root, holder.identity.peer_id, 1000, until, False)
        writer.write_entry("content", content_store.STORE_RECEIPT_TYPE, receipt, lease_millis=60_000,
                           tags=content_store.store_receipt_tags(receipt))
    stores = Stores(content, pdt.store)
    assert sorted(r["holder"] for r in stores.receipts(root)) == sorted([store_a.identity.peer_id,
                                                                         store_b.identity.peer_id])
    clock.advance(60_001)
    assert stores.receipts(root) == []
