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

"""SPEC §6.3 (v0.1.32; AppCard origin and formats, 2026-11-09): the advertisement cache keeps a byte budget beside
its entry count, as Java's ``AdCache`` does. After expired entries leave, it refuses a new id that would pass either
bound and a newer version that would pass the budget, keeping the version it holds; it counts each refusal and
strikes nobody. No card is refused for its own size below the budget."""

import threading

import pytest

from agentspaces import wire
from agentspaces.identity import Identity, instant_iso
from agentspaces.peer import AD_CACHE_MAX_BYTES, AD_CACHE_MAX_ENTRIES, Peer

GROUP = "zBudget"
NOW_MS = 1_762_675_200_000  # 2025-11-09T08:00:00Z


def _peer(**options) -> Peer:
    return Peer(Identity.generate(), GROUP, clock=lambda: NOW_MS / 1000, **options)


def _stored(issuer: Identity, name: str, description: str, issued_ms: int = NOW_MS, ttl: str = "PT10M") -> dict:
    card = wire.agent_card(GROUP, issuer, name, instant_iso(issued_ms), ttl, description, [], [], [], {}, {})
    return wire.stored_ad("AgentCard", card, issuer)


def _size(stored: dict) -> int:
    return len(stored["adBytes"])


def test_the_defaults_are_javas():
    assert AD_CACHE_MAX_ENTRIES == 8192 and AD_CACHE_MAX_BYTES == 33_554_432
    peer = _peer()
    assert peer.ad_cache_max_entries == 8192 and peer.ad_cache_max_bytes == 33_554_432
    assert peer.ad_cache_bytes == 0 and peer.ads_refused_cache_full == 0
    with pytest.raises(ValueError):
        _peer(ad_cache_max_bytes=0)
    with pytest.raises(ValueError):
        _peer(ad_cache_max_entries=0)


def test_a_new_id_is_refused_at_the_byte_budget_and_one_that_fits_exactly_enters():
    issuer = Identity.generate()
    first = _stored(issuer, "a", "x" * 400)
    peer = _peer(ad_cache_max_bytes=_size(first) * 2)
    assert peer.accept_ad(first) is not None and peer.ad_cache_bytes == _size(first)
    large = _stored(issuer, "b", "x" * 500)
    assert peer.accept_ad(large) is None and peer.ads_refused_cache_full == 1
    fits = _stored(issuer, "c", "x" * 400)
    assert _size(fits) == _size(first)
    assert peer.accept_ad(fits) is not None and peer.ad_cache_bytes == peer.ad_cache_max_bytes
    assert set(peer.ads) == {first_id(first), first_id(fits)}


def first_id(stored: dict) -> str:
    from agentspaces import cbor
    return cbor.loads(stored["adBytes"])["id"]


def test_a_new_id_is_refused_at_the_entry_bound():
    issuer = Identity.generate()
    peer = _peer(ad_cache_max_entries=2)
    assert peer.accept_ad(_stored(issuer, "a", "")) and peer.accept_ad(_stored(issuer, "b", ""))
    assert peer.accept_ad(_stored(issuer, "c", "")) is None and peer.ads_refused_cache_full == 1
    # an update of a held id lands while the cache is full
    assert peer.accept_ad(_stored(issuer, "a", "newer", NOW_MS + 1000))["ad"]["description"] == "newer"


def test_a_newer_version_that_would_pass_the_budget_is_refused_and_the_held_one_stays():
    issuer = Identity.generate()
    small = _stored(issuer, "a", "x" * 100)
    peer = _peer(ad_cache_max_bytes=_size(small) + 50)
    assert peer.accept_ad(small) is not None
    grown = _stored(issuer, "a", "x" * 200, NOW_MS + 1000)
    assert peer.accept_ad(grown) is None and peer.ads_refused_cache_full == 1
    assert peer.ads[first_id(small)]["ad"]["description"] == "x" * 100 and peer.ad_cache_bytes == _size(small)
    shrunk = _stored(issuer, "a", "x" * 10, NOW_MS + 2000)
    assert peer.accept_ad(shrunk) is not None and peer.ad_cache_bytes == _size(shrunk)
    # an older version leaves the held one in place and counts nothing
    assert peer.accept_ad(small)["ad"]["description"] == "x" * 10 and peer.ads_refused_cache_full == 1


def test_expired_entries_leave_before_the_bounds_refuse():
    issuer = Identity.generate()
    clock = {"ms": NOW_MS}
    peer = Peer(Identity.generate(), GROUP, clock=lambda: clock["ms"] / 1000, ad_cache_max_entries=1)
    assert peer.accept_ad(_stored(issuer, "a", "", ttl="PT1M")) is not None
    clock["ms"] += 61_000
    fresh = _stored(issuer, "b", "", issued_ms=clock["ms"])
    assert peer.accept_ad(fresh) is not None and list(peer.ads) == [first_id(fresh)]
    assert peer.ad_cache_bytes == _size(fresh) and peer.ads_refused_cache_full == 0


def test_an_advertisement_larger_than_the_whole_budget_never_enters():
    issuer = Identity.generate()
    huge = _stored(issuer, "a", "x" * 2000)
    peer = _peer(ad_cache_max_bytes=_size(huge) - 1)
    assert peer.accept_ad(huge) is None and peer.ads == {} and peer.ad_cache_bytes == 0
    # a card past the spill threshold still enters a cache with room: no size cap refuses it
    big = _stored(issuer, "b", "x" * (wire.CARD_SPILL_THRESHOLD_BYTES + 10))
    roomy = _peer()
    assert roomy.accept_ad(big) is not None and roomy.ad_cache_bytes == _size(big)


def test_an_equal_issue_instant_leaves_the_held_version_in_place():
    issuer = Identity.generate()
    peer = _peer()
    held = _stored(issuer, "a", "first")
    assert peer.accept_ad(held) is not None
    same_instant = _stored(issuer, "a", "second, same issued")
    assert peer.accept_ad(same_instant)["ad"]["description"] == "first", "Java keeps it: issued is not after"
    assert peer.ad_cache_bytes == _size(held)


def test_two_threads_admitting_one_id_keep_the_newer_version_and_the_byte_sum():
    """The caller's publish and the reader thread admit the same id at once (AdCache.admit is synchronized):
    the older admission pauses inside the bound check while the newer one arrives."""
    issuer = Identity.generate()
    peer = _peer()
    older, newer = _stored(issuer, "a", "older"), _stored(issuer, "a", "newer, longer", NOW_MS + 1000)
    inside, newer_done = threading.Event(), threading.Event()
    fits = peer._fits

    def paused_fits(ad_id, length):
        if threading.current_thread().name == "older":
            inside.set()
            newer_done.wait(0.5)  # the newer admission finishes here unless admission excludes it
        return fits(ad_id, length)

    peer._fits = paused_fits
    first = threading.Thread(target=peer.accept_ad, args=(older,), name="older")
    first.start()
    assert inside.wait(5)
    second = threading.Thread(target=lambda: (peer.accept_ad(newer), newer_done.set()), name="newer")
    second.start()
    first.join(5)
    second.join(5)
    assert peer.ads[first_id(newer)]["ad"]["description"] == "newer, longer"
    assert peer.ad_cache_bytes == _size(newer)
