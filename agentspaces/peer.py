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

"""A minimal wire-compatible AgentSpaces peer (spec M3's non-JVM client):
joins a Java fleet over TCP or TLS in the dial-only posture, stays a live member by
answering PINGs and re-leasing its self-advertisement, writes signed entries
into a replicated space, and reads the space back through anti-entropy by
offering an empty digest and folding the returned states. A peer that holds
only a GroupID and a seed endpoint joins by asking the seed for the founding
document (GROUP_AD_WANT / GROUP_AD, spec §5.1, §9, §10.1) and verifying the
answer against the id it already holds. The point is protocol validation:
nothing on this wire is Java-specific, and this module holds the proof."""

import hashlib
import logging
import random
import socket
import struct
import threading
import time
from typing import Callable

from . import beacon, cbor, records, social, tls, wire
from .identity import (Identity, derive_id, instant_iso, verify_agent_certificate_covering,
                       verify_signed_group_ad)
from . import revocation as revocations
from .seed import Seed, parse_seed


# The join through a document waits in slices of 1 s, 2 s, 4 s, then 5 s each
# inside its budget (the schedule of the Java join by id, ISSUE-BootstrapRobustness §9.4).
JOIN_SLICE_FIRST_S = 1.0
JOIN_SLICE_MAX_S = 5.0


HINT_RECORDLESS = "wire.recordless"
#: The AppCard level a member reads (SPEC §6.1a.2 and §9, v0.1.32; AppCard origin and formats,
#: 2026-11-09): canonical decimal text, read as level N or above. A member at level 2 reads a card's
#: origin, formats, an ``idp`` host, and a spill reference; an issuer writes them only while every
#: member of its view is at level 2.
HINT_APPCARD = "wire.appcard"
#: The AppCard level this client reads and, by default, advertises.
APPCARD_LEVEL = 2
#: The advertisement cache's bounds by default (SPEC §6.3, v0.1.32), Java's ``AdCache`` defaults:
#: the most advertisements it holds and the most bytes of their encodings. This client takes no
#: RENDEZVOUS role, so Java's rendezvous multiplier never applies here.
AD_CACHE_MAX_ENTRIES = 8192
AD_CACHE_MAX_BYTES = 33_554_432
#: How often, at most, the peer looks again at its view's AppCard level when no member changed:
#: often enough to see a member's advertisement lapse within a gossip period of one second.
APPCARD_GATE_RECHECK_MS = 1000
#: Recordless states held for entries this replica lacks, at most (PD-L-02), as the Java peer's
#: ``ReplicatedSpace.MAX_PENDING_STATES``; the oldest is dropped past the bound.
MAX_PENDING_STATES = 1024
#: The items of followed streams remembered so each is handed over once, as the gossip bus's dedup memory holds them.
STREAM_ITEMS_REMEMBERED = 4096
#: How long a pending recordless state waits for its record before it is dropped (ten minutes).
PENDING_STATE_TTL_S = 600.0
#: How many distinct refused states and claims, and how many distinct deferred ones, the peer
#: remembers so a re-offer counts once (HLC canonical stamps, 2026-11-08; HLC round four,
#: 2026-11-08); past the bound each memory forgets the least recently offered key, as Java's
#: do (HLC round five, 2026-11-08, decision E14).
REFUSED_STAMPS_CAPACITY = 4096
#: How far a claim's stamp may predate the issue stamp of the entry it answers, as Java's
#: ``ReplicatedSpace.MAX_CLAIM_PREDATES_ISSUE_MILLIS`` (the HLC drift bound; HLC round six,
#: 2026-11-08, R6).
MAX_CLAIM_PREDATES_ISSUE_MILLIS = wire.MAX_HLC_SKEW_MILLIS
#: The race allowance a contesting claim's stamp gets past the drift bound: Java's default
#: ``ReplicatedSpace`` settle window, 200 ms (HLC round six, 2026-11-08, R6).
CONTEST_SETTLE_MILLIS = 200
#: The fewest claims the claim map holds before ``_prune_claims`` scans it (HLC round six,
#: 2026-11-08, R10), as Ruby's ``CLAIMS_PRUNE_FLOOR``.
CLAIMS_PRUNE_FLOOR = 1024

# What the peer does with a verified state or claim after judging its stamps (HLC round
# four, 2026-11-08, decisions D1 and D4), and, for a refusal, the counter it adds to (HLC
# round five, 2026-11-08, decision E2).
_MERGE, _DEFER = "merge", "defer"
_REFUSE_LOGICAL, _REFUSE_FAR_FUTURE = "stamps_logical_refused", "stamps_far_future_refused"

LOG = logging.getLogger(__name__)


def appcard_level_of(text) -> int:
    """The AppCard level a hint's text states, as Java's ``PeerNode.appCardLevelOf`` reads it:
    canonical decimal text, so ``2``, ``10``, or a value past every int reads as at least that
    level; no hint, any other text, a leading zero, and ``0`` read as level 1."""
    if not isinstance(text, str) or not text or (len(text) > 1 and text[0] == "0"):
        return 1
    if any(char < "0" or char > "9" for char in text):
        return 1
    return (1 << 31) - 1 if len(text) > 9 else max(1, int(text))


def _ad_expires_ms(ad: dict) -> int:
    from .identity import parse_duration_millis, parse_instant_millis
    return parse_instant_millis(ad["issued"]) + parse_duration_millis(ad["ttl"])


def _is_tree_root(ref: str) -> bool:
    """Whether a ``b`` reference names a persistent tree (dag-cbor) rather than a piece artifact."""
    try:
        from .pdt import cids as _cids
        return _cids.codec_of(ref) == _cids.DAG_CBOR
    except Exception:  # noqa: BLE001 - a malformed reference is no tree
        return False


def _remember(memory: dict, key: tuple) -> bool:
    """Marks ``key`` most recently offered in a bounded memory and returns whether it was new;
    past REFUSED_STAMPS_CAPACITY the least recently offered key goes (HLC round five,
    2026-11-08, decision E14)."""
    new = memory.pop(key, None) is None
    memory[key] = True
    if len(memory) > REFUSED_STAMPS_CAPACITY:
        del memory[next(iter(memory))]
    return new


class BootstrapTimeout(TimeoutError):
    """``Peer.bootstrap`` spent its ``join_timeout``: the message and the attributes say
    how many times the document was fetched, how many seeds were dialed and how many
    of them connected. A TimeoutError is an OSError, so callers that caught the
    OSError of a failed dial still do."""

    def __init__(self, message: str, *, fetches: int, dialed: int, connected: int):
        super().__init__(message)
        self.fetches = fetches
        self.dialed = dialed
        self.connected = connected


class Peer:
    """One Python peer attached to one group through one seed connection."""

    def __init__(self, identity: Identity, group: str, clock=None, founder: str | None = None, *,
                 appcard_level: int = APPCARD_LEVEL, ad_cache_max_entries: int = AD_CACHE_MAX_ENTRIES,
                 ad_cache_max_bytes: int = AD_CACHE_MAX_BYTES,
                 spill_max_fetch_bytes: int = wire.CARD_SPILL_MAX_FETCH_BYTES):
        if not 1 <= appcard_level <= APPCARD_LEVEL:
            raise ValueError(f"this client reads AppCard levels 1 to {APPCARD_LEVEL}: {appcard_level}")
        if ad_cache_max_entries <= 0 or ad_cache_max_bytes <= 0 or spill_max_fetch_bytes <= 0:
            raise ValueError("the cache bounds and the spill fetch bound are positive")
        self.identity = identity
        self.group = group
        self._socket = None
        self._lock = threading.Lock()
        self._reader = None
        self.states = {}  # entryId -> decoded EntryStateDto dict
        # One read, join and write of a state at a time: a fold on the reader thread, and a completion
        # or a renewal on a caller's, so neither overwrites what the other wrote (core cancel events
        # review, 2026-11-09)
        self._state_lock = threading.RLock()
        self.claims = {}  # entryId -> winning SignedClaim dict (lattice merge)
        self._claims_prune_at = CLAIMS_PRUNE_FLOOR  # the claim map's size that runs _prune_claims
        # Seconds since the epoch; a test pins it to verify time-bound material
        # (agent certificates) against a fixed instant, as Java's TestClock does.
        self.clock = clock or time.time
        self.on_state = None  # optional callback(dto)
        # optional callback(dto) after a fold withdraws an entry that was present here: a cancel
        # (core cancel events, 2026-11-09), which a Space announces as EXPIRED
        self.on_withdrawn = None
        self.on_claim = None  # optional callback(entry_id, signed_claim) after a claim folds
        # Handlers of the gossip streams a capability follows, by stream id: a pushed delta's bundles ride
        # pdt:<space>:<name> (PDT 2 phase 7, P2-P-02), each item handed over once
        self.stream_handlers: dict[str, Callable] = {}
        self._stream_items: dict[str, None] = {}
        # Layer 4 (SPEC §6, §8): the members heard from, the advertisements
        # the 'ads' stream carried, and the capability frames handlers.
        self.members: dict[str, dict] = {}   # peer id -> its PeerAdvertisement (or {} when only heard)
        # The members a frame of ours can reach: those that signed a frame that
        # arrived on our connection. A dial-only peer has one socket, so a
        # member learned only from the peers stream (another dial-only peer
        # behind the same seed) is not among them, and an addressed frame to
        # it would be dropped by the seed rather than relayed.
        self.reachable: set[str] = set()
        self.ads: dict[str, dict] = {}       # ad id -> {"type", "ad", "stored", "issuer", "expires"}
        # SPEC §6.3 (v0.1.32; AppCard origin and formats, 2026-11-09): the cache's two bounds, the
        # sum of the cached encodings, and the advertisements it refused at either bound.
        self.ad_cache_max_entries = ad_cache_max_entries
        self.ad_cache_max_bytes = ad_cache_max_bytes
        self.ad_cache_bytes = 0
        self.ads_refused_cache_full = 0
        # Admission runs on the caller's thread (publish_ad, semantic hits) and the reader's, so the
        # check against the bounds and the store happen under one lock, as AdCache.admit is synchronized.
        self._ads_lock = threading.Lock()
        self.pipe_handlers: dict[str, object] = {}  # capability type -> fn(from_peer, payload bytes)
        # The group's revocations (SPEC §5.6, v0.1.13): peer revocations and
        # credential revocations, verified founder-rooted (when the founder is
        # known, from ``founder`` or the verified founding document) or, for an
        # agent and its keys, by the agent's own peer. Applied at merge.
        self.revocations = revocations.Registry(lambda: self._founder(), lambda: self.group)
        self._configured_founder = founder
        self._running = False
        # The verified SignedGroupAdvertisement this peer joined with, once a
        # GROUP_AD answer passed the four checks of spec §5.1 (join_by_group_id).
        self.founding = None
        self._founding_ready = threading.Event()
        # ROBUSTNESS.md: late, replayed and unknown frames are the normal case; count, never fail.
        self.frames = wire.FrameFilter()
        # Verified states and claims this peer refused for their stamps, each counted once
        # however often it is offered, and space deltas that did not decode, each counted
        # every time; the names follow the Java node's stampsLogicalRefused and
        # deltasUndecodable (HLC round four, 2026-11-08, decision D5). A hostile far-future
        # stamp counts apart from a logical counter above the limit, and a deferral counts
        # once per distinct offer, as Java's stampsFarFutureRefused and
        # stampsFarFutureDeferred (HLC round five, 2026-11-08, decision E2). This client keeps
        # no strikes, so a count is all a refusal leaves.
        self.stamps_logical_refused = 0
        self.stamps_far_future_refused = 0
        self.stamps_far_future_deferred = 0
        self.deltas_undecodable = 0
        self._refused_seen: dict[tuple, bool] = {}
        self._deferred_seen: dict[tuple, bool] = {}
        self.ignored_kinds: dict[str, int] = {}
        self.malformed_frames = 0
        # A lost socket is reconnected to the seed and the peer re-introduced and re-pulled, with
        # rounds of dials that back off from reconnect_interval_s to six times it (5, 10, 20, 30 s)
        # with a random spread, until the owner's close(), which is final (swarm retries).
        self._seed = None
        # The seeds connect_any was given, dialed in order and failed over across on a
        # lost socket (SRAD DB-X-01); a bootstrap also sets _refresh_seeds, which
        # re-fetches the beacon document when the window would expire with nothing
        # reachable (SRAD §7.7).
        self._seeds: list = []
        self._refresh_seeds = None
        # The ``tls`` binding (SPEC §5.6): this peer's channel certificate, generated on
        # the first tls dial; the PeerID the current connection's handshake attested (None
        # on tcp); the socket a CHANNEL_HELLO was announced on; and how many frames
        # arrived bare under that attestation.
        self._credentials = tls.ChannelCredentials(identity)
        self._attested: str | None = None
        self._hello_sent_on = None
        self.attested_frames = 0
        # The resource hints this peer's self-advertisement carries (SPEC §5.1): a join
        # credential under ``aspace:join`` for an INVITE group, set by join_invite.
        self.resource_hints: dict[str, str] = {}
        # The wire hints this peer's self-advertisement carries beside the resource hints
        # (SPEC v0.1.17 §9): ``wire.recordless`` says this client accepts a renew, cancel, or
        # complete whose EntryStateDto carries no record (srad/agentspaces-pdt.md §3.9, PD-L-04).
        self.wire_hints: dict[str, str] = {HINT_RECORDLESS: "1"}
        # ``wire.appcard`` (SPEC §6.1a.2, v0.1.32): this client reads the v0.1.32 AppCard and
        # AgentCard; level 1 advertises no hint, so a test builds a mixed fleet with it.
        self.appcard_level = appcard_level
        if appcard_level > 1:
            self.wire_hints[HINT_APPCARD] = str(appcard_level)
        # The cards this peer issues (SPEC §6.1a.2 and §6.1a.5): each full AppCard and AgentCard
        # by id with its type, the issue instant last signed, the view's AppCard level as the
        # last look saw it, the roots of parts documents held to the expiry of the last card
        # that named them, the size each card id last warned at, and the counters under Java's
        # names (appCardsDowngraded, cardsSpilled, cardsOversizeInline, spillsRefused,
        # spillsOverLimit).
        self._cards: dict[str, tuple[str, dict]] = {}
        self._cards_lock = threading.RLock()  # the card state, shared by callers and the reader thread
        self._signed_issued: dict[str, int] = {}
        self._gate_open: bool | None = None
        self._gate_checked_ms = 0
        self._spill_holds: dict[str, int] = {}
        self._warned: dict[str, int] = {}
        self.spill_max_fetch_bytes = spill_max_fetch_bytes
        self.app_cards_downgraded = 0
        self.cards_spilled = 0
        self.cards_oversize_inline = 0
        self.spills_refused = 0
        self.spills_over_limit = 0
        # The pdt facade, when one is built over this peer: it reassembles a dag-cbor payloadRef
        # (a persistent tree, srad/agentspaces-pdt.md PD-E-01) where the content swarm serves a
        # raw artifact root; without one such an entry stays invisible here.
        self.pdt = None
        # Recordless states for entries whose record has not arrived yet, by entry id:
        # merged when anti-entropy ships the whole DTO, and no event before that (PD-L-02).
        self.pending_states: dict[str, dict] = {}
        self._pending_since: dict[str, float] = {}
        # After join_invite: the key pinned to the delegation this peer joined under
        # (persist it and pass it to join_invite on the next start).
        self.pinned_invite: str | None = None
        self._pulled_spaces: set[str] = set()
        self._pulled_ads = False
        # SPEC v0.1.23 (srad/large-networks-bulk-data.md): the seed's PeerID, learned from
        # the first frame it addresses to us. A dial-only peer reaches the seed directly
        # and every other member through it (a RELAY_FRAME the seed forwards), and it
        # declares the seed as its relay in the ``relay.via`` hint so members reach it
        # the same way back. ``max_path_hops`` bounds a path through further relays.
        self.seed_peer: str | None = None
        self.max_path_hops = 4
        self.relayed_frames = 0
        self.relay_signals: list[dict] = []
        # Block-stored payloads (SPEC §7.1, ``z`` references): blocks this peer put or
        # fetched, by id, and the ids it asked for with when it asked.
        self.blocks: dict[str, bytes] = {}
        self._block_asked: dict[str, float] = {}
        # The content swarm attached to this peer (``agentspaces.capabilities.content``):
        # resolves ``b`` references and takes payloads above its escalation bound.
        self.content = None
        #: The wait after the first round of reconnect dials; each later round doubles it, up to six times it.
        self.reconnect_interval_s = 5.0
        #: How long the seeds are dialed before a bootstrapped peer reads its beacon document again.
        self.reconnect_window_s = 600.0
        self.reconnects = 0
        # When the current link was dialed, and how many links in a row ended within the reconnect
        # interval: such a link counts as a failed round of dials (swarm retries, ROBUSTNESS.md §10.6).
        self._link_since = 0.0
        self._quick_drops = 0
        # Fold-driven waits (JS-V-02): a take, a read, or an ordered take waits on the
        # next fold (a state or a claim) rather than polling, and pulls a space at most
        # once per settle window.
        self._fold_condition = threading.Condition()
        self._fold_count = 0
        self._last_pull: dict[str, float] = {}  # space name -> monotonic seconds of the last pull

    # ------------------------------------------------------------- lifecycle

    def connect(self, host, port: int | None = None, *, scheme: str = "tcp",
                dial_timeout: float = 10.0) -> None:
        """Dials the seed and introduces this peer to the group. ``host`` and ``port``
        name a ``tcp`` seed unless ``scheme`` says ``tls``; ``host`` alone may be a seed
        in text (``tls://host:port``, ``host:port``) or a ``Seed``."""
        seed = parse_seed(host) if port is None else Seed(str(host), int(port), scheme.lower())
        self._seed = seed
        self._socket = self._dial(seed, dial_timeout)
        self._running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.introduce()
        self.pull_revocations()

    def connect_any(self, seeds) -> tuple:
        """Dials the seeds, (host, port) pairs, in order until one accepts, and
        remembers them all: a lost socket fails over to the next seed inside the
        reconnect window (SRAD DB-X-01). A hostname is resolved to every address
        and each is a seed (DB-X-03). Returns the seed connected to; raises OSError
        when none accepted. ``connect(host, port)`` is unchanged underneath."""
        expanded = self._expand_seeds(seeds)
        if not expanded:
            raise OSError("no seeds to dial")
        self._seeds = expanded
        last = None
        for seed in expanded:
            try:
                self.connect(seed.host, seed.port, scheme=seed.scheme)
                return seed
            except OSError as e:
                last = e
        raise OSError(f"no seed accepted: {[str(s) for s in expanded]}") from last

    @staticmethod
    def _expand_seeds(seeds) -> list:
        """Seeds (pairs, triples, text, or ``Seed``) as ``Seed`` tuples, a hostname
        resolved to every address (DB-X-03), duplicates folded, order kept."""
        expanded = []
        for given in seeds:
            seed = parse_seed(given)
            addresses = []
            try:
                for info in socket.getaddrinfo(seed.host, seed.port, type=socket.SOCK_STREAM):
                    addresses.append(Seed(info[4][0], seed.port, seed.scheme))
            except (OSError, ValueError):
                addresses = [seed]
            for address in addresses or [seed]:
                if address not in expanded:
                    expanded.append(address)
        return expanded

    def _dial(self, seed: Seed, timeout: float):
        """One connected socket for ``seed`` by its scheme: ``tcp`` plain, ``tls`` with
        this peer's channel certificate and the seed's attested (``agentspaces.tls``).
        Records the attestation for the reader. Raises OSError for a scheme this
        client does not dial, as for a refused connection."""
        if seed.scheme == "tcp":
            sock = socket.create_connection((seed.host, seed.port), timeout=timeout)
            attested = None
        elif seed.scheme == "tls":
            sock, attested = tls.connect(seed.host, seed.port, self.identity, timeout=timeout,
                                         credentials=self._credentials)
        else:
            raise OSError(f"no dialer for {seed}: this client dials tcp and tls")
        sock.settimeout(None)
        self._attested = attested
        self._link_since = time.monotonic()
        return sock

    def _candidate_seeds(self) -> list:
        """The seeds to try on a lost socket: the one after the current first, the
        current one last, so the failover goes to the next seed."""
        if not self._seeds:
            return [self._seed] if self._seed else []
        if self._seed in self._seeds:
            i = self._seeds.index(self._seed)
            return self._seeds[i + 1:] + self._seeds[:i + 1]
        return list(self._seeds)

    def _reconnect(self) -> bool:
        """After a lost socket: dials the seed again (every seed of connect_any, the next
        one first), then introduces this peer again and pulls what it had pulled before, so
        a network hiccup costs a few seconds rather than the membership (ROBUSTNESS.md §3.6).
        The rounds back off from reconnect_interval_s to six times it with a random spread,
        so the clients of a seed that restarts do not all dial it at once, and they go on
        until the owner closes the peer (swarm retries, ROBUSTNESS.md §10.3 E5). A link
        that ended within reconnect_interval_s of its dial counts as a failed round, so a
        seed that accepts each dial and drops it at once gets the same pauses and no dial
        loop (ROBUSTNESS.md §10.6). A bootstrapped peer reads the beacon document again
        every reconnect_window_s with nothing reachable, and keeps the seeds it has when
        the beacon is unreachable too."""
        if time.monotonic() - self._link_since < self.reconnect_interval_s:
            self._quick_drops += 1
            time.sleep(self._reconnect_pause(self._quick_drops))
        else:
            self._quick_drops = 0
        deadline = time.monotonic() + self.reconnect_window_s
        rounds = 0
        while self._running:
            if time.monotonic() >= deadline:
                deadline = time.monotonic() + self.reconnect_window_s
                if self._refresh_seeds is not None:
                    try:
                        seeds = self._expand_seeds(self._refresh_seeds())
                    except Exception:  # noqa: BLE001 - the beacon is unreachable too: the seeds held stay
                        seeds = None
                    if seeds:
                        self._seeds = seeds
            for seed in self._candidate_seeds():
                if not self._running:
                    return False
                try:
                    fresh = self._dial(seed, 10)
                except OSError:
                    continue
                with self._lock:
                    self._socket = fresh
                self._seed = seed
                self.reconnects += 1
                self.introduce()
                self.pull_revocations()
                if self._pulled_ads:
                    self.pull_ads()
                for space in list(self._pulled_spaces):
                    self.pull_space(space)
                return True
            rounds += 1
            time.sleep(self._reconnect_pause(rounds))
        return False

    def _reconnect_pause(self, rounds: int) -> float:
        """The pause after the ``rounds``-th failed round of dials: reconnect_interval_s doubling
        to six times it, with a random spread of up to a quarter (swarm retries)."""
        wait = min(6 * self.reconnect_interval_s, self.reconnect_interval_s * 2 ** min(rounds - 1, 3))
        return wait * random.uniform(1.0, 1.25)

    def bootstrap(self, url: str, *, group_id: str | None = None, allow_plain: bool = False,
                  beacon_peer: str | None = None, timeout: float = 3.0,
                  join_timeout: float = 10.0) -> dict:
        """Joins through a beacon document (SRAD DB-X-01): fetches and verifies the
        document at ``url`` (https unless ``allow_plain``; signed by ``beacon_peer`` when
        pinned), selects the group (by ``group_id``, else the only one), verifies its
        founding advertisement with the four checks of SPEC §5.1 against ``group_id``
        when given, and dials its ``tcp`` seeds in priority order.
        Returns the verified SignedGroupAdvertisement, kept on ``peer.founding``.

        ``timeout`` bounds one attempt (one fetch, one dial of one seed) and
        ``join_timeout`` bounds the whole call. A first attempt that succeeds asks once
        and dials once. Otherwise the call keeps asking inside the budget, in slices of
        1 s, 2 s, 4 s, then 5 s each (the shape of the Java join by id,
        ISSUE-BootstrapRobustness FR-4): at the start of each slice it fetches the
        document again when the previous fetch failed with an OSError or named no tcp
        seed, and dials again, once per slice, every seed that refused. A beacon or a
        seed that starts a few seconds after this peer is reached on a later slice.
        A refusal (a bad scheme, a document or founding that does not verify, a
        founding for another id, a group the document does not carry) raises ValueError
        at once, as before. When the budget runs out the call raises
        :class:`BootstrapTimeout` (an OSError) whose message and attributes carry the
        number of fetches, the seeds dialed, how many connected, and the last error."""
        deadline = time.monotonic() + join_timeout
        fetches = 0
        dialed: list = []
        connected = 0
        last_error: Exception | None = None
        founding = None
        seeds: list = []
        slice_s = JOIN_SLICE_FIRST_S

        def refresh():
            fresh = beacon.fetch_beacon_document(url, allow_plain=allow_plain,
                                                 beacon_peer=beacon_peer, timeout=timeout)
            return beacon.seeds_of(beacon.group_from_document(fresh, group_id=self.group))

        while True:
            started = time.monotonic()
            if not seeds:
                fetches += 1
                try:
                    doc = beacon.fetch_beacon_document(
                        url, allow_plain=allow_plain, beacon_peer=beacon_peer,
                        timeout=min(timeout, max(deadline - started, 0.001)))
                    group = beacon.group_from_document(doc, group_id=group_id)
                    founding = self._adopt_founding(group, group_id)
                    seeds = self._expand_seeds(beacon.seeds_of(group))
                    if seeds:
                        self._refresh_seeds = refresh
                    else:
                        last_error = ValueError(
                            f"the beacon document names no tcp or tls seed for {group.get('name')!r}")
                except OSError as e:  # the beacon is unreachable or answered an error: ask again
                    last_error = e
            for seed in seeds:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if seed not in dialed:
                    dialed.append(seed)
                self._seeds = seeds
                try:
                    self.connect(seed.host, seed.port, scheme=seed.scheme,
                                 dial_timeout=min(timeout, remaining))
                except OSError as e:
                    last_error = e
                    continue
                connected += 1
                return founding
            now = time.monotonic()
            wait = min(slice_s - (now - started), deadline - now)
            if wait > 0:
                time.sleep(wait)
            if time.monotonic() >= deadline:
                raise BootstrapTimeout(
                    f"no join through {url} within {join_timeout:g}s: {fetches} fetch(es), "
                    f"{connected} of {len(dialed)} seed(s) connected; last error: {last_error}",
                    fetches=fetches, dialed=len(dialed), connected=connected) from last_error
            slice_s = min(slice_s * 2, JOIN_SLICE_MAX_S)

    def join_invite(self, key_text: str, *, allow_plain: bool = False, timeout: float = 3.0) -> tuple:
        """Joins a group for friends with an invite key (SRAD DB-X-07): parses the key,
        fetches the social beacon's document at ``/j/<code>``, takes the delegation from
        the key or the document's ``invite`` field, derives this peer's delegated
        credential with the invite signing key and carries it in the self-advertisement
        under ``aspace:join``, verifies the document's founding against the delegation's
        group, and dials the seeds. Returns ``(content_key, group_id)``: the 32-byte
        content key, epoch 0, and the verified GroupID."""
        key = social.InviteKey.parse(key_text)
        scheme = "http" if allow_plain else "https"
        doc = beacon.fetch_beacon_document(key.document_url(scheme), allow_plain=allow_plain,
                                           timeout=timeout)
        groups = doc.get("groups") or []
        group = None
        if key.delegation is not None:
            try:
                group = beacon.group_from_document(doc, group_id=social.delegation_group(key.delegation))
            except ValueError:
                group = None
        if group is None:
            if len(groups) != 1:
                raise ValueError(f"the beacon knows no group under {key.code}")
            group = groups[0]  # a social beacon serves one group per code
        delegation = key.delegation or group.get("invite")
        if not delegation:
            raise ValueError("the invite key carries no delegation and the beacon document has none")
        group_id = social.delegation_group(delegation)
        founding = self._adopt_founding(group, group_id)
        credential = social.issue_delegated(delegation, key.secret.invite_private_seed(),
                                            self.identity.peer_id)
        issuer = founding["advertisement"]["issuer"]
        verdict = social.judge_delegated_credential(credential, self.identity.peer_id, issuer,
                                                    group_id, self._now_ms())
        if verdict == "invalid":
            raise ValueError("the invite key's delegation does not admit this peer to the group "
                             "(not the founder's, or for another group)")
        # An expired delegation still admits a peer the members admitted while it was valid
        # (SPEC §5.1, v0.1.20); a newcomer is refused by the members, not here.
        self.resource_hints[social.HINT_KEY] = credential
        self.delegation = delegation
        # Keep this key and join with it next time: it carries the delegation this peer was
        # admitted under, so a restart presents the same credential even after the founder
        # re-delegated at the beacon.
        self.pinned_invite = key.with_delegation(delegation).compact()
        seeds = beacon.seeds_of(group)
        if not seeds:
            raise ValueError(f"the beacon document names no tcp or tls seed for {group.get('name')!r}")

        def refresh():
            fresh = beacon.fetch_beacon_document(key.document_url(scheme), allow_plain=allow_plain,
                                                 timeout=timeout)
            return beacon.seeds_of(beacon.group_from_document(fresh, group_id=self.group))
        self._refresh_seeds = refresh
        self.connect_any(seeds)
        return key.secret.content_key(), group_id

    def _adopt_founding(self, group: dict, expected_group_id: str | None) -> dict:
        """Verifies a document group's founding exactly as join_by_group_id verifies a
        GROUP_AD answer (the four checks, then the id this peer wants) and joins on it:
        the group, the founding, and the founder are set before any socket is dialed."""
        derived = beacon.verified_group_id(group, expected_group_id)
        self.group = derived
        self.founding = beacon.founding_of(group)
        self._founding_ready.set()
        return self.founding

    def join_by_group_id(self, host: str, port: int, group_id: str,
                         timeout: float = 10.0, *, scheme: str = "tcp") -> dict:
        """Joins a self-certifying group knowing only its GroupID and one seed
        (spec §5.1, §10.1): dials the seed, sends an unaddressed GROUP_AD_WANT
        for the group (the seed's PeerID is unknown until it answers), waits
        for a GROUP_AD whose body verifies to exactly that GroupID, ignoring
        every answer that fails (§9), and only then introduces this peer.
        Returns the verified SignedGroupAdvertisement. Raises TimeoutError
        when no verified document arrived within ``timeout`` seconds: a
        hostile seed can delay the join and can never substitute a policy."""
        self.group = group_id
        self.founding = None
        self._founding_ready.clear()
        self._seed = Seed(host, int(port), scheme.lower())
        self._socket = self._dial(self._seed, 10)
        self._running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._send(wire.KIND_GROUP_AD_WANT, b"")
        if not self._founding_ready.wait(timeout) or self.founding is None:
            self.close()
            raise TimeoutError(
                f"no verified GROUP_AD for {group_id} from {host}:{port} "
                f"within {timeout}s")
        self.introduce()
        self.pull_revocations()
        return self.founding

    @staticmethod
    def aggregate_roster_token(peer_id: str) -> int:
        """This peer's aspace:cap/aggregate Roster token (spec §8): the first
        8 bytes of sha-256(PeerID) as a signed big-endian int64."""
        return wire.aggregate_roster_token(peer_id)

    def close(self) -> None:
        self._running = False
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None

    def _founder(self):
        if self._configured_founder:
            return self._configured_founder
        if self.founding:
            return (self.founding.get("advertisement") or {}).get("issuer")
        return None

    def _now_ms(self) -> int:
        return int(self.clock() * 1000)

    def counters(self) -> dict[str, int]:
        """The stamp refusals this peer counted, under the Java node's names (HLC round four,
        2026-11-08, decision D5; HLC round five, 2026-11-08, decision E2): frames refused for
        a counter above LOGICAL_LIMIT, frames stamped further past wall + MAX_DRIFT than the
        skew margin, frames within it, verified states and claims refused for a counter above
        the limit, those refused for a stamp an hour past the margin, those deferred for a
        stamp past the margin by less, and space deltas that did not decode."""
        return {"framesLogicalRefused": self.frames.logical_refused,
                "framesFarFuture": self.frames.far_future,
                "framesFarFutureSkewed": self.frames.far_future_skewed,
                "stampsLogicalRefused": self.stamps_logical_refused,
                "stampsFarFutureRefused": self.stamps_far_future_refused,
                "stampsFarFutureDeferred": self.stamps_far_future_deferred,
                "deltasUndecodable": self.deltas_undecodable}

    # ------------------------------------------------------------- protocol

    def introduce(self) -> None:
        """Publishes this peer's leased self-advertisement (spec §5.2)."""
        now_ms = self._now_ms()
        # Whole seconds, as the advertisement has always been stamped.
        ad = wire.peer_advertisement(self.group, self.identity,
                                     instant_iso(now_ms - now_ms % 1000),
                                     resource_hints={**self.wire_hints, **self.resource_hints})
        payload = wire.signed_peer_ad(ad, self.identity)
        item_id = f"peer:{self.identity.peer_id}:{now_ms}"
        self._send("RUMOR", wire.rumor_body("peers", item_id, 6, payload))
        self._announce_channel()

    def _announce_channel(self) -> None:
        """On a connection the transport attested, announces once that this peer
        accepts channel-attested frames there (CHANNEL_HELLO, SPEC §5.6), so a Java
        node in ATTESTED or SESSION mode stops signing every frame toward it. The
        announcement itself travels signed; this peer keeps signing what it sends."""
        sock, attested = self._socket, self._attested
        if sock is None or attested is None or self._hello_sent_on is sock:
            return
        self._hello_sent_on = sock
        self._send("CHANNEL_HELLO", wire.channel_hello_body(True, attested), attested)

    def write_entry(self, space: str, type_name: str, value: dict,
                    agent_name: str = "python", lease_millis: int = 600_000,
                    agent=None, tags: dict | None = None) -> str:
        """Writes one signed entry into a replicated space; returns its id.
        With ``agent`` (an ``AgentIdentity``, v0.1.13) the entry is the agent's
        own: agent-signed record and state, stored AGENT_ATTESTED everywhere.
        ``tags`` travel inside the signed record (SPEC §7.1), where templates
        and tag shards read them."""
        if agent is not None and self.revocations.refuses(agent.agent_id, agent.public_raw, None):
            raise ValueError(f"{agent.agent_id} is revoked in this group")
        payload = cbor.dumps(value)
        payload_ref = None
        if self.content is not None and self.content.escalate_above > 0 \
                and len(payload) > self.content.escalate_above:
            # SPEC §7.1 group E: above the bound the payload becomes an artifact of the
            # content swarm and the record carries its root.
            payload_ref = self.content.publish_opaque(payload, lease_millis)
            payload = None
        elif len(payload) > wire.INLINE_PAYLOAD_LIMIT:
            payload_ref = self.put_block(payload)
            payload = None
        entry_id, body = wire.entry_delta(space, self.group, type_name, payload,
                                          self.identity, agent_name, lease_millis,
                                          agent=agent, now_ms=self._now_ms(), tags=tags,
                                          payload_ref=payload_ref)
        self._send("RUMOR", body)
        # The writer holds its own entry too, so a local read sees it at once.
        delta = cbor.loads(cbor.loads(body)["payload"])
        if isinstance(delta.get("state"), dict):
            self._fold(delta["state"])
        return entry_id

    def publish_ad(self, ad_type: str, ad: dict) -> dict:
        """Publishes an advertisement this peer issued (an AgentCard, an AppCard, an
        AssetCard) on the 'ads' stream, as DiscoveryService.publish does: the stored form,
        under the advertisement's id and issue time. Returns the advertisement as signed.

        An AppCard or AgentCard is a full card, and this peer keeps it (SPEC §6.1a.2 and
        §6.1a.5, v0.1.32; AppCard origin and formats, 2026-11-09): it signs the card without
        origin, formats, and an ``idp`` host while a member of its view is below AppCard
        level 2, as a stub whose large parts sit on the content swarm while the card's
        encoding passes 65,536 bytes, the whole view is at level 2, and a content swarm is
        attached, and in full otherwise. A change of the view's level reissues every card it
        shapes at once; ``withdraw_ad`` stops that."""
        if ad_type in ("AppCard", "AgentCard"):
            if "spill" in ad:
                raise ValueError("publish the full card; the peer spills it when it must")
            if not records.conforms(ad, ad_type):
                raise ValueError(f"no reader decodes this {ad_type} (SPEC §6.1a): {ad.get('id')}")
            with self._cards_lock:
                self._refresh_gate()
                self._cards[ad["id"]] = (ad_type, ad)
                return self._issue_card(ad_type, ad, self._gate_open)
        self._sign_and_send(ad_type, ad)
        return ad

    def withdraw_ad(self, ad_id: str) -> None:
        """Stops reissuing a card: the last one signed lapses at its ttl, and a parts document
        it named is released one ttl after the last card that named it."""
        with self._cards_lock:
            self._cards.pop(ad_id, None)
            self._signed_issued.pop(ad_id, None)

    def _sign_and_send(self, ad_type: str, ad: dict) -> None:
        from .identity import parse_instant_millis
        stored = wire.stored_ad(ad_type, ad, self.identity)
        self.accept_ad(stored)  # our own cache holds it too, as DiscoveryService.publish does
        item_id = f"{ad['id']}:{parse_instant_millis(ad['issued'])}"
        self._send("RUMOR", wire.rumor_body("ads", item_id, 6, cbor.dumps(stored)))

    def _issue_card(self, ad_type: str, card: dict, gate_open: bool) -> dict:
        """Signs a full card for the view (AppCardPublisher.issue): a strictly newer issue
        instant than the last one signed, the gate, then the spill."""
        from .identity import parse_instant_millis
        issued_ms = parse_instant_millis(card["issued"])
        last = self._signed_issued.get(card["id"])
        if last is not None and issued_ms <= last:
            issued_ms = last + 1  # the cache keeps only a strictly newer version
            card = {**card, "issued": instant_iso(issued_ms)}
        self._signed_issued[card["id"]] = issued_ms
        gated = card
        if ad_type == "AppCard":
            gated = wire.app_card_for_view(card, gate_open)
            if gated != card:
                self.app_cards_downgraded += 1
        prepared = self._spill(ad_type, gated, gate_open)
        self._sign_and_send(ad_type, prepared)
        return prepared

    def _spill(self, ad_type: str, card: dict, gate_open: bool) -> dict:
        """CardSpiller.prepare (FR-12, FR-13): the card, or its stub once its parts document is
        on the content swarm."""
        size = len(cbor.dumps(card))
        threshold = wire.CARD_SPILL_THRESHOLD_BYTES
        parts = wire.non_empty_parts(wire.card_parts(card)) if size > threshold else []
        # a card whose size sits outside the spill set (a long name or description) has nothing to move
        spills = bool(parts) and gate_open and self.content is not None
        self._warn_size(ad_type, card, size, spills)
        if size <= threshold:
            return card
        if not spills:
            self.cards_oversize_inline += 1
            return card
        document = cbor.dumps(wire.card_parts(card))
        try:
            root = self.content.put_spill(card["id"], document)
        except (ValueError, OSError) as refused:
            LOG.warning("the content swarm refused the parts document of %s (%s); the card travels inline",
                        card["id"], refused)
            self.cards_oversize_inline += 1
            return card
        self._spill_holds[root] = max(self._spill_holds.get(root, 0), _ad_expires_ms(card))
        self.cards_spilled += 1
        return wire.card_stub(card, wire.card_spill(root, len(document), parts))

    def _warn_size(self, ad_type: str, card: dict, size: int, spills: bool) -> None:
        if size <= wire.CARD_SPILL_WARN_BYTES or self._warned.get(card["id"]) == size:
            return
        self._warned[card["id"]] = size
        kind = f"AppCard (kind {card['kind']})" if ad_type == "AppCard" else ad_type
        if size <= wire.CARD_SPILL_THRESHOLD_BYTES:
            fate = "it travels inline until it passes the threshold"
        elif spills:
            fate = "it spills its large parts to the content swarm"
        else:
            fate = ("it travels inline, since the view is below the AppCard level, no content swarm serves the group,"
                    " or no field of its spill set holds anything")
        LOG.warning("%s %s encodes to %d bytes, past the %d-byte warning; the spill threshold is %d bytes, and %s",
                    kind, card["id"], size, wire.CARD_SPILL_WARN_BYTES, wire.CARD_SPILL_THRESHOLD_BYTES, fate)

    def appcard_gate_open(self) -> bool:
        """Whether this peer and every member of its view read the AppCard level's fields (FR-6,
        FR-7). The view is the member table: a member counts from its first frame or
        advertisement and leaves when its advertisement's lease lapses (SPEC §5.3, leased views);
        one heard from whose advertisement has not arrived counts as level 1."""
        if self.appcard_level < APPCARD_LEVEL:
            return False
        now = self._now_ms()
        for ad in list(self.members.values()):
            if not ad:
                return False
            if _ad_expires_ms(ad) <= now:
                continue
            if appcard_level_of(ad["resourceHints"].get(HINT_APPCARD)) < APPCARD_LEVEL:
                return False
        return True

    def _maintain_cards(self, view_changed: bool) -> None:
        """Reissues every card the gate shapes when the view's level changes, and releases each
        spilled root one ttl after the last card that named it (DiscoveryService's tick work)."""
        with self._cards_lock:
            now = self._now_ms()
            if self._cards and (view_changed or now - self._gate_checked_ms >= APPCARD_GATE_RECHECK_MS):
                self._refresh_gate()
            for root, until in list(self._spill_holds.items()):
                if now >= until:
                    del self._spill_holds[root]
                    if self.content is not None:
                        self.content.release(root)

    def _refresh_gate(self) -> None:
        """Looks at the view's AppCard level; on a change it reissues, at once, every live card
        whose form the gate decides: one with a gated field, or one past the spill threshold."""
        now = self._now_ms()
        self._gate_checked_ms = now
        gate_open, was = self.appcard_gate_open(), self._gate_open
        self._gate_open = gate_open
        if was is None or gate_open == was:
            return
        for ad_type, card in list(self._cards.values()):
            shaped = ad_type == "AppCard" and wire.app_card_for_view(card, False) != card
            if _ad_expires_ms(card) > now and (shaped or len(cbor.dumps(card)) > wire.CARD_SPILL_THRESHOLD_BYTES):
                self._issue_card(ad_type, card, gate_open)

    def resolve(self, card: dict, timeout_s: float | None = None) -> dict:
        """The full card of a stub (SPEC §6.1a.5, FR-15): a card without ``spill`` as it is, and
        otherwise the stub with its parts document's values in place. A ``size`` above
        ``spill_max_fetch_bytes`` fails before any fetch (``spills_over_limit``); a document of
        the wrong length, one that does not decode as the kind's parts record, or one whose
        non-empty fields are not exactly ``spill.parts`` fails (``spills_refused``); each raises
        ``ValueError``. No content swarm raises ``LookupError``, a document no holder serves
        within ``timeout_s`` (the content swarm's 30 s by default) raises ``TimeoutError``, and a fetch that fails for another reason
        (a sealed root, a piece table this client cannot keep inline) raises ``OSError``, each
        uncounted. No failure evicts the stub or strikes anyone."""
        spill = card.get("spill")
        if spill is None:
            return card
        if spill["size"] > self.spill_max_fetch_bytes:
            self.spills_over_limit += 1
            raise ValueError(f"the parts document of {card['id']} is {spill['size']} bytes, above the fetch bound "
                             f"of {self.spill_max_fetch_bytes}")
        if self.content is None:
            raise LookupError(f"no content swarm serves this group, so the stub {card['id']} stays a stub")
        kind = "AgentCard" if "agent" in card else "AppCard"
        try:
            document = (self.content.get_spill(spill["root"], spill["size"]) if timeout_s is None
                        else self.content.get_spill(spill["root"], spill["size"], timeout_s))
        except ValueError as refused:
            self.spills_refused += 1
            raise ValueError(f"the parts document of {card['id']} does not complete its stub: {refused}") from refused
        parts = records.decode(document, kind + ".Parts")
        # the parts record and the stub each passed their decode, which holds every rule of the full card
        if parts is None or wire.non_empty_parts(parts) != list(spill["parts"]):
            self.spills_refused += 1
            raise ValueError(f"the parts document of {card['id']} does not complete its stub")
        return wire.card_complete(card, parts)

    def pull_space(self, space: str) -> None:
        """Anti-entropy pull (spec §5.3): offer an empty digest, and the
        partner answers with every state this replica is missing. The
        revocation streams ride along: a partner answers only the streams a
        digest names, so a late joiner learns the group's revocations here."""
        self._pulled_spaces.add(space)
        self._send("DIGEST", wire.digest_body(
            {f"space:{space}": b"", **{stream: b"" for stream in revocations.STREAMS}}))

    def pull_space_paced(self, space: str, settle_seconds: float) -> bool:
        """Pulls a space unless it was pulled within ``settle_seconds`` (JS-V-02): a
        waiting take issues at most one DIGEST per settle window, and none while
        folds keep arriving. Returns whether a pull went out."""
        now = time.monotonic()
        if now - self._last_pull.get(space, float("-inf")) < settle_seconds:
            return False
        self._last_pull[space] = now
        self.pull_space(space)
        return True

    @property
    def fold_count(self) -> int:
        """How many states and claims have folded so far: a snapshot for ``await_fold``."""
        return self._fold_count

    def await_fold(self, max_seconds: float, since: int | None = None) -> bool:
        """Blocks until the next fold (a state or a claim) or ``max_seconds``, whichever
        comes first. With ``since`` (a ``fold_count`` snapshot taken before a scan) a
        fold between the scan and the wait counts too, so nothing is missed. Returns
        whether a fold woke the wait."""
        with self._fold_condition:
            seen = self._fold_count if since is None else since
            return self._fold_condition.wait_for(lambda: self._fold_count != seen,
                                                 timeout=max(0.0, max_seconds))

    def _wake_fold_waiters(self) -> None:
        with self._fold_condition:
            self._fold_count += 1
            self._fold_condition.notify_all()

    def pull_revocations(self) -> None:
        """Anti-entropy pull of the revocation streams alone (SPEC §5.6): sent
        once on joining, so revocations issued before this peer arrived apply
        from its first merge."""
        self._send("DIGEST", wire.digest_body({stream: b"" for stream in revocations.STREAMS}))

    def pull_ads(self) -> None:
        """Anti-entropy pull of the 'ads' stream (SPEC §6.2): the cards and
        capability advertisements the group holds."""
        self._pulled_ads = True
        self._send("DIGEST", wire.digest_body({"ads": b""}))

    def accept_ad(self, stored) -> dict | None:
        """Admits a StoredAd as AdCache.accept does: a type tag AdCache knows, the
        signature over the advertisement's bytes under the carried key, those bytes
        the record its type tag names in the wire encoding (HLC round six,
        2026-11-08, owner rulings F1 and F3), the issuer derived from that key, the
        TTL not yet passed, and room under the cache's two bounds (SPEC §6.3, v0.1.32).
        Returns the cached entry, or None."""
        from .identity import derive_id, parse_instant_millis
        if not records.conforms(stored, "AdCache.StoredAd") or stored["adType"] not in records.AD_TYPES:
            return None
        ad_bytes, key, signature = stored["adBytes"], stored["publicKey"], stored["signature"]
        if ad_bytes is None or key is None or signature is None or not Identity.verify(key, ad_bytes, signature):
            return None
        ad = records.decode(ad_bytes, stored["adType"])
        if ad is None or ad["issuer"] != derive_id(key):
            return None
        expires = _ad_expires_ms(ad)
        if expires <= self._now_ms():
            return None
        entry = {"type": stored.get("adType"), "ad": ad, "stored": stored, "issuer": ad["issuer"],
                 "expires": expires}
        with self._ads_lock:
            previous = self.ads.get(ad["id"])
            newer = previous is None or parse_instant_millis(previous["ad"]["issued"]) < parse_instant_millis(ad["issued"])
            if not newer:
                return previous  # the held version stays; nothing grows
            if not self._fits(ad["id"], len(ad_bytes)):
                self._evict_expired()
                if not self._fits(ad["id"], len(ad_bytes)):
                    # ASF-019 and SPEC §6.3: a flood fills spare headroom but never evicts a live advertisement
                    self.ads_refused_cache_full += 1
                    return None
            held = self.ads.get(ad["id"])
            self.ad_cache_bytes += len(ad_bytes) - (len(held["stored"]["adBytes"]) if held else 0)
            self.ads[ad["id"]] = entry
            return entry

    def _fits(self, ad_id: str, length: int) -> bool:
        """Whether a newer advertisement of ``length`` bytes fits both bounds, given what the
        cache holds for its id."""
        held = self.ads.get(ad_id)
        if held is None:
            return len(self.ads) < self.ad_cache_max_entries and self.ad_cache_bytes + length <= self.ad_cache_max_bytes
        return self.ad_cache_bytes - len(held["stored"]["adBytes"]) + length <= self.ad_cache_max_bytes

    def _evict_expired(self) -> None:
        """Drops the lapsed advertisements; the caller holds ``_ads_lock``."""
        now = self._now_ms()
        for ad_id, entry in list(self.ads.items()):
            if entry["expires"] <= now:
                del self.ads[ad_id]
                self.ad_cache_bytes -= len(entry["stored"]["adBytes"])

    def cards(self) -> list[dict]:
        """The live AgentCards the ads stream carried."""
        now = self._now_ms()
        return [e["ad"] for e in self.ads.values() if e["type"] == "AgentCard" and e["expires"] > now]

    def app_cards(self) -> list[dict]:
        """The live AppCards the ads stream carried, stubs as they stand: filter them with
        ``wire.from_origin`` and ``wire.handles``, which read the fields a stub keeps, and
        ``resolve`` one before reading its reads, actions, views, or ui."""
        now = self._now_ms()
        return [e["ad"] for e in self.ads.values() if e["type"] == "AppCard" and e["expires"] > now]

    def send_pipe(self, to: str, capability: str, payload: bytes, via: list | None = None) -> None:
        """One capability frame to a member (CapabilityPipes.send): a
        PIPE_DATA envelope addressed to it carrying {capability, payload}. Over a
        socket the seed carries it when ``to`` is any other member (SPEC §5.4);
        ``via`` (the relays the member declared) extends the path past the seed."""
        self.send_addressed("PIPE_DATA", cbor.dumps({"capability": capability, "payload": payload}), to, via)

    def relay_for(self, to: str) -> str | None:
        """The relay an addressed frame to ``to`` goes through, or None for a
        direct send: over a socket, the seed for everyone but the seed itself."""
        if self._seed is None or self.seed_peer is None or to == self.seed_peer:
            return None
        return self.seed_peer

    def send_addressed(self, kind: str, body: bytes, to: str, via: list | None = None) -> None:
        """Sends an addressed frame directly or, when the seed must carry it, wrapped
        in a RELAY_FRAME to the seed (the one-hop form), extended to a path
        ``[seed, via...]`` when ``via`` names other relays (v0.1.23)."""
        relay = self.relay_for(to)
        if relay is None:
            self._send(kind, body, to=to)
            return
        inner = wire.encode_frame(
            wire.envelope(self.group, kind, self.identity.peer_id,
                          wire.hlc_now(self.identity.peer_id, self._now_ms()), body, to), self.identity)
        path = [relay] + [v for v in (via or []) if v != relay and v != to][:max(0, self.max_path_hops - 1)]
        self.relayed_frames += 1
        if len(path) > 1:
            self._send("RELAY_FRAME", wire.relay_frame_body(to, inner, path, 0), to=relay)
        else:
            self._send("RELAY_FRAME", wire.relay_frame_body(to, inner), to=relay)

    # ------------------------------------------------------------- payloads

    def value_of(self, dto: dict) -> tuple:
        """``(True, value)`` with the value an entry's payload holds, or ``(False, None)``
        while the payload is on its way (``payload_of``) or when its bytes are outside the
        wire encoding. The record signature covers those bytes, so such an entry still
        replicates, and every read skips its value (HLC round six, 2026-11-08, owner ruling
        F3)."""
        raw = self.payload_of(dto)
        if raw is None:
            return False, None
        try:
            return True, cbor.loads(raw)
        except ValueError:
            return False, None

    def payload_of(self, dto: dict) -> bytes | None:
        """The payload bytes of an entry's record: inline, or resolved from a block
        (``z``) or a content root (``b``) held here. A reference not yet held starts
        its transfer and returns None; reads never block on the network (SPEC §7.2).
        A null payload with no reference is the CBOR null."""
        record = dto.get("record") or {}
        payload = record.get("payload")
        if payload is not None:
            return payload
        ref = record.get("payloadRef")
        if not isinstance(ref, str) or not ref:
            return b"\xf6"
        if ref[0] == "b":
            # SPEC §7.1 tree roots: the codec alone tells a persistent tree (dag-cbor, 0x71) from a
            # piece artifact (raw, 0x55); each goes to the seam that can carry it, never the other.
            if _is_tree_root(ref):
                return None if self.pdt is None else self.pdt.payload(ref)
            if self.content is None:
                return None
            data = self.content.local(ref)
            if data is None:
                self.content.ensure(ref)
            return data
        data = self.blocks.get(ref)
        if data is None:
            self.want_block(ref, dto)
        return data

    def want_block(self, cid: str, dto: dict | None = None) -> None:
        """Asks the entry's issuing peer (and the seed) for a block, at most once a second."""
        now = time.monotonic()
        if now - self._block_asked.get(cid, float("-inf")) < 1.0:
            return
        self._block_asked[cid] = now
        targets = []
        key = (dto or {}).get("issuerPublicKey")
        if isinstance(key, bytes):
            from .identity import derive_id
            targets.append(derive_id(key))
        if self.seed_peer and self.seed_peer not in targets:
            targets.append(self.seed_peer)
        for target in targets:
            if target != self.identity.peer_id:
                self.send_addressed("BLOCK_WANT", wire.block_want_body(cid), target)

    def put_block(self, data: bytes) -> str:
        """Stores a block here and returns its id; served to any member that asks."""
        cid = wire.block_cid(data)
        self.blocks[cid] = bytes(data)
        return cid

    def _accept_peer_ad(self, payload: bytes) -> None:
        """A 'peers' stream item: PeerNode.SignedPeerAd. The advertisement is
        kept under its issuer when the signature and the derivation hold and no
        newer one of that issuer is held."""
        from .identity import parse_instant_millis
        ad = wire.decode_signed_peer_ad(payload)
        if ad is None or ad["issuer"] == self.identity.peer_id:
            return
        held = self.members.get(ad["issuer"])
        if held and parse_instant_millis(held["issued"]) > parse_instant_millis(ad["issued"]):
            return  # a reordered older advertisement never replaces the hints a newer one states
        self.members[ad["issuer"]] = ad
        self._maintain_cards(view_changed=True)

    def find(self, type_name: str):
        """Returns decoded values of known live entries of one schema type."""
        results = []
        for dto in self.states.values():
            record = dto.get("record") or {}
            if record.get("type") == type_name and not dto.get("completed"):
                readable, value = self.value_of(dto)
                if readable:
                    results.append(value)
        return results

    # ------------------------------------------------------------- internals

    @property
    def connected(self) -> bool:
        """Whether the seed connection is still up."""
        return self._running and self._socket is not None

    def _send(self, kind: str, body: bytes, to: str | None = None) -> None:
        with self._lock:
            if self._socket is None:
                return
            try:
                self._socket.sendall(struct.pack(">i", len(frame := wire.encode_frame(
                    wire.envelope(self.group, kind, self.identity.peer_id,
                                  wire.hlc_now(self.identity.peer_id, self._now_ms()), body, to),
                    self.identity))) + frame)
            except OSError:
                # The remote closed: the reader notices and reconnects.
                try:
                    self._socket.close()
                finally:
                    self._socket = None

    def _read_loop(self) -> None:
        while self._running:
            try:
                header = self._read_exact(4)
                length = struct.unpack(">i", header)[0]
                if length <= 0 or length > wire.MAX_FRAME_BYTES:
                    # Corrupt or hostile prefix: the stream cannot be
                    # resynchronized (ASF-016). Drop the connection.
                    raise OSError(f"bad frame length {length}")
                self._receive(self._read_exact(length))
            except OSError:
                # The socket closed or failed. Closed by the owner: done. Otherwise reconnect
                # to the seed and carry on; the fleet's leases cover the gap either way.
                with self._lock:
                    sock, self._socket = self._socket, None
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                if not self._running or self._seed is None or not self._reconnect():
                    return

    def _receive(self, frame: bytes) -> None:
        """One frame off the connection: decoded, verified, filtered and handled, or dropped
        and counted as malformed. No frame raises out of here, so one hostile frame cannot
        kill the reader (ASF-015)."""
        try:
            decoded = wire.decode_frame_detailed(frame, attested=self._attested)
            env = decoded[0] if decoded is not None else None
            if env is None:
                self.malformed_frames += 1
            elif self._accepts(env):
                if decoded[1] == "attested":
                    self.attested_frames += 1
                self._handle(env)
        except Exception:  # noqa: BLE001 - one hostile frame must not kill the reader
            self.malformed_frames += 1

    def _accepts(self, env) -> bool:
        """The reader filter: a verified envelope for our group that is
        either unaddressed (the bootstrap exception) or addressed to us. An
        addressed frame is honored only by its intended recipient (ASF-010);
        a frame for a group we never joined is dropped (SPEC section 9)."""
        return (env is not None and env.get("group") == self.group
                and env.get("to") in (None, self.identity.peer_id))

    def _read_exact(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            sock = self._socket
            if sock is None:
                raise OSError("no socket")
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise OSError("connection closed")
            data += chunk
        return data

    def _handle(self, env: dict, relayed: bool = False) -> None:
        if not self.frames.admit(env, self._now_ms()):
            return  # stale, far ahead, or a replay: dropped and counted, nothing more
        wire.hlc_observe(self.identity.peer_id, env.get("stamp"), self._now_ms())
        if self._cards or self._spill_holds:
            self._maintain_cards(view_changed=False)
        kind = env.get("kind")
        body = env.get("body") or b""
        sender = env.get("from")
        if isinstance(sender, str) and sender != self.identity.peer_id:
            # A verified frame is a member heard from (the frame's signer), and
            # one our socket reaches; a frame a relay carried for its origin
            # says nothing about reaching that origin.
            if sender not in self.members:
                self.members[sender] = {}
                self._maintain_cards(view_changed=True)
            if not relayed:
                self.reachable.add(sender)
            if not relayed and self._seed is not None and env.get("to") == self.identity.peer_id \
                    and self.seed_peer != sender:
                # Over our one socket an addressed frame is the seed's own; it is the relay
                # we declare, so members behind other seeds reach us through it (SPEC §5.4).
                self.seed_peer = sender
                self.resource_hints["relay.via"] = sender
                self.introduce()
        if kind not in wire.BODY_RECORDS:
            # A kind this client does not speak (the hint-gated kinds of SPEC v0.1.17 are
            # never sent to it, but a misconfigured peer could), or one it does not act on (the
            # seed's own CHANNEL_HELLO: this client signs every frame it sends, so the seed's
            # acceptance of bare frames changes nothing here): ignored, counted, never fatal.
            self.ignored_kinds[str(kind)] = self.ignored_kinds.get(str(kind), 0) + 1
            return
        decoded = wire.decode_body(kind, body)
        if decoded is None:
            # HLC round six, 2026-11-08 (owner rulings F1 and F3): a body outside the wire
            # encoding or its record makes the frame undecodable; nobody is struck for it.
            self.malformed_frames += 1
            return
        if kind == "PING":
            self._send("ACK", wire.ack_body(decoded["nonce"]))
        elif kind == "PIPE_DATA":
            if decoded["capability"] == wire.RELAY_SIGNAL_CAPABILITY:
                signal = records.decode(decoded["payload"], "PeerNode.RelaySignal")
                if signal is not None:
                    self.relay_signals.append(signal)
                    del self.relay_signals[:-64]
                return
            handler = self.pipe_handlers.get(decoded["capability"])
            if handler is not None:
                handler(sender, decoded["payload"] or b"")
        elif kind == "RELAY_FRAME":
            if decoded["target"] != self.identity.peer_id:
                return  # a dial-only peer forwards nothing: it holds no connection to forward on
            inner = wire.decode_frame(decoded["frame"] or b"")
            if inner is not None and inner.get("kind") != "RELAY_FRAME" and self._accepts(inner):
                self._handle(inner, relayed=True)
        elif kind == "BLOCK_WANT":
            data = self.blocks.get(decoded["cid"])
            if data is not None:
                self.send_addressed("BLOCK", wire.block_body(decoded["cid"], data), sender)
        elif kind == "BLOCK":
            block = decoded
            if isinstance(block["bytes"], bytes) and block["cid"] in self._block_asked \
                    and wire.block_cid(block["bytes"]) == block["cid"]:
                self.blocks[block["cid"]] = block["bytes"]
                self._wake_fold_waiters()
        elif kind == wire.KIND_GROUP_AD:
            self._on_group_ad(decoded)
        elif kind == "RUMOR":
            rumor = decoded
            if rumor["streamId"] in revocations.STREAMS:
                self.revocations.accept(rumor["streamId"], rumor["payload"], self._now_ms())
            elif rumor["streamId"] == "peers":
                self._accept_peer_ad(rumor["payload"])
            elif rumor["streamId"] == "ads":
                self.accept_ad(records.decode(rumor["payload"], "AdCache.StoredAd"))
            elif rumor["streamId"] in self.stream_handlers:
                self._on_stream_item(sender, rumor)
            elif str(rumor["streamId"]).startswith("space:"):
                self._prune_claims()
                delta = wire.decode_delta(rumor["payload"])
                if delta is None:
                    self.deltas_undecodable += 1  # HLC round four, 2026-11-08, decision D5
                    return
                # Claim before state: a completion authenticates against the
                # holder's claim, which must be folded first.
                if delta.get("claimEntry") and delta.get("claim") is not None:
                    self._fold_claim(delta["claimEntry"], delta["claim"])
                if delta.get("state") is not None:
                    self._name_recordless(delta["state"], rumor.get("itemId"))
                    self._fold(delta["state"])
        elif kind == "PULL_RESP":
            for stream, delta_bytes in (decoded["deltas"] or {}).items():
                if stream in revocations.STREAMS and delta_bytes:
                    self.revocations.accept_delta(stream, delta_bytes, self._now_ms())
                    continue
                if stream == "ads" and delta_bytes:
                    delta = records.decode(delta_bytes, "AdCache.Delta")
                    for stored in (delta["ads"] or []) if delta is not None else []:
                        self.accept_ad(stored)
                    continue
                if str(stream).startswith("space:") and delta_bytes:
                    self._prune_claims()
                    sync = wire.decode_sync_delta(delta_bytes)
                    if sync is None:
                        self.deltas_undecodable += 1  # HLC round four, 2026-11-08, decision D5
                        continue
                    # Claims before states, as above.
                    for entry_id, signed in (sync.get("claims") or {}).items():
                        self._fold_claim(entry_id, signed)
                    for dto in (sync.get("states") or []):
                        self._fold(dto)

    @staticmethod
    def _name_recordless(state: dict, item_id) -> None:
        """Fills ``entryId`` of a recordless state from the rumor item id (``r:<id>:<stamp>``,
        ``d:<id>``) when the DTO does not carry one."""
        if state.get("record") is not None or state.get("entryId") or not isinstance(item_id, str):
            return
        parts = item_id.split(":")
        if len(parts) >= 2 and parts[0] in ("r", "d", "x", "c"):
            state["entryId"] = parts[1]

    def _on_group_ad(self, signed: dict) -> None:
        """A GROUP_AD answer (spec §9): accepted only while a join-by-GroupID
        is pending and only when the body passes the four checks of §5.1 and
        derives to exactly the wanted group. Anything else is ignored, so a
        seed that serves a wrong or forged founding document delays the join
        and never changes what this peer joins."""
        if self._founding_ready.is_set():
            return  # already joined on a verified document
        if verify_signed_group_ad(signed) != self.group:
            return
        self.founding = signed
        self._founding_ready.set()

    def _fold(self, dto: dict) -> None:
        if dto.get("leaseStamp") is None or dto.get("leaseValue") is None:
            # HLC round five, 2026-11-08 (decision E7): such a state decodes, but a lease
            # register holds nothing without its stamp and value, so the peer drops it before
            # any judgement, with or without its record, as Java's mergeState and Ruby's
            # fold_state do: it merges nothing, waits for nothing, and counts nothing.
            return
        if dto.get("record") is None:
            self._fold_recordless(dto)
            return
        record = dto.get("record")
        entry_id = record.get("entryId") if isinstance(record, dict) else None
        if not entry_id or not _dots_bound_to_issuer(dto, record):
            # ASF-025, as Java's ReplicatedSpace.dotsBoundToIssuer: only the entry's writer
            # mints its dots, so a dot naming another replica is fabricated provenance. The
            # peer drops such a state before verification and counts nothing (HLC round six,
            # 2026-11-08, vector delta-13); a recordless state meets the rule under the record
            # this replica holds, since it comes back here with that record.
            return
        if not self._verify_state(dto, record):
            return  # unauthenticated record or forged mutable state: drop it
        if self._refused_for_revocation(dto, record):
            # Authentic, but its actor is revoked here (SPEC §5.6): what is already held
            # stays as held, this state is not merged, and its stamps count nothing, since
            # the peer judges revocation before them (HLC round five, 2026-11-08, decision E6).
            return
        # HLC round four, 2026-11-08 (decisions D1, D4, D5): after verification, as Java's
        # ReplicatedSpace judges it, the peer refuses a state whose record, lease or signing
        # stamp the rule refuses, or whose record or lease stamp runs more than an hour past
        # the skew margin, and counts it once per distinct signed state; it defers a state
        # stamped past the margin by less until its wall catches up. HLC round five,
        # 2026-11-08 (decisions E2 and E5): the peer judges each offer afresh against its wall,
        # so a refused far-future state merges once the wall catches up, and the memories only
        # keep a re-offer from counting twice.
        # HLC round six, 2026-11-08 (owner ruling F4): an agent's signedAt meets the same
        # far-future rule as the record and lease stamps, where the certificate check dropped
        # it unverified and uncounted past the drift bound.
        stamps = (record.get("issued"), dto.get("leaseStamp"), dto.get("signedAt"))
        verdict = self._stamp_verdict(stamps, stamps)
        key = ("state", entry_id, str(record.get("issued")),
               hashlib.sha256(self._state_view(dto, record)).digest())
        if verdict == _DEFER:
            self._count_deferred(key)
            return
        if verdict != _MERGE:
            self._count_refused(key, verdict)
            return
        pending = self.pending_states.pop(entry_id, None)
        self._pending_since.pop(entry_id, None)
        # ASF-017: states JOIN, mirroring the Java CRDT — dot sets union, the
        # lease is last-writer-wins by HLC stamp, and completed is monotone.
        # A replayed early state (validly signed by its author) can therefore
        # never shrink the sets, roll back the lease, or undo a completion.
        with self._state_lock:
            previous = self.states.get(entry_id)
            merged = self._join(previous, dto) if previous is not None else dto
            self.states[entry_id] = merged
        if self.on_state is not None:
            self.on_state(merged)
        if (self.on_withdrawn is not None and previous is not None and present(previous)
                and not present(merged) and not merged.get("completed")):
            self.on_withdrawn(merged)
        self._wake_fold_waiters()
        if pending is not None:
            self._fold_recordless(pending)

    def _stamp_verdict(self, stamps: tuple, timed: tuple) -> str:
        """What the peer does with a verified state or claim for its stamps (HLC round four,
        2026-11-08). ``_REFUSE_LOGICAL`` when one of ``stamps`` the rule refuses
        (``wire.acceptable_hlc``, decision D1); otherwise ``_REFUSE_FAR_FUTURE`` when one of
        ``timed`` runs more than FAR_FUTURE_HOSTILE_MILLIS past wall + MAX_HLC_SKEW_MILLIS +
        FAR_FUTURE_SKEW_MARGIN_MILLIS, and ``_DEFER`` when one runs past that line by less
        (decision D4); ``_MERGE`` otherwise. An absent stamp passes. The peer judges the
        logical limit first, as Java does (HLC round five, 2026-11-08, decisions E2 and E6)."""
        if any(stamp is not None and wire.acceptable_hlc(stamp) is None for stamp in stamps):
            return _REFUSE_LOGICAL
        line = self._now_ms() + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_SKEW_MARGIN_MILLIS
        ahead = max((wire.hlc_physical(stamp) - line for stamp in timed if stamp is not None), default=0)
        if ahead > wire.FAR_FUTURE_HOSTILE_MILLIS:
            return _REFUSE_FAR_FUTURE
        return _DEFER if ahead > 0 else _MERGE

    def _count_refused(self, key: tuple, counter: str) -> None:
        """Counts a refused verified state or claim in ``counter`` (``_REFUSE_LOGICAL`` or
        ``_REFUSE_FAR_FUTURE``) once per distinct signed one (HLC round four, 2026-11-08,
        decision D5), as Java's ReplicatedSpace counts it. ``key`` holds signed content alone
        (the entry id, the issue stamp and the signed state view, or the entry id and the
        signed claim), so a re-offer by gossip or anti-entropy, with whatever unsigned fields
        beside it, is the same refusal again. The memory decides nothing: the caller judged
        the offer afresh before it got here (HLC round five, 2026-11-08, decision E5)."""
        if _remember(self._refused_seen, key):
            setattr(self, counter, getattr(self, counter) + 1)

    def _count_deferred(self, key: tuple) -> None:
        """Counts a verified state or claim deferred for a stamp past the far-future margin
        once per distinct signed one, keyed as ``_count_refused`` keys it (HLC round five,
        2026-11-08, decision E2)."""
        if _remember(self._deferred_seen, key):
            self.stamps_far_future_deferred += 1

    def _expire_pending_states(self, now: float | None = None) -> None:
        """Drops pending recordless states older than ``PENDING_STATE_TTL_S`` (PD-L-02)."""
        now = time.monotonic() if now is None else now
        for entry_id, since in list(self._pending_since.items()):
            if now - since >= PENDING_STATE_TTL_S:
                self._pending_since.pop(entry_id, None)
                self.pending_states.pop(entry_id, None)

    def _fold_recordless(self, dto: dict) -> None:
        """A renew, cancel, or complete without its record (PD-L-01, PD-L-02): merged when
        this replica holds the record, kept pending without an event until anti-entropy
        ships the whole DTO otherwise. The entry id comes from the DTO's ``entryId`` or
        from the rumor item that carried it. Pending states are bounded at
        ``MAX_PENDING_STATES`` (the oldest dropped) and age out after
        ``PENDING_STATE_TTL_S``, as the Java, TypeScript, and Ruby peers bound them;
        anti-entropy restores whatever was dropped."""
        entry_id = dto.get("entryId")
        if not isinstance(entry_id, str) or not entry_id:
            return
        previous = self.states.get(entry_id)
        if previous is None:
            self._expire_pending_states()
            if entry_id not in self.pending_states and len(self.pending_states) >= MAX_PENDING_STATES:
                oldest = next(iter(self.pending_states))
                self.pending_states.pop(oldest, None)
                self._pending_since.pop(oldest, None)
            self.pending_states[entry_id] = dto
            self._pending_since[entry_id] = time.monotonic()
            return
        self._pending_since.pop(entry_id, None)
        full = dict(dto)
        full["record"] = previous.get("record")
        for carried in ("issuerPublicKey", "agentCertificate"):
            if full.get(carried) is None and previous.get(carried) is not None:
                full[carried] = previous[carried]
        self._fold(full)

    @staticmethod
    def _join(previous: dict, incoming: dict) -> dict:
        merged = dict(previous)
        merged["adds"] = _union_dots(previous.get("adds"), incoming.get("adds"))
        merged["removes"] = _union_dots(previous.get("removes"), incoming.get("removes"))
        # Both lease stamps passed the stamp rule and compare as Java orders them (HLC
        # canonical stamps, 2026-11-08); a state without one never gets here (HLC round five,
        # 2026-11-08, decision E7).
        if wire.hlc_tuple(incoming.get("leaseStamp")) > wire.hlc_tuple(previous.get("leaseStamp")):
            merged["leaseStamp"] = incoming.get("leaseStamp")
            merged["leaseValue"] = incoming.get("leaseValue")
        merged["completed"] = bool(previous.get("completed")) or bool(
            incoming.get("completed"))
        return merged

    def _verify_state(self, dto: dict, record: dict) -> bool:
        """Authenticates a received state DTO: the record signature (the writer's
        identity) and the state signature (the transition itself). The party
        authorized for the transition is the take-claim holder for a completion
        and the issuer otherwise. Mirrors ReplicatedSpace.verifyState (SPEC
        §11a.4): an agent-signed state (``signer`` present) must name that party,
        carry a certificate the party's peer key verifies at ``signedAt``, and
        verify under the certificate's agent key; and an agent-attested party's
        transitions must be agent-signed (A6, v0.1.13), so its peer or a sibling
        agent cannot act in its name."""
        issuer_key = dto.get("issuerPublicKey")
        if not isinstance(issuer_key, (bytes, bytearray)) or len(issuer_key) != 32:
            return False
        # The record: peer-signed, or agent-signed under a peer certificate
        # (TECH-SPEC §7.2's two-key rule, QA4 A4-7), judged at its issue stamp.
        if not wire.verify_record(record, bytes(issuer_key), dto.get("agentCertificate")):
            return False
        state_sig = dto.get("stateSig")
        if not isinstance(state_sig, (bytes, bytearray)):
            return False
        if dto.get("completed"):
            signed = self.claims.get(record.get("entryId"))
            if not signed:
                return False  # no authenticated holder to attribute the completion to
            # The claim authenticating this completion must be bound to exactly
            # this entry and space by its own signed fields (ASF-002/041).
            claim = signed.get("claim") or {}
            if (claim.get("entryId") != record.get("entryId")
                    or claim.get("spaceId") != record.get("spaceId")
                    or not wire.verify_claim_proof(signed)):
                return False
            signer_key = signed.get("holderKey")
            party = claim.get("holder")
            party_attested = signed.get("holderCertificate") is not None
        else:
            signer_key = issuer_key
            party = record.get("issuer")
            party_attested = dto.get("agentCertificate") is not None
        if not isinstance(signer_key, (bytes, bytearray)) or len(signer_key) != 32:
            return False
        signer, signed_at = dto.get("signer"), dto.get("signedAt")
        view = self._state_view(dto, record)
        if signer is not None:
            # HLC round six, 2026-11-08 (owner ruling F4): the certificate bounds signedAt by its
            # own validity window alone, as it bounds a record's or a claim's stamp, and the
            # far-future rule judges how far signedAt leads after verification (``_fold``).
            certificate = dto.get("stateCertificate")
            try:
                signed_ms = wire.hlc_physical(signed_at)
            except (TypeError, ValueError):
                return False
            return (signer == party and isinstance(certificate, dict)
                    and verify_agent_certificate_covering(certificate, bytes(signer_key), party, signed_ms)
                    and Identity.verify(bytes(certificate["agentPublicKey"]), view, bytes(state_sig)))
        if party_attested:
            return False  # A6: an attested party's transitions must be agent-signed
        return Identity.verify(bytes(signer_key), view, bytes(state_sig))

    @staticmethod
    def _state_view(dto: dict, record: dict) -> bytes:
        """The bytes a state's signature covers (StateSignView, SPEC §11a.4)."""
        return cbor.dumps(wire.state_sign_view(
            record.get("spaceId"), record.get("entryId"), dto.get("adds") or [],
            dto.get("removes") or [], dto.get("leaseStamp"), dto.get("leaseValue"),
            bool(dto.get("completed")), dto.get("signer"), dto.get("signedAt")))

    def _refused_for_revocation(self, dto: dict, record: dict) -> bool:
        """SPEC §5.6's freeze rule at merge, for every incoming state: the
        actor of the transition (the claim holder for a completion, the issuer
        otherwise) must not be revoked, peers and agents alike; an agent is
        judged at the state's ``signedAt`` with the keys it signed with. A
        peer-signed state (no ``signedAt``) is judged at its ``leaseStamp``, the
        stamp of the last write or renewal (the record's issue stamp for an
        unrenewed write), so a renewal after the effective instant is refused
        while the original history still folds."""
        if dto.get("completed"):
            signed = self.claims.get(record.get("entryId")) or {}
            claim = signed.get("claim") or {}
            holder = claim.get("holder")
            certificate = signed.get("holderCertificate") or {}
            return holder is not None and self.revocations.refuses(
                holder, certificate.get("agentPublicKey"), self._signing_ms(dto, None))
        issuer = record.get("issuer")
        certificate = dto.get("agentCertificate") or {}
        state_certificate = dto.get("stateCertificate") or {}
        # A merged state carries a lease stamp that decoded (HLC round five, 2026-11-08,
        # decision E7).
        at = self._signing_ms(dto, wire.hlc_physical(dto["leaseStamp"]))
        return issuer is not None and (
            self.revocations.refuses(issuer, certificate.get("agentPublicKey"), at)
            or (dto.get("signer") is not None and self.revocations.refuses(
                issuer, state_certificate.get("agentPublicKey"), self._signing_ms(dto, None))))

    @staticmethod
    def _signing_ms(dto: dict, fallback):
        try:
            return wire.hlc_physical(dto["signedAt"]) if dto.get("signedAt") else fallback
        except (TypeError, ValueError):
            return fallback

    def _fold_claim(self, entry_id: str, signed: dict) -> None:
        claim = signed["claim"]
        # The delta's decode refused a claim whose fields are of another kind, a bid that is no
        # finite double among them (ASF-033; HLC round six, 2026-11-08, owner ruling F1). The
        # peer drops a claim transplanted under a foreign map key (ASF-002).
        if claim["entryId"] != entry_id:
            return
        epoch = claim["epoch"]
        expires = claim["expiresAtMillis"]
        # The proof: peer-signed, or agent-signed under a peer certificate
        # (TECH-SPEC §7.6's two-key rule, QA4 A4-7 phase 3).
        if not wire.verify_claim_proof(signed):
            return
        # SPEC §5.6 v0.1.13 (review M-1): a revoked holder takes nothing, whatever the
        # claim's stamp, since a renewal keeps it. The peer judges revocation before the
        # stamp, so a revoked holder's claim counts nothing (HLC round five, 2026-11-08,
        # decision E6).
        certificate = signed.get("holderCertificate") or {}
        if self.revocations.refuses(claim.get("holder"), certificate.get("agentPublicKey"), None):
            return
        # HLC round four, 2026-11-08 (decisions D4, D5): after verification the peer refuses
        # a claim whose stamp the rule refuses or runs more than an hour past the skew margin
        # and counts it once per distinct signed claim, so the stamp never reaches the
        # lattice; it defers a claim stamped past the margin by less, so an honest taker
        # whose clock a hostile stamp dragged ahead takes once this wall catches up. A claim
        # over non-canonical text never decodes (decision D3). HLC round five, 2026-11-08
        # (decisions E2, E5 and E13): the peer judges each offer afresh, refusals and deferrals
        # count apart, and the key is the claim as its signature covers it.
        stamp = claim.get("stamp")
        verdict = self._stamp_verdict((stamp,), (stamp,))
        key = ("claim", entry_id, hashlib.sha256(cbor.dumps(claim)).digest())
        if verdict not in (_MERGE, _DEFER):
            self._count_refused(key, verdict)
            return
        # ASF-004, mirroring ReplicatedSpace: bound what a remote claim may
        # assert before the lattice (where higher epochs win by design) sees it.
        # Judged before the deferral, as Java's mergeClaim judges it, so a claim
        # these bounds refuse counts no deferral (HLC round five, 2026-11-08,
        # decision E2).
        current = self._claim_of(entry_id) or {}
        observed = int(current.get("epoch", 0))
        now = self._now_ms()
        if (epoch > observed + wire.MAX_CLAIM_EPOCH_JUMP
                or expires > now + wire.MAX_CLAIM_HOLD_MILLIS):
            return
        # HLC round six, 2026-11-08 (R6), as Java's mergeClaim judges them after the bounds
        # above and before the deferral: a claim cannot predate the entry it answers by more
        # than the drift bound (spec §7.4/§11), and a claim contesting another holder's claim
        # with a stamp older than the drift bound and one settle window is a queue-jump, since
        # LEASE_RACE picks the lowest stamp and an honest race settles within the window.
        # Java strikes the holder for each and counts neither; this peer keeps no strikes.
        stamped = wire.hlc_physical(stamp)
        held = self.states.get(entry_id)
        if held is not None and stamped < wire.hlc_physical(held["record"]["issued"]) - MAX_CLAIM_PREDATES_ISSUE_MILLIS:
            return
        if (current and current["holder"] != claim["holder"]
                and stamped < now - wire.MAX_HLC_SKEW_MILLIS - CONTEST_SETTLE_MILLIS):
            return
        if verdict == _DEFER:
            self._count_deferred(key)
            return
        self.claims[entry_id] = wire.merge_claims(self.claims.get(entry_id), signed)
        if self.on_claim is not None:
            self.on_claim(entry_id, self.claims[entry_id])
        self._wake_fold_waiters()

    # ----------------------------------------------------------- take/complete

    def _prune_claims(self) -> None:
        """Drops each claim on an entry this replica does not hold once the claim's expiry
        passes (HLC round six, 2026-11-08, R10), as Java's ``dropOrphanedClaims`` drops it in
        its sweep. A claim folds before its entry's state, since a completion authenticates
        against it, so a claim may come for an entry that never follows; kept, every such
        claim stayed for good. This client runs no periodic work, so the peer prunes before it
        folds a space delta, never inside one, and a completion still finds the claim it
        travels with. It scans once the map has doubled since the last scan, as Ruby's
        ``prune_claims`` does, so the work stays proportional to the claims folded. A live
        claim stays, and a partner that holds the entry offers its claim again with the
        state."""
        if len(self.claims) < self._claims_prune_at:
            return
        now = self._now_ms()
        for entry_id, signed in list(self.claims.items()):
            if entry_id not in self.states and now >= signed["claim"]["expiresAtMillis"]:
                self.claims.pop(entry_id, None)
        self._claims_prune_at = max(2 * len(self.claims), CLAIMS_PRUNE_FLOOR)

    def _claim_of(self, entry_id: str):
        signed = self.claims.get(entry_id)
        return signed["claim"] if signed else None

    def _available(self, type_name: str, now_ms: int):
        for entry_id, dto in self.states.items():
            record = dto.get("record") or {}
            if record.get("type") != type_name or not present(dto):
                continue  # completed, or withdrawn by a cancel (core cancel events, 2026-11-09)
            lease = lease_of(dto)
            if int(lease.get("expiresAtMillis", 0)) <= now_ms:
                continue
            claim = self._claim_of(entry_id)
            if claim and int(claim.get("expiresAtMillis", 0)) > now_ms:
                continue
            yield entry_id, dto

    def take_entry(self, space: str, type_name: str, agent_name: str = "python",
                   lease_millis: int = 60_000, settle_seconds: float = 0.6,
                   timeout_seconds: float = 15.0, agent=None, matches=None, bid=0.0):
        """Takes one entry under LEASE_RACE (spec §7.4): publish a signed
        claim, wait one settle window, and win when the lattice still says so.
        Returns the entry id, or None when out-arbitrated or nothing matched.
        With ``agent`` the claim is the agent's, signed by its key (v0.1.13).
        ``matches(payload_dict, tags_dict)`` narrows the candidates (a
        template); ``bid`` is the AUCTION price, a float or a callable over the
        payload, and 0.0 under LEASE_RACE.

        Fold-driven (JS-V-02): while nothing matches, the take pulls the space
        at most once per settle window and sleeps on the next fold, so an entry
        that arrives wakes it at once; the settle window after a claim is waited
        out in full, since a competing claim may fold at its end."""
        from .identity import space_id_local
        holder = agent.agent_id if agent is not None else self.identity.agent(agent_name)
        if self.revocations.refuses(holder, agent.public_raw if agent else None, None):
            return None  # a revoked agent takes nothing, even locally
        space_id = space_id_local(f"{self.group}/{space}")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline and self._running:  # a reconnect in progress is not a reason to stop
            self.pull_space_paced(space, settle_seconds)
            seen = self.fold_count
            now_ms = self._now_ms()
            claimed = False
            for entry_id, dto in list(self._available(type_name, now_ms)):
                record = dto.get("record") or {}
                if record.get("spaceId") != space_id:
                    continue  # the same type in another space is not this take's
                readable, payload = self.value_of(dto)
                if not readable:
                    continue  # its block or artifact is still on its way, or its bytes are unreadable
                if matches is not None and not matches(payload, record.get("tags") or {}):
                    continue
                price = float(bid(payload)) if callable(bid) else float(bid)
                # The list above is a snapshot, and each claim before this one waited out a
                # settle window: judge this entry again against the claims folded since, as
                # the TypeScript take does, so a lost race moves on to an entry nobody holds
                # rather than claiming one after another that faster members already took.
                now_ms = self._now_ms()
                current = self._claim_of(entry_id)
                if current and int(current.get("expiresAtMillis", 0)) > now_ms:
                    continue
                if not present(self.states.get(entry_id) or {}):
                    continue  # completed or withdrawn meanwhile (core cancel events, 2026-11-09)
                epoch = int(current["epoch"]) + 1 if current else 1
                claim = wire.take_claim(entry_id, space_id, epoch,
                                        wire.hlc_now(holder, now_ms), holder,
                                        price, now_ms + lease_millis)
                signed = wire.signed_claim(claim, self.identity, agent)
                self.claims[entry_id] = wire.merge_claims(
                    self.claims.get(entry_id), signed)
                self._send("RUMOR", wire.rumor_body(
                    f"space:{space}", f"c:{entry_id}:{claim['stamp']}", 6,
                    wire.claim_delta(entry_id, signed)))
                claimed = True
                time.sleep(settle_seconds)  # the settle window: a competing claim folds within it
                self.pull_space_paced(space, settle_seconds)
                self.await_fold(min(settle_seconds, 0.3))
                winner = self._claim_of(entry_id)
                # core cancel events, 2026-11-09: an entry completed or withdrawn during the
                # settle window is nobody's, so a cancel that folded meanwhile leaves the take empty
                if winner and winner.get("holder") == holder \
                        and int(winner.get("epoch")) == epoch \
                        and present(self.states.get(entry_id) or {}):
                    return entry_id
            if not claimed:
                # Nothing to claim: sleep until a fold (an entry, a lapsed claim's
                # successor) or the end of this settle window, not a fixed 300 ms.
                self.await_fold(min(settle_seconds, deadline - time.monotonic()), since=seen)
        return None

    def complete_entry(self, space: str, entry_id: str, agent=None) -> None:
        """Completes a held entry: publishes its state with the monotone
        completed flag set, re-signed by the holder and carrying our winning
        claim, so honest replicas can authenticate the completion (SPEC §11a).
        A completion the holder did not sign is rejected. A claim taken as an
        agent (``take_entry(agent=...)``) must be completed as that agent, whose
        signed state is what receivers require (A6, v0.1.13). An entry this replica
        holds completed or withdrawn is held by nobody, as Java's ``complete``
        refuses it (core cancel events, 2026-11-09)."""
        with self._state_lock:
            dto = dict(self.states[entry_id])
            if not present(dto):
                raise ValueError(f"{entry_id} is not held here: it is completed or withdrawn")
            dto["completed"] = True
            dto = wire.sign_state(dto, self.identity, agent, self._now_ms())
            self.states[entry_id] = dto
        proof = self.claims.get(entry_id)
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"d:{entry_id}", 6,
            cbor.dumps({"state": dto,
                        "claimEntry": entry_id if proof else None,
                        "claim": proof})))


    def renew_entry(self, space: str, entry_id: str, lease_millis: int = 600_000,
                    agent=None) -> None:
        """Renews this peer's write of an entry (SPEC §7.3): a later lease stamp
        and expiry, re-signed by the issuer, as the agent when it wrote as one.
        Only the issuer renews: ``agent`` must be the record's issuer, and
        without one the issuer must be one of this peer's agent names."""
        with self._state_lock:
            dto = dict(self.states[entry_id])
            record = dto.get("record") or {}
            issuer = str(record.get("issuer"))
            if agent is not None and agent.agent_id != issuer:
                raise ValueError(f"{entry_id} was written by {issuer}, not {agent.agent_id}")
            if agent is None and not issuer.startswith(self.identity.peer_id + "/"):
                raise ValueError(f"{entry_id} was written by {issuer}, not by this peer")
            now_ms = self._now_ms()
            dto["leaseStamp"] = wire.hlc_now(record.get("issuer"), now_ms)
            dto["leaseValue"] = {"holder": record.get("issuer"),
                                 "expiresAtMillis": now_ms + lease_millis, "kind": "WRITE"}
            dto = wire.sign_state(dto, self.identity, agent, now_ms)
            self.states[entry_id] = dto
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"r:{entry_id}:{now_ms}", 6,
            cbor.dumps({"state": dto, "claimEntry": None, "claim": None})))

    def on_stream(self, stream_id: str, handler: Callable) -> Callable:
        """Hands each item of a gossip stream to ``handler(sender, item_id, payload)`` once, as Java's
        ``GossipBus.onStream`` does (PDT 2 phase 7, P2-P-02); returns the call that stops it. One handler a stream."""
        if stream_id in self.stream_handlers:
            raise ValueError(f"stream {stream_id} has a handler on this peer already")
        self.stream_handlers[stream_id] = handler
        return lambda: self.stream_handlers.pop(stream_id, None)

    def _on_stream_item(self, sender, rumor: dict) -> None:
        key = f"{rumor['streamId']}|{rumor['itemId']}"
        if key in self._stream_items:
            return  # a copy of an item already handed over
        self._stream_items[key] = None
        while len(self._stream_items) > STREAM_ITEMS_REMEMBERED:
            del self._stream_items[next(iter(self._stream_items))]
        handler = self.stream_handlers.get(rumor["streamId"])
        if handler is not None:
            handler(sender, rumor["itemId"], rumor["payload"])

    def cancel_entry(self, space: str, entry_id: str, agent=None) -> None:
        """Cancels this peer's write of an entry, as Java's ``EntryHandle.cancel`` and the TypeScript
        ``cancelEntry`` do (PDT 2 phase 7, P2-X-05): a state whose removes cover its adds, re-signed by
        the issuer, so every replica drops the entry and its watches hear EXPIRED (core cancel events,
        2026-11-09). Only the issuer cancels, as only the issuer renews. An entry this replica holds
        completed or withdrawn stays as it is and nothing goes out: an issuer's signature over a
        completed state verifies nowhere (SPEC §11a.4)."""
        with self._state_lock:
            previous = self.states.get(entry_id)
            if previous is None:
                raise ValueError(f"{entry_id} is not held here")
            issuer = str((previous.get("record") or {}).get("issuer"))
            if agent is not None and agent.agent_id != issuer:
                raise ValueError(f"{entry_id} was written by {issuer}, not {agent.agent_id}")
            if agent is None and not issuer.startswith(self.identity.peer_id + "/"):
                raise ValueError(f"{entry_id} was written by {issuer}, not by this peer")
            if not present(previous):
                return
            now_ms = self._now_ms()
            dto = dict(previous)
            dto["removes"] = _union_dots(previous.get("removes"), previous.get("adds"))
            dto = wire.sign_state(dto, self.identity, agent, now_ms)
            self.states[entry_id] = dto
        if self.on_withdrawn is not None:
            self.on_withdrawn(dto)
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"x:{entry_id}:{now_ms}", 6,
            cbor.dumps({"state": dto, "claimEntry": None, "claim": None})))


def _dots_bound_to_issuer(dto: dict, record: dict) -> bool:
    """Whether every dot in a received state's adds and removes names the peer of its record's
    issuer as its replica (ASF-025; HLC round six, 2026-11-08). The record's decode holds the
    issuer to Java's AgentId grammar, so its peer is the text before the slash."""
    peer = str(record.get("issuer") or "").partition("/")[0]
    return all(isinstance(dot, dict) and dot.get("replica") == peer
               for dot in (dto.get("adds") or []) + (dto.get("removes") or []))


def lease_of(dto: dict) -> dict:
    """The entry's current lease: the state's lease register, which supersedes the lease its record was
    written with (SPEC §7.3), as Java's ``EntryState`` and the TypeScript client read it. A renewal moves
    the register, so reads, takes and the sweep follow it (lease renewals, 2026-11-09)."""
    return dto.get("leaseValue") or (dto.get("record") or {}).get("lease") or {}


def present(dto: dict) -> bool:
    """Whether the entry of ``dto`` is present, as Java's ``EntryState.present`` judges it: uncompleted,
    with an add dot no remove covers. A cancel's removes cover the adds, so a withdrawn entry is
    absent from reads and takes at once (core cancel events, 2026-11-09)."""
    if dto.get("completed"):
        return False
    removed = {(dot.get("replica"), dot.get("counter")) for dot in dto.get("removes") or [] if isinstance(dot, dict)}
    return any((dot.get("replica"), dot.get("counter")) not in removed
               for dot in dto.get("adds") or [] if isinstance(dot, dict))


def _union_dots(a, b) -> list:
    """The union of two dot lists, deduplicated by (replica, counter) and
    deterministically ordered like the Java side's sorted dots."""
    seen = {}
    for dot in (a or []) + (b or []):
        if isinstance(dot, dict):
            seen[(str(dot.get("replica", "")), int(dot.get("counter", 0)))] = dot
    return [seen[key] for key in sorted(seen)]
