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
import queue
import random
import socket
import struct
import threading
import time
from typing import Callable

from . import beacon, cbor, digests, horizon, records, social, tls, wire
from .identity import (Identity, derive_id, instant_iso, verify_agent_certificate_covering,
                       verify_signed_group_ad)
from . import revocation as revocations
from .seed import Seed, parse_seed
from .timesource import SYSTEM, TimeSource, wait_until


# The join through a document waits in slices of 1 s, 2 s, 4 s, then 5 s each
# inside its budget (the schedule of the Java join by id, ISSUE-BootstrapRobustness §9.4).
JOIN_SLICE_FIRST_S = 1.0
JOIN_SLICE_MAX_S = 5.0


HINT_RECORDLESS = "wire.recordless"
#: SPEC v0.1.35 §7.3 (srad/replication-by-entry.md RE-L-03): this client renews by the rule of §7.2
#: (issuer only, present and unexpired, never shorter) and runs one node per identity, so it
#: advertises the per-entry horizon's hint, and applies that horizon itself while its view does.
HINT_HORIZON = "wire.horizon"
#: SPEC annex I.6: a member that audits by the trie advertises ``wire.ae=2``. This client does not,
#: and reads the hint on its seed's card alone, to send a budget beside its own pull.
HINT_AE = "wire.ae"
#: The PULL_RESP budget this client asks for (annex I.6, *The budget*): 1 MiB, the default.
DEFAULT_PULL_BUDGET = 1_048_576
#: How many times one pull continues after a budgeted answer left states out (annex I.6): each
#: continuation asks for at most one budget, so the bound is about a gigabyte of states.
MAX_PULL_CONTINUATIONS = 1024
#: The most bytes a space's text digest takes in a DIGEST this client sends: room under the
#: frame ceiling of SPEC §9 for the envelope, the signature and the revocation streams.
MAX_DIGEST_TEXT_BYTES = wire.MAX_FRAME_BYTES - 65_536
#: The most bytes of space deltas one PULL_RESP this client sends carries: room under the frame
#: ceiling of SPEC §9, as for its digests. States left out go in the seed's next round, whose digest
#: still lacks them (owner decision 2026-11-23: a dial-only peer answers its seed's DIGEST).
MAX_PULL_RESP_DELTA_BYTES = wire.MAX_FRAME_BYTES - 65_536
#: The DIGEST fields of the hashed round (v0.1.17, ``wire.hashes=1``) and of annex I.6 (``wire.ae=2``):
#: this client advertises neither, so an honest seed sends it the text form alone, and a DIGEST that
#: carries any of these is ignored and counted, as before.
DIGEST_FIELDS_NOT_SPOKEN = ("hashes", "want", "tree", "ids", "budget", "sketch")
#: The acknowledgements a space's digest holds at most (SPEC §7.3 and R7 of §9.2), the least
#: recently refused forgotten first, as Java's REFUSED_ACK_CAP.
REFUSED_ACK_CAP = 8192
#: How long the acknowledgement of a collected tombstone lasts after the last refusal it answered
#: (SPEC §7.3), as Java's COLLECTED_ACK_HOLD_MILLIS.
COLLECTED_ACK_HOLD_MILLIS = 5 * 60 * 1000
#: Rounds the view must stay fully hinted before the per-entry horizon engages, and their bounds
#: (SPEC §7.3, RE-Q-REL-09), as Java's ReplicatedSpace; a round here is HORIZON_ROUND_MILLIS.
DEFAULT_HORIZON_ENGAGE_ROUNDS = 3
HORIZON_ENGAGE_ROUNDS_FLOOR, HORIZON_ENGAGE_ROUNDS_CEILING = 1, 64
#: One round of the hysteresis when the group's period is not known here: Java counts a gossip
#: period of the group, one second by default (``Peer.horizon_round_millis``).
HORIZON_ROUND_MILLIS = 1000
#: How often, at most, the peer collects its tombstones (SPEC §7.3): it runs no timer of its own,
#: so the collection rides on the space sweep, the pulls and the folds.
COLLECT_PERIOD_MILLIS = 1000
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
#: The longest follow-up wait a take makes after its settle window before it judges the race:
#: one fold or this much, as the TypeScript take's ``TAKE_FOLLOW_UP_MAX_MILLIS``.
TAKE_FOLLOW_UP_MAX_MILLIS = 300
#: The keepalive bound a Java member judges this peer by, and the member TTL a released 0.6.0 member
#: judges by (SPEC v0.1.36 §5.2: every member keeps its own keepalive inside 30 s). This client
#: judges nobody by it: it is the step of its wall clock past its monotonic clock that means its
#: members may have dropped it (a suspend), so it introduces itself again (EL-C-14, the resume).
KEEPALIVE_TTL_MS = 30_000
#: A step of the wall clock past the monotonic clock, either way, longer than this re-judges every
#: deadline anchored to wall time (SPEC v0.1.36 §9.5).
WALL_STEP_MS = 1_000
#: A frame whose handling held the reader longer than this is a slow frame, counted by kind
#: (srad/agentspaces-event-loop.md EL-X-10, WD-8); PINGs queued behind it wait as long.
SLOW_FRAME_S = 0.1
#: A frame still in its handler after this long is a wedged reader: the watchdog names it once
#: (WD-8). Per-link order must hold, so no second reader takes over the socket.
WEDGED_FRAME_S = 5.0
#: The displaced holder's re-offers of its claim (SPEC v0.1.36 §7.4, the second rule's evidence):
#: at once, then no sooner than 1 s, 2 s, 4 s and so on after the previous offer, six offers in
#: all, while the claim is live and younger than half the drift ceiling; at most this many lines.
REOFFER_MAX = 6
#: A link to the seed silent this long is asked: this peer PINGs its seed, which answers every PING at
#: once (SPEC §5.2). 1.5 times the 30 s keepalive bound a member keeps, so a live seed in a quiet group
#: is asked rarely; a Java seed's own probes and the targeted relay's PINGs keep a busy link from it.
LINK_QUIET_S = 45.0
#: A link asked and still silent this long after is dead: a seed that left without a FIN (power loss,
#: a partition, a laptop moved to another network or back from a suspend) is otherwise read from for
#: ever, so this peer would never fail over and its ``relay.via`` would go on naming a holder that is
#: gone, and every member's targeted relay would fail. The link is shut and the reader reconnects.
#: The dead-seed rule every dial-only client keeps (owner decision 2026-11-23): this is the ping
#: timeout, 2 s, the one a prober gives each PING (SPEC §9.4, the core's ``GroupMembership``). It is
#: judged when it falls due, not on the watchdog's next check, and bytes of a frame still arriving
#: count as an answer, so a large frame on a slow link is not taken for a dead seed.
LINK_ANSWER_S = 2.0
REOFFER_BACKOFF_MS = 1_000
REOFFER_LINES_CAP = 1024
#: The redial table every peer keeps (owner decision 2026-11-23, one table in the core and every
#: client): the waits between rounds of seed dials, in seconds, taken in turn from a per-peer
#: position that advances after each wait and wraps back to the first. A link that held resets the
#: position, and so does a wake from sleep, which also dials at once. A peer's waits scale with its
#: ``reconnect_interval_s`` (the first entry, 5 s by default), so a test may run the same table faster.
REDIAL_TABLE_S = (5.0, 10.0, 20.0, 30.0)
#: The random spread on each wait of the redial table, a fraction either way (+/-10%), so the clients
#: of a seed that restarts do not all dial it again in the same instant.
REDIAL_SPREAD = 0.10
#: The seed dials' stagger (owner decision 2026-11-23, RFC 8305 Happy Eyeballs' connection attempt
#: delay): the seeds are dialled in list order, each start 250 ms after the one before, or at once when
#: a dial fails; the first to answer wins, the dials not yet started are not started, and a connection
#: that answers after the winner is closed. Every client and the core keep it.
DIAL_STAGGER_S = 0.25
#: At most this many seed dials are out at once (a hostname may resolve to many addresses); the next
#: starts when one fails.
DIALS_IN_FLIGHT_MAX = 16


def take_judged_within_millis(settle_millis: int) -> int:
    """How long after its claim goes out a take may be judged in a quiet space: the whole settle
    window, then the follow-up wait (``min(settle, 300)`` ms), which ends early only when something
    folds. A take lease must be longer than this, or the claim has lapsed when it is judged (SPEC
    §7.4), as the TypeScript ``takeJudgedWithinMillis``."""
    settle = max(0, int(settle_millis))
    return settle + min(settle, TAKE_FOLLOW_UP_MAX_MILLIS)


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
                 spill_max_fetch_bytes: int = wire.CARD_SPILL_MAX_FETCH_BYTES, horizon_hint: bool = True,
                 time_source: TimeSource | None = None):
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
        # The time source (SPEC v0.1.36 §9.5): wall time for what peers read, monotonic time for
        # every local period, and every wait; ``VirtualTime`` drives the same code in a test.
        self.time: TimeSource = time_source or SYSTEM
        # Seconds since the epoch; a test pins it to verify time-bound material
        # (agent certificates) against a fixed instant, as Java's TestClock does. Without one,
        # the time source's wall clock.
        self.clock = clock or (lambda: self.time.wall_ms() / 1000)
        # A bare ``clock`` has no monotonic twin, so a peer given one judges no wall steps; a peer
        # on its time source does (``_judge_wall_step``), and tells these listeners of each step.
        self._steps_judged = clock is None
        self._wall_step_listeners: list[Callable[[int], None]] = []
        # Told after a resume (``_resume``): a renewer of a lease another peer reads (the binder's
        # data-use entries) renews at once rather than at the end of its monotonic wait (WD-4).
        self._resume_listeners: list[Callable[[], None]] = []
        self._step_lock = threading.Lock()
        self.on_state = None  # optional callback(dto)
        # optional callback(dto) after a fold withdraws an entry that was present here: a cancel
        # (core cancel events, 2026-11-09), which a Space announces as EXPIRED
        self.on_withdrawn = None
        self.on_claim = None  # optional callback(entry_id, signed_claim) after a claim folds
        self.on_collected = None  # optional callback(entry_ids) after a collection dropped them (SPEC §7.3)
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
        # The last issue instant and content signed under each advertisement id (``_sign_and_send``).
        self._ads_issued: dict[str, tuple[int, bytes]] = {}
        self._ads_issue_lock = threading.Lock()
        self.pipe_handlers: dict[str, object] = {}  # capability type -> fn(from_peer, payload bytes)
        # The group's revocations (SPEC §5.6, v0.1.13): peer revocations and
        # credential revocations, verified founder-rooted (when the founder is
        # known, from ``founder`` or the verified founding document) or, for an
        # agent and its keys, by the agent's own peer. Applied at merge.
        self.revocations = revocations.Registry(lambda: self._founder(), lambda: self.group)
        self._configured_founder = founder
        self._running = False
        # Set by close(), which is final: the loops over this peer (the sweep, the binder's takes,
        # the aggregate's rounds) run until it, through any reconnect gap (a lost socket is not a
        # closed peer).
        self._closed = False
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
        # rounds of dials paced by the redial table (5, 10, 20, 30 s, then 5 s again) with a random
        # spread, until the owner's close(), which is final (swarm retries, owner decision 2026-11-23).
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
        # ``wire.horizon=1`` (SPEC v0.1.35 §7.3): on by default, since every renewal here keeps the
        # rule of §7.2; ``horizon_hint=False`` builds a member that keeps the legacy horizon, for a
        # mixed fleet in a test or a deployment that runs one identity on two nodes.
        self.horizon_hint = horizon_hint
        if horizon_hint:
            self.wire_hints[HINT_HORIZON] = "1"
        # The collection horizon (SPEC §7.3): the longest lease observed per space id, capped at
        # MAX_TRACKED_LEASE_MILLIS; the per-entry mode, judged from the view with Java's hysteresis
        # (LEGACY, WAITING, SETTLING, PER_ENTRY) and its counters; since when each member has been
        # a hinted member of the view in its current stay (the writer's half); and the last
        # collection. Before v0.1.35 this client kept every state it ever folded.
        self.max_lease: dict[str, int] = {}
        self.horizon_mode = "LEGACY"
        self.horizon_engage_rounds = DEFAULT_HORIZON_ENGAGE_ROUNDS
        self.horizon_engagements = 0
        self.horizon_settlements = 0
        self.horizon_disengagements = 0
        self._horizon_streak = 0
        self._horizon_counted_at: int | None = None
        self._horizon_engaged_at = 0
        self._hinted_since: dict[str, int] = {}
        self._horizon_lock = threading.Lock()
        self._collected_at: int | None = None
        self.tombstones_collected = 0
        self.collected_reoffers_refused = 0
        # The lines this replica acknowledges in the text digests it sends (SPEC §7.3, TECH-SPEC
        # §7.5), per space id: line -> the instant after which the acknowledgement may go, kept in
        # least recently refused order and bounded by REFUSED_ACK_CAP. Only the continuation of a
        # budgeted pull sends a text digest, so a replica that only ever pulls with empty digests
        # relies on its refusal cache alone, as before.
        self._acks: dict[str, dict[str, int]] = {}
        # A budgeted pull in flight per space name (annex I.6): the continuations it made and the
        # digest it last sent, so an answer that changed nothing ends it.
        self._budgeted_pulls: dict[str, dict] = {}
        self._state_hashes: dict[str, tuple] = {}  # entry id -> (the held state, its digest hash)
        # A state this replica joined from two signed inputs, neither of which equals the join, carries
        # no signature anyone made: entry id -> (the join as held, its most advanced signed input),
        # which an answer to the seed's DIGEST forwards in its place, as Java's ``signedStates``.
        self._signed_states: dict[str, tuple] = {}
        #: The seed's DIGESTs this peer answered with a PULL_RESP (owner decision 2026-11-23).
        self.pulls_answered = 0
        self.pull_continuations = 0
        # The connection on which the seed's PeerID was last confirmed by a frame addressed to us:
        # a budget goes only to the seed of the current connection, never to a stale one.
        self._seed_confirmed_on = None
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
        self._via_seed = None  # the seed endpoint seed_peer was learned on
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
        #: The first wait of the redial table (``REDIAL_TABLE_S``); the table's waits scale with it.
        self.reconnect_interval_s = 5.0
        #: How long the seeds are dialed before a bootstrapped peer reads its beacon document again.
        self.reconnect_window_s = 600.0
        self.reconnects = 0
        # When the current link was dialed, and how many links in a row ended within the reconnect
        # interval: such a link counts as a failed round of dials (swarm retries, ROBUSTNESS.md §10.6).
        self._link_since = 0.0
        # The position in the redial table of the next wait (``_next_redial_wait``), and the spread's
        # source of randomness (a test may give its own).
        self._redial_at = 0
        self._redial_random = random.Random()
        # The link's liveness (``_judge_link``): when a frame was last read off it (monotonic), when this
        # peer asked a silent link with a PING (None when not asked), and links judged dead for silence.
        # ``_redial`` cuts a reconnect pause short: a resume (a suspend may have slept through the pause)
        # and close() set it.
        self._heard_at = self.time.monotonic()
        self._link_asked_at: float | None = None
        self._link_lock = threading.Lock()
        # The redial and seed counters, under one set of names in every client (owner decision
        # 2026-11-23; camelCase in TypeScript): PINGs sent to ask the seed (a silent link's or a
        # wake's), the wake's among them, links dropped for silence, wakes judged (``resumes``,
        # below), seed dials started, and connections that answered after another seed won and
        # were closed.
        self.seed_pings = 0
        self.wake_pings = 0
        self.links_silent = 0
        self.seed_dials = 0
        self.late_seed_channels = 0
        # When the reader last took bytes off the link (monotonic), a frame complete or not; the link
        # this peer last judged dead (not judged again while it is still the socket); and the condition
        # an asked link's answer is waited on (``_await_link_answer``).
        self._bytes_at = float("-inf")
        self._link_dropped = None
        # The ask a wake made (its asked instant, or the ask already waiting it adopted): its verdict
        # fails over at once, however young the link (owner decision 2026-11-23, rule 3); and that a
        # dropped link is owed such a failover (``_reconnect`` takes it).
        self._wake_asked = None
        self._link_failover = False
        self._link_answer = threading.Condition()
        self._redial = threading.Event()
        # Fold-driven waits (JS-V-02): a take, a read, or an ordered take waits on the
        # next fold (a state or a claim) rather than polling, and pulls a space at most
        # once per settle window.
        self._fold_condition = threading.Condition()
        self._fold_count = 0
        self._last_pull: dict[str, float] = {}  # space name -> monotonic seconds of the last pull
        # The self-advertisement's last issue (SPEC v0.1.36, §10.16 of the core's record): the
        # gossip item millisecond, the issue instant, and what the advertisement said, so a changed
        # advertisement is never issued under the item id or the instant of the one before it.
        self._self_ad_item_ms = 0
        self._intro_lock = threading.Lock()
        self._self_ad_issued_ms = 0
        self._self_ad_content = None
        # The loop's health (the watchdog-equivalent check, srad/agentspaces-event-loop.md §3.9):
        # when the frame in hand started (monotonic, 0 when none) and its kind; slow frames by kind;
        # wedged frames named once; reader restarts; and the wall step and resume judgements.
        self._frame_started = 0.0
        self._frame_kind = ""
        self._frame_wedge_named = False
        self.slow_frames: dict[str, int] = {}
        self.frames_wedged = 0
        self.reader_restarts = 0
        self.wall_steps = 0
        self.resumes = 0
        self._wall_anchor: tuple[int, float] | None = (
            (self._now_ms(), self.time.monotonic()) if self._steps_judged else None)
        # The sweep of the spaces over this peer (agentspaces.space), set by the first Space: told
        # of every change so it waits for the next deadline rather than polling.
        self._sweeper = None
        # The losing side of the settle guarantee's second rule (SPEC v0.1.36 §7.4): the epoch this
        # peer completed each entry under, and each completion whose claim a better claim displaced,
        # with its offers so far (entry id -> [signed claim, offers, next offer wall ms, space name]).
        self._completed_here: dict[str, tuple[str, str, int]] = {}  # entry id -> (space, holder, epoch)
        self._displaced_own: dict[str, list] = {}
        self._reoffer_lock = threading.Lock()
        self.displaced_reoffers = 0

    # ------------------------------------------------------------- lifecycle

    def connect(self, host, port: int | None = None, *, scheme: str = "tcp",
                dial_timeout: float = 10.0) -> None:
        """Dials the seed and introduces this peer to the group. ``host`` and ``port``
        name a ``tcp`` seed unless ``scheme`` says ``tls``; ``host`` alone may be a seed
        in text (``tls://host:port``, ``host:port``) or a ``Seed``."""
        seed = parse_seed(host) if port is None else Seed(str(host), int(port), scheme.lower())
        self._seed = seed
        self._socket = self._dial(seed, dial_timeout)
        self._begin_link(seed)

    def _begin_link(self, seed) -> None:
        """Starts the peer on the link just dialled to ``seed``: the reader, the introduction, the
        revocation pull and the PING that learns the seed."""
        self._seed = seed
        self._closed = False
        self._running = True
        self._redial.clear()  # a close() before this connect left it set
        self._redial_at = 0  # a fresh start: the redial table from its first wait
        self._note_dialled(seed)
        self._start_reader()
        self.introduce()
        self.pull_revocations()
        self._learn_seed()

    def _start_reader(self) -> None:
        """Starts the reader thread and puts this peer under the process watchdog."""
        from . import watchdog
        self._reader = threading.Thread(target=self._read_loop, name="agentspaces-reader", daemon=True)
        self._reader.start()
        watchdog.watch(self)

    def _note_dialled(self, seed) -> None:
        """Names the member this peer dialled in ``relay.via`` before it introduces itself on a new
        link (SPEC v0.1.36 §5.2, the targeted relay: every non-seed member probes a dial-only peer
        through the holders that hint names, so a member named but not linked is not reached). On
        ``tls`` the handshake attested the seed's PeerID, so the first introduction names it. On
        ``tcp`` the seed is known from its first frame addressed here; a link to another seed than
        the one the hint was learned on clears the hint and the seed until then, rather than naming
        a member this peer no longer holds a link to."""
        attested = self._attested
        if attested is not None:
            self.seed_peer = attested
            self.resource_hints["relay.via"] = attested
            self._via_seed = seed
            return
        if getattr(self, "_via_seed", None) is not None and self._via_seed != seed:
            self.seed_peer = None
            self.resource_hints.pop("relay.via", None)
            self._via_seed = None

    def connect_any(self, seeds, *, dial_timeout: float = 10.0) -> tuple:
        """Dials the seeds, (host, port) pairs, in list order 250 ms apart, and links to
        the first that answers (owner decision 2026-11-23, ``_dial_first``: a dead seed
        costs the stagger, not its connect timeout). It remembers them all: a lost socket fails over to
        another seed (SRAD DB-X-01). A hostname is resolved to every address and each
        is a seed (DB-X-03). Returns the seed connected to; raises OSError when none
        accepted within ``dial_timeout``."""
        expanded = self._expand_seeds(seeds)
        if not expanded:
            raise OSError("no seeds to dial")
        self._seeds = expanded
        seed, sock = self._dial_first(expanded, dial_timeout)
        self._socket = sock
        self._begin_link(seed)
        return seed

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
        """One connected socket for ``seed`` by its scheme (``_open``), taken as this
        peer's link: records the attestation for the reader and starts the link's clock.
        Raises OSError for a scheme this client does not dial, as for a refused connection."""
        self.seed_dials += 1
        sock, attested = self._open(seed, timeout)
        self._adopt_link(sock, attested)
        return sock

    def _open(self, seed: Seed, timeout: float) -> tuple:
        """Dials ``seed`` by its scheme, ``tcp`` plain, ``tls`` with this peer's channel
        certificate and the seed's attested (``agentspaces.tls``), and returns ``(socket,
        attested PeerID or None)``. Touches nothing on the peer, so several run at once
        (``_dial_first``)."""
        if seed.scheme == "tcp":
            sock = socket.create_connection((seed.host, seed.port), timeout=timeout)
            attested = None
        elif seed.scheme == "tls":
            sock, attested = tls.connect(seed.host, seed.port, self.identity, timeout=timeout,
                                         credentials=self._credentials)
        else:
            raise OSError(f"no dialer for {seed}: this client dials tcp and tls")
        sock.settimeout(None)
        return sock, attested

    def _adopt_link(self, sock, attested) -> None:
        """Takes a socket ``_open`` returned as this peer's link: the attestation, and the link's dial
        instant and liveness from now."""
        self._attested = attested
        self._link_since = self.time.monotonic()
        with self._link_lock:
            self._heard_at, self._link_asked_at = self._link_since, None
            self._wake_asked, self._link_failover = None, False  # a new link owes no wake's failover

    def _dial_first(self, seeds, timeout: float) -> tuple:
        """Dials ``seeds`` in list order, staggered ``DIAL_STAGGER_S`` (250 ms) apart, and takes the
        first that answers as this peer's link (owner decision 2026-11-23, RFC 8305): a dial that
        fails starts the next at once, so a refusing seed costs nothing and a silent one costs the
        stagger rather than its connect timeout. When one answers, the dials not yet started are not
        started, and a dial still out that answers later is closed at once. Each dial has its own
        ``timeout``, and at most ``DIALS_IN_FLIGHT_MAX`` are out at once. The stagger is judged on the
        time source. One seed is dialled on the calling thread. Returns ``(seed, socket)``; raises
        OSError, from the last failure, when none answered."""
        seeds = list(seeds)
        if not seeds:
            raise OSError("no seeds to dial")
        if len(seeds) == 1:
            return seeds[0], self._dial(seeds[0], timeout)
        state = threading.Condition()
        answers: list = []  # (seed, socket or None, attested, error), in the order they came
        won: list = []

        def dial(seed) -> None:
            try:
                sock, attested = self._open(seed, timeout)
            except Exception as e:  # noqa: BLE001 - a failed dial is an answer: the next starts at once
                with state:
                    answers.append((seed, None, None, e))
                    state.notify_all()
                return
            with state:
                late = bool(won)
                if late:
                    self.late_seed_channels += 1
                else:
                    won.append(seed)
                    answers.append((seed, sock, attested, None))
                    state.notify_all()
            if late:  # another seed answered first: this connection is not wanted
                try:
                    sock.close()
                except OSError:
                    pass

        started = failed = 0
        last: Exception | None = None
        next_at = self.time.monotonic()
        winner = None
        with state:
            while winner is None:
                token = self.time.token()
                while answers:
                    seed, sock, attested, error = answers.pop(0)
                    if sock is not None:
                        winner = (seed, sock, attested)
                        break
                    failed += 1
                    last = error
                    next_at = self.time.monotonic()  # a failed dial starts the next at once
                if winner is not None:
                    break
                if failed == len(seeds):
                    raise OSError(f"no seed accepted: {[str(s) for s in seeds]}") from last
                can_start = started < len(seeds) and started - failed < DIALS_IN_FLIGHT_MAX
                now = self.time.monotonic()
                if can_start and now >= next_at:
                    threading.Thread(target=dial, args=(seeds[started],), name="agentspaces-dial",
                                     daemon=True).start()
                    started += 1
                    self.seed_dials += 1
                    next_at = now + DIAL_STAGGER_S
                    continue
                self.time.wait(state, next_at - now if can_start else None, token)
        seed, sock, attested = winner
        self._adopt_link(sock, attested)
        return seed, sock

    def _dial_order(self) -> list:
        """The seeds a lost socket dials, in the order ``_dial_first`` staggers them: the seeds of
        connect_any or the beacon in list order, the one just lost last (owner decision 2026-11-23),
        so the peer fails over to the next seed and a hung seed whose kernel still accepts does not
        win the race back. Every round of a reconnect dials in this order."""
        if not self._seeds:
            return [self._seed] if self._seed else []
        order = [seed for seed in self._seeds if seed != self._seed]
        if self._seed in self._seeds:
            order.append(self._seed)
        return order

    def _reconnect(self) -> bool:
        """After a lost socket: dials the seeds again (the seeds of connect_any in list order, 250 ms
        apart, the one just lost last, the first to answer winning: ``_dial_first``, ``_dial_order``),
        then introduces this peer again and pulls what it had pulled before, so a network hiccup costs a few seconds rather than the membership (ROBUSTNESS.md
        §3.6). Between failed rounds it waits on the redial table (``REDIAL_TABLE_S``: 5, 10, 20,
        30 s, then 5 s again, each with a spread of +/-10%), so the clients of a seed that restarts
        do not all dial it at once, and it goes on until the owner closes the peer (swarm retries,
        ROBUSTNESS.md §10.3 E5; owner decision 2026-11-23). A link that held for at least the table's
        first wait (5 s) resets the table and is dialled again at once; one that ended sooner counts
        as a failed round and takes the next wait, so a seed that accepts each dial and drops it at once gets the
        same pauses and no dial loop (ROBUSTNESS.md §10.6). A wake from sleep cuts a wait short and
        resets the table, and so does the dead-seed verdict on a wake's PING, which fails over at once
        however young the link. A bootstrapped peer reads the beacon document again every
        reconnect_window_s with nothing reachable, and keeps the seeds it has when the beacon is
        unreachable too."""
        with self._link_lock:
            at_once, self._link_failover = self._link_failover, False
        if not at_once and self.time.monotonic() - self._link_since < self.reconnect_interval_s:
            self._pause_redial(self._next_redial_wait())
        else:
            self._redial_at = 0  # the link held: a successful link starts the table again
        deadline = self.time.monotonic() + self.reconnect_window_s
        while self._running:
            if self.time.monotonic() >= deadline:
                deadline = self.time.monotonic() + self.reconnect_window_s
                if self._refresh_seeds is not None:
                    try:
                        seeds = self._expand_seeds(self._refresh_seeds())
                    except Exception:  # noqa: BLE001 - the beacon is unreachable too: the seeds held stay
                        seeds = None
                    if seeds:
                        self._seeds = seeds
            seed = fresh = None
            order = self._dial_order()
            if order:
                try:
                    seed, fresh = self._dial_first(order, 10)
                except OSError:
                    pass
            if fresh is not None:
                if not self._running:  # closed by the owner while the dial was out
                    try:
                        fresh.close()
                    except OSError:
                        pass
                    return False
                with self._lock:
                    self._socket = fresh
                self._seed = seed
                self.reconnects += 1
                self._redial.clear()
                self._note_dialled(seed)
                self.introduce()
                self.pull_revocations()
                if self._pulled_ads:
                    self.pull_ads()
                for space in list(self._pulled_spaces):
                    self.pull_space(space)
                self._learn_seed()
                return True
            self._pause_redial(self._next_redial_wait())
        return False

    def _learn_seed(self) -> None:
        """On a link whose seed is not yet known (``tcp``; ``tls`` attests it), asks the seed with a PING,
        which every member answers at once with an ACK addressed to the prober (SPEC §5.2). That
        addressed frame names the seed, so the ``relay.via`` hint names the member this peer dialled
        within one round trip, rather than at the seed's own probe of this peer, which may be a whole
        quiet cycle away (about 196 s at fifty members), while every member's targeted relay has no
        holder to ask (SPEC v0.1.36 §5.2)."""
        if self.seed_peer is None and self._socket is not None:
            self._send("PING", wire.ping_body(random.getrandbits(62)))

    def _pause_redial(self, seconds: float) -> bool:
        """A reconnect pause on the time source, cut short by a resume or close() (``_redial``): a
        laptop that slept through a pause dials again on wake rather than sitting out what is left of
        it (EL-C-14, "a thin client re-dials its seed on wake"), and the redial table starts again.
        Returns whether it was cut short."""
        if self.time.wait_event(self._redial, seconds):
            self._redial.clear()
            self._redial_at = 0
            return True
        return False

    def _next_redial_wait(self) -> float:
        """The next wait of the redial table, from this peer's position, which then advances and wraps
        back to the first wait after the last: ``REDIAL_TABLE_S`` scaled to reconnect_interval_s, with
        a random spread of +/-``REDIAL_SPREAD``."""
        at = self._redial_at % len(REDIAL_TABLE_S)
        self._redial_at = (at + 1) % len(REDIAL_TABLE_S)
        wait = REDIAL_TABLE_S[at] * self.reconnect_interval_s / REDIAL_TABLE_S[0]
        return wait * self._redial_random.uniform(1.0 - REDIAL_SPREAD, 1.0 + REDIAL_SPREAD)

    def bootstrap(self, url: str, *, group_id: str | None = None, allow_plain: bool = False,
                  beacon_peer: str | None = None, timeout: float = 3.0,
                  join_timeout: float = 10.0) -> dict:
        """Joins through a beacon document (SRAD DB-X-01): fetches and verifies the
        document at ``url`` (https unless ``allow_plain``; signed by ``beacon_peer`` when
        pinned), selects the group (by ``group_id``, else the only one), verifies its
        founding advertisement with the four checks of SPEC §5.1 against ``group_id``
        when given, and dials its ``tcp`` and ``tls`` seeds in the document's order,
        250 ms apart, the first to answer winning (owner decision 2026-11-23).
        Returns the verified SignedGroupAdvertisement, kept on ``peer.founding``.

        ``timeout`` bounds one attempt (one fetch, one dial of one seed) and
        ``join_timeout`` bounds the whole call. A first attempt that succeeds asks once
        and dials once. Otherwise the call keeps asking inside the budget, in slices of
        1 s, 2 s, 4 s, then 5 s each (the shape of the Java join by id,
        ISSUE-BootstrapRobustness FR-4): at the start of each slice it fetches the
        document again when the previous fetch failed with an OSError or named no tcp
        seed, and dials every seed again, once per slice, staggered as above. A beacon or a
        seed that starts a few seconds after this peer is reached on a later slice.
        A refusal (a bad scheme, a document or founding that does not verify, a
        founding for another id, a group the document does not carry) raises ValueError
        at once, as before. When the budget runs out the call raises
        :class:`BootstrapTimeout` (an OSError) whose message and attributes carry the
        number of fetches, the seeds dialed, how many connected, and the last error."""
        deadline = self.time.monotonic() + join_timeout
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
            started = self.time.monotonic()
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
            remaining = deadline - self.time.monotonic()
            if seeds and remaining > 0:
                for seed in seeds:
                    if seed not in dialed:
                        dialed.append(seed)
                self._seeds = seeds
                try:  # in order 250 ms apart, the first to answer wins (owner decision 2026-11-23)
                    seed, sock = self._dial_first(seeds, min(timeout, remaining))
                    self._socket = sock
                    self._begin_link(seed)
                except OSError as e:
                    last_error = e
                else:
                    connected += 1
                    return founding
            now = self.time.monotonic()
            wait = min(slice_s - (now - started), deadline - now)
            if wait > 0:
                self.time.sleep(wait)
            if self.time.monotonic() >= deadline:
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
        hostile seed can delay the join and can never substitute a policy.

        ``group_id`` is the bare id or the join URI ``aspace://<id>[/<space>]``.
        The want goes out again while the join waits, in slices of 1 s, 2 s,
        4 s, then 5 s, as Java's join does (ISSUE-BootstrapRobustness FR-4),
        so a seed that missed the first want still answers."""
        bare = beacon.parse_group_id(group_id)
        if bare is None:
            raise ValueError(f"no GroupId in {group_id!r}")
        self.group = bare
        self.founding = None
        self._founding_ready.clear()
        self._seed = Seed(host, int(port), scheme.lower())
        self._socket = self._dial(self._seed, 10)
        self._closed = False
        self._running = True
        self._note_dialled(self._seed)
        self._start_reader()
        deadline = self.time.monotonic() + timeout
        slice_seconds = 1.0
        while True:
            self._send(wire.KIND_GROUP_AD_WANT, b"")
            remaining = deadline - self.time.monotonic()
            if remaining <= 0 or self.time.wait_event(self._founding_ready, min(slice_seconds, remaining)):
                break
            slice_seconds = min(slice_seconds * 2, 5.0)
        if not self._founding_ready.is_set() or self.founding is None:
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
        self._closed = True
        self._running = False
        self._redial.set()  # a reconnect pause in progress ends now
        self._link_answered()
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None
        sweeper = self._sweeper
        if sweeper is not None:
            sweeper.wake()  # it sees the peer closed and ends
        self._wake_fold_waiters()

    @property
    def closed(self) -> bool:
        """Whether ``close()`` ended this peer. A peer between links (a reconnect in progress) is
        not closed: the loops over it wait for the link and go on."""
        return self._closed

    def _founder(self):
        if self._configured_founder:
            return self._configured_founder
        if self.founding:
            return (self.founding.get("advertisement") or {}).get("issuer")
        return None

    def _now_ms(self) -> int:
        if self._steps_judged:
            return self.time.wall_ms()  # the time source's own milliseconds, with no float between
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

    # ------------------------------------------------------------- the loop's health

    def loop_health(self) -> dict:
        """The reader's and the sweep's liveness and what the watchdog judged (SPEC v0.1.36 §9.5;
        srad/agentspaces-event-loop.md §3.9): whether each thread lives, the frame in hand and how
        long it has held the reader, slow frames by kind, wedged frames, reader restarts, wall
        steps and resumes, the displaced claims offered again (§7.4), and the redial and seed counters."""
        started = self._frame_started
        sweeper = self._sweeper
        return {"closed": self._closed, "connected": self.connected,
                "readerAlive": bool(self._reader is not None and self._reader.is_alive()),
                "sweepAlive": bool(sweeper is not None and sweeper.alive()),
                "frameInHand": self._frame_kind if started else "",
                "frameHeldSeconds": round(self.time.monotonic() - started, 3) if started else 0.0,
                "slowFrames": dict(self.slow_frames), "framesWedged": self.frames_wedged,
                "readerRestarts": self.reader_restarts, "wallSteps": self.wall_steps,
                "resumes": self.resumes, "displacedReoffers": self.displaced_reoffers,
                # The redial and seed counters under the names every client shares (owner decision
                # 2026-11-23); "linksSilent" is kept as an alias for one release.
                "seed_pings": self.seed_pings, "wake_pings": self.wake_pings,
                "links_silent": self.links_silent, "seed_dials": self.seed_dials,
                "late_seed_channels": self.late_seed_channels,
                "linksSilent": self.links_silent}

    def _watch(self) -> None:
        """One check by the process watchdog (``agentspaces.watchdog``), from outside the reader: it
        reads this peer's heartbeat and takes no lock a frame handler can hold (WD-1).

        * A reader that died while the peer runs (an exception the read loop did not expect) is
          started again, which reads on or reconnects as the old one would have (the Dead check).
        * A frame still in its handler after WEDGED_FRAME_S is named once, with its kind: every PING
          behind it waits as long, and a prober suspects this peer. No second reader takes the
          socket, since per-link order must hold (WD-8); a handler hands long work to a thread.
        * The sweep's thread is started again if it died.
        * A step of the wall clock past the monotonic clock is judged (``_judge_wall_step``)."""
        if self._closed:
            return
        now = self.time.monotonic()
        reader = self._reader
        if self._running and self._seed is not None and reader is not None and not reader.is_alive():
            self.reader_restarts += 1
            LOG.warning("the reader of %s died while the peer runs; starting it again", self.identity.peer_id)
            self._reader = threading.Thread(target=self._read_loop, name="agentspaces-reader", daemon=True)
            self._reader.start()
        started = self._frame_started
        if started and now - started > WEDGED_FRAME_S and not self._frame_wedge_named:
            self._frame_wedge_named = True
            self.frames_wedged += 1
            LOG.warning("a %s frame has held the reader of %s for %.1f s: PINGs wait behind it and probers "
                        "suspect this peer; a handler or watch callback should hand long work to a thread",
                        self._frame_kind or "?", self.identity.peer_id, now - started)
        sweeper = self._sweeper
        if sweeper is not None:
            sweeper.ensure_alive()
        self._judge_wall_step()
        self._judge_link()

    def _judge_link(self) -> None:
        """Judges the link to the seed by what this peer last read off it (from the watchdog). A link
        silent for LINK_QUIET_S is asked with a PING to the seed; one still silent LINK_ANSWER_S after
        the PING is dead, and is shut so the reader reconnects (to the next seed first) and the
        ``relay.via`` hint follows the new holder. A live seed answers every PING at once, so a quiet
        group costs one PING and one ACK per LINK_QUIET_S and nothing is dropped."""
        sock = self._socket
        if sock is None or self._closed or not self._running or self._seed is None:
            return
        if self._frame_started:
            return  # a frame handler holds the reader: the silence is this peer's, not the seed's (WD-8)
        now = self.time.monotonic()
        with self._link_lock:
            if sock is self._link_dropped:
                return  # judged dead already: the reader is reconnecting
            if self._bytes_at > self._heard_at:
                # Bytes of a frame not yet complete: the seed is writing, and a slow link is no dead one.
                self._heard_at, self._link_asked_at = self._bytes_at, None
            asked = self._link_asked_at
            if asked is None:
                if now - self._heard_at < LINK_QUIET_S:
                    return
                dead = False
            elif now - asked < LINK_ANSWER_S:
                return
            else:
                dead = True
                self._link_asked_at = None
                self._link_dropped = sock
                # the verdict on a wake's PING fails over at once, however young the link (rule 3)
                self._link_failover, self._wake_asked = asked == self._wake_asked, None
        if not dead:
            self._ask_link()
            return
        self.links_silent += 1
        LOG.warning("the link of %s to its seed %s was silent for %.0f s and did not answer a PING: "
                    "dropping it to dial again", self.identity.peer_id, self._seed, now - self._heard_at)
        try:
            shutdown = getattr(sock, "shutdown", None)
            if shutdown is not None:
                shutdown(socket.SHUT_RDWR)  # wakes the reader's recv, which reconnects
        except OSError:
            pass

    def _ask_link(self, wake: bool = False) -> None:
        """Asks the link whether the seed still reads it: a PING to the seed (to it by name once known),
        which every member answers at once with an ACK (SPEC §5.2). Asked once until a frame arrives.

        The PING is sent from the ask's own thread, never from the caller's: toward a seed that died
        without a FIN, another thread's write can hold the send lock in ``sendall`` behind a full send
        buffer until TCP gives up. The watchdog then still judges the ask at its timeout and shuts the
        link, which also frees that write."""
        with self._link_lock:
            if self._link_asked_at is not None or self._socket is None or self._socket is self._link_dropped:
                if wake:  # a PING already waiting is not sent again: it becomes the wake's (rule 3)
                    self._wake_asked = self._link_asked_at
                return
            asked = self._link_asked_at = self.time.monotonic()
            self.seed_pings += 1
            if wake:  # marked with the ask, so no verdict can come before the mark
                self._wake_asked = asked
                self.wake_pings += 1
        threading.Thread(target=self._ask_and_await, args=(asked,), name="agentspaces-link-ask",
                         daemon=True).start()

    def _ask_and_await(self, asked: float) -> None:
        """The ask's thread: the PING to the seed, then the wait for its answer."""
        self._send("PING", wire.ping_body(random.getrandbits(62)), to=self.seed_peer)
        self._await_link_answer(asked)

    def _await_link_answer(self, asked: float) -> None:
        """Waits out the ping timeout of one ask on the time source, then judges the link at once,
        rather than on the watchdog's next check. Ends early when a frame answers (``_receive``),
        a new link replaces the asked one, or the peer closes."""
        deadline = asked + LINK_ANSWER_S
        with self._link_answer:
            while True:
                token = self.time.token()
                if self._closed or self._link_asked_at != asked:
                    return
                remaining = deadline - self.time.monotonic()
                if remaining <= 0:
                    break
                self.time.wait(self._link_answer, remaining, token)
        self._judge_link()

    def _link_answered(self) -> None:
        """Wakes a wait for an asked link's answer (a frame came, a link replaced it, or close())."""
        with self._link_answer:
            self._link_answer.notify_all()

    def _judge_wall_step(self) -> None:
        """Compares the wall clock's movement with the monotonic clock's since the last judgement
        (SPEC v0.1.36 §9.5). A step either way longer than WALL_STEP_MS asks every deadline anchored
        to wall time again (the sweep's lapses). A forward step longer than KEEPALIVE_TTL_MS, which a
        suspend raises, means the members may have dropped this peer for silence: it introduces
        itself again with an advertisement issued now, which re-admits it where it was dropped, and
        pulls what it pulled (the resume, EL-C-14). A lost socket reconnects as before."""
        if not self._steps_judged:
            return
        with self._step_lock:
            wall, mono = self._now_ms(), self.time.monotonic()
            anchor = self._wall_anchor
            self._wall_anchor = (wall, mono)
            if anchor is None:
                return
            step = int((wall - anchor[0]) - (mono - anchor[1]) * 1000)
            if abs(step) <= WALL_STEP_MS:
                return
            self.wall_steps += 1
        for listener in list(self._wall_step_listeners):
            try:
                listener(step)  # a local period anchored to wall time moves with the step
            except Exception:  # noqa: BLE001
                LOG.exception("a wall step listener failed")
        sweeper = self._sweeper
        if sweeper is not None:
            sweeper.wake()
        if step > KEEPALIVE_TTL_MS and self._running and not self._closed:
            self.resumes += 1
            LOG.info("the wall clock of %s moved %d ms past its monotonic clock (a suspend?): "
                     "introducing it again", self.identity.peer_id, int(step))
            threading.Thread(target=self._resume, name="agentspaces-resume", daemon=True).start()

    def _resume(self) -> None:
        """The resume (EL-C-14; owner decision 2026-11-23): with the link up, a PING to the seed under
        the dead-seed rule (no answer within LINK_ANSWER_S, 2 s, drops the link and the peer fails
        over), then a fresh self-advertisement and the pulls a reconnect makes. With no link, the
        reconnect in progress dials at once. Either way the redial table starts again."""
        for listener in list(self._resume_listeners):
            try:
                listener()
            except Exception:  # noqa: BLE001
                LOG.exception("a resume listener failed")
        if self._closed:
            return
        self._redial_at = 0  # a wake starts the redial table again
        if self._socket is None:
            self._redial.set()  # a reconnect pausing between rounds dials again now
            return
        # The link may have died in the suspend with no FIN to tell: ask it first, so a dead one is
        # dropped within LINK_ANSWER_S rather than after LINK_QUIET_S more of silence, and the PING
        # goes out ahead of the introduction and the pulls (the dead-seed rule, the same everywhere).
        # A PING already waiting is not sent again; either way the ask in force is the wake's, and its
        # verdict fails over at once however young the link on the monotonic clock (which did not
        # count the sleep): the wake already started the table again, so it is no quick drop.
        self._ask_link(wake=True)
        self.introduce()
        self.pull_revocations()
        if self._pulled_ads:
            self.pull_ads()
        for space in list(self._pulled_spaces):
            self.pull_space(space)

    # ------------------------------------------------------------- protocol

    def introduce(self) -> None:
        """Publishes this peer's leased self-advertisement (spec §5.2). The issue instant is the
        whole second, as the advertisement has always been stamped, and a changed advertisement is
        issued at least a millisecond after the one before it, which a receiver may keep on an
        equal instant; the gossip item id moves at least a millisecond each time, so a receiver
        never drops a new advertisement as a copy of the last (SPEC v0.1.36; the core's §10.16:
        the ``relay.via`` hint learned a millisecond after the first introduction was lost)."""
        with self._intro_lock:
            now_ms = self._now_ms()
            hints = {**self.wire_hints, **self.resource_hints}
            content = tuple(sorted(hints.items()))
            issued_ms = now_ms - now_ms % 1000
            if issued_ms <= self._self_ad_issued_ms:
                issued_ms = (self._self_ad_issued_ms if content == self._self_ad_content
                             else self._self_ad_issued_ms + 1)
            item_ms = max(now_ms, self._self_ad_item_ms + 1)
            self._self_ad_issued_ms, self._self_ad_item_ms, self._self_ad_content = issued_ms, item_ms, content
            ad = wire.peer_advertisement(self.group, self.identity, instant_iso(issued_ms),
                                         resource_hints=hints)
            payload = wire.signed_peer_ad(ad, self.identity)
            item_id = f"peer:{self.identity.peer_id}:{item_ms}"
            # sent under the lock, so two introductions (a resume's and a seed's first frame) leave in
            # the order they were issued and the last a receiver reads is the newest
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
        return self._sign_and_send(ad_type, ad)

    def withdraw_ad(self, ad_id: str) -> None:
        """Stops reissuing a card: the last one signed lapses at its ttl, and a parts document
        it named is released one ttl after the last card that named it."""
        with self._cards_lock:
            self._cards.pop(ad_id, None)
            self._signed_issued.pop(ad_id, None)

    def _sign_and_send(self, ad_type: str, ad: dict) -> dict:
        """Signs an advertisement, caches it here and sends it on the ``ads`` stream under its id and
        issue millisecond. A changed advertisement whose issue instant is not after the last one
        under its id is issued a millisecond after it (SPEC v0.1.36; the core's §10.16): a cache
        keeps only a strictly newer version, and the gossip item id is the issue millisecond, so
        the change was otherwise lost until the next refresh. The same content keeps its instant.
        Returns the advertisement as signed."""
        from .identity import parse_instant_millis
        issued_ms = parse_instant_millis(ad["issued"])
        fingerprint = hashlib.sha256(cbor.dumps({k: v for k, v in ad.items() if k != "issued"})).digest()
        with self._ads_issue_lock:
            last = self._ads_issued.get(ad["id"])
            if last is not None and issued_ms <= last[0] and fingerprint != last[1]:
                issued_ms = last[0] + 1
                ad = {**ad, "issued": instant_iso(issued_ms)}
            self._ads_issued[ad["id"]] = (max(issued_ms, last[0]) if last is not None else issued_ms, fingerprint)
            while len(self._ads_issued) > AD_CACHE_MAX_ENTRIES:
                del self._ads_issued[next(iter(self._ads_issued))]
        stored = wire.stored_ad(ad_type, ad, self.identity)
        self.accept_ad(stored)  # our own cache holds it too, as DiscoveryService.publish does
        item_id = f"{ad['id']}:{parse_instant_millis(ad['issued'])}"
        self._send("RUMOR", wire.rumor_body("ads", item_id, 6, cbor.dumps(stored)))
        return ad

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
        digest names, so a late joiner learns the group's revocations here.

        Toward a seed whose current card carries ``wire.ae=2`` the pull is budgeted (SPEC
        annex I.6, *The budget*; RE-L-03): it names ``DEFAULT_PULL_BUDGET`` and offers this
        replica's own text digest of the space, empty while it holds nothing there, so the
        partner answers at most a budget of the states this replica lacks, newest first, and
        an answer that left states out is continued at once (``_continue_pulls``). Toward any
        other seed the pull is the empty digest of every release, answered whole."""
        self._pulled_spaces.add(space)
        self._collect_if_due()
        budget = self.pull_budget()
        if budget is None:
            self._send("DIGEST", wire.digest_body(
                {f"space:{space}": b"", **{stream: b"" for stream in revocations.STREAMS}}))
            return
        text = self.space_digest(space)
        self._budgeted_pulls[space] = {"budget": budget, "continuations": 0,
                                       "sent": hashlib.sha256(text).digest()}
        self._send("DIGEST", wire.digest_body(
            {f"space:{space}": text, **{stream: b"" for stream in revocations.STREAMS}}, budget=budget))

    def pull_budget(self) -> int | None:
        """The budget this peer names on a pull (annex I.6), or None for an unbudgeted pull. A
        sender reads the partner's current card before each round and sends ``budget`` only
        toward a card that carries ``wire.ae=2``, since a member without the hint drops the
        whole DIGEST as undecodable (P1). This client's partner is its seed, so the budget goes
        only when the seed's PeerID was confirmed on the current connection and the seed's
        current advertisement, unexpired, carries the hint; a reconnect to another seed sends
        empty digests until that seed is known."""
        seed = self.seed_peer
        if seed is None or self._socket is None or self._seed_confirmed_on is not self._socket:
            return None
        ad = self.members.get(seed) or {}
        if not ad or _ad_expires_ms(ad) <= self._now_ms():
            return None
        return DEFAULT_PULL_BUDGET if (ad.get("resourceHints") or {}).get(HINT_AE) == "2" else None

    def space_digest(self, space: str) -> bytes:
        """This replica's text digest of a space (TECH-SPEC §7.5): an ``e:`` line for every state
        it holds, tombstones included, a ``c:`` line for every claim, and an ``a:`` line for every
        state or claim it acknowledges, so a partner answers only what differs. Past
        MAX_DIGEST_TEXT_BYTES the lines a partner would send first (present states, newest first)
        are kept and the rest left out, so the DIGEST stays within the 8 MiB frame and the
        partner sends the left-out entries again, which costs bytes and never correctness."""
        from .identity import space_id_local
        space_id = space_id_local(f"{self.group}/{space}")
        now = self._now_ms()
        with self._state_lock:
            held = [(entry_id, dto) for entry_id, dto in list(self.states.items())
                    if (dto.get("record") or {}).get("spaceId") == space_id]
            claims = [(entry_id, signed["claim"]) for entry_id, signed in list(self.claims.items())
                      if signed["claim"].get("spaceId") == space_id]
        acknowledged = self._ack_lines(space_id, now)
        lines: dict[str, str] = {}
        for entry_id, dto in held:
            lines[f"e:{entry_id}"] = self._state_hash(entry_id, dto)
        for entry_id, claim in claims:
            lines[f"c:{entry_id}"] = digests.claim_hash(claim)
        text = digests.digest_text(lines, acknowledged)
        if len(text) <= MAX_DIGEST_TEXT_BYTES:
            return text
        # The partner's order (annex I.6, *The fetch*): present states, then tombstones, newest
        # first by lease stamp; a claim travels with its state.
        order = sorted(held, key=lambda item: item[0].encode("utf-8"))
        order.sort(key=lambda item: _stamp_key(item[1].get("leaseStamp")), reverse=True)
        order.sort(key=lambda item: not present(item[1]))
        claimed = dict(claims)
        kept: dict[str, str] = {}
        size = sum(len(f"a:{line}\n".encode("utf-8")) for line in acknowledged)
        for entry_id, dto in order:
            pair = {f"e:{entry_id}": self._state_hash(entry_id, dto)}
            if entry_id in claimed:
                pair[f"c:{entry_id}"] = digests.claim_hash(claimed[entry_id])
            cost = sum(len(f"{k}={v}\n".encode("utf-8")) for k, v in pair.items())
            if size + cost > MAX_DIGEST_TEXT_BYTES:
                break
            kept.update(pair)
            size += cost
        return digests.digest_text(kept, acknowledged)

    def _state_hash(self, entry_id: str, dto: dict) -> str:
        """The digest hash of a held state, cached while the replica holds that same state: a fold,
        a renewal or a cancel replaces the held dict rather than changing it, so a take that pulls
        every settle window hashes only what changed since."""
        cached = self._state_hashes.get(entry_id)
        if cached is not None and cached[0] is dto:
            return cached[1]
        value = digests.state_hash(dto)
        self._state_hashes[entry_id] = (dto, value)
        return value

    def _continue_pulls(self, remainder: dict) -> None:
        """Continues each budgeted pull whose answer left states out (annex I.6): at once, to the
        same seed, with this replica's text digest under the same budget, since the partner holds
        the rest. A pull ends when an answer left nothing out or after MAX_PULL_CONTINUATIONS. An
        answer that changed nothing here (a duplicate, or states this replica refuses) sends
        nothing, since the partner would answer the same digest the same way, and keeps the pull,
        so the answer still in flight to the last digest continues it. A lost answer ends the
        pull; the next pull of the space starts from what this replica holds, and anti-entropy
        brings anything a pull leaves (ROBUSTNESS.md §10)."""
        for stream, left in remainder.items():
            if not str(stream).startswith("space:"):
                continue
            space = stream[len("space:"):]
            pull = self._budgeted_pulls.get(space)
            if pull is None:
                continue  # an answer to no budgeted pull of ours: the states folded, nothing more
            if left <= 0 or pull["continuations"] >= MAX_PULL_CONTINUATIONS:
                self._budgeted_pulls.pop(space, None)
                continue
            text = self.space_digest(space)
            sent = hashlib.sha256(text).digest()
            if sent == pull["sent"]:
                continue
            pull["continuations"] += 1
            pull["sent"] = sent
            self.pull_continuations += 1
            self._send("DIGEST", wire.digest_body({stream: text}, budget=pull["budget"]))

    def pull_space_paced(self, space: str, settle_seconds: float) -> bool:
        """Pulls a space unless it was pulled within ``settle_seconds`` (JS-V-02): a
        waiting take issues at most one DIGEST per settle window, and none while
        folds keep arriving. Returns whether a pull went out."""
        now = self.time.monotonic()
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
            return wait_until(self.time, self._fold_condition, lambda: self._fold_count != seen,
                              max(0.0, max_seconds))

    def _wake_fold_waiters(self) -> None:
        with self._fold_condition:
            self._fold_count += 1
            self._fold_condition.notify_all()
        sweeper = self._sweeper
        if sweeper is not None:
            sweeper.wake()  # a state, a claim or a payload changed: the next deadline may be sooner

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

    def _on_digest(self, sender, body: bytes, relayed: bool) -> bool:
        """Answers the seed's anti-entropy round (SPEC §5.3; owner decision 2026-11-23: a dial-only
        peer answers its seed's DIGEST). The seed's round names its text digest of each space it
        holds; this peer answers, in one PULL_RESP addressed to the seed, the states and claims of the
        spaces it holds that the digest does not name, as Java's ``GossipBus`` answers a pull. A
        rumor of this peer's own that was lost on its only link (a write, a renewal, a completion,
        a claim) is so repaired at the seed's next round, where before it was lost for good unless
        this peer wrote the entry again.

        Only the seed's own text round is answered: an unrelayed DIGEST from the seed whose body is
        a ``Bodies.Digest`` with no field of the hashed round or of annex I.6, which a member sends
        only toward a card advertising them, and this client advertises neither. Anything else
        returns False, and the caller ignores and counts the frame as before. Returns True when the
        DIGEST was the seed's round, whether or not anything was missing."""
        if relayed or not isinstance(sender, str) or sender != self.seed_peer:
            return False
        digest = records.decode(body, "Bodies.Digest")
        if digest is None or not isinstance(digest.get("digests"), dict) \
                or any(digest.get(field) is not None for field in DIGEST_FIELDS_NOT_SPOKEN):
            return False
        deltas: dict[str, bytes] = {}
        room = MAX_PULL_RESP_DELTA_BYTES
        for stream, remote in digest["digests"].items():
            if room <= 0:
                break
            if not isinstance(stream, str) or not stream.startswith("space:") or not isinstance(remote, bytes):
                continue  # ads, view and revocations: this peer serves none of them to its seed
            delta = self.space_delta_for(stream[len("space:"):], remote, room)
            if delta:
                deltas[stream] = delta
                room -= len(delta)
        if deltas:
            self.pulls_answered += 1
            self._send("PULL_RESP", cbor.dumps({"deltas": cbor.canonical_map(deltas)}), to=sender)
        return True

    def space_delta_for(self, space: str, remote_digest: bytes, room: int = MAX_PULL_RESP_DELTA_BYTES) -> bytes:
        """Java's ``ReplicatedSpace.deltaFor``: the encoded ``SyncDelta`` of the states and claims of
        ``space`` this replica holds and the remote text digest names neither as held (``e:``/``c:``)
        nor as acknowledged (``a:``), or empty bytes when nothing is missing. A state goes as its
        signed copy (``_signed_state``), since a join carries no signature anyone made. Tombstones
        this replica would collect are collected first, so it never offers one. Present states go
        first, newest first, then the claims; states and claims past ``room`` encoded bytes together
        are left for the next round, so the answer never passes the frame bound (an oversized frame
        would make the seed drop the link, and every round would drop it again)."""
        from .identity import space_id_local
        space_id = space_id_local(f"{self.group}/{space}")
        self._collect_if_due()
        remote = set(remote_digest.decode("utf-8", "replace").split("\n"))
        with self._state_lock:
            held = [(entry_id, dto) for entry_id, dto in list(self.states.items())
                    if (dto.get("record") or {}).get("spaceId") == space_id]
            claims = [(entry_id, signed) for entry_id, signed in list(self.claims.items())
                      if signed["claim"].get("spaceId") == space_id]
        held.sort(key=lambda item: _stamp_key(item[1].get("leaseStamp")), reverse=True)
        held.sort(key=lambda item: not present(item[1]))
        states: list = []
        size = 0
        for entry_id, dto in held:
            line = f"e:{entry_id}={self._state_hash(entry_id, dto)}"
            if line in remote or f"a:{line}" in remote:
                continue
            signed = self._signed_state(entry_id, dto)
            cost = len(cbor.dumps(signed))
            if size + cost > room:
                break
            states.append(signed)
            size += cost
        missing: dict = {}
        for entry_id, signed in claims:
            line = f"c:{entry_id}={digests.claim_hash(signed['claim'])}"
            if line not in remote and f"a:{line}" not in remote:
                cost = len(entry_id) + len(cbor.dumps(signed))
                if size + cost > room:
                    break  # the claims count against the room too: the rest goes in the next round
                missing[entry_id] = signed
                size += cost
        if not states and not missing:
            return b""
        return cbor.dumps({"states": states, "claims": cbor.canonical_map(missing)})

    def _signed_state(self, entry_id: str, dto: dict) -> dict:
        """The signed state to forward for a held state: the state itself, or, for a join neither
        input equals, its most advanced signed input."""
        joined = self._signed_states.get(entry_id)
        return joined[1] if joined is not None and joined[0] is dto else dto

    def _note_joined(self, entry_id: str, previous: dict, incoming: dict, merged: dict) -> None:
        """Keeps the signed copy of a join (``_signed_state``): the incoming state when the join
        equals it, the held state's own signed copy when the join equals that, else the more
        advanced of the two (completed, then more removes, then the later lease stamp, then more
        adds), as the TypeScript client keeps it. The join's fields mix two inputs, so the held
        state's signature does not cover it."""
        held = self._signed_state(entry_id, previous)
        if _same_state(merged, incoming):
            signed = incoming
        elif _same_state(merged, previous):
            signed = held
        else:
            signed = incoming if _advances_state(incoming, held) else held
        self._signed_states[entry_id] = (merged, signed)

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

    def value_of(self, dto: dict, fetch: bool = True) -> tuple:
        """``(True, value)`` with the value an entry's payload holds, or ``(False, None)``
        while the payload is on its way (``payload_of``) or when its bytes are outside the
        wire encoding. The record signature covers those bytes, so such an entry still
        replicates, and every read skips its value (HLC round six, 2026-11-08, owner ruling
        F3). With ``fetch`` False a payload held nowhere here starts no transfer: the event of
        an entry that arrived completed is raised from what the replica holds alone (SPEC
        §7.2, completed on arrival)."""
        raw = self.payload_of(dto, fetch)
        if raw is None:
            return False, None
        try:
            return True, cbor.loads(raw)
        except ValueError:
            return False, None

    def payload_of(self, dto: dict, fetch: bool = True) -> bytes | None:
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
                if self.pdt is None or (not fetch and not self.pdt.store.complete(ref)):
                    return None
                return self.pdt.payload(ref)
            if self.content is None:
                return None
            data = self.content.local(ref)
            if data is None and fetch:
                self.content.ensure(ref)
            return data
        data = self.blocks.get(ref)
        if data is None and fetch:
            self.want_block(ref, dto)
        return data

    def want_block(self, cid: str, dto: dict | None = None) -> None:
        """Asks the entry's issuing peer (and the seed) for a block, at most once a second."""
        now = self.time.monotonic()
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
        now = self._now_ms()
        if held and _ad_expires_ms(held) <= now:
            self._hinted_since.pop(ad["issuer"], None)  # it left the view meanwhile: a new stay starts
        self.members[ad["issuer"]] = ad
        self._note_stay(ad["issuer"], ad, now)
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
                frame = self._read_exact(length)
                self._frame_started = self.time.monotonic()
                try:
                    self._receive(frame)
                finally:
                    self._frame_done()
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

    def _frame_done(self) -> None:
        """Ends the timing of the frame in hand: one held the reader longer than SLOW_FRAME_S is
        counted under its kind, since every PING behind it waited as long (WD-8)."""
        took = self.time.monotonic() - self._frame_started
        if took > SLOW_FRAME_S:
            kind = self._frame_kind or "?"
            self.slow_frames[kind] = self.slow_frames.get(kind, 0) + 1
        self._frame_started = 0.0
        self._frame_kind = ""
        self._frame_wedge_named = False

    def _receive(self, frame: bytes) -> None:
        """One frame off the connection: decoded, verified, filtered and handled, or dropped
        and counted as malformed. No frame raises out of here, so one hostile frame cannot
        kill the reader (ASF-015)."""
        with self._link_lock:  # any frame at all shows the seed still reads and writes the link
            asked = self._link_asked_at
            self._heard_at, self._link_asked_at = self.time.monotonic(), None
        if asked is not None:
            self._link_answered()
        try:
            decoded = wire.decode_frame_detailed(frame, attested=self._attested)
            env = decoded[0] if decoded is not None else None
            if env is None:
                self.malformed_frames += 1
            elif self._accepts(env):
                if decoded[1] == "attested":
                    self.attested_frames += 1
                self._frame_kind = str(env.get("kind"))
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
            self._bytes_at = self.time.monotonic()  # the seed is writing: an asked link is answered
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
                self._via_seed = self._seed
                self.resource_hints["relay.via"] = sender
                self.introduce()
            if not relayed and self._seed is not None and env.get("to") == self.identity.peer_id \
                    and self.seed_peer == sender:
                self._seed_confirmed_on = self._socket
        if kind == "DIGEST" and self._on_digest(sender, body, relayed):
            return
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
            # Answered at once, to the prober (SPEC v0.1.36 §5.2), as Java answers
            # send(group, from, ACK) and the Rust peer does: addressed, and back through the seed
            # when the PING came inside a RELAY_FRAME (a prober with a relay path to this peer).
            # An unaddressed ACK reached only the seed, which never asked, so every such probe
            # failed its direct stage and cost the prober an indirect round.
            ack = wire.ack_body(decoded["nonce"])
            if relayed and isinstance(sender, str):
                self.send_addressed("ACK", ack, sender)
            else:
                self._send("ACK", ack, to=sender if isinstance(sender, str) else None)
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
                self._collect_if_due()
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
            self._collect_if_due()
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
            if decoded.get("remainder") is not None:
                self._continue_pulls(decoded["remainder"])

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
        if self._displaced_own and not dto.get("completed"):
            self._stale_offered(dto)
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
            self._acknowledge_state(dto, record)
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
            self._acknowledge_state(dto, record)
            return
        # SPEC §7.3 (v0.1.35): the door refuses a state a lagging partner offers once it is past
        # its collection horizon here, so a collected tombstone never returns, and acknowledges
        # the refusal for five minutes when this replica holds no state of the entry, so the
        # partner reads the line as held and stops offering it while its own horizon is later.
        self._observe_state_lease(dto)
        now = self._now_ms()
        if self.collectable_here(dto, now, self.horizon_rule(now)):
            self.collected_reoffers_refused += 1
            if entry_id not in self.states:
                self._acknowledge(record.get("spaceId"), f"e:{entry_id}={digests.state_hash(dto)}",
                                  now + COLLECTED_ACK_HOLD_MILLIS)
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
            if previous is not None:
                self._note_joined(entry_id, previous, dto, merged)
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

    # ------------------------------------------------- the collection horizon (SPEC §7.3)

    def max_lease_of(self, space_id: str) -> int:
        """The longest lease observed in a space, the measure of its horizons (SPEC §7.3)."""
        return self.max_lease.get(space_id, 0)

    def _observe_lease(self, space_id, granted_millis: int) -> None:
        """Raises the longest lease of a space to ``granted_millis``, capped at
        MAX_TRACKED_LEASE_MILLIS; a lease that is not positive records nothing."""
        if not isinstance(space_id, str) or granted_millis <= 0:
            return
        granted = min(int(granted_millis), horizon.MAX_TRACKED_LEASE_MILLIS)
        if granted > self.max_lease.get(space_id, 0):
            self.max_lease[space_id] = granted

    def _observe_state_lease(self, dto: dict) -> None:
        """Records the lease a state grants, from its lease stamp to its expiry."""
        try:
            granted = horizon.lease_expiry(dto) - wire.hlc_physical(dto.get("leaseStamp"))
        except (TypeError, ValueError):
            return
        self._observe_lease((dto.get("record") or {}).get("spaceId"), granted)

    def _note_stay(self, peer_id: str, ad: dict, now: int) -> None:
        """Keeps since when a member has been a hinted member of the view in its current stay (the
        writer's half of SPEC §7.3): it starts the first time the member is seen in view with
        ``wire.horizon=1``, and ends when its advertisement lapses or stops carrying the hint."""
        if ad and _ad_expires_ms(ad) > now and (ad.get("resourceHints") or {}).get(HINT_HORIZON) == "1":
            self._hinted_since.setdefault(peer_id, now)
        else:
            self._hinted_since.pop(peer_id, None)

    def view_advertises_horizon(self, now: int | None = None) -> bool:
        """Whether this peer and every member of its view advertise ``wire.horizon=1`` (SPEC §7.3).
        The view is the member table, as the AppCard gate reads it: a member counts from its
        first frame or advertisement and leaves when its advertisement lapses, and one heard from
        whose advertisement has not arrived counts as lacking the hint. A lone peer judges by its
        own setting."""
        if not self.horizon_hint:
            return False
        now = self._now_ms() if now is None else now
        hinted = True
        for peer_id, ad in list(self.members.items()):
            self._note_stay(peer_id, ad, now)
            if not ad:
                hinted = False
            elif _ad_expires_ms(ad) > now and (ad.get("resourceHints") or {}).get(HINT_HORIZON) != "1":
                hinted = False
        return hinted

    def set_horizon_engage_rounds(self, rounds: int) -> None:
        """Sets the rounds the view must stay fully hinted before the per-entry horizon engages
        (RE-Q-REL-09), from HORIZON_ENGAGE_ROUNDS_FLOOR to HORIZON_ENGAGE_ROUNDS_CEILING."""
        if not HORIZON_ENGAGE_ROUNDS_FLOOR <= rounds <= HORIZON_ENGAGE_ROUNDS_CEILING:
            raise ValueError(f"horizon engage rounds must be from {HORIZON_ENGAGE_ROUNDS_FLOOR} to "
                             f"{HORIZON_ENGAGE_ROUNDS_CEILING}, not {rounds}")
        self.horizon_engage_rounds = rounds

    def horizon_round_millis(self) -> int:
        """One round of the per-entry horizon's hysteresis: one gossip period of the group, as Java
        counts it, read from the founding document this peer joined with, and HORIZON_ROUND_MILLIS,
        Java's default period, when it holds none. SPEC §7.3 asks for three rounds of anti-entropy
        before the rule engages again; a fixed second would cut that short in a group whose period
        is longer (the adversarial review, 2026-11-15). Safety never rests on it: the settle wait of
        one maximum lease plus the grace, and the writer's half, are what the horizon relies on."""
        from .identity import parse_duration_millis
        try:
            period = (self.founding or {})["advertisement"]["gossip"]["period"]
            return max(1, parse_duration_millis(period))
        except (KeyError, TypeError, ValueError):
            return HORIZON_ROUND_MILLIS

    def _settle_millis(self) -> int:
        """One maximum lease plus the lapse grace: the wait after engaging, and a writer's stay."""
        return max(self.max_lease.values(), default=0) + horizon.LAPSED_GRACE_MILLIS

    def horizon_rule(self, now: int | None = None) -> str:
        """Judges the collection rule this replica may apply now and moves the mode, as Java's
        ``ReplicatedSpace.horizon``: a member without the hint in view, or this peer on the legacy
        setting, disengages at once (SPEC §7.3 MUST); a fully hinted view counts one round per
        judgement at least ``horizon_round_millis`` after the last counted one and engages after
        ``horizon_engage_rounds`` of them (SETTLING); the rule comes into force one maximum lease
        plus the grace later (PER_ENTRY), so every copy a member renewed while its card lacked the
        hint has lapsed first. Called by the collection and the door. Returns ``horizon.LEGACY``
        or ``horizon.PER_ENTRY``."""
        now = self._now_ms() if now is None else now
        if not self.view_advertises_horizon(now):
            self._disengage_horizon()
            return horizon.LEGACY
        with self._horizon_lock:
            mode = self.horizon_mode
            if mode in ("LEGACY", "WAITING"):
                if self._horizon_counted_at is None or now < self._horizon_counted_at:
                    self._horizon_counted_at = now  # the first hinted judgement, or a clock that stepped back
                elif now - self._horizon_counted_at >= self.horizon_round_millis():
                    self._horizon_streak += 1
                    self._horizon_counted_at = now
                if self._horizon_streak >= self.horizon_engage_rounds:
                    self._horizon_engaged_at = now
                    mode = "SETTLING"
                    self.horizon_engagements += 1
                else:
                    mode = "WAITING"
            if mode == "SETTLING":
                if now < self._horizon_engaged_at:
                    self._horizon_engaged_at = now  # the clock stepped back: the wait counts from here
                elif now - self._horizon_engaged_at >= self._settle_millis():
                    mode = "PER_ENTRY"
                    self.horizon_settlements += 1
            self.horizon_mode = mode
        return horizon.PER_ENTRY if mode == "PER_ENTRY" else horizon.LEGACY

    def _disengage_horizon(self) -> None:
        with self._horizon_lock:
            was = self.horizon_mode
            self.horizon_mode = "LEGACY"
            self._horizon_streak = 0
            self._horizon_counted_at = None
        if was in ("SETTLING", "PER_ENTRY"):
            self.horizon_disengagements += 1
            LOG.info("a member without wire.horizon=1 is in view; withdrawals keep the legacy horizon again (was %s)",
                     was)

    def _vouches_for_writers(self, dto: dict, now: int) -> bool:
        """The writer's half of SPEC §7.3: whether every node that wrote a state (the replica of
        each add dot) is this peer, or a member of the view whose current card carries the hint
        and whose stay has lasted one maximum lease plus the grace. A state with no add dot, or
        one by a writer out of view or unhinted, is vouched for by nobody here."""
        adds = [dot for dot in dto.get("adds") or [] if isinstance(dot, dict)]
        if not adds:
            return False
        settle = self._settle_millis()
        for dot in adds:
            writer = dot.get("replica")
            if writer == self.identity.peer_id:
                continue
            ad = self.members.get(writer)
            since = self._hinted_since.get(writer)
            if (since is None or not ad or _ad_expires_ms(ad) <= now
                    or (ad.get("resourceHints") or {}).get(HINT_HORIZON) != "1" or now - since < settle):
                return False
        return True

    def collectable_here(self, dto: dict, now: int, rule: str) -> bool:
        """Whether this replica collects a state now under the rule it judged (SPEC §7.3): the
        per-entry rule applies to a withdrawal only when this replica vouches for its writers; a
        withdrawal it cannot vouch for keeps the later of the legacy and the per-entry horizons, so
        a writer leaving the view never brings a horizon closer."""
        max_lease = self.max_lease_of((dto.get("record") or {}).get("spaceId"))
        if rule == horizon.PER_ENTRY and horizon.kind_of(dto) == "withdrawn" \
                and not self._vouches_for_writers(dto, now):
            return (horizon.collectable(dto, now, max_lease, horizon.LEGACY)
                    and horizon.collectable(dto, now, max_lease, horizon.PER_ENTRY))
        return horizon.collectable(dto, now, max_lease, rule)

    def next_collection_ms(self, now: int | None = None) -> int | None:
        """When the next collection may find work (SPEC §7.3), for a sweep that waits for its
        deadlines (SPEC v0.1.36 §9.5): the earliest collection horizon of a state held here under
        the rule in force, the earliest lapse of a claim on an entry not held, and, while the
        per-entry horizon is engaging, its next round or the end of its settling wait; never sooner
        than COLLECT_PERIOD_MILLIS after the last collection. None when nothing needs collecting."""
        now = self._now_ms() if now is None else now
        due: list[int] = []
        rule = horizon.PER_ENTRY if self.horizon_mode == "PER_ENTRY" else horizon.LEGACY
        with self._state_lock:
            states = list(self.states.values())
            orphans = [signed for entry_id, signed in self.claims.items() if entry_id not in self.states]
        for dto in states:
            try:
                max_lease = self.max_lease_of((dto.get("record") or {}).get("spaceId"))
                at = horizon.collection_horizon(dto, max_lease, rule)
                if rule == horizon.PER_ENTRY and horizon.kind_of(dto) == "withdrawn" \
                        and not self._vouches_for_writers(dto, now):
                    at = max(at, horizon.collection_horizon(dto, max_lease, horizon.LEGACY))
                if horizon.kind_of(dto) == "present":
                    at = max(at, horizon.lease_expiry(dto))
            except (TypeError, ValueError):
                continue
            due.append(at)
        for signed in orphans:
            try:
                due.append(int(signed["claim"]["expiresAtMillis"]))
            except (TypeError, ValueError, KeyError):
                continue
        if states and self.horizon_mode == "LEGACY" and self.view_advertises_horizon(now):
            due.append(now + self.horizon_round_millis())  # a hinted view starts counting its rounds
        elif states and self.horizon_mode in ("WAITING", "SETTLING"):
            if self.horizon_mode == "WAITING" and self._horizon_counted_at is not None:
                due.append(self._horizon_counted_at + self.horizon_round_millis())
            elif self.horizon_mode == "SETTLING":
                due.append(self._horizon_engaged_at + self._settle_millis())
        if not due:
            return None
        earliest = min(due)
        if self._collected_at is not None and now >= self._collected_at:
            earliest = max(earliest, self._collected_at + COLLECT_PERIOD_MILLIS)
        return earliest

    def _collect_if_due(self) -> None:
        now = self._now_ms()
        if self._collected_at is None or now < self._collected_at or now - self._collected_at >= COLLECT_PERIOD_MILLIS:
            self.collect_tombstones(now)

    def collect_tombstones(self, now: int | None = None) -> list[str]:
        """Collects every state past its collection horizon (SPEC §7.3, Java's sweep): drops the
        state, its claim, a pending recordless state, a lapsed claim on an entry this replica
        does not hold, and any block or content artifact no remaining state names. Before
        v0.1.35 this client held every state it ever folded. Returns the collected entry ids."""
        now = self._now_ms() if now is None else now
        self._collected_at = now
        rule = self.horizon_rule(now)
        with self._state_lock:
            for signed in list(self.claims.values()):
                claim = signed["claim"]
                try:
                    self._observe_lease(claim.get("spaceId"),
                                        int(claim["expiresAtMillis"]) - wire.hlc_physical(claim["stamp"]))
                except (TypeError, ValueError, KeyError):
                    pass
            collected = [entry_id for entry_id, dto in list(self.states.items())
                         if self.collectable_here(dto, now, rule)]
            refs = set()
            for entry_id in collected:
                dto = self.states.pop(entry_id)
                self._state_hashes.pop(entry_id, None)
                self._signed_states.pop(entry_id, None)
                self.claims.pop(entry_id, None)
                self.pending_states.pop(entry_id, None)
                self._pending_since.pop(entry_id, None)
                self._completed_here.pop(entry_id, None)
                self._displaced_own.pop(entry_id, None)
                ref = (dto.get("record") or {}).get("payloadRef")
                if isinstance(ref, str) and ref:
                    refs.add(ref)
            for entry_id, signed in list(self.claims.items()):
                if entry_id not in self.states and now >= int(signed["claim"]["expiresAtMillis"]):
                    self.claims.pop(entry_id, None)
            if refs:
                refs -= {(dto.get("record") or {}).get("payloadRef") for dto in list(self.states.values())}
        for ref in refs:
            if ref in self.blocks:
                self.blocks.pop(ref, None)
                self._block_asked.pop(ref, None)
            elif ref[0] == "b" and not _is_tree_root(ref) and self.content is not None:
                self.content.unpin(ref)
        if collected:
            self.tombstones_collected += len(collected)
            if self.on_collected is not None:
                self.on_collected(collected)
        return collected

    # ------------------------------------------------- acknowledgements (SPEC §7.3, TECH-SPEC §7.5)

    def _acknowledge(self, space_id, line: str, forget_at: int) -> None:
        """Acknowledges a refused, verified state or claim in this replica's digests, as
        ``a:<line>``, until ``forget_at``; the most recently refused last, at most
        REFUSED_ACK_CAP per space, the least recently refused forgotten first."""
        if not isinstance(space_id, str):
            return
        acks = self._acks.setdefault(space_id, {})
        acks.pop(line, None)
        acks[line] = forget_at
        while len(acks) > REFUSED_ACK_CAP:
            del acks[next(iter(acks))]

    def _ack_lines(self, space_id: str, now: int) -> list[str]:
        """The lines a space's digest acknowledges now, each forgotten once its time passed."""
        acks = self._acks.get(space_id)
        if not acks:
            return []
        for line, until in list(acks.items()):
            if until <= now:
                acks.pop(line, None)
        return list(acks)

    def _acknowledge_state(self, dto: dict, record: dict) -> None:
        """Acknowledges a verified state refused for its stamps or its revoked actor until the
        horizon at which a holder collects it, and no sooner than five minutes after the refusal
        (annex I.6, *The audited set*)."""
        now = self._now_ms()
        space_id = record.get("spaceId")
        try:
            until = horizon.collection_horizon(dto, self.max_lease_of(space_id), horizon.LEGACY)
        except (TypeError, ValueError):
            until = 0
        self._acknowledge(space_id, f"e:{record.get('entryId')}={digests.state_hash(dto)}",
                          max(until, now + COLLECTED_ACK_HOLD_MILLIS))

    def _expire_pending_states(self, now: float | None = None) -> None:
        """Drops pending recordless states older than ``PENDING_STATE_TTL_S`` (PD-L-02)."""
        now = self.time.monotonic() if now is None else now
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
            self._pending_since[entry_id] = self.time.monotonic()
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
            # R7 of SPEC §9.2: the digest acknowledges a revoked holder's claim, until the claim's
            # lapse grace has passed and no sooner than five minutes after the refusal.
            now = self._now_ms()
            self._acknowledge(claim.get("spaceId"), f"c:{entry_id}={digests.claim_hash(claim)}",
                              max(int(expires) + horizon.LAPSED_GRACE_MILLIS, now + COLLECTED_ACK_HOLD_MILLIS))
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
        previous = self.claims.get(entry_id)
        self.claims[entry_id] = wire.merge_claims(previous, signed)
        if previous is not None and self._completed_here:
            self._note_displaced(entry_id, self.claims[entry_id], previous)
        self._observe_lease(claim.get("spaceId"), int(expires) - stamped)  # a hold counts as a lease (SPEC §7.3)
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
        out in full, since a competing claim may fold at its end.

        Only a live claim wins (SPEC §7.4), and in a quiet space the claim is judged
        after the whole settle window and a follow-up wait of up to
        ``min(settle, 300 ms)``, so ``lease_millis`` must exceed
        ``take_judged_within_millis(settle)`` (900 ms for the default 0.6 s window).
        A take whose lease cannot outlast that raises ValueError at once. Leave a
        margin above the bound: a busy interpreter wakes the take late."""
        from .identity import space_id_local
        # A lease no longer than the window and the follow-up wait has always lapsed when the take
        # judges it, so such a take could only publish doomed claims, each holding the entry from
        # other takers for its lease, and come back empty at its timeout as if it had lost every race
        # (2026-11-15; Java and TypeScript refuse the same).
        judged_within = take_judged_within_millis(round(settle_seconds * 1000))
        if not lease_millis > judged_within:
            raise ValueError(
                f"a take lease of {lease_millis} ms cannot outlast its settle window of "
                f"{round(settle_seconds * 1000)} ms and follow-up wait: the claim would lapse "
                f"before the take is judged (the lease must exceed {judged_within} ms)")
        holder = agent.agent_id if agent is not None else self.identity.agent(agent_name)
        if self.revocations.refuses(holder, agent.public_raw if agent else None, None):
            return None  # a revoked agent takes nothing, even locally
        space_id = space_id_local(f"{self.group}/{space}")
        deadline = self.time.monotonic() + timeout_seconds
        while self.time.monotonic() < deadline and self._running:  # a reconnect in progress is not a reason to stop
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
                self._observe_lease(space_id, lease_millis)  # this take's hold counts as a lease (SPEC §7.3)
                self._send("RUMOR", wire.rumor_body(
                    f"space:{space}", f"c:{entry_id}:{claim['stamp']}", 6,
                    wire.claim_delta(entry_id, signed)))
                claimed = True
                self.time.sleep(settle_seconds)  # the settle window: a competing claim folds within it
                self.pull_space_paced(space, settle_seconds)
                self.await_fold(min(settle_seconds, TAKE_FOLLOW_UP_MAX_MILLIS / 1000))
                winner = self._claim_of(entry_id)
                # core cancel events, 2026-11-09: an entry completed or withdrawn during the
                # settle window is nobody's, so a cancel that folded meanwhile leaves the take empty.
                # Only a claim still live wins (SPEC §7.4), as Java's tryTakeOnce and the TypeScript
                # take judge it: a claim that lapsed during a late wake is free for any taker already,
                # so returning it would hand out an entry this peer no longer holds.
                if winner and winner.get("holder") == holder \
                        and int(winner.get("epoch")) == epoch \
                        and int(winner.get("expiresAtMillis", 0)) > self._now_ms() \
                        and present(self.states.get(entry_id) or {}):
                    return entry_id
            if not claimed:
                # Nothing to claim: sleep until a fold (an entry, a lapsed claim's
                # successor) or the end of this settle window, not a fixed 300 ms.
                self.await_fold(min(settle_seconds, deadline - self.time.monotonic()), since=seen)
        return None

    # ------------------------------------------------- the settle guarantee's second rule

    def _note_completed(self, space: str, entry_id: str, proof: dict) -> None:
        """Remembers that this peer completed an entry with its own work under ``proof`` (Java's
        ``completedHere``), so a better claim that displaces it afterwards makes this peer offer
        its claim again (SPEC v0.1.36 §7.4). Bounded at REOFFER_LINES_CAP, the oldest first."""
        claim = proof["claim"]
        with self._reoffer_lock:
            self._completed_here.pop(entry_id, None)
            self._completed_here[entry_id] = (space, str(claim["holder"]), int(claim["epoch"]))
            while len(self._completed_here) > REOFFER_LINES_CAP:
                del self._completed_here[next(iter(self._completed_here))]

    def _note_displaced(self, entry_id: str, kept: dict, lost: dict) -> None:
        """The losing side of the second rule (SPEC v0.1.36 §7.4; Java's ``noteDisplaced``): when a
        better claim displaces the claim this peer completed the entry under, the holder of the
        better claim cannot authenticate that completion, which anti-entropy now carries under the
        better claim alone. This peer offers its displaced claim again, at once and with backoff
        (``_offer_displaced``), so that holder pairs it with the completion and does not do the work
        again. A renewal by the same holder displaces nobody."""
        kept_claim, lost_claim = kept["claim"], lost["claim"]
        if kept is lost or kept_claim.get("holder") == lost_claim.get("holder"):
            return
        holder = str(lost_claim.get("holder"))
        with self._reoffer_lock:
            done = self._completed_here.get(entry_id)
            if (done is None or done[1] != holder or done[2] != int(lost_claim.get("epoch", -1))
                    or entry_id in self._displaced_own):
                return
            self._displaced_own[entry_id] = [lost, 0, self.time.monotonic(), done[0]]
            while len(self._displaced_own) > REOFFER_LINES_CAP:
                del self._displaced_own[next(iter(self._displaced_own))]
        self._offer_displaced()

    def _stale_offered(self, dto: dict) -> None:
        """A state that shows an entry present, received while this peer's completion of it waits
        as displaced: the replica it came from has not heard of the completion, so the displaced
        claim is offered again once its backoff has passed (Java's ``staleOffered``)."""
        entry_id = (dto.get("record") or {}).get("entryId") or dto.get("entryId")
        line = self._displaced_own.get(entry_id) if isinstance(entry_id, str) else None
        if line is not None and self.time.monotonic() >= line[2]:
            self._offer_displaced()

    def _offer_displaced(self) -> None:
        """Offers again each displaced claim that is due, as a claim delta, and moves its next offer
        back: no sooner than 1 s, 2 s, 4 s and so on after the previous one, REOFFER_MAX offers in all.
        A line goes when its offers are spent, its claim lapsed, its stamp is half the drift ceiling
        old (past which a replica holding the better claim refuses it as a far-past contest), or
        this replica no longer holds the entry. Each offer travels under an item id of its own, since
        a seed that forwarded the first would drop a copy under the same id unread.

        The backoff is a local period, judged on the monotonic clock (owner decision 2026-11-23), so
        a wall step neither fires every offer at once nor holds them back; the claim's expiry and
        stamp, which another peer wrote, stay judged on the wall clock."""
        now = self._now_ms()
        mono = self.time.monotonic()
        due = []
        with self._reoffer_lock:
            for entry_id, line in list(self._displaced_own.items()):
                signed, offers, next_ms, space = line
                claim = signed["claim"]
                try:
                    old = now - wire.hlc_physical(claim["stamp"]) > wire.MAX_HLC_SKEW_MILLIS // 2
                except (TypeError, ValueError):
                    old = True
                if (offers >= REOFFER_MAX or int(claim["expiresAtMillis"]) <= now or old
                        or entry_id not in self.states):
                    del self._displaced_own[entry_id]
                elif mono >= next_ms:
                    line[1] = offers + 1
                    line[2] = mono + (REOFFER_BACKOFF_MS << offers) / 1000
                    due.append((space, entry_id, signed, offers))
        for space, entry_id, signed, offers in due:
            self.displaced_reoffers += 1
            self._send("RUMOR", wire.rumor_body(
                f"space:{space}", f"c:{entry_id}:reoffer:{offers}:{now}", 6, wire.claim_delta(entry_id, signed)))

    def require_held(self, entry_id: str, agent=None, holder: str | None = None, epoch: int | None = None) -> None:
        """Raises ValueError unless this replica's live claim on the entry is still the
        taker's: ``holder`` and ``epoch`` when given (the take's own claim), else the
        agent's, else one of this peer's agents. SPEC §7.4, the settle guarantee
        (2026-11-15): a claim can reach a taker later than its settle window, so a take
        that won its window can be displaced by an earlier claim before it completes,
        and a holder that learns of a better claim MUST NOT complete. Java's
        ``complete`` and the TypeScript ``requireHeld`` refuse the same."""
        claim = self._claim_of(entry_id)
        expected = holder if holder is not None else (agent.agent_id if agent is not None else None)
        held = claim is not None and int(claim.get("expiresAtMillis", 0)) > self._now_ms()
        if held and expected is not None:
            held = claim.get("holder") == expected
        elif held:
            held = str(claim.get("holder")).startswith(self.identity.peer_id + "/")
        if held and epoch is not None:
            held = int(claim.get("epoch", 0)) == epoch
        if not held:
            raise ValueError(f"{entry_id} is not held here: the take lapsed, or a better claim displaced it")

    def complete_entry(self, space: str, entry_id: str, agent=None, holder: str | None = None,
                       epoch: int | None = None) -> None:
        """Completes a held entry: publishes its state with the monotone
        completed flag set, re-signed by the holder and carrying our winning
        claim, so honest replicas can authenticate the completion (SPEC §11a).
        A completion the holder did not sign is rejected. A claim taken as an
        agent (``take_entry(agent=...)``) must be completed as that agent, whose
        signed state is what receivers require (A6, v0.1.13). An entry this replica
        holds completed or withdrawn is held by nobody, as Java's ``complete``
        refuses it (core cancel events, 2026-11-09), and so is one whose claim
        lapsed or lost to a better claim that arrived after the settle window
        (``require_held``; ``holder`` and ``epoch`` name the take's own claim)."""
        with self._state_lock:
            dto = dict(self.states[entry_id])
            if not present(dto):
                raise ValueError(f"{entry_id} is not held here: it is completed or withdrawn")
            self.require_held(entry_id, agent=agent, holder=holder, epoch=epoch)
            dto["completed"] = True
            dto = wire.sign_state(dto, self.identity, agent, self._now_ms())
            self.states[entry_id] = dto
        proof = self.claims.get(entry_id)
        if proof is not None:
            self._note_completed(space, entry_id, proof)
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"d:{entry_id}", 6,
            cbor.dumps({"state": dto,
                        "claimEntry": entry_id if proof else None,
                        "claim": proof})))


    def renew_entry(self, space: str, entry_id: str, lease_millis: int = 600_000,
                    agent=None) -> bool:
        """Renews this peer's write of an entry (SPEC §7.2, v0.1.35): the lease runs at least
        ``lease_millis`` from now and never shorter than it already does, ``max(current, now +
        extension)``, under a later lease stamp re-signed by the issuer, as the agent when it
        wrote as one. Three conditions guard it, and a renewal that fails one raises ValueError,
        changes nothing and sends nothing: only the issuer renews (``agent`` must be the record's
        issuer, and without one the issuer must be one of this peer's agent names), and the entry
        must be present here, neither completed nor withdrawn, with its lease not lapsed. A
        renewal whose extension ends before the current expiry leaves the lease as it is, sends
        nothing and returns False; True when the lease moved. A caller that wants a shorter lease
        cancels and writes again."""
        with self._state_lock:
            previous = self.states.get(entry_id)
            if previous is None:
                raise ValueError(f"{entry_id} is not held here")
            dto = dict(previous)
            record = dto.get("record") or {}
            issuer = str(record.get("issuer"))
            if agent is not None and agent.agent_id != issuer:
                raise ValueError(f"{entry_id} was written by {issuer}, not {agent.agent_id}")
            if agent is None and not issuer.startswith(self.identity.peer_id + "/"):
                raise ValueError(f"{entry_id} was written by {issuer}, not by this peer")
            now_ms = self._now_ms()
            current = horizon.lease_expiry(dto)
            if not present(dto) or current <= now_ms:
                raise ValueError(f"{entry_id} cannot be renewed: it is completed, withdrawn or lapsed here")
            expiry = horizon.renewed_expiry(current, now_ms, lease_millis)
            if expiry == current:
                return False  # the lease already runs that long, and a renewal never shortens it
            dto["leaseStamp"] = wire.hlc_now(record.get("issuer"), now_ms)
            dto["leaseValue"] = {"holder": record.get("issuer"), "expiresAtMillis": expiry, "kind": "WRITE"}
            dto = wire.sign_state(dto, self.identity, agent, now_ms)
            self.states[entry_id] = dto
        self._observe_state_lease(dto)
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"r:{entry_id}:{now_ms}", 6,
            cbor.dumps({"state": dto, "claimEntry": None, "claim": None})))
        return True

    def renew_take(self, space: str, entry_id: str, lease_millis: int, agent=None,
                   holder: str | None = None, epoch: int | None = None) -> bool:
        """Renews the take lease of a held entry, as Java's ``TakenEntry.renew`` (SPEC §7.2 and
        §7.4, v0.1.35): the same claim (entry, space, epoch, stamp, holder and bid) with a later
        expiry, ``max(current, now + extension)``, signed by the holder, so the lattice keeps the
        holder and moves only its expiry. ``holder`` and ``epoch`` name the take's own claim (the
        agent's, or one of this peer's, without them). Raises ValueError, sending nothing, when
        that claim is no longer the live claim here or its holder is revoked; returns False,
        sending nothing, when the hold already runs that long, and True when it moved."""
        with self._state_lock:
            signed = self.claims.get(entry_id)
            current = signed["claim"] if signed else None
            now_ms = self._now_ms()
            expected = holder if holder is not None else (agent.agent_id if agent is not None else None)
            held = current is not None and int(current["expiresAtMillis"]) > now_ms
            if held and expected is not None:
                held = current["holder"] == expected
            elif held:
                held = str(current["holder"]).startswith(self.identity.peer_id + "/")
            if held and epoch is not None:
                held = int(current["epoch"]) == epoch
            if not held:
                raise ValueError(f"take lease lapsed for entry {entry_id}")
            certificate = signed.get("holderCertificate") or {}
            if self.revocations.refuses(current["holder"], certificate.get("agentPublicKey"), None):
                raise ValueError(f"take lease of entry {entry_id} cannot be renewed: {current['holder']} is revoked")
            expiry = horizon.renewed_expiry(int(current["expiresAtMillis"]), now_ms, lease_millis)
            if expiry == int(current["expiresAtMillis"]):
                return False  # the hold already runs that long, and a renewal never shortens it
            renewed = wire.take_claim(entry_id, current["spaceId"], int(current["epoch"]), current["stamp"],
                                      current["holder"], current["bid"], expiry)
            proof = wire.signed_claim(renewed, self.identity, agent)
            self.claims[entry_id] = wire.merge_claims(self.claims.get(entry_id), proof)
        self._send("RUMOR", wire.rumor_body(
            f"space:{space}", f"c:{entry_id}:renew:{now_ms}", 6, wire.claim_delta(entry_id, proof)))
        return True

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


def _stamp_key(stamp) -> tuple:
    """A stamp's place in Java's order, the least for one that is missing or not acceptable."""
    try:
        return wire.hlc_tuple(stamp)
    except (TypeError, ValueError):
        return (-1, -1, b"")


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


def _dot_keys(dots) -> set:
    return {(str(d.get("replica", "")), int(d.get("counter", 0))) for d in dots or [] if isinstance(d, dict)}


def _same_state(a: dict, b: dict) -> bool:
    """Whether two states of one entry hold the same CRDT content: dots, lease and completion."""
    return (_dot_keys(a.get("adds")) == _dot_keys(b.get("adds"))
            and _dot_keys(a.get("removes")) == _dot_keys(b.get("removes"))
            and a.get("leaseStamp") == b.get("leaseStamp") and a.get("leaseValue") == b.get("leaseValue")
            and bool(a.get("completed")) == bool(b.get("completed")))


def _advances_state(a: dict, b: dict) -> bool:
    """Whether ``a`` is at least as advanced as ``b``: completed first, then more removes, then the
    later lease stamp, then at least as many adds (the TypeScript client's ``advancesState``)."""
    if bool(a.get("completed")) != bool(b.get("completed")):
        return bool(a.get("completed"))
    removes_a, removes_b = len(_dot_keys(a.get("removes"))), len(_dot_keys(b.get("removes")))
    if removes_a != removes_b:
        return removes_a > removes_b
    try:
        stamp_a, stamp_b = wire.hlc_tuple(a.get("leaseStamp")), wire.hlc_tuple(b.get("leaseStamp"))
    except ValueError:
        stamp_a = stamp_b = None
    if stamp_a != stamp_b:
        return stamp_a > stamp_b
    return len(_dot_keys(a.get("adds"))) >= len(_dot_keys(b.get("adds")))


def _union_dots(a, b) -> list:
    """The union of two dot lists, deduplicated by (replica, counter) and
    deterministically ordered like the Java side's sorted dots."""
    seen = {}
    for dot in (a or []) + (b or []):
        if isinstance(dot, dict):
            seen[(str(dot.get("replica", "")), int(dot.get("counter", 0)))] = dot
    return [seen[key] for key in sorted(seen)]
