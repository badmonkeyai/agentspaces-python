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
joins a Java fleet over TCP in the dial-only posture, stays a live member by
answering PINGs and re-leasing its self-advertisement, writes signed entries
into a replicated space, and reads the space back through anti-entropy by
offering an empty digest and folding the returned states. A peer that holds
only a GroupID and a seed endpoint joins by asking the seed for the founding
document (GROUP_AD_WANT / GROUP_AD, spec §5.1, §9, §10.1) and verifying the
answer against the id it already holds. The point is protocol validation:
nothing on this wire is Java-specific, and this module holds the proof."""

import socket
import struct
import threading
import time

from . import beacon, cbor, social, wire
from .identity import (Identity, derive_id, instant_iso, verify_agent_certificate_at,
                       verify_signed_group_ad)
from . import revocation as revocations


class Peer:
    """One Python peer attached to one group through one seed connection."""

    def __init__(self, identity: Identity, group: str, clock=None, founder: str | None = None):
        self.identity = identity
        self.group = group
        self._socket = None
        self._lock = threading.Lock()
        self._reader = None
        self.states = {}  # entryId -> decoded EntryStateDto dict
        self.claims = {}  # entryId -> winning SignedClaim dict (lattice merge)
        # Seconds since the epoch; a test pins it to verify time-bound material
        # (agent certificates) against a fixed instant, as Java's TestClock does.
        self.clock = clock or time.time
        self.on_state = None  # optional callback(dto)
        self.on_claim = None  # optional callback(entry_id, signed_claim) after a claim folds
        # Layer 4 (SPEC §6, §8): the members heard from, the advertisements
        # the 'ads' stream carried, and the capability frames handlers.
        self.members: dict[str, dict] = {}   # peer id -> its PeerAdvertisement (or {} when only heard)
        # The members a frame of ours can reach: those that signed a frame that
        # arrived on our connection. A dial-only peer has one socket, so a
        # member learned only from the peers stream (another dial-only peer
        # behind the same seed) is not among them, and an addressed frame to
        # it would be dropped by the seed rather than relayed.
        self.reachable: set[str] = set()
        self.ads: dict[str, dict] = {}       # ad id -> {"type", "ad", "stored", "issuer"}
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
        self.ignored_kinds: dict[str, int] = {}
        self.malformed_frames = 0
        # A lost socket is reconnected to the seed and the peer re-introduced and re-pulled,
        # every reconnect_interval_s for reconnect_window_s; a close() by the owner is final.
        self._seed = None
        # The seeds connect_any was given, dialed in order and failed over across on a
        # lost socket (SRAD DB-X-01); a bootstrap also sets _refresh_seeds, which
        # re-fetches the beacon document when the window would expire with nothing
        # reachable (SRAD §7.7).
        self._seeds: list = []
        self._refresh_seeds = None
        # The resource hints this peer's self-advertisement carries (SPEC §5.1): a join
        # credential under ``aspace:join`` for an INVITE group, set by join_invite.
        self.resource_hints: dict[str, str] = {}
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
        self.reconnect_interval_s = 5.0
        self.reconnect_window_s = 600.0
        self.reconnects = 0
        # Fold-driven waits (JS-V-02): a take, a read, or an ordered take waits on the
        # next fold (a state or a claim) rather than polling, and pulls a space at most
        # once per settle window.
        self._fold_condition = threading.Condition()
        self._fold_count = 0
        self._last_pull: dict[str, float] = {}  # space name -> monotonic seconds of the last pull

    # ------------------------------------------------------------- lifecycle

    def connect(self, host: str, port: int) -> None:
        """Dials the seed and introduces this peer to the group."""
        self._seed = (host, port)
        self._socket = socket.create_connection((host, port), timeout=10)
        self._socket.settimeout(None)
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
        for host, port in expanded:
            try:
                self.connect(host, port)
                return (host, port)
            except OSError as e:
                last = e
        raise OSError(f"no seed accepted: {expanded}") from last

    @staticmethod
    def _expand_seeds(seeds) -> list:
        expanded = []
        for host, port in seeds:
            addresses = []
            try:
                for info in socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM):
                    addresses.append((info[4][0], int(port)))
            except (OSError, ValueError):
                addresses = [(host, int(port))]
            for address in addresses or [(host, int(port))]:
                if address not in expanded:
                    expanded.append(address)
        return expanded

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
        one first) until the window runs out, then introduces this peer again and pulls
        what it had pulled before, so a network hiccup costs a few seconds rather than
        the membership (ROBUSTNESS.md §3.6). A bootstrapped peer re-fetches the beacon
        document once when the window would expire with nothing reachable."""
        deadline = time.monotonic() + self.reconnect_window_s
        refreshed = False
        while self._running:
            if time.monotonic() >= deadline:
                if refreshed or self._refresh_seeds is None:
                    return False
                refreshed = True
                try:
                    seeds = self._expand_seeds(self._refresh_seeds())
                except Exception:  # noqa: BLE001 - the beacon is unreachable too: give up
                    return False
                if not seeds:
                    return False
                self._seeds = seeds
                deadline = time.monotonic() + self.reconnect_window_s
            for seed in self._candidate_seeds():
                if not self._running:
                    return False
                try:
                    fresh = socket.create_connection(seed, timeout=10)
                    fresh.settimeout(None)
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
            time.sleep(self.reconnect_interval_s)
        return False

    def bootstrap(self, url: str, *, group_id: str | None = None, allow_plain: bool = False,
                  beacon_peer: str | None = None, timeout: float = 3.0) -> dict:
        """Joins through a beacon document (SRAD DB-X-01): fetches and verifies the
        document at ``url`` (https unless ``allow_plain``; signed by ``beacon_peer`` when
        pinned), selects the group (by ``group_id``, else the only one), verifies its
        founding advertisement with the four checks of SPEC §5.1 against ``group_id``
        when given, and dials its ``tcp`` seeds in priority order with ``connect_any``.
        Returns the verified SignedGroupAdvertisement, kept on ``peer.founding``."""
        doc = beacon.fetch_beacon_document(url, allow_plain=allow_plain, beacon_peer=beacon_peer,
                                           timeout=timeout)
        group = beacon.group_from_document(doc, group_id=group_id)
        founding = self._adopt_founding(group, group_id)
        seeds = beacon.seeds_of(group)
        if not seeds:
            raise ValueError(f"the beacon document names no tcp seed for {group.get('name')!r}")

        def refresh():
            fresh = beacon.fetch_beacon_document(url, allow_plain=allow_plain,
                                                 beacon_peer=beacon_peer, timeout=timeout)
            return beacon.seeds_of(beacon.group_from_document(fresh, group_id=self.group))
        self._refresh_seeds = refresh
        self.connect_any(seeds)
        return founding

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
            raise ValueError(f"the beacon document names no tcp seed for {group.get('name')!r}")

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
                         timeout: float = 10.0) -> dict:
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
        self._seed = (host, port)
        self._socket = socket.create_connection((host, port), timeout=10)
        self._socket.settimeout(None)
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

    # ------------------------------------------------------------- protocol

    def introduce(self) -> None:
        """Publishes this peer's leased self-advertisement (spec §5.2)."""
        now_ms = self._now_ms()
        # Whole seconds, as the advertisement has always been stamped.
        ad = wire.peer_advertisement(self.group, self.identity,
                                     instant_iso(now_ms - now_ms % 1000),
                                     resource_hints=self.resource_hints)
        payload = wire.signed_peer_ad(ad, self.identity)
        item_id = f"peer:{self.identity.peer_id}:{now_ms}"
        self._send("RUMOR", wire.rumor_body("peers", item_id, 6, payload))

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

    def publish_ad(self, ad_type: str, ad: dict) -> None:
        """Publishes an advertisement this peer issued (an AgentCard, an
        AssetCard) on the 'ads' stream, as DiscoveryService.publish does: the
        stored form, under the advertisement's id and issue time."""
        from .identity import parse_instant_millis
        stored = wire.stored_ad(ad_type, ad, self.identity)
        self.accept_ad(stored)  # our own cache holds it too, as DiscoveryService.publish does
        item_id = f"{ad['id']}:{parse_instant_millis(ad['issued'])}"
        self._send("RUMOR", wire.rumor_body("ads", item_id, 6, cbor.dumps(stored)))

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
        """Admits a StoredAd as AdCache.accept does: the signature over the
        canonical bytes under the carried key, the issuer derived from that
        key, and the TTL not yet passed. Returns the cached entry, or None."""
        from .identity import derive_id, parse_duration_millis, parse_instant_millis
        if not isinstance(stored, dict):
            return None
        ad_bytes, key, signature = stored.get("adBytes"), stored.get("publicKey"), stored.get("signature")
        if not (isinstance(ad_bytes, bytes) and isinstance(key, bytes) and isinstance(signature, bytes)):
            return None
        if not Identity.verify(key, ad_bytes, signature):
            return None
        try:
            ad = cbor.loads(ad_bytes)
            if not isinstance(ad, dict) or ad.get("issuer") != derive_id(key):
                return None
            expires = parse_instant_millis(ad["issued"]) + parse_duration_millis(ad["ttl"])
        except (KeyError, ValueError, TypeError):
            return None
        if expires <= self._now_ms():
            return None
        entry = {"type": stored.get("adType"), "ad": ad, "stored": stored, "issuer": ad["issuer"],
                 "expires": expires}
        previous = self.ads.get(ad["id"])
        if previous is None or parse_instant_millis(previous["ad"]["issued"]) <= parse_instant_millis(ad["issued"]):
            self.ads[ad["id"]] = entry
        return self.ads[ad["id"]]

    def cards(self) -> list[dict]:
        """The live AgentCards the ads stream carried."""
        now = self._now_ms()
        return [e["ad"] for e in self.ads.values() if e["type"] == "AgentCard" and e["expires"] > now]

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
        kept under its issuer when the signature and the derivation hold."""
        from .identity import derive_id
        try:
            signed = cbor.loads(payload)
            ad_bytes, key, signature = signed["adBytes"], signed["publicKey"], signed["signature"]
            if not Identity.verify(key, ad_bytes, signature):
                return
            ad = cbor.loads(ad_bytes)
            if isinstance(ad, dict) and ad.get("issuer") == derive_id(key) and ad["issuer"] != self.identity.peer_id:
                self.members[ad["issuer"]] = ad
        except (KeyError, TypeError, ValueError):
            return

    def find(self, type_name: str):
        """Returns decoded values of known live entries of one schema type."""
        results = []
        for dto in self.states.values():
            record = dto.get("record") or {}
            if record.get("type") == type_name and not dto.get("completed"):
                payload = self.payload_of(dto)
                if payload is not None:
                    results.append(cbor.loads(payload))
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
                try:
                    env = wire.decode_frame(frame)
                    if env is None:
                        self.malformed_frames += 1
                    elif self._accepts(env):
                        self._handle(env)
                except Exception:  # noqa: BLE001 - one hostile frame must not
                    self.malformed_frames += 1  # kill the reader (ASF-015); the frame is dropped
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
        kind = env.get("kind")
        body = env.get("body") or b""
        sender = env.get("from")
        if isinstance(sender, str) and sender != self.identity.peer_id:
            # A verified frame is a member heard from (the frame's signer), and
            # one our socket reaches; a frame a relay carried for its origin
            # says nothing about reaching that origin.
            self.members.setdefault(sender, {})
            if not relayed:
                self.reachable.add(sender)
            if not relayed and self._seed is not None and env.get("to") == self.identity.peer_id \
                    and self.seed_peer != sender:
                # Over our one socket an addressed frame is the seed's own; it is the relay
                # we declare, so members behind other seeds reach us through it (SPEC §5.4).
                self.seed_peer = sender
                self.resource_hints["relay.via"] = sender
                self.introduce()
        if kind == "PING":
            ping = cbor.loads(body)
            self._send("ACK", wire.ack_body(ping.get("nonce", 0)))
        elif kind == "PIPE_DATA":
            frame = cbor.loads(body)
            if isinstance(frame, dict) and frame.get("capability") == wire.RELAY_SIGNAL_CAPABILITY:
                signal = cbor.loads(frame.get("payload") or b"\xf6")
                if isinstance(signal, dict):
                    self.relay_signals.append(signal)
                    del self.relay_signals[:-64]
                return
            handler = self.pipe_handlers.get(frame.get("capability")) if isinstance(frame, dict) else None
            if handler is not None:
                handler(sender, frame.get("payload") or b"")
        elif kind == "RELAY_FRAME":
            relay = cbor.loads(body)
            if not isinstance(relay, dict) or relay.get("target") != self.identity.peer_id:
                return  # a dial-only peer forwards nothing: it holds no connection to forward on
            inner = wire.decode_frame(relay.get("frame") or b"")
            if inner is not None and inner.get("kind") != "RELAY_FRAME" and self._accepts(inner):
                self._handle(inner, relayed=True)
        elif kind == "BLOCK_WANT":
            want = cbor.loads(body)
            data = self.blocks.get(want.get("cid")) if isinstance(want, dict) else None
            if data is not None:
                self.send_addressed("BLOCK", wire.block_body(want["cid"], data), sender)
        elif kind == "BLOCK":
            block = cbor.loads(body)
            if isinstance(block, dict) and isinstance(block.get("bytes"), bytes) \
                    and block.get("cid") in self._block_asked and wire.block_cid(block["bytes"]) == block["cid"]:
                self.blocks[block["cid"]] = block["bytes"]
                self._wake_fold_waiters()
        elif kind == wire.KIND_GROUP_AD:
            self._on_group_ad(body)
        elif kind == "RUMOR":
            rumor = cbor.loads(body)
            if isinstance(rumor, dict) and rumor.get("streamId") in revocations.STREAMS:
                self.revocations.accept(rumor["streamId"], rumor.get("payload"), self._now_ms())
            elif isinstance(rumor, dict) and rumor.get("streamId") == "peers":
                self._accept_peer_ad(rumor.get("payload") or b"")
            elif isinstance(rumor, dict) and rumor.get("streamId") == "ads":
                self.accept_ad(cbor.loads(rumor.get("payload") or b"\xf6"))
            elif isinstance(rumor, dict) and str(
                    rumor.get("streamId", "")).startswith("space:"):
                delta = cbor.loads(rumor.get("payload") or b"\xf6")
                if isinstance(delta, dict):
                    # Claim before state: a completion authenticates against the
                    # holder's claim, which must be folded first.
                    if delta.get("claimEntry") and isinstance(delta.get("claim"), dict):
                        self._fold_claim(delta["claimEntry"], delta["claim"])
                    if isinstance(delta.get("state"), dict):
                        self._fold(delta["state"])
        elif kind == "PULL_RESP":
            resp = cbor.loads(body)
            for stream, delta_bytes in (resp.get("deltas") or {}).items():
                if stream in revocations.STREAMS and delta_bytes:
                    for signed in cbor.loads(delta_bytes) or []:
                        self.revocations.accept_signed(stream, signed, self._now_ms())
                    continue
                if stream == "ads" and delta_bytes:
                    delta = cbor.loads(delta_bytes)
                    for stored in (delta.get("ads") or []) if isinstance(delta, dict) else []:
                        self.accept_ad(stored)
                    continue
                if str(stream).startswith("space:") and delta_bytes:
                    sync = cbor.loads(delta_bytes)
                    # Claims before states, as above.
                    for entry_id, signed in (sync.get("claims") or {}).items():
                        if isinstance(signed, dict):
                            self._fold_claim(entry_id, signed)
                    for dto in (sync.get("states") or []):
                        if isinstance(dto, dict):
                            self._fold(dto)
        else:
            # A kind this client does not speak (the hint-gated kinds of SPEC v0.1.17 are
            # never sent to it, but a misconfigured peer could): ignored, counted, never fatal.
            self.ignored_kinds[str(kind)] = self.ignored_kinds.get(str(kind), 0) + 1

    def _on_group_ad(self, body: bytes) -> None:
        """A GROUP_AD answer (spec §9): accepted only while a join-by-GroupID
        is pending and only when the body passes the four checks of §5.1 and
        derives to exactly the wanted group. Anything else is ignored, so a
        seed that serves a wrong or forged founding document delays the join
        and never changes what this peer joins."""
        if self._founding_ready.is_set():
            return  # already joined on a verified document
        signed = cbor.loads(body)
        if verify_signed_group_ad(signed) != self.group:
            return
        self.founding = signed
        self._founding_ready.set()

    def _fold(self, dto: dict) -> None:
        record = dto.get("record") or {}
        entry_id = record.get("entryId")
        if not entry_id or not self._verify_state(dto, record):
            return  # unauthenticated record or forged mutable state: drop it
        if self._refused_for_revocation(dto, record):
            # Authentic, but its actor is revoked here (SPEC §5.6): what is
            # already held stays as held, and this state is not merged.
            return
        # ASF-017: states JOIN, mirroring the Java CRDT — dot sets union, the
        # lease is last-writer-wins by HLC stamp, and completed is monotone.
        # A replayed early state (validly signed by its author) can therefore
        # never shrink the sets, roll back the lease, or undo a completion.
        previous = self.states.get(entry_id)
        merged = self._join(previous, dto) if previous is not None else dto
        self.states[entry_id] = merged
        if self.on_state is not None:
            self.on_state(merged)
        self._wake_fold_waiters()

    @staticmethod
    def _join(previous: dict, incoming: dict) -> dict:
        merged = dict(previous)
        merged["adds"] = _union_dots(previous.get("adds"), incoming.get("adds"))
        merged["removes"] = _union_dots(previous.get("removes"), incoming.get("removes"))
        if (wire._hlc_tuple(str(incoming.get("leaseStamp", "0:0:")))
                > wire._hlc_tuple(str(previous.get("leaseStamp", "0:0:")))):
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
        now_ms = self._now_ms()
        # The record: peer-signed, or agent-signed under a peer certificate
        # (TECH-SPEC §7.2's two-key rule, QA4 A4-7), judged at its issue stamp.
        if not wire.verify_record(record, bytes(issuer_key), dto.get("agentCertificate"), now_ms):
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
                    or not wire.verify_claim_proof(signed, now_ms)):
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
        view = cbor.dumps(wire.state_sign_view(
            record.get("spaceId"), record.get("entryId"), dto.get("adds") or [],
            dto.get("removes") or [], dto.get("leaseStamp"), dto.get("leaseValue"),
            bool(dto.get("completed")), signer, signed_at))
        if signer is not None:
            certificate = dto.get("stateCertificate")
            try:
                signed_ms = wire.hlc_physical(signed_at)
            except (TypeError, ValueError):
                return False
            return (signer == party and isinstance(certificate, dict)
                    and verify_agent_certificate_at(certificate, bytes(signer_key), party,
                                                    signed_ms, now_ms)
                    and Identity.verify(bytes(certificate["agentPublicKey"]), view, bytes(state_sig)))
        if party_attested:
            return False  # A6: an attested party's transitions must be agent-signed
        return Identity.verify(bytes(signer_key), view, bytes(state_sig))

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
        try:
            lease_ms = wire.hlc_physical(dto.get("leaseStamp"))
        except (TypeError, ValueError):
            lease_ms = None  # an unknown time: refused under any revocation
        at = self._signing_ms(dto, lease_ms)
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
        claim = signed.get("claim")
        holder_key = signed.get("holderKey")
        if not isinstance(claim, dict) or not isinstance(holder_key, bytes):
            return
        # Validate the signed bindings and numeric fields before the lattice
        # sees them: a claim transplanted under a foreign map key is dropped
        # (ASF-002), and a NaN bid cannot win every comparison by making the
        # total order lie (ASF-033).
        if claim.get("entryId") != entry_id:
            return
        epoch = claim.get("epoch")
        bid = claim.get("bid", 0.0)
        expires = claim.get("expiresAtMillis")
        if (not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0
                or not isinstance(expires, int) or isinstance(expires, bool)
                or not isinstance(bid, (int, float)) or bid != bid
                or bid in (float("inf"), float("-inf"))
                or not isinstance(claim.get("stamp"), str)):
            return
        # The proof: peer-signed, or agent-signed under a peer certificate
        # (TECH-SPEC §7.6's two-key rule, QA4 A4-7 phase 3).
        if not wire.verify_claim_proof(signed, self._now_ms()):
            return
        # SPEC §5.6 v0.1.13 (review M-1): a revoked holder takes nothing, whatever
        # the claim's stamp, since a renewal keeps it.
        certificate = signed.get("holderCertificate") or {}
        if self.revocations.refuses(claim.get("holder"), certificate.get("agentPublicKey"), None):
            return
        # ASF-004, mirroring ReplicatedSpace: bound what a remote claim may
        # assert before the lattice (where higher epochs win by design) sees it.
        current = self._claim_of(entry_id) or {}
        observed = int(current.get("epoch", 0))
        if (epoch > observed + wire.MAX_CLAIM_EPOCH_JUMP
                or expires > self._now_ms() + wire.MAX_CLAIM_HOLD_MILLIS):
            return
        self.claims[entry_id] = wire.merge_claims(self.claims.get(entry_id), signed)
        if self.on_claim is not None:
            self.on_claim(entry_id, self.claims[entry_id])
        self._wake_fold_waiters()

    # ----------------------------------------------------------- take/complete

    def _claim_of(self, entry_id: str):
        signed = self.claims.get(entry_id)
        return signed["claim"] if signed else None

    def _available(self, type_name: str, now_ms: int):
        for entry_id, dto in self.states.items():
            record = dto.get("record") or {}
            if record.get("type") != type_name or dto.get("completed"):
                continue
            lease = record.get("lease") or {}
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
                raw = self.payload_of(dto)
                if raw is None:
                    continue  # its block or artifact is still on its way
                payload = cbor.loads(raw)
                if matches is not None and not matches(payload, record.get("tags") or {}):
                    continue
                price = float(bid(payload)) if callable(bid) else float(bid)
                current = self._claim_of(entry_id)
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
                if winner and winner.get("holder") == holder \
                        and int(winner.get("epoch")) == epoch \
                        and not (self.states.get(entry_id) or {}).get("completed"):
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
        signed state is what receivers require (A6, v0.1.13)."""
        dto = dict(self.states[entry_id])
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


def _union_dots(a, b) -> list:
    """The union of two dot lists, deduplicated by (replica, counter) and
    deterministically ordered like the Java side's sorted dots."""
    seen = {}
    for dot in (a or []) + (b or []):
        if isinstance(dot, dict):
            seen[(str(dot.get("replica", "")), int(dot.get("counter", 0)))] = dot
    return [seen[key] for key in sorted(seen)]
