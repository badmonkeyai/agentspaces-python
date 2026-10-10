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

from . import cbor, wire
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

    # ------------------------------------------------------------- lifecycle

    def connect(self, host: str, port: int) -> None:
        """Dials the seed and introduces this peer to the group."""
        self._socket = socket.create_connection((host, port), timeout=10)
        self._socket.settimeout(None)
        self._running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.introduce()
        self.pull_revocations()

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
                                     instant_iso(now_ms - now_ms % 1000))
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
        entry_id, body = wire.entry_delta(space, self.group, type_name, payload,
                                          self.identity, agent_name, lease_millis,
                                          agent=agent, now_ms=self._now_ms(), tags=tags)
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
        self._send("DIGEST", wire.digest_body(
            {f"space:{space}": b"", **{stream: b"" for stream in revocations.STREAMS}}))

    def pull_revocations(self) -> None:
        """Anti-entropy pull of the revocation streams alone (SPEC §5.6): sent
        once on joining, so revocations issued before this peer arrived apply
        from its first merge."""
        self._send("DIGEST", wire.digest_body({stream: b"" for stream in revocations.STREAMS}))

    def pull_ads(self) -> None:
        """Anti-entropy pull of the 'ads' stream (SPEC §6.2): the cards and
        capability advertisements the group holds."""
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

    def send_pipe(self, to: str, capability: str, payload: bytes) -> None:
        """One capability frame to a member (CapabilityPipes.send): a
        PIPE_DATA envelope addressed to it carrying {capability, payload}."""
        self._send("PIPE_DATA", cbor.dumps({"capability": capability, "payload": payload}), to=to)

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
                results.append(cbor.loads(record.get("payload") or b"\xf6"))
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
                # The remote closed; leases and gossip absorb our absence.
                self._running = False
                self._socket = None

    def _read_loop(self) -> None:
        try:
            while self._running:
                header = self._read_exact(4)
                length = struct.unpack(">i", header)[0]
                if length <= 0 or length > wire.MAX_FRAME_BYTES:
                    # Corrupt or hostile prefix: the stream cannot be
                    # resynchronized (ASF-016). Drop the connection.
                    raise OSError(f"bad frame length {length}")
                frame = self._read_exact(length)
                try:
                    env = wire.decode_frame(frame)
                    if self._accepts(env):
                        self._handle(env)
                except Exception:  # noqa: BLE001 - one hostile frame must not
                    pass  # kill the reader (ASF-015); the frame is dropped
        except OSError:
            pass  # the socket closed; the fleet's leases handle the rest

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
            chunk = self._socket.recv(count - len(data))
            if not chunk:
                raise OSError("connection closed")
            data += chunk
        return data

    def _handle(self, env: dict) -> None:
        wire.hlc_observe(self.identity.peer_id, env.get("stamp"), self._now_ms())
        kind = env.get("kind")
        body = env.get("body") or b""
        sender = env.get("from")
        if isinstance(sender, str) and sender != self.identity.peer_id:
            # A verified frame is a member heard from (the frame's signer), and
            # one our socket reaches.
            self.members.setdefault(sender, {})
            self.reachable.add(sender)
        if kind == "PING":
            ping = cbor.loads(body)
            self._send("ACK", wire.ack_body(ping.get("nonce", 0)))
        elif kind == "PIPE_DATA":
            frame = cbor.loads(body)
            handler = self.pipe_handlers.get(frame.get("capability")) if isinstance(frame, dict) else None
            if handler is not None:
                handler(sender, frame.get("payload") or b"")
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
        payload, and 0.0 under LEASE_RACE."""
        from .identity import space_id_local
        holder = agent.agent_id if agent is not None else self.identity.agent(agent_name)
        if self.revocations.refuses(holder, agent.public_raw if agent else None, None):
            return None  # a revoked agent takes nothing, even locally
        space_id = space_id_local(f"{self.group}/{space}")
        deadline = time.time() + timeout_seconds
        while time.time() < deadline and self.connected:
            self.pull_space(space)
            time.sleep(0.3)
            now_ms = self._now_ms()
            for entry_id, dto in list(self._available(type_name, now_ms)):
                record = dto.get("record") or {}
                if record.get("spaceId") != space_id:
                    continue  # the same type in another space is not this take's
                payload = cbor.loads(record.get("payload") or b"\xf6")
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
                time.sleep(settle_seconds)
                self.pull_space(space)
                time.sleep(0.3)
                winner = self._claim_of(entry_id)
                if winner and winner.get("holder") == holder \
                        and int(winner.get("epoch")) == epoch:
                    return entry_id
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
