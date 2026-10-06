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

"""The wire protocol (spec §9) in Python: signed CBOR envelopes, the bodies
this client speaks, and the entry-record structures for space writes. Every
dict here lists its keys in the Java record's field order, because the
envelope signature covers the canonical CBOR and byte order is meaning."""

import hashlib
import threading
import time
import uuid

from . import cbor
from .identity import (Identity, derive_id, verify_agent_certificate,
                       verify_agent_certificate_at)

# The wire version every envelope carries and the only one a receiver accepts
# (SPEC §9, TECH-SPEC §3): a frame of any other version is dropped before its
# signature is checked, so versions coexist at the cost of mutual silence.
WIRE_VERSION = 2

# The join-by-GroupID bootstrap kinds (SPEC §9, v0.1.10): a GROUP_AD_WANT names
# the wanted group in the envelope and carries an empty body; a GROUP_AD
# answers with the SignedGroupAdvertisement the answering member joined with.
KIND_GROUP_AD_WANT = "GROUP_AD_WANT"
KIND_GROUP_AD = "GROUP_AD"


# Largest frame accepted or sent, mirroring the JVM transport cap: a length
# prefix beyond it is hostile or corrupt, never legitimate (ASF-016).
MAX_FRAME_BYTES = 8 * 1024 * 1024

# ASF-004 bounds, mirroring ReplicatedSpace: the largest epoch advance a remote
# claim may assert over the locally observed epoch, and the longest TAKE hold
# it may assert beyond this client's clock.
MAX_CLAIM_EPOCH_JUMP = 1 << 20
MAX_CLAIM_HOLD_MILLIS = 24 * 60 * 60 * 1000


# How far ahead of this client's wall clock a remote stamp may run before it
# is ignored rather than merged (the HLC clamp, ASF-020/043).
MAX_HLC_SKEW_MILLIS = 10 * 60 * 1000

_hlc_lock = threading.Lock()
_hlc_state: dict = {}  # node -> (physical_millis, logical)


def hlc_now(node: str, now_ms: int | None = None) -> str:
    """A fresh hybrid-logical-clock stamp in the Java string form: physical
    time never runs backwards, and the logical counter increments within one
    millisecond, so two stamps from the same node never collide and stamps
    after an observed remote stamp sort after it (ASF-043). ``now_ms`` is the
    caller's clock (a peer's, so tests are deterministic); default wall time."""
    wall = int(time.time() * 1000) if now_ms is None else int(now_ms)
    with _hlc_lock:
        physical, logical = _hlc_state.get(node, (0, -1))
        if wall > physical:
            physical, logical = wall, 0
        else:
            logical += 1
        _hlc_state[node] = (physical, logical)
    return f"{physical}:{logical}:{node}"


def hlc_physical(stamp) -> int:
    """The physical milliseconds of an HLC stamp string: its signing time."""
    return int(str(stamp).split(":", 1)[0])


def hlc_observe(node: str, stamp, now_ms: int | None = None) -> None:
    """Merges a remote stamp into the local clock so later local stamps sort
    after everything observed. Remote physicals beyond the skew ceiling are
    ignored: a hostile far-future stamp cannot pin this clock (ASF-020).
    ``now_ms`` is the caller's clock the skew is judged against (a peer's);
    default wall time."""
    try:
        parts = str(stamp).split(":", 2)
        physical, logical = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return
    wall = int(time.time() * 1000) if now_ms is None else int(now_ms)
    if physical > wall + MAX_HLC_SKEW_MILLIS:
        return
    with _hlc_lock:
        current_physical, current_logical = _hlc_state.get(node, (0, -1))
        if (physical, logical) > (current_physical, current_logical):
            _hlc_state[node] = (physical, logical)


def envelope(group: str, kind: str, sender: str, stamp: str, body: bytes,
             to: str = None) -> dict:
    """An Envelope in field order: ver, group, kind, from, to, stamp, body.

    ``to`` binds the frame to its recipient (ASF-010); None is an unaddressed
    frame (the bootstrap self-introduction). ver is WIRE_VERSION (2)."""
    return {"ver": WIRE_VERSION, "group": group, "kind": kind, "from": sender,
            "to": to, "stamp": stamp, "body": body}


def encode_frame(env: dict, identity: Identity) -> bytes:
    """Signs and encodes an envelope into a frame (WireCodec.Signed)."""
    canonical = cbor.dumps(env)
    return cbor.dumps({
        "envelope": env,
        "senderPublicKey": identity.public_raw,
        "signature": identity.sign(canonical),
    })


def decode_frame(frame: bytes):
    """Decodes and verifies a frame; returns the envelope dict or None. The
    version check runs first (SPEC §9): an envelope whose ``ver`` is not
    WIRE_VERSION is dropped before any signature work."""
    try:
        signed = cbor.loads(frame)
    except (ValueError, IndexError, UnicodeDecodeError):
        return None
    if not isinstance(signed, dict):
        return None
    env = signed.get("envelope")
    if not isinstance(env, dict):
        return None
    ver = env.get("ver")
    if not isinstance(ver, int) or isinstance(ver, bool) or ver != WIRE_VERSION:
        return None
    key = signed.get("senderPublicKey")
    signature = signed.get("signature")
    if not isinstance(key, bytes) or len(key) != 32:
        return None
    if derive_id(key) != env.get("from"):
        return None
    if not Identity.verify(key, cbor.dumps(env), signature or b""):
        return None
    return env


# ------------------------------------------------------------------ bodies

def ping_body(nonce: int) -> bytes:
    return cbor.dumps({"nonce": nonce})


def ack_body(nonce: int) -> bytes:
    return cbor.dumps({"nonce": nonce, "onBehalf": None})


def rumor_body(stream_id: str, item_id: str, hops: int, payload: bytes) -> bytes:
    return cbor.dumps({"streamId": stream_id, "itemId": item_id,
                       "hopsRemaining": hops, "payload": payload})


def digest_body(digests: dict) -> bytes:
    return cbor.dumps({"digests": digests})


# --------------------------------------------------- join by GroupID (§9)

def group_ad_want_envelope(group: str, sender: str, stamp: str,
                           to: str = None) -> dict:
    """The GROUP_AD_WANT envelope (SPEC §9, §10.1): the wanted group in
    ``group`` and an empty body. A real request travels unaddressed
    (``to`` None) because the seed's PeerID is unknown until it answers;
    the golden vector addresses it to exercise the destination binding."""
    return envelope(group, KIND_GROUP_AD_WANT, sender, stamp, b"", to=to)


def group_ad_body(signed: dict) -> bytes:
    """The GROUP_AD body: the SignedGroupAdvertisement
    {advertisement, founderPublicKey, signature} as canonical CBOR (§5.1)."""
    return cbor.dumps({"advertisement": signed["advertisement"],
                       "founderPublicKey": signed["founderPublicKey"],
                       "signature": signed["signature"]})


# ------------------------------------------------ capability payloads (§8)

def aggregate_roster_token(peer_id: str) -> int:
    """The aggregate Roster's participant token (SPEC §8 aspace:cap/aggregate):
    the first 8 bytes of sha-256(PeerID as UTF-8) read big-endian as a signed
    int64, as PushSumAggregate.tokenOf computes it. A negative token encodes
    as a CBOR negative integer, never as an unsigned 8-byte value."""
    digest = hashlib.sha256(peer_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def aggregate_frame(share: dict = None, extremum: dict = None,
                    histogram: dict = None, roster: dict = None) -> dict:
    """The aspace:cap/aggregate PIPE_DATA payload: a Frame union carrying
    exactly one of Share {epochId, value, weight}, Extremum {epochId, max,
    value}, Histogram {epochId, lo, hi, buckets}, or Roster {epochId,
    members}; the other three travel as CBOR null (§8)."""
    if sum(part is not None for part in (share, extremum, histogram, roster)) != 1:
        raise ValueError("an aggregate Frame carries exactly one variant")
    return {"share": share, "extremum": extremum, "histogram": histogram,
            "roster": roster}


def learn_content_id(encoding: bytes) -> str:
    """The gossip-learn content identifier (SPEC §8 aspace:cap/gossip-learn):
    base58btc multibase of sha-256 over the model's encoding, the same
    derivation as BlockExchange.cidOf."""
    return derive_id(encoding)


def learn_exchange(model_id: str, token: int, kind: str, round_: int,
                   inline: bytes = None, cid: str = None) -> dict:
    """The aspace:cap/gossip-learn PIPE_DATA payload, GossipLearner.Exchange
    in field order: modelId, token, kind (OFFER, ACCEPT, or BUSY), round,
    inline (the encoding when it fits the inline limit, else null), cid (the
    block-exchange CID when it does not, else null) (§8)."""
    return {"modelId": model_id, "token": int(token), "kind": kind,
            "round": int(round_), "inline": inline, "cid": cid}


def peer_advertisement(group: str, identity: Identity, issued_iso: str,
                       ttl_iso: str = "PT10M") -> dict:
    """A PeerAdvertisement with no endpoints: the dial-only NAT posture."""
    return {
        "id": f"aspace://{group}/peer/{identity.peer_id}",
        "issuer": identity.peer_id,
        "group": group,
        "issued": issued_iso,
        "ttl": ttl_iso,
        "endpoints": [],
        "roles": [],
        "resourceHints": {},
    }


def signed_peer_ad(ad: dict, identity: Identity) -> bytes:
    """The 'peers' stream payload: PeerNode.SignedPeerAd."""
    ad_bytes = cbor.dumps(ad)
    return cbor.dumps({
        "adBytes": ad_bytes,
        "publicKey": identity.public_raw,
        "signature": identity.sign(ad_bytes),
    })


# ------------------------------------------------------------- space writes

def sign_view(entry_id: str, space_id: str, type_name: str, payload: bytes,
              issuer: str, issued: str, key_epoch: int | None = None) -> dict:
    """ReplicatedSpace's SignView: the record identity the signature covers.
    ``keyEpoch`` (v0.1.13, SPEC §11a.1) is appended only for a record sealed
    under a content-key epoch from 1, so other records sign the same bytes."""
    view = {"entryId": entry_id, "spaceId": space_id, "type": type_name,
            "payload": payload, "payloadRef": None, "issuer": issuer,
            "issued": issued, "tags": {}}
    if key_epoch is not None:
        view["keyEpoch"] = key_epoch
    return view


def sign_view_of(record: dict) -> dict:
    """The SignView for an already-built record, from its own fields."""
    view = {"entryId": record.get("entryId"), "spaceId": record.get("spaceId"),
            "type": record.get("type"), "payload": record.get("payload"),
            "payloadRef": record.get("payloadRef"), "issuer": record.get("issuer"),
            "issued": record.get("issued"), "tags": record.get("tags") or {}}
    if record.get("keyEpoch") is not None:
        view["keyEpoch"] = record.get("keyEpoch")
    return view


def verify_record(record: dict, issuer_public_raw, certificate,
                  now_ms: int) -> bool:
    """TECH-SPEC §7.2's record rule, as ReplicatedSpace.verifyRecord applies
    it. ``issuer_public_raw`` must always be the 32-byte key of the record's
    issuing peer. Without a certificate the record signature verifies under
    that peer key. With one, the certificate must verify under the peer key
    for exactly this issuer, judged at the record's own issue stamp (v0.1.13:
    signing time, not receipt; ``now_ms`` bounds how far that stamp may lead),
    and the record signature must then verify under the certificate's agent
    key: a record that arrives with a certificate but a peer-key signature is
    refused."""
    if (not isinstance(issuer_public_raw, (bytes, bytearray))
            or len(issuer_public_raw) != 32):
        return False
    issuer = record.get("issuer")
    if (not isinstance(issuer, str)
            or not issuer.startswith(derive_id(bytes(issuer_public_raw)) + "/")):
        return False
    signature = record.get("sig")
    if not isinstance(signature, (bytes, bytearray)):
        return False
    view = cbor.dumps(sign_view_of(record))
    if certificate is None:
        return Identity.verify(bytes(issuer_public_raw), view, bytes(signature))
    try:
        signed_at = hlc_physical(record.get("issued"))
    except (TypeError, ValueError):
        return False
    if not verify_agent_certificate_at(certificate, bytes(issuer_public_raw),
                                       issuer, signed_at, now_ms):
        return False
    return Identity.verify(bytes(certificate["agentPublicKey"]), view, bytes(signature))


def _sorted_dots(dots: list) -> list:
    """Dots sorted by (replica, counter), matching ReplicatedSpace.sortedDots."""
    return sorted(dots, key=lambda d: (d.get("replica", ""), d.get("counter", 0)))


def state_sign_view(space_id: str, entry_id: str, adds: list, removes: list,
                    lease_stamp: str, lease_value: dict, completed: bool,
                    signer: str | None = None, signed_at: str | None = None) -> dict:
    """ReplicatedSpace's StateSignView (SPEC §11a): the mutable state the actor
    signs so a receiver can authenticate a completion, removal, or lease. Field
    order and dot sorting must match the Java record exactly. An agent-signed
    state (v0.1.13, SPEC §11a.4) appends ``signer`` and ``signedAt``; a
    peer-signed one omits them and keeps its bytes."""
    view = {"spaceId": space_id, "entryId": entry_id,
            "adds": _sorted_dots(adds), "removes": _sorted_dots(removes),
            "leaseStamp": lease_stamp, "leaseValue": lease_value,
            "completed": completed}
    if signer is not None:
        view["signer"] = signer
    if signed_at is not None:
        view["signedAt"] = signed_at
    return view


def sign_state(dto: dict, identity: Identity, agent=None, now_ms: int | None = None) -> dict:
    """Signs a state DTO's mutable fields as its actor and returns the DTO.
    With ``agent`` (an ``AgentIdentity``) the agent signs (SPEC §11a.4,
    v0.1.13): the DTO names it as ``signer``, stamps ``signedAt``, and
    carries the certificate covering that time as ``stateCertificate``; the
    peer's own transitions stay peer-signed and byte-identical to before."""
    record = dto.get("record") or {}
    signer = signed_at = certificate = None
    if agent is not None:
        signer = agent.agent_id
        signed_at = hlc_now(agent.agent_id, now_ms)
        certificate = agent.certificate_covering(hlc_physical(signed_at))
        if certificate is None:
            raise ValueError(f"{agent.agent_id} holds no certificate covering {signed_at}")
    view = state_sign_view(record.get("spaceId"), record.get("entryId"),
                           dto.get("adds") or [], dto.get("removes") or [],
                           dto.get("leaseStamp"), dto.get("leaseValue"),
                           bool(dto.get("completed")), signer, signed_at)
    signed = {key: value for key, value in dto.items()
              if key not in ("stateSig", "stateCertificate", "signer", "signedAt")}
    signed["stateSig"] = (agent or identity).sign(cbor.dumps(view))
    # EntryStateDto field order: ... stateSig, agentCertificate, stateCertificate,
    # signer, signedAt; the v0.1.13 fields are omitted when absent.
    if "agentCertificate" in signed:
        signed["agentCertificate"] = signed.pop("agentCertificate")
    if agent is not None:
        signed["stateCertificate"] = certificate
        signed["signer"] = signer
        signed["signedAt"] = signed_at
    return signed


def entry_delta(space_name: str, group: str, type_name: str, payload: bytes,
                identity: Identity, agent_name: str, lease_millis: int,
                agent=None, now_ms: int | None = None) -> tuple:
    """Builds a full write delta; returns (entry_id, rumor_body_bytes). With
    ``agent`` (an ``AgentIdentity``, v0.1.13) the record is the agent's: signed
    by its key, the certificate covering the record's stamp attached, and the
    state agent-signed, so every receiver stores it AGENT_ATTESTED."""
    from .identity import space_id_local
    entry_id = str(uuid.uuid4())
    space_id = space_id_local(f"{group}/{space_name}")
    issuer = agent.agent_id if agent is not None else identity.agent(agent_name)
    issued = hlc_now(issuer, now_ms)
    view = sign_view(entry_id, space_id, type_name, payload, issuer, issued)
    certificate = None
    if agent is not None:
        certificate = agent.certificate_covering(hlc_physical(issued))
        if certificate is None:
            raise ValueError(f"{issuer} holds no certificate covering {issued}")
    signature = (agent or identity).sign(cbor.dumps(view))
    expires = (int(time.time() * 1000) if now_ms is None else int(now_ms)) + lease_millis
    record = {
        "entryId": entry_id, "spaceId": space_id, "type": type_name,
        "payload": payload, "payloadRef": None, "issuer": issuer,
        "issued": issued,
        "lease": {"holder": issuer, "expiresAtMillis": expires, "kind": "WRITE"},
        "tags": {}, "sig": signature,
    }
    adds = [{"replica": identity.peer_id, "counter": 1}]
    lease_value = {"holder": issuer, "expiresAtMillis": expires, "kind": "WRITE"}
    dto = {
        "record": record,
        "issuerPublicKey": identity.public_raw,
        "adds": adds,
        "removes": [],
        "leaseStamp": issued,
        "leaseValue": lease_value,
        "completed": False,
    }
    if certificate is not None:
        dto["agentCertificate"] = certificate
    # The state signature: the issuer authenticates the whole mutable state so a
    # receiver can tell a real write from a forged one (SPEC §11a).
    dto = sign_state(dto, identity, agent, now_ms)
    delta = cbor.dumps({"state": dto, "claimEntry": None, "claim": None})
    return entry_id, rumor_body(f"space:{space_name}", f"w:{entry_id}", 6, delta)


# ------------------------------------------------------------- take claims

def take_claim(entry_id: str, space_id: str, epoch: int, stamp: str, holder: str,
               bid: float, expires_at_millis: int) -> dict:
    """A TakeClaim in field order: entryId, spaceId, epoch, stamp, holder, bid,
    expiresAtMillis. entryId and spaceId are signed bindings (ASF-002), so a
    signed claim cannot be transplanted onto another entry. The bid MUST be a
    float so it encodes as a CBOR double, matching Java."""
    return {"entryId": entry_id, "spaceId": space_id, "epoch": epoch,
            "stamp": stamp, "holder": holder,
            "bid": float(bid), "expiresAtMillis": expires_at_millis}


def signed_claim(claim: dict, identity: Identity, agent=None) -> dict:
    """A SignedClaim: the claim, the holder's *peer* key, the holder's signature.
    With ``agent`` (an ``AgentIdentity``) the signature is the agent key's and
    the peer's certificate covering the claim's stamp rides beside it in the
    appended ``holderCertificate`` field (QA4 A4-7 phase 3; v0.1.13 judges it at
    that stamp); without it the proof is byte-identical to before."""
    signed = {"claim": claim, "holderKey": identity.public_raw,
              "signature": (agent or identity).sign(cbor.dumps(claim))}
    if agent is not None:
        certificate = agent.certificate_covering(hlc_physical(claim["stamp"]))
        if certificate is None:
            raise ValueError(f"{agent.agent_id} holds no certificate covering {claim['stamp']}")
        signed["holderCertificate"] = certificate
    return signed


def verify_claim_proof(signed: dict, now_ms: int) -> bool:
    """TECH-SPEC §7.6's proof rule, as ReplicatedSpace.verifyClaim applies it.
    ``holderKey`` is always the holder's 32-byte peer key and must hash to the
    claim's holder peer. Without a certificate the signature verifies under
    that key; with one, the certificate must verify under the peer key for
    exactly the claim's holder at the claim's own stamp (not at ``now_ms``,
    which only bounds how far ahead that stamp may run) and the signature
    under the certificate's agent key. The entry and space bindings are the caller's."""
    from .identity import derive_id, verify_agent_certificate
    claim = signed.get("claim")
    holder_key = signed.get("holderKey")
    signature = signed.get("signature")
    if (not isinstance(claim, dict) or not isinstance(holder_key, (bytes, bytearray))
            or len(holder_key) != 32 or not isinstance(signature, (bytes, bytearray))):
        return False
    holder = claim.get("holder")
    if not isinstance(holder, str) or not holder.startswith(derive_id(bytes(holder_key)) + "/"):
        return False
    certificate = signed.get("holderCertificate")
    if certificate is None:
        return Identity.verify(bytes(holder_key), cbor.dumps(claim), bytes(signature))
    try:
        stamped = hlc_physical(claim.get("stamp"))
    except (TypeError, ValueError):
        return False
    # v0.1.13: judged at the claim's own stamp, which a renewal keeps.
    if not verify_agent_certificate_at(certificate, bytes(holder_key), holder, stamped, now_ms):
        return False
    return Identity.verify(bytes(certificate["agentPublicKey"]), cbor.dumps(claim), bytes(signature))


def agent_card(group: str, identity: Identity, local_name: str, issued_iso: str,
               ttl_iso: str, description: str, goals: list, consumes: list,
               produces: list, cost_hints: dict, space_bindings: dict,
               agent_public_raw: bytes | None = None, actions: list | None = None,
               agent_certificate: dict | None = None) -> dict:
    """An AgentCard in Java field order: id, issuer, group, issued, ttl,
    agent, description, goals, consumes, produces, costHints, spaceBindings,
    then the appended agentPublicKey, actions (v0.1.13, item 6), and
    agentCertificate (v0.1.13), each omitted when absent so earlier cards keep
    their bytes. A certificate must certify ``agent_public_raw`` for this agent."""
    agent = identity.agent(local_name)
    card = {"id": f"aspace://{group}/agent/{agent}", "issuer": identity.peer_id,
            "group": group, "issued": issued_iso, "ttl": ttl_iso, "agent": agent,
            "description": description, "goals": goals, "consumes": consumes,
            "produces": produces, "costHints": cost_hints,
            "spaceBindings": space_bindings}
    if agent_certificate is not None and (agent_public_raw is None
                                          or agent_certificate.get("agentPublicKey") != agent_public_raw
                                          or agent_certificate.get("agent") != agent):
        raise ValueError("a card's certificate must certify its agent and agentPublicKey")
    if agent_public_raw is not None:
        card["agentPublicKey"] = agent_public_raw
    if actions:
        card["actions"] = actions
    if agent_certificate is not None:
        card["agentCertificate"] = agent_certificate
    return card


def card_action(name: str, description: str, consumes: list, produces: list,
                kind: str, space: str | None = None) -> dict:
    """A CardAction in Java field order (SPEC §6.1, v0.1.13): name,
    description, consumes, produces, space (omitted when absent), kind."""
    action = {"name": name, "description": description, "consumes": consumes,
              "produces": produces}
    if space is not None:
        action["space"] = space
    action["kind"] = kind
    return action


def claim_delta(entry_id: str, signed: dict) -> bytes:
    """A claim-only Delta, as tryTakeOnce publishes it."""
    return cbor.dumps({"state": None, "claimEntry": entry_id, "claim": signed})


def _hlc_tuple(stamp: str) -> tuple:
    physical, logical, node = stamp.split(":", 2)
    return (int(physical), int(logical), node)


def claim_sort_key(claim: dict) -> tuple:
    """The claim lattice's total order (spec §7.4): the SMALLEST key wins.
    Epoch descending, bid ascending, HLC stamp ascending, holder ascending,
    expiry descending; identical to TakeClaim.merge on the Java side."""
    return (-int(claim.get("epoch", 0)), float(claim.get("bid", 0.0)),
            _hlc_tuple(claim.get("stamp", "0:0:")), claim.get("holder", ""),
            -int(claim.get("expiresAtMillis", 0)))


def merge_claims(a: dict, b: dict) -> dict:
    """Returns the winning SignedClaim of two, by the lattice order."""
    if a is None:
        return b
    if b is None:
        return a
    return a if claim_sort_key(a["claim"]) <= claim_sort_key(b["claim"]) else b
