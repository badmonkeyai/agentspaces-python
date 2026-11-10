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

"""The protocol records this client reads from the network, and the rules P1 to P4 of the
wire encoding (HLC round six, 2026-11-08) that each one obeys.

A protocol record is a map whose keys are exactly the fields its schema names, in the
schema's declared order (P1). A field is present always (its null written as null), or
omitted when null (``?null``), or omitted when null or empty (``?empty``). Each field holds
the kind its schema names and no other (P2): no tag, no float where an integer belongs, no
integer where text or a double belongs, no text where bytes belong (P3, owner ruling F1),
and a primitive (``int``, ``long``, ``double``, ``boolean``) is never null (P4). A typed text
field holds the exact text Java prints for its value: a canonical stamp, an ``Instant`` as
``ISO_INSTANT`` prints it, a ``Duration`` as ``Duration.toString`` prints it, an agent id in
Java's ``AgentId`` grammar (R5). A map field lists its keys in the RFC 8949 order, and a set
field its elements in the order of their encodings.

``decode`` runs the receiver's procedure on one nested document: the item rules of
``cbor.loads`` (S1 to S12), the record rules here, then the canonical-bytes rule: re-encoding
what it decoded gives back exactly the bytes received (owner ruling F3). A document that
fails any step is undecodable, and the caller counts it where it counts an undecodable
carrier of its kind.

The schemas copy appendix A of the round six wire encoding definition, which Java's own
serializers generated, for the records this client decodes, and SPEC annex I's records of the
capability pipes (HLC round seven, 2026-11-08): the aggregate, semantic-discovery and Raft
frames this client reads. Two of their byte fields stay opaque here: ``SemHit.adBytes`` decodes
on the advertisement path, and a Raft ``command`` holds a ``ClaimCommand`` its own reader
decodes. This client reads no gossip-learning exchange."""

import math
import re
import unicodedata

from . import cbor, wire

SCHEMAS_TEXT = """
WireCodec.Signed { envelope: Envelope, senderPublicKey: bytes, signature: bytes }
Envelope { ver: int, group: GroupId, kind: enum Kind[PING,PING_REQ,ACK,RUMOR,DIGEST,PULL_RESP,QUERY,QUERY_HIT,BLOCK_WANT,BLOCK,PIPE_DATA,BATCH,HAVE,GRAFT,PRUNE,RELAY_FRAME,CHANNEL_HELLO,SESSION_HELLO,GROUP_AD_WANT,GROUP_AD], from: PeerId, to: PeerId, stamp: HlcTimestamp, body: bytes }
Bodies.Ping { nonce: long, root: bytes ?null, hashes: map<String,bytes> ?null, have: list<Bodies.HaveItem> ?null }
Bodies.Rumor { streamId: String, itemId: String, hopsRemaining: int, payload: bytes }
Bodies.PullResp { deltas: map<String,bytes> }
Bodies.RelayFrame { target: PeerId, frame: bytes, path: list<PeerId> ?null, hop: Integer ?null }
Bodies.HaveItem { streamId: String, hash: bytes }
BlockExchange.Want { cid: String }
BlockExchange.Block { cid: String, bytes: bytes }
PeerNode.SignedPeerAd { adBytes: bytes, publicKey: bytes, signature: bytes }
PeerNode.RelaySignal { target: PeerId, failedHop: PeerId, reason: String }
CapabilityPipes.PipeFrame { capability: String, payload: bytes }
SignedGroupAdvertisement { advertisement: GroupAdvertisement, founderPublicKey: bytes, signature: bytes }
RevocationRegistry.SignedRevocation { adBytes: bytes, publicKey: bytes, signature: bytes }
AdCache.StoredAd { adType: String, adBytes: bytes, publicKey: bytes, signature: bytes }
AdCache.Delta { ads: list<AdCache.StoredAd> }
AgentCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, agent: AgentId, description: String, goals: list<String>, consumes: list<String>, produces: list<String>, costHints: map<String,String>, spaceBindings: map<String,String>, agentPublicKey: bytes ?null, actions: list<CardAction> ?null, agentCertificate: AgentCertificate ?null, ui: UiDeclaration ?null, spill: CardSpill ?null }
AgentCard.Parts { actions: list<CardAction> ?null, ui: UiDeclaration ?null }
AppCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, kind: String, shape: String, owner: String, reads: list<String>, actions: list<String>, idpClient: String, url: String, pkg: String, version: String, views: list<String>, ui: AppCard.Ui ?null, host: AppCard.Host ?null, origin: AppCard.Origin ?null, formats: list<String> ?null, spill: CardSpill ?null }
AppCard.Ui { protocol: String, version: String, catalogIds: list<String>, agent: String, transport: String, surfaces: list<String>, components: list<UiDeclaration.Component> ?empty }
AppCard.Host { url: String, port: int, hostAgent: String, path: String, signOn: String, publishedBy: String, publishedAt: Instant, status: String }
AppCard.Origin { system: String, ref: String, version: String, attrs: map<String,String> ?null }
AppCard.Parts { reads: list<String>, actions: list<String>, views: list<String>, ui: AppCard.Ui ?null }
CardSpill { root: String, size: long, parts: list<String> }
AssetCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, asset: String, uri: String, description: String, shape: String, freshness: String, costHints: map<String,String>, access: map<String,String> }
CapabilityAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, capabilityType: String, version: String, binding: String, parameters: map<String,String>, costHints: map<String,String> }
CredentialRevocation { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, target: CredentialRevocation.Target, reason: String, effectiveFrom: Instant ?null, evidence: bytes ?null }
CredentialRevocation.Target { kind: String, agent: AgentId ?null, keyFingerprint: bytes ?null, x509Issuer: String ?null, x509Serial: String ?null, certificateFingerprint: bytes ?null, credentialHash: bytes ?null }
GroupAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, membershipPolicy: enum MembershipPolicy[OPEN,INVITE,POLICY], defaultStrategy: enum ConflictStrategyType[LEASE_RACE,AUCTION,ORDERED], gossip: GroupAdvertisement.GossipParameters }
GroupAdvertisement.GossipParameters { fanout: int, period: Duration }
ModelCard { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, name: String, version: String, tasks: list<String>, modality: String, limits: map<String,String>, licence: String, provenance: map<String,String>, evals: map<String,String>, costHints: map<String,String>, residency: map<String,String>, engine: String, servers: list<PeerId> }
PeerAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, endpoints: list<PeerAdvertisement.Endpoint>, roles: set<enum PeerRole[RENDEZVOUS,RELAY]>, resourceHints: map<String,String> }
PeerAdvertisement.Endpoint { transport: String, address: String, priority: int }
RevocationAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, revoked: PeerId, reason: String, successor: PeerId, evidence: bytes ?null }
SpaceAdvertisement { id: String, issuer: PeerId, group: GroupId, issued: Instant, ttl: Duration, spaceName: String, schemaHints: list<String>, strategy: enum ConflictStrategyType[LEASE_RACE,AUCTION,ORDERED], admission: enum Admission[GROUP,ALLOWLIST,CREDENTIAL,AUTHORIZER], replication: enum Replication[FULL,TAG_SHARDED] }
CardAction { name: String, description: String, consumes: list<String>, produces: list<String>, space: String ?null, kind: String, contract: CardAction.Contract ?null }
CardAction.Contract { pre: list<String>, post: list<String>, cost: String, methods: list<String> }
UiDeclaration { protocol: String, version: String, components: list<UiDeclaration.Component>, entries: UiDeclaration.Entries, catalogIds: list<String> }
UiDeclaration.Component { id: String, catalogId: String, component: String, entry: String, controls: list<String>, role: String }
UiDeclaration.Entries { reads: list<String>, writes: list<String> }
AgentCertificate { agent: AgentId, agentPublicKey: bytes, issued: Instant, ttl: Duration, peerSignature: bytes, encryptionPublicKey: bytes ?null }
SpaceWire.Delta { state: SpaceWire.EntryStateDto, claimEntry: EntryId, claim: SpaceWire.SignedClaim }
SpaceWire.SyncDelta { states: list<SpaceWire.EntryStateDto>, claims: map<String,SpaceWire.SignedClaim> }
SpaceWire.EntryStateDto { record: EntryRecord ?null, issuerPublicKey: bytes, adds: list<Dot>, removes: list<Dot>, leaseStamp: HlcTimestamp, leaseValue: LeaseInfo, completed: boolean, stateSig: bytes, agentCertificate: AgentCertificate ?null, stateCertificate: AgentCertificate ?null, signer: String ?null, signedAt: HlcTimestamp ?null, entryId: EntryId ?null }
SpaceWire.SignedClaim { claim: TakeClaim, holderKey: bytes, signature: bytes, holderCertificate: AgentCertificate ?null }
TakeClaim { entryId: EntryId, spaceId: SpaceId, epoch: long, stamp: HlcTimestamp, holder: AgentId, bid: double, expiresAtMillis: long }
EntryRecord { entryId: EntryId, spaceId: SpaceId, type: String, payload: bytes, payloadRef: String, issuer: AgentId, issued: HlcTimestamp, lease: LeaseInfo, tags: map<String,String>, sig: bytes, keyEpoch: Long ?null }
Dot { replica: String, counter: long }
LeaseInfo { holder: AgentId, expiresAtMillis: long, kind: enum LeaseKind[WRITE,TAKE] }
PushSumAggregate.Frame { share: PushSumAggregate.Share, extremum: PushSumAggregate.Extremum, histogram: PushSumAggregate.Histogram, roster: PushSumAggregate.Roster }
PushSumAggregate.Share { epochId: String, value: double, weight: double }
PushSumAggregate.Extremum { epochId: String, max: boolean, value: double }
PushSumAggregate.Histogram { epochId: String, lo: double, hi: double, buckets: list<double> }
PushSumAggregate.Roster { epochId: String, members: list<long> }
SemanticDiscovery.SemQuery { nonce: long, text: String, limit: int }
SemanticDiscovery.SemResponse { nonce: long, hits: list<SemanticDiscovery.SemHit> }
SemanticDiscovery.SemHit { adType: String, adBytes: bytes, publicKey: bytes, signature: bytes }
RaftMessages.Frame { requestVote: RaftMessages.RequestVote, voteReply: RaftMessages.VoteReply, appendEntries: RaftMessages.AppendEntries, appendReply: RaftMessages.AppendReply, clientSubmit: RaftMessages.ClientSubmit }
RaftMessages.RequestVote { term: long, candidate: PeerId, lastLogIndex: long, lastLogTerm: long }
RaftMessages.VoteReply { term: long, granted: boolean }
RaftMessages.AppendEntries { term: long, leader: PeerId, prevLogIndex: long, prevLogTerm: long, entries: list<RaftMessages.LogEntry>, leaderCommit: long }
RaftMessages.AppendReply { term: long, follower: PeerId, success: boolean, matchIndex: long }
RaftMessages.ClientSubmit { command: bytes }
RaftMessages.LogEntry { term: long, command: bytes }
"""

# The record each advertisement type tag of a StoredAd names, as Java's AdCache maps it.
AD_TYPES = ("PeerAdvertisement", "GroupAdvertisement", "SpaceAdvertisement", "CapabilityAdvertisement",
            "AgentCard", "AssetCard", "ModelCard", "AppCard")

_RECORD = re.compile(r"^(\S+) \{ (.*) \}$")
_PRIMITIVES = ("int", "long", "double", "boolean")
_INT_MIN, _INT_MAX = -(1 << 31), (1 << 31) - 1
_LONG_MIN, _LONG_MAX = -(1 << 63), (1 << 63) - 1


def _split_top(text: str) -> list:
    """``text`` split at each ", " outside angle and square brackets."""
    parts, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "<[":
            depth += 1
        elif char in ">]":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


def _parse_kind(text: str) -> tuple:
    """A schema kind as a tuple: ``("list", X)``, ``("set", X)``, ``("map", X)``,
    ``("enum", names)``, ``("record", name)`` or ``(name,)`` for a scalar kind."""
    if text.startswith("enum "):
        names = text[text.index("[") + 1:-1].split(",")
        return ("enum", frozenset(names))
    for container in ("list", "set"):
        if text.startswith(container + "<"):
            return (container, _parse_kind(text[len(container) + 1:-1]))
    if text.startswith("map<String,"):
        return ("map", _parse_kind(text[len("map<String,"):-1]))
    if text in _SCALARS:
        return (text,)
    return ("record", text)


def _parse(text: str) -> dict:
    """Record name to its fields, each ``(name, kind, presence)`` with presence ``always``,
    ``null`` or ``empty``."""
    schemas = {}
    for line in filter(None, (line.strip() for line in text.splitlines())):
        name, body = _RECORD.match(line).groups()
        fields = []
        for part in _split_top(body):
            field, kind = part.split(": ", 1)
            presence = "always"
            for marker in ("null", "empty"):
                if kind.endswith(" ?" + marker):
                    kind, presence = kind[:-len(marker) - 2], marker
            fields.append((field, _parse_kind(kind), presence))
        schemas[name] = fields
    return schemas


_INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{3}|[0-9]{6}|[0-9]{9}))?Z",
                      re.ASCII)
_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def is_canonical_instant(text) -> bool:
    """Whether ``text`` is an instant exactly as Java's ``DateTimeFormatter.ISO_INSTANT``
    prints it: a year from 0000 to 9999, a real date and time, and a fraction only when the
    nanoseconds are not zero, in the fewest of 3, 6 or 9 digits that hold them (HLC round six,
    2026-11-08, rule P2)."""
    match = _INSTANT.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if not 1 <= month <= 12 or not 1 <= day <= _DAYS[month - 1] + (month == 2 and leap):
        return False
    if hour > 23 or minute > 59 or second > 59:
        return False
    fraction = match.group(7)
    return fraction is None or fraction[-3:] != "000"


_DURATION = re.compile(r"PT(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)(?:\.([0-9]{1,9}))?S)?", re.ASCII)


def is_canonical_duration(text) -> bool:
    """Whether ``text`` is a non-negative duration exactly as Java's ``Duration.toString``
    prints it: ``PT0S`` for zero, else the hours, the minutes (1 to 59) and the seconds each
    when not zero, a fraction of 1 to 9 digits with no trailing zero, and no days (HLC round
    six, 2026-11-08, rule P2)."""
    match = _DURATION.fullmatch(text) if isinstance(text, str) else None
    if match is None or text == "PT":
        return False
    hours, minutes, seconds, fraction = match.groups()
    total = (int(hours or 0) * 3600 + int(minutes or 0) * 60 + int(seconds or 0)) * 10**9 \
        + int((fraction or "").ljust(9, "0") or 0)
    return text == _duration_text(total)


def _duration_text(nanos: int) -> str:
    """``Duration.toString`` of a non-negative duration of ``nanos`` nanoseconds."""
    seconds, fraction = divmod(nanos, 10**9)
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    text = "PT" + (f"{hours}H" if hours else "") + (f"{minutes}M" if minutes else "")
    if seconds == 0 and fraction == 0 and len(text) > 2:
        return text
    return text + str(seconds) + (("." + f"{fraction:09d}".rstrip("0")) if fraction else "") + "S"


def _integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value) -> bool:
    return isinstance(value, str)


def _id(value) -> bool:
    return isinstance(value, str) and value != ""


# Scalar kinds: what each accepts once it is present and not null.
_SCALARS = {
    "int": lambda v: _integer(v) and _INT_MIN <= v <= _INT_MAX,
    "Integer": lambda v: _integer(v) and _INT_MIN <= v <= _INT_MAX,
    "long": lambda v: _integer(v) and _LONG_MIN <= v <= _LONG_MAX,
    "Long": lambda v: _integer(v) and _LONG_MIN <= v <= _LONG_MAX,
    # A double field is a float64, whatever its value, as Java reads one; a Float32 is an
    # application value (rule P2; HLC round seven, 2026-11-08).
    "double": lambda v: type(v) is float,
    "boolean": lambda v: isinstance(v, bool),
    "String": _text,
    "bytes": lambda v: isinstance(v, bytes),
    "PeerId": _id,
    "GroupId": _id,
    "SpaceId": _id,
    "EntryId": _id,
    "AgentId": lambda v: wire.is_agent_id(v),
    "HlcTimestamp": lambda v: wire.parse_hlc(v) is not None,
    "Instant": is_canonical_instant,
    "Duration": is_canonical_duration,
}

SCHEMAS = _parse(SCHEMAS_TEXT)


def _none_of(value: dict, *fields) -> bool:
    return all(value[field] is not None for field in fields)


# What the constructor of each Java record refuses beyond its fields' kinds: a null where the
# record requires a value, a counter or expiry that is not positive, a payload in both places
# or in neither. Java's codec refuses such a carrier as it decodes it, whoever signed it, so
# this client refuses it as undecodable too (HLC round six, 2026-11-08, reference rule and
# owner ruling F1). TakeClaim refuses a bid that is not finite.
_INVARIANTS = {
    "Envelope": lambda v: _none_of(v, "group", "kind", "from", "stamp", "body"),
    "EntryRecord": lambda v: (_none_of(v, "entryId", "spaceId", "type", "issuer", "issued", "lease", "tags")
                              and (v["payload"] is None) != (v["payloadRef"] is None)
                              and (v["payload"] is None or len(v["payload"]) <= wire.INLINE_PAYLOAD_LIMIT)
                              and (v.get("keyEpoch") is None or v["keyEpoch"] >= 1)),
    "LeaseInfo": lambda v: _none_of(v, "holder", "kind") and v["expiresAtMillis"] > 0,
    "Dot": lambda v: v["replica"] is not None and v["counter"] > 0,
    "TakeClaim": lambda v: (_none_of(v, "entryId", "spaceId", "stamp", "holder") and v["epoch"] >= 1
                            and math.isfinite(v["bid"])),
    "AgentCertificate": lambda v: (_none_of(v, "agent", "agentPublicKey", "issued", "ttl") and v["ttl"] != "PT0S"
                                   and (v.get("encryptionPublicKey") is None
                                        or len(v["encryptionPublicKey"]) == 32)),
}
# Every Java advertisement requires its id, issuer, group, issue instant and period.
_INVARIANTS.update({name: lambda v: _none_of(v, "id", "issuer", "group", "issued", "ttl")
                    for name in AD_TYPES + ("RevocationAdvertisement", "CredentialRevocation")})


# ------------------------------------------------- the AppCard and the card spill
#
# SPEC §6.1a.2 to §6.1a.5 and §6.1b (v0.1.32; AppCard origin and formats, 2026-11-09): what the
# constructors of Java's AppCard, its Ui, Host, Origin and Parts, CardSpill, and the AgentCard's
# spill refuse, so a card Java refuses at decode is undecodable here too. The closed values (kind,
# shape, ui.transport, ui.components[].role, host.signOn, host.status, the names in spill.parts)
# meet SPEC §6.1b's rule for unknown values; origin and formats are open and meet only their
# grammar. Lengths count UTF-16 code units, as Java's do.

def _units(text: str) -> int:
    """The length of ``text`` in UTF-16 code units."""
    return len(text) + sum(1 for char in text if ord(char) > 0xFFFF)


def _blank(text) -> bool:
    """Java's ``String.isBlank``: empty, or only code points ``Character.isWhitespace`` names."""
    return all(_java_whitespace(char) for char in text)


def _java_whitespace(char: str) -> bool:
    if char in "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f":
        return True
    return unicodedata.category(char) in ("Zs", "Zl", "Zp") and char not in "\u00a0\u2007\u202f"


def _has_control(text: str) -> bool:
    """A control character: U+0000 to U+001F, or U+007F."""
    return any(ord(char) <= 0x1F or ord(char) == 0x7F for char in text)


# A control character or a code unit of the Unicode White_Space property, as Java's
# AppCard.hasWhitespaceOrControl lists them.
_WHITESPACE_OR_CONTROL = re.compile("[\x00-\x20\x7f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*")
_SYSTEM = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?")
_KEY_TAIL = re.compile(r"[a-z0-9.-]+")


def formats_hold(formats: list) -> bool:
    """FR-3: 1 to MAX_FORMATS distinct entries, each a lower-case media type without a
    parameter or a vocabulary IRI with a scheme and no whitespace or control character."""
    if not 1 <= len(formats) <= wire.APP_CARD_MAX_FORMATS or len(set(formats)) != len(formats):
        return False
    for entry in formats:
        if not 1 <= _units(entry) <= wire.APP_CARD_MAX_FORMAT_LENGTH:
            return False
        scheme, colon, _rest = entry.partition(":")
        if not colon:
            if not _MEDIA_TYPE.fullmatch(entry):
                return False
        elif not _SCHEME.fullmatch(scheme) or _WHITESPACE_OR_CONTROL.search(entry):
            return False
    return True


def _origin_holds(v: dict) -> bool:
    """FR-2: the system's grammar, the ref's and version's bounds, and 1 to 8 attributes keyed
    under the system."""
    system, ref, version, attrs = v["system"], v["ref"], v["version"], v.get("attrs")
    if system is None or ref is None or version is None or not _SYSTEM.fullmatch(system):
        return False
    if not 1 <= _units(ref) <= 256 or _has_control(ref) or _units(version) > 64 or _has_control(version):
        return False
    if attrs is None:
        return True
    prefix = system + "."
    return 1 <= len(attrs) <= 8 and all(
        len(key) <= 128 and key.startswith(prefix) and _KEY_TAIL.fullmatch(key[len(prefix):])
        and _units(value) <= 256 and not _has_control(value) for key, value in attrs.items())


def _is_content_root(text) -> bool:
    """Whether ``text`` is a content root as ``spill.root`` holds it: ``b``, then the lower-case
    base32 (RFC 4648, no padding, zero pad bits) of a CIDv1 with codec raw and a sha2-256
    multihash, 59 characters in all (SPEC §6.1a.5)."""
    from .pdt import cids  # imported here: the pdt package reads records
    return cids.is_cid(text) and cids.codec_of(text) == cids.RAW


def _spill_holds(v: dict) -> bool:
    """CardSpill: a content root, a size of 1 to 2^53 - 1, and one or more distinct parts."""
    parts = v["parts"]
    return (_is_content_root(v["root"]) and 1 <= v["size"] <= wire.CARD_SPILL_MAX_SIZE
            and parts is not None and len(parts) > 0 and len(set(parts)) == len(parts))


def _parts_within(parts: list, spill_set: tuple) -> bool:
    """FR-14: every name in the kind's spill set, in the set's field order."""
    at = [spill_set.index(part) if part in spill_set else -1 for part in parts]
    return all(index >= 0 for index in at) and all(a < b for a, b in zip(at, at[1:]))


def _terms_hold(*lists) -> bool:
    return all(terms is not None and len(terms) <= wire.APP_CARD_MAX_TERMS for terms in lists)


def _app_card_holds(v: dict) -> bool:
    if not _none_of(v, "id", "issuer", "group", "issued", "ttl", "name", "owner", "idpClient", "url", "pkg",
                    "version") or _blank(v["name"]) or _blank(v["version"]):
        return False
    if v["kind"] not in wire.APP_CARD_KINDS or v["shape"] not in wire.APP_CARD_SHAPES:
        return False
    if not _terms_hold(v["reads"], v["actions"], v["views"]):
        return False
    formats, spill, ui = v.get("formats"), v.get("spill"), v.get("ui")
    if formats is not None and not formats_hold(formats):
        return False
    if spill is not None and (not _parts_within(spill["parts"], wire.APP_CARD_SPILL_SET)
                              or v["reads"] or v["actions"] or v["views"] or ui is not None):
        return False
    return not (v["shape"] == "a2ui" and ui is None and (spill is None or "ui" not in spill["parts"]))


def _app_card_ui_holds(v: dict) -> bool:
    return (v["protocol"] is not None and not _blank(v["protocol"]) and v["version"] is not None
            and not _blank(v["version"]) and v["agent"] is not None and v["transport"] in wire.APP_CARD_TRANSPORTS
            and _terms_hold(v["catalogIds"], v["surfaces"])
            and len(v.get("components") or []) <= wire.UI_MAX_COMPONENTS)


def _app_card_host_holds(v: dict) -> bool:
    return (v["url"] is not None and not _blank(v["url"]) and 0 <= v["port"] <= 65535
            and _none_of(v, "hostAgent", "path", "publishedBy", "publishedAt") and not _blank(v["path"])
            and v["signOn"] in wire.APP_CARD_SIGN_ONS and v["status"] in wire.APP_CARD_STATUSES)


def _agent_card_holds(v: dict) -> bool:
    spill = v.get("spill")
    return _none_of(v, "id", "issuer", "group", "issued", "ttl") and (
        spill is None or (_parts_within(spill["parts"], wire.AGENT_CARD_SPILL_SET)
                          and v.get("actions") is None and v.get("ui") is None))


_INVARIANTS.update({
    "AppCard": _app_card_holds,
    "AppCard.Ui": _app_card_ui_holds,
    "AppCard.Host": _app_card_host_holds,
    "AppCard.Origin": _origin_holds,
    "AppCard.Parts": lambda v: _terms_hold(v["reads"], v["actions"], v["views"]),
    "AgentCard": _agent_card_holds,
    "CardSpill": _spill_holds,
    "UiDeclaration.Component": lambda v: v["role"] in wire.UI_ROLES,
})


def _holds(kind: tuple, value) -> bool:
    """Whether a present, non-null ``value`` holds ``kind``."""
    tag = kind[0]
    if tag == "record":
        return conforms(value, kind[1])
    if tag == "enum":
        return isinstance(value, str) and value in kind[1]
    if tag == "list":
        return isinstance(value, list) and all(item is not None and _holds(kind[1], item) for item in value)
    if tag == "set":
        if not (isinstance(value, list) and all(item is not None and _holds(kind[1], item) for item in value)):
            return False
        encoded = [(len(raw), raw) for raw in map(cbor.dumps, value)]
        return all(a < b for a, b in zip(encoded, encoded[1:]))
    if tag == "map":
        return (isinstance(value, dict) and cbor.is_canonical_map(value)
                and all(item is not None and _holds(kind[1], item) for item in value.values()))
    return _SCALARS[tag](value)


def conforms(value, name: str) -> bool:
    """Whether a decoded ``value`` is the protocol record ``name`` under rules P1 to P4:
    exactly the schema's fields in its order, each present as its presence rule says and of
    its kind, and the record one Java's constructor holds (``_INVARIANTS``)."""
    if not isinstance(value, dict):
        return False
    keys = iter(value)
    key = next(keys, None)
    for field, kind, presence in SCHEMAS[name]:
        if key != field:
            if presence == "always":
                return False
            continue
        item = value[field]
        if item is None:
            if presence != "always" or kind[0] in _PRIMITIVES:
                return False
        elif not _holds(kind, item) or (presence == "empty" and item == []):
            return False
        key = next(keys, None)
    return key is None and (name not in _INVARIANTS or _INVARIANTS[name](value))


def load_canonical(raw):
    """The value the bytes ``raw`` hold when they are one item in the wire encoding that
    re-encodes to exactly those bytes, else None (HLC round six, 2026-11-08, owner ruling
    F3)."""
    if not isinstance(raw, bytes):
        return None
    try:
        value = cbor.loads(raw)
    except ValueError:
        return None
    return value if cbor.dumps(value) == raw else None


def decode(raw, name: str):
    """The record ``name`` that the bytes ``raw`` hold, or None when they hold no such record
    in the wire encoding: an item rule, a record rule, or the canonical-bytes rule fails (HLC
    round six, 2026-11-08, owner rulings F1 and F3)."""
    value = load_canonical(raw)
    return value if value is not None and conforms(value, name) else None
