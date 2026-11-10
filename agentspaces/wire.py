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
import math
import re
import threading
import time
import uuid

from . import cbor, records
from .identity import MAX_DRIFT_MILLIS, Identity, derive_id, is_local_name, verify_agent_certificate_covering

# The wire version every envelope carries and the only one a receiver accepts
# (SPEC §9, TECH-SPEC §3): a frame of any other version is dropped before its
# signature is checked, so versions coexist at the cost of mutual silence.
# 3 since ISSUE-CanonicalMaps: map entries sorted by key in every encoding.
WIRE_VERSION = 3

# The join-by-GroupID bootstrap kinds (SPEC §9, v0.1.10): a GROUP_AD_WANT names
# the wanted group in the envelope and carries an empty body; a GROUP_AD
# answers with the SignedGroupAdvertisement the answering member joined with.
KIND_GROUP_AD_WANT = "GROUP_AD_WANT"
KIND_GROUP_AD = "GROUP_AD"


# Largest frame accepted or sent, mirroring the JVM transport cap: a length
# prefix beyond it is hostile or corrupt, never legitimate (ASF-016).
MAX_FRAME_BYTES = 8 * 1024 * 1024
# Payloads above this travel as a block or an artifact and the record carries a reference (SPEC §7.1).
INLINE_PAYLOAD_LIMIT = 64 * 1024

# ASF-004 bounds, mirroring ReplicatedSpace: the largest epoch advance a remote
# claim may assert over the locally observed epoch, and the longest TAKE hold
# it may assert beyond this client's clock.
MAX_CLAIM_EPOCH_JUMP = 1 << 20
MAX_CLAIM_HOLD_MILLIS = 24 * 60 * 60 * 1000


# How far ahead of this client's wall clock a remote stamp may run (the HLC clamp,
# ASF-020/043): the frame filter drops a frame stamped further ahead, and the clock clamps
# a merged physical one millisecond inside it.
MAX_HLC_SKEW_MILLIS = MAX_DRIFT_MILLIS

# How far past wall + MAX_HLC_SKEW_MILLIS a frame's stamp may run before the receiver
# treats it as an attack (HLC canonical stamps, 2026-11-08, decision B). A hostile member
# can drag an honest peer's clock to its own wall + the skew, and a receiver whose wall
# runs a little behind then sees the honest frames just past its ceiling: it drops them
# and counts them apart (``far_future_skewed``), and a peer that keeps strikes strikes
# nobody for them. Further past, the frame is ``far_future`` and the sender is struck.
FAR_FUTURE_SKEW_MARGIN_MILLIS = 5_000

# How far past wall + MAX_HLC_SKEW_MILLIS + FAR_FUTURE_SKEW_MARGIN_MILLIS a folded state's
# record or lease stamp, or a folded claim's stamp, may run before the peer refuses it as
# hostile (HLC round four, 2026-11-08, decision D4). Nearer, the peer defers it: it does not
# merge it, counts it once per distinct offer (HLC round five, 2026-11-08, decision E2), and
# anti-entropy offers it again until this peer's wall catches up, so an honest taker whose
# clock a hostile stamp dragged ahead is never refused. The peer judges each offer afresh, so
# a hostile one merges too once the wall catches up (HLC round five, 2026-11-08, decision E5).
FAR_FUTURE_HOSTILE_MILLIS = 60 * 60 * 1000

# The largest logical counter a stamp may carry (HLC logical counter, 2026-11-08 (Rust team
# report)). Every merge and ordering point refuses a remote stamp above it (see
# ``acceptable_hlc``): it drops the frame, the folded state, or the folded claim that carries
# the stamp, counts the refusal, and keeps the stamp off the clock. A stamp that does not
# parse strictly never gets that far: its frame or space delta does not decode (HLC round
# four, 2026-11-08, decision D3). A local increment past the limit carries into the next millisecond. An honest
# counter stays tiny because it resets every millisecond, and Java, Rust, Python, TypeScript
# and Ruby share this value on the wire.
LOGICAL_LIMIT = 1 << 16
# HLC round seven, 2026-11-08 (SPEC §9.1, S6): a stamp is one definite text of at most this many
# UTF-16 units, and a clock's node leaves room for the longest physical part (19 digits), the
# longest logical part (10 digits) and their two colons, so every stamp it issues fits.
MAX_STAMP_UNITS = cbor.JACKSON_CHUNK_UNITS
MAX_NODE_UNITS = MAX_STAMP_UNITS - 31

# The ranges of Java's HlcTimestamp fields (long physical, int logical), which bound what
# ``parse_hlc`` reads.
_PHYSICAL_MAX = (1 << 63) - 1
_LOGICAL_MAX = (1 << 31) - 1
# A canonical number: "0", or a non-zero ASCII digit followed by ASCII digits, so each value
# has exactly one spelling (HLC canonical stamps, 2026-11-08, decision A).
_CANONICAL_NUMBER = re.compile(r"0|[1-9][0-9]*", re.ASCII)
# What a node may not hold: a colon, the control characters U+0000..U+001F and U+007F, and a
# lone surrogate U+D800..U+DFFF, which no peer can send as UTF-8 (HLC round five, 2026-11-08,
# decision E11). A decoded stamp never holds a surrogate, so the last range binds the local node.
_NODE_REFUSED = re.compile(r"[:\x00-\x1f\x7f\ud800-\udfff]")

# How far in the past a frame's stamp may be before it is dropped as stale, and how many
# (sender, stamp) pairs the replay filter remembers (ROBUSTNESS.md §3.3, §3.4; the Java
# node's MAX_FRAME_AGE_MILLIS and its recent-frames cache).
MAX_FRAME_AGE_MILLIS = 5 * 60 * 1000
FRAME_FILTER_CAPACITY = 4096


class FrameFilter:
    """Admits each verified frame once, fresh, judging its stamp in SPEC §9's order (HLC
    canonical stamps, 2026-11-08). A frame reaches it only with a stamp that decoded:
    ``decode_frame_detailed`` drops a frame whose stamp is no stamp item before it checks the
    frame's signature, and the peer counts it among its malformed frames (HLC round five,
    2026-11-08, decision E9). The filter drops a stamp older than MAX_FRAME_AGE_MILLIS
    (``stale``) and a (sender, stamp) pair it saw before (``replayed``), which anyone can
    replay. Then it judges the fresh frame only its
    sender could have signed: a stamp past wall + MAX_HLC_SKEW_MILLIS within
    FAR_FUTURE_SKEW_MARGIN_MILLIS of it (``far_future_skewed``), one further past
    (``far_future``), and one whose logical counter is above LOGICAL_LIMIT
    (``logical_refused``); the three counters carry the names of the Java node's
    framesFarFutureSkewed, framesFarFuture and framesLogicalRefused (HLC round four,
    2026-11-08, decision D5). It drops each silently and counts it: late, duplicated and
    replayed frames are the normal case on a network. This client keeps no strikes, so the
    Java node's strike reasons "far-future stamp" and "logical counter above 65536" appear
    here only as counts."""

    def __init__(self, capacity: int = FRAME_FILTER_CAPACITY):
        self._seen = {}
        self._capacity = capacity
        self.stale = 0
        self.replayed = 0
        self.far_future_skewed = 0
        self.far_future = 0
        self.logical_refused = 0

    def admit(self, env: dict, now_ms: int) -> bool:
        """Whether to handle a decoded frame; raises ValueError when its stamp does not parse,
        which a frame from ``decode_frame_detailed`` never carries."""
        stamp = env.get("stamp")
        parsed = parse_hlc(stamp)
        if parsed is None:
            raise ValueError(f"a decoded frame carries no stamp: {stamp!r}")
        physical, logical, _ = parsed
        if now_ms - physical > MAX_FRAME_AGE_MILLIS:
            self.stale += 1
            return False
        # A canonical stamp has one spelling, so its text identifies it.
        key = (env.get("from"), stamp)
        if key in self._seen:
            self.replayed += 1
            return False
        self._seen[key] = True
        if len(self._seen) > self._capacity:
            del self._seen[next(iter(self._seen))]
        ahead = physical - now_ms - MAX_HLC_SKEW_MILLIS
        if ahead > FAR_FUTURE_SKEW_MARGIN_MILLIS:
            self.far_future += 1
            return False
        if ahead > 0:
            self.far_future_skewed += 1
            return False
        if logical > LOGICAL_LIMIT:
            self.logical_refused += 1
            return False
        return True

_hlc_lock = threading.Lock()
_hlc_state: dict = {}  # node -> (physical_millis, logical)


def hlc_now(node: str, now_ms: int | None = None) -> str:
    """A fresh hybrid-logical-clock stamp in the Java string form: physical
    time never runs backwards, and the logical counter increments within one
    millisecond, so two stamps from the same node never collide and stamps
    after an observed remote stamp sort after it (ASF-043). A counter that
    would pass LOGICAL_LIMIT carries into the next millisecond instead (HLC
    logical counter, 2026-11-08 (Rust team report)), so every stamp is new and
    every peer accepts it. ``now_ms`` is the caller's clock (a peer's, so tests
    are deterministic); default wall time. A ``node`` the stamp grammar refuses (empty,
    or holding a colon, a control character or a lone surrogate) raises ValueError, so this
    peer never emits a stamp its peers refuse (HLC round four, 2026-11-08, decision D6; HLC
    round five, 2026-11-08, decision E11), and so does a node past MAX_NODE_UNITS (HLC round
    seven, 2026-11-08)."""
    if (not isinstance(node, str) or not node or _NODE_REFUSED.search(node)
            or cbor.utf16_units(node) > MAX_NODE_UNITS):
        raise ValueError(f"not a stamp node: {node!r}")
    wall = int(time.time() * 1000) if now_ms is None else int(now_ms)
    with _hlc_lock:
        physical, logical = _hlc_state.get(node, (0, -1))
        if wall > physical:
            physical, logical = wall, 0
        elif logical < LOGICAL_LIMIT:
            logical += 1
        else:
            physical, logical = physical + 1, 0
        _hlc_state[node] = (physical, logical)
    return f"{physical}:{logical}:{node}"


def parse_hlc(stamp) -> tuple | None:
    """``(physical, logical, node)`` when ``stamp`` is a string in the canonical
    ``physical:logical:node`` grammar, None otherwise (HLC canonical stamps, 2026-11-08,
    decision A). Each number is "0" or a non-zero ASCII digit followed by ASCII digits, so
    a leading zero, a sign, a fraction, an exponent, whitespace or an empty part fails;
    the physical fits a signed 64-bit integer and the logical a Java int; the node is
    present and holds no colon, no control character and no lone surrogate (HLC round five,
    2026-11-08, decision E11). An accepted stamp therefore re-encodes to exactly its text,
    so a signature over the text is a signature over the stamp. Only a plain ``str`` of at most
    3996 UTF-16 units parses: a longer text travels only in Jackson's chunks, and a stamp is one
    definite text, so no such text is a stamp, a ``pdt.issued`` included (HLC round seven,
    2026-11-08). The decoder already refuses text under a longer head than it needs, a tag over
    text and ill-formed UTF-8 (HLC round four, 2026-11-08, decision D3; HLC round five,
    2026-11-08, decisions E1 and E8; HLC round six, 2026-11-08, rule S3). This is syntax
    alone, which decides whether a stamp decodes; ``acceptable_hlc`` adds LOGICAL_LIMIT for
    every merge and ordering point."""
    if type(stamp) is not str or cbor.utf16_units(stamp) > MAX_STAMP_UNITS:
        return None
    parts = stamp.split(":", 2)
    if len(parts) != 3:
        return None
    physical, logical, node = parts
    if (not _CANONICAL_NUMBER.fullmatch(physical) or not _CANONICAL_NUMBER.fullmatch(logical)
            or not node or _NODE_REFUSED.search(node)):
        return None
    try:
        physical, logical = int(physical), int(logical)
    except ValueError:  # more digits than Python converts: far past either range
        return None
    if physical > _PHYSICAL_MAX or logical > _LOGICAL_MAX:
        return None
    return physical, logical, node


def acceptable_hlc(stamp) -> tuple | None:
    """``(physical, logical, node)`` when ``stamp`` parses strictly (``parse_hlc``) and its
    logical counter is at most LOGICAL_LIMIT, None otherwise (HLC logical counter,
    2026-11-08 (Rust team report)). Every merge and ordering point accepts a remote stamp
    only through this rule: the frame filter, the folded record, lease and signing stamps,
    the folded claim, and a ref's advisory ``pdt.issued`` (HLC round four, 2026-11-08,
    decisions D1 and D2)."""
    parsed = parse_hlc(stamp)
    return parsed if parsed is not None and parsed[1] <= LOGICAL_LIMIT else None


def is_agent_id(text) -> bool:
    """Whether ``text`` is an agent id in Java's AgentId grammar: a non-empty peer, one slash,
    and a non-empty local name that holds no slash (HLC round five, 2026-11-08, decision E3)
    and no colon, since a stamp's node holds no colon and an agent signs stamps under its id
    (HLC round six, 2026-11-08, R5)."""
    if not isinstance(text, str):
        return False
    peer, slash, local = text.partition("/")
    return bool(peer) and bool(slash) and is_local_name(local)


def decode_delta(raw) -> dict | None:
    """A space delta (``SpaceWire.Delta``, the payload of a ``space:`` rumor), or None when it
    does not decode: bytes outside the wire encoding, a field of another kind or out of its
    place (HLC round six, 2026-11-08, owner rulings F1 and F3), a stamp that is no canonical
    stamp (HLC round four, 2026-11-08, decision D3), or a claim or record Java's records
    refuse. Java's codec refuses the same deltas before any signature check, and the caller
    counts each one as undecodable (decision D5)."""
    return records.decode(raw, "SpaceWire.Delta")


def decode_sync_delta(raw) -> dict | None:
    """An anti-entropy SyncDelta (``{states, claims}``, one stream of a PULL_RESP), or None
    when it does not decode, under the rule of ``decode_delta``: one state or claim that does
    not decode drops the whole SyncDelta, as Java's codec drops it (HLC round four,
    2026-11-08, decisions D3 and D5)."""
    return records.decode(raw, "SpaceWire.SyncDelta")


def utf16_order(text: str) -> bytes:
    """A key that orders strings by UTF-16 code units, as Java's String.compareTo does
    (HLC canonical stamps, 2026-11-08): big-endian code units compare bytewise in unit
    order. Code point order differs above the surrogate range, where Java puts U+E000..U+FFFF
    after every supplementary character."""
    return text.encode("utf-16-be", "surrogatepass")


def hlc_tuple(stamp) -> tuple:
    """``(physical, logical, node key)`` of a stamp the rule accepts, ordered as Java's
    HlcTimestamp.compareTo orders it (the node by ``utf16_order``); raises ValueError on
    any other stamp. The peer admits only acceptable stamps, so ordering never meets one
    the rule refuses."""
    parsed = acceptable_hlc(stamp)
    if parsed is None:
        raise ValueError(f"not an acceptable HLC stamp: {stamp!r}")
    return parsed[0], parsed[1], utf16_order(parsed[2])


def hlc_physical(stamp) -> int:
    """The physical milliseconds of an HLC stamp string: its signing time. Raises
    ValueError on text outside the canonical grammar (``parse_hlc``). It reads the time
    alone; the merge points judge LOGICAL_LIMIT on every stamp a state or claim carries,
    its signing stamp included (HLC round four, 2026-11-08, decision D1)."""
    parsed = parse_hlc(stamp)
    if parsed is None:
        raise ValueError(f"not a canonical HLC stamp: {stamp!r}")
    return parsed[0]


def hlc_observe(node: str, stamp, now_ms: int | None = None) -> None:
    """Merges a remote stamp into the local clock so later local stamps sort
    after everything observed. The clock clamps a remote physical at
    wall + MAX_HLC_SKEW_MILLIS - 1, so a hostile far-future stamp cannot pin it
    (ASF-020), and a carry after the merge lands at most at wall + the skew,
    which a receiver's far-future check (strictly greater) still admits. A
    stamp the rule refuses (``acceptable_hlc``) never reaches the clock, so one
    hostile stamp cannot push every later local stamp past what peers accept
    (HLC logical counter, 2026-11-08 (Rust team report)). ``now_ms`` is the
    caller's clock the skew is judged against (a peer's); default wall time."""
    parsed = acceptable_hlc(stamp)
    if parsed is None:
        return
    wall = int(time.time() * 1000) if now_ms is None else int(now_ms)
    physical, logical = min(parsed[0], wall + MAX_HLC_SKEW_MILLIS - 1), parsed[1]
    with _hlc_lock:
        current_physical, current_logical = _hlc_state.get(node, (0, -1))
        if (physical, logical) > (current_physical, current_logical):
            _hlc_state[node] = (physical, logical)


def envelope(group: str, kind: str, sender: str, stamp: str, body: bytes,
             to: str = None) -> dict:
    """An Envelope in field order: ver, group, kind, from, to, stamp, body.

    ``to`` binds the frame to its recipient (ASF-010); None is an unaddressed
    frame (the bootstrap self-introduction). ver is WIRE_VERSION (3)."""
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
    """Decodes and verifies a fully signed frame; returns the envelope dict or
    None. The version check runs first (SPEC §9): an envelope whose ``ver`` is
    not WIRE_VERSION is dropped before any signature work."""
    decoded = decode_frame_detailed(frame)
    return decoded[0] if decoded is not None else None


HELLO_KINDS = ("SESSION_HELLO", "CHANNEL_HELLO")


def decode_frame_detailed(frame: bytes, attested: str | None = None):
    """``(envelope, auth)`` with auth ``"signed"`` or ``"attested"``, or None. A bare
    frame (no key, no signature) is accepted only on a connection whose transport
    attested exactly its sender (``attested``, SPEC §5.6), and a hello never travels
    bare. Mirrors Java ``WireCodec`` as the Ruby and TypeScript clients do.

    The frame decodes in the receiver's order (HLC round six, 2026-11-08, owner ruling F3):
    the item rules over its bytes, then ``ver`` (a frame of another version drops before any
    other work, so versions coexist), then the record rules of ``WireCodec.Signed`` and its
    ``Envelope``, then the canonical-bytes rule, and only then the signature, over the
    envelope's bytes, which equal its re-encoding. A frame whose stamp is no stamp item
    does not decode: it drops before any signature check, so its sender is never blamed for
    it (HLC round five, 2026-11-08, decision E9)."""
    try:
        signed = cbor.loads(frame)
    except ValueError:  # the decoder raises ValueError on every input outside the encoding
        return None
    env = signed.get("envelope") if isinstance(signed, dict) else None
    if not isinstance(env, dict) or type(env.get("ver")) is not int or env["ver"] != WIRE_VERSION:
        return None
    if not records.conforms(signed, "WireCodec.Signed") or cbor.dumps(signed) != frame:
        return None
    key = signed["senderPublicKey"]
    signature = signed["signature"]
    if key is None and signature is None:
        if env.get("kind") in HELLO_KINDS or attested is None or attested != env.get("from"):
            return None
        return env, "attested"
    if key is None or len(key) != 32 or derive_id(key) != env["from"]:
        return None
    if not Identity.verify(key, cbor.dumps(env), signature or b""):
        return None
    return env, "signed"


# The body record of each kind this client acts on (appendix A of the round six definition).
BODY_RECORDS = {
    "PING": "Bodies.Ping",
    "RUMOR": "Bodies.Rumor",
    "PULL_RESP": "Bodies.PullResp",
    "RELAY_FRAME": "Bodies.RelayFrame",
    "BLOCK_WANT": "BlockExchange.Want",
    "BLOCK": "BlockExchange.Block",
    "PIPE_DATA": "CapabilityPipes.PipeFrame",
    KIND_GROUP_AD: "SignedGroupAdvertisement",
}


def decode_body(kind: str, body: bytes) -> dict | None:
    """The body of a verified frame of ``kind`` as its record, or None when it holds no such
    record in the wire encoding (HLC round six, 2026-11-08, owner rulings F1 and F3): the
    frame is then undecodable, and the receiver drops it and counts it as malformed."""
    return records.decode(body, BODY_RECORDS[kind])


def encode_bare_frame(env: dict) -> bytes:
    """An envelope with no signature (WireCodec.encodeBare): what a node sends on a
    connection whose transport attested it, toward a peer that announced it accepts
    bare frames there, its key and signature written null as Java writes them. This
    client never sends one; tests and stand-in seeds do."""
    return cbor.dumps({"envelope": env, "senderPublicKey": None, "signature": None})


# ------------------------------------------------------------------ bodies

def ping_body(nonce: int) -> bytes:
    return cbor.dumps({"nonce": nonce})


def ack_body(nonce: int) -> bytes:
    return cbor.dumps({"nonce": nonce, "onBehalf": None})


def rumor_body(stream_id: str, item_id: str, hops: int, payload: bytes) -> bytes:
    return cbor.dumps({"streamId": stream_id, "itemId": item_id,
                       "hopsRemaining": hops, "payload": payload})


def digest_body(digests: dict) -> bytes:
    """A DIGEST body, its digests map in the canonical order a map field takes (HLC round
    six, 2026-11-08, rule P2): ``peers`` before ``space:<name>``."""
    return cbor.dumps({"digests": cbor.canonical_map(digests)})


def channel_hello_body(accepts_bare: bool, attested_remote: str) -> bytes:
    """Bodies.ChannelHello (SPEC §5.6): this peer accepts channel-attested frames on
    the connection whose remote end it attested as ``attested_remote``."""
    return cbor.dumps({"acceptsBare": accepts_bare, "attestedRemote": attested_remote})


RELAY_SIGNAL_CAPABILITY = "aspace:cap/relay-signal"


def relay_frame_body(target: str, frame: bytes, path: list | None = None, hop: int | None = None) -> bytes:
    """A RELAY_FRAME body (SPEC §5.4): the origin's complete signed frame for
    ``target``, carried by the relay the envelope is addressed to. With ``path``
    (the relays to traverse, v0.1.23) and ``hop`` (the index of the relay this
    envelope is addressed to) the frame crosses several relays; both are absent
    in the one-hop form."""
    body = {"target": target, "frame": frame}
    if path is not None:
        body["path"] = list(path)
        body["hop"] = 0 if hop is None else int(hop)
    return cbor.dumps(body)


def relay_signal_body(target: str, failed_hop: str, reason: str = "unreachable") -> bytes:
    """The PIPE_DATA body a relay sends back to an origin when the next hop of a
    path could not carry its frame (``aspace:cap/relay-signal``, SPEC §5.4)."""
    return cbor.dumps({"capability": RELAY_SIGNAL_CAPABILITY,
                       "payload": cbor.dumps({"target": target, "failedHop": failed_hop, "reason": reason})})


def block_cid(data: bytes) -> str:
    """The id of a block (SPEC §7.1): multibase base58btc of sha-256 over the bytes."""
    from .identity import multibase
    return multibase(hashlib.sha256(data).digest())


def block_want_body(cid: str) -> bytes:
    """A BLOCK_WANT body: one block by id."""
    return cbor.dumps({"cid": cid})


def block_body(cid: str, data: bytes) -> bytes:
    """A BLOCK body: the bytes under their id."""
    return cbor.dumps({"cid": cid, "bytes": data})


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
                       ttl_iso: str = "PT10M", resource_hints: dict | None = None) -> dict:
    """A PeerAdvertisement with no endpoints: the dial-only NAT posture.
    ``resource_hints`` (string to string) is where a join credential travels
    (``aspace:join``, SPEC §5.1); a signed map, so it is canonically ordered."""
    return {
        "id": f"aspace://{group}/peer/{identity.peer_id}",
        "issuer": identity.peer_id,
        "group": group,
        "issued": issued_iso,
        "ttl": ttl_iso,
        "endpoints": [],
        "roles": [],
        "resourceHints": cbor.canonical_map({str(k): str(v) for k, v in (resource_hints or {}).items()}),
    }


def stored_ad(ad_type: str, ad: dict, identity: Identity) -> dict:
    """AdCache.StoredAd, the 'ads' stream payload (SPEC §6.2): the type tag
    (``AgentCard``, ``AssetCard``, ...), the advertisement's canonical bytes,
    the issuer's key, and the issuer's signature over those bytes."""
    ad_bytes = cbor.dumps(ad)
    return {"adType": ad_type, "adBytes": ad_bytes, "publicKey": identity.public_raw,
            "signature": identity.sign(ad_bytes)}


def decode_signed_peer_ad(payload) -> dict | None:
    """The PeerAdvertisement a 'peers' stream item (PeerNode.SignedPeerAd) carries, or None
    when the item or its advertisement is outside the wire encoding or its record (HLC round
    six, 2026-11-08, owner rulings F1 and F3), the signature over the advertisement's bytes
    fails, or the key does not derive the issuer."""
    signed = records.decode(payload, "PeerNode.SignedPeerAd")
    if signed is None or None in (signed["adBytes"], signed["publicKey"], signed["signature"]):
        return None
    ad = records.decode(signed["adBytes"], "PeerAdvertisement")
    if (ad is None or len(signed["publicKey"]) != 32 or ad["issuer"] != derive_id(signed["publicKey"])
            or not Identity.verify(signed["publicKey"], signed["adBytes"], signed["signature"])):
        return None
    return ad


def signed_peer_ad(ad: dict, identity: Identity) -> bytes:
    """The 'peers' stream payload: PeerNode.SignedPeerAd."""
    ad_bytes = cbor.dumps(ad)
    return cbor.dumps({
        "adBytes": ad_bytes,
        "publicKey": identity.public_raw,
        "signature": identity.sign(ad_bytes),
    })


# ------------------------------------------------------------- space writes

def sign_view(entry_id: str, space_id: str, type_name: str, payload: bytes | None,
              issuer: str, issued: str, key_epoch: int | None = None,
              tags: dict | None = None, payload_ref: str | None = None) -> dict:
    """ReplicatedSpace's SignView: the record identity the signature covers,
    tags included (SPEC §7.1: a tag is part of the signed record, sorted on
    the wire by the canonical form). ``keyEpoch`` (v0.1.13, SPEC §11a.1) is
    appended only for a record sealed under a content-key epoch from 1, so
    other records sign the same bytes. ``payload_ref`` (SPEC §7.1) names a
    block (``z``) or a content root (``b``) when the payload travels outside the
    record; the payload is then null."""
    view = {"entryId": entry_id, "spaceId": space_id, "type": type_name,
            "payload": payload, "payloadRef": payload_ref, "issuer": issuer,
            "issued": issued, "tags": cbor.canonical_map(dict(tags or {}))}
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


def verify_record(record: dict, issuer_public_raw, certificate) -> bool:
    """TECH-SPEC §7.2's record rule, as ReplicatedSpace.verifyRecord applies
    it. ``issuer_public_raw`` must always be the 32-byte key of the record's
    issuing peer. Without a certificate the record signature verifies under
    that peer key. With one, the certificate must verify under the peer key
    for exactly this issuer, judged at the record's own issue stamp (v0.1.13:
    signing time, not receipt), and the record signature must then verify
    under the certificate's agent key: a record that arrives with a
    certificate but a peer-key signature is refused. How far the issue stamp
    may lead is the far-future rule's to judge after verification, as for a
    peer-signed record (HLC round five, 2026-11-08, decision E4)."""
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
    if not verify_agent_certificate_covering(certificate, bytes(issuer_public_raw),
                                             issuer, signed_at):
        return False
    return Identity.verify(bytes(certificate["agentPublicKey"]), view, bytes(signature))


def _sorted_dots(dots: list) -> list:
    """Dots sorted by (replica, counter) as ReplicatedSpace.sortedDots sorts them, the replica
    by UTF-16 code units as Java's String.compareTo orders it (HLC round six, 2026-11-08,
    vector delta-13): a replica holding a supplementary character sorts before one holding
    U+E000 to U+FFFF, where code point order puts it after."""
    return sorted(dots, key=lambda d: (utf16_order(d.get("replica", "")), d.get("counter", 0)))


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


def entry_delta(space_name: str, group: str, type_name: str, payload: bytes | None,
                identity: Identity, agent_name: str, lease_millis: int,
                agent=None, now_ms: int | None = None, tags: dict | None = None,
                payload_ref: str | None = None) -> tuple:
    """Builds a full write delta; returns (entry_id, rumor_body_bytes). With
    ``agent`` (an ``AgentIdentity``, v0.1.13) the record is the agent's: signed
    by its key, the certificate covering the record's stamp attached, and the
    state agent-signed, so every receiver stores it AGENT_ATTESTED."""
    from .identity import space_id_local
    entry_id = str(uuid.uuid4())
    space_id = space_id_local(f"{group}/{space_name}")
    issuer = agent.agent_id if agent is not None else identity.agent(agent_name)
    issued = hlc_now(issuer, now_ms)
    view = sign_view(entry_id, space_id, type_name, payload, issuer, issued, tags=tags,
                     payload_ref=payload_ref)
    certificate = None
    if agent is not None:
        certificate = agent.certificate_covering(hlc_physical(issued))
        if certificate is None:
            raise ValueError(f"{issuer} holds no certificate covering {issued}")
    signature = (agent or identity).sign(cbor.dumps(view))
    expires = (int(time.time() * 1000) if now_ms is None else int(now_ms)) + lease_millis
    record = {
        "entryId": entry_id, "spaceId": space_id, "type": type_name,
        "payload": payload, "payloadRef": payload_ref, "issuer": issuer,
        "issued": issued,
        "lease": {"holder": issuer, "expiresAtMillis": expires, "kind": "WRITE"},
        "tags": view["tags"], "sig": signature,
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


def canonical_claim(claim: dict) -> dict:
    """The TakeClaim a claim map stands for, its fields in the record's declared order and no
    other field: what a claim's signature covers and how it travels (HLC round five,
    2026-11-08, decision E13)."""
    return take_claim(claim.get("entryId"), claim.get("spaceId"), claim.get("epoch"),
                      claim.get("stamp"), claim.get("holder"), claim.get("bid"), claim.get("expiresAtMillis"))


def signed_claim(claim: dict, identity: Identity, agent=None) -> dict:
    """A SignedClaim: the claim, the holder's *peer* key, the holder's signature.
    With ``agent`` (an ``AgentIdentity``) the signature is the agent key's and
    the peer's certificate covering the claim's stamp rides beside it in the
    appended ``holderCertificate`` field (QA4 A4-7 phase 3; v0.1.13 judges it at
    that stamp); without it the proof is byte-identical to before. The claim is
    signed and carried in Java's field order (``canonical_claim``)."""
    claim = canonical_claim(claim)
    signed = {"claim": claim, "holderKey": identity.public_raw,
              "signature": (agent or identity).sign(cbor.dumps(claim))}
    if agent is not None:
        certificate = agent.certificate_covering(hlc_physical(claim["stamp"]))
        if certificate is None:
            raise ValueError(f"{agent.agent_id} holds no certificate covering {claim['stamp']}")
        signed["holderCertificate"] = certificate
    return signed


def verify_claim_proof(signed: dict) -> bool:
    """TECH-SPEC §7.6's proof rule, as ReplicatedSpace.verifyClaim applies it.
    ``holderKey`` is always the holder's 32-byte peer key and must hash to the
    claim's holder peer. Without a certificate the signature verifies under
    that key; with one, the certificate must verify under the peer key for
    exactly the claim's holder at the claim's own stamp and the signature
    under the certificate's agent key. Either signature covers the claim as it
    travels, a TakeClaim in Java's field order (HLC round five, 2026-11-08,
    decision E13), which a claim in any other form is not (HLC round six,
    2026-11-08, owner ruling F3). How far the stamp may lead is the far-future
    rule's to judge after verification, as for a peer-signed claim (HLC round
    five, 2026-11-08, decision E4). The entry and space bindings are the caller's."""
    claim = signed.get("claim")
    holder_key = signed.get("holderKey")
    signature = signed.get("signature")
    if (not records.conforms(claim, "TakeClaim") or not isinstance(holder_key, bytes)
            or len(holder_key) != 32 or not isinstance(signature, bytes)):
        return False
    holder = claim["holder"]
    if not isinstance(holder, str) or not holder.startswith(derive_id(holder_key) + "/"):
        return False
    signed_bytes = cbor.dumps(claim)
    certificate = signed.get("holderCertificate")
    if certificate is None:
        return Identity.verify(bytes(holder_key), signed_bytes, bytes(signature))
    try:
        stamped = hlc_physical(claim.get("stamp"))
    except (TypeError, ValueError):
        return False
    # v0.1.13: judged at the claim's own stamp, which a renewal keeps.
    if not verify_agent_certificate_covering(certificate, bytes(holder_key), holder, stamped):
        return False
    return Identity.verify(bytes(certificate["agentPublicKey"]), signed_bytes, bytes(signature))


def agent_card(group: str, identity: Identity, local_name: str, issued_iso: str,
               ttl_iso: str, description: str, goals: list, consumes: list,
               produces: list, cost_hints: dict, space_bindings: dict,
               agent_public_raw: bytes | None = None, actions: list | None = None,
               agent_certificate: dict | None = None, ui: dict | None = None) -> dict:
    """An AgentCard in Java field order: id, issuer, group, issued, ttl,
    agent, description, goals, consumes, produces, costHints, spaceBindings,
    then the appended agentPublicKey, actions (v0.1.13, item 6),
    agentCertificate (v0.1.13), and ui (v0.1.26, what the agent can show), each
    omitted when absent so earlier cards keep their bytes. A certificate must
    certify ``agent_public_raw`` for this agent."""
    agent = identity.agent(local_name)
    card = {"id": f"aspace://{group}/agent/{agent}", "issuer": identity.peer_id,
            "group": group, "issued": issued_iso, "ttl": ttl_iso, "agent": agent,
            "description": description, "goals": goals, "consumes": consumes,
            "produces": produces, "costHints": cbor.canonical_map(cost_hints),
            "spaceBindings": cbor.canonical_map(space_bindings)}
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
    if ui is not None:
        card["ui"] = ui
    return card


def ui_declaration(components: list, reads: list | None = None, writes: list | None = None,
                   protocol: str = "a2ui", version: str = "v0.9.1") -> dict:
    """A UiDeclaration in Java field order (SPEC §6.1a.3): protocol, version,
    components (each id, catalogId, component, entry, controls, role), entries
    (reads, writes), catalogIds (derived from the components when not given)."""
    catalogs = list(dict.fromkeys(c["catalogId"] for c in components))
    return {"protocol": protocol, "version": version, "components": components,
            "entries": {"reads": list(reads or []), "writes": list(writes or [])}, "catalogIds": catalogs}


# ------------------------------------------------------------- the AppCard
#
# SPEC §6.1a.2 to §6.1a.5 (v0.1.32; AppCard origin and formats, 2026-11-09). ``kind`` says how an app
# connects and is closed; ``origin`` names the external system it came from and ``formats`` the
# media types and vocabularies it reads or renders, both open values; no kind is tied to an origin.
# ``records`` checks each rule at decode, and every builder here refuses what a reader refuses.

#: How an app connects: ``peer``, the app is a member; ``fed``, an agent of the group feeds it;
#: ``gateway``, it sits behind the A2A gateway; ``assembled``, a static app its publisher
#: assembled from extracted data and serves as is, reading nothing live.
APP_CARD_KINDS = ("peer", "fed", "gateway", "assembled")
APP_CARD_SHAPES = ("web", "desktop", "static", "a2ui")
APP_CARD_TRANSPORTS = ("views", "a2a")
#: ``idp``, the identity provider of whoever runs the host, enforced at its door (the default), or ``none``.
APP_CARD_SIGN_ONS = ("idp", "none")
APP_CARD_STATUSES = ("serving", "stopped")
APP_CARD_MAX_TERMS = 64
APP_CARD_MAX_FORMATS = 16
APP_CARD_MAX_FORMAT_LENGTH = 256
UI_ROLES = ("panel", "control", "row")
UI_MAX_COMPONENTS = 32

#: The fields a stub moves into its parts document, in field order (SPEC §6.1a.5).
APP_CARD_SPILL_SET = ("reads", "actions", "views", "ui")
AGENT_CARD_SPILL_SET = ("actions", "ui")
#: A card whose encoding is more than this many bytes spills: the inline limit of a payload.
CARD_SPILL_THRESHOLD_BYTES = 65_536
#: A publisher warns once a card's encoding passes this many bytes (56 KiB), just before it spills.
CARD_SPILL_WARN_BYTES = 57_344
#: The piece size of a parts document, so every implementation computes the same root for the same bytes.
CARD_SPILL_PIECE_SIZE = 65_536
#: The default bound on a parts document a reader fetches.
CARD_SPILL_MAX_FETCH_BYTES = 16_777_216
#: The largest ``spill.size``: 2^53 - 1, the largest integer every implementation holds exactly.
CARD_SPILL_MAX_SIZE = (1 << 53) - 1
#: The length of ``spill.root``.
CARD_SPILL_ROOT_LENGTH = 59

_APP_CARD_FIELDS = ("id", "issuer", "group", "issued", "ttl", "name", "kind", "shape", "owner", "reads", "actions",
                    "idpClient", "url", "pkg", "version", "views", "ui", "host", "origin", "formats", "spill")
_AGENT_CARD_FIELDS = ("id", "issuer", "group", "issued", "ttl", "agent", "description", "goals", "consumes",
                      "produces", "costHints", "spaceBindings", "agentPublicKey", "actions", "agentCertificate",
                      "ui", "spill")


def _require(value: dict, record: str) -> dict:
    if not records.conforms(value, record):
        raise ValueError(f"not a valid {record} under SPEC §6.1a" + (f": {value['id']}" if "id" in value else ""))
    return value


def app_card(group: str, identity: Identity, app: str, issued_iso: str, ttl_iso: str = "PT15M", *,
             name: str | None = None, kind: str = "fed", shape: str = "web", owner: str = "", reads=(), actions=(),
             idp_client: str = "", url: str = "", pkg: str = "", version: str = "1", views=(), ui: dict | None = None,
             host: dict | None = None, origin: dict | None = None, formats=None) -> dict:
    """An AppCard in Java field order (SPEC §6.1a.2), its id ``aspace://<group>/app/<peer>/<app>``
    and its name ``app`` unless given: ui, host, origin (``app_card_origin``), and formats
    (normalised by ``app_card_formats``) are each omitted when absent, so a card without them
    keeps its earlier bytes. The peer publishes it through ``Peer.publish_ad``, which applies
    the AppCard level and the spill; a card the record refuses raises ``ValueError``."""
    card = {"id": f"aspace://{group}/app/{identity.peer_id}/{app}", "issuer": identity.peer_id, "group": group,
            "issued": issued_iso, "ttl": ttl_iso, "name": app if name is None else name, "kind": kind, "shape": shape,
            "owner": owner, "reads": list(reads), "actions": list(actions), "idpClient": idp_client, "url": url,
            "pkg": pkg, "version": version, "views": list(views)}
    for field, value in (("ui", ui), ("host", host), ("origin", origin), ("formats", app_card_formats(formats))):
        if value is not None:
            card[field] = value
    return _require(card, "AppCard")


def app_card_host(url: str, port: int = 0, host_agent: str = "", path: str = "/", sign_on: str = "idp",
                  published_by: str = "", published_at_iso: str = "", status: str = "serving") -> dict:
    """The host group of a published AppCard in Java field order (SPEC §6.1a.4, v0.1.28):
    url, port, hostAgent, path, signOn (idp or none, v0.1.32), publishedBy, publishedAt,
    status (serving or stopped). Appended after ui; a card without it keeps its bytes."""
    if not url:
        raise ValueError("a host has a url")
    if port < 0 or port > 65535:
        raise ValueError("a host's port is 0 to 65535")
    if sign_on not in APP_CARD_SIGN_ONS:
        raise ValueError("a host's signOn is idp or none")
    if status not in APP_CARD_STATUSES:
        raise ValueError("a host's status is serving or stopped")
    if not records.is_canonical_instant(published_at_iso):
        raise ValueError("a host names when it was published, an Instant as Java prints it")
    return {"url": url, "port": port, "hostAgent": host_agent, "path": path or "/", "signOn": sign_on,
            "publishedBy": published_by, "publishedAt": published_at_iso, "status": status}


def app_card_origin(system: str, ref: str, version: str | None = "", attrs: dict | None = None) -> dict:
    """The origin group of an AppCard in Java field order (FR-2): system, ref, version (empty when
    the system names none), and attrs in the SPEC §9.1 order of a map, omitted when empty. A
    registered system is a token such as ``realm``; an unregistered one is a reverse-DNS name its
    owner controls (``agentspaces-spec/REGISTRY.md``)."""
    origin = {"system": system, "ref": ref, "version": "" if version is None else version}
    if attrs:
        origin["attrs"] = cbor.canonical_map({str(k): str(v) for k, v in attrs.items()})
    return _require(origin, "AppCard.Origin")


def app_card_formats(formats) -> list | None:
    """``formats`` as the issuer writes it (FR-3): media types lower-cased, a repeated entry
    dropped after its first occurrence, the issuer's order kept, and an empty list absent."""
    if not formats:
        return None
    normalised = list(dict.fromkeys(f if ":" in f else f.lower() for f in formats))
    if not records.formats_hold(normalised):
        raise ValueError(f"formats holds 1 to {APP_CARD_MAX_FORMATS} media types or vocabulary IRIs: {formats!r}")
    return normalised


def from_origin(card: dict, system: str, ref: str | None = None) -> bool:
    """Whether an AppCard came from ``system`` (FR-8), and under ``ref`` when given: a ref ending
    in ``/*`` matches every ref that starts with the part before ``*``. A stub keeps its origin."""
    origin = card.get("origin")
    if origin is None or origin.get("system") != system:
        return False
    if ref is None:
        return True
    return origin["ref"].startswith(ref[:-1]) if ref.endswith("/*") else origin["ref"] == ref


def handles(card: dict, format: str) -> bool:
    """Whether an AppCard reads or renders ``format`` (FR-8): a media type is lower-cased and
    matches an entry exactly, ``type/*`` matches every media type of that type, and a
    vocabulary IRI matches exactly."""
    formats = card.get("formats")
    if not formats or format is None:
        return False
    if ":" in format:
        return format in formats
    wanted = format.lower()
    if wanted.endswith("/*"):
        return any(":" not in f and f.startswith(wanted[:-1]) for f in formats)
    return wanted in formats


def app_card_for_view(card: dict, gate_open: bool) -> dict:
    """The AppCard a view may receive (FR-7): the card itself while every member reads the
    v0.1.32 fields, and otherwise the card without origin, formats, and a host whose signOn is
    ``idp``. A host of signOn ``none`` reads at level 1 and stays."""
    if "spill" in card:
        raise ValueError("the gate applies to a full card; a stub exists only behind an open gate")
    if gate_open:
        return card
    stripped = {k: v for k, v in card.items() if k not in ("origin", "formats")}
    if (card.get("host") or {}).get("signOn") == "idp":
        del stripped["host"]
    return stripped


# ------------------------------------------------------------- the card spill

def card_spill(root: str, size: int, parts) -> dict:
    """The CardSpill a stub carries (SPEC §6.1a.5): the parts document's content root, its
    length, and the non-empty spill-set fields it holds."""
    return _require({"root": root, "size": size, "parts": list(parts)}, "CardSpill")


def _is_agent_card(card: dict) -> bool:
    return "agent" in card


def card_parts(card: dict) -> dict:
    """The parts record of a full AppCard or AgentCard: the full values of its spill set, what
    a publisher writes as the parts document (``AppCard.Parts`` or ``AgentCard.Parts``)."""
    if "spill" in card:
        raise ValueError("a stub's parts are in its spill document; resolve the card first")
    if _is_agent_card(card):
        return {field: card[field] for field in AGENT_CARD_SPILL_SET if card.get(field) is not None}
    parts = {"reads": list(card["reads"]), "actions": list(card["actions"]), "views": list(card["views"])}
    if card.get("ui") is not None:
        parts["ui"] = card["ui"]
    return parts


def non_empty_parts(parts: dict) -> list:
    """The names of a parts record's non-empty fields, in field order: what ``spill.parts`` lists."""
    return [field for field in (APP_CARD_SPILL_SET if "reads" in parts else AGENT_CARD_SPILL_SET)
            if parts.get(field) not in (None, [])]


def _ordered(card: dict, fields: tuple) -> dict:
    return {field: card[field] for field in fields if field in card}


def card_stub(card: dict, spill: dict) -> dict:
    """The stub of a full card (SPEC §6.1a.5): every spill-set field at its placeholder (``[]``
    for the AppCard's lists, absent for the optional fields) and ``spill`` appended."""
    named = non_empty_parts(card_parts(card))
    if list(spill["parts"]) != named:
        raise ValueError(f"a stub moves every non-empty part {named}: {spill['parts']}")
    if _is_agent_card(card):
        stub = {k: v for k, v in card.items() if k not in AGENT_CARD_SPILL_SET}
        return _ordered({**stub, "spill": spill}, _AGENT_CARD_FIELDS)
    stub = {k: v for k, v in card.items() if k != "ui"}
    stub.update(reads=[], actions=[], views=[], spill=spill)
    return _ordered(stub, _APP_CARD_FIELDS)


def card_complete(stub: dict, parts: dict) -> dict:
    """The full card of a stub (FR-15): the parts document's values in place and no ``spill``."""
    spill = stub.get("spill")
    if spill is None:
        raise ValueError("only a stub completes; this card carries its parts inline")
    if non_empty_parts(parts) != list(spill["parts"]):
        raise ValueError(f"the parts document holds {non_empty_parts(parts)} where the stub names {spill['parts']}")
    full = {k: v for k, v in stub.items() if k != "spill"}
    full.update(parts)
    return _ordered(full, _AGENT_CARD_FIELDS if _is_agent_card(stub) else _APP_CARD_FIELDS)


def ui_component(id: str, catalog_id: str, component: str, entry: str = "", controls: list | None = None,
                 role: str = "panel") -> dict:
    """One component of a UiDeclaration, in Java field order."""
    if role not in ("panel", "control", "row"):
        raise ValueError("a ui component's role is one of panel, control, row")
    return {"id": id, "catalogId": catalog_id, "component": component, "entry": entry,
            "controls": list(controls or []), "role": role}


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


def claim_sort_key(claim: dict) -> tuple:
    """The claim lattice's total order (spec §7.4): the SMALLEST key wins.
    Epoch descending, bid ascending, HLC stamp ascending, holder ascending,
    expiry descending; identical to TakeClaim.merge on the Java side, which compares
    the stamp's node and the holder by UTF-16 code units (HLC canonical stamps, 2026-11-08),
    and the bids as Double.compare orders them, -0.0 below 0.0 (HLC round six, 2026-11-08,
    vector claim-20)."""
    bid = claim["bid"]
    return (-int(claim["epoch"]), (bid, math.copysign(1.0, bid)),
            hlc_tuple(claim["stamp"]), utf16_order(claim["holder"]),
            -int(claim["expiresAtMillis"]))


def merge_claims(a: dict, b: dict) -> dict:
    """Returns the winning SignedClaim of two, by the lattice order."""
    if a is None:
        return b
    if b is None:
        return a
    return a if claim_sort_key(a["claim"]) <= claim_sort_key(b["claim"]) else b
