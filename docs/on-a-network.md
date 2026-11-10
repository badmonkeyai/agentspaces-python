# On a network

Written for: Python developers who build with agentspaces-client.

The client ignores the frame kinds it does not speak and survives every hostile
frame (ROBUSTNESS.md). Every document it reads from the network is in the AgentSpaces
wire encoding (HLC round six, 2026-11-08): one item under shortest heads, at
most 64 nested levels, definite byte strings and arrays, indefinite maps whose
keys are distinct text, text of shortest-form UTF-8 that is definite up to
3996 UTF-16 units and in Jackson's exact chunks past that, an integer outside
a Java long as a bignum (tag 2 or 3) of at most 1000 bytes, a decimal as a normalized tag 4, a
float64 or a float32 with the one NaN Java writes, and no other tag, simple
value or half float. A bignum decodes to an `int` and a decimal to a
`decimal.Decimal`, and a float32 to a `cbor.Float32`, each of which re-encodes
to the bytes it came from. A protocol record (a frame, a body, a space delta,
a claim, an advertisement, a revocation, a founding, a capability pipe payload) holds exactly the fields
Java's record holds, in its order, each of its kind: no float or text where an
integer belongs, no integer where text or a double belongs, no text where bytes
belong, no tag, an `Instant` and a `Duration` as Java prints them, maps sorted,
and an agent id whose local name holds no `/` and no `:`. It also holds what
Java's record constructor holds: no null where Java requires a value (an
envelope's group, kind, sender, stamp or body; a record's identity, lease or
tags; a lease's holder or kind; a certificate's agent, key, issue instant or
period), a positive dot counter, lease expiry and certificate period, a payload
inline or by reference and never both or neither, an inline payload of at most
64 KiB, and a key epoch of 1 or more when present. A receiver decodes a
carrier only when re-encoding what it decoded gives back exactly the bytes it
received, so a relay cannot relabel a signed frame, and every signature
verifies over the same bytes at every peer. A frame or body that fails counts
in `peer.malformed_frames`, a space delta in `peer.deltas_undecodable`, and
nobody is struck for either. An entry whose payload is outside the encoding
still replicates, and every read skips its value. A stamp is a definite text
item in the canonical `physical:logical:node` grammar: each number `0` or
ASCII digits without a leading zero, a physical that fits a signed 64-bit
integer, a node part present with no colon, no control character and no lone
surrogate. A stamp holds at most 3996 UTF-16 units, so a text in Jackson's chunks is
never a stamp, and `hlc_now` refuses a node past 3965 units (HLC round seven,
2026-11-08). A frame whose stamp is no stamp item does not decode: the peer
drops it before any signature check and counts it in `peer.malformed_frames`.
Every verified frame then passes a `FrameFilter`, which judges the stamp in the order SPEC §9 gives: one
older than five minutes and a sender-and-stamp pair it saw before, then one
past the HLC drift bound by at most five seconds
(`wire.FAR_FUTURE_SKEW_MARGIN_MILLIS`, the room a receiver whose wall runs a
little behind gives an honest peer), one further past it, and one whose
logical counter is above 65536 (`wire.LOGICAL_LIMIT`). It drops each without
a reply and counts it (`peer.frames.stale`, `.replayed`, `.far_future_skewed`,
`.far_future`, `.logical_refused`). Because each stamp has one spelling, the
bytes a signer signed always equal the stamp's re-encoding.

A space delta whose state or claim holds anything but such a stamp (record,
lease, signing or claim stamp) does not decode, as in Java's codec: the peer
drops the whole delta and counts it in `peer.deltas_undecodable` on every
offer. The peer checks a state or claim in this order: its signatures and
certificate, its actor's revocation, then its stamps, so a revoked actor counts
in no stamp counter. It applies `wire.acceptable_hlc` to the record, lease and
signing stamps of a state and to a claim's stamp, and counts a refusal once in
`peer.stamps_logical_refused`. It refuses a state or claim whose record, lease
or claim stamp runs more than an hour past wall + drift + margin and counts it
once in `peer.stamps_far_future_refused`. A state or claim stamped past wall +
drift + margin by less is deferred: it does not merge, it counts once in
`peer.stamps_far_future_deferred`, and it merges when anti-entropy offers it
again after this peer's wall catches up, so an honest taker whose clock a
hostile stamp dragged ahead loses nothing. The peer judges every offer afresh,
so a refused far-future offer merges too once the wall catches up; a memory of
the 4096 most recently offered keys, keyed on the signed content alone, only
keeps each refusal and each deferral at one count. An agent certificate bounds
a record, a claim or an agent-signed state by its validity window alone, so an
agent's record stamp, claim stamp and state `signedAt` meet these same rules.
A state with a null lease stamp decodes and merges nothing, uncounted. A claim
travels as a `TakeClaim` in Java's field order and its signature covers those
bytes; a claim whose fields arrive in another order, or whose epoch, expiry or
bid is null, absent or of another kind, makes its delta undecodable. Bids
order as Java's `Double.compare` orders them, -0.0 below 0.0. As Java's
`mergeClaim` does, the peer drops, uncounted, a claim stamped more than the
drift bound before its entry's issue stamp, and a claim contesting another
holder's claim with a stamp older than the drift bound and Java's 200 ms
settle window. This client offers an empty digest on every pull, so it
acknowledges no refused state; its partners re-offer it, and the count stays
at one. This client keeps no strikes. `peer.counters()` returns these counts
under the Java node's names (`framesLogicalRefused`, `framesFarFuture`,
`framesFarFutureSkewed`, `stampsLogicalRefused`, `stampsFarFutureRefused`,
`stampsFarFutureDeferred`, `deltasUndecodable`). A ref head reads its advisory
`pdt.issued` and `pdt.issuer` as Java's `Refs` reads them: when the stamp is
absent, null, not text, not acceptable, or past the drift bound plus the
margin, or the issuer is present but null, not text or no agent id, the head
keeps the entry's own stamp and issuer together, and the peer counts nothing.
Every other attribute holds text: a head with a null or non-text value there
does not decode, and the ref counts the entry once in `heads_ignored`, as it
counts a head that breaks a bound or names another kind or ref. A claim on an
entry this replica collected or never held leaves the claim map once its
expiry passes: the peer prunes such claims as a space delta arrives, once the
map holds at least 1024 claims and twice what its last scan left, so the map
stays bounded under churn. Nodes and holders order by UTF-16 code
units, as Java's `String.compareTo` orders them. The local clock clamps a
merged physical one millisecond inside the drift bound, carries a counter past
the limit into the next millisecond, and raises on a node the grammar refuses,
so no stamp it issues repeats, exceeds the limit, breaks the grammar, or runs
past what a receiver admits. The peer counts a kind this client does not speak
in `peer.ignored_kinds` and a body that does not decode in
`peer.malformed_frames`, and the reader goes on. A lost socket is a hiccup: the peer
re-dials the seeds, pausing after each round of refusals for `reconnect_interval_s`
(5 s), then 10, 20 and 30 s with a random spread, until `close()` (swarm retries,
ROBUSTNESS.md §10.3 E5). A link that ends within `reconnect_interval_s` of its dial counts
as a refused round, so a seed that accepts each dial and drops it at once gets the same
pauses (§10.6). A bootstrapped peer reads its beacon again every
`reconnect_window_s` (10 min) with nothing reachable. It then introduces itself again and pulls again what it had pulled
(revocations, advertisements, spaces), counting in `peer.reconnects`; a `take`
in flight keeps polling across the gap. `close()` by the owner is final.
`tests/test_robustness.py` pins each case against a fake seed over TCP, and
`tests/test_tls.py` the tls binding against one over TLS.
