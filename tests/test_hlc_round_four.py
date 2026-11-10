#
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

"""The round-four stamp decisions (HLC round four, 2026-11-08), end to end through the peer.

Round three's adversaries found that the implementations disagreed on signedAt and on
pdt.issued, that Java accepted non-canonical CBOR text for a stamp, that far-future records
quarantined honest takers, and that the counts differed. The owner's binding decisions:

D1. signedAt is a stamp like any other: canonical, counter 0..65536, refused after the
    state's signatures verify and counted once per distinct state.
D2. A pdt.issued that is not acceptable, or a pdt.issuer that is no agent id, makes the head
    fall back to the entry's own stamp and issuer together; nothing is refused or counted.
D3. A stamp on the wire is a definite-length, untagged CBOR text string of shortest-form
    UTF-8 in the canonical grammar. Any other item in a stamp's place makes its carrier
    undecodable, and the receiver counts it as such.
D4. A folded state or claim stamped past wall + MAX_DRIFT + the skew margin is deferred: not
    merged, not counted, and merged once the receiver's wall catches up. Past the margin plus
    one hour it is refused as hostile.
D5. Refusals are keyed on signed content and counted after verification once per distinct
    offer, under Java's counter names.
D6. A peer never emits a stamp whose node breaks the grammar.

Round five (HLC round five, 2026-11-08) counts a deferral once per distinct offer and a
hostile far-future refusal apart (E2), judges every offer afresh so a refused far-future
offer merges once the wall catches up (E5), and drops a frame whose stamp does not decode
before anyone checks its signature (E9); the tests below follow it, and
test_hlc_round_five.py pins the rest."""

import types

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.pdt import NodeStore, PMap
from agentspaces.pdt import refs
from agentspaces.space import Space
from test_hlc_logical_limit import (DRIFT, GROUP, LIMIT, T, CapturingPeer, _claim, _with_issued,
                                    _with_lease_stamp, _with_signed_at, _write)

MARGIN = wire.FAR_FUTURE_SKEW_MARGIN_MILLIS
HOUR = 60 * 60 * 1000


class Clock:
    """A receiver's wall clock the test moves forward."""

    def __init__(self, millis: int):
        self.millis = millis

    def __call__(self) -> float:
        return self.millis / 1000


class Link:
    """Delivers signed frames from ``sender`` to ``receiver``, each stamped at the receiver's
    wall time so the frame filter admits every one however far the test moves that clock."""

    def __init__(self, sender: Identity, receiver: CapturingPeer):
        self.sender, self.receiver, self.logical = sender, receiver, 0

    def frame(self, kind: str, body: bytes) -> bytes:
        self.logical += 1
        stamp = f"{self.receiver._now_ms()}:{self.logical}:{self.sender.peer_id}"
        env = wire.envelope(GROUP, kind, self.sender.peer_id, stamp, body, self.receiver.identity.peer_id)
        return wire.encode_frame(env, self.sender)

    def rumor_raw(self, delta: bytes) -> None:
        self.receiver._receive(self.frame("RUMOR", wire.rumor_body("space:tasks", f"w:{self.logical}", 6, delta)))

    def pull_raw(self, sync: bytes) -> None:
        self.receiver._receive(self.frame("PULL_RESP", cbor.dumps({"deltas": {"space:tasks": sync}})))

    def rumor(self, state: dict | None = None, claim: tuple | None = None) -> None:
        entry_id, signed = claim if claim is not None else (None, None)
        self.rumor_raw(cbor.dumps({"state": state, "claimEntry": entry_id, "claim": signed}))

    def pull_resp(self, states: list, claims: dict) -> None:
        self.pull_raw(cbor.dumps({"states": states, "claims": claims}))


def _receiver(host: Identity, millis: int = T) -> tuple:
    clock = Clock(millis)
    receiver = CapturingPeer(clock=clock)
    return receiver, Link(host, receiver), clock


def _counts(peer) -> dict:
    return {name: value for name, value in peer.counters().items() if value}


# Hostile CBOR items in a stamp's place, each built from the honest stamp's text ----------

def _head(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    return bytes([(major << 5) | 24, length])


def _indefinite(text: str) -> bytes:
    """The same text as an indefinite-length string of two definite chunks."""
    half = len(text) // 2
    return b"\x7f" + cbor.dumps(text[:half]) + cbor.dumps(text[half:]) + b"\xff"


def _tagged(text: str) -> bytes:
    return b"\xd8\x20" + cbor.dumps(text)  # tag 32 (URI) around the text


def _overlong(text: str) -> bytes:
    """The text with its first ':' written as the overlong two-byte sequence C0 BA."""
    raw = text.encode("utf-8").replace(b":", b"\xc0\xba", 1)
    return _head(3, len(raw)) + raw


def _surrogate(text: str) -> bytes:
    """The text with U+D800 encoded in UTF-8 (ED A0 80) appended to its node."""
    raw = text.encode("utf-8") + b"\xed\xa0\x80"
    return _head(3, len(raw)) + raw


HOSTILE_ITEMS = {
    "indefinite-length text": _indefinite,
    "tagged text": _tagged,
    "overlong UTF-8": _overlong,
    "surrogate in UTF-8": _surrogate,
    "byte string": lambda text: cbor.dumps(text.encode("utf-8")),
    "number": lambda text: cbor.dumps(T),
    "map": lambda text: cbor.dumps({"stamp": text}),
    "non-canonical text": lambda text: cbor.dumps(text.replace(":", ":0", 1)),
}


def _swap(encoded: bytes, stamp: str, hostile: bytes) -> bytes:
    """``encoded`` with every definite encoding of ``stamp`` replaced by ``hostile``."""
    assert cbor.dumps(stamp) in encoded
    return encoded.replace(cbor.dumps(stamp), hostile)


# D3: the decoder ----------------------------------------------------------------------

def test_the_decoder_reads_the_indefinite_text_jackson_writes_for_long_strings():
    # HLC round seven, 2026-11-08: such a text runs past 3996 UTF-16 units, which no stamp does,
    # so the decoder needs no mark to keep it from parsing as one
    long_text = "x" * 4000 + "é"
    decoded = cbor.loads(cbor.dumps(long_text))
    assert decoded == long_text and type(decoded) is str
    assert type(cbor.loads(cbor.dumps("x" * 3996))) is str
    # HLC round six, 2026-11-08 (rules S5 and S6): no other chunking decodes, and no byte
    # string arrives in chunks.
    for raw in (_indefinite(long_text), b"\x5f" + cbor.dumps(b"ab") + cbor.dumps(b"c") + b"\xff"):
        with pytest.raises(ValueError):
            cbor.loads(raw)


@pytest.mark.parametrize("raw", [b"\x7f\x41a\xff", b"\x7f\x7f\x61a\xff\xff", b"\x7f\x61a", b"\x5f\x61a\xff"])
def test_the_decoder_refuses_a_chunk_of_another_type_and_an_unterminated_string(raw):
    with pytest.raises(ValueError):
        cbor.loads(raw)


@pytest.mark.parametrize("name", ["tagged text", "overlong UTF-8", "surrogate in UTF-8"])
def test_the_decoder_refuses_tags_and_ill_formed_utf8(name):
    with pytest.raises(ValueError):
        cbor.loads(HOSTILE_ITEMS[name](f"{T}:0:n"))


@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_no_hostile_item_parses_as_a_stamp(name):
    try:
        item = cbor.loads(HOSTILE_ITEMS[name](f"{T}:0:n"))
    except ValueError:
        return
    assert wire.parse_hlc(item) is None and wire.acceptable_hlc(item) is None


# D3: frames ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_a_frame_whose_stamp_is_not_canonical_cbor_text_is_dropped_and_counted(name):
    peer, _, _ = _receiver(Identity.generate())
    other = Identity.generate()
    stamp = f"{T}:1:{other.peer_id}"
    env = wire.envelope(GROUP, "PING", other.peer_id, stamp, wire.ping_body(1), peer.identity.peer_id)
    peer._receive(_swap(wire.encode_frame(env, other), stamp, HOSTILE_ITEMS[name](stamp)))
    assert peer.sent == [] and other.peer_id not in peer.members
    assert peer.malformed_frames == 1
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T}:0:{peer.identity.peer_id}"


# D3 and D5: deltas carrying a stamp that does not decode ------------------------------

@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_a_rumored_state_whose_issue_stamp_is_not_a_stamp_is_undecodable_every_time(name):
    host = Identity.generate()
    write = _write(host, T)
    receiver, link, _ = _receiver(host)
    issued = write["record"]["issued"]
    delta = _swap(cbor.dumps({"state": write, "claimEntry": None, "claim": None}), issued,
                  HOSTILE_ITEMS[name](issued))
    link.rumor_raw(delta)
    link.rumor_raw(delta)
    assert receiver.states == {}
    assert _counts(receiver) == {"deltasUndecodable": 2}
    link.rumor(write)
    assert set(receiver.states) == {write["record"]["entryId"]}


@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_a_pulled_lease_stamp_that_is_not_a_stamp_drops_the_whole_sync_delta(name):
    host = Identity.generate()
    write, other = _write(host, T), _write(host, T)
    lease = f"{T + 1}:0:{host.agent('w')}"
    renewed = _with_lease_stamp(write, host, lease, T)
    receiver, link, _ = _receiver(host)
    link.pull_raw(_swap(cbor.dumps({"states": [other, renewed], "claims": {}}), lease,
                        HOSTILE_ITEMS[name](lease)))
    assert receiver.states == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_an_agent_state_whose_signed_at_is_not_a_stamp_is_undecodable(name):
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=Clock(T))
    write = _write(host, T, agent=agent)
    signed_at = f"{T}:3:{agent.agent_id}"
    receiver, link, _ = _receiver(host)
    state = _with_signed_at(write, agent, signed_at)
    link.rumor_raw(_swap(cbor.dumps({"state": state, "claimEntry": None, "claim": None}), signed_at,
                         HOSTILE_ITEMS[name](signed_at)))
    assert receiver.states == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}
    link.rumor(state)
    assert set(receiver.states) == {write["record"]["entryId"]}


@pytest.mark.parametrize("name", sorted(HOSTILE_ITEMS))
def test_a_claim_whose_stamp_is_not_a_stamp_is_undecodable_by_rumor_and_by_pull(name):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    stamp = f"{T}:9:{host.agent('w')}"
    signed = _claim(write, host, stamp, T)
    hostile = HOSTILE_ITEMS[name](stamp)
    link.rumor_raw(_swap(cbor.dumps({"state": None, "claimEntry": entry_id, "claim": signed}), stamp, hostile))
    link.pull_raw(_swap(cbor.dumps({"states": [], "claims": {entry_id: signed}}), stamp, hostile))
    assert receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 2}
    link.rumor(claim=(entry_id, signed))
    assert receiver.claims[entry_id] == signed


def test_a_recordless_state_whose_lease_stamp_is_not_a_stamp_never_waits():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    lease = f"{T + 1}:0:{host.agent('w')}"
    renewed = _with_lease_stamp(write, host, lease, T)
    recordless = {k: v for k, v in renewed.items() if k not in ("record", "issuerPublicKey")}
    receiver, link, _ = _receiver(host)
    link.rumor_raw(_swap(cbor.dumps({"state": dict(recordless, entryId=entry_id), "claimEntry": None,
                                     "claim": None}), lease, _indefinite(lease)))
    assert receiver.pending_states == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("payload", [b"\xff", cbor.dumps([1, 2]), cbor.dumps({"state": 5}),
                                     cbor.dumps({"state": None, "claimEntry": "e", "claim": [1]}),
                                     cbor.dumps({"state": {"record": "x"}})])
def test_a_rumored_delta_that_is_no_delta_is_counted_undecodable(payload):
    receiver, link, _ = _receiver(Identity.generate())
    link.rumor_raw(payload)
    assert _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("sync", [b"\x18", cbor.dumps("states"), cbor.dumps({"states": [1]}),
                                  cbor.dumps({"states": [], "claims": {"e": 1}})])
def test_a_pulled_delta_that_is_no_sync_delta_is_counted_undecodable(sync):
    receiver, link, _ = _receiver(Identity.generate())
    link.pull_raw(sync)
    assert _counts(receiver) == {"deltasUndecodable": 1}


# D1: signedAt is judged like every other stamp ----------------------------------------

def test_a_signed_at_above_the_limit_is_refused_after_verification_and_counted_once():
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=Clock(T))
    write = _write(host, T, agent=agent)
    receiver, link, _ = _receiver(host)
    hostile = _with_signed_at(write, agent, f"{T}:{LIMIT + 1}:{agent.agent_id}")
    link.rumor(hostile)
    link.pull_resp([hostile], {})
    link.rumor(hostile)
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsLogicalRefused": 1}
    # A second distinct hostile state counts again; one at exactly the limit folds.
    link.rumor(_with_signed_at(write, agent, f"{T}:{LIMIT + 2}:{agent.agent_id}"))
    assert _counts(receiver) == {"stampsLogicalRefused": 2}
    link.rumor(_with_signed_at(write, agent, f"{T}:{LIMIT}:{agent.agent_id}"))
    assert set(receiver.states) == {write["record"]["entryId"]}


def test_a_forged_state_with_a_signed_at_above_the_limit_is_dropped_uncounted():
    host, mallory = Identity.generate(), Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=Clock(T))
    write = _write(host, T, agent=agent)
    receiver, link, _ = _receiver(host)
    forged = _with_signed_at(write, mallory, f"{T}:{LIMIT + 1}:{agent.agent_id}")
    link.rumor(forged)
    assert receiver.states == {}
    assert _counts(receiver) == {}


def test_a_completion_whose_signed_at_is_above_the_limit_leaves_the_entry_open():
    host, taker = Identity.generate(), Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    agent = taker.renewing_subordinate("t", "PT24H", clock=Clock(T))
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    record = write["record"]
    claim = wire.take_claim(entry_id, record["spaceId"], 1, f"{T}:1:{agent.agent_id}", agent.agent_id,
                            0.0, T + 60_000)
    signed = wire.signed_claim(claim, taker, agent)
    done = _with_signed_at(wire.sign_state(dict(write, completed=True), taker, agent, T), agent,
                           f"{T}:{LIMIT + 1}:{agent.agent_id}")
    link.rumor(done, claim=(entry_id, signed))
    assert receiver.claims[entry_id] == signed
    assert not receiver.states[entry_id]["completed"]
    assert _counts(receiver) == {"stampsLogicalRefused": 1}


# D4: far-future records are deferred, and refused only far past the margin -------------

def test_a_state_issued_past_the_margin_is_deferred_and_merges_once_the_wall_catches_up():
    host = Identity.generate()
    ahead = _with_issued(_write(host, T), host, f"{T + DRIFT + MARGIN + 1}:0:{host.agent('w')}")
    receiver, link, clock = _receiver(host)
    link.rumor(ahead)
    link.pull_resp([ahead], {})
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis += 1
    link.pull_resp([ahead], {})
    assert set(receiver.states) == {ahead["record"]["entryId"]}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}


def test_a_state_issued_within_the_margin_merges_at_once():
    host = Identity.generate()
    within = _with_issued(_write(host, T), host, f"{T + DRIFT + MARGIN}:0:{host.agent('w')}")
    receiver, link, _ = _receiver(host)
    link.rumor(within)
    assert set(receiver.states) == {within["record"]["entryId"]}


def test_a_renewal_past_the_margin_is_deferred_and_the_held_lease_stays():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    link.rumor(write)
    renewal = _with_lease_stamp(write, host, f"{T + DRIFT + MARGIN + 10}:0:{host.agent('w')}", T)
    link.rumor(renewal)
    assert receiver.states[entry_id]["leaseStamp"] == write["leaseStamp"]
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis += 10
    link.rumor(renewal)
    assert receiver.states[entry_id]["leaseStamp"] == renewal["leaseStamp"]


def test_a_claim_past_the_margin_is_deferred_and_merges_once_the_wall_catches_up():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    link.rumor(write)
    ahead = _claim(write, host, f"{T + DRIFT + MARGIN + 1}:0:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, ahead))
    assert receiver.claims == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis += 1
    link.rumor(claim=(entry_id, ahead))
    assert receiver.claims[entry_id] == ahead


def test_an_honest_taker_dragged_ahead_is_never_refused_by_a_receiver_running_behind():
    # A hostile member dragged the honest taker's clock to its wall + MAX_DRIFT; the
    # receiver's wall runs eight seconds behind the taker's.
    host, taker = Identity.generate(), Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host, T - 8_000)
    link.rumor(write)
    record = write["record"]
    honest = wire.signed_claim(wire.take_claim(entry_id, record["spaceId"], 1, f"{T + DRIFT}:0:{taker.agent('w')}",
                                               taker.agent("w"), 0.0, T + 60_000), taker)
    taker_link = Link(taker, receiver)
    for _ in range(5):
        taker_link.rumor(claim=(entry_id, honest))
    assert receiver.claims == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis = T - MARGIN
    taker_link.rumor(claim=(entry_id, honest))
    assert receiver.claims[entry_id] == honest
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}


def test_a_state_past_the_margin_by_more_than_an_hour_is_refused_once_until_the_wall_catches_up():
    host = Identity.generate()
    hostile = _with_issued(_write(host, T), host, f"{T + DRIFT + MARGIN + HOUR + 1}:0:{host.agent('w')}")
    receiver, link, clock = _receiver(host)
    link.rumor(hostile)
    link.pull_resp([hostile], {})
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}
    # HLC round five, 2026-11-08 (decision E5): the wall catches up two hours later, and the
    # peer judges the state afresh and merges it; the count stays at one.
    clock.millis += 2 * HOUR
    link.pull_resp([hostile], {})
    assert set(receiver.states) == {hostile["record"]["entryId"]}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}


def test_a_state_past_the_margin_by_exactly_an_hour_is_still_deferred():
    host = Identity.generate()
    deferred = _with_issued(_write(host, T), host, f"{T + DRIFT + MARGIN + HOUR}:0:{host.agent('w')}")
    receiver, link, _ = _receiver(host)
    link.rumor(deferred)
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}


def test_a_claim_past_the_margin_by_more_than_an_hour_is_refused_once_until_the_wall_catches_up():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    link.rumor(write)
    hostile = _claim(write, host, f"{T + DRIFT + MARGIN + HOUR + 1}:0:{host.agent('w')}", T + 3 * HOUR)
    link.rumor(claim=(entry_id, hostile))
    link.pull_resp([], {entry_id: hostile})
    assert receiver.claims == {}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}
    # HLC round five, 2026-11-08 (decision E5): the peer judges the claim afresh once the wall catches up.
    clock.millis += 2 * HOUR
    link.rumor(claim=(entry_id, hostile))
    assert receiver.claims[entry_id] == hostile
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}


def test_a_forged_far_future_state_is_dropped_uncounted():
    host = Identity.generate()
    hostile = _with_issued(_write(host, T), host, f"{T + DRIFT + MARGIN + HOUR + 1}:0:{host.agent('w')}")
    hostile = dict(hostile, record=dict(hostile["record"], sig=bytes(64)))
    receiver, link, _ = _receiver(host)
    link.rumor(hostile)
    assert receiver.states == {} and _counts(receiver) == {}


# D5: refusals keyed on signed content, under Java's counter names ----------------------

def test_the_counters_carry_java_names():
    peer, _, _ = _receiver(Identity.generate())
    assert peer.counters() == {"framesLogicalRefused": 0, "framesFarFuture": 0, "framesFarFutureSkewed": 0,
                               "stampsLogicalRefused": 0, "stampsFarFutureRefused": 0,
                               "stampsFarFutureDeferred": 0, "deltasUndecodable": 0}


def test_frame_refusals_count_under_java_names():
    peer, _, _ = _receiver(Identity.generate())
    other = Identity.generate()
    for nonce, stamp in enumerate((f"{T}:{LIMIT + 1}:{other.peer_id}", f"{T + DRIFT + MARGIN + 1}:0:{other.peer_id}",
                                   f"{T + DRIFT + 1}:0:{other.peer_id}")):
        env = wire.envelope(GROUP, "PING", other.peer_id, stamp, wire.ping_body(nonce), peer.identity.peer_id)
        peer._receive(wire.encode_frame(env, other))
    assert _counts(peer) == {"framesLogicalRefused": 1, "framesFarFuture": 1, "framesFarFutureSkewed": 1}


def test_a_refused_state_re_offered_with_other_unsigned_fields_counts_once():
    host = Identity.generate()
    honest = _write(host, T)
    receiver, link, _ = _receiver(host)
    hostile = _with_issued(honest, host, f"{T}:{LIMIT + 1}:{host.agent('w')}")
    link.rumor(hostile)
    link.rumor(dict(hostile, entryId=hostile["record"]["entryId"]))
    link.pull_resp([dict(hostile, entryId=hostile["record"]["entryId"])], {})
    assert _counts(receiver) == {"stampsLogicalRefused": 1}


def test_a_refused_claim_re_offered_with_other_unsigned_fields_counts_once():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    hostile = _claim(write, host, f"{T}:{LIMIT + 1}:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, hostile))
    link.pull_resp([], {entry_id: hostile})
    # HLC round six, 2026-11-08 (owner ruling F3): an unsigned field the record does not name
    # makes the delta undecodable before anything judges the claim.
    link.rumor(claim=(entry_id, dict(hostile, padding=b"\x01")))
    assert _counts(receiver) == {"stampsLogicalRefused": 1, "deltasUndecodable": 1}


# D2: the advisory pdt.issued of a ref --------------------------------------------------

def _pref_state(host: Identity, attrs: dict | None) -> dict:
    root = PMap.empty(NodeStore()).assoc("k", 1).root()
    record = refs.pref_record("facts", refs.KIND_MAP, root, attrs=attrs)
    _, body = wire.entry_delta("pdt", GROUP, refs.PREF_TYPE, cbor.dumps(record), host, "w", 60_000,
                               now_ms=T, tags=refs.pref_tags(record))
    return cbor.loads(cbor.loads(body)["payload"])["state"]


def _head_through_the_peer(attrs: dict | None):
    host = Identity.generate()
    state = _pref_state(host, attrs)
    receiver, link, _ = _receiver(host)
    link.rumor(state)
    assert set(receiver.states) == {state["record"]["entryId"]}
    assert _counts(receiver) == {}
    pdt = types.SimpleNamespace(peer=receiver, space=Space(receiver, "pdt"), store=NodeStore(),
                                follow=refs.FOLLOW_FULL)
    [head] = refs.Ref(pdt, "facts", refs.KIND_MAP, refs.MODE_MULTI)._live_entries()
    own = wire.parse_hlc(state["record"]["issued"]), state["record"]["issuer"]
    return (head.issued, head.issuer), own


ORIGINAL_ISSUER = "zOriginalPeer/writer"


def test_an_acceptable_pdt_issued_orders_the_head_with_its_issuer():
    head, _ = _head_through_the_peer({refs.ISSUED_ATTR: f"{T - 5}:{LIMIT}:n", refs.ISSUER_ATTR: ORIGINAL_ISSUER})
    assert head == ((T - 5, LIMIT, "n"), ORIGINAL_ISSUER)


def test_a_pdt_issued_without_a_pdt_issuer_keeps_the_entrys_issuer_as_java_refs_does():
    head, own = _head_through_the_peer({refs.ISSUED_ATTR: f"{T - 5}:0:n"})
    assert head == ((T - 5, 0, "n"), own[1])
    # HLC round five, 2026-11-08 (decision E10): a present but null issuer attr makes the head
    # fall back to the entry's own stamp and issuer together.
    assert refs.head_order(f"{T}:0:n", "zPeer/w", {refs.ISSUED_ATTR: f"{T - 5}:0:n", refs.ISSUER_ATTR: None}, T) \
        == ((T, 0, "n"), "zPeer/w")


@pytest.mark.parametrize("attrs", [
    {refs.ISSUED_ATTR: f"{T - 5}:{LIMIT + 1}:n", refs.ISSUER_ATTR: ORIGINAL_ISSUER},
    {refs.ISSUED_ATTR: f"{T - 5}:007:n", refs.ISSUER_ATTR: ORIGINAL_ISSUER},
    {refs.ISSUED_ATTR: f"0{T - 5}:0:n", refs.ISSUER_ATTR: ORIGINAL_ISSUER},
    {refs.ISSUED_ATTR: "", refs.ISSUER_ATTR: ORIGINAL_ISSUER},
    {refs.ISSUED_ATTR: f"{T - 5}:0:n", refs.ISSUER_ATTR: "no-slash"},
    {refs.ISSUED_ATTR: f"{T - 5}:0:n", refs.ISSUER_ATTR: "/writer"},
    {refs.ISSUED_ATTR: f"{T - 5}:0:n", refs.ISSUER_ATTR: "zPeer/"},
    {refs.ISSUED_ATTR: f"{T - 5}:0:n", refs.ISSUER_ATTR: ""},
    {refs.ISSUER_ATTR: ORIGINAL_ISSUER},
])
def test_a_refused_pdt_attr_falls_back_to_the_entrys_own_stamp_and_issuer_together(attrs):
    head, own = _head_through_the_peer(attrs)
    assert head == own


# D6: the local node ---------------------------------------------------------------------

@pytest.mark.parametrize("node", ["", "peer/a:b", "peer/a\x00b", "peer/a\nb", "peer/a\x7fb"])
def test_the_clock_never_issues_a_stamp_whose_node_breaks_the_grammar(node):
    with pytest.raises(ValueError):
        wire.hlc_now(node, T)


def test_a_write_by_an_agent_name_with_a_colon_raises_before_anything_is_sent():
    peer, _, _ = _receiver(Identity.generate())
    with pytest.raises(ValueError):
        peer.write_entry("tasks", "T#v1", {"x": 1}, agent_name="a:b")
    assert peer.sent == [] and peer.states == {}
