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

"""The round-five stamp decisions (HLC round five, 2026-11-08) this client implements.

Round four left Java, Python, TypeScript and Ruby disagreeing. The owner's final rules, as
they bind this client:

E1. A stamp decodes only from a definite-length text item under its shortest length header.
E2. A hostile far-future refusal counts in stampsFarFutureRefused, and a deferral counts once
    per distinct offer in stampsFarFutureDeferred.
E4. An agent certificate no longer bounds how far a record's or a claim's signing time may
    lead; the far-future rule judges the stamp after the signatures verify. A state's signedAt
    keeps the drift ceiling.
E7. A state without its lease stamp or value decodes and merges nothing.
E5. A replica judges each offer afresh; the refused-offer memory only stops double counting.
E6. Signatures and certificate first, then revocation, then the stamp checks.
E8. Indefinite-length text decodes and re-encodes as Jackson writes it, as a Java peer
    re-encodes what it read; ill-formed UTF-8 never decodes, and no tag decodes but the
    big-number tags 2, 3 and 4 Java's codec writes for a BigInteger and a BigDecimal.
E9. A frame whose stamp is no stamp item drops at decode, before anyone checks its signature.
E11. The local node refuses a lone surrogate.
E13. A claim's signature covers the TakeClaim in Java's record field order.
E14. The refused-offer memory keeps 4096 keys and forgets the least recently offered.

HLC round six, 2026-11-08, changed three of these, and the tests below follow it: a state's
signedAt meets the far-future rule (owner ruling F4, replacing part of E4); only the wire
encoding decodes, so Java's other forms of a big number, text chunked unlike Jackson and
text under a longer head no longer decode (owner rulings F2 and F3, narrowing E1 and E8);
and a claim whose map arrives out of Java's order, or whose field is of another kind, makes
its delta undecodable (owner rulings F1 and F3, replacing E13's re-encode)."""

from decimal import Decimal

import pytest

from agentspaces import cbor, identity as identity_module, peer as peer_module, wire
from agentspaces.identity import Identity
from test_hlc_logical_limit import (DRIFT, GROUP, LIMIT, T, CapturingPeer, _claim, _with_issued,
                                    _with_lease_stamp, _with_signed_at, _write)
from test_hlc_round_four import HOUR, MARGIN, Clock, Link, _counts, _receiver, _swap

DEFER_AT = T + DRIFT + MARGIN + 1           # the first deferred physical at wall T
HOSTILE_AT = T + DRIFT + MARGIN + HOUR + 1  # the first hostile physical at wall T


# E1: the stamp item's length header ---------------------------------------------------------

def _longer(text: str, info: int) -> bytes:
    """``text`` as a definite text item under the length header ``info`` (24 to 27)."""
    raw = text.encode("utf-8")
    return bytes([0x60 | info]) + len(raw).to_bytes(1 << (info - 24), "big") + raw


# ISSUE-HlcCanonicalStamps §14.5: rows 1 to 4 decode as stamps, rows 5 to 9 do not.
CANONICAL_ROWS = {
    1: "65353A303A6E",
    2: "7819313736323536303030303030303A36353533363A7A50656572",
    3: "66353A303AC3B1",
    4: "68353A303AF09F9880",
}
LONGER_HEAD_ROWS = {
    5: "7805353A303A6E",
    6: "790005353A303A6E",
    7: "7A00000005353A303A6E",
    8: "7B0000000000000005353A303A6E",
    9: "790019313736323536303030303030303A36353533363A7A50656572",
}


@pytest.mark.parametrize("row", sorted(CANONICAL_ROWS))
def test_a_canonical_stamp_item_decodes_as_a_stamp(row):
    assert wire.parse_hlc(cbor.loads(bytes.fromhex(CANONICAL_ROWS[row]))) is not None


@pytest.mark.parametrize("row", sorted(LONGER_HEAD_ROWS))
def test_a_stamp_under_a_longer_length_header_does_not_decode(row):
    # HLC round six, 2026-11-08 (rule S3): no item decodes under a longer head than it needs.
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex(LONGER_HEAD_ROWS[row]))


def test_text_under_a_longer_header_does_not_decode_outside_a_stamp_either():
    # HLC round six, 2026-11-08 (rule S3): Java's repair of such text let a relay relabel a
    # signed carrier, so every implementation refuses it.
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex("790005") + b"hello")


SHORT_HEADS = {"one-byte length": 24, "two-byte length": 25, "four-byte length": 26, "eight-byte length": 27}


@pytest.mark.parametrize("head", sorted(SHORT_HEADS))
def test_a_frame_stamp_under_a_longer_header_drops_at_decode_unverified(head, monkeypatch):
    receiver = CapturingPeer(clock=Clock(T))
    other = Identity.generate()
    stamp = f"{T}:1:n"
    env = wire.envelope(GROUP, "PING", other.peer_id, stamp, wire.ping_body(1), receiver.identity.peer_id)
    frame = _swap(wire.encode_frame(env, other), stamp, _longer(stamp, SHORT_HEADS[head]))
    _no_signature_checks(monkeypatch)
    receiver._receive(frame)
    assert receiver.sent == [] and receiver.malformed_frames == 1


def test_a_frame_stamp_under_a_two_byte_header_where_one_byte_suffices_drops_at_decode(monkeypatch):
    receiver = CapturingPeer(clock=Clock(T))
    other = Identity.generate()
    stamp = f"{T}:1:{other.peer_id}"
    env = wire.envelope(GROUP, "PING", other.peer_id, stamp, wire.ping_body(1), receiver.identity.peer_id)
    frame = _swap(wire.encode_frame(env, other), stamp, _longer(stamp, 25))
    _no_signature_checks(monkeypatch)
    receiver._receive(frame)
    assert receiver.sent == [] and receiver.malformed_frames == 1


@pytest.mark.parametrize("head", sorted(SHORT_HEADS))
def test_every_delta_stamp_under_a_longer_header_is_undecodable(head):
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=Clock(T))
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    info = SHORT_HEADS[head]
    issued, lease, signed_at, claimed = f"{T}:0:n", f"{T + 1}:0:n", f"{T}:3:n", f"{T}:9:n"
    carriers = [
        (_with_issued(write, host, issued), issued),
        (_with_lease_stamp(write, host, lease, T), lease),
        (_with_signed_at(_write(host, T, agent=agent), agent, signed_at), signed_at),
    ]
    for state, stamp in carriers:
        link.rumor_raw(_swap(cbor.dumps({"state": state, "claimEntry": None, "claim": None}), stamp,
                             _longer(stamp, info)))
    signed = _claim(write, host, claimed, T)
    link.rumor_raw(_swap(cbor.dumps({"state": None, "claimEntry": entry_id, "claim": signed}), claimed,
                         _longer(claimed, info)))
    link.pull_raw(_swap(cbor.dumps({"states": [], "claims": {entry_id: signed}}), claimed, _longer(claimed, info)))
    assert receiver.states == {} and receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 5}


# E9: a frame whose stamp is no stamp item drops before anyone checks its signature ---------

def _no_signature_checks(monkeypatch):
    def refuse(*_):
        raise AssertionError("a frame whose stamp does not decode reached its signature check")
    monkeypatch.setattr(wire.Identity, "verify", staticmethod(refuse))


NO_STAMP_ITEMS = {
    "non-canonical text": lambda text: cbor.dumps(text.replace(":", ":0", 1)),
    "indefinite-length text": lambda text: b"\x7f" + cbor.dumps(text[:3]) + cbor.dumps(text[3:]) + b"\xff",
    "byte string": lambda text: cbor.dumps(text.encode("utf-8")),
    "number": lambda text: cbor.dumps(T),
    "null": lambda text: cbor.dumps(None),
}


@pytest.mark.parametrize("name", sorted(NO_STAMP_ITEMS))
def test_a_frame_whose_stamp_is_no_stamp_item_drops_at_decode_before_its_signature(name, monkeypatch):
    receiver = CapturingPeer(clock=Clock(T))
    other = Identity.generate()
    stamp = f"{T}:1:{other.peer_id}"
    env = wire.envelope(GROUP, "PING", other.peer_id, stamp, wire.ping_body(1), receiver.identity.peer_id)
    frame = _swap(wire.encode_frame(env, other), stamp, NO_STAMP_ITEMS[name](stamp))
    _no_signature_checks(monkeypatch)
    assert wire.decode_frame_detailed(frame) is None
    receiver._receive(frame)
    assert receiver.sent == [] and receiver.malformed_frames == 1
    assert other.peer_id not in receiver.members


def test_a_relayed_frame_whose_stamp_is_no_stamp_item_is_dropped_whole():
    receiver = CapturingPeer(clock=Clock(T))
    relay, origin = Identity.generate(), Identity.generate()
    stamp = f"{T}:1:{origin.peer_id}"
    inner = wire.envelope(GROUP, "PING", origin.peer_id, stamp, wire.ping_body(1), receiver.identity.peer_id)
    inner_frame = _swap(wire.encode_frame(inner, origin), stamp, cbor.dumps(f"0{stamp}"))
    body = cbor.dumps({"target": receiver.identity.peer_id, "frame": inner_frame})
    outer = wire.envelope(GROUP, "RELAY_FRAME", relay.peer_id, f"{T}:2:{relay.peer_id}", body,
                          receiver.identity.peer_id)
    receiver._receive(wire.encode_frame(outer, relay))
    assert receiver.sent == [] and origin.peer_id not in receiver.members


# E2 and E5: far-future refusals and deferrals count apart; the peer judges afresh ------

def test_the_counters_carry_java_names_for_far_future_refusals_and_deferrals():
    receiver, _, _ = _receiver(Identity.generate())
    assert receiver.counters() == {"framesLogicalRefused": 0, "framesFarFuture": 0,
                                   "framesFarFutureSkewed": 0, "stampsLogicalRefused": 0,
                                   "stampsFarFutureRefused": 0, "stampsFarFutureDeferred": 0,
                                   "deltasUndecodable": 0}


def test_a_hostile_far_future_state_counts_apart_and_merges_once_the_wall_catches_up():
    host = Identity.generate()
    hostile = _with_issued(_write(host, T), host, f"{HOSTILE_AT}:0:{host.agent('w')}")
    receiver, link, clock = _receiver(host)
    link.rumor(hostile)
    link.pull_resp([hostile], {})
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}
    clock.millis += 2 * HOUR
    link.pull_resp([hostile], {})
    assert set(receiver.states) == {hostile["record"]["entryId"]}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}


def test_a_hostile_far_future_claim_counts_apart_and_merges_once_the_wall_catches_up():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    link.rumor(write)
    hostile = _claim(write, host, f"{HOSTILE_AT}:0:{host.agent('w')}", T + 3 * HOUR)
    link.rumor(claim=(entry_id, hostile))
    link.pull_resp([], {entry_id: hostile})
    assert receiver.claims == {}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}
    clock.millis += 2 * HOUR
    link.rumor(claim=(entry_id, hostile))
    assert receiver.claims[entry_id] == hostile
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}


def test_a_deferral_counts_once_per_distinct_offer():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, clock = _receiver(host)
    ahead = _with_issued(write, host, f"{DEFER_AT}:0:{host.agent('w')}")
    link.rumor(ahead)
    link.pull_resp([ahead], {})
    link.rumor(dict(ahead, entryId=entry_id))
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    link.rumor(_with_issued(write, host, f"{DEFER_AT + 1}:0:{host.agent('w')}"))
    assert _counts(receiver) == {"stampsFarFutureDeferred": 2}
    link.rumor(write)
    deferred_claim = _claim(write, host, f"{DEFER_AT}:0:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, deferred_claim))
    link.pull_resp([], {entry_id: deferred_claim})
    assert _counts(receiver) == {"stampsFarFutureDeferred": 3}
    clock.millis += 1
    link.rumor(claim=(entry_id, deferred_claim))
    assert receiver.claims[entry_id] == deferred_claim
    assert _counts(receiver) == {"stampsFarFutureDeferred": 3}


def test_a_claim_past_the_margin_that_breaks_a_claim_bound_counts_no_deferral():
    # HLC round five, 2026-11-08 (decision E2): Java's mergeClaim defers a claim only when no
    # other check refuses it, so an epoch jump or a hold past MAX_CLAIM_HOLD_MILLIS counts
    # nothing in stampsFarFutureDeferred, whatever the stamp's lead.
    host = Identity.generate()
    write = _write(host, T)
    record = write["record"]
    entry_id, issuer = record["entryId"], record["issuer"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    stamp = f"{DEFER_AT}:0:{issuer}"
    held_too_long = wire.take_claim(entry_id, record["spaceId"], 1, stamp, issuer, 0.0,
                                    T + wire.MAX_CLAIM_HOLD_MILLIS + 1)
    jumped = wire.take_claim(entry_id, record["spaceId"], wire.MAX_CLAIM_EPOCH_JUMP + 1, stamp, issuer, 0.0,
                             T + 60_000)
    for claim in (held_too_long, jumped):
        link.rumor(claim=(entry_id, wire.signed_claim(claim, host)))
    assert receiver.claims == {} and _counts(receiver) == {}


def test_a_logical_refusal_is_judged_before_the_far_future_line():
    host = Identity.generate()
    hostile = _with_issued(_write(host, T), host, f"{HOSTILE_AT}:{LIMIT + 1}:{host.agent('w')}")
    receiver, link, _ = _receiver(host)
    link.rumor(hostile)
    assert _counts(receiver) == {"stampsLogicalRefused": 1}


# E4: the far-future rule judges an agent's record or claim -------------------------------

def _agent(host: Identity):
    return host.renewing_subordinate("w", "PT24H", clock=Clock(T))


def _signed_now(state: dict, agent) -> dict:
    """``state`` with its agent's signature made at the receiver's wall T, so only the
    record's stamps lead."""
    return _with_signed_at(state, agent, f"{T}:0:{agent.agent_id}")


def test_an_agent_signed_states_signing_time_meets_the_far_future_rule():
    # HLC round six, 2026-11-08 (owner ruling F4): round five kept the certificate's drift
    # ceiling on a state's signedAt, which dropped such a state unverified and uncounted. Now
    # the far-future rule judges signedAt after verification: it merges up to the drift bound
    # and the 5 s margin, waits and counts once as deferred up to an hour past that, and is
    # refused and counted beyond.
    host = Identity.generate()
    agent = _agent(host)
    write = _write(host, T, agent=agent)
    receiver, link, clock = _receiver(host)
    link.rumor(_with_signed_at(write, agent, f"{T + DRIFT + MARGIN}:0:{agent.agent_id}"))
    assert set(receiver.states) == {write["record"]["entryId"]} and _counts(receiver) == {}

    write = _write(host, T, agent=agent)
    ahead = _with_signed_at(write, agent, f"{DEFER_AT}:0:{agent.agent_id}")
    link.rumor(ahead)
    link.rumor(ahead)
    assert write["record"]["entryId"] not in receiver.states
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis += 1
    link.rumor(ahead)
    assert write["record"]["entryId"] in receiver.states

    write = _write(host, T, agent=agent)
    hostile = _with_signed_at(write, agent, f"{HOSTILE_AT + 1}:0:{agent.agent_id}")
    link.rumor(hostile)
    link.rumor(hostile)
    assert write["record"]["entryId"] not in receiver.states
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1, "stampsFarFutureRefused": 1}


def test_the_certificate_bounds_a_signing_time_by_its_window_alone():
    host = Identity.generate()
    agent = _agent(host)
    certificate, key, name = agent.certificate_covering(T), host.public_raw, agent.agent_id
    assert identity_module.verify_agent_certificate_covering(certificate, key, name, T + DRIFT + 1)
    assert not identity_module.verify_agent_certificate_covering(certificate, key, name, T - 1)


def test_an_agent_record_past_the_margin_is_deferred_and_merges_once_the_wall_catches_up():
    host = Identity.generate()
    agent = _agent(host)
    ahead = _signed_now(_write(host, DEFER_AT, agent=agent), agent)
    receiver, link, clock = _receiver(host)
    link.rumor(ahead)
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1}
    clock.millis += 2
    link.rumor(ahead)
    assert set(receiver.states) == {ahead["record"]["entryId"]}


def test_an_agent_record_an_hour_past_the_margin_is_refused_as_hostile():
    host = Identity.generate()
    agent = _agent(host)
    hostile = _signed_now(_write(host, HOSTILE_AT, agent=agent), agent)
    receiver, link, clock = _receiver(host)
    link.rumor(hostile)
    link.rumor(hostile)
    assert receiver.states == {}
    assert _counts(receiver) == {"stampsFarFutureRefused": 1}
    clock.millis += 2 * HOUR
    link.rumor(hostile)
    assert set(receiver.states) == {hostile["record"]["entryId"]}


def test_an_agent_claim_past_the_margin_is_deferred_and_one_an_hour_past_is_hostile():
    host, taker = Identity.generate(), Identity.generate()
    write = _write(host, T)
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    agent = _agent(taker)
    receiver, link, clock = _receiver(host)
    link.rumor(write)

    def agent_claim(epoch, physical):
        claim = wire.take_claim(entry_id, space_id, epoch, f"{physical}:0:{agent.agent_id}", agent.agent_id,
                                0.0, T + 3 * HOUR)
        return wire.signed_claim(claim, taker, agent)

    deferred, hostile = agent_claim(1, DEFER_AT), agent_claim(2, HOSTILE_AT)
    link.rumor(claim=(entry_id, deferred))
    link.rumor(claim=(entry_id, hostile))
    assert receiver.claims == {}
    assert _counts(receiver) == {"stampsFarFutureDeferred": 1, "stampsFarFutureRefused": 1}
    clock.millis += 1
    link.rumor(claim=(entry_id, deferred))
    assert receiver.claims[entry_id] == deferred


def test_an_agent_certificate_still_bounds_its_window():
    # The certificate's own validity window keeps judging the signing time: a record its agent
    # stamped after the certificate lapsed never verifies, so nothing counts it.
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT1H", clock=Clock(T))
    lapsed = _with_issued(_write(host, T, agent=agent), agent, f"{T + 2 * HOUR}:0:{agent.agent_id}")
    receiver, link, _ = _receiver(host, T + 2 * HOUR)
    link.rumor(lapsed)
    assert receiver.states == {} and _counts(receiver) == {}


# E7: a state without its lease stamp or value decodes and merges nothing -----------------

def test_a_state_without_its_lease_stamp_or_value_merges_nothing_and_counts_nothing():
    # HLC round five, 2026-11-08 (decision E7): such a state decodes, and Java's mergeState and
    # Ruby's fold_state drop it before any judgement, since a lease register holds nothing
    # without its stamp and value; with or without its record it merges and counts nothing.
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    for field in ("leaseStamp", "leaseValue"):
        unleased = wire.sign_state(dict(write, **{field: None}), host)
        link.rumor(unleased)
        link.rumor(dict({key: value for key, value in unleased.items() if key != "record"}, entryId=entry_id))
    assert receiver.states == {} and receiver.pending_states == {} and _counts(receiver) == {}
    link.rumor(write)
    assert set(receiver.states) == {entry_id}


# E6: revocation before the stamp checks -------------------------------------------------

def _revoking(receiver, revoked: Identity):
    receiver.revocations.refuses = lambda agent, key, at: str(agent).startswith(revoked.peer_id + "/")


def test_a_revoked_issuers_state_counts_nothing_whatever_its_stamps():
    host = Identity.generate()
    write = _write(host, T)
    receiver, link, _ = _receiver(host)
    _revoking(receiver, host)
    link.rumor(_with_issued(write, host, f"{T}:{LIMIT + 1}:{host.agent('w')}"))
    link.rumor(_with_issued(write, host, f"{HOSTILE_AT}:0:{host.agent('w')}"))
    link.rumor(_with_issued(write, host, f"{DEFER_AT}:0:{host.agent('w')}"))
    assert receiver.states == {} and _counts(receiver) == {}


def test_a_revoked_holders_claim_counts_nothing_whatever_its_stamp():
    host, taker = Identity.generate(), Identity.generate()
    write = _write(host, T)
    entry_id, space_id = write["record"]["entryId"], write["record"]["spaceId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    _revoking(receiver, taker)
    for epoch, stamp in enumerate((f"{T}:{LIMIT + 1}:n", f"{HOSTILE_AT}:0:n", f"{DEFER_AT}:0:n"), start=1):
        claim = wire.take_claim(entry_id, space_id, epoch, stamp, taker.agent("t"), 0.0, T + 3 * HOUR)
        link.rumor(claim=(entry_id, wire.signed_claim(claim, taker)))
    assert receiver.claims == {} and _counts(receiver) == {}


# E8: CBOR outside the stamp positions ---------------------------------------------------

JACKSON_CHUNK = 3996  # the UTF-16 units Jackson's CBORGenerator writes per chunk of long text


def _jackson_text(text: str) -> bytes:
    """``text`` as Jackson 2.21 writes a string longer than 3996 UTF-16 units: an
    indefinite-length text item of definite chunks of 3996 units, one fewer where the chunk
    would end on a high surrogate, then the rest; measured against jackson-dataformat-cbor."""
    units = text.encode("utf-16-be", "surrogatepass")
    out, start = bytearray(b"\x7f"), 0
    while (len(units) - start) // 2 > JACKSON_CHUNK:
        end = start + 2 * JACKSON_CHUNK
        if 0xD800 <= int.from_bytes(units[end - 2:end], "big") <= 0xDBFF:
            end -= 2
        out += cbor.dumps(units[start:end].decode("utf-16-be"))
        start = end
    out += cbor.dumps(units[start:].decode("utf-16-be")) + b"\xff"
    return bytes(out)


def _java_signed_frame(sender: Identity, env: dict, field: str, long_text: str) -> bytes:
    """A frame as a Java peer signs it when ``env[field]`` holds ``long_text``."""
    placeholder = "PLACEHOLDER-FOR-THE-LONG-TEXT"
    canonical = _swap(cbor.dumps(dict(env, **{field: placeholder})), placeholder, _jackson_text(long_text))
    return (b"\xbf" + cbor.dumps("envelope") + canonical + cbor.dumps("senderPublicKey")
            + cbor.dumps(sender.public_raw) + cbor.dumps("signature") + cbor.dumps(sender.sign(canonical))
            + b"\xff")


@pytest.mark.parametrize("long_text", ["g" * 8000, "a" * 3995 + "\U0001F600" + "é" * 4000])
def test_a_frame_holding_javas_long_text_verifies_as_java_signed_it(long_text):
    sender = Identity.generate()
    env = wire.envelope(GROUP, "PING", sender.peer_id, f"{T}:0:{sender.peer_id}", wire.ping_body(1), None)
    decoded = wire.decode_frame(_java_signed_frame(sender, env, "group", long_text))
    assert decoded is not None and decoded["group"] == long_text


def test_a_long_string_encodes_as_jackson_writes_it():
    # Measured against jackson-dataformat-cbor 2.21: definite up to 3996 UTF-16 units, then
    # chunks of 3996 units, one fewer where a surrogate pair would straddle two chunks.
    assert cbor.dumps("x" * 3996) == bytes.fromhex("790f9c") + b"x" * 3996
    for text in ("x" * 3997, "x" * 7992, "x" * 9000, "a" * 3995 + "\U0001F600" + "b" * 10, "é" * 5000,
                 "\u20ac" * 4000 + "\U0001F600" * 3000):
        assert cbor.dumps(text) == _jackson_text(text)
    assert cbor.dumps({"k" * 4000: 1}) == b"\xbf" + _jackson_text("k" * 4000) + b"\x01\xff"


def test_a_python_signed_long_string_round_trips_and_verifies():
    sender = Identity.generate()
    env = wire.envelope("g" * 9000, "PING", sender.peer_id, f"{T}:0:{sender.peer_id}", wire.ping_body(1), None)
    frame = wire.encode_frame(env, sender)
    assert _jackson_text("g" * 9000) in frame
    assert wire.decode_frame(frame)["group"] == "g" * 9000


def test_only_jacksons_chunks_of_a_long_text_decode():
    # HLC round six, 2026-11-08 (rule S6): Java's own chunks come back byte for byte, and no
    # other chunking decodes, a short text in chunks included.
    jackson = _jackson_text("x" * 9000)
    assert cbor.dumps(cbor.loads(jackson)) == jackson
    for raw in (b"\x7f\x62ab\x61c\xff", b"\x7f\xff", b"\x7f" + cbor.dumps("x" * 4000) + cbor.dumps("y") + b"\xff"):
        with pytest.raises(ValueError):
            cbor.loads(raw)


def test_a_signature_over_text_chunked_unlike_jackson_never_verifies():
    sender = Identity.generate()
    env = wire.envelope(GROUP, "PING", sender.peer_id, f"{T}:0:{sender.peer_id}", wire.ping_body(1), None)
    odd = b"\x7f" + cbor.dumps(GROUP[:2]) + cbor.dumps(GROUP[2:]) + b"\xff"
    canonical = _swap(cbor.dumps(env), GROUP, odd)
    frame = (b"\xbf" + cbor.dumps("envelope") + canonical + cbor.dumps("senderPublicKey")
             + cbor.dumps(sender.public_raw) + cbor.dumps("signature") + cbor.dumps(sender.sign(canonical))
             + b"\xff")
    assert wire.decode_frame(frame) is None


TAGGED = {
    "tag 0 over text": "c06161",
    "tag 42 over a byte string (CID link)": "d82a420001",
    "tag 55799 over a map": "d9d9f7bfff",
    "a tag nested in a map value": "bf616bc00aff",
    "tag 2 over text": "c26161",
    "tag 3 over an indefinite-length byte string": "c35f4101ff",
    "tag 4 over a three-element array": "c483000000",
    "tag 4 over an indefinite-length array": "c49f0000ff",
    "tag 4 over a map": "c4bfff",
    "tag 4 whose exponent is a bignum": "c482c2410100",
    "tag 4 whose mantissa is a double": "c48200fb3ff0000000000000",
    "tag 4 whose mantissa is a decimal fraction": "c48200c4820000",
    "tag 4 whose mantissa is a bignum under a two-byte tag head": "c48200d8024105",
    "tag 4 whose exponent runs past a Java int": "c4821a8000000001",
    "tag 4 whose exponent runs below a Java int": "c4823a8000000001",
}


@pytest.mark.parametrize("name", sorted(TAGGED))
def test_no_tag_but_the_big_number_tags_decodes_anywhere(name):
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex(TAGGED[name]))


# HLC round six, 2026-11-08 (rule S9): each big number has one encoding. A bignum holds a
# value outside Java's long range as the minimal bytes of its magnitude, and a decimal is
# stripped of its trailing zeros with its exponent inside -(2^31-1) to 2^31-1. These rows
# decode to exactly the value Java reads and re-encode to the same bytes.
BIG_NUMBERS = {
    "c249400000000000000000": 2 ** 70,
    "c349400000000000000000": -(2 ** 70),
    "c249010000000000000000": 2 ** 64,
    "c349010000000000000001": -(2 ** 64) - 1,
    "c48221187d": Decimal("1.25"),
    "c4820305": Decimal("5E+3"),
    "c4822024": Decimal("-0.5"),
    "c4820320": Decimal("-1E+3"),
    "c482211b0000010000000001": Decimal(2 ** 40 + 1).scaleb(-2),
    "c48221c249400000000000000001": Decimal(2 ** 70 + 1).scaleb(-2),
    "c482003b7fffffffffffffff": Decimal(-(2 ** 63)),
    "c48200c249008000000000000000": Decimal(2 ** 63),
    "c4823a7ffffffe01": Decimal("1E-2147483647"),
    "c4821a7fffffff01": Decimal("1E+2147483647"),
}


@pytest.mark.parametrize("raw", sorted(BIG_NUMBERS))
def test_a_big_number_decodes_to_the_value_java_reads_and_re_encodes_to_its_bytes(raw):
    value = cbor.loads(bytes.fromhex(raw))
    expected = BIG_NUMBERS[raw]
    assert type(value) is type(expected) and value == expected
    assert cbor.dumps(expected).hex() == raw and cbor.dumps(value).hex() == raw


# What Jackson wrote before the round six encoder changes (JC-1, JC-2), each a value with
# another encoding, refused at decode (HLC round six, 2026-11-08, rules S3 and S9).
NON_CANONICAL_BIG_NUMBERS = {
    "c24105": "5, a long, as a bignum",
    "c2420080": "128 as a bignum",
    "c24180": "a bignum with its top bit set",
    "c248ffffffffffffffff": "a bignum whose bytes are no magnitude",
    "c240": "an empty bignum",
    "c341ff": "a bignum whose bytes are no magnitude",
    "d8024105": "tag 2 under a one-byte head",
    "d900034105": "tag 3 under a two-byte head",
    "c482201905dc": "150.0 with its trailing zero",
    "c48221c24105": "a decimal whose mantissa is a long written as a bignum",
    "c48221c240": "a decimal zero with an exponent",
    "c4821b000000000000000101": "a mantissa under a longer head than it needs",
    "c4823a7fffffff01": "the exponent -2^31, which Jackson negates into 2^31",
}


@pytest.mark.parametrize("raw", sorted(NON_CANONICAL_BIG_NUMBERS))
def test_a_big_number_in_another_encoding_does_not_decode(raw):
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex(raw))


def test_an_integer_past_javas_long_range_encodes_as_a_bignum():
    # HLC round six, 2026-11-08 (rule S4): a plain integer holds a Java long and nothing more.
    assert cbor.dumps(2 ** 63 - 1).hex() == "1b7fffffffffffffff"
    assert cbor.dumps(-(2 ** 63)).hex() == "3b7fffffffffffffff"
    assert cbor.dumps(2 ** 64 - 1).hex() == "c24900ffffffffffffffff"
    assert cbor.dumps(-(2 ** 64)).hex() == "c349010000000000000000"


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"),
                                   Decimal("1E+2147483648"), Decimal("1E-2147483648")], ids=str)
def test_a_decimal_outside_the_encoding_never_encodes(value):
    with pytest.raises(ValueError):
        cbor.dumps(value)


# A Java entry payload holding a BigInteger count past a long and a BigDecimal price, as the
# round six encoding writes it; this client reads both into exact types (HLC round six,
# 2026-11-08, owner ruling F2).
JAVA_MONEY_PAYLOAD = "bf65636f756e74c249400000000000000000657072696365c48221187dff"


def test_a_java_payload_holding_a_big_integer_and_a_big_decimal_decodes():
    raw = bytes.fromhex(JAVA_MONEY_PAYLOAD)
    assert cbor.loads(raw) == {"count": 2 ** 70, "price": Decimal("1.25")}
    assert cbor.dumps(cbor.loads(raw)) == raw


def _claim_delta_with(field: str, honest: bytes, raw: bytes) -> tuple:
    """A host's write, and its signed claim as a rumored delta whose ``field`` value arrives
    as the item ``raw`` in place of the plain item ``honest`` the signature covers."""
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    signed = _claim(write, host, f"{T}:1:{host.agent('w')}", T)
    delta = cbor.dumps({"state": None, "claimEntry": entry_id, "claim": signed})
    tagged = delta.replace(cbor.dumps(field) + honest, cbor.dumps(field) + raw, 1)
    assert tagged != delta
    return host, write, entry_id, tagged


@pytest.mark.parametrize("field,honest,raw", [
    ("epoch", cbor.dumps(1), "c24101"),
    ("epoch", cbor.dumps(1), "c4820001"),
    ("bid", cbor.dumps(0.0), "c4820000"),
    ("bid", cbor.dumps(0.0), "00"),
    ("bid", cbor.dumps(0.0), "fa00000000"),
], ids=["epoch as a bignum", "epoch as a decimal", "bid as a decimal", "bid as an integer", "bid as a float32"])
def test_a_claim_field_of_another_cbor_type_makes_the_delta_undecodable(field, honest, raw):
    # HLC round six, 2026-11-08 (owner ruling F1): Java's coercions read these, and every
    # implementation now refuses them, so the delta counts in deltasUndecodable.
    host, write, entry_id, tagged = _claim_delta_with(field, honest, bytes.fromhex(raw))
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    link.rumor_raw(tagged)
    assert entry_id not in receiver.claims and _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("bid", [float("inf"), float("-inf"), float("nan")], ids=["inf", "-inf", "nan"])
def test_a_bid_that_is_no_finite_double_makes_the_delta_undecodable(bid):
    # Java's TakeClaim refuses a bid that is not finite (HLC round six, 2026-11-08, rule P2).
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    signed = _claim(write, host, f"{T}:1:{host.agent('w')}", T)
    claim = dict(signed["claim"], bid=bid)
    signed = dict(signed, claim=claim, signature=host.sign(cbor.dumps(claim)))
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    link.rumor(claim=(entry_id, signed))
    assert entry_id not in receiver.claims and _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("raw", ["62c1ae", "63e081ae", "63eda080", "61ff", "6280", "bf62c0ba01ff"])
def test_ill_formed_utf8_in_any_text_never_decodes(raw):
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex(raw))


# E11: the local node --------------------------------------------------------------------

@pytest.mark.parametrize("node", ["peer/a\ud800b", "peer/a\udfff", "\udbff"])
def test_the_clock_refuses_a_node_holding_a_lone_surrogate(node):
    with pytest.raises(ValueError):
        wire.hlc_now(node, T)


# E13: a claim's signature covers Java's field order ----------------------------------------

def _reordered(claim: dict) -> dict:
    return {key: claim[key] for key in reversed(list(claim))}


def test_a_claim_whose_fields_arrive_out_of_javas_order_makes_the_delta_undecodable():
    # HLC round six, 2026-11-08 (owner ruling F3, rule P1): round five verified such a claim
    # over Java's order (decision E13); its carrier no longer re-encodes to the bytes received.
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    signed = _claim(write, host, f"{T}:1:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, dict(signed, claim=_reordered(signed["claim"]))))
    assert entry_id not in receiver.claims and _counts(receiver) == {"deltasUndecodable": 1}
    link.rumor(claim=(entry_id, signed))
    assert receiver.claims[entry_id] == signed


def test_signed_claim_signs_and_carries_javas_field_order():
    host = Identity.generate()
    claim = wire.take_claim("e", "s", 1, f"{T}:1:{host.agent('w')}", host.agent("w"), 0.0, T + 1)
    signed = wire.signed_claim(_reordered(claim), host)
    assert list(signed["claim"]) == list(claim)
    assert Identity.verify(host.public_raw, cbor.dumps(claim), signed["signature"])


# E14: the refused-offer memory --------------------------------------------------------------

def test_the_refused_offer_memory_forgets_the_least_recently_offered_key():
    receiver, _, _ = _receiver(Identity.generate())
    capacity = peer_module.REFUSED_STAMPS_CAPACITY
    assert capacity == 4096
    receiver._count_refused(("kept",), "stamps_logical_refused")
    for index in range(capacity - 1):
        receiver._count_refused(("other", index), "stamps_logical_refused")
    receiver._count_refused(("kept",), "stamps_logical_refused")  # offered again: most recent
    receiver._count_refused(("pushes one out",), "stamps_logical_refused")
    assert receiver.stamps_logical_refused == capacity + 1
    receiver._count_refused(("kept",), "stamps_logical_refused")
    assert receiver.stamps_logical_refused == capacity + 1
    receiver._count_refused(("other", 0), "stamps_logical_refused")
    assert receiver.stamps_logical_refused == capacity + 2


def test_the_deferred_offer_memory_forgets_the_least_recently_offered_key():
    receiver, _, _ = _receiver(Identity.generate())
    capacity = peer_module.REFUSED_STAMPS_CAPACITY
    receiver._count_deferred(("kept",))
    for index in range(capacity - 1):
        receiver._count_deferred(("other", index))
    receiver._count_deferred(("kept",))
    receiver._count_deferred(("pushes one out",))
    receiver._count_deferred(("kept",))
    assert receiver.stamps_far_future_deferred == capacity + 1
    receiver._count_deferred(("other", 0))
    assert receiver.stamps_far_future_deferred == capacity + 2


def test_a_claim_whose_bid_is_null_never_verifies_and_makes_its_delta_undecodable():
    # HLC round six, 2026-11-08 (owner ruling F1, rule P4): Java's codec read a null bid as
    # 0.0 (round five, decision E13); a double field is never null now.
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    signed = _claim(write, host, f"{T}:1:{host.agent('w')}", T)
    arrived = dict(signed, claim=dict(signed["claim"], bid=None))
    assert not wire.verify_claim_proof(arrived)
    link.rumor(claim=(entry_id, arrived))
    assert entry_id not in receiver.claims and _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("bid", [True, False, [1], "not a number"])
def test_a_claim_whose_bid_no_double_reads_never_verifies(bid):
    # Java's codec refuses a boolean bid, so the claim never folds there or here (HLC round
    # five, 2026-11-08, decision E13).
    host = Identity.generate()
    signed = _claim(_write(host, T), host, f"{T}:1:{host.agent('w')}", T)
    assert not wire.verify_claim_proof(dict(signed, claim=dict(signed["claim"], bid=bid)))


# A tag in a map key's place: Java's codec reads none as a key, so no implementation decodes
# one there (HLC round five, 2026-11-08, decision E8).
TAGGED_KEYS = {
    "tag 2 as a key": "bfc2494000000000000000006178ff",
    "tag 4 over [0, 1] as a key": "bfc48200016178ff",
    "tag 3 as a nested map's key": "bf6161bfc3494000000000000000006178ffff",
}


@pytest.mark.parametrize("name", sorted(TAGGED_KEYS))
def test_a_tag_never_decodes_as_a_map_key(name):
    with pytest.raises(ValueError):
        cbor.loads(bytes.fromhex(TAGGED_KEYS[name]))


def test_a_big_number_tag_still_decodes_as_a_map_value():
    assert cbor.loads(bytes.fromhex("bf6178c249400000000000000000ff")) == {"x": 2 ** 70}


# Claim fields Java's TakeClaim never decodes (Jackson 2.21.7 under CborCodec, read on
# 2026-11-08): Java counts the delta that carries one in deltasUndecodable before any proof
# check, and so does this client (HLC round five, 2026-11-08, conformance rows on typed claim
# fields). Each claim is re-signed over its altered fields, so only the decode refuses it.
_ABSENT = object()
CLAIM_FIELDS_JAVA_REFUSES = {
    "epoch 0": {"epoch": 0},
    "epoch -1": {"epoch": -1},
    "epoch past a long": {"epoch": 1 << 63},
    "epoch 2^64": {"epoch": 1 << 64},
    "epoch null": {"epoch": None},
    "epoch absent": {"epoch": _ABSENT},
    "epoch a boolean": {"epoch": True},
    "epoch a byte string": {"epoch": b"\x01"},
    "epoch an array": {"epoch": [1]},
    "epoch a map": {"epoch": {}},
    "expiry past a long": {"expiresAtMillis": 1 << 63},
    "expiry below a long": {"expiresAtMillis": -(1 << 63) - 1},
    "expiry a boolean": {"expiresAtMillis": False},
    "expiry a byte string": {"expiresAtMillis": b"\x01"},
    "expiry an array": {"expiresAtMillis": [1]},
    "bid a boolean": {"bid": True},
    "bid a byte string": {"bid": b"\x00"},
    "bid an array": {"bid": [0]},
    "bid a map": {"bid": {}},
    "bid an infinity": {"bid": float("inf")},
    "bid NaN": {"bid": float("nan")},
    "bid an integer past every double": {"bid": 10 ** 400},
    "bid a decimal past every double": {"bid": Decimal("1E+1000")},
    "holder null": {"holder": None},
    "holder without a slash": {"holder": "pw"},
    "holder with a second slash": {"holder": "p/w/x"},
    "entryId null": {"entryId": None},
    "entryId empty": {"entryId": ""},
    "spaceId null": {"spaceId": None},
    "spaceId empty": {"spaceId": ""},
    "spaceId an integer": {"spaceId": 3},
    # HLC round six, 2026-11-08 (owner ruling F1, rules P1 and P4): Java coerced these, and
    # every implementation now refuses them.
    "bid absent": {"bid": _ABSENT},
    "bid null": {"bid": None},
    "bid a decimal": {"bid": Decimal("1E-999")},
    "bid an integer": {"bid": 0},
    "bid text": {"bid": "0"},
    "epoch a double": {"epoch": 1.0},
    "epoch text": {"epoch": "1"},
    "expiry null": {"expiresAtMillis": None},
    "expiry absent": {"expiresAtMillis": _ABSENT},
    "expiry a double": {"expiresAtMillis": 1.5},
    "holder a byte string": {"holder": b"p/w"},
    "holder with a colon in its local name": {"holder": "p/w:x"},
}


def _re_signed_claim(host: Identity, write: dict, changes: dict) -> dict:
    """The host's signed claim on ``write`` with ``changes`` applied in place, a value of
    ``_ABSENT`` dropping its field, and the signature re-made over exactly those bytes."""
    signed = _claim(write, host, f"{T}:1:{host.agent('w')}", T)
    claim = dict(signed["claim"])
    for field, value in changes.items():
        if value is _ABSENT:
            del claim[field]
        else:
            claim[field] = value
    return dict(signed, claim=claim, signature=host.sign(cbor.dumps(claim)))


@pytest.mark.parametrize("name", sorted(CLAIM_FIELDS_JAVA_REFUSES))
def test_a_rumored_claim_whose_field_java_never_decodes_counts_its_delta_undecodable(name):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    link.rumor(claim=(entry_id, _re_signed_claim(host, write, CLAIM_FIELDS_JAVA_REFUSES[name])))
    assert receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("name", sorted(CLAIM_FIELDS_JAVA_REFUSES))
def test_a_pulled_claim_whose_field_java_never_decodes_counts_its_sync_delta_undecodable(name):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.pull_resp([write], {entry_id: _re_signed_claim(host, write, CLAIM_FIELDS_JAVA_REFUSES[name])})
    assert receiver.states == {} and receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}


def test_a_claim_java_never_decodes_drops_the_state_its_delta_carries():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link, _ = _receiver(host)
    link.rumor(write, claim=(entry_id, _re_signed_claim(host, write, {"epoch": 0})))
    assert receiver.states == {} and receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}


@pytest.mark.parametrize("changes", [{"epoch": (1 << 63) - 1}, {"expiresAtMillis": -(1 << 63)},
                                     {"bid": -0.0}, {"bid": 1e308}],
                         ids=["largest epoch", "least expiry", "bid -0.0", "largest bid"])
def test_the_claim_fields_java_decodes_at_each_edge_still_decode(changes):
    host = Identity.generate()
    write = _write(host, T)
    signed = _re_signed_claim(host, write, changes)
    delta = cbor.dumps({"state": None, "claimEntry": write["record"]["entryId"], "claim": signed})
    assert wire.decode_delta(delta) is not None


# The conformance probe's big-number items in a claim's epoch, expiry and bid, each in place of
# the plain item the signature covers: Java reads each into a value its TakeClaim refuses
# (HLC round five, 2026-11-08, decision E8 and the conformance rows on typed claim fields).
CLAIM_ITEMS_JAVA_REFUSES = {
    "epoch -1 as tag 2 over ff": ("epoch", "c241ff"),
    "epoch -1 as tag 3 over 01": ("epoch", "c34101"),
    "epoch 128 sent as tag 2 over 80, which reads -128": ("epoch", "c24180"),
    "expiresAtMillis 2^64 as tag 2": ("expiresAtMillis", "c249010000000000000000"),
    "bid 1E+1000 as tag 4": ("bid", "c4821903e801"),
}


@pytest.mark.parametrize("name", sorted(CLAIM_ITEMS_JAVA_REFUSES))
def test_a_claim_item_java_reads_out_of_range_counts_its_delta_undecodable(name):
    field, raw = CLAIM_ITEMS_JAVA_REFUSES[name]
    host = Identity.generate()
    write = _write(host, T)
    honest = cbor.dumps(_claim(write, host, f"{T}:1:{host.agent('w')}", T)["claim"][field])
    _, write, entry_id, tagged = _claim_delta_with(field, honest, bytes.fromhex(raw))
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    link.rumor_raw(tagged)
    assert receiver.claims == {}
    assert _counts(receiver) == {"deltasUndecodable": 1}
