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

"""The canonical stamp grammar and the far-future margin (HLC canonical stamps, 2026-11-08).

Round three's adversaries found that Java read "007" as 7 and re-encoded it away while
this client verified signatures over the raw text, so a claim signed over a non-canonical
stamp could win a client's lattice and stay unverifiable to Java. The owner's decisions:

A. A stamp is "<physical>:<logical>:<node>". Each number is "0" or a non-zero ASCII digit
   followed by ASCII digits, the physical part fits a signed 64-bit integer, the logical
   counter is 0..65536, and the node is non-empty with no colon and no control character.
   Every decode, merge, ordering and deduplication point refuses any other text, so the
   bytes a signer signed always equal the stamp's re-encoding.
B. A frame stamped past the receiver's wall + MAX_DRIFT but within a five-second skew
   margin of it is dropped and counted apart, and strikes nobody.

The peer also counts a refused state or claim after verification and once per distinct
one, judges a frame's stamp in SPEC §9's order, and compares nodes and holders by UTF-16
code units as Java's String.compareTo does. Round four (HLC round four, 2026-11-08) makes a
space delta holding a stamp outside the grammar undecodable, as Java's codec makes it,
judges signedAt like every other stamp, and counts under the Java node's names; the tests
below follow it, and test_hlc_round_four.py pins the rest."""

import pytest

from agentspaces import wire
from agentspaces.identity import Identity
from test_hlc_logical_limit import (DRIFT, GROUP, LIMIT, LONG_MAX, T, CapturingPeer, Wire, _at,
                                    _claim, _counted, _frame, _with_issued, _with_lease_stamp,
                                    _with_signed_at, _write)

MARGIN = 5_000

# Text a Java peer under decision A refuses, each beside the part it breaks.
NON_CANONICAL = {
    "leading zero physical": f"0{T}:0:n",
    "leading zero logical": f"{T}:007:n",
    "double zero logical": f"{T}:00:n",
    "double zero physical": "00:0:n",
    "physical past a long": f"{LONG_MAX + 1}:0:n",
    "nul in node": f"{T}:0:a\x00b",
    "unit separator in node": f"{T}:0:a\x1fb",
    "delete in node": f"{T}:0:a\x7fb",
    "newline in node": f"{T}:0:n\n",
    "tab in node": f"{T}:0:\tn",
    "trailing newline after logical": f"{T}:0\n:n",
}
CANONICAL = [f"{T}:0:n", "0:0:n", f"{LONG_MAX}:{LIMIT}:peer/agent", f"{T}:10:é",
             f"{T}:1:z6Mk/\U0001F600", f"{T}:65535:n with spaces"]


# (A) the grammar -------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(NON_CANONICAL))
def test_the_parser_refuses_text_outside_the_canonical_grammar(name):
    assert wire.parse_hlc(NON_CANONICAL[name]) is None
    assert wire.acceptable_hlc(NON_CANONICAL[name]) is None


def test_every_accepted_stamp_is_its_own_re_encoding():
    for stamp in CANONICAL:
        physical, logical, node = wire.acceptable_hlc(stamp)
        assert f"{physical}:{logical}:{node}" == stamp


def test_the_logical_limit_belongs_to_the_merge_rule_and_the_syntax_reads_past_it():
    assert wire.parse_hlc(f"{T}:{LIMIT + 1}:n") == (T, LIMIT + 1, "n")
    assert wire.acceptable_hlc(f"{T}:{LIMIT + 1}:n") is None


def test_reading_a_signing_time_leaves_the_limit_to_the_merge_points():
    # HLC round four, 2026-11-08 (decision D1): the fold judges signedAt against the limit;
    # reading its time for the certificate check judges the grammar alone.
    assert wire.hlc_physical(f"{T}:{LIMIT + 1}:n") == T
    for refused in (f"{T}:007:n", f"0{T}:0:n", f"{T}:0:a\x00b"):
        with pytest.raises(ValueError):
            wire.hlc_physical(refused)


# (A) through the frame handler ------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(NON_CANONICAL))
def test_the_peer_drops_and_counts_a_frame_stamped_outside_the_grammar(name):
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    env = wire.envelope(GROUP, "PING", other.peer_id, NON_CANONICAL[name], wire.ping_body(1),
                        peer.identity.peer_id)
    peer._receive(wire.encode_frame(env, other))
    assert peer.sent == []
    assert peer.malformed_frames == 1
    assert other.peer_id not in peer.members
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T}:0:{peer.identity.peer_id}"


# SPEC §9 order: parse, stale, replay, far-future, limit ------------------------------------

def test_the_filter_judges_a_stale_frame_before_its_counter():
    frames = wire.FrameFilter()
    assert not frames.admit({"from": "a", "stamp": f"{T - wire.MAX_FRAME_AGE_MILLIS - 1}:{LIMIT + 1}:a"}, T)
    assert (frames.stale, frames.logical_refused) == (1, 0)


def test_the_filter_judges_a_replay_before_its_counter():
    frames = wire.FrameFilter()
    hostile = {"from": "a", "stamp": f"{T}:{LIMIT + 1}:a"}
    assert not frames.admit(hostile, T)
    assert not frames.admit(hostile, T)
    assert (frames.logical_refused, frames.replayed) == (1, 1)


def test_the_filter_judges_a_far_future_frame_before_its_counter():
    frames = wire.FrameFilter()
    assert not frames.admit({"from": "a", "stamp": f"{T + DRIFT + MARGIN + 1}:{LIMIT + 1}:a"}, T)
    assert (frames.far_future, frames.logical_refused) == (1, 0)


def test_the_filter_never_judges_a_stamp_that_did_not_decode():
    # HLC round five, 2026-11-08 (decision E9): such a frame never decodes, so the filter
    # refuses to judge it and counts nothing.
    frames = wire.FrameFilter()
    with pytest.raises(ValueError):
        frames.admit({"from": "a", "stamp": f"0{T - wire.MAX_FRAME_AGE_MILLIS - 1}:0:a"}, T)
    assert frames.stale == 0


# (B) the far-future margin ---------------------------------------------------------------

def test_the_skew_margin_is_five_seconds():
    assert wire.FAR_FUTURE_SKEW_MARGIN_MILLIS == MARGIN


def test_a_frame_within_the_margin_is_dropped_and_counted_apart_from_far_future_ones():
    frames = wire.FrameFilter()
    assert frames.admit({"from": "a", "stamp": f"{T + DRIFT}:0:a"}, T)
    assert not frames.admit({"from": "a", "stamp": f"{T + DRIFT + 1}:0:a"}, T)
    assert not frames.admit({"from": "a", "stamp": f"{T + DRIFT + MARGIN}:0:a"}, T)
    assert (frames.far_future_skewed, frames.far_future) == (2, 0)
    assert not frames.admit({"from": "a", "stamp": f"{T + DRIFT + MARGIN + 1}:0:a"}, T)
    assert (frames.far_future_skewed, frames.far_future) == (2, 1)


def test_an_honest_peer_dragged_to_the_ceiling_loses_frames_to_a_receiver_running_behind():
    # A hostile member drags the honest peer's clock to its wall + MAX_DRIFT.
    honest = CapturingPeer(clock=_at(T))
    mallory = Identity.generate()
    honest._handle(_frame(mallory, "PING", wire.ping_body(1), honest.identity.peer_id,
                          f"{T + DRIFT}:{LIMIT}:{mallory.peer_id}"))
    dragged = wire.hlc_now(honest.identity.peer_id, T)
    assert dragged == f"{T + DRIFT}:0:{honest.identity.peer_id}"
    # A receiver whose wall runs three seconds behind drops the honest peer's frame
    # inside the margin and counts it there.
    behind = CapturingPeer(clock=_at(T - 3_000))
    behind._handle(_frame(honest.identity, "PING", wire.ping_body(2), behind.identity.peer_id, dragged))
    assert behind.sent == []
    assert (behind.frames.far_future_skewed, behind.frames.far_future) == (1, 0)
    assert wire.hlc_now(behind.identity.peer_id, T - 3_000) == f"{T - 3_000}:0:{behind.identity.peer_id}"


# Refusals counted after verification, once per distinct state or claim -----------------

def _forged(state: dict) -> dict:
    record = dict(state["record"], sig=bytes(64))
    return dict(state, record=record)


def test_a_state_with_a_non_canonical_issue_stamp_is_undecodable_on_every_offer():
    host = Identity.generate()
    honest = _write(host, T)
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    # HLC round four, 2026-11-08 (decisions D3, D5): Java's codec refuses the delta before
    # any signature check and counts each one; this peer does the same.
    hostile = _with_issued(honest, host, f"{T}:007:{host.agent('w')}")
    link.rumor(hostile)
    link.pull_resp([hostile], {})
    link.rumor(hostile)
    assert receiver.states == {}
    assert _counted(receiver) == {"deltasUndecodable": 3}
    # A verified state with a counter above the limit is refused once however often offered.
    above = _with_issued(honest, host, f"{T}:{LIMIT + 1}:{host.agent('w')}")
    link.rumor(above)
    link.rumor(above)
    assert _counted(receiver) == {"deltasUndecodable": 3, "stampsLogicalRefused": 1}


def test_a_forged_state_with_a_hostile_stamp_is_dropped_uncounted():
    host = Identity.generate()
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(_forged(_with_issued(_write(host, T), host, f"{T}:{LIMIT + 1}:{host.agent('w')}")))
    assert receiver.states == {}
    assert _counted(receiver) == {}


def test_a_signing_stamp_outside_the_grammar_never_decodes_and_one_past_the_limit_is_refused():
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=_at(T))
    write = _write(host, T, agent=agent)
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(_with_signed_at(write, agent, f"{T}:007:{agent.agent_id}"))
    assert receiver.states == {}
    assert _counted(receiver) == {"deltasUndecodable": 1}
    # HLC round four, 2026-11-08 (decision D1): signedAt is judged like every other stamp.
    link.rumor(_with_signed_at(write, agent, f"{T}:{LIMIT + 1}:{agent.agent_id}"))
    assert receiver.states == {}
    assert _counted(receiver) == {"deltasUndecodable": 1, "stampsLogicalRefused": 1}


def test_a_recordless_renewal_with_a_hostile_lease_stamp_waits_uncounted_then_is_refused_once():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    hostile = _with_lease_stamp(write, host, f"{T + 1}:{LIMIT + 1}:{host.agent('w')}", T)
    # A recordless state omits its record and writes its issuer key null, as Java writes it.
    recordless = dict({k: v for k, v in hostile.items() if k != "record"}, issuerPublicKey=None)
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(dict(recordless, entryId=entry_id))
    assert set(receiver.pending_states) == {entry_id}
    assert _counted(receiver) == {}
    # The record arrives: the pending renewal now verifies and the peer refuses it.
    link.rumor(write)
    assert receiver.states[entry_id]["leaseStamp"] == write["leaseStamp"]
    assert receiver.pending_states == {}
    assert _counted(receiver) == {"stampsLogicalRefused": 1}
    link.rumor(dict(recordless, entryId=entry_id))
    assert _counted(receiver) == {"stampsLogicalRefused": 1}


def _rival_claim(state: dict, rival: Identity, stamp: str) -> dict:
    record = state["record"]
    claim = wire.take_claim(record["entryId"], record["spaceId"], 1, stamp, rival.agent("w"),
                            0.0, T + 60_000)
    return wire.signed_claim(claim, rival)


def test_a_claim_signed_over_a_non_canonical_stamp_cannot_replace_an_honest_claim():
    host, mallory = Identity.generate(), Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(write)
    honest = _claim(write, host, f"{T}:5:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, honest))
    # "0T:0" would read as T:0, which sorts before T:5 and wins the lattice; it never
    # decodes (HLC round four, 2026-11-08, decision D3).
    hostile = _rival_claim(write, mallory, f"0{T}:0:{mallory.agent('w')}")
    link.rumor(claim=(entry_id, hostile))
    link.pull_resp([], {entry_id: hostile})
    assert receiver.claims[entry_id] == honest
    assert _counted(receiver) == {"deltasUndecodable": 2}


def test_a_forged_claim_with_a_hostile_stamp_is_dropped_uncounted():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(write)
    forged = dict(_claim(write, host, f"{T}:{LIMIT + 1}:{host.agent('w')}", T), signature=bytes(64))
    link.rumor(claim=(entry_id, forged))
    assert receiver.claims == {}
    assert _counted(receiver) == {}


# UTF-16 code unit order, as Java's String.compareTo -------------------------------------

# U+FF61 is one UTF-16 unit 0xFF61; U+1F600 is the surrogate pair 0xD83D 0xDE00. By code
# point U+1F600 sorts last; by UTF-16 code unit, as Java compares, U+FF61 does.
HIGH_BMP, ASTRAL = "｡", "\U0001F600"


def test_stamps_order_their_nodes_by_utf16_code_units():
    assert wire.hlc_tuple(f"{T}:0:{ASTRAL}") < wire.hlc_tuple(f"{T}:0:{HIGH_BMP}")


def test_claims_order_their_holders_by_utf16_code_units():
    def claim(holder):
        return wire.take_claim("e", "s", 1, f"{T}:0:n", holder, 0.0, T)
    assert wire.claim_sort_key(claim(f"p/{ASTRAL}")) < wire.claim_sort_key(claim(f"p/{HIGH_BMP}"))


def test_the_lease_register_keeps_the_stamp_java_orders_later():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(write)
    later = _with_lease_stamp(write, host, f"{T + 1}:0:{host.agent(HIGH_BMP)}", T)
    earlier = _with_lease_stamp(write, host, f"{T + 1}:0:{host.agent(ASTRAL)}", T)
    link.rumor(later)
    link.rumor(earlier)
    assert receiver.states[entry_id]["leaseStamp"] == later["leaseStamp"]


def test_the_claim_lattice_picks_the_holder_java_orders_first():
    host = Identity.generate()
    write = _write(host, T)
    record = write["record"]
    receiver = CapturingPeer(clock=_at(T))
    link = Wire(host, receiver)
    link.rumor(write)

    def signed(name):
        claim = wire.take_claim(record["entryId"], record["spaceId"], 1, f"{T}:0:{host.peer_id}",
                                host.agent(name), 0.0, T + 60_000)
        return wire.signed_claim(claim, host)
    first = signed(ASTRAL)
    link.rumor(claim=(record["entryId"], signed(HIGH_BMP)))
    link.rumor(claim=(record["entryId"], first))
    assert receiver.claims[record["entryId"]] == first
