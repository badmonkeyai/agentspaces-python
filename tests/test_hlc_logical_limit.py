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

"""The HLC stamp rule (HLC logical counter, 2026-11-08 (Rust team report)).
One signed stamp with a logical counter at the top of its type pinned the Java clock for up
to ten minutes, and this client copied the hostile counter into every later stamp, which a
peer that applies the rule refuses. Round two found that a negative, fractional, empty or
missing counter passed this client's checks and poisoned its clock the same way, and that a
carry after merging a stamp at the drift cap left the cap behind.

Every implementation now accepts a stamp only when its physical part is a non-negative
integer, its logical counter an integer from 0 to 65536, and its node part present. Each
merge and ordering point (frames, the replay filter, folded records, lease and signing
stamps, folded claims) refuses any other stamp and counts the refusal. This client keeps
no strikes. A local counter past 65536 carries into the next millisecond, and the clock
clamps a remote physical at wall + MAX_DRIFT - 1, so a carry after merging lands at most
at wall + MAX_DRIFT, where a receiver's far-future check still admits it.

Round three (HLC canonical stamps, 2026-11-08) narrows the grammar to one spelling per
stamp, judges a signing stamp by the grammar alone, and counts a refusal after
verification once per distinct state or claim; test_hlc_canonical_stamps.py pins it."""

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.peer import Peer

GROUP = "zPyHlcLogical"
LIMIT = 65536  # the wire rule every implementation shares
JAVA_INT_MAX = 2**31 - 1  # the counter of the reported attack
LONG_MAX = 2**63 - 1  # the most any peer's counter type holds
T = 1_800_000_000_000
DRIFT = wire.MAX_HLC_SKEW_MILLIS

# Counters a Java peer refuses as malformed: a sign, a fraction, an exponent, nothing at
# all, whitespace, digits outside ASCII, and a value past Integer.MAX_VALUE.
HOSTILE_COUNTERS = {
    "negative": "-1",
    "far negative": "-" + "9" * 300,
    "fractional": "1.5",
    "exponent": "1e3",
    "plus sign": "+1",
    "empty": "",
    "whitespace": " 1",
    "underscore": "1_0",
    "non-ascii digit": "١",
    "past int": str(2**31),
}
# Physical parts a Java peer refuses as malformed.
HOSTILE_PHYSICALS = {
    "fractional": "{t}.5",
    "exponent": "18e11",
    "plus sign": "+{t}",
    "empty": "",
}


def _tuple(stamp: str):
    physical, logical, node = stamp.split(":", 2)
    return int(physical), int(logical), node


def _node() -> str:
    return Identity.generate().peer_id


class CapturingPeer(Peer):
    def __init__(self, identity=None, clock=None):
        super().__init__(identity or Identity.generate(), GROUP, clock=clock)
        self.sent = []

    def _send(self, kind, body, to=None):
        self.sent.append((kind, body, to))


def _at(millis):
    return lambda: millis / 1000


def _frame(sender: Identity, kind: str, body: bytes, to: str, stamp: str) -> dict:
    env = wire.envelope(GROUP, kind, sender.peer_id, stamp, body, to)
    return wire.decode_frame(wire.encode_frame(env, sender))


class Wire:
    """Delivers signed frames from ``sender`` to ``receiver`` through its frame handler,
    each under a fresh honest stamp so the replay filter admits every one."""

    def __init__(self, sender: Identity, receiver: CapturingPeer):
        self.sender, self.receiver, self.logical = sender, receiver, 0

    def deliver(self, kind: str, body: bytes) -> None:
        self.logical += 1
        stamp = f"{T}:{self.logical}:{self.sender.peer_id}"
        self.receiver._handle(_frame(self.sender, kind, body, self.receiver.identity.peer_id, stamp))

    def rumor(self, state: dict | None = None, claim: tuple | None = None) -> None:
        entry_id, signed = claim if claim is not None else (None, None)
        delta = cbor.dumps({"state": state, "claimEntry": entry_id, "claim": signed})
        self.deliver("RUMOR", wire.rumor_body("space:tasks", f"w:{self.logical}", 6, delta))

    def pull_resp(self, states: list, claims: dict) -> None:
        sync = cbor.dumps({"states": states, "claims": claims})
        self.deliver("PULL_RESP", cbor.dumps({"deltas": {"space:tasks": sync}}))


def _write(host: Identity, now_ms: int, agent=None) -> dict:
    """A signed write as another member gossips it."""
    _, body = wire.entry_delta("tasks", GROUP, "T#v1", cbor.dumps({"x": 1}), host, "w",
                               60_000, agent=agent, now_ms=now_ms)
    return cbor.loads(cbor.loads(body)["payload"])["state"]


def _with_issued(state: dict, host: Identity, issued: str) -> dict:
    """The same write re-signed by its issuer under another issue stamp."""
    record = dict(state["record"], issued=issued)
    record["sig"] = host.sign(cbor.dumps(wire.sign_view_of(record)))
    return dict(state, record=record)


def _with_lease_stamp(state: dict, host: Identity, lease_stamp, now_ms: int) -> dict:
    """A renewal of ``state`` stamped ``lease_stamp``, re-signed by its issuer."""
    renewed = dict(state, leaseStamp=lease_stamp,
                   leaseValue={"holder": state["record"]["issuer"],
                               "expiresAtMillis": now_ms + 600_000, "kind": "WRITE"})
    return wire.sign_state(renewed, host)


def _with_signed_at(state: dict, agent, signed_at: str) -> dict:
    """An agent-signed state re-signed by that agent under another signing stamp."""
    record = state["record"]
    view = wire.state_sign_view(record["spaceId"], record["entryId"], state["adds"], state["removes"],
                                state["leaseStamp"], state["leaseValue"], bool(state["completed"]),
                                state["signer"], signed_at)
    return dict(state, signedAt=signed_at, stateSig=agent.sign(cbor.dumps(view)))


def _claim(state: dict, host: Identity, stamp: str, now_ms: int) -> dict:
    record = state["record"]
    claim = wire.take_claim(record["entryId"], record["spaceId"], 1, stamp, record["issuer"],
                            0.0, now_ms + 60_000)
    return wire.signed_claim(claim, host)


# (a) the strict parser -------------------------------------------------------------------

def test_the_shared_limit_is_two_to_the_sixteenth():
    assert wire.LOGICAL_LIMIT == LIMIT


def test_the_parser_reads_only_the_canonical_form():
    assert wire.acceptable_hlc(f"{T}:0:n") == (T, 0, "n")
    assert wire.acceptable_hlc(f"{T}:{LIMIT}:peer/agent") == (T, LIMIT, "peer/agent")
    assert wire.acceptable_hlc(f"{LONG_MAX}:0:n") == (LONG_MAX, 0, "n")
    for name, counter in HOSTILE_COUNTERS.items():
        assert wire.acceptable_hlc(f"{T}:{counter}:n") is None, name
    for name, physical in HOSTILE_PHYSICALS.items():
        assert wire.acceptable_hlc(f"{physical.format(t=T)}:0:n") is None, name
    for malformed in (f"{T}:0:", f"{T}:0", f"{T}", f"{T}:0:a:b", f"{LONG_MAX + 1}:0:n",
                      f"-{T}:0:n", f"{T}:{LIMIT + 1}:n", None, 5, b"1:0:n"):
        assert wire.acceptable_hlc(malformed) is None, malformed
    # The syntax alone follows Java's HlcTimestamp.parse; the limit is the merge rule.
    assert wire.parse_hlc(f"{T}:{JAVA_INT_MAX}:n") == (T, JAVA_INT_MAX, "n")
    assert wire.parse_hlc(f"{T}:{JAVA_INT_MAX + 1}:n") is None


def test_hlc_physical_raises_on_a_stamp_outside_the_grammar():
    assert wire.hlc_physical(f"{T}:3:n") == T
    for refused in (f"{T}.5:0:n", f"{T}:-1:n", None):
        with pytest.raises(ValueError):
            wire.hlc_physical(refused)


# (b) the clock -------------------------------------------------------------------------

def test_a_remote_stamp_above_the_limit_never_reaches_the_clock():
    for hostile_logical in (JAVA_INT_MAX, LONG_MAX, LIMIT + 1):
        node = _node()
        assert wire.hlc_now(node, T) == f"{T}:0:{node}"
        # Physical just under wall + max drift: the physical cap alone lets it through.
        wire.hlc_observe(node, f"{T + DRIFT - 1}:{hostile_logical}:evil", T)
        assert wire.hlc_now(node, T) == f"{T}:1:{node}", hostile_logical


def test_a_malformed_remote_stamp_never_reaches_the_clock():
    for name, counter in HOSTILE_COUNTERS.items():
        node = _node()
        wire.hlc_observe(node, f"{T + 5}:{counter}:evil", T)
        assert wire.hlc_now(node, T) == f"{T}:0:{node}", name


def test_the_clock_merges_a_remote_stamp_at_exactly_the_limit():
    node = _node()
    wire.hlc_observe(node, f"{T + 5}:{LIMIT}:remote", T)
    assert _tuple(wire.hlc_now(node, T)) > (T + 5, LIMIT, "remote")


def test_a_counter_driven_to_the_limit_carries_into_the_next_millisecond():
    node = _node()
    stamps = [wire.hlc_now(node, T) for _ in range(LIMIT + 1)]
    assert stamps[-1] == f"{T}:{LIMIT}:{node}"
    assert wire.hlc_now(node, T) == f"{T + 1}:0:{node}"


def test_a_merged_stamp_at_the_limit_carries_the_next_local_stamp():
    node = _node()
    wire.hlc_observe(node, f"{T}:{LIMIT}:remote", T)
    assert wire.hlc_now(node, T) == f"{T + 1}:0:{node}"


def test_stamps_after_a_merged_stamp_at_the_limit_never_repeat_and_stay_under_it():
    node = _node()
    wire.hlc_observe(node, f"{T + DRIFT - 1}:{LIMIT}:remote", T)
    stamps = [_tuple(wire.hlc_now(node, T)) for _ in range(3 * LIMIT)]
    assert all(a < b for a, b in zip(stamps, stamps[1:]))
    assert len(set(stamps)) == len(stamps)
    assert max(logical for _, logical, _ in stamps) <= LIMIT


def test_the_clock_clamps_a_remote_physical_one_millisecond_inside_the_drift_cap():
    node = _node()
    wire.hlc_observe(node, f"{T + DRIFT}:{LIMIT}:remote", T)
    # Clamped to T + DRIFT - 1 at the limit, the carry lands exactly on the cap.
    carried = wire.hlc_now(node, T)
    assert carried == f"{T + DRIFT}:0:{node}"
    # A receiver at the same wall time admits it: its far-future check is strictly greater.
    receiver = wire.FrameFilter()
    assert receiver.admit({"from": node, "stamp": carried}, T)
    assert receiver.ahead == 0
    # Far past the cap the clamp holds too.
    far = _node()
    wire.hlc_observe(far, f"{LONG_MAX}:{LIMIT}:remote", T)
    assert wire.hlc_now(far, T) == f"{T + DRIFT}:0:{far}"


def test_an_honest_frame_at_the_cap_leaves_the_receiver_admissible_to_its_peers():
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    at_cap = f"{T + DRIFT}:{LIMIT}:{other.peer_id}"
    peer._handle(_frame(other, "PING", wire.ping_body(1), peer.identity.peer_id, at_cap))
    assert [kind for kind, _, _ in peer.sent] == ["ACK"]
    next_stamp = wire.hlc_now(peer.identity.peer_id, T)
    assert _tuple(next_stamp)[0] <= T + DRIFT
    third = CapturingPeer(clock=_at(T))
    assert third.frames.admit({"from": peer.identity.peer_id, "stamp": next_stamp}, T)


# (c) frames, end to end through the frame handler ---------------------------------------

def _hostile_ping(peer: CapturingPeer, other: Identity, stamp: str, nonce: int = 1) -> None:
    peer._handle(_frame(other, "PING", wire.ping_body(nonce), peer.identity.peer_id, stamp))


def test_the_peer_drops_counts_and_keeps_off_its_clock_a_frame_stamped_above_the_limit():
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    _hostile_ping(peer, other, f"{T + DRIFT - 1}:{JAVA_INT_MAX}:{other.peer_id}")
    assert peer.sent == [], "a frame carrying a hostile counter earns no ACK"
    assert peer.frames.logical_over_limit == 1
    assert other.peer_id not in peer.members and other.peer_id not in peer.reachable
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T}:0:{peer.identity.peer_id}"
    # The honest path: a counter at exactly the limit is a frame like any other.
    _hostile_ping(peer, other, f"{T}:{LIMIT}:{other.peer_id}", 2)
    assert [kind for kind, _, _ in peer.sent] == ["ACK"]
    assert peer.frames.logical_over_limit == 1
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T + 1}:0:{peer.identity.peer_id}"


@pytest.mark.parametrize("name", sorted(HOSTILE_COUNTERS))
def test_the_peer_drops_and_counts_a_frame_with_a_malformed_counter(name):
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    _hostile_ping(peer, other, f"{T + 5}:{HOSTILE_COUNTERS[name]}:{other.peer_id}")
    assert peer.sent == []
    assert peer.frames.malformed_stamps == 1
    assert other.peer_id not in peer.members
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T}:0:{peer.identity.peer_id}"
    _hostile_ping(peer, other, f"{T}:0:{other.peer_id}", 2)
    assert [kind for kind, _, _ in peer.sent] == ["ACK"]


@pytest.mark.parametrize("name", sorted(HOSTILE_PHYSICALS))
def test_the_peer_drops_and_counts_a_frame_with_a_malformed_physical(name):
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    _hostile_ping(peer, other, f"{HOSTILE_PHYSICALS[name].format(t=T)}:0:{other.peer_id}")
    assert peer.sent == []
    assert peer.frames.malformed_stamps == 1
    assert wire.hlc_now(peer.identity.peer_id, T) == f"{T}:0:{peer.identity.peer_id}"


def test_the_peer_drops_and_counts_a_frame_without_a_node_part():
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    _hostile_ping(peer, other, f"{T}:0:")
    _hostile_ping(peer, other, f"{T}:0", 2)
    assert peer.sent == []
    assert peer.frames.malformed_stamps == 2


def test_a_stamp_has_one_spelling_so_a_respelled_replay_is_malformed():
    peer = CapturingPeer(clock=_at(T))
    other = Identity.generate()
    _hostile_ping(peer, other, f"{T}:7:{other.peer_id}")
    # HLC canonical stamps, 2026-11-08: the sender re-signs the same stamp written with
    # leading zeros, which the canonical grammar refuses before the replay filter.
    _hostile_ping(peer, other, f"{T}:007:{other.peer_id}", 2)
    assert [kind for kind, _, _ in peer.sent] == ["ACK"]
    assert (peer.frames.malformed_stamps, peer.frames.replayed) == (1, 0)


# (d) folded states and claims, end to end through RUMOR and PULL_RESP -------------------

def _receiver_of(host: Identity) -> tuple:
    receiver = CapturingPeer(clock=_at(T))
    return receiver, Wire(host, receiver)


@pytest.mark.parametrize("counter", [str(JAVA_INT_MAX), "-1", "1.5", ""])
def test_the_peer_refuses_and_counts_a_rumored_record_with_a_refused_issue_stamp(counter):
    host = Identity.generate()
    honest = _write(host, T)
    receiver, link = _receiver_of(host)
    link.rumor(_with_issued(honest, host, f"{T}:{counter}:{host.agent('w')}"))
    assert receiver.states == {}
    assert receiver.refused_stamps["states"] == 1
    link.rumor(_with_issued(honest, host, f"{T}:{LIMIT}:{host.agent('w')}"))
    assert set(receiver.states) == {honest["record"]["entryId"]}
    assert receiver.refused_stamps["states"] == 1


@pytest.mark.parametrize("counter", [str(JAVA_INT_MAX), "-1", "1.5", ""])
def test_the_peer_refuses_and_counts_a_rumored_lease_stamp_the_rule_refuses(counter):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link = _receiver_of(host)
    link.rumor(write)
    hostile = _with_lease_stamp(write, host, f"{T + 1}:{counter}:{host.agent('w')}", T)
    link.rumor(hostile)
    assert receiver.states[entry_id]["leaseStamp"] == write["leaseStamp"]
    assert receiver.refused_stamps["states"] == 1
    # The honest renewal at exactly the limit extends the lease.
    renewed = _with_lease_stamp(write, host, f"{T + 1}:{LIMIT}:{host.agent('w')}", T)
    link.rumor(renewed)
    assert receiver.states[entry_id]["leaseStamp"] == renewed["leaseStamp"]


def test_the_peer_drops_a_rumored_agent_state_whose_signing_stamp_does_not_parse():
    host = Identity.generate()
    agent = host.renewing_subordinate("w", "PT24H", clock=_at(T))
    write = _write(host, T, agent=agent)
    receiver, link = _receiver_of(host)
    # HLC canonical stamps, 2026-11-08: the certificate is judged at the signing time, so
    # the state does not verify, and the peer counts only verified refusals.
    link.rumor(_with_signed_at(write, agent, f"{T}:-1:{agent.agent_id}"))
    assert receiver.states == {}
    assert receiver.refused_stamps["states"] == 0
    link.rumor(_with_signed_at(write, agent, f"{T}:{LIMIT}:{agent.agent_id}"))
    assert set(receiver.states) == {write["record"]["entryId"]}


def test_a_lease_without_a_stamp_joins_a_later_renewal():
    host = Identity.generate()
    write = _with_lease_stamp(_write(host, T), host, None, T)
    entry_id = write["record"]["entryId"]
    receiver, link = _receiver_of(host)
    link.rumor(write)
    assert receiver.states[entry_id]["leaseStamp"] is None
    renewed = _with_lease_stamp(write, host, f"{T + 1}:0:{host.agent('w')}", T)
    link.rumor(renewed)
    assert receiver.states[entry_id]["leaseStamp"] == renewed["leaseStamp"]


@pytest.mark.parametrize("counter", [str(JAVA_INT_MAX), "-1", "1.5", "", "1e3", "x"])
def test_the_peer_refuses_and_counts_a_rumored_claim_the_rule_refuses(counter):
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    receiver, link = _receiver_of(host)
    link.rumor(write)
    link.rumor(claim=(entry_id, _claim(write, host, f"{T}:{counter}:{host.agent('w')}", T)))
    assert receiver.claims == {}
    assert receiver.refused_stamps["claims"] == 1
    # Every later honest claim on the entry still folds: the hostile one left nothing behind.
    honest = _claim(write, host, f"{T}:{LIMIT}:{host.agent('w')}", T)
    link.rumor(claim=(entry_id, honest))
    assert receiver.claims[entry_id] == honest


def test_the_peer_refuses_and_counts_a_hostile_state_and_claim_in_a_pull_response():
    host = Identity.generate()
    write = _write(host, T)
    entry_id = write["record"]["entryId"]
    hostile_state = _with_issued(_write(host, T), host, f"{T}:-5:{host.agent('w')}")
    hostile_claim = _claim(write, host, f"{T}.25:0:{host.agent('w')}", T)
    receiver, link = _receiver_of(host)
    link.pull_resp([write, hostile_state], {entry_id: hostile_claim})
    assert set(receiver.states) == {entry_id}
    assert receiver.claims == {}
    assert receiver.refused_stamps == {"states": 1, "claims": 1}
    honest = _claim(write, host, f"{T}:0:{host.agent('w')}", T)
    link.pull_resp([], {entry_id: honest})
    assert receiver.claims[entry_id] == honest
    assert wire.hlc_now(receiver.identity.peer_id, T) == f"{T}:{3}:{receiver.identity.peer_id}"


# (e) the PDT head order ------------------------------------------------------------------

def test_the_pdt_head_order_reads_an_advisory_issue_stamp_as_java_refs_does():
    from agentspaces.pdt import refs
    # Refs.java reads pdt.issued with HlcTimestamp.parse and keeps the entry's own stamp
    # when it fails; the (0, 0, "") answer is that fallback's signal.
    for name, counter in HOSTILE_COUNTERS.items():
        assert refs._hlc(f"{T}:{counter}:n") == (0, 0, ""), name
    assert refs._hlc(f"{T}.5:0:n") == (0, 0, "")
    assert refs._hlc(f"{T}:{JAVA_INT_MAX}:n") == (T, JAVA_INT_MAX, "n")
