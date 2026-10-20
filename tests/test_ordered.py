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
"""The Raft client of the ordered log from Python (srad/agentspaces-js.md
JS-V-05 under JS-V-13): the Raft frame union and the ClientSubmit pinned by
the golden ``raft_*`` vectors, the ClaimCommand in Java record order, and a
client that submits to the advertised leader, follows a follower's leader
hint, and observes the commit through the space, against a simulated log
that applies the OrderedTakes.onCommand rule. The end-to-end proof against
three Java voters is agentspaces-capabilities' PythonOrderedTakeTest."""

import json
import time
import pathlib

import pytest

from agentspaces import cbor, wire
from agentspaces.capabilities import OrderedLog, Pipes, ordered
from agentspaces.identity import Identity, derive_id, instant_iso, space_id_local
from agentspaces.space import Space, Template
from fleet import fleet

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPyOrdered"
JOB = "com.acme.Job#v1"


class SimulatedLog:
    """Three voters of a NetPeer fleet: a ClientSubmit at the leader commits
    its command and every voter applies it by OrderedTakes.onCommand (the
    holder key is the claim holder's peer, the claim is bound to its entry,
    the epoch is the committed epoch plus one); a follower forwards a submit
    to the leader under its leader hint; the leader gossips an installed
    claim as a signed claim delta, which is how a client observes the commit."""

    def __init__(self, voters, space_name, leader_index=0, term=1):
        self.voters = voters
        self.space_name = space_name
        self.leader = voters[leader_index]
        self.term = term
        self.submits = {v.identity.peer_id: 0 for v in voters}
        self.forwarded = 0
        self.installed: list[str] = []   # entryId:epoch, once each
        self.rejected: list[str] = []    # not the next generation of its entry
        self.refused: list[str] = []     # unbound or inauthentic commands
        for voter in voters:
            voter.pipe_handlers[ordered.TYPE] = self._handler(voter)

    def _handler(self, voter):
        def on_frame(sender, payload):
            frame = ordered.parse_frame(payload)
            if not frame or "clientSubmit" not in frame:
                return
            self.submits[voter.identity.peer_id] += 1
            if voter is not self.leader:
                self.forwarded += 1
                voter.send_pipe(self.leader.identity.peer_id, ordered.TYPE, payload)  # RaftLog.submit's hint
                return
            self.commit(frame["clientSubmit"]["command"])
        return on_frame

    def commit(self, command: bytes) -> None:
        """The leader appends, the log replicates, every voter applies in order."""
        installed = None
        for voter in self.voters:
            installed = self._apply(voter, command) or installed
        if installed is not None:
            entry_id, signed = installed
            self.leader._send("RUMOR", wire.rumor_body(
                f"space:{self.space_name}", f"c:{entry_id}:{signed['claim']['stamp']}", 6,
                wire.claim_delta(entry_id, signed)))

    def _apply(self, voter, command: bytes):
        try:
            parsed = cbor.loads(command)
        except ValueError:
            return None
        claim, holder_key, entry_id = parsed.get("claim"), parsed.get("holderKey"), parsed.get("entryId")
        if (not isinstance(claim, dict) or not isinstance(holder_key, bytes) or not isinstance(parsed.get("signature"), bytes)
                or claim.get("entryId") != entry_id
                or not str(claim.get("holder", "")).startswith(derive_id(holder_key) + "/")):
            self._note(self.refused, f"{entry_id}:{(claim or {}).get('epoch')}")
            return None
        committed = int((voter._claim_of(entry_id) or {}).get("epoch", 0))
        epoch = int(claim["epoch"])
        if epoch != committed + 1:
            self._note(self.rejected, f"{entry_id}:{epoch}")
            return None
        signed = {"claim": claim, "holderKey": holder_key, "signature": parsed["signature"]}
        if parsed.get("holderCertificate") is not None:
            signed["holderCertificate"] = parsed["holderCertificate"]
        voter._fold_claim(entry_id, signed)  # the space's own verifier: an inauthentic command is dropped
        if int((voter._claim_of(entry_id) or {}).get("epoch", -1)) != epoch:
            self._note(self.refused, f"{entry_id}:{epoch}")
            return None
        self._note(self.installed, f"{entry_id}:{epoch}")
        return entry_id, signed

    @staticmethod
    def _note(record: list, item: str) -> None:
        """Once per command, whichever voter judged it first: every voter reaches the same verdict."""
        if item not in record:
            record.append(item)

    def advertise(self) -> None:
        """Every voter's ordered-log advertisement as RaftLog.describe publishes it."""
        for voter in self.voters:
            now_ms = voter._now_ms()
            parameters = {"members": str(len(self.voters)), "term": str(self.term),
                          "role": "leader" if voter is self.leader else "follower"}
            if voter is self.leader:
                parameters["leaseUntil"] = instant_iso(now_ms + 5_000)
            voter.publish_ad("CapabilityAdvertisement", {
                "id": f"aspace://{GROUP}/cap/ordered-log/{voter.identity.peer_id}",
                "issuer": voter.identity.peer_id, "group": GROUP, "issued": instant_iso(now_ms - now_ms % 1000),
                "ttl": "PT15M", "capabilityType": ordered.TYPE, "version": "0.1", "binding": "pipe",
                "parameters": cbor.canonical_map(parameters), "costHints": {}})


class Reach(set):
    """A dial-only client's reachable set: the seed it dialed and nothing else,
    whatever frames the seed relays to it."""

    def __init__(self, allowed):
        super().__init__(allowed)
        self.allowed = set(allowed)

    def add(self, peer_id):
        if peer_id in self.allowed:
            super().add(peer_id)


def _log_fleet(n_clients=1, leader_index=0):
    peers = fleet(GROUP, 3 + n_clients)
    voters, clients = peers[:3], peers[3:]
    log = SimulatedLog(voters, "jobs", leader_index=leader_index)
    log.advertise()
    return voters, clients, log


# ------------------------------------------------------------ the frames

def test_the_raft_frames_encode_as_the_java_records_do():
    assert ordered.raft_frame(requestVote={"term": 3, "candidate": "zA", "lastLogIndex": 7, "lastLogTerm": 2}).hex() \
        == GOLDEN["raft_request_vote_cbor"]
    assert ordered.raft_frame(voteReply={"term": 3, "granted": True}).hex() == GOLDEN["raft_vote_reply_cbor"]
    assert ordered.raft_frame(appendEntries={"term": 3, "leader": "zA", "prevLogIndex": 7, "prevLogTerm": 2,
                                             "entries": [{"term": 3, "command": b"cmd"}], "leaderCommit": 6}).hex() \
        == GOLDEN["raft_append_entries_cbor"]
    assert ordered.raft_frame(appendReply={"term": 3, "follower": "zB", "success": True, "matchIndex": 8}).hex() \
        == GOLDEN["raft_append_reply_cbor"]
    assert ordered.client_submit_frame(b"cmd").hex() == GOLDEN["raft_client_submit_cbor"]
    assert ordered.parse_frame(ordered.client_submit_frame(b"cmd")) == {"clientSubmit": {"command": b"cmd"}}
    assert ordered.parse_frame(b"\x01") is None and ordered.parse_frame(b"\xff") is None
    with pytest.raises(ValueError):
        ordered.raft_frame(heartbeat={})


def test_a_claim_command_carries_the_holders_proof_in_record_order():
    identity = Identity.generate()
    space_id = space_id_local(f"{GROUP}/jobs")
    claim = wire.take_claim("e-1", space_id, 1, wire.hlc_now(identity.agent("w"), 1_700_000_000_000),
                            identity.agent("w"), 0.0, 1_700_000_060_000)
    signed = wire.signed_claim(claim, identity)
    command = cbor.loads(ordered.claim_command("e-1", claim, identity.public_raw, signed["signature"]))
    assert list(command) == ["entryId", "claim", "holderKey", "signature"]
    assert command["claim"] == claim and command["holderKey"] == identity.public_raw
    assert Identity.verify(command["holderKey"], cbor.dumps(command["claim"]), command["signature"])
    # An agent holder: its certificate rides in the appended field and the proof verifies as a SignedClaim.
    agent = identity.renewing_subordinate("clerk", "PT24H")
    now_ms = int(time.time() * 1000)  # inside the certificate's window, which opens at the real clock
    claim = wire.take_claim("e-2", space_id, 1, wire.hlc_now(agent.agent_id, now_ms), agent.agent_id, 0.0,
                            now_ms + 60_000)
    signed = wire.signed_claim(claim, identity, agent)
    command = cbor.loads(ordered.claim_command("e-2", claim, identity.public_raw, signed["signature"],
                                               signed["holderCertificate"]))
    assert list(command) == ["entryId", "claim", "holderKey", "signature", "holderCertificate"]
    assert wire.verify_claim_proof({"claim": command["claim"], "holderKey": command["holderKey"],
                                    "signature": command["signature"],
                                    "holderCertificate": command["holderCertificate"]}, now_ms + 1_000)


# ------------------------------------------------------------ the client

def test_a_client_takes_exactly_once_through_the_log_and_observes_the_commit():
    voters, (client,), log = _log_fleet()
    ordered_log = OrderedLog(Pipes(client))
    assert {m.peer for m in ordered_log.members()} == {v.identity.peer_id for v in voters}
    assert ordered_log.leader() == voters[0].identity.peer_id
    assert ordered_log.submit_target() == voters[0].identity.peer_id
    job = voters[1].write_entry("jobs", JOB, {"jobId": "job-1", "payload": "settle the invoice"})
    taken = ordered_log.take("jobs", JOB, "py-worker", lease_millis=60_000, timeout_seconds=5.0)
    assert taken == job
    assert log.installed == [f"{job}:1"] and log.rejected == [] and log.refused == []
    assert log.submits[voters[0].identity.peer_id] == 1 and log.forwarded == 0
    holder = client.identity.agent("py-worker")
    for voter in voters:
        assert voter._claim_of(job)["holder"] == holder and voter._claim_of(job)["epoch"] == 1
    client.complete_entry("jobs", taken)
    assert all(v.states[job]["completed"] for v in voters)
    # Through the Space: the same take as a Taken, completed with a result.
    second = voters[2].write_entry("jobs", JOB, {"jobId": "job-2", "payload": "file the return"})
    space = Space(client, "jobs")
    held = space.take(Template(JOB), lease="1m", timeout="5s", through=ordered_log)
    assert held is not None and held.entry_id == second and held.value["jobId"] == "job-2"
    held.complete()
    assert log.installed == [f"{job}:1", f"{second}:1"]
    assert all(v.states[second]["completed"] for v in voters)


def test_an_attested_agent_takes_through_the_log_with_its_own_signature():
    voters, (client,), log = _log_fleet()
    agent = client.identity.renewing_subordinate("clerk", "PT24H")
    job = voters[0].write_entry("jobs", JOB, {"jobId": "job-3", "payload": "x"})
    taken = OrderedLog(Pipes(client)).take("jobs", JOB, lease_millis=60_000, timeout_seconds=5.0, agent=agent)
    assert taken == job and log.installed == [f"{job}:1"]
    for voter in voters:
        signed = voter.claims[job]
        assert signed["claim"]["holder"] == agent.agent_id and signed.get("holderCertificate") is not None
    client.complete_entry("jobs", taken, agent=agent)
    assert all(v.states[job]["completed"] for v in voters)


def test_the_client_follows_a_followers_leader_hint_when_the_leader_is_out_of_reach():
    voters, (client,), log = _log_fleet(leader_index=2)
    client.reachable = Reach({voters[0].identity.peer_id})  # dial-only behind the first voter
    ordered_log = OrderedLog(Pipes(client))
    assert ordered_log.leader() == voters[2].identity.peer_id
    assert ordered_log.submit_target() == voters[0].identity.peer_id, "a reachable member forwards"
    job = voters[1].write_entry("jobs", JOB, {"jobId": "job-4", "payload": "y"})
    assert ordered_log.take("jobs", JOB, "py-worker", lease_millis=60_000, timeout_seconds=5.0) == job
    assert log.forwarded == 1
    assert log.submits[voters[0].identity.peer_id] == 1 and log.submits[voters[2].identity.peer_id] == 1
    assert log.installed == [f"{job}:1"]


def test_a_generation_installs_once_and_a_duplicate_a_jump_or_an_unbound_claim_is_refused():
    voters, (first, second), log = _log_fleet(n_clients=2)
    job = voters[0].write_entry("jobs", JOB, {"jobId": "job-5", "payload": "z"})
    assert OrderedLog(Pipes(first)).take("jobs", JOB, "py-worker", lease_millis=60_000, timeout_seconds=5.0) == job
    winner = first.identity.agent("py-worker")
    space_id = space_id_local(f"{GROUP}/jobs")
    rival = OrderedLog(Pipes(second))
    now_ms = second._now_ms()
    loser = second.identity.agent("py-worker")

    def command(epoch, entry_id=job, holder=loser, signer=second.identity):
        claim = wire.take_claim(job, space_id, epoch, wire.hlc_now(holder, now_ms), holder, 0.0, now_ms + 60_000)
        signed = wire.signed_claim(claim, signer)
        return ordered.claim_command(entry_id, claim, signer.public_raw, signed["signature"])

    assert rival.submit(command(1))  # the same generation again: the log already decided it
    assert rival.submit(command(3))  # a jump past the next generation
    assert log.rejected == [f"{job}:1", f"{job}:3"]
    assert rival.submit(command(2, entry_id="other-entry"))  # the claim is bound to its entry
    assert rival.submit(command(2, holder=winner))           # the key is not the named holder's peer
    assert log.refused == ["other-entry:2", f"{job}:2"]
    assert log.installed == [f"{job}:1"]
    for voter in voters:
        assert voter._claim_of(job)["holder"] == winner and voter._claim_of(job)["epoch"] == 1
    # A second client cannot take the held entry: nothing is submitted while the claim is live.
    assert rival.take("jobs", JOB, "py-worker", lease_millis=60_000, timeout_seconds=1.0) is None
    assert log.submits[voters[0].identity.peer_id] == 5


def test_without_a_log_in_the_ads_a_take_submits_nothing_and_returns_at_its_timeout():
    writer, client = fleet(GROUP, 2)
    writer.write_entry("jobs", JOB, {"jobId": "job-6", "payload": "w"})
    ordered_log = OrderedLog(Pipes(client))
    assert ordered_log.members() == [] and ordered_log.leader() is None and ordered_log.submit_target() is None
    assert ordered_log.submit(b"cmd") is False
    assert ordered_log.take("jobs", JOB, "py-worker", lease_millis=60_000, timeout_seconds=0.5) is None
    assert client.claims == {}
