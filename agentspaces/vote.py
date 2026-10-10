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
"""The QUORUM tally (SPEC §8, TECH-SPEC §8.4), as Java's VoteCapability.tally
counts it, over the ballot states a Peer has folded. Ballots are ordinary
entries of the reserved type below; the voter is the entry's authenticated
issuer, and a ballot whose declared ``voter`` differs from it is a forgery.

Counting follows a granularity (QA4 A4-7 phase 2). Under ``PEER`` the counted
identity is the issuer's peer, so one peer is one counted ballot however many
names it writes; under ``AGENT`` each permitted agent counts once, and only an
``AGENT_ATTESTED`` record (one whose state carried a certificate the two-key
rule accepted) is eligible, because a peer-asserted name is exactly what that
granularity exists to distrust."""

from . import cbor

BALLOT_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Ballot#v1"
PROPOSAL_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Proposal#v1"
PEER = "PEER"
AGENT = "AGENT"


def ballots(states: dict, proposal_id: str) -> list:
    """The folded, present ballot records for one proposal, in stored order."""
    found = []
    for dto in states.values():
        record = dto.get("record") or {}
        if record.get("type") != BALLOT_TYPE or dto.get("completed"):
            continue
        adds = {(d.get("replica"), d.get("counter")) for d in dto.get("adds") or []}
        removes = {(d.get("replica"), d.get("counter")) for d in dto.get("removes") or []}
        if not adds - removes:
            continue  # withdrawn
        try:
            ballot = cbor.loads(record.get("payload") or b"")
        except ValueError:
            continue
        if isinstance(ballot, dict) and ballot.get("proposalId") == proposal_id:
            found.append((record, dto, ballot))
    return found


def tally(states: dict, proposal_id: str, options=None, granularity: str = PEER,
          permits=None) -> dict:
    """Votes per option. ``permits(issuer_agent_id)`` is the authorizer's
    per-agent answer (everyone, by default); ``options`` zero-fills and spoils
    ballots for options the proposal does not offer, when known."""
    result = {option: 0 for option in options or []}
    counted = set()
    for record, dto, ballot in ballots(states, proposal_id):
        issuer = record.get("issuer")
        if not isinstance(issuer, str) or ballot.get("voter") != issuer:
            continue  # declared voter is not the authenticated writer: forged
        option = ballot.get("option")
        if options is not None and option not in options:
            continue  # spoiled
        if granularity == AGENT and dto.get("agentCertificate") is None:
            continue  # per-agent counting trusts only the agent's own key
        if permits is not None and not permits(issuer):
            continue
        key = issuer if granularity == AGENT else issuer.split("/", 1)[0]
        if key in counted:
            continue
        counted.add(key)
        result[option] = result.get(option, 0) + 1
    return result


# ------------------------------------------------------- proposals and casts

def proposals(states: dict) -> dict:
    """The open proposals by id: ``{id: {"proposalId", "question", "options",
    "quorum"}}``, from the folded Proposal records."""
    found = {}
    for dto in states.values():
        record = dto.get("record") or {}
        if record.get("type") != PROPOSAL_TYPE or dto.get("completed"):
            continue
        try:
            proposal = cbor.loads(record.get("payload") or b"")
        except ValueError:
            continue
        if isinstance(proposal, dict) and isinstance(proposal.get("proposalId"), str):
            found.setdefault(proposal["proposalId"], proposal)
    return found


def propose(peer, space: str, proposal_id: str, question: str, options: list, quorum: int,
            lease_millis: int = 3_600_000, agent=None, agent_name: str = "python") -> str | None:
    """Opens a proposal (SPEC §8.4): a Proposal entry in the vote space, in
    Java field order; idempotent on the id (an open proposal is not rewritten).
    Returns the entry id, or None when the proposal was already open."""
    if proposal_id in proposals(peer.states):
        return None
    payload = {"proposalId": proposal_id, "question": question, "options": list(options), "quorum": int(quorum)}
    return peer.write_entry(space, PROPOSAL_TYPE, payload, agent_name=agent_name,
                            lease_millis=lease_millis, agent=agent)


def cast(peer, space: str, proposal_id: str, option: str, lease_millis: int = 3_600_000,
         agent=None, agent_name: str = "python") -> str:
    """Casts this agent's ballot: a Ballot entry whose ``voter`` is the
    authenticated writer (a tally skips any other). One ballot per voter per
    proposal counts, the first observed."""
    voter = agent.agent_id if agent is not None else peer.identity.agent(agent_name)
    payload = {"proposalId": proposal_id, "option": option, "voter": voter}
    return peer.write_entry(space, BALLOT_TYPE, payload, agent_name=agent_name,
                            lease_millis=lease_millis, agent=agent)


def decision(states: dict, proposal_id: str, granularity: str = PEER, permits=None) -> dict | None:
    """The QUORUM decision as Java closes it (SPEC §8.4): once distinct
    counted voters reach the proposal's quorum, the winner is the option with
    the most votes, ties broken to the lexicographically first option, so every
    replica decides identically. None while open or unknown."""
    proposal = proposals(states).get(proposal_id)
    if proposal is None:
        return None
    options = list(proposal.get("options") or [])
    counts = tally(states, proposal_id, options, granularity, permits)
    voters = sum(counts.values())
    if voters < int(proposal.get("quorum", 0)) or voters == 0:
        return None
    winner = sorted(options, key=lambda o: (-counts.get(o, 0), o))[0]
    return {"proposalId": proposal_id, "winner": winner, "tally": counts}
