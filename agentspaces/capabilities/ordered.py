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
"""The Raft client of the ordered log (srad/agentspaces-js.md JS-V-05, JS-V-13;
reviews/L3L4-COVERAGE.md "a Raft client, not a Raft voter"): a Python peer
submits a signed claim command to the log's leader (named by the leader's
``aspace:cap/ordered-log`` advertisement, or forwarded by any member of the
log under its leader hint) and observes the commit through the space, where
the committed claim arrives as a signed claim delta. An ordered take is
therefore exactly once fleet-wide: the log decides each generation, and only
the holder the log committed completes. This is the client half of Java's
``OrderedTakes``; the voter stays in Java (JS-F-18).

    log = OrderedLog(Pipes(peer))
    entry_id = log.take("jobs", JOB_TYPE, "py-worker", lease_millis=60_000, timeout_seconds=10)
    peer.complete_entry("jobs", entry_id)
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .. import cbor, wire
from ..identity import parse_instant_millis, space_id_local

TYPE = "aspace:cap/ordered-log"  # RaftLog.TYPE

_FRAME_FIELDS = ("requestVote", "voteReply", "appendEntries", "appendReply", "clientSubmit")


@dataclass(frozen=True)
class LogMember:
    """A member's view of the log, from its advertisement: ``role`` is
    ``leader``, ``follower``, or ``candidate``; ``lease_until_ms`` is the
    leader's lease, None for the others."""
    peer: str
    role: str
    term: int
    lease_until_ms: int | None


def raft_frame(**parts) -> bytes:
    """RaftMessages.Frame, the union of the five Raft messages in Java record
    order with every absent field null (golden ``raft_*``): ``raft_frame(
    clientSubmit={"command": b"..."})``."""
    unknown = set(parts) - set(_FRAME_FIELDS)
    if unknown:
        raise ValueError(f"not Raft frame fields: {sorted(unknown)}")
    return cbor.dumps({field: parts.get(field) for field in _FRAME_FIELDS})


def client_submit_frame(command: bytes) -> bytes:
    """A Frame carrying one ClientSubmit (golden ``raft_client_submit_cbor``)."""
    return raft_frame(clientSubmit={"command": bytes(command)})


def claim_command(entry_id: str, claim: dict, peer_public_raw: bytes, signature: bytes,
                  holder_certificate: dict | None = None) -> bytes:
    """OrderedTakes.ClaimCommand: the claim, the holder's peer key, the holder's
    signature over the claim's canonical bytes, and (for an agent holder) the
    certificate covering the claim's stamp, omitted otherwise. The voters
    install it only when the key derives to the claim holder's peer, the claim
    is bound to ``entry_id``, and its epoch is the committed epoch plus one."""
    command = {"entryId": entry_id, "claim": claim, "holderKey": bytes(peer_public_raw),
               "signature": bytes(signature)}
    if holder_certificate is not None:
        command["holderCertificate"] = holder_certificate
    return cbor.dumps(command)


def parse_frame(payload: bytes) -> dict | None:
    """The Frame a member received, as a dict of the present fields, or None
    when malformed: what a test voter (or a future Python voter) dispatches on."""
    try:
        frame = cbor.loads(payload)
    except ValueError:
        return None
    if not isinstance(frame, dict):
        return None
    return {k: v for k, v in frame.items() if k in _FRAME_FIELDS and v is not None}


class OrderedLog:
    """A client of one group's ordered log, over the peer's pipes."""

    def __init__(self, pipes, pull_interval_seconds: float = 0.6, attempt_seconds: float = 3.0):
        self.pipes = pipes
        # One ads and space pull per interval while waiting, as a take's settle window
        # paces its pulls (JS-V-02); an attempt resubmits after attempt_seconds undecided.
        self.pull_interval_seconds = pull_interval_seconds
        self.attempt_seconds = attempt_seconds

    @property
    def peer(self):
        return self.pipes.peer

    def members(self) -> list[LogMember]:
        """The log's members as their live advertisements describe them."""
        peer = self.peer
        now = peer._now_ms()
        out = []
        for entry in list(peer.ads.values()):
            if (entry["type"] != "CapabilityAdvertisement" or entry["expires"] <= now
                    or entry["ad"].get("capabilityType") != TYPE):
                continue
            parameters = entry["ad"].get("parameters") or {}
            lease_until = None
            if parameters.get("leaseUntil") is not None:
                try:
                    lease_until = parse_instant_millis(str(parameters["leaseUntil"]))
                except (TypeError, ValueError):
                    lease_until = None
            try:
                term = int(parameters.get("term") or 0)
            except (TypeError, ValueError):
                term = 0
            out.append(LogMember(entry["issuer"], str(parameters.get("role") or ""), term, lease_until))
        return out

    def leader(self) -> str | None:
        """The leader whose lease has not lapsed, by the highest term, or None."""
        now = self.peer._now_ms()
        leaders = [m for m in self.members()
                   if m.role == "leader" and (m.lease_until_ms is None or m.lease_until_ms > now)]
        if not leaders:
            return None
        return max(leaders, key=lambda m: m.term).peer

    def submit_target(self) -> str | None:
        """Where a submit goes: the leader when this peer can reach it, else any
        reachable member of the log, which forwards it under its leader hint."""
        leader = self.leader()
        if leader is not None and leader in self.peer.reachable:
            return leader
        for member in self.members():
            if member.peer in self.peer.reachable:
                return member.peer
        return None

    def submit(self, command: bytes) -> bool:
        """Submits one command as a ClientSubmit; returns whether a target was known."""
        target = self.submit_target()
        if target is None:
            return False
        self.pipes.send(target, TYPE, client_submit_frame(command))
        return True

    def take(self, space: str, type_name: str, agent_name: str = "python", lease_millis: int = 60_000,
             timeout_seconds: float = 15.0, agent=None, matches=None) -> str | None:
        """OrderedTakes.take as a client: claims a matching live entry through
        the log and returns its id once the log committed this peer's claim for
        the generation it asked for, or None at the timeout. With ``agent`` the
        claim is the agent's, signed by its key with its certificate in the
        command (v0.1.13). ``matches(payload, tags)`` narrows the candidates.
        The caller completes the entry as after any take; a command lost to a
        leader election is resubmitted on the next scan."""
        peer = self.peer
        holder = agent.agent_id if agent is not None else peer.identity.agent(agent_name)
        if peer.revocations.refuses(holder, agent.public_raw if agent else None, None):
            return None
        space_id = space_id_local(f"{peer.group}/{space}")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline and peer._running:
            if peer.pull_space_paced(space, self.pull_interval_seconds):
                peer.pull_ads()  # the log's advertisements name the leader
            seen = peer.fold_count
            now_ms = peer._now_ms()
            submitted = False
            for entry_id, dto in list(peer.states.items()):
                record = dto.get("record") or {}
                if record.get("type") != type_name or dto.get("completed") or record.get("spaceId") != space_id:
                    continue
                lease = dto.get("leaseValue") or record.get("lease") or {}
                if int(lease.get("expiresAtMillis", 0)) <= now_ms:
                    continue
                current = peer._claim_of(entry_id)
                if current and int(current.get("expiresAtMillis", 0)) > now_ms:
                    continue
                payload = cbor.loads(record.get("payload") or b"\xf6")
                if matches is not None and not matches(payload or {}, record.get("tags") or {}):
                    continue
                epoch = int(current["epoch"]) + 1 if current else 1
                claim = wire.take_claim(entry_id, space_id, epoch, wire.hlc_now(holder, now_ms), holder, 0.0,
                                        now_ms + lease_millis)
                signed = wire.signed_claim(claim, peer.identity, agent)
                command = claim_command(entry_id, claim, peer.identity.public_raw, signed["signature"],
                                        signed.get("holderCertificate"))
                if not self.submit(command):
                    break  # no member of the log reachable yet: pull the ads again
                submitted = True
                # The log decides this generation within a bounded attempt, observed as the
                # committed claim folding from the space; undecided, the next scan resubmits.
                attempt = min(deadline, time.monotonic() + self.attempt_seconds)
                while time.monotonic() < attempt:
                    peer.await_fold(min(self.pull_interval_seconds, attempt - time.monotonic()))
                    decided = peer._claim_of(entry_id)
                    if decided and int(decided.get("epoch", 0)) >= epoch:
                        if (decided.get("holder") == holder and int(decided["epoch"]) == epoch
                                and not (peer.states.get(entry_id) or {}).get("completed")):
                            return entry_id
                        break  # someone else won this generation; try another entry
                    peer.pull_space_paced(space, self.pull_interval_seconds)
                break  # re-scan (and resubmit when still undecided)
            if not submitted:
                peer.await_fold(min(self.pull_interval_seconds, deadline - time.monotonic()), since=seen)
        return None
