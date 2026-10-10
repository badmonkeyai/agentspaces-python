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
"""The council worker of the polyglot demo (L3L4-COVERAGE.md §6.6): a
PYTHON member of the Java coordinator's council. It joins the research
fleet, binds a decorated agent that takes the coordinator's tasks and votes
on its proposal, contributes its load to the push-sum epoch, answers
semantic queries over the pipe, and serves the remote action its card
declares. Start the Java side first:

    mvn -q -pl examples/example-02-research-fleet exec:java \\
        -Dexec.mainClass=ai.badmonkey.agentspaces.examples.fleet.CouncilFleet \\
        -Dexec.args="7470 2 20"
then:
    python3 demo_council_worker.py 127.0.0.1 7470 10 [max-seconds]
"""

import sys
import time
from dataclasses import dataclass

from agentspaces.agents import Binder, Decision, Proposal, agent, ballot, on_decision, space_take
from agentspaces.capabilities import Aggregate, Pipes, Semantic, Settle
from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer
from agentspaces.space import entry


@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1")
@dataclass
class ResearchTask:
    topic: str
    priority: int


@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1")
@dataclass
class Finding:
    topic: str
    summary: str
    worker: str


class State:
    decided = None
    completed = 0


@agent("py-researcher", description="Researches topics in Python and sits on the council", goals=["research", "vote"])
class Councillor:
    @space_take("tasks", lease="30s", poll_timeout="2s", description="Researches one topic in Python")
    def research(self, task: ResearchTask) -> Finding:
        State.completed += 1
        print(f"  [py] took and completed '{task.topic}' ({State.completed})", flush=True)
        return Finding(task.topic, "researched in python: " + task.topic, "py-worker")

    @ballot("votes", prefix="council:")
    def judge(self, proposal: Proposal) -> str | None:
        print(f"  [py] ballot on {proposal.proposal_id}: yes", flush=True)
        return "yes"

    @on_decision("votes", prefix="council:")
    def record(self, decision: Decision) -> None:
        State.decided = decision
        print(f"  [py] decision {decision.proposal_id} -> {decision.winner} {decision.tally}", flush=True)
        return None


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7470
    value = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0
    max_seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 90.0
    identity = Identity.generate()
    group = group_id_from_founding(b"research-fleet-demo-v1")
    print(f"python council worker {identity.peer_id}", flush=True)
    agent_identity = identity.renewing_subordinate("py-worker", "PT24H")
    peer = Peer(identity, group)
    peer.connect(host, port)
    time.sleep(1.0)
    peer.pull_ads()
    pipes = Pipes(peer)
    aggregate = Aggregate(pipes)
    Semantic(pipes)  # answers the coordinator's semantic queries from this peer's cache
    bound = Binder(peer, agent=agent_identity).bind(Councillor())
    aggregate.start("load", value)
    aggregate.run(0.25)
    settled = None
    deadline = time.time() + max_seconds
    try:
        while time.time() < deadline and peer.connected:
            if settled is None:
                settled = aggregate.await_settled("load", Settle.after(3, 0.01), timeout_seconds=1.0)
                if settled is not None:
                    print(f"  [py] epoch load settled at {settled:.3f}", flush=True)
            peer.pull_space("tasks")
            peer.pull_space("votes")
            time.sleep(0.5)
    finally:
        bound.close()
        aggregate.close()
        peer.close()
    print(f"python council worker done: {State.completed} tasks, decision "
          f"{State.decided.winner if State.decided else 'none'}, estimate {settled}", flush=True)
    return 0 if State.completed >= 1 and State.decided is not None and settled is not None else 1


if __name__ == "__main__":
    sys.exit(main())
