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

"""The polyglot worker demo: a PYTHON worker drains a JAVA coordinator's
task space, claims and all. Start the Java side first:

    mvn -q -pl examples/example-02-research-fleet exec:java \\
        -Dexec.args="coordinator 7467"

then:

    python3 demo_python_worker.py 127.0.0.1 7467

The coordinator publishes six tasks and waits for six findings; this worker
takes each task under the LEASE_RACE claim lattice (signed claims, settle
window, deterministic arbitration), completes it, and writes the finding the
Java side is waiting for."""

import sys
import time

from agentspaces import cbor
from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer

TASK_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1"
FINDING_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1"


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7467
    identity = Identity.generate()
    group = group_id_from_founding(b"research-fleet-demo-v1")
    print(f"python worker {identity.peer_id}")

    # SPEC §4.2 v0.1.13: the worker acts as its own agent, with a key this peer
    # certifies and renews, so the fleet stores its work AGENT_ATTESTED.
    agent = identity.renewing_subordinate("py-worker", "PT24H")
    peer = Peer(identity, group)
    peer.connect(host, port)
    time.sleep(1.0)

    race = len(sys.argv) > 3 and sys.argv[3] == "race"
    completed = 0
    idle_strikes = 0
    deadline = time.time() + (90 if race else 60)
    while time.time() < deadline and peer.connected:
        if race:
            if idle_strikes >= 2:
                break
        elif completed >= 6:
            break
        entry_id = peer.take_entry("tasks", TASK_TYPE, agent_name="py-worker",
                                   timeout_seconds=8.0 if race else 15.0, agent=agent)
        if entry_id is None:
            if race and completed > 0:
                idle_strikes += 1
            continue
        idle_strikes = 0
        record = peer.states[entry_id]["record"]
        task = cbor.loads(record["payload"])
        peer.complete_entry("tasks", entry_id, agent=agent)
        peer.write_entry("tasks", FINDING_TYPE,
                         {"topic": task["topic"],
                          "summary": "researched in python: " + task["topic"],
                          "worker": "py-worker"},
                         agent_name="py-worker", lease_millis=3_600_000, agent=agent)
        completed += 1
        print(f"  [py] took and completed '{task['topic']}' ({completed})")

    print(f"python worker done: {completed} tasks")
    peer.close()
    if race:
        return 0 if completed >= 1 else 1
    return 0 if completed == 6 else 1


if __name__ == "__main__":
    sys.exit(main())
