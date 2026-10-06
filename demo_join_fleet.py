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

"""The cross-language demo: a Python peer joins the Java research fleet
(example 02), writes a signed ResearchTask into the replicated space, and
reads the Finding a Java worker completes it with. Start the Java side first:

    mvn -q -pl examples/example-02-research-fleet exec:java \\
        -Dexec.args="worker 7461 0"

then:

    python3 demo_join_fleet.py 127.0.0.1 7461
"""

import sys
import time

from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer

TASK_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1"
FINDING_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1"


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7461
    identity = Identity.generate()
    group = group_id_from_founding(b"research-fleet-demo-v1")
    print(f"python peer {identity.peer_id}")
    print(f"joining group {group} via {host}:{port}")

    peer = Peer(identity, group)
    peer.connect(host, port)
    time.sleep(1.0)  # the intro rumor lands; membership learns this peer

    topic = "sent from python"
    entry_id = peer.write_entry("tasks", TASK_TYPE,
                                {"topic": topic, "priority": 3})
    print(f"wrote ResearchTask('{topic}') as entry {entry_id}")

    deadline = time.time() + 30
    while time.time() < deadline:
        peer.pull_space("tasks")
        time.sleep(1.0)
        for finding in peer.find(FINDING_TYPE):
            if finding.get("topic") == topic:
                print(f"finding from the Java fleet: '{finding.get('summary')}'"
                      f" by {finding.get('worker')}")
                print("\nno JVM was involved on this side of the wire.")
                peer.close()
                return 0
    print("timed out waiting for a finding")
    peer.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
