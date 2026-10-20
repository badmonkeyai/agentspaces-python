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
"""The Python worker of the Java cross-language ordered-take test
(agentspaces-capabilities PythonOrderedTakeTest; srad/agentspaces-js.md
JS-V-05 under JS-V-13): dials a Java seed over tcp, joins by the founding,
finds the ordered log in the ads, takes the one Job through the log as a
Raft client, completes it, writes a Done, and prints one JSON line.

    python tests/workers/ordered_worker.py <host> <port> <founding> <jobType> <doneType> [maxSeconds]
"""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentspaces import cbor  # noqa: E402
from agentspaces.capabilities import OrderedLog, Pipes  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402


def main() -> int:
    host, port, founding, job_type, done_type = sys.argv[1:6]
    max_seconds = float(sys.argv[6]) if len(sys.argv) > 6 else 60.0
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    time.sleep(1.0)
    peer.pull_ads()
    log = OrderedLog(Pipes(peer))
    deadline = time.monotonic() + max_seconds
    taken = None
    members = 0
    while taken is None and time.monotonic() < deadline:
        members = len(log.members())
        taken = log.take("jobs", job_type, "py-worker", lease_millis=60_000, timeout_seconds=10.0)
    if taken is None:
        print(json.dumps({"ok": False, "reason": "no job taken through the log", "logMembers": members,
                          "leader": log.leader(), "reachable": len(peer.reachable)}, separators=(",", ":")))
        peer.close()
        return 2
    epoch = int((peer._claim_of(taken) or {}).get("epoch", 0))
    peer.complete_entry("jobs", taken)
    payload = cbor.loads(peer.states[taken]["record"].get("payload") or b"\xf6") or {}
    peer.write_entry("jobs", done_type, {"jobId": str(payload.get("jobId", "job-1")), "by": "python-ordered"},
                     agent_name="py-worker", lease_millis=600_000)
    time.sleep(1.5)
    print(json.dumps({"ok": True, "taken": taken, "epoch": epoch, "logMembers": members, "leader": log.leader(),
                      "peerId": peer.identity.peer_id}, separators=(",", ":")))
    peer.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - one line for the Java side, then a failing exit code
        print(json.dumps({"ok": False, "reason": str(e)}, separators=(",", ":")))
        sys.exit(1)
