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
"""The Python worker of the Java cross-language content-swarm test
(agentspaces-content PythonContentClientTest; srad/large-networks-bulk-data.md
§10): dials a Java relay over tcp, joins by the founding, fetches the root the
Java side published from every holder it can see (the seed directly, the other
Java member through the seed as a relay), publishes an artifact of its own,
waits until the Java members hold it in full, and prints one JSON line.

    python tests/workers/content_worker.py <host> <port> <founding> <root> [maxSeconds]
"""

import hashlib
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentspaces.capabilities import Content, MemoryStore, Pipes  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402
from agentspaces.space import Space  # noqa: E402

PIECE = 64 * 1024


def reply_artifact() -> bytes:
    return bytes((i * 13 + 5) & 0xFF for i in range(3 * PIECE + 77))


def main() -> int:
    host, port, founding, root = sys.argv[1:5]
    max_seconds = float(sys.argv[5]) if len(sys.argv) > 5 else 90.0
    deadline = time.monotonic() + max_seconds
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    space = Space(peer, "content")
    content = Content(Pipes(peer), space, MemoryStore(), piece_size=PIECE)
    content.run(0.1)
    time.sleep(1.0)
    peer.pull_space("content")
    fetch = content.fetch(root)
    while not fetch.done.is_set() and time.monotonic() < deadline:
        if fetch.manifest is None:
            peer.pull_space("content")
        time.sleep(0.5)
    if not fetch.complete:
        print(json.dumps({"ok": False, "reason": "fetch did not complete", "trace": fetch.trace[-8:],
                          "manifestKnown": fetch.manifest is not None, "holdings": len(content.holdings(root)),
                          "seedPeer": peer.seed_peer, "progress": fetch.progress()}, separators=(",", ":")))
        peer.close()
        return 2
    data = fetch.read_bytes()
    progress = fetch.progress()
    mine = content.publish(reply_artifact(), name="from-python.bin")
    java_holders = []
    while time.monotonic() < deadline:
        java_holders = sorted(h["holder"] for h in content.holdings(mine["root"])
                              if h["holder"] != peer.identity.peer_id and h.get("complete"))
        if len(java_holders) >= 2:
            break
        peer.pull_space("content")
        time.sleep(0.5)
    time.sleep(0.5)
    report = {"ok": len(java_holders) >= 2, "peerId": peer.identity.peer_id, "seedPeer": peer.seed_peer,
              "root": root, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "bySource": progress["bytesBySource"], "publishedRoot": mine["root"], "javaHolders": java_holders,
              "relayedFrames": peer.relayed_frames, "bytesServed": content.bytes_served,
              "relaySignals": len(peer.relay_signals)}
    print(json.dumps(report, separators=(",", ":")))
    content.stop()
    peer.close()
    return 0 if report["ok"] else 4


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - one line for the Java side, then a failing exit code
        print(json.dumps({"ok": False, "reason": repr(e)}, separators=(",", ":")))
        sys.exit(1)
