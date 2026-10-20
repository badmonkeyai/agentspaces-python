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
"""The Python worker of the Java cross-language connector-client test
(agentspaces-connect-core PythonConnectorClientTest; srad/agentspaces-js.md
JS-C-14): dials a Java seed over tcp, joins by the founding, finds the
``orders`` AssetCard in the ads, queries the asset through
``DataQueryClient`` twice (the second answered from the space), invokes
``reserve``, retries it under the same invocation id, asks for an operation
the card does not list, and prints one JSON line.

    python tests/workers/connect_worker.py <host> <port> <founding> [maxSeconds]
"""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentspaces.capabilities import connect  # noqa: E402
from agentspaces.capabilities.connect import DataQueryClient, asset_cards, invoke_ops  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402


def main() -> int:
    host, port, founding = sys.argv[1:4]
    max_seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 90.0
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    time.sleep(1.0)
    deadline = time.monotonic() + max_seconds
    card = None
    while card is None and time.monotonic() < deadline:
        peer.pull_ads()
        time.sleep(0.5)
        cards = asset_cards(peer, "orders")
        card = cards[0] if cards else None
    if card is None:
        print(json.dumps({"ok": False, "reason": "no orders AssetCard in the ads", "ads": len(peer.ads),
                          "reachable": len(peer.reachable)}, separators=(",", ":")))
        peer.close()
        return 2
    client = DataQueryClient(peer, "py-analyst", trusted_connectors={card["issuer"]})
    remaining = lambda: max(1.0, deadline - time.monotonic())  # noqa: E731
    fetched = client.fetch("orders", {"region": "eu"}, timeout=remaining())
    if fetched is None:
        print(json.dumps({"ok": False, "reason": "the query was not answered"}, separators=(",", ":")))
        peer.close()
        return 3
    cached = client.fetch("orders", {"region": "eu"}, timeout=remaining())  # the same hash: served from the space
    result = connect.invoke(client.space, card, "reserve", {"sku": "A-1", "qty": "2"}, timeout=remaining())
    retry = None if result is None else connect.invoke(client.space, card, "reserve", {"sku": "A-1", "qty": "2"},
                                                       timeout=remaining(), invocation_id=result.invocationId)
    refused = connect.invoke(client.space, card, "drop", {"table": "orders"}, timeout=remaining())
    time.sleep(1.0)  # let the last take's completion reach the seed before the socket closes
    report = {"ok": result is not None and result.ok and retry is not None and retry.ok and refused is not None,
              "peerId": peer.identity.peer_id, "connector": card["issuer"], "invokeOps": invoke_ops(card),
              "rows": [row["id"] for row in fetched.result.rows], "servedBy": fetched.result.servedBy,
              "fromCache": fetched.from_cache, "cached": cached is not None and cached.from_cache,
              "cacheHits": client.cache_hits, "queriesSent": client.queries_sent,
              "invocationId": None if result is None else result.invocationId,
              "reserved": None if result is None else result.result.get("reserved"),
              "retryOk": retry is not None and retry.ok,
              "refused": None if refused is None else refused.error,
              "refusedRule": None if refused is None else refused.result.get("rule")}
    print(json.dumps(report, separators=(",", ":")))
    peer.close()
    return 0 if report["ok"] else 4


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - one line for the Java side, then a failing exit code
        print(json.dumps({"ok": False, "reason": str(e)}, separators=(",", ":")))
        sys.exit(1)
