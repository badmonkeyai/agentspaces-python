"""A Python agent that declares its data use (S1-G-09): joins a fleet by
seed and founding, binds an ``@agent`` carrying ``@data_use``, and stays
bound for ``maxSeconds`` so the console's bridge mirrors the declaration.

    python tests/workers/datause_worker.py <host> <port> <founding> [maxSeconds]
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from agentspaces.agents import Binder, agent, data_use, space_notify  # noqa: E402
from agentspaces.console import rules  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402
from agentspaces.space import entry  # noqa: E402


@entry("https://badmonkey.ai/console#Finding")
class Finding:
    def __init__(self, **kw):
        self.__dict__.update(kw)


@data_use(reads=["claims.policies"], source="jdbc:postgresql://claims-py/policies", sensitivity="internal",
          freshness="PT5M")
@agent("py-coverage", description="Checks coverage from Python")
class PyCoverage:
    @space_notify("catalog")
    def on_finding(self, finding: Finding):
        return None


def main() -> int:
    host, port, founding = sys.argv[1:4]
    max_seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 60.0
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    time.sleep(1.0)
    binder = Binder(peer, agent_name="py-coverage", card_ttl="PT2M")
    bound = binder.bind(PyCoverage())
    print(json.dumps({"ok": bool(bound.data_use), "peerId": peer.identity.peer_id, "entries": bound.data_use}),
          flush=True)
    deadline = time.monotonic() + max_seconds
    reported = False
    while time.monotonic() < deadline:
        time.sleep(1.0)
        if not reported:
            # S3-H-06: the console's rule entries read as data, once the group has settled
            read = rules(peer)
            if all(read.values()):
                print(json.dumps({"rules": {k: len(v) for k, v in read.items()},
                                  "sample": read["Constraint"][0].template}), flush=True)
                reported = True
    bound.close()
    peer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
