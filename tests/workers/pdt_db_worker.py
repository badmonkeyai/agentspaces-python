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
"""The Python reader of a Java ``db`` ref (srad/agentspaces-pdt2.md P2-O-03, example 34): dials a Java
peer over tcp, joins by the founding, follows the ref space lazily, and answers DataScript reads of one
``db`` ref through ``DbReader`` (P2-D-09), so the reader loads only the nodes a read walks.

    python tests/workers/pdt_db_worker.py <host> <port> <founding> <refName> [refSpace] [contentSpace]

Commands on stdin, one per line; a value or a component list is JSON:

    await <root> <seconds>          wait until the ref derefs to the root: {"ok":true,"root":...,"heads":n,"held":k}
    lookup <attr> <value>           {"ok":true,"root":...,"e":n or null,"entity":{...},"held":k}
    datoms <index> <components>     {"ok":true,"root":...,"datoms":[[e,a,v,tx],...],"held":k}
    quit

``held`` is the count of nodes in this reader's store: the nodes its reads loaded, and the nodes the
heads carried inline. Every answer is one JSON line with ``ok``; a failure carries ``reason``."""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentspaces.capabilities import Content, MemoryStore, Pipes  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.pdt import NodeStore, Pdt  # noqa: E402
from agentspaces.pdt.refs import FOLLOW_LAZY  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402
from agentspaces.space import Space  # noqa: E402


def _answer(**fields) -> None:
    print(json.dumps(fields, separators=(",", ":"), default=str), flush=True)


def _root(ref):
    heads = ref.heads()
    return (ref.deref().root if heads else None), len(heads)


def main() -> int:
    host, port, founding, name = sys.argv[1:5]
    ref_space = sys.argv[5] if len(sys.argv) > 5 else "pdt"
    content_space = sys.argv[6] if len(sys.argv) > 6 else "content"
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    store = NodeStore()
    content = Content(Pipes(peer), Space(peer, content_space), MemoryStore())
    pdt = Pdt(content, Space(peer, ref_space), store, load_timeout=15.0, follow=FOLLOW_LAZY)
    content.run(0.1)
    pdt.run(0.1)
    time.sleep(1.0)
    peer.pull_ads()
    peer.pull_space(content_space)
    peer.pull_space(ref_space)
    ref = pdt.db_ref(name)
    _answer(ok=True, peerId=peer.identity.peer_id, ref=name, heads=len(ref.heads()))
    for line in sys.stdin:
        parts = line.strip().split(" ", 2)
        if not parts or not parts[0]:
            continue
        try:
            command = parts[0]
            if command == "quit":
                break
            if command == "await":
                want, seconds = parts[1], float(parts[2])
                deadline = time.monotonic() + seconds
                root, heads = _root(ref)
                while root != want and time.monotonic() < deadline:
                    peer.pull_space(ref_space)
                    time.sleep(0.3)
                    root, heads = _root(ref)
                _answer(ok=root == want, root=root, heads=heads, held=store.count(),
                        **({} if root == want else {"reason": f"the ref derefs to {root}, not {want}"}))
            elif command == "lookup":
                attr, value = parts[1], json.loads(parts[2])
                db = ref.deref()
                e = db.lookup(attr, value)
                _answer(ok=True, root=db.root, e=e, entity=db.entity(e) if e is not None else {}, held=store.count())
            elif command == "datoms":
                index, components = parts[1], json.loads(parts[2])
                db = ref.deref()
                found = [[d.e, d.a, d.v, d.tx] for d in db.datoms(index, *components)]
                _answer(ok=True, root=db.root, datoms=found, held=store.count())
            else:
                _answer(ok=False, reason=f"unknown command {command}")
        except Exception as e:  # noqa: BLE001 - one line per command for the Java side
            _answer(ok=False, reason=repr(e))
    pdt.close()
    content.stop()
    peer.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "reason": repr(e)}, separators=(",", ":")), flush=True)
        sys.exit(1)
