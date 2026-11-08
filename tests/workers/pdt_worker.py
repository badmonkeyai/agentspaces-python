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
"""The Python worker of a Java cross-language refs test (srad/agentspaces-pdt.md
PD-C-04): dials a Java peer over tcp, joins by the founding, holds a map ref by
name in the ref space, applies the swaps it is told on stdin, and prints one
JSON line per command.

    python tests/workers/pdt_worker.py <host> <port> <founding> <refName> [refSpace] [contentSpace]

Commands on stdin, one per line:

    swap <key> <value>      assoc key to value (a JSON value when it parses, else text)
    dissoc <key>            remove a key
    deref                   print {"ok":true,"root":...,"seq":...,"value":{...}}
    heads                   print the heads
    stats                   print the facade's counters
    roots <path>            the roots of the maps and files in a CBOR file {"maps": [{k: v,...},...],
                            "files": [bytes,...]} (PD-Q-INT-01): {"ok":true,"maps":[...],"files":[...]}
    read <space> <schema>   pull the space and print its live entries of the schema whose
                            payload is here: {"ok":true,"entries":[{"id":..,"bytes":..},..],"pending":n}
                            (an escalated payload comes through the facade, PD-E-01)
    quit

Every answer is one JSON line with ``ok``; a failure carries ``reason``."""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentspaces.capabilities import Content, MemoryStore, Pipes  # noqa: E402
from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.pdt import NodeStore, Pdt  # noqa: E402
from agentspaces.peer import Peer  # noqa: E402
from agentspaces.space import Space  # noqa: E402


def _value(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def _answer(**fields) -> None:
    print(json.dumps(fields, separators=(",", ":"), default=str), flush=True)


def _summary(raw: bytes) -> dict:
    """A record's scalar fields and the size of the rest, so the Java side can check a value."""
    from agentspaces import cbor
    value = cbor.loads(raw)
    if not isinstance(value, dict):
        return {"type": type(value).__name__}
    out = {}
    for key, item in value.items():
        if isinstance(item, (str, int, bool)) or item is None:
            out[key] = item
        elif isinstance(item, dict):
            out[key] = {"entries": len(item)}
        elif isinstance(item, (list, bytes)):
            out[key] = {"length": len(item)}
    return out


def _deref(ref) -> dict:
    value = ref.deref()
    heads = ref.heads()
    return {"ok": True, "root": value.root(), "seq": max([h.seq for h in heads], default=0),
            "heads": len(heads), "value": value.to_dict()}


def main() -> int:
    host, port, founding, name = sys.argv[1:5]
    ref_space = sys.argv[5] if len(sys.argv) > 5 else "pdt"
    content_space = sys.argv[6] if len(sys.argv) > 6 else "content"
    peer = Peer(Identity.generate(), group_id_from_founding(founding.encode("utf-8")))
    peer.connect(host, int(port))
    content = Content(Pipes(peer), Space(peer, content_space), MemoryStore())
    pdt = Pdt(content, Space(peer, ref_space), NodeStore(), load_timeout=15.0)
    content.run(0.1)
    pdt.run(0.1)
    time.sleep(1.0)
    peer.pull_ads()
    peer.pull_space(content_space)
    peer.pull_space(ref_space)
    time.sleep(1.0)
    ref = pdt.map_ref(name)
    _answer(ok=True, peerId=peer.identity.peer_id, seedPeer=peer.seed_peer, ref=name, **{"heads": len(ref.heads())})
    for line in sys.stdin:
        parts = line.strip().split(" ", 2)
        if not parts or not parts[0]:
            continue
        try:
            command = parts[0]
            if command == "quit":
                break
            if command == "swap":
                key, value = parts[1], _value(parts[2] if len(parts) > 2 else "")
                ref.swap(lambda m: m.assoc(key, value))
                _answer(**_deref(ref))
            elif command == "dissoc":
                key = parts[1]
                ref.swap(lambda m: m.dissoc(key))
                _answer(**_deref(ref))
            elif command == "deref":
                peer.pull_space(ref_space)
                time.sleep(0.3)
                _answer(**_deref(ref))
            elif command == "heads":
                _answer(ok=True, heads=[{"root": h.root, "seq": h.seq, "base": list(h.base), "issuer": h.issuer}
                                        for h in ref.heads()])
            elif command == "stats":
                _answer(ok=True, stats=pdt.stats(), trees=pdt.trees.stats())
            elif command == "roots":
                from agentspaces import cbor as _cbor
                from agentspaces.pdt import PBlob, PMap
                spec = _cbor.loads(pathlib.Path(parts[1]).read_bytes())
                scratch = NodeStore()
                map_roots = []
                for entries in spec["maps"]:
                    value = PMap.empty(scratch)
                    for key, item in entries.items():
                        value = value.assoc(key, item)
                    map_roots.append(value.root())
                file_roots = [PBlob.of(data, scratch).root() for data in spec["files"]]
                _answer(ok=True, maps=map_roots, files=file_roots)
            elif command == "read":
                space_name, schema = parts[1], parts[2]
                peer.pull_space(space_name)
                time.sleep(0.5)
                app = Space(peer, space_name)
                found = []
                pending = 0
                for entry_id, dto in list(peer.states.items()):
                    record = dto.get("record") or {}
                    if record.get("type") != schema or not app._mine(dto):
                        continue
                    raw = peer.payload_of(dto)
                    if raw is None:
                        pending += 1
                        continue
                    found.append({"id": entry_id, "bytes": len(raw), "payloadRef": record.get("payloadRef"),
                                  "value": _summary(raw)})
                _answer(ok=True, entries=found, pending=pending, payloadsRead=pdt.payloads_read,
                        space=app.name, trees=pdt.trees.stats())
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
