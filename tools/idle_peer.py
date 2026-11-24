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

"""A dial-only Python peer for the mixed idle liveness run (tools/conformance/mixed/idle.mjs,
srad/agentspaces-event-loop.md EL-P-03; DRIFT-FROM-PHASE6 item 2). It joins a founding-text
group through its seeds (dialled in list order, 250 ms apart, the first to answer wins, a lost
seed fails over to the next), names the seed it holds in ``relay.via``, and stays idle. It speaks
the line protocol of the Java IdleMember and the Ruby idle peer on stdin and stdout:

    python tools/idle_peer.py <founding> <port[,port...]> [host]

    READY <peerId>                        once dialled
    view  -> VIEW <peerId>=<m1,m2,...>    its view: a member heard from whose card has not lapsed
    via   -> VIA <relay.via or ->         the member this peer names as its relay
    loop  -> LOOP <peerId>=health:<..>;resumes:<n>;links_silent:<n>;seed_pings:<n>;seed_dials:<n>;reconnects:<n>
    write <n> -> WROTE <n>                writes a ``mixed.Note#v1`` {from: python, n} into ``notes``, 1 min lease
    notes -> NOTES <from>:<n> ...         per writer, the highest ``n`` held in ``notes``
    quit  -> BYE                          closes the peer and exits
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agentspaces.identity import Identity, group_id_from_founding  # noqa: E402
from agentspaces.peer import Peer, _ad_expires_ms  # noqa: E402


NOTES = "notes"
NOTE_TYPE = "mixed.Note#v1"


def view(peer: Peer) -> list:
    """The members held now, itself left out: one heard from with no card yet, or a card not lapsed."""
    now = peer._now_ms()
    me = peer.identity.peer_id
    return sorted(m for m, ad in list(peer.members.items()) if m != me and (not ad or _ad_expires_ms(ad) > now))


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: python tools/idle_peer.py <founding> <port[,port...]> [host]", file=sys.stderr)
        return 2
    founding, ports = sys.argv[1], sys.argv[2]
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    identity = Identity.generate()
    peer = Peer(identity, group_id_from_founding(founding.encode("utf-8")))
    peer.connect_any([(host, int(p)) for p in ports.split(",")])
    me = identity.peer_id
    peer.pull_space(NOTES)  # the background writes of the live run (opens the space and its sweep)
    print(f"READY {me}", flush=True)
    for line in sys.stdin:
        command = line.strip()
        if command == "view":
            print(f"VIEW {me}={','.join(view(peer))}", flush=True)
        elif command == "via":
            print(f"VIA {peer.resource_hints.get('relay.via') or '-'}", flush=True)
        elif command == "loop":
            h = peer.loop_health()
            # No sweep runs until a space is opened, so only a sweep that was started and died counts.
            sweep_ok = peer._sweeper is None or h["sweepAlive"]
            state = "ok" if (h["readerAlive"] and sweep_ok and not h["closed"] and not h["framesWedged"]) else "down"
            print(f"LOOP {me}=health:{state};connected:{int(bool(h['connected']))};resumes:{h['resumes']};"
                  f"links_silent:{h['links_silent']};seed_pings:{h['seed_pings']};seed_dials:{h['seed_dials']};"
                  f"late_seed_channels:{h['late_seed_channels']};readerRestarts:{h['readerRestarts']};"
                  f"framesWedged:{h['framesWedged']};reconnects:{peer.reconnects}", flush=True)
        elif command.startswith("write "):
            n = int(command.split()[1])
            peer.write_entry(NOTES, NOTE_TYPE, {"from": "python", "n": n}, lease_millis=60_000)
            print(f"WROTE {n}", flush=True)
        elif command == "notes":
            highest = {}
            for note in peer.find(NOTE_TYPE):
                if isinstance(note, dict) and "from" in note:
                    highest[note["from"]] = max(highest.get(note["from"], -1), int(note["n"]))
            print("NOTES " + " ".join(f"{k}:{v}" for k, v in sorted(highest.items())), flush=True)
        elif command == "quit":
            peer.close()
            print("BYE", flush=True)
            return 0
        elif command:
            print(f"ERROR unknown command {command}", flush=True)
    peer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
