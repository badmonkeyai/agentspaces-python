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
"""The in-memory fleet the verb tests run on: peers wired to each other
without sockets (an addressed frame reaches its peer, a rumor every other
peer, as test_layer4.py wires them), a pinned clock, and a wait helper. Not
a test file: the suites import it."""

import time

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.peer import Peer


class Clock:
    """A pinned clock in milliseconds; ``advance`` moves it."""

    def __init__(self, millis):
        self.millis = millis

    def __call__(self):
        return self.millis / 1000

    def advance(self, millis):
        self.millis += millis


class Network:
    """Peers by id; an addressed frame goes to its peer, a rumor to every other."""

    def __init__(self):
        self.peers: dict[str, "NetPeer"] = {}

    def add(self, peer: "NetPeer"):
        self.peers[peer.identity.peer_id] = peer
        return peer


class NetPeer(Peer):
    """A peer of a ``Network``: sends are delivered in-process, and a rumor of
    its own folds here as well (gossip hands it back to us)."""

    def __init__(self, network: Network, group: str, clock=None):
        super().__init__(Identity.generate(), group, clock=clock)
        self.network = network
        self._running = True
        self._socket = object()
        network.add(self)

    def _send(self, kind, body, to=None):
        env = wire.envelope(self.group, kind, self.identity.peer_id,
                            wire.hlc_now(self.identity.peer_id, self._now_ms()), body, to)
        targets = [self.network.peers[to]] if to else [p for pid, p in self.network.peers.items()
                                                       if pid != self.identity.peer_id]
        for target in targets:
            if target._accepts(env):
                target._handle(env)
        if kind == "RUMOR" and to is None:
            rumor = cbor.loads(body)
            if str(rumor.get("streamId", "")).startswith("space:"):
                delta = cbor.loads(rumor["payload"])
                if delta.get("claimEntry") and isinstance(delta.get("claim"), dict):
                    self._fold_claim(delta["claimEntry"], delta["claim"])
                if isinstance(delta.get("state"), dict):
                    self._fold(delta["state"])

    def pull_space(self, space):
        pass

    def pull_revocations(self):
        pass


def fleet(group: str, n: int, clock=None) -> list:
    """``n`` peers of one group that have introduced themselves to each other."""
    network = Network()
    peers = [NetPeer(network, group, clock=clock) for _ in range(n)]
    for p in peers:
        p.introduce()
    return peers


def until(timeout: float, condition) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.025)
    return condition()
