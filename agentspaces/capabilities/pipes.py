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
"""The capability pipes (TECH-SPEC §8, CapabilityPipes): one PIPE_DATA
envelope per frame, addressed to a member, carrying ``{capability,
payload}``; handlers by capability type on the receiving side."""

from __future__ import annotations

import random
from typing import Callable


class Pipes:
    """The multiplexer over a ``Peer``: at most one per peer, shared by the
    capabilities built on it."""

    def __init__(self, peer):
        self.peer = peer
        self._random = random.Random()

    def on_capability(self, capability_type: str, handler: Callable[[str, bytes], None]) -> None:
        """Registers ``handler(from_peer_id, payload)`` for one capability's frames."""
        self.peer.pipe_handlers[capability_type] = handler

    def send(self, to: str, capability_type: str, payload: bytes, via: list | None = None) -> None:
        """One frame to a member; ``via`` names the relays the member declared
        (its ``relay.via`` hint or a holding's ``via``), extending the path the
        seed carries the frame along (SPEC §5.4, v0.1.23)."""
        self.peer.send_pipe(to, capability_type, payload, via)

    def members(self) -> list[str]:
        """The members a frame can reach (those that signed a frame on our
        connection), this peer excluded. A member known only from the peers
        stream is left out: a dial-only peer cannot address it directly."""
        return [m for m in self.peer.reachable if m != self.peer.identity.peer_id]

    def random_members(self, n: int) -> list[str]:
        """``n`` members at random (PeerSampler.randomMembers)."""
        ids = self.members()
        self._random.shuffle(ids)
        return ids[:n]
