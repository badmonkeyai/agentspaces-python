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
"""Layer 4 from Python (L3L4-COVERAGE.md §6.4): the capability services
over the peer's PIPE_DATA pipes, in the protocols the Java providers speak.

- ``pipes``: the multiplexer, ``Pipes(peer)``.
- ``aggregate``: push-sum and rosters (``aspace:cap/aggregate``).
- ``semantic``: the hashing embedder and the query pipe (``aspace:cap/semantic-discovery``).
- ``remote``: the actions other agents' cards declare, invoked through spaces.

Ordered takes (the Raft client), joins, and reduces are the plan's phase G
and are not here yet."""

from .pipes import Pipes
from .aggregate import Aggregate, Settle
from .semantic import HashingEmbedder, Semantic
from .remote import RemoteAction, actions, invoke

__all__ = ["Pipes", "Aggregate", "Settle", "HashingEmbedder", "Semantic", "RemoteAction", "actions", "invoke"]
