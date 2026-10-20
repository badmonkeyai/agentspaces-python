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
- ``ordered``: the Raft client of the ordered log (``aspace:cap/ordered-log``,
  JS-V-05): ``OrderedLog.take`` submits a claim command to the advertised
  leader and observes the commit through the space.
- ``connect``: the agent side of the connector protocol (``aspace:cap/data-query``
  and ``aspace:cap/asset-invoke``, JS-C-14): ``DataQueryClient.fetch`` pull-once
  by canonical hash, ``connect.invoke`` of one operation through an AssetCard.

The Raft voter, the fleet-wide join modes, reduces, and the connector runtime
stay in Java (and TypeScript)."""

from . import connect, ordered
from .pipes import Pipes
from .aggregate import Aggregate, Settle
from .connect import (AssetChange, AssetInvocation, AssetInvocationResult, DataQuery, DataQueryClient, DataResult,
                      Fetched, asset_cards, canonical_hash, invoke_ops)
from .ordered import LogMember, OrderedLog
from .semantic import HashingEmbedder, Semantic
from .remote import RemoteAction, actions, invoke

__all__ = ["Pipes", "Aggregate", "Settle", "HashingEmbedder", "Semantic", "RemoteAction", "actions", "invoke",
           "OrderedLog", "LogMember", "ordered", "connect", "DataQuery", "DataResult", "AssetChange",
           "AssetInvocation", "AssetInvocationResult", "DataQueryClient", "Fetched", "asset_cards",
           "canonical_hash", "invoke_ops"]
