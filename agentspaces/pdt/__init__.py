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

"""Persistent data trees in Python (srad/agentspaces-pdt.md, PD-C-04): the
node codec and CIDs, ``PMap``, ``PSet``, ``PVector``, ``PBlob``, the node
store, the tree exchange over the content swarm (tags 8 to 11), and refs
(``deref`` and ``swap`` with the merge of §3.6.1).

    pdt = Pdt(content, Space(peer, "pdt"))
    facts = pdt.map_ref("facts")
    facts.swap(lambda m: m.assoc("k", "v"))
    facts.deref().get("k")
"""

from . import cids, nodes, fastcdc
from .blob import PBlob, BlobTree
from .champ import PMap, PSet
from .nodes import NodeFormatError, NodeUnavailable
from .store import NodeStore
from .values import Raw
from .vector import PVector
from .tree import Trees, TreeFetch
from .refs import Pdt, Ref, PRef, PConflict, pref_record, pref_violation, PREF_TYPE

__all__ = ["cids", "nodes", "fastcdc", "PBlob", "BlobTree", "PMap", "PSet", "PVector", "NodeStore", "Raw",
           "NodeFormatError", "NodeUnavailable", "Trees", "TreeFetch", "Pdt", "Ref", "PRef", "PConflict",
           "pref_record", "pref_violation", "PREF_TYPE"]
