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
(``deref`` and ``swap`` with the merge of §3.6.1). PDT 2 phase 0 (srad/agentspaces-pdt2.md §8)
adds the level-2 node kinds to the codec with their typed readers in ``kinds`` and items in
``items``, the ``pdt.ancestry`` reader in ``ancestry``, and the store's entry records in
``content_store``. PDT 2 phase 2 adds ``DbReader`` in ``db``, the lazy reader of a DataScript
database's ``db`` and ``dn`` nodes (P2-D-09). PDT 2 phase 7 (P2-C-01) brings the port to feature level 2: ``PText``
in ``text``, relaxed vectors in ``vector``, BLAKE3 in ``blake3`` and verified windows in ``bao``, ``dcz`` frames,
negentropy and RIBLT in ``sync``, push reception in ``push``, the store's cards and signed pins in ``content_store``,
``db`` refs, version 2 heads, and the version graph in ``refs``.

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
from .db import DbReader
from .text import PText
from .tree import Trees, TreeFetch
from .refs import Pdt, Ref, PRef, PConflict, decode_pref, pref_record, pref_violation, PREF_TYPE

__all__ = ["cids", "nodes", "fastcdc", "PBlob", "BlobTree", "PMap", "PSet", "PVector", "NodeStore", "Raw",
           "NodeFormatError", "NodeUnavailable", "DbReader", "PText", "Trees", "TreeFetch", "Pdt", "Ref", "PRef",
           "PConflict", "decode_pref", "pref_record", "pref_violation", "PREF_TYPE"]
