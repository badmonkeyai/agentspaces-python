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

"""A head's ancestry, the reserved attribute ``pdt.ancestry`` (PDT 2 phase 0, P2-V-01;
srad/agentspaces-pdt2.md §3.10 and §6.10.3, rule 9). A head is a record every member reads and
a strict reader refuses a field it does not know, so the CID of the head's ``vg`` node rides in
``attrs`` beside ``pdt.issued`` and ``pdt.issuer``; the ``PRef`` schema keeps its twelve fields
and a level-1 reader passes the attribute through as text.

The attribute is advisory. A reader uses it only when its text is a CIDv1 of codec ``dag-cbor``
over sha2-256 in its one base32 form, and the node it names hashes to it and decodes as a ``vg``
node of the head's own root; otherwise the head reads as one without ancestry (P2-V-02), and
nothing is refused, counted, or struck."""

from __future__ import annotations

from . import cids
from .kinds import VgNode
from .nodes import NodeFormatError

ANCESTRY_ATTR = "pdt.ancestry"


def ancestry_cid(record: dict) -> str | None:
    """The CID a ``PRef`` record names under ``pdt.ancestry`` when the text is a usable one."""
    value = (record.get("attrs") or {}).get(ANCESTRY_ATTR)
    if not cids.is_cid(value) or cids.codec_of(value) != cids.DAG_CBOR:
        return None
    return value


def read_ancestry(record: dict, data: bytes) -> VgNode | None:
    """The ``vg`` node of a head from the bytes a store or a fetch returned for ``ancestry_cid``,
    or None when the head names none, the bytes hash to another CID, or they do not decode as a
    ``vg`` node of the head's root."""
    cid = ancestry_cid(record)
    if cid is None or not cids.verifies(cid, data):
        return None
    try:
        node = VgNode.decode(cid, data)
    except NodeFormatError:
        return None
    return node if node.root == record.get("root") else None
