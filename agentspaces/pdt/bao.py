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

"""BLAKE3 identities and verified windows (srad/agentspaces-pdt2.md §3.5; PDT 2 phase 7, P2-C-01 group B, P2-B-01,
P2-B-03): the Python port of Java's ``BlobIdentity`` claim and ``VerifiedWindow``.

A blob's identity is the CIDv1 ``raw`` over the BLAKE3 multihash (0x1e) of its whole content, whatever the chunking.
A blob ref's head names it in the advisory attribute ``pdt.blake3`` and the root of its Bao outboard, a tree of ``bo``
nodes, in ``pdt.bao`` (rule 10); a flat manifest carries the same pair in its ``attrs`` (rule 11). ``claim_of`` reads
the pair from either, and refuses nothing: an unusable pair reads as no claim.

A window walks, at open, the ``bo`` nodes that cover its 16 KiB chunk groups from the root ``pdt.bao`` names: each
parent pair on the way must hash to the value above it, the top pair with BLAKE3's root flag to the identity, and each
child node must cover the bytes its parent claims, so the walk ends with the expected chaining value of every group in
the window. A node that breaks the chain fails the open. Each group then loads as the read reaches it, from the chunks
of the blob tree that cover it, and the window delivers its bytes only when the group's chaining value equals the
expected one. A group that does not verify, or a node or chunk the loader cannot have, fails the read with an
``OSError`` naming it, after the groups before it arrived, and every later read with the same error. A blob of one
group verifies that group hashed as the root against the identity."""

from __future__ import annotations

from . import blake3, cids, nodes
from .kinds import BoNode

BLAKE3_ATTR = "pdt.blake3"
BAO_ATTR = "pdt.bao"
GROUP = BoNode.GROUP_BYTES


def identity_of(data: bytes) -> str:
    """The identity of some content: the BLAKE3 of the whole of it as a CIDv1 ``raw`` over multihash 0x1e."""
    return cids.identity(blake3.digest(data))


def claim_of(attrs) -> tuple[str, str] | None:
    """The ``(identity, outboard root)`` a head's or a manifest's attributes name, or None when either is absent or not
    in its one canonical form (advisory, as rule 10 says)."""
    identity, bao = (attrs or {}).get(BLAKE3_ATTR), (attrs or {}).get(BAO_ATTR)
    if not cids.is_identity(identity) or not cids.is_cid(bao) or cids.codec_of(bao) != cids.DAG_CBOR:
        return None
    return identity, bao


class VerifiedWindow:
    """``length`` bytes of a blob tree from ``offset``, delivered group by group as each verifies (P2-B-03)."""

    def __init__(self, tree, claim: tuple[str, str], offset: int, length: int):
        if offset < 0 or length < 0 or offset + length > tree.size:
            raise IndexError(f"range {offset}+{length} outside a blob of {tree.size} bytes")
        self.tree = tree
        self.identity, bao = claim
        self.size = tree.size
        self.position = offset
        self.end = offset + length
        self.single_group = BoNode.groups(self.size) == 1
        self.expected: dict[int, bytes] = {}
        self.group = -1
        self.current = b""
        self.failure: OSError | None = None
        self.chunks = []
        self._chunk_index = 0
        self._chunk = None
        if length == 0:
            return
        first, last = offset // GROUP, (self.end - 1) // GROUP
        root = self._node(bao)
        if root.size != self.size:
            raise OSError(f"the outboard {bao} covers {root.size} bytes where the blob {tree.root} holds {self.size}")
        self._walk(bao, root, 0, cids.identity_digest(self.identity), True, first, last)
        start = first * GROUP
        self.chunks = tree.chunks_in(start, min(self.size, (last + 1) * GROUP) - start)

    # ---- the outboard

    def _node(self, cid: str) -> BoNode:
        try:
            return BoNode.decode(cid, self.tree.fetch(cid))
        except (nodes.NodeFormatError, nodes.NodeUnavailable) as e:
            raise OSError(f"the outboard node {cid} does not read: {e}") from None

    def _walk(self, cid: str, node: BoNode, first_group: int, cv: bytes, root: bool, first: int, last: int) -> None:
        """Walks one ``bo`` node whose subtree starts at group ``first_group`` and must chain to ``cv``."""
        blocks = BoNode.child_sizes(node.size)
        per_leaf = BoNode.groups(blocks[0]) if blocks else 1
        leaves = len(blocks) if blocks else BoNode.groups(node.size)
        self._descend((cid, node, blocks, first_group, per_leaf, first, last), 0, 0, leaves, cv, root)

    def _descend(self, walk: tuple, pair: int, lo: int, hi: int, cv: bytes, root: bool) -> None:
        """Descends the pre-order parents of leaves ``[lo, hi)``, whose subtree value is ``cv``, from parent pair
        ``pair``: BLAKE3 puts the largest power of two strictly below the count on the left."""
        cid, node, blocks, first_group, per_leaf, first, last = walk
        if hi - lo == 1:
            group_start = first_group + lo * per_leaf
            if not blocks:
                self.expected[group_start] = cv
                return
            child = node.children[lo].cid
            child_node = self._node(child)
            if child_node.size != blocks[lo]:
                raise OSError(f"the outboard node {child} covers {child_node.size} bytes where its parent {cid} "
                              f"claims {blocks[lo]}")
            self._walk(child, child_node, group_start, cv, False, first, last)
            return
        at = pair * BoNode.PARENT_BYTES
        left, right = node.parents[at:at + 32], node.parents[at + 32:at + BoNode.PARENT_BYTES]
        if blake3.parent(left, right, root) != cv:
            raise OSError(f"the outboard node {cid} does not chain to the identity {self.identity} at parent {pair}")
        mid = lo + (1 << ((hi - lo - 1).bit_length() - 1))

        def overlaps(a, b):
            return first_group + a * per_leaf <= last and first_group + b * per_leaf > first

        if overlaps(lo, mid):
            self._descend(walk, pair + 1, lo, mid, left, False)
        if overlaps(mid, hi):
            self._descend(walk, pair + 1 + (mid - lo - 1), mid, hi, right, False)

    # ---- the groups

    def _load(self, g: int) -> None:
        """Loads group ``g`` from the chunks that cover it and verifies it before it is delivered."""
        start, stop = g * GROUP, min(self.size, (g + 1) * GROUP)
        out = bytearray()
        filled = start
        while filled < stop:
            located = self.chunks[self._chunk_index]
            chunk_end = located.start + located.length
            if chunk_end <= filled:
                self._chunk_index += 1
                self._chunk = None
                continue
            if self._chunk is None:
                try:
                    self._chunk = self.tree.chunk_at(located)
                except (nodes.NodeFormatError, nodes.NodeUnavailable) as e:
                    raise OSError(f"chunk group {g}: chunk {located.cid} does not read: {e}") from None
            n = min(chunk_end, stop) - filled
            at = filled - located.start
            out.extend(self._chunk[at:at + n])
            filled += n
        data = bytes(out)
        cv = blake3.digest(data) if self.single_group else blake3.group_cv(data, g << BoNode.GROUP_LOG)
        if cv != self.expected.get(g):
            raise OSError(f"chunk group {g} (bytes {start} to {stop}) does not verify against the identity "
                          f"{self.identity}")
        self.current, self.group = data, g

    def read(self, size: int = -1) -> bytes:
        """Up to ``size`` verified bytes (all that remain when negative), never past the group that fails."""
        if self.failure is not None:
            raise self.failure
        out = bytearray()
        while self.position < self.end and (size < 0 or len(out) < size):
            g = self.position // GROUP
            if g != self.group:
                try:
                    self._load(g)
                except OSError as e:
                    self.failure = e  # the chunk cursor has moved past the group's start, so it is not loaded again
                    if out:
                        return bytes(out)
                    raise
            at = self.position - g * GROUP
            n = min(len(self.current) - at, self.end - self.position, size - len(out) if size >= 0 else self.end)
            out.extend(self.current[at:at + n])
            self.position += n
        return bytes(out)
