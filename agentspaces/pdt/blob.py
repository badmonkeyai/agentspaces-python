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

"""``PBlob``, the prolly tree over FastCDC chunks (srad/agentspaces-pdt.md §3.3,
§10.2; PD-B-02, PD-B-03, PD-B-04). Chunks are raw nodes (codec 0x55). A blob of
zero or one chunk is that chunk; otherwise interior nodes ``{k:"b", h, c, z}``
group the level below, closing a node after an entry whose sha256 digest's
first four bytes read as an unsigned big-endian integer below ``0x08000000``
(average fanout 32), with at least 4 and at most 256 entries per node, until
one node remains. An edit re-chunks from the start of the chunk holding the
first changed byte until a cut coincides with an old cut and reuses every old
chunk after it, so the layout stays canonical."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from . import cids, fastcdc, nodes
from .nodes import NodeFormatError

BOUNDARY = 0x08000000
MIN_FANOUT = 4
MAX_FANOUT = 256
EMPTY_ROOT = cids.of(b"", cids.RAW)


@dataclass(frozen=True)
class Entry:
    cid: str
    length: int

    def boundary(self) -> bool:
        digest = cids.parse(self.cid).digest
        return int.from_bytes(digest[:4], "big") < BOUNDARY


@dataclass(frozen=True)
class Located:
    cid: str
    start: int
    length: int


class BlobTree:
    """The interior of a blob: build, open, seek, and the chunk list."""

    def __init__(self, store, root: str, size: int, height: int, written_bytes: int, written_nodes: int, chunks,
                 loader=None):
        self.store = store
        self.root = root
        self.size = size
        self.height = height
        self.written_bytes = written_bytes
        self.written_nodes = written_nodes
        self._chunks = chunks
        #: Loads what the store lacks, so a verified window of a lazy reader fetches only its own groups (P2-B-03).
        self.loader = loader

    def fetch(self, cid: str) -> bytes:
        """A node's bytes from the store, else through the loader; ``NodeUnavailable`` when neither has it."""
        data = self.store.get(cid)
        if data is None and self.loader is not None:
            data = self.loader.load(cid)
        if data is None:
            raise nodes.NodeUnavailable(cid, [], f"node {cid} is not in the store")
        return data

    @staticmethod
    def group(level: list[Entry]) -> list[list[Entry]]:
        out, current = [], []
        for entry in level:
            current.append(entry)
            if len(current) >= MAX_FANOUT or (len(current) >= MIN_FANOUT and entry.boundary()):
                out.append(current)
                current = []
        if current:
            out.append(current)
        return out

    @staticmethod
    def encode_node(height: int, entries: list[Entry]) -> bytes:
        return nodes.encode({"k": nodes.KIND_B, "h": height, "c": [nodes.Link(e.cid) for e in entries],
                             "z": [e.length for e in entries]})

    @staticmethod
    def build(chunks: list[Entry], store, record: dict | None = None) -> "BlobTree":
        """Builds the tree over chunks already in the store and writes the interior nodes it lacks."""
        size = sum(c.length for c in chunks)
        if not chunks:
            root = store.put(b"", cids.RAW)
            return BlobTree(store, root, 0, 0, 0, 0, [])
        written, written_nodes = 0, 0
        level, height = list(chunks), 0
        while len(level) > 1:
            height += 1
            nxt = []
            for entries in BlobTree.group(level):
                data = BlobTree.encode_node(height, entries)
                cid = cids.of(data, cids.DAG_CBOR)
                if store.put_verified(cid, data):
                    written += len(data)
                    written_nodes += 1
                    if record is not None:
                        record[cid] = data
                nxt.append(Entry(cid, sum(e.length for e in entries)))
            level = nxt
        return BlobTree(store, level[0].cid, size, height, written, written_nodes, list(chunks))

    @staticmethod
    def open(store, root: str, loader=None) -> "BlobTree":
        parsed = cids.parse(root)
        data = store.get(root)
        if data is None and loader is not None:
            data = loader.load(root)
        if data is None:
            raise NodeFormatError("blob root is not in the store", root)
        if parsed.codec == cids.RAW:
            return BlobTree(store, root, len(data), 0, 0, 0, [] if not data else [Entry(root, len(data))], loader)
        node = BlobTree._decode_b(root, data)
        return BlobTree(store, root, sum(node["z"]), node["h"], 0, 0, None, loader)

    @staticmethod
    def _decode_b(cid: str, data: bytes) -> dict:
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_B:
            raise NodeFormatError(f"kind '{node.get('k')}' where a blob node was expected", cid)
        links, sizes = node.get("c") or [], node.get("z") or []
        if not links or len(links) != len(sizes):
            raise NodeFormatError(f"blob node with {len(links)} links and {len(sizes)} sizes", cid)
        if not isinstance(node.get("h"), int) or node["h"] < 1:
            raise NodeFormatError("blob node without a height", cid)
        return node

    def _load(self, cid: str, under: int) -> dict:
        data = self.store.get(cid)
        if data is None and self.loader is not None:
            data = self.loader.load(cid)
        if data is None:
            raise NodeFormatError("blob node is not in the store", cid)
        node = self._decode_b(cid, data)
        held = sum(node["z"])
        if held != under:
            raise NodeFormatError(f"blob node holds {held} bytes where its parent claims {under}", cid)
        return node

    def chunks(self) -> list[Entry]:
        if self._chunks is None:
            leaves = []
            self._collect(self.root, self.size, leaves, 1)
            self._chunks = leaves
        return self._chunks

    def _collect(self, cid: str, under: int, leaves: list, depth: int) -> None:
        if cids.codec_of(cid) == cids.RAW:
            leaves.append(Entry(cid, under))
            return
        if depth > nodes.MAX_DEPTH:
            raise NodeFormatError(f"tree deeper than {nodes.MAX_DEPTH} levels", cid)
        node = self._load(cid, under)
        for link, z in zip(node["c"], node["z"]):
            self._collect(link.cid, z, leaves, depth + 1)

    def seek(self, offset: int) -> Located:
        if offset < 0 or offset >= self.size:
            raise IndexError(f"offset {offset} outside a blob of {self.size} bytes")
        cid, start, under, depth = self.root, 0, self.size, 1
        while cids.codec_of(cid) != cids.RAW:
            if depth > nodes.MAX_DEPTH:
                raise NodeFormatError(f"tree deeper than {nodes.MAX_DEPTH} levels", cid)
            node = self._load(cid, under)
            sizes = node["z"]
            i = 0
            while i < len(sizes) - 1 and offset >= start + sizes[i]:
                start += sizes[i]
                i += 1
            cid, under = node["c"][i].cid, sizes[i]
            depth += 1
        return Located(cid, start, under)

    def chunk(self, entry: Entry) -> bytes:
        data = self.store.get(entry.cid)
        if data is None and self.loader is not None:
            data = self.loader.load(entry.cid)
        if data is None:
            raise NodeFormatError("chunk is not in the store", entry.cid)
        if len(data) != entry.length:
            raise NodeFormatError(f"chunk of {len(data)} bytes where the tree claims {entry.length}", entry.cid)
        return data

    def chunk_at(self, located: Located) -> bytes:
        return self.chunk(Entry(located.cid, located.length))

    def chunks_in(self, start: int, length: int) -> list[Located]:
        """The chunks that cover ``[start, start + length)``, loading only the path to each (PDT 2 phase 7, P2-B-03)."""
        out, pos = [], start
        while pos < start + length:
            located = self.seek(pos)
            out.append(located)
            pos = located.start + located.length
        return out


class PBlob:
    """A persistent byte sequence: read, append, splice, and ``of`` a file or stream. A blob a ref loaded carries the
    claim of its head, ``(identity, outboard root)`` (PDT 2 phase 7, P2-B-01), for ``open_verified``."""

    def __init__(self, store, tree: BlobTree, written_bytes: int = 0, claim: tuple[str, str] | None = None):
        self.store = store
        self.tree = tree
        self.written_bytes = written_bytes
        self.claim = claim

    # ---- construction

    @staticmethod
    def of(source, store, previous: "PBlob | None" = None, record: dict | None = None) -> "PBlob":
        """Chunks bytes, a path, or a binary stream into the store and builds the tree.
        With ``previous`` (a blob of this store) every chunk and interior node still
        present is shared and only the rest is written (PD-B-04)."""
        if isinstance(source, (bytes, bytearray, memoryview)):
            iterator = iter(fastcdc.chunks_of(bytes(source)))
        elif isinstance(source, (str, Path)):
            return PBlob._of_stream(open(source, "rb"), store, record, close=True)
        else:
            return PBlob._of_stream(source, store, record, close=False)
        return PBlob._write(iterator, store, record)

    @staticmethod
    def _of_stream(stream, store, record, close: bool) -> "PBlob":
        try:
            return PBlob._write(fastcdc.chunks(stream), store, record)
        finally:
            if close:
                stream.close()

    @staticmethod
    def _write(chunk_iter, store, record) -> "PBlob":
        entries, written = [], 0
        for chunk in chunk_iter:
            cid = cids.of(chunk, cids.RAW)
            if store.put_verified(cid, chunk):
                written += len(chunk)
                if record is not None:
                    record[cid] = chunk
            entries.append(Entry(cid, len(chunk)))
        tree = BlobTree.build(entries, store, record)
        return PBlob(store, tree, written + tree.written_bytes)

    @staticmethod
    def load(store, root: str, loader=None, claim: tuple[str, str] | None = None) -> "PBlob":
        return PBlob(store, BlobTree.open(store, root, loader), claim=claim)

    def identity(self) -> str:
        """The BLAKE3 identity of the content, computed from it (P2-B-01): the CIDv1 ``raw`` over multihash 0x1e."""
        from .bao import identity_of
        return identity_of(self.read_all())

    def open_verified(self, offset: int, length: int, claim: tuple[str, str] | None = None):
        """A reader of ``length`` bytes from ``offset`` that delivers each 16 KiB chunk group only once it verifies
        against the identity through the Bao outboard (P2-B-03), under ``claim`` or the claim of the head that named
        this blob; ``OSError`` at open when the outboard does not chain to the identity."""
        from .bao import VerifiedWindow
        claim = claim or self.claim
        if claim is None:
            raise ValueError(f"blob {self.root()} carries no identity and outboard to verify against (pdt.blake3, pdt.bao)")
        return VerifiedWindow(self.tree, claim, offset, length)

    # ---- reads

    def size(self) -> int:
        return self.tree.size

    def root(self) -> str:
        return self.tree.root

    def chunks(self) -> list[Entry]:
        return self.tree.chunks()

    def read(self, offset: int = 0, length: int | None = None) -> bytes:
        """The bytes of a range, loading only the chunks that hold it (PD-B-07)."""
        size = self.tree.size
        if length is None:
            length = size - offset
        if offset < 0 or length < 0 or offset + length > size:
            raise IndexError(f"range {offset}+{length} outside a blob of {size} bytes")
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            located = self.tree.seek(pos)
            data = self.tree.chunk(Entry(located.cid, located.length))
            take = min(end, located.start + located.length) - pos
            out.extend(data[pos - located.start:pos - located.start + take])
            pos += take
        return bytes(out)

    def read_all(self) -> bytes:
        return b"".join(self.tree.chunk(e) for e in self.chunks())

    def open(self, offset: int = 0, length: int | None = None):
        """A reader over a range, chunk by chunk."""
        import io
        return io.BytesIO(self.read(offset, length))

    # ---- writes

    def append(self, data: bytes) -> "PBlob":
        return self.splice(self.tree.size, 0, data)

    def splice(self, offset: int, remove_length: int, insert: bytes = b"") -> "PBlob":
        """A blob with ``remove_length`` bytes at ``offset`` replaced by ``insert``;
        re-chunks from the chunk holding the first changed byte until a cut lands on an
        old cut point, and reuses every old chunk after it (PD-B-03)."""
        size = self.tree.size
        if offset < 0 or remove_length < 0 or offset + remove_length > size:
            raise IndexError(f"splice {offset}+{remove_length} outside a blob of {size} bytes")
        old = self.chunks()
        starts = []
        pos = 0
        for e in old:
            starts.append(pos)
            pos += e.length
        # the first old chunk touched: the one holding offset, or the last when appending at the end
        first = 0
        while first < len(old) and starts[first] + old[first].length <= offset:
            first += 1
        if first >= len(old):
            first = max(0, len(old) - 1)
            # an append rewrites the old last chunk unless that chunk closed at MAX_SIZE (10.4)
            if old and old[first].length == fastcdc.MAX_SIZE and offset == size:
                first = len(old)
        # the old chunk index from which bytes are unchanged (after the removed range)
        after_offset = offset + remove_length
        resume = first
        while resume < len(old) and starts[resume] < after_offset:
            resume += 1
        delta = len(insert) - remove_length
        kept = list(old[:first])
        head_start = starts[first] if first < len(old) else size
        # the new bytes from head_start: old bytes up to offset, the insert, then old bytes from after_offset
        buffer = bytearray(self._bytes(old, starts, head_start, offset))
        buffer.extend(insert)
        # the rest of the chunk the removed range ends in, up to the first old chunk kept whole
        buffer.extend(self._bytes(old, starts, after_offset, starts[resume] if resume < len(old) else size))
        new_entries = []
        written = 0
        record = {}
        next_old = resume              # the next old chunk whose bytes have not been pulled into the buffer
        consumed = head_start          # the new offset of the next cut's start
        # new offsets at which an old cut point lies with unchanged content after it: old chunk i ends
        # there, and old chunks i + 1 onward can be reused whole
        old_cuts = {starts[i] + old[i].length + delta: i for i in range(max(resume - 1, 0), len(old))}
        while True:
            # fill the buffer with old chunks until it holds enough to cut or the end
            while next_old < len(old) and len(buffer) < 2 * fastcdc.MAX_SIZE:
                buffer.extend(self.tree.chunk(old[next_old]))
                next_old += 1
            if not buffer:
                break
            length = fastcdc.cut(buffer, 0, len(buffer))
            chunk = bytes(buffer[:length])
            del buffer[:length]
            cid = cids.of(chunk, cids.RAW)
            if self.store.put_verified(cid, chunk):
                written += len(chunk)
                record[cid] = chunk
            new_entries.append(Entry(cid, length))
            consumed += length
            # resync: the cut lands on an old cut point whose following content is unchanged, so
            # what the buffer still holds is old chunks pulled in whole and every old chunk from
            # i + 1 onward is reused as it was (the chunker restarts at every cut)
            i = old_cuts.get(consumed)
            if i is not None and i + 1 < len(old):
                new_entries.extend(old[i + 1:])
                next_old = len(old)
                break
        entries = kept + new_entries
        tree = BlobTree.build(entries, self.store, record)
        return PBlob(self.store, tree, written + tree.written_bytes)

    def _bytes(self, old: list[Entry], starts: list[int], start: int, end: int) -> bytes:
        out = bytearray()
        for i, e in enumerate(old):
            s = starts[i]
            if s + e.length <= start or s >= end:
                continue
            data = self.tree.chunk(e)
            out.extend(data[max(0, start - s):min(e.length, end - s)])
        return bytes(out)

    def __eq__(self, other) -> bool:
        return isinstance(other, PBlob) and self.root() == other.root()

    def __hash__(self) -> int:
        return hash(self.root())

    def __repr__(self) -> str:
        return f"PBlob[{self.tree.size} bytes, {self.root()}]"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
