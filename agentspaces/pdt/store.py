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

"""The node store (srad/agentspaces-pdt.md §3.4; PD-S-01, PD-S-04, PD-S-06,
PD-S-07): nodes by CID over a memory or file backend, with ``has`` without a
read, batch ``put``, root pins with a reference count, and the reachability
walks a tree needs (``complete``, ``missing``, ``reachable``). Every read
verifies the bytes against the CID (PD-N-06); a block that no longer hashes to
its CID reads as absent. ``collect(roots)`` is a mark and sweep from the
pinned roots plus the roots given."""

from __future__ import annotations

import hashlib
import os
import threading
from collections import deque
from pathlib import Path

from . import cids, nodes


class MemoryBackend:
    kind = "memory"

    def __init__(self):
        self._blocks: dict[str, bytes] = {}

    def has(self, cid: str) -> bool:
        return cid in self._blocks

    def get(self, cid: str) -> bytes | None:
        return self._blocks.get(cid)

    def put(self, cid: str, data: bytes) -> None:
        self._blocks.setdefault(cid, bytes(data))

    def remove(self, cid: str) -> None:
        self._blocks.pop(cid, None)

    def cids(self) -> list[str]:
        return list(self._blocks)

    def size(self, cid: str) -> int:
        block = self._blocks.get(cid)
        return 0 if block is None else len(block)


class FileBackend:
    """One file per CID under ``path``; pins in ``pins`` (one CID and count per line)."""
    kind = "file"

    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

    def _file(self, cid: str) -> Path:
        cids.parse(cid)
        return self.path / cid

    def has(self, cid: str) -> bool:
        return self._file(cid).is_file()

    def get(self, cid: str) -> bytes | None:
        f = self._file(cid)
        return f.read_bytes() if f.is_file() else None

    def put(self, cid: str, data: bytes) -> None:
        f = self._file(cid)
        if f.is_file():
            return
        tmp = f.with_name(f.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, f)

    def remove(self, cid: str) -> None:
        self._file(cid).unlink(missing_ok=True)

    def cids(self) -> list[str]:
        return [p.name for p in self.path.iterdir() if p.is_file() and cids.is_cid(p.name)]

    def size(self, cid: str) -> int:
        f = self._file(cid)
        return f.stat().st_size if f.is_file() else 0

    def read_pins(self) -> dict[str, int]:
        f = self.path / "pins"
        pins = {}
        if f.is_file():
            for line in f.read_text().splitlines():
                cid, _, count = line.partition(" ")
                if cids.is_cid(cid) and count.isdigit() and int(count) > 0:
                    pins[cid] = int(count)
        return pins

    def write_pins(self, pins: dict[str, int]) -> None:
        tmp = self.path / "pins.tmp"
        tmp.write_text("".join(f"{cid} {count}\n" for cid, count in sorted(pins.items())))
        os.replace(tmp, self.path / "pins")


class NodeStore:
    """CID-keyed nodes with pins and reachability. ``NodeStore()`` is in memory;
    ``NodeStore(path)`` keeps one file per node."""

    MAX_DEPTH = nodes.MAX_DEPTH

    def __init__(self, path=None, backend=None):
        self.backend = backend or (FileBackend(path) if path is not None else MemoryBackend())
        self._pins: dict[str, int] = self.backend.read_pins() if hasattr(self.backend, "read_pins") else {}
        self._lock = threading.RLock()
        self._links: dict[str, list[str]] = {}
        self.nodes_written = 0
        self.bytes_written = 0

    @property
    def kind(self) -> str:
        return self.backend.kind

    # ---- blocks

    def has(self, cid: str) -> bool:
        return self.backend.has(cid)

    def get(self, cid: str) -> bytes | None:
        """The verified bytes, or None when absent or corrupt (PD-N-06)."""
        data = self.backend.get(cid)
        if data is None:
            return None
        if not cids.verifies(cid, data):
            return None
        return data

    def put(self, data: bytes, codec: int = cids.DAG_CBOR) -> str:
        cid = cids.of(data, codec)
        self.put_verified(cid, data)
        return cid

    def put_verified(self, cid: str, data: bytes) -> bool:
        """Stores bytes the caller verified against the CID; returns whether they were new."""
        with self._lock:
            if self.backend.has(cid):
                return False
            self.backend.put(cid, data)
            self.nodes_written += 1
            self.bytes_written += len(data)
            return True

    def put_all(self, items: dict[str, bytes]) -> int:
        """Stores every (cid, bytes) whose bytes hash to the CID; returns how many were new."""
        new = 0
        for cid, data in items.items():
            if cids.verifies(cid, data) and self.put_verified(cid, data):
                new += 1
        return new

    def remove(self, cid: str) -> None:
        with self._lock:
            self.backend.remove(cid)
            self._links.pop(cid, None)

    def cids(self) -> list[str]:
        return self.backend.cids()

    def size_of(self, cid: str) -> int:
        return self.backend.size(cid)

    def count(self) -> int:
        return len(self.backend.cids())

    def bytes_held(self) -> int:
        return sum(self.backend.size(c) for c in self.backend.cids())

    # ---- pins

    def pin(self, root: str) -> int:
        with self._lock:
            self._pins[root] = self._pins.get(root, 0) + 1
            self._persist_pins()
            return self._pins[root]

    def unpin(self, root: str) -> int:
        with self._lock:
            count = self._pins.get(root, 0) - 1
            if count <= 0:
                self._pins.pop(root, None)
                count = 0
            else:
                self._pins[root] = count
            self._persist_pins()
            return count

    def pinned(self) -> dict[str, int]:
        return dict(self._pins)

    def _persist_pins(self) -> None:
        if hasattr(self.backend, "write_pins"):
            self.backend.write_pins(self._pins)

    # ---- trees

    def links(self, cid: str, data: bytes | None = None) -> list[str]:
        """The links of a held node (cached); a node the codec refuses reads as a leaf."""
        cached = self._links.get(cid)
        if cached is not None:
            return cached
        if data is None:
            data = self.get(cid)
            if data is None:
                return []
        try:
            out = nodes.links(data, cid)
        except nodes.NodeFormatError:
            out = []
        self._links[cid] = out
        return out

    def _walk(self, root: str, want_missing: bool):
        seen, missing = set(), []
        frontier = deque([(root, 1)])
        while frontier:
            cid, depth = frontier.popleft()
            if cid in seen:
                continue
            seen.add(cid)
            data = self.get(cid)
            if data is None:
                missing.append(cid)
                continue
            if depth >= self.MAX_DEPTH:
                raise nodes.NodeFormatError(f"tree deeper than {self.MAX_DEPTH} levels", cid)
            for link in self.links(cid, data):
                if link not in seen:
                    frontier.append((link, depth + 1))
        return seen, missing

    def reachable(self, root: str) -> set[str]:
        """Every CID reachable from a root that the store holds."""
        seen, missing = self._walk(root, False)
        return seen - set(missing)

    def missing(self, root: str) -> set[str]:
        """The CIDs reachable from a root the store lacks (children of absent nodes unknown)."""
        return set(self._walk(root, True)[1])

    def complete(self, root: str) -> bool:
        return not self._walk(root, True)[1]

    def held_under(self, root: str) -> int:
        return len(self.reachable(root))

    # ---- collection

    def collect(self, extra_roots=()) -> int:
        """Mark from the pins and ``extra_roots``, sweep the rest; returns how many were removed (PD-S-04)."""
        with self._lock:
            marked = set()
            for root in list(self._pins) + list(extra_roots):
                marked |= self.reachable(root)
            removed = 0
            for cid in self.cids():
                if cid not in marked:
                    self.remove(cid)
                    removed += 1
            return removed

    def stats(self) -> dict:
        return {"nodesHeld": self.count(), "bytesHeld": self.bytes_held(), "pins": len(self._pins),
                "nodesWritten": self.nodes_written, "bytesWritten": self.bytes_written}


class RecordingStore:
    """A store view that records the nodes written through it (a swap's delta) and
    reads through to the store beneath."""

    def __init__(self, store: NodeStore):
        self.store = store
        self.written: dict[str, bytes] = {}

    def __getattr__(self, name):
        return getattr(self.store, name)

    def put(self, data: bytes, codec: int = cids.DAG_CBOR) -> str:
        cid = cids.of(data, codec)
        self.put_verified(cid, data)
        return cid

    def put_verified(self, cid: str, data: bytes) -> bool:
        new = self.store.put_verified(cid, data)
        if new:
            self.written[cid] = bytes(data)
        return new


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
