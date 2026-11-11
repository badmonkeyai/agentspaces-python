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

"""What the persistent values share (srad/agentspaces-pdt.md §3.1, §10.2):
the value codec, the spill rules of PD-N-05, the context a value reads cold
nodes through (PD-V-06), and the flusher that hashes and writes new nodes once
(PD-V-08).

A value slot holds, in memory, inline CBOR ``bytes``, a spilled ``XNode``, a
spilled ``BlobNode``, a spilled sub-tree (a CHAMP node or a vector root), or
the ``str`` CID of a spilled node still cold. A bare link item (tag 42 over a
CID) in a value slot always names a spilled node, so an application value or
key is never one; hold a CID as text."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from .. import cbor
from . import cids, nodes
from .nodes import NodeFormatError

VALUE_LIMIT = 1024
TREE_LIMIT = 4096
MAX_X_VALUE = nodes.MAX_NODE_BYTES - 7


# ------------------------------------------------------------------ codec

@dataclass(frozen=True)
class Raw:
    """A key or value given as exact CBOR bytes (one data item), for a form
    ``cbor.dumps`` does not produce, such as a 32-bit float."""
    bytes: bytes


def encode_value(value) -> bytes:
    from .text import PText, to_wire
    if isinstance(value, Raw):
        return value.bytes
    if isinstance(value, PText):
        return to_wire(value.leaf())  # PDT 2 phase 7, P2-T-02: a text travels in its value form
    return cbor.dumps(value)


def decode_value(data: bytes):
    """A value's CBOR as Python data; a text in its value form reads as a ``PText`` with no replica (P2-T-02)."""
    from .text import TEXT_PREFIX, PText, from_wire
    if data.startswith(TEXT_PREFIX):
        try:
            return PText.of(from_wire(data))
        except ValueError:
            pass  # an indefinite map that only starts like a text
    return cbor.loads(data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ------------------------------------------------------------------ context

class StoreLoader:
    """Loads from one store alone (PD-V-06 without the fetch)."""

    def __init__(self, store):
        self.store = store

    def load(self, cid: str) -> bytes:
        data = self.store.get(cid)
        if data is None:
            raise nodes.NodeUnavailable(cid, [], f"node {cid} is not in the store")
        return data


class Ctx:
    """The loader and hasher a value operation runs under. A level-one context writes and reads level-1 kinds only, so
    a text spills as any other map does (PDT 2 phase 7; §6.10.3, rule 7: every member reads an escalated payload)."""

    def __init__(self, loader, store=None, level_one: bool = False):
        self.loader = loader
        self.store = store
        self.level_one = level_one

    def load(self, cid: str) -> bytes:
        return self.loader.load(cid)

    @staticmethod
    def hash(key: bytes) -> bytes:
        return sha256(key)


class TreeNode:
    """A node in memory: unhashed until the flusher names it."""
    cid: str | None = None

    def encode(self, flusher: "Flusher") -> bytes:
        raise NotImplementedError

    def flush(self, flusher: "Flusher") -> str:
        data = self.encode(flusher)
        self.cid = flusher.write(data, cids.DAG_CBOR)
        return self.cid


class Flusher:
    """Hashes new nodes bottom up and writes those the store lacks (PD-V-08)."""

    def __init__(self, store):
        self.store = store
        self.written: dict[str, bytes] = {}

    def write(self, data: bytes, codec: int) -> str:
        cid = cids.of(data, codec)
        if not self.store.has(cid):
            self.store.put_verified(cid, data)
            self.written[cid] = data
        return cid

    def cid_of(self, ref) -> str:
        if isinstance(ref, str):
            return ref
        if ref.cid is not None:
            return ref.cid
        return ref.flush(self)

    @staticmethod
    def flush(node: TreeNode, store) -> dict[str, bytes]:
        flusher = Flusher(store)
        flusher.cid_of(node)
        return flusher.written


class XNode(TreeNode):
    """A value spill: ``{k:"x", v: <embedded cbor>}``."""

    def __init__(self, value: bytes):
        self.value = value

    def encode(self, flusher: Flusher) -> bytes:
        return nodes.encode({"k": nodes.KIND_X, "v": nodes.Embedded(self.value)})

    @staticmethod
    def decode(cid: str, data: bytes) -> "XNode":
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_X:
            raise NodeFormatError(f"expected an x node, found kind '{node.get('k')}'", cid)
        x = XNode(node["v"].bytes)
        x.cid = cid
        return x


class TextNode(TreeNode):
    """A text value held out of line, kind ``t`` (PDT 2 phase 7, P2-T-02): a value in the text form above 1 KiB spills
    to a node holding the canonical bytes of the same leaf, and reads back as the value it was. The node bytes are
    made at once, so a text whose node would pass the 1 MiB node bound is refused on its way into a map or a vector,
    as an ``x`` value of that size is (the phase 6 review's T1)."""

    def __init__(self, value: bytes):
        from .text import from_wire
        self.value = value
        try:
            self.node = from_wire(value).encode()
        except NodeFormatError as too_large:
            raise ValueError(f"a text value whose t node exceeds the 1 MiB node bound; split it into smaller texts: {too_large}") from None

    def encode(self, flusher: Flusher) -> bytes:
        return self.node


class BlobNode(TreeNode):
    """A spilled byte string: the blob tree of §3.3 over its content."""

    def __init__(self, content: bytes):
        self.content = content

    def flush(self, flusher: Flusher) -> str:
        from .blob import PBlob
        blob = PBlob.of(self.content, flusher.store, record=flusher.written)
        self.cid = blob.root()
        return self.cid

    def encode(self, flusher: Flusher) -> bytes:
        raise AssertionError("a blob node flushes as a tree")


# ------------------------------------------------------------------ spilling

def is_link_item(item: bytes) -> bool:
    return nodes.is_link_shaped(item)


def check_key(key: bytes) -> None:
    if is_link_item(key):
        raise ValueError("a key must not be a bare link item (CBOR tag 42 over a CID): "
                         "a link item in a map node names a spilled node; hold a CID as text")


def ref_of(item: bytes):
    """The in-memory reference of a decoded value slot: the bytes, or the CID of a spilled node."""
    return nodes.link_cid(item) if is_link_item(item) else item


def embed(ref, flusher: Flusher) -> nodes.Embedded:
    if isinstance(ref, bytes):
        return nodes.Embedded(ref)
    return nodes.Embedded(nodes.link_item(flusher.cid_of(ref)))


def same_value(a, b) -> bool:
    """Whether two references hold the same value without loading anything."""
    if a is b:
        return True
    if isinstance(a, bytes) and isinstance(b, bytes):
        return a == b
    if isinstance(a, XNode) and isinstance(b, XNode):
        return a.value == b.value
    if isinstance(a, BlobNode) and isinstance(b, BlobNode):
        return a.content == b.content
    if isinstance(a, TextNode) and isinstance(b, TextNode):
        return a.value == b.value
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def cid_of(ref) -> str | None:
    if isinstance(ref, str):
        return ref
    if isinstance(ref, TreeNode):
        return ref.cid
    return None


def equal_hashed(a, b) -> bool:
    """Whether two hashed references hold equal values: inline bytes compare, spilled nodes by CID."""
    if isinstance(a, bytes):
        return isinstance(b, bytes) and a == b
    ca, cb = cid_of(a), cid_of(b)
    return ca is not None and ca == cb


def _header_length(info: int) -> int:
    return 1 if info < 24 else 1 + (1 << (info - 24))


def spill(item: bytes, ctx: Ctx):
    """Applies PD-N-05 to one encoded value: inline bytes, or the new spill node."""
    if is_link_item(item):
        raise ValueError("a value must not be a bare link item (CBOR tag 42 over a CID): "
                         "a link item in a value slot names a spilled node; hold a CID as text")
    if len(item) <= VALUE_LIMIT:
        return item
    if not ctx.level_one:
        from .text import is_text
        if is_text(item):
            return TextNode(item)
    major, info = item[0] >> 5, item[0] & 0x1F
    if len(item) > TREE_LIMIT:
        if major == 5 and info == 31:
            return _sub_map(item, ctx) if canonical_keys(item) else _sub_ordered(item, ctx)
        if major == 4 and info != 31:
            return _sub_vector(item, ctx)
        if major == 2 and info != 31:
            return BlobNode(item[_header_length(info):])
    if len(item) > MAX_X_VALUE:
        raise ValueError(f"a value of {len(item)} CBOR bytes exceeds the {MAX_X_VALUE} bytes an x node can hold "
                         "under the 1 MiB node bound; store a value this large as a byte string, which becomes a blob,"
                         " or split it into a map or a vector")
    return XNode(item)


def _sub_map(item: bytes, ctx: Ctx):
    from .champ import ChampNode
    root = ChampNode.empty()
    count = 0
    p = 1
    while p < len(item) and item[p] != 0xFF:
        key_end = nodes.skip(item, p)
        value_end = nodes.skip(item, key_end)
        key = item[p:key_end]
        value = item[key_end:value_end]
        check_key(key)
        root, change = root.assoc(ctx.hash(key), 0, key, spill(value, ctx), ctx)
        if change == "added":
            count += 1
        p = value_end
    root.cnt = count
    return root


def canonical_keys(item: bytes) -> bool:
    """Whether an indefinite map's keys come in canonical order (shorter first, then
    bytewise), the order the Java codec gives a map and a CHAMP reassembly restores."""
    p = 1
    previous = None
    while p < len(item) and item[p] != 0xFF:
        key_end = nodes.skip(item, p)
        key = item[p:key_end]
        if previous is not None and (len(previous), previous) >= (len(key), key):
            return False
        previous = key
        p = nodes.skip(item, key_end)
    return True


class OrderedNode(TreeNode):
    """A spilled map in its written order (the Java ordered-map spill of phase 4, 10.2): an
    ``x`` node whose value links the ``vr`` of its keys and values; the vector is hashed first."""

    def __init__(self, items):
        self.items = items

    def encode(self, flusher: Flusher) -> bytes:
        return XNode(nodes.link_item(flusher.cid_of(self.items))).encode(flusher)


def _sub_ordered(item: bytes, ctx: Ctx):
    from .vector import VecRoot
    items = VecRoot.empty()
    p = 1
    while p < len(item) and item[p] != 0xFF:
        key_end = nodes.skip(item, p)
        value_end = nodes.skip(item, key_end)
        key = item[p:key_end]
        check_key(key)
        items = items.conj(spill(key, ctx), ctx)
        items = items.conj(spill(item[key_end:value_end], ctx), ctx)
        p = value_end
    return OrderedNode(items)


def _sub_vector(item: bytes, ctx: Ctx):
    from .vector import VecRoot
    info = item[0] & 0x1F
    p = 1
    if info < 24:
        n = info
    else:
        width = 1 << (info - 24)
        n = int.from_bytes(item[1:1 + width], "big")
        p += width
    root = VecRoot.empty()
    for _ in range(n):
        end = nodes.skip(item, p)
        root = root.conj(spill(item[p:end], ctx), ctx)
        p = end
    return root


# ------------------------------------------------------------------ resolving

def _header(major: int, value: int) -> bytes:
    m = major << 5
    if value < 24:
        return bytes([m | value])
    if value < 0x100:
        return bytes([m | 24, value])
    if value < 0x10000:
        return bytes([m | 25]) + value.to_bytes(2, "big")
    return bytes([m | 26]) + value.to_bytes(4, "big")


def byte_string(raw: bytes) -> bytes:
    return _header(2, len(raw)) + raw


def resolve(ref, ctx: Ctx, depth: int = 0) -> bytes:
    """The CBOR bytes of a value reference, loading and reassembling a spilled node."""
    from .champ import ChampNode
    from .vector import VecRoot
    if isinstance(ref, bytes):
        return ref
    if isinstance(ref, BlobNode):
        return byte_string(ref.content)
    if isinstance(ref, TextNode):
        return ref.value
    if depth > nodes.MAX_DEPTH:
        raise NodeFormatError(f"spilled values nested deeper than {nodes.MAX_DEPTH} levels", cid_of(ref))
    if isinstance(ref, XNode):
        return _resolve_linked(nodes.link_cid(ref.value), ctx, depth + 1) if is_link_item(ref.value) else ref.value
    if isinstance(ref, OrderedNode):
        return _reassemble_ordered(ref.items, ctx, depth)
    if isinstance(ref, ChampNode):
        return _reassemble_map(ref, ctx, depth)
    if isinstance(ref, VecRoot):
        return _reassemble_array(ref, ctx, depth)
    cid = ref
    data = ctx.load(cid)
    if cids.codec_of(cid) == cids.RAW:
        return byte_string(data)
    kind = nodes.kind_of(data)
    if kind == nodes.KIND_X:
        value = XNode.decode(cid, data).value
        return _resolve_linked(nodes.link_cid(value), ctx, depth + 1) if is_link_item(value) else value
    if kind == nodes.KIND_M:
        return _reassemble_map(ChampNode.load_root(cid, data), ctx, depth)
    if kind == nodes.KIND_VR:
        return _reassemble_array(VecRoot.decode(cid, data), ctx, depth)
    if kind == nodes.KIND_B:
        return byte_string(read_blob(cid, data, ctx))
    if kind == nodes.KIND_T:
        if ctx.level_one:
            raise NodeFormatError("a level-one tree holds no text node (rule 7)", cid)
        from .kinds import TextLeaf
        from .text import to_wire
        return to_wire(TextLeaf.decode(cid, data))
    raise NodeFormatError(f"a spilled value cannot be a node of kind '{kind}'", cid)


def _resolve_linked(cid: str, ctx: Ctx, depth: int) -> bytes:
    """The value an ``x`` envelope links (phase 4, 10.2): an ordered map when the linked node
    is a ``vr`` (``bf``, the items in order, ``ff``), a byte string when it is a chunk or a ``b``."""
    from .vector import VecRoot
    if depth > nodes.MAX_DEPTH:
        raise NodeFormatError(f"spilled values nested deeper than {nodes.MAX_DEPTH} levels", cid)
    data = ctx.load(cid)
    if cids.codec_of(cid) == cids.RAW:
        return byte_string(data)
    kind = nodes.kind_of(data)
    if kind == nodes.KIND_VR:
        return _reassemble_ordered(VecRoot.decode(cid, data), ctx, depth)
    if kind == nodes.KIND_B:
        return byte_string(read_blob(cid, data, ctx))
    raise NodeFormatError(f"an x envelope links a node of kind '{kind}'", cid)


def _reassemble_ordered(root, ctx: Ctx, depth: int) -> bytes:
    if root.n % 2:
        raise NodeFormatError(f"an ordered-map envelope links a vector of {root.n} items; keys and values pair up",
                              cid_of(root))
    out = bytearray(b"\xbf")
    for i in range(root.n):
        out.extend(resolve(root.nth(i, ctx), ctx, depth + 1))
    out.append(0xFF)
    return bytes(out)


def _reassemble_map(root, ctx: Ctx, depth: int) -> bytes:
    entries = sorted(root.entries(0, ctx), key=lambda kv: (len(kv[0]), kv[0]))
    out = bytearray(b"\xbf")
    for key, value in entries:
        out.extend(key)
        out.extend(resolve(value, ctx, depth + 1))
    out.append(0xFF)
    return bytes(out)


def _reassemble_array(root, ctx: Ctx, depth: int) -> bytes:
    out = bytearray(_header(4, root.n))
    for i in range(root.n):
        out.extend(resolve(root.nth(i, ctx), ctx, depth + 1))
    return bytes(out)


def read_blob(root: str, root_bytes: bytes, ctx: Ctx) -> bytes:
    """Reads a stored blob tree depth first with an explicit stack, bounded by the tree depth."""
    out = bytearray()
    stack = [(root, 1)]
    while stack:
        cid, depth = stack.pop()
        data = root_bytes if cid == root else ctx.load(cid)
        if cids.codec_of(cid) == cids.RAW:
            out.extend(data)
            continue
        if depth >= nodes.MAX_DEPTH:
            raise NodeFormatError(f"tree deeper than {nodes.MAX_DEPTH} levels", cid)
        node = nodes.decode(data, cid)
        if node.get("k") != nodes.KIND_B:
            raise NodeFormatError(f"expected a blob node, found kind '{node.get('k')}'", cid)
        for link in reversed(node.get("c") or []):
            stack.append((link.cid, depth + 1))
    return bytes(out)


# ------------------------------------------------------------------ loaders

class StoreThenFetchLoader:
    """Reads the store and otherwise starts a fetch through ``fetch(cid)`` (a
    callable returning the bytes or raising ``NodeUnavailable``), the production
    loader of PD-V-06."""

    def __init__(self, store, fetch: Callable[[str], bytes]):
        self.store = store
        self.fetch = fetch

    def load(self, cid: str) -> bytes:
        data = self.store.get(cid)
        if data is not None:
            return data
        data = self.fetch(cid)
        if data is None:
            raise nodes.NodeUnavailable(cid, [], f"node {cid} could not be fetched")
        return data


# ------------------------------------------------------------------ payload trees (group E)

def write_payload(item: bytes, store) -> tuple[str, dict[str, bytes]]:
    """A space payload as a tree (srad/agentspaces-pdt.md PD-E-02, the Java ``PayloadTree.write``):
    the spill rules over the whole CBOR item, a bare value or a single chunk under an ``x``
    envelope, so a root is always a dag-cbor node. Returns the root and the nodes written."""
    if not item:
        raise ValueError("an empty payload is not a CBOR item")
    ctx = Ctx(StoreLoader(store), store, level_one=True)
    spilled = spill(item, ctx)
    if isinstance(spilled, bytes):
        root = XNode(spilled)
        return root.flush(Flusher(store)), {}
    flusher = Flusher(store)
    if isinstance(spilled, BlobNode):
        blob_cid = flusher.cid_of(spilled)
        if cids.codec_of(blob_cid) == cids.RAW:
            root = XNode(nodes.link_item(blob_cid))
            return root.flush(flusher), flusher.written
        return blob_cid, flusher.written
    return flusher.cid_of(spilled), flusher.written


def read_payload(root: str, ctx: Ctx) -> bytes:
    """The payload bytes ``write_payload`` was given, from the root (the Java ``PayloadTree.read``)."""
    if cids.codec_of(root) != cids.DAG_CBOR:
        raise NodeFormatError("a payload root is a dag-cbor node", root)
    kind = nodes.kind_of(ctx.load(root))
    if kind not in (nodes.KIND_X, nodes.KIND_M, nodes.KIND_VR, nodes.KIND_B):
        raise NodeFormatError(f"a payload root is an x, m, vr, or b node, not '{kind}'", root)
    return resolve(root, ctx)
