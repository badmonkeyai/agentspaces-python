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
"""PDT 2 phase 7, P2-C-01 group B (P2-B-01, P2-B-03; srad/agentspaces-pdt2.md §3.5, §10.12, §10.15): a Python reader
verifies a window of a blob against its BLAKE3 identity through the Bao outboard, group by group, over 8 MiB ``bo``
leaves under upper nodes of 16 children. The cases mirror Java's ``VerifiedWindowTest``: one corrupt byte refuses its
group and the groups before it arrive, a window crosses the seam of two leaves, a blob of one group verifies against
its root hash, a mismatched outboard fails the open, and a lazy reader loads only its window."""

import json
import pathlib

import pytest

from agentspaces.capabilities import Content, MemoryStore, Pipes
from agentspaces.pdt import NodeStore, PBlob, Pdt, bao, blake3, cids, refs
from agentspaces.pdt.kinds import BoNode
from agentspaces.pdt.refs import pref_record
from agentspaces.space import Space
from fleet import Network, NetPeer
from test_pdt_vectors import java_random_bytes

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = BoNode.GROUP_BYTES


def _leaf(data: bytes, first_group: int = 0) -> tuple[BoNode, bytes]:
    """A leaf ``bo`` node over at most 512 groups and the chaining value of its subtree."""
    cvs = [blake3.group_cv(data[i:i + GROUP], first_group + (i // GROUP) << BoNode.GROUP_LOG)
           for i in range(0, max(1, len(data)), GROUP)]
    parents = bytearray()

    def pre_order(lo, hi):
        if hi - lo == 1:
            return cvs[lo]
        at = len(parents)
        parents.extend(bytes(BoNode.PARENT_BYTES))
        mid = lo + (1 << ((hi - lo - 1).bit_length() - 1))
        left, right = pre_order(lo, mid), pre_order(mid, hi)
        parents[at:at + BoNode.PARENT_BYTES] = left + right
        return blake3.parent(left, right, False)

    cv = pre_order(0, len(cvs))
    return BoNode(len(data), bytes(parents), []), cv


def _claim(store: NodeStore, data: bytes) -> tuple[str, str]:
    """The identity and the root of the outboard of a blob of at most one leaf, the outboard stored."""
    node, _cv = _leaf(data)
    return bao.identity_of(data), store.put(node.encode())


def test_a_window_reads_its_bytes_and_one_corrupt_byte_refuses_its_group_after_the_groups_before_it():
    data = java_random_bytes(42, 300_000)
    store = NodeStore()
    claim = _claim(store, data)
    honest = PBlob.of(data, store)
    assert honest.identity() == claim[0]
    assert honest.open_verified(20_000, 200_000, claim).read() == data[20_000:220_000]
    edited = bytearray(data)
    edited[5 * GROUP + 100] ^= 0x01  # group 5
    forged = PBlob.of(bytes(edited), store)
    window = forged.open_verified(GROUP, 8 * GROUP, claim)
    assert window.read() == data[GROUP:5 * GROUP], "groups 1 to 4 arrive"
    with pytest.raises(OSError, match="chunk group 5"):
        window.read()
    with pytest.raises(OSError, match="chunk group 5"):
        window.read(), "every later read fails the same way"


def test_a_blob_of_one_group_verifies_against_its_root_hash():
    data = b"a small blob" * 100
    store = NodeStore()
    claim = _claim(store, data)
    assert claim[0] == cids.identity(blake3.digest(data))
    assert PBlob.of(data, store).open_verified(3, 500, claim).read() == data[3:503]
    with pytest.raises(OSError, match="chunk group 0"):
        PBlob.of(data[:-1] + b"?", store).open_verified(0, 10, claim).read()


def test_an_outboard_of_other_content_or_size_fails_the_open():
    data = java_random_bytes(43, 100_000)
    store = NodeStore()
    other = java_random_bytes(44, 100_000)
    _identity, other_bao = _claim(store, other)
    with pytest.raises(OSError, match="does not chain to the identity"):
        PBlob.of(data, store).open_verified(0, 10, (bao.identity_of(data), other_bao))
    _id, short = _claim(store, other[:90_000])
    with pytest.raises(OSError, match="covers 90000 bytes"):
        PBlob.of(data, store).open_verified(0, 10, (bao.identity_of(data), short))


@pytest.fixture(scope="module")
def split():
    """``pdt_bo_split``: 8 MiB + 5,000 bytes of the stream, a full leaf and a one-group leaf under the root."""
    leaf_bytes = BoNode.LEAF_GROUPS * GROUP
    data = java_random_bytes(42, leaf_bytes + 5000)
    parts = GOLDEN["pdt_bo_split"].split(",")
    store = NodeStore()
    full, _cv = _leaf(data[:leaf_bytes])
    for node in (bytes.fromhex(parts[0]), full.encode(), BoNode(5000, b"", []).encode()):
        store.put(node)
    return data, store, (parts[1], cids.of(bytes.fromhex(parts[0])))


def test_a_window_across_the_seam_of_two_outboard_leaves_verifies_through_both(split):
    data, outboard, claim = split
    store = NodeStore()
    store.put_all({c: outboard.get(c) for c in outboard.cids()})
    blob = PBlob.of(data, store)
    seam = BoNode.LEAF_GROUPS * GROUP
    assert blob.open_verified(seam - 40_000, 44_000, claim).read() == data[seam - 40_000:seam + 4000]


def test_a_lazy_reader_loads_only_the_window_and_its_path(split):
    data, outboard, claim = split
    writer = NodeStore()
    root = PBlob.of(data, writer).root()

    class Loader:
        loaded = []

        def load(self, cid):
            self.loaded.append(cid)
            return writer.get(cid) or outboard.get(cid)

    loader = Loader()
    reader = PBlob.load(NodeStore(), root, loader)
    assert reader.open_verified(3 * GROUP, 2 * GROUP, claim).read() == data[3 * GROUP:5 * GROUP]
    chunks = [c for c in loader.loaded if cids.codec_of(c) == cids.RAW]
    assert 0 < len(chunks) <= 3 and len(loader.loaded) < 12, "only the window's chunks, its path, and two bo nodes"


def test_a_blob_head_gives_its_value_the_claim_it_names_and_a_manifest_names_one_too():
    peer = NetPeer(Network(), "zPythonBlake3")
    content = Content(Pipes(peer), Space(peer, "content"), MemoryStore(), seed=1)
    pdt = Pdt(content, Space(peer, "pdt"), NodeStore(), seed=1)
    data = java_random_bytes(45, 100_000)
    blob = PBlob.of(data, pdt.store)
    identity, outboard = _claim(pdt.store, data)
    pdt.write_head(pref_record("file", refs.KIND_BLOB, blob.root(), size=len(data),
                               attrs={bao.BLAKE3_ATTR: identity, bao.BAO_ATTR: outboard}))
    value = pdt.blob_ref("file").deref()
    assert value.claim == (identity, outboard)
    assert value.open_verified(1000, 50_000).read() == data[1000:51_000]
    assert bao.claim_of({bao.BLAKE3_ATTR: identity, bao.BAO_ATTR: outboard}) == (identity, outboard)
    assert bao.claim_of({bao.BLAKE3_ATTR: blob.root(), bao.BAO_ATTR: outboard}) is None, "a sha2-256 CID is no identity"
    assert bao.claim_of({bao.BLAKE3_ATTR: identity}) is None and bao.claim_of(None) is None
