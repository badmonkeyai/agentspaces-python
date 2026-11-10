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
"""PDT 2 phase 7, P2-C-01 group R (P2-R-03, P2-R-04; srad/agentspaces-pdt2.md §3.7, §10.10): the Python reader of a
relaxed vector. It indexes an ``rr`` tree through ``z`` by binary search and a dense node by radix, reads an ``rr``
root whose tail another port left empty, refuses by name every form §3.7 refuses, and packs a relaxed vector into the
``vr`` vector of its elements. A write to a relaxed vector packs it first, which a port may do (§10.10)."""

import pytest

from agentspaces import cbor
from agentspaces.pdt import NodeStore, PVector, cids, nodes
from agentspaces.pdt.kinds import RrRoot, RvNode
from agentspaces.pdt.nodes import Embedded, Link, NodeFormatError


def _leaf(store, lo, hi) -> Link:
    return Link(store.put(nodes.encode({"k": nodes.KIND_V, "e": [Embedded(cbor.dumps(i)) for i in range(lo, hi)]})))


def _rv(store, children, sizes) -> Link:
    return Link(store.put(RvNode(children, sizes).encode()))


def _root(store, count, shift, trie, tail) -> str:
    return store.put(RrRoot(count, shift, trie, [Embedded(cbor.dumps(i)) for i in tail]).encode())


def _relaxed(store, leaves=((0, 32), (32, 40), (40, 72), (72, 96)), tail=range(96, 100)):
    rv = _rv(store, [_leaf(store, lo, hi) for lo, hi in leaves], [hi for _lo, hi in leaves])
    return _root(store, leaves[-1][1] + len(tail), 5, rv, tail)


def test_a_relaxed_vector_reads_by_its_size_tables_iterates_and_packs():
    store = NodeStore()
    v = PVector.load(store, _relaxed(store))
    assert v.count() == 100 and v.relaxed()
    assert [v.nth(i) for i in (0, 31, 32, 39, 40, 71, 72, 95, 96, 99)] == [0, 31, 32, 39, 40, 71, 72, 95, 96, 99]
    assert list(v) == list(range(100))
    packed = v.packed()
    assert not packed.relaxed() and packed.root() == PVector.empty(NodeStore()).conj_many(range(100)).root()
    assert v == packed, "equality compares packed roots"
    grown = v.conj(100)
    assert not grown.relaxed() and list(grown) == list(range(101)), "a write packs the vector first"


def test_an_rr_root_whose_tail_another_port_left_empty_reads():
    store = NodeStore()
    v = PVector.load(store, _relaxed(store, tail=()))
    assert v.count() == 96 and v.nth(95) == 95 and list(v)[-1] == 95


@pytest.mark.parametrize("build, why", [
    (lambda s: _root(s, 50, 5, Link(s.put(RvNode([_leaf(s, 0, 32), _leaf(s, 32, 50)], None).encode())), []),
     "an rv node without z"),
    (lambda s: _root(s, 50, 5, _rv(s, [_leaf(s, 0, 32), _leaf(s, 32, 50)], [32, 50]), []), "a size table on a dense node"),
    (lambda s: _root(s, 50, 5, _rv(s, [_leaf(s, 0, 10), _leaf(s, 10, 50)], [10, 50]), []), "more than the 32"),
    (lambda s: _root(s, 40, 10, _rv(s, [_rv(s, [_leaf(s, 0, 8), _leaf(s, 8, 16)], [8, 16]), _leaf(s, 16, 40)],
                                    [16, 40]), []), "a vector leaf at level 5"),
    (lambda s: _root(s, 40, 5, _rv(s, [_leaf(s, 0, 8), _leaf(s, 8, 30)], [8, 40]), []), "does not hold the 32"),
    (lambda s: _root(s, 41, 5, _rv(s, [_leaf(s, 0, 8), _leaf(s, 8, 40)], [8, 40]), []), "does not hold the 41"),
    (lambda s: _root(s, 40, 35, _rv(s, [_leaf(s, 0, 8), _leaf(s, 8, 40)], [8, 40]), []), "shift 35"),
])
def test_the_reader_refuses_by_name_every_form_section_3_7_refuses(build, why):
    store = NodeStore()
    with pytest.raises(NodeFormatError, match=why):
        list(PVector.load(store, build(store)))


def test_an_rv_node_at_the_leaf_level_is_refused():
    store = NodeStore()
    inner = _rv(store, [_leaf(store, 0, 8), _leaf(store, 8, 16)], [8, 16])
    trie = _rv(store, [inner, _leaf(store, 16, 40)], [16, 40])
    with pytest.raises(NodeFormatError, match="an rv node where a vector leaf belongs"):
        list(PVector.load(store, _root(store, 40, 5, trie, [])))
    assert cids.is_cid(trie.cid)
