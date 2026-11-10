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
"""The DataScript database reader (srad/agentspaces-pdt2.md §3.1.5; PDT 2 phase 2, P2-D-09): the golden
database of phase 0 read through its root, a 1,000-datom database read lazily over a counting loader, the
tail applied over the indexes, the comparators against DataScript's ``value-compare`` (the expected
signs come from DataScript 1.7.8 run on the same pairs), and the refusals of a tree out of order."""

import json
import pathlib
import uuid

import pytest

from agentspaces import cbor
from agentspaces.pdt import NodeStore, cids, nodes
from agentspaces.pdt.db import DbReader, compare_values
from agentspaces.pdt.items import Datom, Tagged
from agentspaces.pdt.kinds import DbRoot, DnNode
from agentspaces.pdt.nodes import Embedded, Link, NodeFormatError
from agentspaces.pdt.values import XNode

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
TX0 = 0x20000000
TX1, TX2 = TX0 + 1, TX0 + 2


class CountingLoader:
    """A loader over a node store that counts the nodes a read asks for."""

    def __init__(self, store: NodeStore):
        self.store = store
        self.loads = []

    def load(self, cid: str) -> bytes:
        self.loads.append(cid)
        data = self.store.get(cid)
        if data is None:
            raise nodes.NodeUnavailable(cid)
        return data


def _put(store: NodeStore, node) -> Link:
    return Link(store.put(node.encode()))


def _golden_store() -> tuple[NodeStore, str]:
    store = NodeStore()
    for name in ("pdt_db_root", "pdt_dn_leaf", "pdt_dn_tail", "pdt_dn_branch"):
        for part in GOLDEN[name].split(","):
            store.put(bytes.fromhex(part))
    return store, cids.of(bytes.fromhex(GOLDEN["pdt_db_root"].split(",")[0]))


# ------------------------------------------------------------------ the golden database of phase 0

def test_the_golden_database_reads_through_its_root_with_the_tail_applied():
    store, root = _golden_store()
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert loader.loads == [root], "restore reads the db root and nothing else (P2-D-04)"
    assert (db.max_eid, db.max_tx) == (2, TX2)
    assert db.schema[":person/name"] == {":db/index": True}
    # the tail retracts [2 :person/age 45] and asserts 46 in transaction TX2
    assert [(d.e, d.a, d.v, d.tx) for d in db.datoms("eavt")] == [
        (1, ":person/age", 36, TX1), (1, ":person/name", "Ada", TX1),
        (2, ":person/age", 46, TX2), (2, ":person/name", "Grace", TX1)]
    assert [d.v for d in db.datoms("aevt", ":person/age")] == [36, 46]
    assert [d.e for d in db.datoms("avet", ":person/name", "Grace")] == [2]
    assert db.entity(2) == {":person/age": 46, ":person/name": "Grace"}
    assert db.entity(3) == {}


def test_a_lookup_and_an_avet_read_follow_the_schema_as_datascript_does():
    store, root = _golden_store()
    db = DbReader(root, CountingLoader(store))
    with pytest.raises(ValueError, match="not :db/unique"):
        db.lookup(":person/name", "Ada")
    with pytest.raises(ValueError, match=":db/index"):
        list(db.datoms("avet", ":person/age"))
    with pytest.raises(ValueError, match="index"):
        db.datoms("vaet")
    assert db.lookup(":db/ident", ":nobody") is None, "the implicit schema makes :db/ident unique"


def test_the_branch_vector_reads_one_child_for_one_entity():
    store, _ = _golden_store()
    branch = cids.of(bytes.fromhex(GOLDEN["pdt_dn_branch"].split(",")[0]))
    empty = _put(store, DnNode.leaf("aevt", []))
    root = store.put(DbRoot(Embedded(cbor.dumps({})), 2, TX1, 128, Link(branch), empty,
                            _put(store, DnNode.leaf("avet", [])), None).encode())
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert [d.v for d in db.datoms("eavt", 2)] == [45, "Grace"]
    second = GOLDEN["pdt_dn_branch"].split(",")[2]
    assert loader.loads == [root, branch, cids.of(bytes.fromhex(second))], "the first child is never read"


# ------------------------------------------------------------------ a 1,000-datom database

PEOPLE = 250
SCHEMA = {":person/email": {":db/unique": ":db.unique/identity"},
          ":person/friend": {":db/valueType": ":db.type/ref", ":db/cardinality": ":db.cardinality/many"},
          ":person/name": {":db/index": True}}


def _people() -> list[Datom]:
    """Four datoms per person, 1,000 in all; ASCII text in one width sorts the same in every order."""
    out = []
    for e in range(1, PEOPLE + 1):
        out.append(Datom(e, ":person/age", 20 + e % 50, TX1))
        out.append(Datom(e, ":person/email", f"p{e:04d}@example.org", TX1))
        out.append(Datom(e, ":person/friend", e % PEOPLE + 1, TX1))
        out.append(Datom(e, ":person/name", f"name-{e:04d}", TX1))
    return out


INDEX_KEY = {"eavt": lambda d: (d.e, d.a, d.v, d.tx), "aevt": lambda d: (d.a, d.e, d.v, d.tx),
             "avet": lambda d: (d.a, d.v, d.e, d.tx)}


def _index(store: NodeStore, index: str, datoms: list[Datom], bf: int = 128) -> tuple[Link, int]:
    """A persistent-sorted-set tree over sorted datoms: leaves of ``bf`` datoms, each branch keying a child
    by its largest datom. Returns the root link and the depth (1 for a lone leaf)."""
    level = [(_put(store, DnNode.leaf(index, datoms[i:i + bf])), datoms[min(i + bf, len(datoms)) - 1])
             for i in range(0, len(datoms), bf)] or [(_put(store, DnNode.leaf(index, [])), None)]
    depth, height = 1, 0
    while len(level) > 1:
        height += 1
        level = [(_put(store, DnNode.branch(height, index, [k for _, k in level[i:i + bf]],
                                            [c for c, _ in level[i:i + bf]])), level[min(i + bf, len(level)) - 1][1])
                 for i in range(0, len(level), bf)]
        depth += 1
    return level[0][0], depth


def _database(datoms, tail=(), schema=None, bf=128):
    store = NodeStore()
    schema = SCHEMA if schema is None else schema
    indexed = {a for a, p in schema.items() if ":db/unique" in p or p.get(":db/index")
               or p.get(":db/valueType") == ":db.type/ref"}
    links, depth = {}, {}
    for index in ("eavt", "aevt", "avet"):
        chosen = [d for d in datoms if index != "avet" or d.a in indexed]
        links[index], depth[index] = _index(store, index, sorted(chosen, key=INDEX_KEY[index]), bf)
    tail_link = _put(store, DnNode.tail(list(tail))) if tail else None
    root = store.put(DbRoot(Embedded(cbor.dumps(schema)), max(d.e for d in datoms), TX1 + len(tail), bf,
                            links["eavt"], links["aevt"], links["avet"], tail_link).encode())
    return store, root, depth


def test_the_first_datom_of_a_thousand_reads_at_most_depth_plus_one_nodes():
    datoms = _people()
    assert len(datoms) == 1000
    store, root, depth = _database(datoms)
    assert depth["eavt"] == 2
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    first = next(iter(db.datoms("eavt")))
    assert (first.e, first.a) == (1, ":person/age")
    assert len(loader.loads) <= depth["eavt"] + 1, loader.loads


def test_every_read_of_a_thousand_datoms_equals_the_sorted_set():
    datoms = _people()
    store, root, _ = _database(datoms, bf=8)
    db = DbReader(root, CountingLoader(store))
    by = {i: sorted(datoms, key=INDEX_KEY[i]) for i in INDEX_KEY}
    assert list(db.datoms("eavt")) == by["eavt"]
    assert list(db.datoms("aevt")) == by["aevt"]
    assert list(db.datoms("avet")) == sorted((d for d in datoms if d.a != ":person/age"), key=INDEX_KEY["avet"])
    assert list(db.datoms("eavt", 17)) == [d for d in by["eavt"] if d.e == 17]
    assert list(db.datoms("eavt", 17, ":person/name")) == [Datom(17, ":person/name", "name-0017", TX1)]
    assert list(db.datoms("eavt", 17, ":person/name", "nobody")) == []
    assert list(db.datoms("aevt", ":person/friend", 9)) == [Datom(9, ":person/friend", 10, TX1)]
    assert [d.e for d in db.datoms("avet", ":person/friend", 10)] == [9]
    assert list(db.datoms("eavt", PEOPLE + 1)) == []
    assert list(db.datoms("aevt", ":person/zzz")) == []


def test_an_entity_and_a_lookup_read_only_their_own_paths():
    store, root, depth = _database(_people())
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert db.lookup(":person/email", "p0200@example.org") == 200
    assert len(loader.loads) <= 1 + depth["avet"], loader.loads
    assert db.lookup(":person/email", "nobody@example.org") is None
    assert db.entity(200) == {":person/age": 20, ":person/email": "p0200@example.org",
                              ":person/friend": (201,), ":person/name": "name-0200"}


def test_a_read_stops_at_the_first_datom_past_its_components():
    store, root, depth = _database(_people(), bf=8)
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert depth["eavt"] == 4
    assert len(db.entity(17)) == 4
    # the path to entity 17's leaf, and at most the next leaf, where the datom past entity 17 sits
    assert len(loader.loads) <= 1 + depth["eavt"] + 1, loader.loads


def test_the_tail_retracts_asserts_and_reasserts_over_the_indexes():
    datoms = _people()
    tail = [Datom(5, ":person/name", "name-0005", -(TX1 + 1)), Datom(5, ":person/name", "Eve", TX1 + 1),
            Datom(5, ":person/friend", 1, TX1 + 1), Datom(5, ":person/friend", 6, -(TX1 + 2)),
            Datom(251, ":person/email", "new@example.org", TX1 + 2), Datom(251, ":person/email", "new@example.org",
                                                                          -(TX1 + 3)),
            Datom(251, ":person/email", "new@example.org", TX1 + 3), Datom(1, ":person/age", 21, -(TX1 + 3))]
    store, root, _ = _database(datoms, tail, bf=16)
    db = DbReader(root, CountingLoader(store))
    assert db.entity(5) == {":person/age": 25, ":person/email": "p0005@example.org", ":person/friend": (1,),
                            ":person/name": "Eve"}
    assert db.lookup(":person/email", "new@example.org") == 251
    assert db.entity(1) == {":person/email": "p0001@example.org", ":person/friend": (2,),
                            ":person/name": "name-0001"}
    assert [d.v for d in db.datoms("avet", ":person/name")][:5] == ["Eve", "name-0001", "name-0002", "name-0003",
                                                                    "name-0004"]
    assert [(d.e, d.v, d.tx) for d in db.datoms("aevt", ":person/friend", 5)] == [(5, 1, TX1 + 1)]
    assert [d.e for d in db.datoms("eavt")][-1] == 251
    # name 5 and friend 6 of entity 5 and the age of entity 1 leave; Eve, friend 1, and entity 251's email arrive
    assert sum(1 for _ in db.datoms("eavt")) == 1000


def test_a_spilled_value_reads_as_the_value_it_names():
    store = NodeStore()
    long_text = "a long biography " * 100
    spill = store.put(XNode(cbor.dumps(long_text)).encode(None))
    datoms = [Datom(1, ":person/bio", Link(spill), TX1), Datom(1, ":person/name", "Ada", TX1)]
    eavt, _ = _index(store, "eavt", datoms)
    aevt, _ = _index(store, "aevt", datoms)
    avet, _ = _index(store, "avet", [])
    root = store.put(DbRoot(Embedded(cbor.dumps({})), 1, TX1, 128, eavt, aevt, avet, None).encode())
    db = DbReader(root, CountingLoader(store))
    assert db.entity(1) == {":person/bio": long_text, ":person/name": "Ada"}
    assert [d.v for d in db.datoms("aevt", ":person/bio", 1, long_text)] == [long_text]


def test_a_spilled_schema_reads_through_its_link():
    store = NodeStore()
    schema = store.put(XNode(cbor.dumps(SCHEMA)).encode(None))
    datoms = [Datom(1, ":person/email", "a@example.org", TX1)]
    links = {i: _index(store, i, datoms)[0] for i in INDEX_KEY}
    root = store.put(DbRoot(Embedded(nodes.link_item(schema)), 1, TX1, 128, links["eavt"], links["aevt"],
                            links["avet"], None).encode())
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert loader.loads == [root]
    assert db.lookup(":person/email", "a@example.org") == 1
    assert schema in loader.loads


# ------------------------------------------------------------------ the comparators

@pytest.mark.parametrize("x, y, sign", [
    # value-compare of DataScript 1.7.8 on the same pairs, run 2026-11-09
    (":a/c", ":a.b/c", -1),                      # a keyword compares its namespace before its name
    (":a", ":a/b", -1), (":b", ":a/b", -1),      # a keyword without a namespace sorts first
    ("￿", "\U0001f600", 1),                 # text compares by UTF-16 code unit, as Java's String does
    (1, 1.0, 0), (1, 1.5, -1), (2, Tagged.bigint(2), 0), (Tagged.bigint(5), 6, -1),
    (1, True, 1), (True, "x", -1), (":x", "x", -1), (b"\x01", "x", -1), (Tagged.bigint(5), "s", -1),
    (1.5, True, 1), (False, True, -1),
    (Tagged.uuid(uuid.UUID(int=1 << 127)), Tagged.uuid(uuid.UUID(int=0)), -1),  # Java's UUID compares signed
    (Tagged.instant(5), Tagged.instant(6), -1), (Tagged.instant(5), Tagged.uuid(uuid.UUID(int=0)), -1),
    # PDT 2 phase 2 gate, P2-D-09: a text that starts with a backslash is the string after it, the escape the
    # Clojure face writes for a string that starts with ':' or '\\', and ':' alone is a string
    ("\\:x", "B", -1), ("\\b", "a", 1), ("\\:x", ":x", 1), ("\\:x", "\\:x", 0), (":", "a", -1), (":", ":a", 1),
])
def test_values_compare_as_datascript_value_compare_does(x, y, sign):
    assert compare_values(x, y) == sign
    assert compare_values(y, x) == -sign


def test_the_golden_sample_answers_as_datascript_does():
    # PDT 2 phase 2 gate, P2-D-09: pdt_db_sample is 1,000 folded datoms and a three-datom tail; each answer of
    # pdt_db_sample_answers is a dn leaf of the datoms DataScript returns, in the index's order
    root, *parts = GOLDEN["pdt_db_sample"].split(",")
    store = NodeStore()
    for part in parts:
        store.put(bytes.fromhex(part))
    answers = {name: [(d.e, d.a, d.v) for d in DnNode.decode(None, bytes.fromhex(leaf)).datoms]
               for name, leaf in (pair.split("=", 1) for pair in GOLDEN["pdt_db_sample_answers"].split(","))}
    loader = CountingLoader(store)
    db = DbReader(root, loader)
    assert loader.loads == [root]
    read = lambda index, *components: [(d.e, d.a, d.v) for d in db.datoms(index, *components)]
    assert len(read("eavt")) == 1001
    assert read("eavt", 7) == answers["eavt_7"]
    assert read("eavt", 126) == answers["eavt_126"]
    assert read("aevt", ":p/name") == answers["aevt_name"]
    assert read("avet", ":p/name", "Ada") == answers["avet_name_ada"]
    assert read("avet", ":p/friend", 9) == answers["avet_friend_9"]
    assert read("eavt", 42) == answers["entity_42"]
    assert read("avet", ":p/email", "p42@example.org") == answers["lookup_email_p42"]
    assert read("avet", ":p/name", "Person 7") == answers["avet_name_person7"] == []
    assert db.lookup(":p/email", "p42@example.org") == 42
    assert db.entity(7)[":p/tag"] == (":tag/odd",)
    assert db.entity(7)[":p/name"] == "Ada"


def test_two_byte_arrays_have_no_datascript_order():
    assert compare_values(b"\x01", b"\x01") == 0
    assert compare_values(b"\x01", b"\x02") is None, "DataScript orders two arrays by identity hash"


def test_a_byte_array_component_reads_by_equality():
    datoms = [Datom(1, ":file/hash", b"\x09", TX1), Datom(2, ":file/hash", b"\x01", TX1),
              Datom(3, ":file/hash", b"\x05", TX1)]
    store = NodeStore()
    links = {"eavt": _index(store, "eavt", datoms)[0], "aevt": _index(store, "aevt", datoms)[0],
             "avet": _index(store, "avet", datoms)[0]}
    schema = {":file/hash": {":db/unique": ":db.unique/identity"}}
    root = store.put(DbRoot(Embedded(cbor.dumps(schema)), 3, TX1, 128, links["eavt"], links["aevt"], links["avet"],
                            None).encode())
    db = DbReader(root, CountingLoader(store))
    assert db.lookup(":file/hash", b"\x01") == 2


def test_a_branch_over_an_attribute_whose_values_datascript_orders_in_a_cycle_reads():
    # value-compare puts a big integer before a keyword by class, the keyword before a double by class, and
    # the numbers by value, so DataScript's sort may leave 2.0 before 1.0 two leaves apart; its leaves
    # still hold each neighbour in order, and the reader refuses only a neighbour out of order
    values = [2.0, Tagged.bigint(3), ":k", 1.0]
    datoms = [Datom(e, ":x/v", v, TX1) for e, v in enumerate(values, 1)]
    store = NodeStore()
    avet, _ = _index(store, "avet", datoms, bf=2)
    empty = {i: _put(store, DnNode.leaf(i, [])) for i in ("eavt", "aevt")}
    root = store.put(DbRoot(Embedded(cbor.dumps({":x/v": {":db/index": True}})), 4, TX1, 2, empty["eavt"],
                            empty["aevt"], avet, None).encode())
    assert list(DbReader(root, CountingLoader(store)).datoms("avet")) == datoms


# ------------------------------------------------------------------ refusals

def _hostile(eavt_leaves, tail=None):
    store = NodeStore()
    if len(eavt_leaves) == 1:
        eavt = _put(store, DnNode.leaf("eavt", eavt_leaves[0]))
    else:
        children = [_put(store, DnNode.leaf("eavt", leaf)) for leaf in eavt_leaves]
        eavt = _put(store, DnNode.branch(1, "eavt", [leaf[-1] for leaf in eavt_leaves], children))
    empty = {i: _put(store, DnNode.leaf(i, [])) for i in ("aevt", "avet")}
    root = store.put(DbRoot(Embedded(cbor.dumps({})), 9, TX1, 128, eavt, empty["aevt"], empty["avet"],
                            tail).encode())
    return DbReader(root, CountingLoader(store)), store


def test_a_leaf_out_of_comparator_order_is_refused_by_name():
    db, _ = _hostile([[Datom(2, ":a/b", 1, TX1), Datom(1, ":a/b", 1, TX1)]])
    with pytest.raises(NodeFormatError, match="eavt order"):
        list(db.datoms("eavt"))
    db, _ = _hostile([[Datom(1, ":a/b", 1, TX1), Datom(1, ":a/b", 1, TX1)]])
    with pytest.raises(NodeFormatError, match="eavt order"):
        list(db.datoms("eavt"))


def test_a_child_outside_its_branch_key_is_refused():
    a, b, c = (Datom(e, ":a/b", 1, TX1) for e in (1, 2, 3))
    store = NodeStore()
    first, second = _put(store, DnNode.leaf("eavt", [a, c])), _put(store, DnNode.leaf("eavt", [b]))
    eavt = _put(store, DnNode.branch(1, "eavt", [b, c], [first, second]))
    empty = {i: _put(store, DnNode.leaf(i, [])) for i in ("aevt", "avet")}
    root = store.put(DbRoot(Embedded(cbor.dumps({})), 3, TX1, 128, eavt, empty["aevt"], empty["avet"],
                            None).encode())
    with pytest.raises(NodeFormatError, match="outside"):
        list(DbReader(root, CountingLoader(store)).datoms("eavt"))
    above = _put(store, DnNode.branch(1, "eavt", [b], [first]))
    root = store.put(DbRoot(Embedded(cbor.dumps({})), 3, TX1, 128, above, empty["aevt"], empty["avet"],
                            None).encode())
    with pytest.raises(NodeFormatError, match="outside"):
        list(DbReader(root, CountingLoader(store)).datoms("eavt"))


def test_a_node_of_another_index_or_level_and_a_retraction_in_an_index_are_refused():
    store = NodeStore()
    d = Datom(1, ":a/b", 1, TX1)
    leaf = {i: _put(store, DnNode.leaf(i, [d])) for i in INDEX_KEY}
    deep = _put(store, DnNode.branch(2, "eavt", [d], [leaf["eavt"]]))
    retracted = _put(store, DnNode.leaf("eavt", [Datom(1, ":a/b", 1, -TX1)]))

    def reader(eavt, tail=None):
        root = store.put(DbRoot(Embedded(cbor.dumps({})), 1, TX1, 128, eavt, leaf["aevt"], leaf["avet"],
                                tail).encode())
        return DbReader(root, CountingLoader(store))

    with pytest.raises(NodeFormatError, match="index aevt"):
        list(reader(leaf["aevt"]).datoms("eavt"))
    with pytest.raises(NodeFormatError, match="level"):
        list(reader(deep).datoms("eavt"))
    with pytest.raises(NodeFormatError, match="retraction"):
        list(reader(retracted).datoms("eavt"))
    with pytest.raises(NodeFormatError, match="tail"):
        list(reader(leaf["eavt"], tail=leaf["eavt"]).datoms("eavt"))


# ------------------------------------------------------------------ a database DataScript wrote

DATASCRIPT_DB = json.loads((pathlib.Path(__file__).parent / "pdt2_datascript_db.json").read_text())


def _datascript_reader() -> DbReader:
    store = NodeStore()
    for part in DATASCRIPT_DB["nodes"]:
        store.put(bytes.fromhex(part))
    return DbReader(DATASCRIPT_DB["root"], CountingLoader(store))


@pytest.mark.parametrize("query", DATASCRIPT_DB["queries"], ids=lambda q: f"{q['index']}-{q['n']}-{q['probe'][-16:]}")
def test_a_database_datascript_wrote_answers_as_datascript_does(query):
    # PDT 2 phase 2 gate, P2-D-09: agentspaces-datascript's cross_language_test writes the database through the
    # adapter (every value form, the escaped strings, branches, and a tail) with DataScript's answers
    probe = DnNode.decode(None, bytes.fromhex(query["probe"])).datoms[0]
    by_index = {"eavt": (probe.e, probe.a, probe.v), "aevt": (probe.a, probe.e, probe.v), "avet": (probe.a, probe.v, probe.e)}
    components = by_index[query["index"]][:query["n"]]
    want = [(d.e, d.a, d.v) for d in DnNode.decode(None, bytes.fromhex(query["answer"])).datoms]
    assert [(d.e, d.a, d.v) for d in _datascript_reader().datoms(query["index"], *components)] == want


def test_the_lookups_of_a_database_datascript_wrote_resolve_as_datascript_does():
    db = _datascript_reader()
    assert [db.lookup(q["a"], q["v"]) for q in DATASCRIPT_DB["lookups"]] == [q["e"] for q in DATASCRIPT_DB["lookups"]]
