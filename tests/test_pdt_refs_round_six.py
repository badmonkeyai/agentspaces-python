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

"""The PDT rulings of HLC round six, 2026-11-08, for the Python refs.

F1, F3. A PRef is a protocol record: its fields arrive in Java's declared order with the kinds
    Java's record names, and its bytes re-encode to themselves; otherwise it is undecodable.
R1. PRef attrs map text to text. Under pdt.issued and pdt.issuer any canonical item may stand,
    and a null or non-text one falls back to the entry's own stamp and issuer together (E10).
    A null or non-text value under any other key makes the PRef undecodable. The 4 KiB bound
    counts the UTF-8 bytes of keys and of text values.
R2. A pdt.issued whose physical time lies past the reader's wall + MAX_DRIFT + 5 s falls back.
R3. headsIgnored counts what Java's Refs counts: a bound violation, a wrong kind, a wrong ref
    name, and an undecodable PRef, once per entry.
R4. The common-base walk is Java's Refs.walk, over the known versions Java's toHead keeps."""

import types

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.pdt import NodeStore, PMap
from agentspaces.pdt import refs
from agentspaces.space import Space
from test_hlc_logical_limit import T
from test_hlc_round_four import _counts, _receiver
from test_pdt_refs_round_five import OWN, OWN_ISSUER, ORIGINAL, _Graph, _state_with_payload

# The PRef vectors of /tmp/r6/vectors.json (HLC round six, 2026-11-08): id, verdict, bytes.
PREF_VECTORS = [
    ("pref-01", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e697373756564783d313830303030303030303030303a303a7a364d314e3950797948476b4a664c5a526d5134566a4179705a5569357575556d3855444d484b31596669654a6a7064742e69737375657278327a364d314e3950797948476b4a664c5a526d5134566a4179705a5569357575556d3855444d484b31596669654a2f6a617661ffff"),
    ("pref-02", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e69737375656405ffff"),
    ("pref-03", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e697373756564f66a7064742e697373756572f6ffff"),
    ("pref-04", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e697373756572420102ffff"),
    ("pref-05", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e6973737565648201bf616102ffffff"),
    ("pref-06", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf647573657205ffff"),
    ("pref-07", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6475736572f6ffff"),
    ("pref-08", "accept", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf647573657261616a7064742e697373756564783d313830303030303030303030303a303a7a364d314e3950797948476b4a664c5a526d5134566a4179705a5569357575556d3855444d484b31596669654affff"),
    ("pref-09", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e697373756564783d313830303030303030303030303a303a7a364d314e3950797948476b4a664c5a526d5134566a4179705a5569357575556d3855444d484b31596669654a64757365726161ffff"),
    ("pref-10", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273bf6a7064742e6973737565641805ffff"),
    ("pref-11", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571fb3ff00000000000006473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65ff"),
    ("pref-12", "refuse-undecodable", "bf617601646e616d65656661637473646b696e64636d617064726f6f74783b62616679726569646b6a696b357332636c6d68616d65626734706b356a7770676564646f3778336273636d6262373633666c6173676c337734706964626173658063736571016473697a6500646d6f6465656d756c7469677365616c696e67646e6f6e65656174747273f6ff"),
]

# The line R2 draws: the reader's wall + MAX_DRIFT + the 5 s far-future margin.
LINE = T + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_SKEW_MARGIN_MILLIS


# F1, F3, R1: what decodes as a PRef ----------------------------------------------------------

@pytest.mark.parametrize("vector_id, verdict, hex_bytes", PREF_VECTORS, ids=[v[0] for v in PREF_VECTORS])
def test_a_pref_decodes_exactly_when_the_wire_encoding_accepts_it(vector_id, verdict, hex_bytes):
    decoded = refs.decode_pref(bytes.fromhex(hex_bytes))
    assert (decoded is not None) == (verdict == "accept"), vector_id


def _root(label: str = "k") -> str:
    return PMap.empty(NodeStore()).assoc(label, 1).root()


def _minimal(**fields) -> dict:
    return dict(refs.pref_record("facts", refs.KIND_MAP, _root()), **fields)


def _with_attrs(attrs: dict) -> bytes:
    """A PRef whose attrs hold ``attrs`` as given, in the canonical key order."""
    return cbor.dumps(_minimal(attrs=cbor.canonical_map(attrs)))


def test_the_records_every_writer_writes_decode():
    root = _root()
    full = refs.pref_record("facts", refs.KIND_MAP, root, [_root("b")], 2, 1, [b"\x01"], refs.MODE_LINEAR,
                            refs.SEALING_GROUP_KEY, 3, {"user": "x", refs.ISSUED_ATTR: ORIGINAL})
    for record in (full, refs.pref_record("facts", refs.KIND_MAP, root)):
        assert refs.decode_pref(cbor.dumps(record)) == record


@pytest.mark.parametrize("change", [
    {"v": 1.0}, {"v": "1"}, {"seq": "1"}, {"seq": True}, {"size": None}, {"size": 1 << 63},
    {"name": b"facts"}, {"name": 7}, {"kind": None}, {"base": None}, {"base": [7]}, {"base": "b"},
    {"nodes": None}, {"nodes": ["text"]}, {"keyEpoch": None}, {"keyEpoch": 1.5}, {"mode": b"multi"},
    {"sealing": 0}, {"attrs": None}, {"attrs": ["user", "x"]},
], ids=lambda change: ",".join(f"{k}={v!r}" for k, v in change.items()))
def test_a_field_of_the_wrong_kind_makes_the_pref_undecodable(change):
    assert refs.decode_pref(cbor.dumps(_minimal(**change))) is None


@pytest.mark.parametrize("nodes", [None, ["text"], [b"\x01", 7], b"\x01"], ids=repr)
def test_inline_nodes_that_are_not_an_array_of_byte_strings_make_the_pref_undecodable(nodes):
    # nodes sits between size and mode, so the change keeps every field in its declared place
    record = refs.pref_record("facts", refs.KIND_MAP, _root(), node_list=[b"\x01"])
    assert refs.decode_pref(cbor.dumps(record)) == record
    assert refs.decode_pref(cbor.dumps(dict(record, nodes=nodes))) is None


def test_fields_out_of_the_declared_order_an_unknown_field_or_a_missing_field_make_the_pref_undecodable():
    record = _minimal()
    reordered = {"name": record["name"], **{k: v for k, v in record.items() if k != "name"}}
    missing = {k: v for k, v in record.items() if k != "base"}
    assert refs.decode_pref(cbor.dumps(reordered)) is None
    assert refs.decode_pref(cbor.dumps(dict(record, extra="x"))) is None
    assert refs.decode_pref(cbor.dumps(missing)) is None


def test_bytes_that_do_not_re_encode_to_themselves_make_the_pref_undecodable():
    honest = cbor.dumps(_minimal())
    definite_map = b"\xac" + honest[1:-1]                  # the same fields under a definite head
    wide_seq = honest.replace(b"\x63seq\x01", b"\x63seq\x18\x01")
    wide_name = honest.replace(b"\x64name\x65facts", b"\x64name\x78\x05facts")
    assert refs.decode_pref(honest) is not None
    for relabel in (definite_map, wide_seq, wide_name, honest + b"\x00", b"\xa1\x01\x02"):
        assert refs.decode_pref(relabel) is None


@pytest.mark.parametrize("value", [None, 5, b"zOther/w", ["x"], {"a": 1}])
def test_a_null_or_non_text_value_under_another_key_makes_the_pref_undecodable(value):
    assert refs.decode_pref(_with_attrs({"user": value})) is None


@pytest.mark.parametrize("value", [None, 5, b"zOther/w", ["x"], {"a": 1}, True])
def test_any_canonical_item_under_a_reserved_key_decodes_and_falls_back(value):
    for key in (refs.ISSUED_ATTR, refs.ISSUER_ATTR):
        decoded = refs.decode_pref(_with_attrs({refs.ISSUED_ATTR: ORIGINAL, key: value}))
        assert decoded is not None
        assert refs.head_order(f"{T}:0:n", OWN_ISSUER, decoded["attrs"], T) == OWN


def test_attrs_keys_out_of_the_canonical_order_make_the_pref_undecodable():
    out_of_order = {refs.ISSUED_ATTR: ORIGINAL, "user": "x"}
    assert refs.decode_pref(cbor.dumps(_minimal(attrs=out_of_order))) is None
    assert refs.decode_pref(cbor.dumps(_minimal(attrs=cbor.canonical_map(out_of_order)))) is not None


def test_the_attrs_bound_counts_keys_and_text_values_and_nothing_for_a_non_text_reserved_value():
    key = "k"
    room = refs.MAX_ATTRS_BYTES - len(refs.ISSUED_ATTR) - len(key)
    at_the_bound = {refs.ISSUED_ATTR: None, key: "x" * room}
    assert refs.pref_violation(_minimal(attrs=at_the_bound)) is None
    assert refs.pref_violation(_minimal(attrs=dict(at_the_bound, k="x" * (room + 1)))) \
        == f"attrs larger than {refs.MAX_ATTRS_BYTES} bytes"
    assert refs.pref_violation(_minimal(attrs={refs.ISSUED_ATTR: "y" * 3, key: "x" * room})) \
        == f"attrs larger than {refs.MAX_ATTRS_BYTES} bytes"


def test_a_writer_refuses_a_non_text_value_under_a_key_every_reader_refuses():
    with pytest.raises(ValueError):
        refs.pref_record("facts", refs.KIND_MAP, _root(), attrs={"user": 5})
    with pytest.raises(ValueError):
        refs.pref_record("facts", refs.KIND_MAP, _root(), attrs={7: "x"})
    record = refs.pref_record("facts", refs.KIND_MAP, _root(), attrs={"user": "x", refs.ISSUER_ATTR: None})
    assert record["attrs"] == {"user": "x", refs.ISSUER_ATTR: None}


# R2: a pdt.issued past the reader's far-future line falls back -------------------------------

def test_a_pdt_issued_up_to_the_far_future_line_orders_the_head():
    attrs = {refs.ISSUED_ATTR: f"{LINE}:0:n", refs.ISSUER_ATTR: "zOther/w"}
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, attrs, T) == ((LINE, 0, "n"), "zOther/w")


def test_a_pdt_issued_past_the_far_future_line_falls_back_to_the_entrys_own_pair():
    attrs = {refs.ISSUED_ATTR: f"{LINE + 1}:0:n", refs.ISSUER_ATTR: "zOther/w"}
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, attrs, T) == OWN
    # the reader's wall decides: the same stamp orders the head once the wall catches up
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, attrs, T + 1) == ((LINE + 1, 0, "n"), "zOther/w")


# R3: headsIgnored counts what Java counts, once per entry ------------------------------------

def _reader(payloads: list[bytes]):
    """A receiver holding one ref-space entry per payload, each tagged with the name facts."""
    host = Identity.generate()
    receiver, link, clock = _receiver(host)
    for payload in payloads:
        link.rumor(_state_with_payload(host, payload, _root()))
    pdt = types.SimpleNamespace(peer=receiver, space=Space(receiver, "pdt"), store=NodeStore(),
                                follow=refs.FOLLOW_FULL)
    return refs.Ref(pdt, "facts", refs.KIND_MAP, refs.MODE_MULTI), receiver, clock


@pytest.mark.parametrize("payload", [
    pytest.param(_with_attrs({"user": None}), id="undecodable: null attr"),
    pytest.param(cbor.dumps(_minimal(seq=1.0)), id="undecodable: seq a double"),
    pytest.param(b"\xff", id="undecodable: no item"),
    pytest.param(cbor.dumps(_minimal(name="other")), id="another ref's name"),
    pytest.param(cbor.dumps(_minimal(kind=refs.KIND_SET)), id="another kind"),
    pytest.param(cbor.dumps(_minimal(root="not-a-cid")), id="bound violation"),
])
def test_a_head_java_ignores_counts_once_in_heads_ignored(payload):
    ref, receiver, _ = _reader([payload])
    assert ref._live_entries() == [] and ref._live_entries() == []
    assert ref.heads_ignored == 1 and ref.known == {}
    assert _counts(receiver) == {}


def test_the_remembered_ignored_entries_stay_bounded_by_the_live_entries():
    ref, _, clock = _reader([_with_attrs({"user": None}), cbor.dumps(_minimal(kind=refs.KIND_SET))])
    ref._live_entries()
    assert ref.heads_ignored == 2 and len(ref.ignored) == 2
    clock.millis += 61_000  # past every entry's lease
    assert ref._live_entries() == []
    assert ref.ignored == set() and ref.heads_ignored == 2


def test_a_head_with_a_null_reserved_attr_is_kept_and_counts_nothing():
    ref, receiver, _ = _reader([_with_attrs({refs.ISSUED_ATTR: [1, {"a": 1}], refs.ISSUER_ATTR: None})])
    [head] = ref._live_entries()
    assert head.issuer != "zOther/w" and ref.heads_ignored == 0 and _counts(receiver) == {}


def test_a_head_whose_pdt_issued_runs_past_the_readers_line_orders_by_the_entrys_own_pair():
    ref, _, clock = _reader([_with_attrs({refs.ISSUED_ATTR: f"{LINE + 1}:0:n", refs.ISSUER_ATTR: "zOther/w"})])
    [head] = ref._live_entries()
    assert head.issuer != "zOther/w"
    clock.millis += 1
    [head] = ref._live_entries()
    assert (head.issued, head.issuer) == ((LINE + 1, 0, "n"), "zOther/w")


# R4: the base walk Java's Refs walks ---------------------------------------------------------

def test_a_later_record_of_a_known_root_puts_its_own_bases_first_as_java_to_head_does():
    # Refs.toHead (HLC round six, 2026-11-08, R4): a record with a larger seq for a known root
    # keeps the union of the bases with the newer record's bases first, so the breadth-first walk
    # from that root meets them first and every reader picks the same common base.
    g = _Graph()
    a, b = g.version(), g.version()
    x = g.version(a.root)
    newer = refs.Head(x.root, (b.root,), x.seq + 5, 1, refs.KIND_MAP, refs.MODE_MULTI, OWN_ISSUER,
                      (T + 99, 0, "n"), "e-newer", T + 60_000)
    g.ref._know(newer)
    assert g.ref.known[x.root].base == (b.root, a.root)
    other = g.version(a.root, b.root)
    assert g.ref._common_base([other, g.ref.known[x.root]]) == b.root


def test_an_earlier_record_of_a_known_root_appends_its_bases():
    g = _Graph()
    a, b = g.version(), g.version()
    x = g.version(a.root)
    older = refs.Head(x.root, (b.root,), x.seq - 1, 1, refs.KIND_MAP, refs.MODE_MULTI, OWN_ISSUER,
                      (T, 0, "n"), "e-older", T + 90_000)
    g.ref._know(older)
    assert g.ref.known[x.root].base == (a.root, b.root) and g.ref.known[x.root].seq == x.seq
    # Java's toHead keeps the known version and takes the entry it was last seen as
    known = g.ref.known[x.root]
    assert (known.entry_id, known.expires_at_millis, known.issued) == ("e-older", T + 90_000, x.issued)


def test_a_revert_cycle_walks_to_its_end_within_the_bound_as_java_walks_it():
    g = _Graph()
    r0, r1 = g.version(), g.version()
    g.ref.known[r0.root] = refs.Head(r0.root, (r1.root,), *_rest(r0))
    g.ref.known[r1.root] = refs.Head(r1.root, (r0.root,), *_rest(r1))
    history = g.chain(g.version(), 2)
    assert g.ref._common_base([history, g.ref.known[r1.root]]) == refs.EMPTY_BASE


def test_a_version_reached_at_step_sixty_four_with_a_base_cuts_the_walk_even_when_a_shorter_path_reached_its_base():
    g = _Graph()
    w = g.version()
    deep = g.chain(g.version(w.root), 63)
    head = g.version(deep.root, w.root)
    assert g.ref._common_base([g.version(), head]) is None


def _rest(head: refs.Head) -> tuple:
    return head.seq, head.size, head.kind, head.mode, head.issuer, head.issued, head.entry_id, head.expires_at_millis


# R3 at the take: a linear swap takes only a head that decodes -------------------------------

def test_a_linear_swap_never_takes_an_undecodable_head_and_advances_the_real_one():
    # Java's take decodes each candidate and passes over one that does not decode
    # (ReplicatedSpace.decodeIfMatches), so a hostile entry tagged with the ref's name never
    # becomes the taken head; the swap takes the real head and advances it (HLC round six,
    # 2026-11-08, R1, R3).
    from test_pdt_swarm import _fleet
    _network, [(peer, _content, pdt)] = _fleet(1, take_settle=0.05, take_timeout="3s", mode={"log": "linear"})
    log = pdt.vector_ref("log")
    hostile = dict(refs.pref_record("log", refs.KIND_VECTOR, _root()), attrs={"user": None})
    hostile_id = peer.write_entry("pdt", refs.PREF_TYPE, hostile, tags={refs.NAME_TAG: "log", refs.ROOT_TAG: _root()})
    log.swap(lambda v: v.conj("first"))
    log.swap(lambda v: v.conj("second"))
    assert log.deref().to_list() == ["first", "second"]
    assert not peer.states[hostile_id].get("completed") and log.heads_ignored == 1
