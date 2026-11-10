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

"""The PDT decisions of HLC round five, 2026-11-08, for the Python refs.

E3. An agent id in pdt.issuer is a non-empty peer, one "/", and a non-empty local name that
    holds no "/", as Java's AgentId.parse reads one.
E10. A pdt.issued that is absent, null, not text, or not acceptable, or a pdt.issuer that is
    present and null, not text, or no agent id, makes the head fall back to the entry's own
    stamp and issuer together. The reader refuses nothing, counts nothing, and keeps the head.
E16. When the base walks of the heads share no version and every walk ends at a first
    version within the 64-step bound, the empty value is the shared base, so the three-way
    merge keeps every key of both writers."""

import types

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.pdt import NodeStore, PMap
from agentspaces.pdt import refs
from agentspaces.space import Space
from test_hlc_logical_limit import GROUP, LIMIT, T
from test_hlc_round_four import _counts, _receiver
from test_pdt_swarm import _fleet, release

OWN_ISSUER = "zPeer/w"
OWN = ((T, 0, "n"), OWN_ISSUER)
ORIGINAL = f"{T - 5}:0:n"


# E3: the agent id grammar ----------------------------------------------------------------

@pytest.mark.parametrize("issuer", ["zOther/w/x", "zOther//w", "zOther/w/", "/w", "zOther/", "", "no-slash"])
def test_a_pdt_issuer_that_java_agent_id_parse_refuses_falls_back_to_the_entrys_own_pair(issuer):
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, {refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: issuer}, T) == OWN


def test_a_pdt_issuer_with_one_slash_between_a_peer_and_a_local_name_orders_the_head():
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, {refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: "zOther/w"}, T) \
        == ((T - 5, 0, "n"), "zOther/w")


# E10: the advisory pair falls back together ------------------------------------------------

@pytest.mark.parametrize("attrs", [
    {refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: None},
    {refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: 7},
    {refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: b"zOther/w"},
    {refs.ISSUED_ATTR: None, refs.ISSUER_ATTR: "zOther/w"},
    {refs.ISSUED_ATTR: T - 5, refs.ISSUER_ATTR: "zOther/w"},
    {refs.ISSUED_ATTR: f"{T - 5}:{LIMIT + 1}:n", refs.ISSUER_ATTR: "zOther/w"},
    {refs.ISSUER_ATTR: "zOther/w"},
    {},
])
def test_a_refused_advisory_attr_falls_back_to_the_entrys_own_stamp_and_issuer_together(attrs):
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, attrs, T) == OWN


def test_an_acceptable_pdt_issued_without_a_pdt_issuer_keeps_the_entrys_issuer():
    assert refs.head_order(f"{T}:0:n", OWN_ISSUER, {refs.ISSUED_ATTR: ORIGINAL}, T) == ((T - 5, 0, "n"), OWN_ISSUER)


def _indefinite(text: str) -> bytes:
    return b"\x7f" + cbor.dumps(text[:3]) + cbor.dumps(text[3:]) + b"\xff"


def _under_a_longer_header(text: str) -> bytes:
    data = text.encode("utf-8")
    return bytes([0x79]) + len(data).to_bytes(2, "big") + data


@pytest.mark.parametrize("form", [_indefinite, _under_a_longer_header])
def test_a_head_whose_advisory_attrs_arrive_in_a_text_form_the_wire_encoding_refuses_is_undecodable(form):
    # Round five read such attrs as their text, as Jackson did. HLC round six, 2026-11-08 (F3):
    # a PRef decodes only when its bytes are the wire encoding of what they decode to, so short
    # text arrives definite under its shortest header or the head is undecodable.
    root = PMap.empty(NodeStore()).assoc("k", 1).root()
    honest = cbor.dumps(refs.pref_record("facts", refs.KIND_MAP, root,
                                         attrs={refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: "zOther/w"}))
    relabelled = honest.replace(cbor.dumps(ORIGINAL), form(ORIGINAL)).replace(cbor.dumps("zOther/w"),
                                                                              form("zOther/w"))
    assert refs.decode_pref(honest) is not None and relabelled != honest
    assert refs.decode_pref(relabelled) is None


def _state_with_payload(host: Identity, payload: bytes, root: str) -> dict:
    _, body = wire.entry_delta("pdt", GROUP, refs.PREF_TYPE, payload, host, "w", 60_000, now_ms=T,
                               tags={refs.NAME_TAG: "facts", refs.ROOT_TAG: root})
    return cbor.loads(cbor.loads(body)["payload"])["state"]


def test_a_head_whose_attrs_hold_a_null_issuer_decodes_and_orders_by_the_entrys_own_pair():
    host = Identity.generate()
    root = PMap.empty(NodeStore()).assoc("k", 1).root()
    record = refs.pref_record("facts", refs.KIND_MAP, root)
    record["attrs"] = cbor.canonical_map({refs.ISSUED_ATTR: ORIGINAL, refs.ISSUER_ATTR: None})
    state = _state_with_payload(host, cbor.dumps(record), root)
    receiver, link, _ = _receiver(host)
    link.rumor(state)
    assert set(receiver.states) == {state["record"]["entryId"]}
    pdt = types.SimpleNamespace(peer=receiver, space=Space(receiver, "pdt"), store=NodeStore(),
                                follow=refs.FOLLOW_FULL)
    ref = refs.Ref(pdt, "facts", refs.KIND_MAP, refs.MODE_MULTI)
    [head] = ref._live_entries()
    assert (head.issued, head.issuer) == (wire.parse_hlc(state["record"]["issued"]), state["record"]["issuer"])
    assert ref.heads_ignored == 0 and _counts(receiver) == {}


# E16: the empty value is the base of histories that share no version -------------------------

def test_two_writers_whose_histories_start_from_empty_and_share_no_version_keep_every_key():
    network, nodes = _fleet(2)
    (_pa, _ca, a), (_pb, _cb, b) = nodes
    ra, rb = a.map_ref("facts"), b.map_ref("facts")
    conflicts = []
    rb.on_conflict(conflicts.append)
    network.holding = True
    for i in range(3):
        ra.swap(lambda m, i=i: m.assoc(f"a-{i}", i))
        rb.swap(lambda m, i=i: m.assoc(f"b-{i}", i))
    release(network)
    heads = rb.heads()
    assert len(heads) == 2 and all(h.seq == 3 for h in heads)
    expected = {f"a-{i}": i for i in range(3)} | {f"b-{i}": i for i in range(3)}
    assert ra.deref().to_dict() == expected and rb.deref().to_dict() == expected
    assert conflicts == []


class _Graph:
    """A ref over a local store whose known versions the test lays out by hand."""

    def __init__(self):
        self.store = NodeStore()
        self.ref = refs.Ref(types.SimpleNamespace(store=self.store, follow=refs.FOLLOW_FULL),
                            "facts", refs.KIND_MAP, refs.MODE_MULTI)
        self.count = 0

    def version(self, *base: str) -> refs.Head:
        self.count += 1
        root = PMap.empty(self.store).assoc("v", self.count).root()
        head = refs.Head(root, tuple(base), self.count, 1, refs.KIND_MAP, refs.MODE_MULTI, OWN_ISSUER,
                         (T + self.count, 0, "n"), f"e{self.count}", T + 60_000)
        self.ref.known[root] = head
        return head

    def chain(self, first: refs.Head, steps: int) -> refs.Head:
        head = first
        for _ in range(steps):
            head = self.version(head.root)
        return head


def test_walks_that_reach_first_versions_within_the_bound_share_the_empty_base():
    g = _Graph()
    one, two = g.chain(g.version(), 2), g.chain(g.version(), 64)
    assert g.ref._common_base([one, two]) == refs.EMPTY_BASE


def test_a_walk_the_bound_cuts_before_its_first_version_shares_no_base():
    g = _Graph()
    one, two = g.version(), g.chain(g.version(), 65)
    assert g.ref._common_base([one, two]) is None


def test_a_walk_through_a_version_the_reader_never_saw_shares_no_base():
    g = _Graph()
    unseen = PMap.empty(g.store).assoc("unseen", 1).root()
    one, two = g.version(), g.chain(g.version(unseen), 1)
    assert g.ref._common_base([one, two]) is None


def test_a_common_version_sixty_four_steps_below_the_latest_head_is_the_base_as_java_walks():
    g = _Graph()
    shared = g.version(g.version().root)
    other = g.version(shared.root)
    latest = g.chain(shared, 64)
    assert g.ref._common_base([other, latest]) == shared.root
