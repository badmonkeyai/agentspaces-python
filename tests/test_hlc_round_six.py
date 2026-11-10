#
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

"""Three rows of the HLC round six conformance probe, 2026-11-08, as they bind this client.

ASF-025. A received state whose dots name a replica other than its issuer's peer merges
    nothing and counts nothing, as Java's ``ReplicatedSpace.dotsBoundToIssuer`` drops it.
JD-4. A persistent-tree node decodes only when each embedded item is a document in the wire
    encoding (rules S1 to S12, tags 2, 3 and 4 included); a bare link item may stand in a
    value slot and in no key slot, as Java's ``NodeCodec.checkEmbedded`` rules.
R10. A lapsed claim on an entry this replica does not hold leaves the claim map, so claims
    for entries that never arrive cannot grow it without bound."""

import json
import pathlib
import uuid

import pytest

from agentspaces import cbor, wire
from agentspaces.identity import Identity
from agentspaces.pdt import cids, nodes
from test_hlc_logical_limit import T, _write
from test_hlc_round_four import _counts, _receiver

HERE = pathlib.Path(__file__).parent
VECTORS = {vector["id"]: vector for vector in
           json.loads((HERE / "wire_encoding_vectors.json").read_text())["vectors"]}
GOLDEN = json.loads((HERE / "golden.json").read_text())


# ASF-025: a state's dots name its issuer's peer --------------------------------------------

def test_a_state_whose_dots_name_other_replicas_merges_nothing_and_counts_nothing():
    # Vector delta-13: Java signed it and both signatures verify, but its dots name U+E000 and
    # U+1F600 where the writer's peer id belongs, so Java's fold drops it before any merge.
    raw = bytes.fromhex(VECTORS["delta-13"]["hex"])
    state = wire.decode_delta(raw)["state"]
    receiver, link, _ = _receiver(Identity.generate())
    assert receiver._verify_state(state, state["record"])
    link.rumor_raw(raw)
    assert receiver.states == {} and _counts(receiver) == {}


def test_a_state_with_one_foreign_dot_beside_the_issuers_merges_nothing():
    host = Identity.generate()
    write = _write(host, T)
    foreign = wire.sign_state(dict(write, adds=write["adds"] + [{"replica": Identity.generate().peer_id,
                                                                 "counter": 1}]), host)
    receiver, link, _ = _receiver(host)
    link.rumor(foreign)
    assert receiver.states == {} and _counts(receiver) == {}
    link.rumor(write)
    assert list(receiver.states) == [write["record"]["entryId"]]


def test_a_recordless_state_whose_removes_name_another_replica_merges_nothing():
    # The held record's issuer binds the dots of a recordless state, as Java checks the
    # state after it takes the record this replica holds.
    host = Identity.generate()
    write = _write(host, T)
    receiver, link, _ = _receiver(host)
    link.rumor(write)
    entry_id = write["record"]["entryId"]
    cancel = wire.sign_state(dict(write, removes=[{"replica": Identity.generate().peer_id, "counter": 1}]), host)
    recordless = dict({k: v for k, v in cancel.items() if k != "record"}, issuerPublicKey=None, entryId=entry_id)
    link.rumor(recordless)
    assert receiver.states[entry_id]["removes"] == [] and _counts(receiver) == {}
    honest = wire.sign_state(dict(write, removes=list(write["adds"])), host)
    link.rumor(dict({k: v for k, v in honest.items() if k != "record"}, issuerPublicKey=None, entryId=entry_id))
    assert receiver.states[entry_id]["removes"] == write["adds"]


# JD-4: every embedded item of a node is a document in the wire encoding --------------------

GOLDEN_NODE = bytes.fromhex(GOLDEN["pdt_node_embedded"])
FLOAT_ITEM = bytes.fromhex("fa3fc00000")  # Java's 1.5f, the golden node's one value

REFUSED_ITEMS = {
    "tag 2 inside a long (S9)": "c24101",
    "tag 4 unnormalized 1.50 (S9)": "c482211896",
    "tag 4 exponent -2^31 (S9)": "c4823a7fffffff01",
    "tag 0 over text": "c06161",
    "tag 1 over an int": "c11a5f000000",
    "tag 55799 over an int": "d9d9f701",
    "tag 42 over bytes 00 01 (no CID)": "d82a420001",
    "indefinite text of one chunk (S6)": "7f6161ff",
    "definite map (S8)": "a1616101",
    "half float (S10)": "f93e00",
    "a NaN Java does not write (S10)": "fbfff8000000000000",
    "an integer under a wider head (S3)": "1801",
    "undefined (S11)": "f7",
    "duplicate map key (S8)": "bf616101616102ff",
}

ACCEPTED_ITEMS = {
    "tag 2 bignum 2^64": "c249010000000000000000",
    "tag 3 bignum -2^63-1": "c349008000000000000001",
    "tag 4 decimal 1.5": "c482200f",
    "tag 4 with a bignum mantissa": "c48200c24e04ee2d6d415b85acef8100000001",
    "an application map in arrival order (b before a)": "bf616201616102ff",
}


def _holding(item_hex: str) -> bytes:
    assert GOLDEN_NODE.count(FLOAT_ITEM) == 1
    return GOLDEN_NODE.replace(FLOAT_ITEM, bytes.fromhex(item_hex))


@pytest.mark.parametrize("item", list(REFUSED_ITEMS.values()), ids=list(REFUSED_ITEMS))
def test_a_node_whose_embedded_item_breaks_the_wire_encoding_does_not_decode(item):
    with pytest.raises(nodes.NodeFormatError):
        nodes.decode(_holding(item))


@pytest.mark.parametrize("item", list(REFUSED_ITEMS.values()), ids=list(REFUSED_ITEMS))
def test_a_node_whose_embedded_item_breaks_the_wire_encoding_does_not_encode(item):
    node = nodes.decode(GOLDEN_NODE)
    node["e"] = [node["e"][0], nodes.Embedded(bytes.fromhex(item))] + node["e"][2:]
    with pytest.raises(nodes.NodeFormatError):
        nodes.encode(node)


@pytest.mark.parametrize("item", list(ACCEPTED_ITEMS.values()), ids=list(ACCEPTED_ITEMS))
def test_a_node_whose_embedded_item_is_in_the_wire_encoding_decodes_and_re_encodes(item):
    data = _holding(item)
    assert nodes.encode(nodes.decode(data)) == data


def test_a_link_item_stands_in_a_value_slot_and_in_no_key_slot():
    link = nodes.link_item(cids.of(b"spilled"))
    in_value = GOLDEN_NODE.replace(FLOAT_ITEM, link)
    assert nodes.decode(in_value)["e"][1].bytes == link
    key = bytes.fromhex("6166")  # the golden node's first key, "f"
    assert GOLDEN_NODE.count(key) == 1
    with pytest.raises(nodes.NodeFormatError):
        nodes.decode(GOLDEN_NODE.replace(key, link))


# R10: the claim map stays bounded under churn -------------------------------------------------

ROUND = 1000


def _claim(holder: Identity, entry_id: str, now_ms: int, expires_ms: int) -> dict:
    agent = holder.agent("t")
    return wire.signed_claim(wire.take_claim(entry_id, "zPyHlcSpace", 1, f"{now_ms}:0:{agent}", agent, 0.0,
                                             expires_ms), holder)


def test_lapsed_claims_on_entries_never_held_leave_the_claim_map_under_churn():
    # The probe's churn: eight rounds of claims on entries that never arrive, each round's
    # claims lapsed before the next begins. The map holds at most one round's claims.
    holder = Identity.generate()
    receiver, link, clock = _receiver(holder)
    sizes = []
    for round_number in range(8):
        clock.millis = T + round_number * 600_000
        for _ in range(ROUND):
            entry_id = str(uuid.uuid4())
            link.rumor(claim=(entry_id, _claim(holder, entry_id, clock.millis, clock.millis + 60_000)))
        sizes.append(len(receiver.claims))
    assert max(sizes) <= ROUND, sizes
    assert _counts(receiver) == {}


def test_a_live_claim_and_a_claim_on_a_held_entry_stay():
    holder = Identity.generate()
    receiver, link, clock = _receiver(holder)
    write = _write(holder, T)
    held = write["record"]["entryId"]
    link.rumor(write)
    link.rumor(claim=(held, _claim(holder, held, T, T + 60_000)))
    live = str(uuid.uuid4())
    link.rumor(claim=(live, _claim(holder, live, T, T + 2 * HOUR)))
    clock.millis = T + HOUR
    for _ in range(2 * ROUND):
        entry_id = str(uuid.uuid4())
        link.rumor(claim=(entry_id, _claim(holder, entry_id, clock.millis, clock.millis + 1)))
    clock.millis += 1
    for _ in range(2 * ROUND):
        entry_id = str(uuid.uuid4())
        link.rumor(claim=(entry_id, _claim(holder, entry_id, clock.millis, clock.millis + 60_000)))
    assert held in receiver.claims and live in receiver.claims
    assert len(receiver.claims) <= 2 * ROUND + 2


HOUR = 60 * 60 * 1000
