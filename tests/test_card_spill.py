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

"""SPEC §6.1a.5 (v0.1.32; AppCard origin and formats, 2026-11-09): the card spill. The two golden stubs and their
parts documents decode and complete here as in Java, and each document's content root over 65,536-byte pieces is
the stub's ``spill.root``. The stub's rules hold at decode, and ``card_parts``, ``card_stub``, and
``card_complete`` give back the vectors' bytes."""

import json
import pathlib

import pytest

from agentspaces import cbor, records, wire
from agentspaces.capabilities import content as c

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())


def _hex(name: str) -> bytes:
    return bytes.fromhex(GOLDEN[name])


PAIRS = [("app_card_spill_cbor", "app_card_parts_cbor", "AppCard"),
         ("agent_card_spill_cbor", "agent_card_parts_cbor", "AgentCard")]


def test_the_constants_equal_the_golden_values():
    assert wire.CARD_SPILL_THRESHOLD_BYTES == GOLDEN["card_spill_threshold_bytes"] == 65536
    assert wire.CARD_SPILL_WARN_BYTES == GOLDEN["card_spill_warn_bytes"] == 57344
    assert wire.CARD_SPILL_PIECE_SIZE == 65536
    assert wire.CARD_SPILL_MAX_FETCH_BYTES == 16_777_216
    assert wire.CARD_SPILL_MAX_SIZE == 2 ** 53 - 1
    assert wire.CARD_SPILL_ROOT_LENGTH == 59
    assert wire.APP_CARD_SPILL_SET == ("reads", "actions", "views", "ui")
    assert wire.AGENT_CARD_SPILL_SET == ("actions", "ui")


@pytest.mark.parametrize("stub_name, parts_name, kind", PAIRS)
def test_each_golden_stub_names_its_parts_document_and_completes(stub_name, parts_name, kind):
    stub = records.decode(_hex(stub_name), kind)
    document = _hex(parts_name)
    parts = records.decode(document, kind + ".Parts")
    assert stub is not None and parts is not None
    spill = stub["spill"]
    assert list(stub)[-1] == "spill", "spill is appended last"
    assert spill["size"] == len(document)
    assert spill["root"] == c.content_root(c.hash_pieces(document, wire.CARD_SPILL_PIECE_SIZE))
    assert spill["parts"] == wire.non_empty_parts(parts)
    full = wire.card_complete(stub, parts)
    assert "spill" not in full and records.conforms(full, kind)
    assert cbor.dumps(wire.card_parts(full)) == document
    assert cbor.dumps(wire.card_stub(full, spill)) == _hex(stub_name)


def test_the_app_card_parts_hold_every_list_and_name_only_the_non_empty_ones():
    parts = cbor.loads(_hex("app_card_parts_cbor"))
    assert parts["actions"] == [] and wire.non_empty_parts(parts) == ["reads", "views", "ui"]
    stub = cbor.loads(_hex("app_card_spill_cbor"))
    assert (stub["reads"], stub["actions"], stub["views"]) == ([], [], []) and "ui" not in stub


def test_a_stub_or_a_completion_refuses_parts_that_do_not_match():
    stub = cbor.loads(_hex("app_card_spill_cbor"))
    full = wire.card_complete(stub, cbor.loads(_hex("app_card_parts_cbor")))
    with pytest.raises(ValueError):
        wire.card_stub(full, {**stub["spill"], "parts": ["reads", "ui"]})
    with pytest.raises(ValueError):
        wire.card_complete(stub, {"reads": [], "actions": [], "views": ["one"]})
    with pytest.raises(ValueError):
        wire.card_complete(full, cbor.loads(_hex("app_card_parts_cbor")))
    with pytest.raises(ValueError):
        wire.card_parts(stub)


def _with_spill(name: str, **fields) -> dict:
    card = cbor.loads(_hex(name))
    return {**card, "spill": {**card["spill"], **fields}}


def test_every_stub_rule_holds_at_decode_on_both_kinds():
    good_root = cbor.loads(_hex("app_card_spill_cbor"))["spill"]["root"]
    assert records.decode(cbor.dumps(_with_spill("app_card_spill_cbor", size=2 ** 53 - 1)), "AppCard") is not None
    for fields in ({"size": 2 ** 53}, {"size": 0}, {"size": -1}, {"parts": []}, {"parts": ["reads", "reads"]},
                   {"parts": ["host"]}, {"parts": ["views", "reads"]}, {"root": good_root[:-1]},
                   {"root": "B" + good_root[1:]}, {"root": good_root[:-1] + "1"}):
        assert records.decode(cbor.dumps(_with_spill("app_card_spill_cbor", **fields)), "AppCard") is None, fields
    # the last character carries two pad bits of the 36-byte CID, which must be zero
    padded = good_root[:-1] + c._B32[c._B32.index(good_root[-1]) | 1]
    assert records.decode(cbor.dumps(_with_spill("app_card_spill_cbor", root=padded)), "AppCard") is None
    stub = cbor.loads(_hex("app_card_spill_cbor"))
    for field in ("reads", "actions", "views"):
        assert records.decode(cbor.dumps({**stub, field: ["x"]}), "AppCard") is None, field
    agent = cbor.loads(_hex("agent_card_spill_cbor"))
    assert records.decode(cbor.dumps(_with_spill("agent_card_spill_cbor", parts=["reads"])), "AgentCard") is None
    assert records.decode(cbor.dumps(_with_spill("agent_card_spill_cbor", parts=["ui", "actions"])), "AgentCard") is None
    with_ui = {k: v for k, v in agent.items() if k != "spill"}
    with_ui["ui"] = cbor.loads(_hex("agent_card_parts_cbor"))["ui"]
    with_ui["spill"] = agent["spill"]
    assert records.decode(cbor.dumps(with_ui), "AgentCard") is None, "a stub's ui is absent"


def test_the_card_spill_builder_refuses_what_the_record_refuses():
    root = cbor.loads(_hex("app_card_spill_cbor"))["spill"]["root"]
    assert wire.card_spill(root, 452, ["reads", "views", "ui"]) == cbor.loads(_hex("app_card_spill_cbor"))["spill"]
    for args in ((root, 0, ["reads"]), (root, 1, []), ("bafy", 1, ["reads"]), (root, 1, ["reads", "reads"])):
        with pytest.raises(ValueError):
            wire.card_spill(*args)
