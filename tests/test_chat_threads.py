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

"""SPEC §6.1 (v0.1.38): ``AgentCard.threads``, the conversations an agent answers. The golden
card with threads decodes and re-encodes byte for byte; each refusal vector is undecodable; the
builder writes the Java field order and refuses what a reader refuses; an empty list is the
absent field, so a card without threads keeps its earlier bytes."""

import json
import pathlib

import pytest

from agentspaces import cbor, records, wire
from agentspaces.identity import Identity

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())

REFUSALS = (
    "adv_agent_card_threads_scope_cbor",
    "adv_agent_card_threads_all_key_cbor",
    "adv_agent_card_threads_key_cbor",
    "adv_agent_card_threads_count_cbor",
    "adv_agent_card_threads_twice_cbor",
    "adv_agent_card_threads_empty_cbor",
)


def _hex(name):
    return bytes.fromhex(GOLDEN[name])


def test_the_golden_card_with_threads_round_trips_byte_for_byte():
    raw = _hex("agent_card_threads_cbor")
    card = records.decode(raw, "AgentCard")
    assert card is not None
    assert list(card.keys())[-1] == "threads", "threads is the last key, appended after spill"
    assert card["threads"] == [
        {"space": "conversations", "key": "main", "scope": "tree"},
        {"space": "conversations", "key": "agent-research", "scope": "exact"},
        {"space": "findings", "key": "", "scope": "all"},
    ]
    assert cbor.dumps(card) == raw
    rebuilt = wire.chat_threads([wire.chat_thread(t["space"], t["key"], t["scope"]) for t in card["threads"]])
    assert cbor.dumps(rebuilt) == cbor.dumps(card["threads"]), "the Python builder encodes the Java threads byte for byte"
    without = {k: v for k, v in card.items() if k != "threads"}
    assert cbor.dumps(without) == _hex("agent_card_ui_cbor"), "the card without threads is the ui card"


@pytest.mark.parametrize("name", REFUSALS)
def test_every_threads_refusal_vector_is_undecodable(name):
    raw = _hex(name)
    assert isinstance(cbor.loads(raw), dict), "the vector is a well-formed map; only the record rule refuses it"
    assert records.decode(raw, "AgentCard") is None


def test_an_empty_list_keeps_the_card_bytes():
    identity = Identity.generate()
    args = ("g", identity, "desk", "2026-11-23T00:00:00Z", "PT10M", "", [], [], [], {}, {})
    plain = wire.agent_card(*args)
    assert "threads" not in wire.agent_card(*args, threads=[])
    assert cbor.dumps(wire.agent_card(*args, threads=[])) == cbor.dumps(plain)
    assert wire.chat_threads([]) is None
    written = dict(plain, threads=[])
    assert records.decode(cbor.dumps(written), "AgentCard") is None, "an empty list on the wire is refused"
    card = wire.agent_card(*args, threads=[wire.chat_thread("conversations", "main", "tree")])
    assert list(card.keys())[-1] == "threads"
    assert records.decode(cbor.dumps(card), "AgentCard") == card


def test_the_builder_refuses_what_a_reader_refuses():
    assert list(wire.chat_thread("findings", "", "all").keys()) == ["space", "key", "scope"]
    for space, key, scope in (("conversations", "main", "branch"), ("findings", "x", "all"),
                              ("conversations", "", "exact"), ("conversations", "a b", "tree"),
                              ("", "main", "exact"), ("con versations", "main", "exact"),
                              ("s" * 129, "main", "exact"), ("conversations", "k" * 129, "exact")):
        with pytest.raises(ValueError):
            wire.chat_thread(space, key, scope)
    assert wire.chat_thread("s" * 128, "k" * 128, "exact")["space"] == "s" * 128
    one = wire.chat_thread("conversations", "main")
    with pytest.raises(ValueError):
        wire.chat_threads([one, dict(one)])
    with pytest.raises(ValueError):
        wire.chat_threads([wire.chat_thread("conversations", f"t{i}") for i in range(17)])
    assert len(wire.chat_threads([wire.chat_thread("conversations", f"t{i}") for i in range(16)])) == 16
