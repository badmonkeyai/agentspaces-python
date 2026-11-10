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

"""SPEC §6.1a.3 (v0.1.26; ISSUE-UiComponents FR-6): the ui declaration on an AgentCard. The
decorator form derives the same ``ui`` group the Java binder derives; the golden card with a
declaration round-trips byte for byte; a control that is not an action is refused; a card
without a declaration carries no ``ui`` key."""

import json
import pathlib

import pytest

from agentspaces import cbor, wire
from agentspaces.agents import _ui_declaration, ui_component, space_take

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())

SHARED_ITEM = "https://example.org/ns/demo/v1/SharedItem"
MESSAGE = "https://example.org/ns/demo/v1/Message"


class Task:
    def __init__(self, topic=""):
        self.topic = topic


@ui_component(catalog="example-widgets", component="ItemPanel", id="share", entry=SHARED_ITEM, controls=("research",))
class Desk:
    @space_take(space="tasks")
    @ui_component(catalog="example-widgets", component="MessageInput", id="ask", entry=MESSAGE, role="control", reads=False,
                  writes=True)
    def research(self, task: Task):
        return None


class Plain:
    @space_take(space="tasks")
    def research(self, task: Task):
        return None


def _methods(obj):
    import inspect
    return [(n, m) for n, m in inspect.getmembers(obj, callable) if getattr(m, "__agentspaces_binding__", None)]


def test_the_decorators_derive_the_declaration_in_java_field_order():
    actions = [wire.card_action("research", "", ["Task"], [], "take", "tasks")]
    ui = _ui_declaration(Desk(), _methods(Desk()), actions)
    assert list(ui.keys()) == ["protocol", "version", "components", "entries", "catalogIds"]
    assert ui["protocol"] == "a2ui" and ui["version"] == "v0.9.1"
    assert [c["id"] for c in ui["components"]] == ["share", "ask"]
    assert list(ui["components"][0].keys()) == ["id", "catalogId", "component", "entry", "controls", "role"]
    assert ui["components"][0]["controls"] == ["research"]
    assert ui["components"][1]["role"] == "control"
    assert ui["entries"] == {"reads": [SHARED_ITEM], "writes": [MESSAGE]}
    assert ui["catalogIds"] == ["example-widgets"]
    assert _ui_declaration(Plain(), _methods(Plain()), actions) is None


def test_a_control_that_is_not_an_action_is_refused():
    with pytest.raises(ValueError, match="control 'research'"):
        _ui_declaration(Desk(), _methods(Desk()), [])


def test_the_golden_card_with_a_declaration_round_trips_byte_for_byte():
    raw = bytes.fromhex(GOLDEN["agent_card_ui_cbor"])
    card = cbor.loads(raw)
    assert list(card.keys())[-1] == "ui", "ui is the last key, appended after agentCertificate"
    assert cbor.dumps(card) == raw
    ui = card["ui"]
    rebuilt = wire.ui_declaration(
        [wire.ui_component(c["id"], c["catalogId"], c["component"], c["entry"], c["controls"], c["role"]) for c in ui["components"]],
        ui["entries"]["reads"], ui["entries"]["writes"])
    assert cbor.dumps(rebuilt) == cbor.dumps(ui), "the Python builder encodes the Java declaration byte for byte"
    desk = Desk()
    assert cbor.dumps(_ui_declaration(desk, _methods(desk), card["actions"])) == cbor.dumps(ui), \
        "the decorators derive the golden declaration"
    without = dict(card)
    del without["ui"]
    assert "ui" not in cbor.loads(cbor.dumps(without))
