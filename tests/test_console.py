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

"""The console records as data (enterprise platform S3-H-06): the helper names
the console's types, decodes what the wire carries, and knows the space each
record lives in."""

from agentspaces.console import (SPACES, AgentConfiguration, Constraint, JuryDecision, Vocabulary,
                                 console_type, rules)
from agentspaces.identity import Identity
from agentspaces.peer import Peer
from agentspaces.space import Template, from_payload, schema_of


def test_the_console_types_are_named_by_the_console_namespace():
    assert schema_of(Constraint) == "https://badmonkey.ai/console#Constraint"
    assert console_type("JuryDecision") == schema_of(JuryDecision)
    assert Template(Vocabulary).schema == "https://badmonkey.ai/console#Vocabulary"


def test_a_wire_payload_decodes_into_the_declared_fields_and_ignores_the_rest():
    c = from_payload(Constraint, {"schemaVersion": 1, "book": "rb-claims", "template": "precedence", "a": "DamageReport",
                                  "b": "PaymentOrder", "enforcement": ["gate"], "jury": {"quorum": 2}, "unknown": "later"})
    assert (c.book, c.template, c.a, c.b, c.enforcement, c.jury) == ("rb-claims", "precedence", "DamageReport",
                                                                       "PaymentOrder", ["gate"], {"quorum": 2})
    a = from_payload(AgentConfiguration, {"agent": "rule-agent", "instance": "rules-1", "body": {"books": ["rb-claims"]}})
    assert a.body == {"books": ["rb-claims"]} and a.version == 0


def test_each_record_names_the_space_the_console_writes_it_into():
    assert SPACES == {"Vocabulary": "constraints", "Constraint": "constraints", "AgentConfiguration": "policy",
                      "JuryDecision": "decisions", "Finding": "findings"}


def test_rules_pulls_each_space_once_and_reads_through_a_space():
    peer = Peer(Identity.generate(), "g")
    peer.pulled = []
    peer.pull_space_paced = lambda space, settle: peer.pulled.append(space) or True
    read = rules(peer)
    assert sorted(read) == ["AgentConfiguration", "Constraint", "JuryDecision", "Vocabulary"]
    assert peer.pulled == ["constraints", "policy", "decisions"], "one pull per space, constraints shared"


def test_a_prompt_ref_renders_the_fallback_until_the_set_names_it():
    from agentspaces.console import PromptRef, render_prompt
    import pytest
    ref = PromptRef("correlation/classify", "Compare {left} and {right}.", lambda: None)
    assert ref.version == 0 and ref.text == "Compare {left} and {right}."
    assert ref.render({"left": "A", "right": "B"}) == "Compare A and B."
    assert ref.hint == ("prompt.correlation/classify", "0")
    live = {"group": "claims-fleet", "prompts": [{"id": "correlation/classify", "version": 3, "hash": "sha256:x", "kind": "agent-system",
                                                  "text": "You compare {left} with {right}. {hint}",
                                                  "variables": [{"name": "left", "required": True}, {"name": "right", "required": True}, {"name": "hint", "required": False}]}]}
    ref = PromptRef("correlation/classify", "fallback", lambda: live)
    assert ref.version == 3
    assert ref.render({"left": "A", "right": "B"}) == "You compare A with B. "
    with pytest.raises(ValueError, match="right"):
        ref.render({"left": "A"})
    assert render_prompt("no placeholders", [], None) == "no placeholders"



def test_every_console_golden_vector_round_trips_byte_for_byte():
    """S4-I-14: the console's golden vectors (bma-console-common/src/main/resources/console-golden.properties, the
    canonical CBOR of every console record as the Java codec writes it) decode and re-encode to the same bytes here,
    so a Python agent that reads a console record and writes it back changes nothing on the wire."""
    import pathlib
    from agentspaces import cbor
    vectors = pathlib.Path(__file__).resolve().parents[2] / "enterprise-platform" / "bma-console-common" / "src" / "main" / "resources" / "console-golden.properties"
    if not vectors.exists():
        import pytest
        pytest.skip("the platform's console golden vectors are not beside this checkout")
    count = 0
    for line in vectors.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, hexed = line.split("=", 1)
        raw = bytes.fromhex(hexed.strip())
        decoded = cbor.loads(raw)
        assert isinstance(decoded, dict), name
        assert cbor.dumps(decoded) == raw, f"{name} re-encodes to different bytes"
        count += 1
    assert count >= 60
