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
"""Remote actions (RemoteActions, RemoteAction) from Python: the actions the
fleet's AgentCards declare, each a take binding (a task space and the
schema it consumes and produces), invoked by writing the input into the
task space and awaiting the correlated result."""

from __future__ import annotations

from dataclasses import dataclass

from ..space import Space, Template, to_payload
from ..timesource import SYSTEM

#: How often, at most, an invoke pulls the result space while it waits: the take's settle window.
PULL_EVERY_S = 0.6


@dataclass(frozen=True)
class RemoteAction:
    card: dict
    name: str
    description: str
    consumes: str
    produces: str
    space: str

    @property
    def agent(self) -> str:
        return self.card["agent"]


def actions(peer) -> list[RemoteAction]:
    """Every invocable action the cached cards declare: a declared ``take``
    action with one consumed and one produced schema and a space, or, for a
    card without declared actions, each (consumes, produces, binding) pair."""
    found = []
    for card in peer.cards():
        declared = card.get("actions") or []
        if declared:
            for a in declared:
                if a.get("kind") == "take" and a.get("space") and len(a.get("consumes") or []) == 1 \
                        and len(a.get("produces") or []) == 1:
                    found.append(RemoteAction(card, a["name"], a.get("description") or card.get("description", ""),
                                              a["consumes"][0], a["produces"][0], a["space"]))
            continue
        bindings = card.get("spaceBindings") or {}
        for consumed in card.get("consumes") or []:
            space = bindings.get(consumed)
            for produced in card.get("produces") or []:
                if space:
                    found.append(RemoteAction(card, f"{card['agent'].rsplit('/', 1)[-1]}_{consumed}",
                                              card.get("description", ""), consumed, produced, space))
    return found


def shared_fields(input_payload: dict, candidate: dict) -> bool:
    """Correlation.sharedFields: every field both carry is equal."""
    return all(candidate.get(k) == v for k, v in input_payload.items() if k in candidate)


def invoke(peer, action: RemoteAction, value, result_type=None, timeout_seconds: float = 30.0,
           result_space: str | None = None, lease="10m", agent=None, agent_name: str = "python"):
    """Writes ``value`` into the action's task space and awaits the first
    result (of the produced schema, decoded as ``result_type`` when given)
    not present before the write whose shared fields match; None at the
    timeout."""
    task_space = Space(peer, action.space, agent=agent, agent_name=agent_name)
    results = Space(peer, result_space or action.space, agent=agent, agent_name=agent_name)
    template = Template(result_type or action.produces)
    input_payload = to_payload(value)
    baseline = {e.entry_id for e in results.entries(template, 1_000)}
    task_space.write(value, lease=lease)
    # A local period on the peer's monotonic clock, woken by each fold and pulling the result space
    # at most once per settle window (SPEC v0.1.36 §9.5; JS-V-02), where it polled every 100 ms on
    # the wall clock and pulled on every poll.
    source = getattr(peer, "time", SYSTEM)
    deadline = source.monotonic() + timeout_seconds
    while True:
        seen = peer.fold_count
        for e in results.entries(template, 1_000):
            if e.entry_id in baseline:
                continue
            payload = to_payload(e.value) if not isinstance(e.value, dict) else e.value
            if shared_fields(input_payload, payload):
                return e.value
        remaining = deadline - source.monotonic()
        if remaining <= 0:
            return None
        peer.pull_space_paced(results.name, PULL_EVERY_S)
        peer.await_fold(min(PULL_EVERY_S, remaining), since=seen)
