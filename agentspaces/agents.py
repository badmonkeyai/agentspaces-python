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
"""The programming model, Python-shaped (L3L4-COVERAGE.md §6.4): decorators on
the methods of a plain class, and a ``Binder`` that runs the loops the Java
``AgentBinder`` runs for the annotations, over a ``Peer``:

    @agent("researcher", description="Researches topics", goals=["research"])
    class Researcher:
        @space_take("tasks", lease="2s", where={"priority": gte(1)})
        def research(self, task: ResearchTask) -> Finding:
            return Finding(task.topic, "researched", "py")

        @space_notify("findings")
        def audit(self, finding: Finding) -> Receipt | None:
            return Receipt(finding.topic)

        @bid_function("tasks")
        def price(self, task: ResearchTask) -> float:
            return 1.0 if task.priority > 3 else 10.0

        @ballot("decisions")
        def judge(self, proposal: Proposal) -> str | None:
            return "approve"

        @on_decision("decisions", result_space="ledger")
        def record(self, decision: Decision) -> Verdict:
            return Verdict(decision.proposal_id, decision.winner)

    bound = Binder(peer, agent=identity.renewing_subordinate("py-worker", "PT24H")).bind(Researcher())
    bound.close()

The parameter annotation is the cue (an ``@entry`` class), the return value is
the next entry (``None`` writes nothing, or abstains), a ``Tagged(value, tags)``
written with its tags, a list or tuple of entries (the fork, each written on
its own), or a ``Motion`` opening a vote once per proposal id. ``@propose``
opens a vote from a cue once per key; ``@space_join`` (LOCAL mode) fires
once per key when every required part is present. A take completes in its
space with the result, where a remote caller awaits it, or in ``result_space``;
a notify fires once per entry; a ballot casts once per proposal; a decision
fires once per proposal when the quorum closes; the AgentCard, with the
declared actions, is published on bind. A notify, a propose, and a join part
hold a leased push subscription the binder renews at half-lease (JS-V-01).
An ordered take goes through ``Space.take(template, through=OrderedLog)``
(JS-V-05); the decorated ordered verbs (``@OrderedTake``, reduces, the
fleet-wide join modes) are not here.
"""

from __future__ import annotations

import dataclasses
import inspect
import threading
import time
import typing
from typing import Any, Callable

from . import vote as votes
from . import wire
from .identity import instant_iso
from .space import (COMPLETED, Contribution, Event, Motion, Space, TakeContext, Tagged, Template, WRITTEN,
                    duration_millis, from_payload, schema_of, to_payload)

# ------------------------------------------------------------- vote records


@dataclasses.dataclass(frozen=True)
class Proposal:
    """A proposal as the ballot method sees it."""
    proposal_id: str
    question: str
    options: list
    quorum: int


@dataclasses.dataclass(frozen=True)
class Decision:
    """A closed vote as the decision method sees it."""
    proposal_id: str
    winner: str
    tally: dict


# -------------------------------------------------------------- decorators

_META = "__agentspaces_binding__"


def _mark(fn, verb: str, **attrs):
    setattr(fn, _META, {"verb": verb, **attrs})
    return fn


def agent(name: str, description: str = "", goals: list | None = None):
    """Names the agent, as ``@AgentSpec`` does: the card's name, description, and goals."""
    def bind(cls):
        cls.__agentspaces_spec__ = {"name": name, "description": description, "goals": list(goals or [])}
        return cls
    return bind


def space_take(space: str, lease="10m", poll_timeout="1s", result_space: str | None = None,
               result_lease="1h", tags: dict | None = None, where: dict | None = None, description: str = "",
               produces=None, filters: list | tuple = ()):
    """The kill-tolerant worker: take one matching entry under a lease, call,
    complete with the result; a crash lets the lease lapse and the entry
    reappear. ``produces`` names the entry classes the card lists when the
    return annotation does not say (the elements of a fork). ``filters`` are
    clauses of the portable grammar (``"priority>=3"``), as Java's ``where``
    strings are (JS-V-03); ``where`` holds Python matchers."""
    return lambda fn: _mark(fn, "take", space=space, lease=lease, poll_timeout=poll_timeout,
                            result_space=result_space, result_lease=result_lease, tags=tags, where=where,
                            description=description, produces=produces, filters=list(filters))


def space_notify(space: str, result_space: str | None = None, result_lease="1h",
                 tags: dict | None = None, where: dict | None = None, on=WRITTEN, description: str = "",
                 produces=None, filters: list | tuple = (), lease="1h"):
    """Choreography: called once per matching entry and event kind, never
    consuming it. ``on`` is one kind or several of ``WRITTEN``, ``TAKEN``,
    ``COMPLETED``, ``EXPIRED`` (the write lease lapsed: a leased entry as a
    timer), and ``REAPPEARED`` (a take claim lapsed). ``lease`` is the push
    subscription's lease, renewed at half-lease while the agent stays bound
    (JS-V-01), so a reactor that outlives its binder goes quiet."""
    kinds = [on] if isinstance(on, str) else list(on)
    if not kinds:
        raise ValueError("@space_notify needs at least one event kind")
    return lambda fn: _mark(fn, "notify", space=space, result_space=result_space, result_lease=result_lease,
                            tags=tags, where=where, on=kinds, description=description, produces=produces,
                            filters=list(filters), lease=lease)


def bid_function(space: str):
    """The price of work under AUCTION: a float per entry, the lowest wins."""
    return lambda fn: _mark(fn, "bid", space=space)


def ballot(space: str, prefix: str = "", lease="1h"):
    """One signed ballot per proposal: return the option, or None to abstain."""
    return lambda fn: _mark(fn, "ballot", space=space, prefix=prefix, lease=lease)


def on_decision(space: str, prefix: str = "", result_space: str | None = None, result_lease="1h"):
    """Reacts once when a proposal's quorum closes it."""
    return lambda fn: _mark(fn, "decision", space=space, prefix=prefix, result_space=result_space,
                            result_lease=result_lease)


@dataclasses.dataclass(frozen=True)
class Part:
    """One part of a join (``@Part``): its entry class, the space it lives in
    (the join's by default), the key field (the join's by default) or the
    key tag, whether it is optional, how many are needed, and filters."""
    type: Any
    space: str | None = None
    key: str | None = None
    key_tag: str | None = None
    optional: bool = False
    at_least: int = 1
    where: dict | None = None
    tags: dict | None = None
    filters: tuple = ()  # clauses of the portable grammar (JS-V-03)


def space_join(space: str, key: str, parts: list, within="1h", result_space: str | None = None,
               result_lease="1h", max_open: int = 10_000, description: str = ""):
    """The fan-in (``@SpaceJoin`` in LOCAL mode): once per key, when every
    required part is readable, the method receives a ``Joined`` and its
    return is dispatched as a take's is. A key is forgotten after ``within``
    if it never completes; the fleet-wide LEASED and ORDERED modes are not
    available from Python."""
    return lambda fn: _mark(fn, "join", space=space, key=key, parts=list(parts), within=within,
                            result_space=result_space, result_lease=result_lease, max_open=max_open,
                            description=description)


def propose(space: str, vote: str, options: list, quorum: int, prefix: str = "", key: list | str | None = None,
            key_tag: str | None = None, lease="1h", where: dict | None = None, tags: dict | None = None,
            description: str = "", filters: list | tuple = ()):
    """Opens a vote from a cue (``@Propose``): the method receives the cue
    and returns the question (or None to ask nothing, or a ``Motion``); the
    proposal id is ``prefix`` plus the key fields joined by ``:`` (or the key
    tag), opened once per id. ``filters`` are clauses of the portable grammar
    over the cue (JS-V-03)."""
    keys = [key] if isinstance(key, str) else list(key or [])
    if keys and key_tag:
        raise ValueError("@propose names both key and key_tag; choose one")
    if len(options) < 2 or quorum <= 0:
        raise ValueError("@propose needs at least two options and a positive quorum")
    return lambda fn: _mark(fn, "propose", space=space, vote=vote, options=list(options), quorum=int(quorum),
                            prefix=prefix, key=keys, key_tag=key_tag, lease=lease, where=where, tags=tags,
                            description=description, filters=list(filters))


def on_estimate(epochs: str = "", ticks: int = 0, tolerance: float = 0.0, result_space: str | None = None,
                result_lease="1h"):
    """Reacts once per aggregate epoch (by prefix, or every epoch) when its
    estimate has settled under the rule, as ``@OnEstimate`` does; the method
    receives an ``Estimate`` and may return an entry for ``result_space``.
    Needs a ``Binder(..., aggregate=Aggregate)``."""
    return lambda fn: _mark(fn, "estimate", epochs=epochs, ticks=ticks, tolerance=tolerance,
                            result_space=result_space, result_lease=result_lease)


# ------------------------------------------------------------------ binder


def _cue_type(fn) -> Any:
    hints = typing.get_type_hints(fn)
    params = [p for p in inspect.signature(fn).parameters.values() if p.name != "self"]
    if len(params) != 1:
        raise TypeError(f"{fn.__name__} takes one entry parameter, found {len(params)}")
    hint = hints.get(params[0].name)
    if hint is None:
        raise TypeError(f"{fn.__name__}'s parameter {params[0].name} needs an @entry type annotation")
    return hint


def _produced(fn, declared=None):
    if declared:
        return declared if isinstance(declared, (list, tuple)) else [declared]
    hint = typing.get_type_hints(fn).get("return")
    if hint is None:
        return None
    args = typing.get_args(hint)
    for candidate in (args or (hint,)):
        if candidate is not type(None) and getattr(candidate, "__agentspaces_schema__", None):
            return [candidate]
    return None


class Joined:
    """What a join method receives (``Joined`` in Java): the key and the parts by class."""

    def __init__(self, key: str, parts: dict):
        self.key = key
        self._parts = parts  # class -> [values]

    def get(self, cls):
        found = self._parts.get(cls) or []
        if not found:
            raise KeyError(f"no {getattr(cls, '__name__', cls)} part for key {self.key!r}")
        return found[0]

    def find(self, cls):
        found = self._parts.get(cls) or []
        return found[0] if found else None

    def all(self, cls) -> list:
        return list(self._parts.get(cls) or [])

    def has(self, cls) -> bool:
        return bool(self._parts.get(cls))

    def parts(self) -> dict:
        return {k: list(v) for k, v in self._parts.items()}


class Bound:
    """A bound agent: its loops and watches, closed together."""

    def __init__(self, binder: "Binder", name: str, card: dict | None):
        self.binder = binder
        self.name = name
        self.card = card
        self._threads: list[threading.Thread] = []
        self._subscriptions = []
        self._running = True
        self._stopped = threading.Event()  # set on close: a renewal sleeping on it wakes at once

    def close(self) -> None:
        self._running = False
        self._stopped.set()
        for s in self._subscriptions:
            s.close()
        for t in self._threads:
            t.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Binder:
    """Runs decorated agents over one peer. ``agent`` (an ``AgentIdentity``)
    makes every record the agent's own attested one; the peer-signed
    ``agent_name`` otherwise. ``publish_card`` sends the AgentCard on bind."""

    def __init__(self, peer, agent=None, agent_name: str = "python", publish_card: bool = True,
                 card_ttl: str = "PT10M", aggregate=None, vote_space: str | None = None):
        self.peer = peer
        self.agent = agent
        self.agent_name = agent_name
        self.publish_card = publish_card
        self.card_ttl = card_ttl
        self.aggregate = aggregate
        self.vote_space = vote_space  # where a Motion without a space is proposed
        self._spaces: dict[str, Space] = {}
        self._bids: dict[str, Callable] = {}

    def space(self, name: str) -> Space:
        if name not in self._spaces:
            self._spaces[name] = Space(self.peer, name, agent=self.agent, agent_name=self.agent_name)
        return self._spaces[name]

    def bind(self, obj) -> Bound:
        spec = getattr(type(obj), "__agentspaces_spec__", None) or {
            "name": type(obj).__name__[:1].lower() + type(obj).__name__[1:], "description": "", "goals": []}
        name = spec["name"]
        bound = Bound(self, name, None)
        methods = [(n, m) for n, m in inspect.getmembers(obj, callable) if getattr(m, _META, None)]
        consumes, produces, bindings, actions = [], [], {}, []
        # Bids first, so AUCTION spaces are priced before any take runs.
        for _, method in methods:
            meta = getattr(method, _META)
            if meta["verb"] == "bid":
                cue = _cue_type(method)
                self.space(meta["space"]).bid_function = lambda payload, m=method, c=cue: float(m(from_payload(c, payload)))
        for mname, method in methods:
            meta = getattr(method, _META)
            verb = meta["verb"]
            if verb == "bid":
                continue
            if verb == "estimate":
                self._start_estimate(bound, obj, method, meta)
                continue
            if verb == "join":
                for part in meta["parts"]:
                    consumes.append(schema_of(part.type))
                produced_schemas = [schema_of(p) for p in (_produced(method) or [])]
                produces.extend(produced_schemas)
                actions.append(wire.card_action(mname, meta.get("description") or "",
                                                [schema_of(p.type) for p in meta["parts"]],
                                                produced_schemas, "join", meta["space"]))
                self._start_join(bound, obj, method, meta)
                continue
            cue = _cue_type(method)
            produced = _produced(method, meta.get("produces"))
            if produced is not None and not isinstance(produced, (list, tuple)):
                produced = [produced]
            if verb == "propose":
                schema = schema_of(cue)
                consumes.append(schema)
                bindings.setdefault(votes.PROPOSAL_TYPE, meta["vote"])
                actions.append(wire.card_action(mname, meta.get("description") or "", [schema],
                                                [votes.PROPOSAL_TYPE], "propose", meta["space"]))
                self._start_propose(bound, obj, method, meta, cue)
                continue
            if verb in ("take", "notify"):
                schema = schema_of(cue)
                consumes.append(schema)
                produced_schemas = [schema_of(p) for p in (produced or [])]
                produces.extend(produced_schemas)
                if verb == "take":
                    bindings[schema] = meta["space"]
                actions.append(wire.card_action(mname, meta.get("description") or "", [schema],
                                                produced_schemas, "take" if verb == "take" else "notify",
                                                meta["space"]))
                if verb == "take":
                    self._start_take(bound, obj, method, meta, cue)
                else:
                    self._start_notify(bound, obj, method, meta, cue)
            elif verb == "ballot":
                self._start_ballot(bound, obj, method, meta)
            elif verb == "decision":
                self._start_decision(bound, obj, method, meta)
        if self.publish_card and hasattr(self.peer, "publish_ad"):
            bound.card = self._publish_card(name, spec, consumes, produces, bindings, actions)
        return bound

    # ----------------------------------------------------------------- card

    def _publish_card(self, name, spec, consumes, produces, bindings, actions) -> dict:
        now_ms = self.peer._now_ms()
        issued = instant_iso(now_ms - now_ms % 1000)
        certificate = None
        agent_key = None
        local_name = name
        if self.agent is not None:
            # The card names the certified agent: its own name, as the Java binder does.
            agent_key = self.agent.public_raw
            certificate = self.agent.certificate_covering(now_ms)
            local_name = self.agent.agent_id.rsplit("/", 1)[-1]
        card = wire.agent_card(self.peer.group, self.peer.identity, local_name, issued, self.card_ttl,
                               spec.get("description") or "", list(spec.get("goals") or []),
                               list(dict.fromkeys(consumes)), list(dict.fromkeys(produces)), {}, bindings,
                               agent_public_raw=agent_key, actions=actions or None, agent_certificate=certificate)
        self.peer.publish_ad("AgentCard", card)
        return card

    # ---------------------------------------------------------------- loops

    def _write_result(self, bound: Bound, result, meta, default_space: Space):
        """The dispatch of a method's return (AgentBinder.dispatch): nothing for
        None; each element of a list or tuple on its own (the fork); a
        ``Motion`` proposed in its vote space; a ``Tagged`` written with its
        tags; any other value written as the next entry."""
        if result is None:
            return None
        if isinstance(result, (list, tuple)):
            for element in result:
                if isinstance(element, (list, tuple)):
                    raise ValueError(f"{bound.name} returned a fork inside a fork")
                self._write_result(bound, element, meta, default_space)
            return None
        if isinstance(result, Motion):
            self._move(bound, result)
            return None
        if isinstance(result, Contribution):
            if self.aggregate is None:
                raise ValueError(f"{bound.name} returned a Contribution and the binder has no aggregate")
            self.aggregate.start(result.epoch_id, float(result.value), result.mode)
            return None
        target = self.space(meta["result_space"]) if meta.get("result_space") else default_space
        if isinstance(result, Tagged):
            return target.write(result.value, lease=meta.get("result_lease", "1h"), tags=result.tags)
        return target.write(result, lease=meta.get("result_lease", "1h"))

    def _move(self, bound: Bound, motion: Motion) -> None:
        space = motion.space or self.vote_space
        if not space:
            raise ValueError(f"{bound.name} returned a Motion naming no space and the binder has no vote_space")
        votes.propose(self.peer, space, motion.proposal_id, motion.question, motion.options, motion.quorum,
                      lease_millis=duration_millis(motion.lease), agent=self.agent, agent_name=self.agent_name)

    @staticmethod
    def _template(cue, meta) -> Template:
        """The binding's template (AgentBinder.templateFor): Python matchers in
        ``where``, tag conditions, and the portable grammar's clauses in
        ``filters`` (JS-V-03), judged as Java and TypeScript judge them."""
        return Template(cue, where=meta.get("where"), tags=meta.get("tags"), filters=meta.get("filters") or ())

    def _subscribe(self, bound: Bound, space: Space, template: Template, on_event, lease="1h") -> None:
        """The leased subscription every reacting binding shares (AgentBinder.watch,
        JS-V-01): ``space.notify`` under ``lease``, renewed at half-lease on a thread
        while the agent stays bound, so a long-lived reactor never goes deaf and a
        subscription whose binder is gone lapses on its own."""
        lease_ms = duration_millis(lease)
        subscription = space.notify(template, on_event, lease=lease_ms)
        half_seconds = max(0.05, lease_ms / 2000)

        def renew():
            while bound._running and subscription.open:
                if bound._stopped.wait(half_seconds):
                    return
                if bound._running and subscription.open:
                    subscription.renew()

        thread = threading.Thread(target=renew, name=f"{bound.name}.renew", daemon=True)
        bound._subscriptions.append(subscription)
        bound._threads.append(thread)
        thread.start()

    def _start_take(self, bound: Bound, obj, method, meta, cue) -> None:
        space = self.space(meta["space"])
        template = self._template(cue, meta)
        lease, poll = meta["lease"], meta["poll_timeout"]

        def loop():
            while bound._running and self.peer.connected:
                try:
                    taken = space.take(template, lease=lease, timeout=poll)
                except Exception:
                    time.sleep(0.5)
                    continue
                if taken is None:
                    continue
                token = TakeContext.bind(taken)
                try:
                    result = method(taken.value)
                except Exception:
                    # The lease lapses and the entry reappears for another worker.
                    continue
                finally:
                    TakeContext.unbind(token)
                try:
                    if result is None or isinstance(result, (Motion, Contribution, list, tuple)) or meta.get("result_space"):
                        # The take is finished first: a failed open or fork cannot
                        # make a completed task reappear (ISSUE-Motion FR-4).
                        taken.complete(None)
                        self._write_result(bound, result, meta, space)
                    elif isinstance(result, Tagged):
                        taken.complete(result.value, lease=meta.get("result_lease", "1h"), tags=result.tags)
                    else:
                        taken.complete(result, lease=meta.get("result_lease", "1h"))
                except Exception:
                    pass

        thread = threading.Thread(target=loop, name=f"{bound.name}.{method.__name__}", daemon=True)
        bound._threads.append(thread)
        thread.start()

    def _start_notify(self, bound: Bound, obj, method, meta, cue) -> None:
        space = self.space(meta["space"])
        template = self._template(cue, meta)
        wanted = set(meta.get("on") or [WRITTEN])

        def on_event(event: Event):
            if event.kind not in wanted:
                return
            # Off the delivery thread, as the Java binder runs reactions.
            def react():
                try:
                    self._write_result(bound, method(event.entry.value), meta, space)
                except Exception:
                    pass
            threading.Thread(target=react, name=f"{bound.name}.{method.__name__}", daemon=True).start()

        self._subscribe(bound, space, template, on_event, lease=meta.get("lease", "1h"))

    def _start_ballot(self, bound: Bound, obj, method, meta) -> None:
        space = self.space(meta["space"])
        prefix = meta.get("prefix") or ""
        cast_for: set[str] = set()
        lease_ms = duration_millis(meta.get("lease", "1h"))

        def on_event(event: Event):
            proposal = event.entry.value
            pid = proposal.get("proposalId")
            if not isinstance(pid, str) or not pid.startswith(prefix) or pid in cast_for:
                return
            cast_for.add(pid)

            def react():
                try:
                    option = method(Proposal(pid, proposal.get("question", ""), list(proposal.get("options") or []),
                                             int(proposal.get("quorum", 0))))
                except Exception:
                    return
                if option is not None:
                    votes.cast(self.peer, space.name, pid, option, lease_millis=lease_ms,
                               agent=self.agent, agent_name=self.agent_name)
            threading.Thread(target=react, name=f"{bound.name}.{method.__name__}", daemon=True).start()

        bound._subscriptions.append(space.watch(Template(votes.PROPOSAL_TYPE), on_event))

    def _start_decision(self, bound: Bound, obj, method, meta) -> None:
        space = self.space(meta["space"])
        prefix = meta.get("prefix") or ""
        fired: set[str] = set()
        lock = threading.Lock()

        def check(pid: str):
            if not pid.startswith(prefix):
                return
            decided = votes.decision(self.peer.states, pid)
            if decided is None:
                return
            with lock:
                if pid in fired:
                    return
                fired.add(pid)

            def react():
                try:
                    self._write_result(bound, method(Decision(pid, decided["winner"], decided["tally"])), meta, space)
                except Exception:
                    pass
            threading.Thread(target=react, name=f"{bound.name}.{method.__name__}", daemon=True).start()

        def on_ballot(event: Event):
            check(event.entry.value.get("proposalId", ""))

        def on_proposal(event: Event):
            check(event.entry.value.get("proposalId", ""))

        bound._subscriptions.append(space.watch(Template(votes.BALLOT_TYPE), on_ballot))
        bound._subscriptions.append(space.watch(Template(votes.PROPOSAL_TYPE), on_proposal))

    def _start_estimate(self, bound: Bound, obj, method, meta) -> None:
        if self.aggregate is None:
            raise ValueError(f"{method.__name__} needs an aggregate: Binder(peer, aggregate=Aggregate(pipes))")
        from .capabilities.aggregate import Settle
        prefix = meta.get("epochs") or ""
        space = self.space(meta["result_space"]) if meta.get("result_space") else None

        def react(estimate):
            try:
                result = method(estimate)
                if space is not None and result is not None:
                    space.write(result, lease=meta.get("result_lease", "1h"))
            except Exception:
                pass

        closer = self.aggregate.on_estimate(lambda e: e.startswith(prefix),
                                            Settle.after(int(meta.get("ticks", 0)), float(meta.get("tolerance", 0.0))),
                                            react)
        bound._subscriptions.append(type("Closer", (), {"close": staticmethod(closer)})())

    # --------------------------------------------------------------- propose

    def _start_propose(self, bound: Bound, obj, method, meta, cue) -> None:
        cue_space = self.space(meta["space"])
        template = self._template(cue, meta)
        keys, key_tag, prefix = meta["key"], meta.get("key_tag"), meta.get("prefix") or ""
        opened: set[str] = set()
        lock = threading.Lock()

        def on_event(event: Event):
            if event.kind != WRITTEN:
                return
            if key_tag:
                key = event.entry.tags.get(key_tag)
            elif keys:
                payload = to_payload(event.entry.value)
                parts = [payload.get(k) for k in keys]
                key = None if any(p is None for p in parts) else ":".join(str(p) for p in parts)
            else:
                key = None
            if (keys or key_tag) and key is None:
                return
            proposal_id = prefix + key if key is not None else None
            if proposal_id is not None:
                with lock:
                    if proposal_id in opened:
                        return
                    opened.add(proposal_id)

            def react():
                try:
                    if proposal_id is not None and proposal_id in votes.proposals(self.peer.states):
                        return
                    result = method(event.entry.value)
                    if result is None:
                        with lock:
                            opened.discard(proposal_id)
                        return
                    if isinstance(result, Motion):
                        self._move(bound, dataclasses.replace(result, space=result.space or meta["vote"]))
                        return
                    if proposal_id is None:
                        raise ValueError(f"{bound.name}.{method.__name__} names no key and returned no Motion")
                    votes.propose(self.peer, meta["vote"], proposal_id, str(result), meta["options"], meta["quorum"],
                                  lease_millis=duration_millis(meta.get("lease", "1h")), agent=self.agent,
                                  agent_name=self.agent_name)
                except Exception:
                    with lock:
                        opened.discard(proposal_id)
            threading.Thread(target=react, name=f"{bound.name}.{method.__name__}", daemon=True).start()

        self._subscribe(bound, cue_space, template, on_event)

    # ------------------------------------------------------------------ join

    def _start_join(self, bound: Bound, obj, method, meta) -> None:
        join_space = self.space(meta["space"])
        parts: list[Part] = meta["parts"]
        within_ms = duration_millis(meta["within"])
        state: dict[str, dict] = {}   # key -> {"parts": {cls: [values]}, "seen": set(entry ids), "since": ms}
        fired: set[str] = set()
        lock = threading.Lock()
        max_open = int(meta.get("max_open", 10_000))

        def key_of(part: Part, value, tags: dict):
            if part.key_tag:
                return tags.get(part.key_tag)
            field = part.key or meta["key"]
            return (lambda v: None if v is None else str(v))(to_payload(value).get(field))

        def complete(st) -> bool:
            for part in parts:
                if part.optional:
                    continue
                if len(st["parts"].get(part.type) or []) < max(1, part.at_least):
                    return False
            return True

        def fire(key: str):
            with lock:
                st = state.pop(key, None)
            if st is None:
                return
            joined = Joined(key, st["parts"])
            try:
                self._write_result(bound, method(joined), meta, join_space)
            except Exception:
                with lock:
                    fired.discard(key)  # the next part fires it again

        def on_part(part: Part):
            def on_event(event: Event):
                if event.kind != WRITTEN:
                    return
                key = key_of(part, event.entry.value, event.entry.tags)
                if key is None:
                    return
                now = self.peer._now_ms()
                with lock:
                    if key in fired:
                        return
                    # Forget keys that never completed within the window.
                    for stale in [k for k, st in state.items() if now - st["since"] > within_ms]:
                        state.pop(stale, None)
                    st = state.get(key)
                    if st is None:
                        if len(state) >= max_open:
                            state.pop(next(iter(state)), None)
                        st = state[key] = {"parts": {}, "seen": set(), "since": now}
                    if event.entry.entry_id in st["seen"]:
                        return
                    st["seen"].add(event.entry.entry_id)
                    st["parts"].setdefault(part.type, []).append(event.entry.value)
                    ready = complete(st)
                    if ready:
                        fired.add(key)
                if ready:
                    threading.Thread(target=fire, args=(key,), name=f"{bound.name}.{method.__name__}",
                                     daemon=True).start()
            return on_event

        for part in parts:
            space = self.space(part.space) if part.space else join_space
            template = Template(part.type, where=part.where, tags=part.tags, filters=part.filters or ())
            self._subscribe(bound, space, template, on_part(part))
