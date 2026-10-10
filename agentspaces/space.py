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
"""The AgentSpace, Python-shaped (L3L4-COVERAGE.md §6.4): typed entries
bound to their wire schema, templates over fields and tags with the Java
``Matchers`` semantics, a ``Space`` with the layer-3 verbs over a ``Peer``,
events from the fold, and the in-flight take as a context variable.

    @entry("com.acme.Task#v1")
    @dataclass
    class Task:
        topic: str
        priority: int

    space = Space(peer, "tasks")
    space.write(Task("index", 3), lease="10m", tags={"region": "eu"})
    for task in space.read_all(Template(Task, where={"priority": gte(3)}, tags={"region": "eu"})):
        ...
    taken = space.take(Template(Task), lease="1m", timeout="15s")
    taken.complete(Finding(taken.value.topic, "done"))
"""

from __future__ import annotations

import contextvars
import dataclasses
import re
import threading
import time
from typing import Any, Callable

from . import cbor

# ----------------------------------------------------------------- durations

_UNITS = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1_000.0, "m": 60_000.0, "h": 3_600_000.0, "d": 86_400_000.0}


def duration_millis(value) -> int:
    """A duration as milliseconds: an int (millis), a float (seconds), or the
    short form ``"250ms"``, ``"10m"``, ``"2h"`` and ISO-8601 ``"PT5M"``."""
    if isinstance(value, bool):
        raise ValueError("not a duration: bool")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value * 1000)
    text = str(value).strip()
    if text.upper().startswith("PT"):
        total = 0.0
        for amount, unit in re.findall(r"([0-9.]+)([HMS])", text.upper()):
            total += float(amount) * {"H": 3_600_000, "M": 60_000, "S": 1_000}[unit]
        return int(total)
    m = re.fullmatch(r"([0-9]+)\s*([a-z]+)", text)
    if not m:
        raise ValueError(f"not a duration: {value!r}")
    return int(int(m.group(1)) * _UNITS[m.group(2)])


# ------------------------------------------------------------------- entries

def entry(schema: str):
    """Binds a class (a dataclass, usually) to its wire schema name, the name
    the fleet names the type by: a Java record's binary class name plus
    ``#v1`` under the default registry, or the namespace a schema registry
    assigns."""
    def bind(cls):
        cls.__agentspaces_schema__ = schema
        return cls
    return bind


def schema_of(type_or_obj) -> str:
    """The wire schema name of an ``@entry`` class, an instance of one, or a
    schema string passed through."""
    if isinstance(type_or_obj, str):
        return type_or_obj
    cls = type_or_obj if isinstance(type_or_obj, type) else type(type_or_obj)
    schema = getattr(cls, "__agentspaces_schema__", None)
    if schema is None:
        raise TypeError(f"{cls.__name__} is not an @entry class and names no schema")
    return schema


def to_payload(value) -> dict:
    """The wire payload of an entry value: a dataclass's fields, or a dict."""
    if isinstance(value, dict):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    raise TypeError(f"cannot encode {type(value).__name__} as an entry payload")


def from_payload(cls, payload: dict):
    """An entry value from its wire payload: the dataclass built from the
    fields it declares (extra wire fields are ignored), or the dict when the
    class is a plain schema string."""
    if isinstance(cls, str) or cls is dict:
        return payload
    if dataclasses.is_dataclass(cls):
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in names})
    return cls(**payload)


# ------------------------------------------------------------------ matchers

def eq(expected):
    return lambda v: v == expected


def ne(unexpected):
    return lambda v: v != unexpected


def gt(bound):
    return lambda v: v is not None and v > bound


def gte(bound):
    return lambda v: v is not None and v >= bound


def lt(bound):
    return lambda v: v is not None and v < bound


def lte(bound):
    return lambda v: v is not None and v <= bound


def in_(*alternatives):
    return lambda v: v in alternatives


def contains(fragment: str):
    return lambda v: isinstance(v, str) and fragment in v


def is_null():
    return lambda v: v is None


def not_null():
    return lambda v: v is not None


def _matcher(spec) -> Callable[[Any], bool]:
    return spec if callable(spec) else eq(spec)


class Template:
    """A query: the entry type (an ``@entry`` class or a schema string), field
    conditions, and tag conditions. A plain value means equality; a callable
    is a predicate; ``eq``, ``ne``, ``gt``, ``gte``, ``lt``, ``lte``, ``in_``,
    ``contains``, ``is_null``, ``not_null`` are the Java matchers."""

    def __init__(self, type, where: dict | None = None, tags: dict | None = None):
        self.type = type
        self.schema = schema_of(type)
        self.where = {k: _matcher(v) for k, v in (where or {}).items()}
        self.tags = {k: _matcher(v) for k, v in (tags or {}).items()}

    def matches(self, payload: dict, tags: dict | None = None) -> bool:
        payload = payload or {}
        for field, test in self.where.items():
            if not test(payload.get(field)):
                return False
        return self.matches_tags(tags or {})

    def matches_tags(self, tags: dict) -> bool:
        for key, test in self.tags.items():
            if not test(tags.get(key)):
                return False
        return True

    def decode(self, payload: dict):
        return from_payload(self.type, payload)

    def __repr__(self):
        return f"Template({self.schema}, where={list(self.where)}, tags={list(self.tags)})"


# --------------------------------------------------------------- the entries

@dataclasses.dataclass(frozen=True)
class Entry:
    """An entry as the space holds it: the value, its id, its tags, who
    issued it, when its write lease ends, and whether it is completed."""
    entry_id: str
    value: Any
    tags: dict
    issuer: str
    expires_at_millis: int
    completed: bool
    taken: bool


@dataclasses.dataclass(frozen=True)
class Event:
    """What a watch delivers: WRITTEN, TAKEN, or COMPLETED, with the entry."""
    kind: str
    entry: Entry


WRITTEN = "WRITTEN"
TAKEN = "TAKEN"
COMPLETED = "COMPLETED"
EXPIRED = "EXPIRED"        # the write lease lapsed with the entry still open
REAPPEARED = "REAPPEARED"  # a take claim lapsed and the entry is available again


class Subscription:
    """A watch handle; ``close()`` stops the deliveries."""

    def __init__(self, space: "Space", key: int):
        self._space = space
        self._key = key

    def close(self) -> None:
        self._space._watchers.pop(self._key, None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Taken:
    """A held entry: complete it, with a result or without, or renew it."""

    def __init__(self, space: "Space", entry_id: str, value, lease_millis: int):
        self.space = space
        self.entry_id = entry_id
        self.value = value
        self.lease_millis = lease_millis

    def complete(self, result=None, lease="1h", tags: dict | None = None, result_space: "Space | None" = None) -> str | None:
        """Completes the take, writing ``result`` first (into the take space,
        or ``result_space``) so a caller correlating on it sees it with the
        completion. Returns the result's entry id."""
        result_id = None
        if result is not None:
            target = result_space or self.space
            result_id = target.write(result, lease=lease, tags=tags)
        self.space.peer.complete_entry(self.space.name, self.entry_id, agent=self.space.agent)
        return result_id

    def renew(self, lease=None) -> None:
        millis = self.lease_millis if lease is None else duration_millis(lease)
        self.space.peer.renew_entry(self.space.name, self.entry_id, millis, agent=self.space.agent)


# ------------------------------------------------------ return conventions

@dataclasses.dataclass(frozen=True)
class Tagged:
    """A result written with tags (``Tagged.of`` in Java): ``Tagged(value, {"region": "eu"})``."""
    value: Any
    tags: dict

    @staticmethod
    def of(value, **tags) -> "Tagged":
        return Tagged(value, dict(tags))


@dataclasses.dataclass(frozen=True)
class Contribution:
    """This peer's contribution to a push-sum epoch, as a return value
    (``Contribution`` in Java): the binder starts the epoch on its aggregate."""
    epoch_id: str
    value: float
    mode: str = "avg"


@dataclasses.dataclass(frozen=True)
class Motion:
    """A vote opened as a return value (``Motion`` in Java): the binder proposes
    it in the vote space (``space``, or the binder's default vote space) once
    per proposal id, after the take is completed."""
    proposal_id: str
    question: str
    options: list
    quorum: int
    space: str | None = None
    lease: Any = "1h"

    def __post_init__(self):
        if len(self.options) < 2:
            raise ValueError("a motion needs at least two options")
        if self.quorum <= 0:
            raise ValueError("quorum must be positive")


_current_take: contextvars.ContextVar[Taken | None] = contextvars.ContextVar("agentspaces_take", default=None)


class TakeContext:
    """The take a worker method runs under, as a context variable: the
    binder sets it around the call, so a listener (a model call's lease
    renewal, say) finds it without a parameter."""

    @staticmethod
    def current() -> Taken | None:
        return _current_take.get()

    @staticmethod
    def bind(taken: Taken):
        return _current_take.set(taken)

    @staticmethod
    def unbind(token) -> None:
        _current_take.reset(token)


# ----------------------------------------------------------------- the space

class Space:
    """One space of the peer's group, by name: the layer-3 verbs over typed
    entries. ``agent`` (an ``AgentIdentity``) makes every write, take, and
    completion that agent's own attested record; ``agent_name`` names the
    peer-signed agent otherwise."""

    def __init__(self, peer, name: str, agent=None, agent_name: str = "python"):
        self.peer = peer
        self.name = name
        self.agent = agent
        self.agent_name = agent_name
        self.bid_function: Callable[[dict], float] | None = None
        self._watchers: dict[int, tuple[Template, Callable[[Event], None], set]] = {}
        self._next_key = 0
        self._lock = threading.Lock()
        self._seen: dict[str, str] = {}   # entry_id -> last delivered kind
        self._install()

    # the fold hooks: one dispatcher per peer, shared by every Space over it
    def _install(self) -> None:
        peer = self.peer
        if getattr(peer, "_agentspaces_spaces", None) is None:
            peer._agentspaces_spaces = []
            previous_state, previous_claim = peer.on_state, peer.on_claim

            def on_state(dto):
                if previous_state is not None:
                    previous_state(dto)
                for s in list(peer._agentspaces_spaces):
                    s._on_state(dto)

            def on_claim(entry_id, signed):
                if previous_claim is not None:
                    previous_claim(entry_id, signed)
                for s in list(peer._agentspaces_spaces):
                    s._on_claim(entry_id, signed)

            peer.on_state, peer.on_claim = on_state, on_claim

            def sweep():
                # EXPIRED and REAPPEARED are judged by the clock, not by a fold.
                while getattr(peer, "_running", True):
                    time.sleep(0.25)
                    for s in list(peer._agentspaces_spaces):
                        try:
                            s._sweep()
                        except Exception:
                            pass

            threading.Thread(target=sweep, name="agentspaces-sweep", daemon=True).start()
        peer._agentspaces_spaces.append(self)

    def _space_id(self) -> str:
        from .identity import space_id_local
        return space_id_local(f"{self.peer.group}/{self.name}")

    def _mine(self, dto: dict) -> bool:
        return (dto.get("record") or {}).get("spaceId") == self._space_id()

    # ---------------------------------------------------------------- verbs

    def write(self, value, lease="10m", tags: dict | None = None) -> str:
        return self.peer.write_entry(self.name, schema_of(value), to_payload(value),
                                     agent_name=self.agent_name, lease_millis=duration_millis(lease),
                                     agent=self.agent, tags=tags)

    def entries(self, template: Template, limit: int = 100, include_taken: bool = True) -> list[Entry]:
        """Every live entry matching the template, with its metadata."""
        now_ms = self.peer._now_ms()
        found = []
        for entry_id, dto in list(self.peer.states.items()):
            record = dto.get("record") or {}
            if record.get("type") != template.schema or not self._mine(dto) or dto.get("completed"):
                continue
            lease = record.get("lease") or {}
            if int(lease.get("expiresAtMillis", 0)) <= now_ms:
                continue
            payload = cbor.loads(record.get("payload") or b"\xf6")
            tags = record.get("tags") or {}
            if not template.matches(payload, tags):
                continue
            claim = self.peer._claim_of(entry_id)
            taken = bool(claim and int(claim.get("expiresAtMillis", 0)) > now_ms)
            if taken and not include_taken:
                continue
            found.append(Entry(entry_id, template.decode(payload), dict(tags), record.get("issuer"),
                               int(lease.get("expiresAtMillis", 0)), False, taken))
            if len(found) >= limit:
                break
        return found

    def read_all(self, template: Template, limit: int = 100) -> list:
        return [e.value for e in self.entries(template, limit)]

    def read(self, template: Template, timeout=None):
        """The first match, waiting up to ``timeout`` (pulling the space) for one."""
        deadline = time.time() + (duration_millis(timeout) / 1000 if timeout else 0)
        while True:
            found = self.entries(template, 1)
            if found:
                return found[0].value
            if time.time() >= deadline:
                return None
            self.peer.pull_space(self.name)
            time.sleep(0.2)

    def take(self, template: Template, lease="1m", timeout="15s") -> Taken | None:
        """An exclusive take of one matching entry under the space's strategy;
        the configured bid function prices it under AUCTION."""
        millis = duration_millis(lease)
        bid = self.bid_function or 0.0
        entry_id = self.peer.take_entry(self.name, template.schema, agent_name=self.agent_name,
                                        lease_millis=millis, timeout_seconds=duration_millis(timeout) / 1000,
                                        agent=self.agent,
                                        matches=lambda payload, tags: template.matches(payload, tags),
                                        bid=bid)
        if entry_id is None:
            return None
        record = self.peer.states[entry_id]["record"]
        return Taken(self, entry_id, template.decode(cbor.loads(record.get("payload") or b"\xf6")), millis)

    def complete(self, taken: Taken, result=None, lease="1h", tags: dict | None = None) -> str | None:
        return taken.complete(result, lease=lease, tags=tags)

    def watch(self, template: Template, callback: Callable[[Event], None]) -> Subscription:
        """Delivers WRITTEN, TAKEN, and COMPLETED events for matching entries
        as they fold, once per entry and kind, on the peer's reader thread:
        return promptly. (Lease expiry is not timed here; a reader's
        ``entries`` already excludes lapsed entries.)"""
        with self._lock:
            key = self._next_key
            self._next_key += 1
            self._watchers[key] = (template, callback, set())
        return Subscription(self, key)

    # ---------------------------------------------------------------- events

    def _deliver(self, dto: dict, kind: str, mark: str | None = None) -> None:
        record = dto.get("record") or {}
        entry_id = record.get("entryId")
        payload = cbor.loads(record.get("payload") or b"\xf6")
        tags = record.get("tags") or {}
        for template, callback, delivered in list(self._watchers.values()):
            if record.get("type") != template.schema or not template.matches(payload, tags):
                continue
            mark = (entry_id, mark or kind)
            if mark in delivered:
                continue
            delivered.add(mark)
            lease = record.get("lease") or {}
            entry = Entry(entry_id, template.decode(payload), dict(tags), record.get("issuer"),
                          int(lease.get("expiresAtMillis", 0)), kind == COMPLETED, kind == TAKEN)
            callback(Event(kind, entry))

    def _on_state(self, dto: dict) -> None:
        if not self._mine(dto):
            return
        if dto.get("completed"):
            self._deliver(dto, COMPLETED)
        else:
            self._deliver(dto, WRITTEN)

    def _on_claim(self, entry_id: str, signed: dict) -> None:
        dto = self.peer.states.get(entry_id)
        if dto is None or not self._mine(dto) or dto.get("completed"):
            return
        self._deliver(dto, TAKEN)

    def _sweep(self) -> None:
        """Delivers EXPIRED once per entry whose write lease lapsed while open,
        and REAPPEARED once per lapsed claim epoch on an entry still open."""
        if not self._watchers:
            return
        now = self.peer._now_ms()
        for entry_id, dto in list(self.peer.states.items()):
            if not self._mine(dto) or dto.get("completed"):
                continue
            record = dto.get("record") or {}
            lease = record.get("lease") or {}
            if int(lease.get("expiresAtMillis", 0)) <= now:
                self._deliver(dto, EXPIRED)
                continue
            claim = self.peer._claim_of(entry_id)
            if claim and int(claim.get("expiresAtMillis", 0)) <= now:
                self._deliver(dto, REAPPEARED, mark=f"{REAPPEARED}:{claim.get('epoch')}")
