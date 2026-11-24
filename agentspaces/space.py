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
from decimal import Decimal
import threading
from typing import Any, Callable

from . import cbor
from .peer import lease_of, present
from .timesource import SYSTEM

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
    """The wire payload of an entry value: a dataclass's fields, or a dict. A
    dataclass may carry ``__agentspaces_wire_names__ = {"from_": "from"}`` for
    a wire key Python cannot spell as a field name, and
    ``__agentspaces_omit_none__`` for the fields left out while None, as Java's
    ``@JsonInclude(NON_NULL)`` leaves them (the version 2 fields of the open A2UI
    records)."""
    if isinstance(value, dict):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        renames = getattr(type(value), "__agentspaces_wire_names__", {})
        omit = getattr(type(value), "__agentspaces_omit_none__", ())
        return {renames.get(k, k): v for k, v in dataclasses.asdict(value).items() if not (k in omit and v is None)}
    raise TypeError(f"cannot encode {type(value).__name__} as an entry payload")


def from_payload(cls, payload: dict):
    """An entry value from its wire payload: the dataclass built from the
    fields it declares (extra wire fields are ignored), or the dict when the
    class is a plain schema string."""
    if isinstance(cls, str) or cls is dict:
        return payload
    if dataclasses.is_dataclass(cls):
        names = {f.name for f in dataclasses.fields(cls)}
        back = {wire: name for name, wire in getattr(cls, "__agentspaces_wire_names__", {}).items()}
        return cls(**{back.get(k, k): v for k, v in payload.items() if back.get(k, k) in names})
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


_FILTER_OPS = ("!=", "<=", ">=", "=", "<", ">", " in ")  # as they appear in a clause
_NUMBER = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")


def _filter_form(value) -> str:
    """The string form a value compares under: Python's str, except that a whole float prints
    as Java prints it, so ``3.0`` and ``3`` compare numerically either way."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def filter_compare(form: str, literal: str) -> int:
    """Numeric when both sides are decimal numbers, else the strings' order (Java FieldFilter.compare)."""
    f, l = form.strip(), literal.strip()
    if _NUMBER.match(f) and _NUMBER.match(l):
        a, b = Decimal(f), Decimal(l)
        return -1 if a < b else 1 if a > b else 0
    return -1 if form < literal else 1 if form > literal else 0


def parse_filter(clause: str):
    """One clause of the portable field filter grammar (SPEC §7.2; Java ``FieldFilter``, TypeScript
    ``parseFilter``): ``field op literal`` with ``=``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, or
    ``field in a,b,c``. Returns ``(field, predicate)``. A None value matches ``!=`` alone."""
    text = clause.strip()
    # The earliest operator in the clause is the operator; at a tie the longest (so "<=" beats
    # "<"), and "!=x" is malformed rather than the field "!".
    best, best_op = -1, ""
    for op in _FILTER_OPS:
        at = text.find(op)
        if at >= 0 and (best < 0 or at < best or (at == best and len(op) > len(best_op))):
            best, best_op = at, op
    if best <= 0:
        raise ValueError(f"malformed field filter '{clause}'; use \"field=value\", \"field!=value\", "
                         "\"field<value\", \"field<=value\", \"field>value\", \"field>=value\", or \"field in a,b,c\"")
    field, literal, op = text[:best].strip(), text[best + len(best_op):].strip(), best_op.strip()
    if op == "in":
        elements = [e.strip() for e in literal.split(",")]
        return field, (lambda value, elements=elements: value is not None
                       and any(filter_compare(_filter_form(value), e) == 0 for e in elements))

    def test(value, op=op, literal=literal):
        if value is None:
            return op == "!="
        c = filter_compare(_filter_form(value), literal)
        return {"=": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]
    return field, test


class Template:
    """A query: the entry type (an ``@entry`` class or a schema string), field
    conditions, and tag conditions. A plain value means equality; a callable
    is a predicate; ``eq``, ``ne``, ``gt``, ``gte``, ``lt``, ``lte``, ``in_``,
    ``contains``, ``is_null``, ``not_null`` are the Java matchers. ``filters``
    are clauses of the portable grammar (``"priority>=3"``, ``"region in eu,us"``),
    judged as Java and TypeScript judge them (JS-V-03)."""

    def __init__(self, type, where: dict | None = None, tags: dict | None = None,
                 filters: list | tuple = ()):
        self.type = type
        self.schema = schema_of(type)
        self.where = {k: _matcher(v) for k, v in (where or {}).items()}
        for clause in filters:
            field, test = parse_filter(clause)
            previous = self.where.get(field)
            self.where[field] = (test if previous is None
                                 else (lambda v, p=previous, t=test: p(v) and t(v)))
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
    """A watch handle; ``close()`` stops the deliveries. A leased subscription
    (``Space.notify``, JS-V-01) closes itself when its lease lapses on the
    peer's clock unless ``renew`` extends it; the binder renews at half-lease
    on the agent's behalf, the shape of the Java ``Subscription``. ``reason``
    is ``"closed"`` or ``"lapsed"`` once closed."""

    def __init__(self, space: "Space", key: int):
        self._space = space
        self._key = key
        self._lease_millis: int | None = None
        self._expires_ms: int | None = None
        self._closed = False
        self.reason: str | None = None
        self._on_close: list[Callable[[str], None]] = []

    @property
    def open(self) -> bool:
        """Whether the subscription is still delivering."""
        return not self._closed

    def renew(self, lease=None) -> None:
        """Extends the lease (the same length again when none is given) to at least that
        long from now, never shorter than it already runs (SPEC §7.2, v0.1.35: a subscription's
        lease reads "extend" as an entry's does); close the subscription to stop it sooner. A
        lapsed subscription stays closed, and a watch without a lease never lapses."""
        if self._closed:
            return
        millis = self._lease_millis if lease is None else duration_millis(lease)
        if millis is None:
            return
        self._lease_millis = millis
        with self._space._lock:  # two renewals at once must not let the shorter one write last
            now = self._space.peer._now_ms()
            self._expires_ms = now + millis if self._expires_ms is None else max(self._expires_ms, now + millis)

    def lapsed(self, now_ms: int) -> bool:
        return self._expires_ms is not None and self._expires_ms <= now_ms

    def _shift(self, step_ms: int) -> None:
        """Moves the lease by a step of the wall clock the peer judged (SPEC v0.1.36 §9.5): a
        subscription's lease is a local period, so a suspend or an NTP step neither lapses it at
        once nor keeps it past its length."""
        with self._space._lock:
            if self._expires_ms is not None:
                self._expires_ms += int(step_ms)

    def on_close(self, listener: Callable[[str], None]) -> None:
        """Calls ``listener(reason)`` once, when the subscription closes."""
        self._on_close.append(listener)

    def close(self, reason: str = "closed") -> None:
        if self._closed:
            return
        self._closed = True
        self.reason = reason
        self._space._watchers.pop(self._key, None)
        for listener in self._on_close:
            try:
                listener(reason)
            except Exception:
                pass

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
        # The claim this take won, so completing checks that exact claim still holds (SPEC §7.4).
        # The holder is the take's own, never read back from the lattice: a rival's better claim
        # can fold between the take's win and this line, and reading it here would make the
        # completion check the rival's claim and pass (the adversarial review, 2026-11-15). The
        # epoch is the lattice's only while the claim there is still the take's.
        self.holder = space.agent.agent_id if space.agent is not None else space.peer.identity.agent(space.agent_name)
        claim = space.peer._claim_of(entry_id) or {}
        self.epoch = int(claim["epoch"]) if claim.get("holder") == self.holder and "epoch" in claim else None
        # The binder's end (the core's I-05 fix, DRIFT-FROM-PHASE6 item 11): a binder running a handler
        # under this take sets whether it would still renew it (its agent still bound), so a handler or a
        # library renewing from inside it (a model stream's keepalive) cannot hold the entry past the
        # unbind. None: no binder, always renewable.
        self._renewable: Callable[[], bool] | None = None
        #: Set when a wake or a wall step found the take's wall-time lease lapsed (owner decision C05,
        #: 2026-11-23): another worker may hold the entry now, so the take renews no more and its
        #: completion is refused as late, whatever the wall clock says after (a step back included).
        self.late = False

    def recheck(self) -> bool:
        """Judges the hold again on the wall clock, as a wake or a wall step asks (owner decision C05):
        a take whose lease lapsed, or that a better claim displaced, is marked ``late``. Returns
        whether the take still holds."""
        if self.late:
            return False
        try:
            self.space.peer.require_held(self.entry_id, agent=self.space.agent, holder=self.holder,
                                         epoch=self.epoch)
        except ValueError:
            self.late = True
        return not self.late

    def complete(self, result=None, lease="1h", tags: dict | None = None, result_space: "Space | None" = None) -> str | None:
        """Completes the take, writing ``result`` first (into the take space,
        or ``result_space``) so a caller correlating on it sees it with the
        completion. Returns the result's entry id. Raises ValueError, writing
        nothing, when the take no longer holds the entry: its lease lapsed, or a
        better claim that reached this replica after the settle window displaced
        it, or the entry completed meanwhile (SPEC §7.4, the settle guarantee), or a wake found
        its lease lapsed (``late``)."""
        if self.late:
            raise ValueError(f"{self.entry_id} is not held here: its take lease lapsed while this peer slept")
        self.space.peer.require_held(self.entry_id, agent=self.space.agent, holder=self.holder, epoch=self.epoch)
        if not present(self.space.peer.states.get(self.entry_id) or {}):
            raise ValueError(f"{self.entry_id} is not held here: it is completed or withdrawn")
        result_id = None
        if result is not None:
            target = result_space or self.space
            result_id = target.write(result, lease=lease, tags=tags)
        self.space.peer.complete_entry(self.space.name, self.entry_id, agent=self.space.agent,
                                       holder=self.holder, epoch=self.epoch)
        return result_id

    def renew(self, lease=None) -> bool:
        """Renews the take lease, not the entry's write lease, as Java's ``TakenEntry.renew``
        (SPEC §7.2 and §7.4, v0.1.35; matrix P19): the hold runs at least ``lease`` from now
        (the take's lease again when none is given) and never shorter. Raises ValueError when
        the take no longer holds the entry; returns whether the hold moved. To give the entry
        back sooner, let the take lapse; nothing here shortens it.

        Under a binder, renews only while the binder would (its agent still bound), as Java's
        ``TakeContext.renew``: past the unbind, or once a wake found the lease lapsed (``late``), it
        renews nothing and returns False, so the entry lapses to another taker."""
        if self.late or (self._renewable is not None and not self._renewable()):
            return False
        millis = self.lease_millis if lease is None else duration_millis(lease)
        return self.space.peer.renew_take(self.space.name, self.entry_id, millis, agent=self.space.agent,
                                          holder=self.holder, epoch=self.epoch)


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


# ----------------------------------------------------------------- the sweep

#: The longest the sweep waits with nothing due, so a deadline no change announced is still judged
#: (the backstop of the core's node loop).
SWEEP_BACKSTOP_S = 30.0
#: While a WRITTEN waits for its payload, the sweep looks again this often: a payload that lands on
#: the content swarm announces nothing to the spaces.
AWAITING_RECHECK_S = 1.0
#: After a run a change asked for, the sweep runs again no sooner than this: a pull that folds
#: thousands of states wakes it at most this often, the old tick's pace, never once per fold.
#: A deadline is never held back by it.
CHANGE_GAP_S = 0.25


class _Sweeper:
    """The sweep of the spaces over one peer, as due work (SPEC v0.1.36 §9.5, EL-P-08): one thread
    that runs the tombstone collection (SPEC §7.3) and each space's lapse events (EXPIRED,
    REAPPEARED, a leased subscription's lapse, a WRITTEN that waited for its payload), then sleeps
    on the peer's time source until the earliest of those deadlines or a change (a fold, a claim,
    a payload, a new watch, a wall step), never on a fixed tick. Before v0.1.36 it woke every
    250 ms. It runs until the peer is closed, through any reconnect gap, and the process watchdog
    starts it again if it ever dies."""

    def __init__(self, peer):
        self.peer = peer
        self._cond = threading.Condition()
        self._asked = False
        self._thread: threading.Thread | None = None
        self.runs = 0
        self.restarts = 0

    def wake(self) -> None:
        """A change: the next run comes at once and judges its deadlines again."""
        with self._cond:
            self._asked = True
            self._cond.notify_all()

    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="agentspaces-sweep", daemon=True)
        self._thread.start()

    def ensure_alive(self) -> None:
        if not self.alive() and not getattr(self.peer, "_closed", False):
            self.restarts += 1
            self.start()

    def _closed(self) -> bool:
        return bool(getattr(self.peer, "_closed", False))

    def _loop(self) -> None:
        source = getattr(self.peer, "time", SYSTEM)
        while not self._closed():
            with self._cond:
                self._asked = False
            ran = source.monotonic()
            self.run_once()
            token = source.token()
            wait = self.next_wait()
            armed = source.monotonic() + wait  # the deadline this wait is for
            if source.token() != token:
                continue  # a virtual clock moved while the deadline was judged: judge it again
            with self._cond:
                # A wait returns on a change, at the deadline, or when a virtual clock moves; only the
                # first two end it, so moving the clock wakes nothing that is not due.
                while not self._asked and not self._closed():
                    token = source.token()
                    remaining = armed - source.monotonic()
                    if remaining <= 0:
                        break
                    source.wait(self._cond, remaining, token)
                changed = self._asked
            if changed:
                # coalesces a burst of folds; the deadline armed above is not held back
                pause = min(ran + CHANGE_GAP_S, armed) - source.monotonic()
                if pause > 0 and not self._closed():
                    source.sleep(pause)

    def run_once(self) -> None:
        """One sweep: the collection, then every space's lapses. A fault in one never stops the rest."""
        self.runs += 1
        peer = self.peer
        try:
            peer._collect_if_due()  # the tombstone collection of SPEC §7.3 rides on the sweep
        except Exception:  # noqa: BLE001
            pass
        for space in list(getattr(peer, "_agentspaces_spaces", ())):
            try:
                space._sweep()
            except Exception:  # noqa: BLE001
                pass

    def next_wait(self) -> float:
        """Seconds until the earliest deadline: a space's lapse, the next collection, the payload
        recheck, or the backstop."""
        peer = self.peer
        now_ms = peer._now_ms()
        due = [SWEEP_BACKSTOP_S]
        for space in list(getattr(peer, "_agentspaces_spaces", ())):
            try:
                if space._awaiting:
                    due.append(AWAITING_RECHECK_S)
                at = space._next_due(now_ms)
            except Exception:  # noqa: BLE001
                at = None
            if at is not None:
                due.append(at)
        try:
            collection = peer.next_collection_ms(now_ms) if hasattr(peer, "next_collection_ms") else None
        except Exception:  # noqa: BLE001
            collection = None
        if collection is not None:
            due.append(max(0.0, (collection - now_ms) / 1000))
        return max(0.0, min(due))


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
        self._watchers: dict[int, tuple[Template, Callable[[Event], None], set, Subscription]] = {}
        self._next_key = 0
        self._lock = threading.Lock()
        self._seen: dict[str, str] = {}   # entry_id -> last delivered kind
        # Entries that were present and unexpired when their state merged here but whose block or
        # artifact had not landed: their WRITTEN waits for the payload, and the sweep raises it
        # then if the entry is still live, or COMPLETED alone if it completed meanwhile (SPEC
        # §7.2, v0.1.35, completed on arrival; Java's payloadArrived).
        self._awaiting: dict[str, bool] = {}
        self._install()

    # the fold hooks: one dispatcher per peer, shared by every Space over it
    def _install(self) -> None:
        peer = self.peer
        if getattr(peer, "_agentspaces_spaces", None) is None:
            peer._agentspaces_spaces = []
            previous_state, previous_claim = peer.on_state, peer.on_claim
            previous_withdrawn = peer.on_withdrawn

            def on_state(dto):
                if previous_state is not None:
                    previous_state(dto)
                for s in list(peer._agentspaces_spaces):
                    s._on_state(dto)

            def on_withdrawn(dto):
                if previous_withdrawn is not None:
                    previous_withdrawn(dto)
                for s in list(peer._agentspaces_spaces):
                    s._on_withdrawn(dto)

            def on_claim(entry_id, signed):
                if previous_claim is not None:
                    previous_claim(entry_id, signed)
                for s in list(peer._agentspaces_spaces):
                    s._on_claim(entry_id, signed)

            peer.on_state, peer.on_claim, peer.on_withdrawn = on_state, on_claim, on_withdrawn

            sweeper = _Sweeper(peer)
            peer._sweeper = sweeper
            listeners = getattr(peer, "_wall_step_listeners", None)
            if listeners is not None:
                listeners.append(lambda step: [sub._shift(step) for sp in list(peer._agentspaces_spaces)
                                               for *_, sub in list(sp._watchers.values())])
            sweeper.start()
        peer._agentspaces_spaces.append(self)
        sweeper = getattr(peer, "_sweeper", None)
        if sweeper is not None:
            sweeper.wake()

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
            if record.get("type") != template.schema or not self._mine(dto) or not present(dto):
                continue  # completed, or withdrawn by a cancel (core cancel events, 2026-11-09)
            lease = lease_of(dto)
            if int(lease.get("expiresAtMillis", 0)) <= now_ms:
                continue
            readable, payload = self.peer.value_of(dto)
            if not readable:
                continue  # a block or artifact still on its way, or a payload outside the encoding
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

    def read(self, template: Template, timeout=None, settle="600ms"):
        """The first match, waiting up to ``timeout`` for one: the space is pulled
        at most once per ``settle`` window and the wait wakes on a fold (JS-V-02)."""
        settle_seconds = duration_millis(settle) / 1000
        source = getattr(self.peer, "time", SYSTEM)
        deadline = source.monotonic() + (duration_millis(timeout) / 1000 if timeout else 0)
        while True:
            seen = self.peer.fold_count
            found = self.entries(template, 1)
            if found:
                return found[0].value
            remaining = deadline - source.monotonic()
            if remaining <= 0:
                return None
            self.peer.pull_space_paced(self.name, settle_seconds)
            self.peer.await_fold(min(settle_seconds, remaining), since=seen)

    def take(self, template: Template, lease="1m", timeout="15s", through=None) -> Taken | None:
        """An exclusive take of one matching entry under the space's strategy;
        the configured bid function prices it under AUCTION. With ``through``
        (an ``OrderedLog``, JS-V-05) the claim goes through the fleet's ordered
        log instead, and the take is held once the log committed it. Without
        ``through`` the lease must outlast the take's settle window and
        follow-up wait (over 900 ms), or ValueError (``Peer.take_entry``)."""
        millis = duration_millis(lease)
        timeout_seconds = duration_millis(timeout) / 1000
        if through is not None:
            entry_id = through.take(self.name, template.schema, agent_name=self.agent_name,
                                    lease_millis=millis, timeout_seconds=timeout_seconds, agent=self.agent,
                                    matches=lambda payload, tags: template.matches(payload, tags))
        else:
            bid = self.bid_function or 0.0
            entry_id = self.peer.take_entry(self.name, template.schema, agent_name=self.agent_name,
                                            lease_millis=millis, timeout_seconds=timeout_seconds,
                                            agent=self.agent,
                                            matches=lambda payload, tags: template.matches(payload, tags),
                                            bid=bid)
        if entry_id is None:
            return None
        dto = self.peer.states[entry_id]
        return Taken(self, entry_id, template.decode(cbor.loads(self.peer.payload_of(dto) or b"\xf6")), millis)

    def complete(self, taken: Taken, result=None, lease="1h", tags: dict | None = None) -> str | None:
        return taken.complete(result, lease=lease, tags=tags)

    def watch(self, template: Template, callback: Callable[[Event], None]) -> Subscription:
        """Delivers WRITTEN, TAKEN, and COMPLETED events for matching entries
        as they fold, once per entry and kind, on the peer's reader thread:
        return promptly. (Lease expiry is not timed here; a reader's
        ``entries`` already excludes lapsed entries.) A cancel that folds
        here delivers EXPIRED, as the sweep delivers it for a lapse (core
        cancel events, 2026-11-09)."""
        with self._lock:
            key = self._next_key
            self._next_key += 1
            subscription = Subscription(self, key)
            self._watchers[key] = (template, callback, set(), subscription)
        self._wake_sweep()
        return subscription

    def _wake_sweep(self) -> None:
        sweeper = getattr(self.peer, "_sweeper", None)
        if sweeper is not None:
            sweeper.wake()

    def notify(self, template: Template, callback: Callable[[Event], None], lease="1h") -> Subscription:
        """The leased push subscription of the Java space (JS-V-01): events reach
        ``callback`` as they fold, and the subscription lapses after ``lease``
        on the peer's clock unless renewed. A watch that outlives its owner never
        leaks: the lease ends it."""
        subscription = self.watch(template, callback)
        subscription.renew(lease)
        self._wake_sweep()  # its lapse is a deadline now
        return subscription

    # ---------------------------------------------------------------- events

    def _deliver(self, dto: dict, kind: str, mark: str | None = None, fetch: bool = True) -> bool:
        """Delivers ``kind`` for an entry to every matching watch once; returns whether the
        entry's value was readable here, which an event needs. ``fetch`` False reads only what
        the replica holds and starts no transfer."""
        record = dto.get("record") or {}
        entry_id = record.get("entryId")
        readable, payload = self.peer.value_of(dto, fetch)
        if not readable:
            return False  # a referenced payload not here yet, or one outside the encoding
        tags = record.get("tags") or {}
        self._judge_wall_step()
        now_ms = self.peer._now_ms()
        # one mark for every watch: a watch's mark must not depend on the watches before it
        # (core cancel events, 2026-11-09)
        seen = (entry_id, mark or kind)
        for template, callback, delivered, subscription in list(self._watchers.values()):
            if subscription.lapsed(now_ms):
                subscription.close("lapsed")  # judged here as well as on the sweep: nothing after the lease
                continue
            if record.get("type") != template.schema or not template.matches(payload, tags):
                continue
            with self._lock:
                # the reader thread and the sweep thread both deliver EXPIRED, for a cancel and for
                # a lapse: one judges the mark (core cancel events, 2026-11-09)
                if seen in delivered:
                    continue
                delivered.add(seen)
            lease = lease_of(dto)
            entry = Entry(entry_id, template.decode(payload), dict(tags), record.get("issuer"),
                          int(lease.get("expiresAtMillis", 0)), kind == COMPLETED, kind == TAKEN)
            callback(Event(kind, entry))
        return True

    def _live(self, dto: dict) -> bool:
        """Present and unexpired: an entry a reader here could see."""
        return present(dto) and int(lease_of(dto).get("expiresAtMillis", 0)) > self.peer._now_ms()

    def _written(self, dto: dict) -> bool:
        """WRITTEN for an entry a reader could see, then TAKEN when a claim on it is already in
        force (a claim merges before its entry's state in a pull), as Java's writtenThenTaken.
        Returns whether the value was readable."""
        if not self._deliver(dto, WRITTEN):
            return False
        entry_id = (dto.get("record") or {}).get("entryId")
        claim = self.peer._claim_of(entry_id)
        if claim and int(claim.get("expiresAtMillis", 0)) > self.peer._now_ms():
            self._deliver(dto, TAKEN)
        return True

    def _on_state(self, dto: dict) -> None:
        """The events of a merged state (SPEC §7.2, v0.1.35). A completed entry raises COMPLETED
        from what the replica holds alone, never fetching for it, and an entry first learned
        completed raises COMPLETED and never WRITTEN, since no reader here saw it live (completed
        on arrival, decision 21). WRITTEN is for an entry present and unexpired when it merges:
        one withdrawn or lapsed when learned is history, not news. When its payload is still on
        its way, WRITTEN waits for it (``_awaiting``)."""
        if not self._mine(dto):
            return
        entry_id = (dto.get("record") or {}).get("entryId")
        if dto.get("completed"):
            if self._deliver(dto, COMPLETED, fetch=False):
                self._awaiting.pop(entry_id, None)
            # Without the value here, an entry whose WRITTEN waits for its payload hears COMPLETED
            # when the payload lands; one first learned completed raises nothing.
        elif self._live(dto):
            if not self._written(dto) and self._watchers:
                self._awaiting[entry_id] = True

    def _on_withdrawn(self, dto: dict) -> None:
        """EXPIRED for a cancel that withdrew an entry present here, the kind Java's ReplicatedSpace and
        LocalSpace raise for a cancel, once per entry with the sweep's (core cancel events, 2026-11-09)."""
        if self._mine(dto):
            self._deliver(dto, EXPIRED)

    def _on_claim(self, entry_id: str, signed: dict) -> None:
        dto = self.peer.states.get(entry_id)
        if dto is None or not self._mine(dto) or not present(dto):
            return
        self._deliver(dto, TAKEN)

    def _payloads_arrived(self) -> None:
        """The events a merge deferred until a block or artifact landed, as Java's payloadArrived:
        the state is read again now, so a live entry raises WRITTEN (and the TAKEN of a claim in
        force), one that completed meanwhile raises COMPLETED alone, and one withdrawn or lapsed
        meanwhile raises nothing, since no reader here saw it live. Each entry is decided once."""
        for entry_id in list(self._awaiting):
            dto = self.peer.states.get(entry_id)
            if dto is None or not (dto.get("completed") or self._live(dto)):
                self._awaiting.pop(entry_id, None)
                continue
            readable, _ = self.peer.value_of(dto)
            if not readable:
                continue
            self._awaiting.pop(entry_id, None)
            if dto.get("completed"):
                self._deliver(dto, COMPLETED)
            else:
                self._written(dto)

    def _judge_wall_step(self) -> None:
        """A step of the wall clock is judged before any lease is: the subscriptions move with it."""
        judge = getattr(self.peer, "_judge_wall_step", None)
        if judge is not None:
            judge()

    def _next_due(self, now_ms: int) -> float | None:
        """Seconds until this space's next lapse the sweep raises an event for: an entry's write lease,
        a claim's, a leased subscription's; 0 for a WRITTEN waiting on its payload (looked at again
        on the sweep's recheck); None when nothing here is due."""
        if not self._watchers:
            return None
        due = []
        for _, _, _, subscription in list(self._watchers.values()):
            if subscription._expires_ms is not None:
                due.append(subscription._expires_ms)
        for entry_id, dto in list(self.peer.states.items()):
            if not self._mine(dto) or not present(dto):
                continue
            expiry = int(lease_of(dto).get("expiresAtMillis", 0))
            if expiry > now_ms:
                due.append(expiry)
            claim = self.peer._claim_of(entry_id)
            if claim and int(claim.get("expiresAtMillis", 0)) > now_ms:
                due.append(int(claim["expiresAtMillis"]))
        if not due:
            return None
        return max(0.0, (min(due) - now_ms) / 1000)

    def _sweep(self) -> None:
        """Closes every leased subscription whose lease lapsed (JS-V-01), then
        delivers EXPIRED once per entry whose write lease lapsed while open,
        and REAPPEARED once per lapsed claim epoch on an entry still open."""
        if not self._watchers:
            self._awaiting.clear()
            return
        self._judge_wall_step()
        now = self.peer._now_ms()
        for _, _, _, subscription in list(self._watchers.values()):
            if subscription.lapsed(now):
                subscription.close("lapsed")
        if not self._watchers:
            self._awaiting.clear()
            return
        self._payloads_arrived()
        for entry_id, dto in list(self.peer.states.items()):
            if not self._mine(dto) or not present(dto):
                continue  # a cancel already delivered a withdrawn entry's EXPIRED (core cancel events, 2026-11-09)
            record = dto.get("record") or {}
            lease = lease_of(dto)
            if int(lease.get("expiresAtMillis", 0)) <= now:
                self._deliver(dto, EXPIRED)
                continue
            claim = self.peer._claim_of(entry_id)
            if claim and int(claim.get("expiresAtMillis", 0)) <= now:
                self._deliver(dto, REAPPEARED, mark=f"{REAPPEARED}:{claim.get('epoch')}")
