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
"""The push-sum aggregate (SPEC §8.2, PushSumAggregate) from Python: AVG by
push-sum, SUM and COUNT by the gossiped roster, MIN and MAX by extremum
frames; estimates, settle rules, and estimate listeners.

    aggregate = Aggregate(pipes)
    aggregate.start("load", 12.5)
    aggregate.run()                              # a round a second on a thread
    value = aggregate.await_settled("load", Settle.after("3s", 0.01), timeout_seconds=20)

Rounds run every ``ROUND_PERIOD`` (one second, as Java's ``PushSumAggregate.ROUND_PERIOD``) on
the peer's time source, at deadlines that do not drift, and the thread sleeps while the aggregate
knows no epoch. A settle rule is a span counted in those rounds (SPEC v0.1.36 §8, §9.5):
``Settle.after("8s", t)`` and ``Settle.after(8, t)`` are the same rule.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .. import cbor, records, wire
from ..timesource import SYSTEM

LOG = logging.getLogger(__name__)

TYPE = "aspace:cap/aggregate"
MODES = ("avg", "sum", "count", "min", "max")
#: One gossip round, as Java's ``PushSumAggregate.ROUND_PERIOD`` (SPEC v0.1.36 §9.5). Before v0.1.36
#: this client ran a round every 300 ms by default, so ``Settle(ticks=40)`` settled after about
#: 12 s where Java's ``settle = "PT40S"`` takes 40 s.
ROUND_PERIOD_S = 1.0
#: How long the round loop sleeps, at most, while the aggregate knows no epoch: it wakes on an
#: epoch or a frame, and this backstop only notices a peer closed meanwhile.
IDLE_BACKSTOP_S = 30.0
#: Rounds of an unchanged estimate before an epoch stops being shared (Java's quiet: 30 s, 120 ticks of
#: 250 ms read as rounds of 1 s), until a share moves it; and before its state is forgotten (one hour).
QUIET_AFTER_ROUNDS = 30
EVICT_AFTER_ROUNDS = 3600
#: The relative change below which an estimate counts as unchanged between rounds (Java's 1e-3).
QUIET_TOLERANCE = 1e-3


def _span_seconds(span) -> float:
    """A span as seconds: a number of seconds, a ``timedelta``, or duration text (``"PT40S"``,
    ``"40s"``, ``"1500ms"``)."""
    if isinstance(span, (int, float)) and not isinstance(span, bool):
        return float(span)
    if hasattr(span, "total_seconds"):
        return float(span.total_seconds())
    from ..space import duration_millis
    return duration_millis(str(span)) / 1000


@dataclass(frozen=True)
class Settle:
    """When an estimate counts as settled: unchanged within a relative
    ``tolerance`` for ``ticks`` consecutive rounds; ``Settle.FIRST`` is the
    first estimate present. A round is ``ROUND_PERIOD_S`` (one second) on a
    running aggregate, so ``ticks`` reads as seconds there, as in Java."""
    ticks: int = 0
    tolerance: float = 0.0
    #: The span a rule made from a duration asks for, in seconds; a running aggregate counts it in the
    #: rounds it actually runs (``run(interval_seconds=...)``), so a span is time whatever the round.
    #: Not compared: ``after("8s", t) == after(8, t)``, as in Java.
    span_s: float | None = field(default=None, compare=False)

    def __post_init__(self):
        if self.ticks < 0 or self.tolerance < 0:
            raise ValueError("ticks and tolerance are not negative")

    @staticmethod
    def after(ticks, tolerance: float) -> "Settle":
        """A rule of ``ticks`` rounds, or, given a span (duration text such as ``"PT40S"`` or ``"8s"``,
        or a ``timedelta``), the rounds of ``ROUND_PERIOD_S`` that span takes, rounded up, as Java's
        ``Settle.after(Duration, tolerance)``: ``after(8, t)`` and ``after("8s", t)`` are the same rule."""
        if isinstance(ticks, int) and not isinstance(ticks, bool):
            return Settle(ticks, tolerance)
        seconds = _span_seconds(ticks)
        if seconds < 0:
            raise ValueError(f"a settle span is not negative: {ticks!r}")
        return Settle(int(math.ceil(seconds / ROUND_PERIOD_S - 1e-9)), tolerance, seconds)

    def rounds_at(self, interval_seconds: float) -> int:
        """The rounds this rule's streak needs at ``interval_seconds`` a round: its span in those rounds,
        rounded up, or its count when it was given as one."""
        if self.span_s is None or interval_seconds <= 0:
            return self.ticks
        return int(math.ceil(self.span_s / interval_seconds - 1e-9))

    def stable(self, previous: float | None, current: float) -> bool:
        if previous is None:
            return False
        scale = max(abs(previous), abs(current), 1e-12)
        return abs(current - previous) <= self.tolerance * scale


Settle.FIRST = Settle(0, 0.0)


@dataclass(frozen=True)
class Estimate:
    epoch_id: str
    mode: str
    value: float
    ticks: int


class Aggregate:
    """One node's share of every epoch it joined or heard about."""

    def __init__(self, pipes, clock=None, advertise: bool = True):
        self.pipes = pipes
        self.clock = clock or time.time
        self._changed = threading.Condition()  # an epoch started or a frame heard: the round loop wakes
        self._interval = ROUND_PERIOD_S  # the round a settle span is counted in (``run``)
        self.rounds = 0
        self.self_token = wire.aggregate_roster_token(pipes.peer.identity.peer_id)
        self._received: dict[str, int] = {}             # epoch -> frames heard, the settle evidence
        self._epochs: dict[str, list[float]] = {}      # epoch -> [value, weight]
        self._rosters: dict[str, set[int]] = {}
        self._extrema: dict[str, list] = {}            # epoch -> [max?, value]
        self._declared: dict[str, str] = {}
        self._ticks: dict[str, int] = {}
        # Quiet lines (Java's ``Quiet``): key -> [the value or fingerprint last seen to change, rounds unchanged];
        # keys "e:<epoch>", "x:<epoch>" and "r:<epoch>" for an estimate, an extremum and a roster.
        self._quiet: dict[str, list] = {}
        self.quiet_after_rounds = QUIET_AFTER_ROUNDS
        self.evict_after_rounds = EVICT_AFTER_ROUNDS
        self._watches: list[dict] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False
        self.exchanged = False
        pipes.on_capability(TYPE, self._on_frame)
        if advertise and hasattr(pipes.peer, "publish_ad"):
            self.advertise()

    # ------------------------------------------------------------ participants

    def describe(self) -> dict:
        """This node's CapabilityAdvertisement for the aggregate, in Java field
        order (CapabilityAdvertisement: id, issuer, group, issued, ttl,
        capabilityType, version, binding, parameters, costHints)."""
        from ..identity import instant_iso
        peer = self.pipes.peer
        now_ms = peer._now_ms()
        return {"id": f"aspace://{peer.group}/cap/aggregate/{peer.identity.peer_id}",
                "issuer": peer.identity.peer_id, "group": peer.group,
                "issued": instant_iso(now_ms - now_ms % 1000), "ttl": "PT15M",
                "capabilityType": TYPE, "version": "0.1", "binding": "pipe",
                "parameters": cbor.canonical_map({"modes": "sum,avg,count,min,max"}), "costHints": {}}

    def advertise(self) -> None:
        """Publishes the advertisement on the ads stream, so other members'
        participant rules admit this node (re-publish within the TTL)."""
        self.pipes.peer.publish_ad("CapabilityAdvertisement", self.describe())

    def participants(self) -> list[str]:
        """The reachable members that advertise the aggregate. A share pushed
        to a member without one is mass lost (the receiver never mixes it
        back), so a share goes only to a member whose advertisement is live."""
        peer = self.pipes.peer
        now = peer._now_ms()
        advertised = {e["issuer"] for e in peer.ads.values()
                      if e["type"] == "CapabilityAdvertisement" and e["expires"] > now
                      and e["ad"].get("capabilityType") == TYPE}
        return [m for m in self.pipes.members() if m in advertised]

    # ------------------------------------------------------------- joining

    def start(self, epoch_id: str, value: float, mode: str = "avg") -> None:
        """Joins an epoch with this node's value under ``mode``."""
        mode = mode.lower()
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        with self._lock:
            self._declared[epoch_id] = mode
            if mode in ("avg", "sum"):
                e = self._epochs.setdefault(epoch_id, [0.0, 0.0])
                e[0] += float(value)
                e[1] += 1.0
            if mode in ("sum", "count"):
                self._rosters.setdefault(epoch_id, set()).add(self.self_token)
            if mode in ("min", "max"):
                self._merge_extremum(epoch_id, mode == "max", float(value))
        self._wake()

    def epochs(self) -> set[str]:
        """The epochs this node joined or heard about."""
        with self._lock:
            return self._known_epochs()

    # ---------------------------------------------------------------- tick

    def tick(self) -> None:
        """One protocol round: halve each push-sum mass and push the other
        half to one sampled participant; push each roster and extremum whole.
        A node with no participant holds its mass and, with nobody to exchange
        with at all, judges its settle rules on its own ticks."""
        self.exchanged = True
        participants = self.participants()
        targets = [self.pipes._random.choice(participants)] if participants else []
        with self._lock:
            # Each state is judged quiet or not every round, shared or not (Java's step): an estimate
            # unchanged for QUIET_AFTER_ROUNDS is silent until a share moves it, and forgotten after
            # EVICT_AFTER_ROUNDS. A silent state is neither halved nor sent.
            active_epochs = [epoch_id for epoch_id, e in list(self._epochs.items())
                             if self._active("e:" + epoch_id, e[0] / e[1] if e[1] else math.nan,
                                             lambda k=epoch_id: self._forget(k))]
            active_extrema = [epoch_id for epoch_id, ex in list(self._extrema.items())
                              if not math.isnan(ex[1]) and self._active(
                                  "x:" + epoch_id, float(ex[1]), lambda k=epoch_id: self._extrema.pop(k, None))]
            active_rosters = [epoch_id for epoch_id, members in list(self._rosters.items())
                              if self._active("r:" + epoch_id, frozenset(members),
                                              lambda k=epoch_id: self._rosters.pop(k, None))]
        if not targets:
            # Mass held is mass kept: halve only when a participant takes the other half.
            self._evaluate_watches(alone=not self.pipes.members())
            return
        with self._lock:
            frames = []
            for epoch_id in active_epochs:
                e = self._epochs.get(epoch_id)
                if e is None:
                    continue
                e[0] /= 2
                e[1] /= 2
                frames.append(wire.aggregate_frame(share={"epochId": epoch_id, "value": float(e[0]),
                                                          "weight": float(e[1])}))
            for epoch_id in active_extrema:
                ex = self._extrema.get(epoch_id)
                if ex is not None and not math.isnan(ex[1]):
                    frames.append(wire.aggregate_frame(extremum={"epochId": epoch_id, "max": ex[0],
                                                                 "value": float(ex[1])}))
            for epoch_id in active_rosters:
                members = self._rosters.get(epoch_id)
                if members is not None:
                    frames.append(wire.aggregate_frame(roster={"epochId": epoch_id, "members": sorted(members)}))
        for to in targets:
            for frame in frames:
                self.pipes.send(to, TYPE, cbor.dumps(frame))
        self._evaluate_watches(alone=False)

    def _active(self, key: str, value, forget) -> bool:
        """Records this round's value of one state and returns whether it is still shared (Java's
        ``activeValue``): unchanged within QUIET_TOLERANCE (a number) or equal (a fingerprint) for
        ``quiet_after_rounds`` rounds is quiet; for ``evict_after_rounds`` it is forgotten. Under the lock."""
        line = self._quiet.get(key)
        if line is None:
            self._quiet[key] = [value, 0]
            return True
        last = line[0]
        if isinstance(value, float):
            if math.isnan(value):
                same = isinstance(last, float) and math.isnan(last)
            else:
                same = (isinstance(last, float) and not math.isnan(last)
                        and abs(value - last) <= QUIET_TOLERANCE * max(abs(value), abs(last), 1e-12))
        else:
            same = last == value
        if same:
            line[1] += 1
        else:
            line[0], line[1] = value, 0
        if line[1] >= self.evict_after_rounds:
            self._quiet.pop(key, None)
            forget()
            return False
        return line[1] < self.quiet_after_rounds

    def _forget(self, epoch_id: str) -> None:
        """Forgets an epoch's push-sum state after the retention (Java's ``forget``). Under the lock."""
        self._epochs.pop(epoch_id, None)
        self._declared.pop(epoch_id, None)
        self._received.pop(epoch_id, None)
        self._ticks.pop(epoch_id, None)

    def run(self, interval_seconds: float = ROUND_PERIOD_S) -> None:
        """Runs a round every ``interval_seconds`` (one second by default, Java's ``ROUND_PERIOD``) on
        a daemon thread until ``close`` or the peer's close, at deadlines on the peer's time source
        that do not drift with the round's own cost. While the aggregate knows no epoch and no watch
        waits it sleeps until an epoch is started or a frame arrives, rather than waking each round.
        A peer between links is not closed: the rounds wait for the link and go on."""
        if self._thread is not None:
            return
        self._running = True
        self._interval = interval_seconds
        peer = self.pipes.peer
        source = getattr(peer, "time", SYSTEM)

        def loop():
            due = source.monotonic()
            while self._running and not getattr(peer, "_closed", False):
                token = source.token()
                now = source.monotonic()
                if now >= due:
                    if getattr(peer, "connected", True) and (self._knows_any() or self._watches):
                        self.rounds += 1
                        try:
                            self.tick()
                        except Exception:  # noqa: BLE001 - one failed round never ends the rounds
                            LOG.exception("an aggregate round failed")
                    due = max(due + interval_seconds, now)  # a late round does not stack up the missed ones
                idle = not self._knows_any() and not self._watches
                with self._changed:
                    if not self._running:
                        break
                    # idle: until an epoch or a frame, with a backstop that notices the peer's close
                    source.wait(self._changed, IDLE_BACKSTOP_S if idle else max(0.0, due - source.monotonic()), token)
                if idle:
                    due = source.monotonic()

        self._thread = threading.Thread(target=loop, name="aggregate-rounds", daemon=True)
        self._thread.start()

    def _wake(self) -> None:
        with self._changed:
            self._changed.notify_all()

    def _knows_any(self) -> bool:
        with self._lock:
            return bool(self._epochs or self._rosters or self._extrema or self._declared)

    def close(self) -> None:
        self._running = False
        self._wake()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    # ------------------------------------------------------------ estimate

    def estimate(self, epoch_id: str) -> float | None:
        """The current estimate under the declared mode (AVG for epochs only
        heard about), or None before any exchange."""
        with self._lock:
            mode = self._declared.get(epoch_id, "avg")
            if mode == "avg":
                return self._mean(epoch_id)
            if mode == "sum":
                mean = self._mean(epoch_id)
                n = len(self._rosters.get(epoch_id, ()))
                return None if mean is None or n == 0 else mean * n
            if mode == "count":
                n = len(self._rosters.get(epoch_id, ()))
                return None if n == 0 else float(n)
            ex = self._extrema.get(epoch_id)
            return None if ex is None or math.isnan(ex[1]) else ex[1]

    def _mean(self, epoch_id: str) -> float | None:
        e = self._epochs.get(epoch_id)
        if e is None or e[1] == 0.0 or not self.exchanged:
            return None
        return e[0] / e[1]

    def tick_alone(self) -> None:
        """A tick for a node that cannot exchange: marks the node exchanged so
        its own value is the estimate (Java's tick does the same)."""
        self.exchanged = True

    def await_settled(self, epoch_id: str, settle: Settle = Settle.FIRST, timeout_seconds: float = 30.0) -> float | None:
        """Blocks until the epoch's estimate settles under the rule, on the
        protocol tick; the value, or None at the timeout."""
        done = threading.Event()
        box: list[float] = []
        handle = self.on_estimate(lambda e: e == epoch_id, settle, lambda est: (box.append(est.value), done.set()))
        try:
            getattr(self.pipes.peer, "time", SYSTEM).wait_event(done, timeout_seconds)  # on the peer's time source
            return box[0] if box else None
        finally:
            handle()

    def on_estimate(self, epochs: Callable[[str], bool], settle: Settle, listener: Callable[[Estimate], None]):
        """Calls ``listener`` once per matching epoch when its estimate has
        settled under the rule, evaluated on the tick. Returns a closer."""
        watch = {"epochs": epochs, "settle": settle, "listener": listener, "tracks": {}}
        self._watches.append(watch)
        self._wake()
        return lambda: self._watches.remove(watch) if watch in self._watches else None

    def _known_epochs(self) -> set[str]:
        return set(self._epochs) | set(self._rosters) | set(self._extrema) | set(self._declared)

    def _evaluate_watches(self, alone: bool = False) -> None:
        """A round counts toward a settle rule once this node has heard a frame for
        the epoch at all, as Java's ``evaluateWatches`` counts it since R1 (2026-11-14):
        a round this node took part in. Counting only rounds that brought a new frame
        starved the streak once the epoch went quiet, and a 0.7.0 Java member stops
        sharing an epoch whose estimate has not moved for 30 s, so a longer rule here
        never fired. A node never heard from says nothing about the fleet and counts
        nothing; a node with nobody to exchange with judges every round, its own value
        being the only estimate there is."""
        for epoch_id in self._known_epochs():
            ticks = self._ticks[epoch_id] = self._ticks.get(epoch_id, 0) + 1
            now = self.estimate(epoch_id)
            receipts = self._received.get(epoch_id, 0)
            for watch in list(self._watches):
                if not watch["epochs"](epoch_id):
                    continue
                track = watch["tracks"].setdefault(epoch_id, {"last": None, "stable": 0, "fired": False, "seen": 0})
                if track["fired"] or now is None:
                    continue
                if receipts == 0 and not alone:
                    continue  # never heard: the streak neither grows nor resets
                track["seen"] = receipts
                settle: Settle = watch["settle"]
                track["stable"] = track["stable"] + 1 if settle.stable(track["last"], now) else 0
                track["last"] = now
                if track["stable"] >= settle.rounds_at(self._interval):
                    track["fired"] = True
                    estimate = Estimate(epoch_id, self._declared.get(epoch_id, "avg"), now, ticks)
                    threading.Thread(target=watch["listener"], args=(estimate,), daemon=True).start()

    # -------------------------------------------------------------- frames

    def _merge_extremum(self, epoch_id: str, is_max: bool, value: float) -> None:
        ex = self._extrema.setdefault(epoch_id, [is_max, math.nan])
        if math.isnan(ex[1]) or (value > ex[1] if ex[0] else value < ex[1]):
            ex[1] = value

    def _on_frame(self, sender: str, payload: bytes) -> None:
        # HLC round seven, 2026-11-08: a frame decodes as Java's fromWire reads it, under its
        # annex I schema and the canonical-bytes rule, or it is dropped unheard
        frame = records.decode(payload, "PushSumAggregate.Frame")
        if frame is None:
            return
        self.exchanged = True
        share, extremum, roster = frame.get("share"), frame.get("extremum"), frame.get("roster")
        heard = next((part["epochId"] for part in (share, extremum, roster, frame.get("histogram"))
                      if isinstance(part, dict) and isinstance(part.get("epochId"), str)), None)
        with self._lock:
            if heard is not None:
                self._received[heard] = self._received.get(heard, 0) + 1
            if isinstance(share, dict) and isinstance(share.get("epochId"), str):
                value, weight = share["value"], share["weight"]
                if math.isfinite(value) and math.isfinite(weight) and weight >= 0.0:
                    e = self._epochs.setdefault(share["epochId"], [0.0, 0.0])
                    e[0] += value
                    e[1] += weight
            elif isinstance(extremum, dict) and isinstance(extremum.get("epochId"), str):
                self._merge_extremum(extremum["epochId"], extremum["max"], extremum["value"])
            elif isinstance(roster, dict) and isinstance(roster.get("epochId"), str) and roster["members"] is not None:
                self._rosters.setdefault(roster["epochId"], set()).update(roster["members"])
        self._wake()  # a frame for an epoch the round loop did not know wakes it
