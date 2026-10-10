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
    aggregate.run(interval_seconds=0.3)          # ticks on a thread
    value = aggregate.await_settled("load", Settle.after(3, 0.01), timeout_seconds=20)
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .. import cbor, wire

TYPE = "aspace:cap/aggregate"
MODES = ("avg", "sum", "count", "min", "max")


@dataclass(frozen=True)
class Settle:
    """When an estimate counts as settled: unchanged within a relative
    ``tolerance`` for ``ticks`` consecutive ticks; ``Settle.FIRST`` is the
    first estimate present."""
    ticks: int = 0
    tolerance: float = 0.0

    def __post_init__(self):
        if self.ticks < 0 or self.tolerance < 0:
            raise ValueError("ticks and tolerance are not negative")

    @staticmethod
    def after(ticks: int, tolerance: float) -> "Settle":
        return Settle(ticks, tolerance)

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
        self.self_token = wire.aggregate_roster_token(pipes.peer.identity.peer_id)
        self._received: dict[str, int] = {}             # epoch -> frames heard, the settle evidence
        self._epochs: dict[str, list[float]] = {}      # epoch -> [value, weight]
        self._rosters: dict[str, set[int]] = {}
        self._extrema: dict[str, list] = {}            # epoch -> [max?, value]
        self._declared: dict[str, str] = {}
        self._ticks: dict[str, int] = {}
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
        if not targets:
            # Mass held is mass kept: halve only when a participant takes the other half.
            self._evaluate_watches(alone=not self.pipes.members())
            return
        with self._lock:
            frames = []
            for epoch_id, e in self._epochs.items():
                e[0] /= 2
                e[1] /= 2
                frames.append(wire.aggregate_frame(share={"epochId": epoch_id, "value": float(e[0]),
                                                          "weight": float(e[1])}))
            for epoch_id, ex in self._extrema.items():
                if not math.isnan(ex[1]):
                    frames.append(wire.aggregate_frame(extremum={"epochId": epoch_id, "max": ex[0],
                                                                 "value": float(ex[1])}))
            for epoch_id, members in self._rosters.items():
                frames.append(wire.aggregate_frame(roster={"epochId": epoch_id, "members": sorted(members)}))
        for to in targets:
            for frame in frames:
                self.pipes.send(to, TYPE, cbor.dumps(frame))
        self._evaluate_watches(alone=False)

    def run(self, interval_seconds: float = 0.3) -> None:
        """Ticks on a daemon thread until ``close``."""
        if self._thread is not None:
            return
        self._running = True

        def loop():
            while self._running and self.pipes.peer.connected:
                self.tick()
                time.sleep(interval_seconds)

        self._thread = threading.Thread(target=loop, name="aggregate-tick", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._running = False
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
            done.wait(timeout_seconds)
            return box[0] if box else None
        finally:
            handle()

    def on_estimate(self, epochs: Callable[[str], bool], settle: Settle, listener: Callable[[Estimate], None]):
        """Calls ``listener`` once per matching epoch when its estimate has
        settled under the rule, evaluated on the tick. Returns a closer."""
        watch = {"epochs": epochs, "settle": settle, "listener": listener, "tracks": {}}
        self._watches.append(watch)
        return lambda: self._watches.remove(watch) if watch in self._watches else None

    def _known_epochs(self) -> set[str]:
        return set(self._epochs) | set(self._rosters) | set(self._extrema) | set(self._declared)

    def _evaluate_watches(self, alone: bool = False) -> None:
        """A tick counts toward a settle rule only when this node heard a frame
        for the epoch since the track last judged it: halving keeps the local
        ratio, so a node nobody pushes to is stable by construction and says
        nothing about the fleet. A node with nobody to exchange with judges
        every tick, its own value being the only estimate there is."""
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
                if receipts <= track["seen"] and not alone:
                    continue  # no new evidence: the streak neither grows nor resets
                track["seen"] = receipts
                settle: Settle = watch["settle"]
                track["stable"] = track["stable"] + 1 if settle.stable(track["last"], now) else 0
                track["last"] = now
                if track["stable"] >= settle.ticks:
                    track["fired"] = True
                    estimate = Estimate(epoch_id, self._declared.get(epoch_id, "avg"), now, ticks)
                    threading.Thread(target=watch["listener"], args=(estimate,), daemon=True).start()

    # -------------------------------------------------------------- frames

    def _merge_extremum(self, epoch_id: str, is_max: bool, value: float) -> None:
        ex = self._extrema.setdefault(epoch_id, [is_max, math.nan])
        if math.isnan(ex[1]) or (value > ex[1] if ex[0] else value < ex[1]):
            ex[1] = value

    def _on_frame(self, sender: str, payload: bytes) -> None:
        try:
            frame = cbor.loads(payload)
        except ValueError:
            return
        if not isinstance(frame, dict):
            return
        self.exchanged = True
        share, extremum, roster = frame.get("share"), frame.get("extremum"), frame.get("roster")
        heard = next((part["epochId"] for part in (share, extremum, roster, frame.get("histogram"))
                      if isinstance(part, dict) and isinstance(part.get("epochId"), str)), None)
        with self._lock:
            if heard is not None:
                self._received[heard] = self._received.get(heard, 0) + 1
            if isinstance(share, dict) and isinstance(share.get("epochId"), str):
                value, weight = _number(share.get("value")), _number(share.get("weight"))
                if math.isfinite(value) and math.isfinite(weight) and weight >= 0.0:
                    e = self._epochs.setdefault(share["epochId"], [0.0, 0.0])
                    e[0] += value
                    e[1] += weight
            elif isinstance(extremum, dict) and isinstance(extremum.get("epochId"), str):
                self._merge_extremum(extremum["epochId"], bool(extremum.get("max")), _number(extremum.get("value")))
            elif isinstance(roster, dict) and isinstance(roster.get("epochId"), str):
                members = self._rosters.setdefault(roster["epochId"], set())
                for m in roster.get("members") or []:
                    members.add(int(m))


def _number(value) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return math.nan
