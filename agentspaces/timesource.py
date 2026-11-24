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
"""One time source for a peer and everything over it (SPEC v0.1.36 §9.5; the Python half of
srad/agentspaces-event-loop.md EL-C-04 and EL-P-08).

Two clocks, kept apart on purpose:

* **wall time** (``wall_ms``) stamps what another peer reads: HLC stamps, leases, expiries,
  advertisement issue instants. It may step.
* **monotonic time** (``monotonic``) judges every local period: how long to wait for the next
  deadline, a settle window, a reconnect pause, a subscription's lease, a forgotten join key.
  It never steps, so a wall-clock step neither drops a view nor keeps a silent member.

Every wait a peer makes goes through ``sleep`` and ``wait``, so a test drives the same code on
:class:`VirtualTime`: ``advance`` moves both clocks and wakes every waiter at once, and
``step_wall`` moves the wall clock alone, as an NTP correction or a suspend does (``monotonic``
on Linux and macOS does not count a suspend).

    vt = VirtualTime()
    peer = Peer(identity, group, time_source=vt)
    ...
    vt.advance(30)          # the sweep, the aggregate rounds and the watchdog see 30 s pass

A wait may return early (a notify, or the advance of a virtual clock): callers loop on their
own deadline, read from ``monotonic``.
"""

from __future__ import annotations

import threading
import time


class TimeSource:
    """The clock and the waits of a peer. The default, :class:`SystemTime`, is the process clock."""

    def wall_ms(self) -> int:
        """Milliseconds since the epoch: stamps, leases and expiries another peer reads."""
        raise NotImplementedError

    def monotonic(self) -> float:
        """Seconds on a clock that never steps: every local period is judged on it."""
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        """Waits ``seconds`` of this source's monotonic time."""
        raise NotImplementedError

    def token(self) -> int:
        """A snapshot a caller reads before it judges a deadline and hands to ``wait``: a virtual clock
        that moved since then makes the wait return at once, so no advance is missed. 0 on the
        process clock."""
        return 0

    def wait(self, condition: threading.Condition, seconds: float | None, token: int | None = None) -> bool:
        """Waits on ``condition`` (held by the caller) for a notify or ``seconds``, whichever comes
        first; None waits for a notify alone. May return early; returns whether it was notified."""
        raise NotImplementedError

    def wait_event(self, event: threading.Event, seconds: float | None) -> bool:
        """Waits for ``event`` or ``seconds``; returns whether the event is set."""
        raise NotImplementedError


class SystemTime(TimeSource):
    """The process clock: ``time.time``, ``time.monotonic``, and the threading waits as they are."""

    def wall_ms(self) -> int:
        return int(time.time() * 1000)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def wait(self, condition: threading.Condition, seconds: float | None, token: int | None = None) -> bool:
        if seconds is not None and seconds <= 0:
            return False
        return condition.wait(seconds)

    def wait_event(self, event: threading.Event, seconds: float | None) -> bool:
        return event.wait(None if seconds is None else max(0.0, seconds))


#: The source a peer takes when none is given.
SYSTEM = SystemTime()


class VirtualTime(TimeSource):
    """A clock a test moves by hand (Java's ``VirtualTime``). Nothing waits out real time: a
    thread waiting on this source wakes when ``advance`` passes its deadline, or when the
    condition it waits on is notified. ``real_guard`` bounds one wait in real seconds, so a
    waiter re-checks its deadline even if nobody notifies it; a test never relies on it.

    ``wall_ms`` starts at ``start_wall_ms`` (2026-01-01T00:00:00Z by default) and ``monotonic``
    at ``1000.0``; both are read under a lock."""

    def __init__(self, start_wall_ms: int = 1_767_225_600_000, start_monotonic: float = 1000.0,
                 real_guard: float = 5.0):
        self._lock = threading.Condition()
        self._wall_ms = int(start_wall_ms)
        self._mono = float(start_monotonic)
        self._waiting: dict[int, threading.Condition] = {}  # one line per wait in progress
        self._serial = 0
        self.real_guard = real_guard
        self.advances = 0

    # the clocks

    def wall_ms(self) -> int:
        with self._lock:
            return self._wall_ms

    def monotonic(self) -> float:
        with self._lock:
            return self._mono

    def advance(self, seconds: float) -> None:
        """Moves both clocks by ``seconds`` and wakes every waiter, which re-checks its deadline."""
        if seconds < 0:
            raise ValueError("virtual time moves forward")
        with self._lock:
            self._mono += seconds
            self._wall_ms += int(round(seconds * 1000))
            self.advances += 1
            waiting = list(self._waiting.values())
            self._lock.notify_all()
        for condition in waiting:
            with condition:
                condition.notify_all()

    def step_wall(self, millis: int) -> None:
        """Steps the wall clock alone, forward or back, as NTP or a suspend does; wakes every waiter."""
        with self._lock:
            self._wall_ms += int(millis)
            self.advances += 1
            waiting = list(self._waiting.values())
            self._lock.notify_all()
        for condition in waiting:
            with condition:
                condition.notify_all()

    # the waits

    def sleep(self, seconds: float) -> None:
        with self._lock:
            deadline = self._mono + max(0.0, seconds)
            while self._mono < deadline:
                self._lock.wait(self.real_guard)

    def token(self) -> int:
        with self._lock:
            return self.advances

    def wait(self, condition: threading.Condition, seconds: float | None, token: int | None = None) -> bool:
        if seconds is not None and seconds <= 0:
            return False
        with self._lock:
            if token is not None and token != self.advances:
                return False  # the clock moved since the caller judged its deadline: judge again
            self._serial += 1
            key = self._serial
            self._waiting[key] = condition
        try:
            return condition.wait(self.real_guard)
        finally:
            with self._lock:
                self._waiting.pop(key, None)

    def wait_event(self, event: threading.Event, seconds: float | None) -> bool:
        with self._lock:
            deadline = None if seconds is None else self._mono + max(0.0, seconds)
        while not event.is_set():
            with self._lock:
                if deadline is not None and self._mono >= deadline:
                    return False
                self._lock.wait(min(self.real_guard, 0.02))
        return True


def wait_until(source: TimeSource, condition: threading.Condition, predicate, seconds: float | None) -> bool:
    """Waits on ``condition`` (held by the caller) until ``predicate()`` holds or ``seconds`` of the
    source's monotonic time pass; returns the predicate's last value. The loop every fold-driven
    wait uses, so it runs the same on the process clock and on :class:`VirtualTime`."""
    deadline = None if seconds is None else source.monotonic() + max(0.0, seconds)
    while True:
        token = source.token()
        if predicate():
            return True
        if deadline is not None:
            remaining = deadline - source.monotonic()
            if remaining <= 0:
                return bool(predicate())
        else:
            remaining = None
        source.wait(condition, remaining, token)
