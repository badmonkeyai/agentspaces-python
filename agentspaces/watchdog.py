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
"""The process watchdog of the Python peer (the Python half of srad/agentspaces-event-loop.md §3.9).

One daemon thread per process, started with the first connected peer and ended when no watched
peer is left. Every ``PERIOD_S`` (2 s, re-armed from the end of each check, never at a fixed rate)
it asks each live peer for one check (``Peer._watch``): a reader that died while its peer runs is
started again; a frame that has held the reader past the wedge bound is named; a sweep thread
that died is started again; and a step of the wall clock past the monotonic clock is judged, a
suspend's included, after which the peer introduces itself again. A check that comes back more than
30 s past its period with no wall step means the whole process was frozen (SIGSTOP, a long pause), and
each peer treats it as the same wake (owner decision 3 of 2026-11-23). It is redundant by design: the
reader and the sweep are built to work without it, and it exists for the day one of them does not.

It does no protocol work and takes no lock a frame handler can hold (WD-1); the resume's frames go
out on a thread of their own. A peer holds no reference to it, and it holds each peer weakly.
A test calls ``check()`` on a ``Watchdog`` of its own rather than waiting out the period."""

from __future__ import annotations

import logging
import threading
import time
import weakref

LOG = logging.getLogger(__name__)

#: The watchdog's period (decision 4 of the core's SRAD: 2 s).
PERIOD_S = 2.0


class Watchdog:
    """Checks the peers it watches. ``start()`` runs the checks on a daemon thread every ``period``
    seconds of real time; ``check()`` runs one at once."""

    def __init__(self, period: float = PERIOD_S, clock=time.monotonic):
        self.period = period
        # The clock a check's lateness is read on (the process's monotonic clock; a test's virtual one),
        # and when the last check ended on it (None before the first, and again when the thread restarts).
        self._clock = clock
        self._last_end: float | None = None
        #: Checks more than LATE_WAKE_S late (the process was frozen; owner decision 3 of 2026-11-23).
        self.late_checks = 0
        self._peers: "weakref.WeakSet" = weakref.WeakSet()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.checks = 0
        self.restarts = 0  # the watchdog's own thread, started again after it died (WD-6)

    def watch(self, peer) -> None:
        with self._lock:
            self._peers.add(peer)

    def watched(self) -> list:
        with self._lock:
            return [p for p in list(self._peers) if not getattr(p, "_closed", False)]

    def check(self) -> None:
        """One check of every watched peer; a peer's failure to check never stops the others.

        A check that begins more than LATE_WAKE_S past its period, read on this watchdog's monotonic
        clock from the end of the check before, tells each peer how late it was: every thread of the
        process was frozen that long (SIGSTOP, a long pause), so each peer treats it as a wake unless
        a wall step already did (owner decision 3 of 2026-11-23). Late checks are counted."""
        from .peer import LATE_WAKE_S
        self.checks += 1
        now = self._clock()
        late = 0.0 if self._last_end is None else now - self._last_end - self.period
        if late > LATE_WAKE_S:
            self.late_checks += 1
        else:
            late = 0.0
        for peer in self.watched():
            try:
                peer._watch(late)
            except Exception:  # noqa: BLE001 - the watchdog outlives any one peer's fault
                LOG.exception("the watchdog's check of a peer failed")
        self._last_end = self._clock()

    def ensure_running(self) -> None:
        """Starts the thread when it is not running (first use, or after it died)."""
        with self._lock:
            thread = self._thread
            if thread is not None and thread.is_alive():
                return
            if thread is not None:
                self.restarts += 1
            self._stop.clear()
            self._last_end = None  # an idle gap with nobody to watch is no freeze
            self._thread = threading.Thread(target=self._run, name="agentspaces-watchdog", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            # Re-armed from the end of each check: a slow check delays the next, never stacks them.
            if self._stop.wait(self.period):
                return
            self.check()
            if not self.watched():
                with self._lock:
                    if not list(self._peers) or all(getattr(p, "_closed", False) for p in list(self._peers)):
                        self._thread = None
                        return  # nobody left to watch: the next connected peer starts it again


#: The process's watchdog.
PROCESS = Watchdog()


def watch(peer) -> None:
    """Puts a connected peer under the process watchdog and makes sure it runs."""
    PROCESS.watch(peer)
    PROCESS.ensure_running()
