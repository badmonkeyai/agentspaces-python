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
"""The TTL floor (SPEC v0.1.36 §9.5, *TTLs*; Java's ``TtlFloor``, srad/agentspaces-event-loop.md
EL-E-03 and EL-E-04): "TTLs need to be generous; any TTL under 60 s is probably too fast, unless
someone really knows what they are doing."

A short TTL makes a noisy group, since every renewal is a frame: a TTL something renews should be
about 1.5 times the cycle that renews it. The binder checks the TTLs and leases it is configured
with against the floor:

* a value equal to its registered default passes silently (the default's reason is on record);
* a key with an expert override passes, and the override is logged once with its reason;
* any other value under 60 s logs a WARNING naming the key, or, under ``strict``, raises
  :class:`TtlFloorError`.

Keys read as the Java binder writes them: ``binder.<AgentClass>.<method>.<member>``, and
``binder.card-ttl`` for the AgentCard's TTL."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

LOG = logging.getLogger(__name__)

#: Principle 8's presumption: a TTL, lease or expiry under this is too fast unless someone says why.
FLOOR_MILLIS = 60_000

WARNED, REFUSED, OVERRIDDEN = "WARNED", "REFUSED", "OVERRIDDEN"


class TtlFloorError(ValueError):
    """A configured TTL under the floor, refused under a strict floor; the message names the key."""


@dataclass(frozen=True)
class Finding:
    key: str
    millis: int
    verdict: str
    reason: str = ""


class TtlFloor:
    """The check. ``TtlFloor()`` warns and never refuses; ``TtlFloor(strict=True)`` refuses.
    ``overrides`` maps a key to the reason it may be short; a reason is required."""

    def __init__(self, strict: bool = False, overrides: dict[str, str] | None = None):
        overrides = dict(overrides or {})
        for key, reason in overrides.items():
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"the expert override of {key} names no reason (principle 8: the reason is the point)")
        self.strict = strict
        self.overrides = overrides
        self.findings: list[Finding] = []
        self._told: set[str] = set()
        self._lock = threading.Lock()

    def check(self, key: str, millis: int | None, default_millis: int | None = None,
              override_reason: str | None = None) -> None:
        """Checks one configured value; None and the registered default pass."""
        if millis is None or millis == default_millis or millis >= FLOOR_MILLIS:
            return
        reason = override_reason or self.overrides.get(key)
        with self._lock:
            first = key not in self._told
            self._told.add(key)
        if reason:
            if first:
                self.findings.append(Finding(key, int(millis), OVERRIDDEN, reason))
                LOG.info("TTL %s of %d ms is under the 60 s floor by an expert override: %s", key, millis, reason)
            return
        if self.strict:
            if first:
                self.findings.append(Finding(key, int(millis), REFUSED))
            raise TtlFloorError(f"{key} is {millis} ms, under the 60 s TTL floor: a TTL something renews should "
                                f"be about 1.5 times the cycle that renews it; name an expert override with "
                                f"its reason to keep it")
        if first:
            self.findings.append(Finding(key, int(millis), WARNED))
            LOG.warning("TTL %s of %d ms is under the 60 s floor (principle 8): every renewal is a frame, so a "
                        "short TTL makes a noisy group; keep it about 1.5 times the cycle that renews it", key, millis)
