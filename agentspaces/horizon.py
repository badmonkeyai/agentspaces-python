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

"""The renewal rule of SPEC §7.2 and the collection horizons of SPEC §7.3 (v0.1.35), as
pure functions of a state, a clock reading and the longest lease a replica observed, the
shape of Java's ``SpaceStateCrdt`` (srad/replication-by-entry.md RE-H-02 to RE-H-04, owner
decision 22). The peer decides which rule applies from its view (``Peer.horizon_rule``);
nothing here reads a view or a clock.

- A renewal sets the lease to ``max(current, now + extension)``: it never shortens.
- A completed entry keeps ``2 x maxLease`` past its lease expiry under both rules.
- A withdrawn entry keeps ``max(2 x maxLease, MAX_DRIFT)`` under the legacy rule and
  ``max(5 min, MAX_DRIFT)`` under the per-entry rule: the drift floor means no withdrawal is
  collected before ``L + MAX_DRIFT``, so a replica whose clock trails by up to the ceiling,
  and that never heard of the withdrawal, cannot be handed a copy it would show live.
- An entry both withdrawn and completed keeps ``max(2 x maxLease, MAX_DRIFT)`` under both.
- A present entry whose lease lapsed keeps ``min(2 x maxLease, 5 min)``, the lapse horizon."""

from . import wire

LEGACY = "legacy"
PER_ENTRY = "per-entry"

#: The grace a lapsed entry keeps at most, and the per-entry horizon's base (SPEC §7.3).
LAPSED_GRACE_MILLIS = 5 * 60 * 1000
#: The clock drift ceiling of SPEC §11, the floor under every withdrawal's horizon.
WITHDRAWN_DRIFT_FLOOR_MILLIS = wire.MAX_DRIFT_MILLIS
#: The ceiling on the lease that feeds the horizon, as Java's MAX_TRACKED_LEASE_MILLIS: one
#: member's century-long lease cannot stop collection fleet-wide.
MAX_TRACKED_LEASE_MILLIS = 24 * 60 * 60 * 1000

_LONG_MAX = (1 << 63) - 1


def renewed_expiry(current_expiry_millis: int, now_millis: int, extension_millis: int) -> int:
    """The expiry a renewal sets (SPEC §7.2): at least the extension from now, never less than
    the lease already had. The sum saturates at a Java long, as Java's does."""
    return max(int(current_expiry_millis), min(int(now_millis) + int(extension_millis), _LONG_MAX))


def lapsed_keep_millis(max_lease_millis: int) -> int:
    """How long a present entry is kept past its lapse: ``min(2 x maxLease, 5 min)``."""
    return min(2 * max(0, int(max_lease_millis)), LAPSED_GRACE_MILLIS)


def keep_millis(kind: str, max_lease_millis: int, rule: str = LEGACY) -> int:
    """How long a state of ``kind`` (``completed``, ``withdrawn_completed``, ``withdrawn`` or
    ``lapsed``) is kept past its own lease expiry under ``rule``."""
    twice = 2 * max(0, int(max_lease_millis))
    if kind == "completed":
        return twice
    if kind == "withdrawn_completed":
        return max(twice, WITHDRAWN_DRIFT_FLOOR_MILLIS)
    if kind == "withdrawn":
        keep = LAPSED_GRACE_MILLIS if rule == PER_ENTRY else twice
        return max(keep, WITHDRAWN_DRIFT_FLOOR_MILLIS)
    return lapsed_keep_millis(max_lease_millis)


def _covered(dto: dict) -> bool:
    """Whether every add dot of a state is covered by a remove: a withdrawal."""
    removed = {(d.get("replica"), d.get("counter")) for d in dto.get("removes") or [] if isinstance(d, dict)}
    return all((d.get("replica"), d.get("counter")) in removed for d in dto.get("adds") or [] if isinstance(d, dict))


def kind_of(dto: dict) -> str:
    """The horizon class of a state: ``completed``, ``withdrawn_completed``, ``withdrawn`` or
    ``present`` (whose lapse horizon applies once its lease lapses)."""
    if dto.get("completed"):
        return "withdrawn_completed" if _covered(dto) else "completed"
    if not dto.get("adds") or _covered(dto):
        return "withdrawn"
    return "present"


def lease_expiry(dto: dict) -> int:
    """The expiry the state's lease register carries (the record's lease before any renewal)."""
    lease = dto.get("leaseValue") or (dto.get("record") or {}).get("lease") or {}
    return int(lease.get("expiresAtMillis", 0))


def collection_horizon(dto: dict, max_lease_millis: int, rule: str = LEGACY) -> int:
    """The instant from which the state is collectable under ``rule``: its lease expiry plus
    what it keeps (``collectable`` is exactly ``now >= collection_horizon``)."""
    kind = kind_of(dto)
    return min(lease_expiry(dto) + keep_millis("lapsed" if kind == "present" else kind, max_lease_millis, rule),
               _LONG_MAX)


def collectable(dto: dict, now_millis: int, max_lease_millis: int, rule: str = LEGACY) -> bool:
    """Whether a state is a collectable tombstone under ``rule`` (SPEC §7.3): no longer live,
    and its horizon passed. A present entry is never collectable before its lease lapses."""
    expiry = lease_expiry(dto)
    if kind_of(dto) == "present" and expiry > now_millis:
        return False
    return collection_horizon(dto, max_lease_millis, rule) <= now_millis
