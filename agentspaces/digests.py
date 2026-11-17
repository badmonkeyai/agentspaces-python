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

"""The text digest of a replicated space (SPEC §5.3, TECH-SPEC §7.5), as Java's
``ReplicatedSpace`` writes it: one line per entry and per claim, ``e:<entryId>=<stateHash>``
and ``c:<entryId>=<claimHash>``, in the order of Java's ``TreeMap``, then one
``a:<line>`` per state or claim the replica acknowledges.

This client reads no DIGEST, but since v0.1.35 it sends one: a budgeted pull of a whole
space (SPEC annex I.6, *The budget*) draws the partner's newest states first, and the asker
continues with its own text digest under the same budget, since the empty digest again
would draw the same states again (srad/replication-by-entry.md RE-L-03). A partner answers
the states and claims whose lines the digest lacks, so the hashes here must equal Java's
bit for bit; the golden vectors ``space_state_hash``, ``space_claim_hash`` and
``java_double_strings`` pin them, as they pin the TypeScript ``serving.ts``."""

from decimal import Decimal

_INT_MASK = 0xFFFFFFFF


def _int32(value: int) -> int:
    """``value`` wrapped to a Java int."""
    value &= _INT_MASK
    return value - (1 << 32) if value & 0x80000000 else value


def java_string_hash(text: str) -> int:
    """``String.hashCode()``: UTF-16 code units, 31-chained, wrapped to an int."""
    units = text.encode("utf-16-be", "surrogatepass")
    h = 0
    for i in range(0, len(units), 2):
        h = (31 * h + ((units[i] << 8) | units[i + 1])) & _INT_MASK
    return _int32(h)


def java_long_hash(value: int) -> int:
    """``Long.hashCode(v)``: ``(int) (v ^ (v >>> 32))``."""
    v = value & 0xFFFFFFFFFFFFFFFF
    return _int32(v ^ (v >> 32))


def _record_hash(components) -> int:
    """A record's hash as ``java.lang.runtime.ObjectMethods`` derives it: 31-chained from 0."""
    h = 0
    for c in components:
        h = (31 * h + c) & _INT_MASK
    return _int32(h)


def _objects_hash(components) -> int:
    """``Objects.hash(...)``: 31-chained from 1."""
    h = 1
    for c in components:
        h = (31 * h + c) & _INT_MASK
    return _int32(h)


def dot_set_hash(dots) -> int:
    """A ``Set<Dot>``'s hash: the sum of its members' record hashes, a dot counted once by
    replica and counter, as Java's set holds it."""
    seen = set()
    h = 0
    for dot in dots or []:
        if not isinstance(dot, dict):
            continue
        key = (str(dot.get("replica", "")), int(dot.get("counter", 0)))
        if key in seen:
            continue
        seen.add(key)
        h = (h + _record_hash((java_string_hash(key[0]), java_long_hash(key[1])))) & _INT_MASK
    return _int32(h)


def hlc_hash(encoded: str) -> int:
    """An ``HlcTimestamp(long physical, int logical, String node)`` record's hash, from its text."""
    physical, logical, node = str(encoded).split(":", 2)
    return _record_hash((java_long_hash(int(physical) if physical.isdigit() else 0),
                         _int32(int(logical) if logical.isdigit() else 0), java_string_hash(node)))


def state_hash(dto: dict) -> str:
    """``SpaceStateCrdt.stateHash``: ``Integer.toHexString(Objects.hash(adds, removes,
    lease.stamp, completed))`` over the state a replica holds."""
    code = _objects_hash((dot_set_hash(dto.get("adds")), dot_set_hash(dto.get("removes")),
                          hlc_hash(dto.get("leaseStamp") or "0:0:"),
                          1231 if dto.get("completed") else 1237))
    return format(code & _INT_MASK, "x")


def java_double_string(value: float) -> str:
    """``Double.toString(d)``: the shortest digits that round-trip, always with a fraction,
    and in computerized scientific notation (``1.0E7``, ``1.5E-5``) outside [1e-3, 1e7)."""
    value = float(value)
    if value != value:
        return "NaN"
    if value in (float("inf"), float("-inf")):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "-0.0" if str(value).startswith("-") else "0.0"
    if abs(value) == 5e-324:
        return "4.9E-324" if value > 0 else "-4.9E-324"  # Java prints the least subnormal with two digits
    sign, digits, exponent = Decimal(repr(value)).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    text = "".join(map(str, digits))
    scientific = len(text) - 1 + exponent  # the power of ten of the first digit
    prefix = "-" if sign else ""
    if 1e-3 <= abs(value) < 1e7:
        if scientific >= 0:
            whole = text[:scientific + 1].ljust(scientific + 1, "0")
            fraction = text[scientific + 1:] or "0"
        else:
            whole, fraction = "0", "0" * (-scientific - 1) + text
        return f"{prefix}{whole}.{fraction}"
    return f"{prefix}{text[0]}.{text[1:] or '0'}E{scientific}"


def claim_hash(claim: dict) -> str:
    """``ReplicatedSpace.claimHash``: ``epoch:stamp:bid:expiresAtMillis``, the bid as Java prints a double."""
    return (f"{int(claim['epoch'])}:{claim['stamp']}:{java_double_string(claim['bid'])}"
            f":{int(claim['expiresAtMillis'])}")


def utf16_key(text: str) -> bytes:
    """A key that orders text as Java's ``String.compareTo`` does."""
    return text.encode("utf-16-be", "surrogatepass")


def digest_text(lines: dict, acknowledged=()) -> bytes:
    """The text digest: each ``key=value`` of ``lines`` with an LF, in Java ``TreeMap`` order,
    then each acknowledged line as ``a:<line>`` with an LF, in the same order."""
    out = [f"{key}={lines[key]}\n" for key in sorted(lines, key=utf16_key)]
    out.extend(f"a:{line}\n" for line in sorted(acknowledged, key=utf16_key))
    return "".join(out).encode("utf-8")
