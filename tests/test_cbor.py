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

"""Decoder edge cases, including the regression that once desynced on
doubles: major-7 items carry no length head, so a float's payload bytes must
never be consumed as a length."""

from agentspaces import cbor


def test_round_trips():
    for value in [0, 23, 24, 255, 65536, 2**40, -1, -1000, True, False, None,
                  "text", b"bytes", 3.5, [1, "two", None],
                  {"a": 1, "b": [b"x"], "c": {"d": False}}]:
        assert cbor.loads(cbor.dumps(value)) == value


def test_double_followed_by_uint64_stays_in_sync():
    # The TakeClaim shape that surfaced the desync: a double then a uint64.
    value = {"bid": 0.0, "expiresAtMillis": 1787778127650}
    encoded = cbor.dumps(value)
    assert cbor.loads(encoded) == value


def test_definite_maps_and_arrays_decode_too():
    # Canonical form (wire v2, SPEC v0.1.8) writes indefinite-length maps and
    # definite-length arrays; the decoder accepts both forms of each so other
    # CBOR producers interoperate.
    assert cbor.loads(bytes.fromhex("a161610f")) == {"a": 15}
    assert cbor.loads(bytes.fromhex("bf61610fff")) == {"a": 15}
    assert cbor.loads(bytes.fromhex("83010203")) == [1, 2, 3]
    assert cbor.loads(bytes.fromhex("9f010203ff")) == [1, 2, 3]


def test_canonical_form_uses_indefinite_maps_and_definite_arrays():
    # The encoder side of the same rule, pinned as bytes (SPEC v0.1.8).
    assert cbor.dumps([1, 2, 3]) == bytes.fromhex("83010203")
    assert cbor.dumps({"a": 15}) == bytes.fromhex("bf61610fff")


def test_half_and_single_floats_decode():
    assert cbor.loads(bytes.fromhex("f90000")) == 0.0
    assert abs(cbor.loads(bytes.fromhex("fa40490fdb")) - 3.14159) < 1e-5


def test_canonical_map_sorts_keys_by_utf8_length_then_bytes():
    """SPEC v0.1.15 (wire version 3): a map a signature covers is sorted by
    its keys' UTF-8 encoding, shorter first, bytewise between equal lengths."""
    from agentspaces import wire
    assert wire.WIRE_VERSION == 3
    assert list(cbor.canonical_map({"region": "eu", "b": "1", "aa": "2", "a": "3", "é": "4"})) == \
        ["a", "b", "aa", "é", "region"]
    view = wire.sign_view("e", "s", "T#v1", b"", "i", "1-0-i", tags={"zz": "1", "a": "2"})
    assert list(view["tags"]) == ["a", "zz"]
