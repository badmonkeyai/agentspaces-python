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

"""The invite key and the delegated credential against the social golden
vector (SRAD DB-X-07): every derivation from the secret, the founder's
delegation, the candidate's credential, both hashes, the signed view, and
both key renderings must match the Java bytes exactly. The vendored copy in
tests/ is the one the suite reads; the sibling module's copy, when present,
is read too so a regenerated vector cannot drift from the vendored one."""

import base64
import json
import pathlib

import pytest

from agentspaces import cbor, social
from agentspaces.identity import Identity, found_group, parse_instant_millis

_VENDORED = pathlib.Path(__file__).parent / "social-golden.json"
_SIBLING = (pathlib.Path(__file__).resolve().parents[2]
            / "agentspaces-bootstrap-social" / "golden" / "social-golden.json")
GOLDEN_PATHS = [_VENDORED] + ([_SIBLING] if _SIBLING.exists() else [])


@pytest.fixture(params=GOLDEN_PATHS, ids=lambda p: "vendored" if p == _VENDORED else "sibling")
def golden(request) -> dict:
    return json.loads(request.param.read_text())


def _secret(golden) -> social.GroupSecret:
    return social.GroupSecret(bytes.fromhex(golden["secret_hex"]))


def test_vendored_golden_matches_the_sibling_when_present():
    if not _SIBLING.exists():
        pytest.skip("no sibling golden")
    assert json.loads(_VENDORED.read_text()) == json.loads(_SIBLING.read_text())


def test_secret_derivations_match_java(golden):
    secret = _secret(golden)
    assert social.SALT == golden["hkdf_salt"].encode()
    assert secret.code() == golden["code"]
    assert len(secret.code()) == 16
    assert secret.invite_private_seed().hex() == golden["invite_private_seed_hex"]
    assert secret.invite_public_key().hex() == golden["invite_public_key_hex"]
    assert secret.content_key().hex() == golden["content_key_hex"]
    assert len(secret.content_key()) == 32
    assert social.GroupSecret(secret.bytes) == secret


def test_identities_from_seeds_match_java(golden):
    founder = Identity.from_seed(bytes.fromhex(golden["founder_seed_hex"]))
    candidate = Identity.from_seed(bytes.fromhex(golden["candidate_seed_hex"]))
    assert founder.peer_id == golden["founder_peer_id"]
    assert candidate.peer_id == golden["candidate_peer_id"]


def test_the_python_founder_reproduces_the_golden_founding(golden):
    founder = Identity.from_seed(bytes.fromhex(golden["founder_seed_hex"]))
    # Java: GroupFounding.found(founder, "weekend-hack", INVITE, LEASE_RACE,
    # GossipParameters.defaults(), issued, Duration.ofDays(365)).
    signed = found_group(founder, "weekend-hack", "INVITE", "LEASE_RACE", 3, "PT1S",
                         golden["founding_issued"], "PT8760H")
    assert cbor.dumps(signed) == base64.b64decode(golden["founding_cbor_base64"])
    assert signed["advertisement"]["group"] == golden["group_id"]


def test_the_delegation_decodes_and_hashes(golden):
    info = social.delegation_info(golden["delegation_base64"])
    assert info["founder"] == golden["founder_peer_id"]
    assert info["invite_key"].hex() == golden["invite_public_key_hex"]
    assert info["group"] == golden["group_id"]
    assert info["not_after_millis"] == parse_instant_millis(golden["delegation_not_after"])
    assert info["label"] == golden["delegation_label"]
    assert social.delegation_group(golden["delegation_base64"]) == golden["group_id"]
    assert social.delegation_hash(golden["delegation_base64"]).hex() == golden["delegation_hash_hex"]
    # The decoded record re-encodes to the same bytes: the field order is Java's.
    assert cbor.dumps(social.decode_delegation(golden["delegation_base64"])) \
        == base64.b64decode(golden["delegation_base64"])


def test_the_python_founder_signs_the_same_delegation(golden):
    founder = Identity.from_seed(bytes.fromhex(golden["founder_seed_hex"]))
    delegation = social.delegate(founder, golden["group_id"], _secret(golden).invite_public_key(),
                                 parse_instant_millis(golden["delegation_not_after"]),
                                 golden["delegation_label"])
    assert delegation == golden["delegation_base64"]


def test_the_delegated_credential_is_reproduced_byte_for_byte(golden):
    secret = _secret(golden)
    credential = social.issue_delegated(golden["delegation_base64"], secret.invite_private_seed(),
                                        golden["candidate_peer_id"])
    assert credential == golden["credential"]
    assert credential.startswith(social.DELEGATED_PREFIX)
    # The invite Identity signs the same bytes as its seed.
    assert social.issue_delegated(golden["delegation_base64"], secret.invite_key(),
                                  golden["candidate_peer_id"]) == credential
    assert social.credential_hash(credential).hex() == golden["credential_hash_hex"]
    assert social.delegation_hash(credential).hex() == golden["delegation_hash_hex"]
    assert cbor.dumps(social.credential_view(golden["candidate_peer_id"], golden["group_id"])).hex() \
        == golden["credential_view_cbor_hex"]


def test_the_credential_admits_exactly_the_candidate_in_the_window(golden):
    credential = golden["credential"]
    issued = parse_instant_millis(golden["founding_issued"])
    not_after = parse_instant_millis(golden["delegation_not_after"])
    admits = social.delegated_credential_admits
    issuer, group = golden["founder_peer_id"], golden["group_id"]
    candidate = golden["candidate_peer_id"]
    assert admits(credential, candidate, issuer, group, issued)
    assert admits(credential, candidate, issuer, group, not_after + social.EXPIRY_SKEW_MILLIS)
    assert not admits(credential, candidate, issuer, group, not_after + social.EXPIRY_SKEW_MILLIS + 1)
    assert not admits(credential, golden["founder_peer_id"], issuer, group, issued), "another candidate"
    assert not admits(credential, candidate, candidate, group, issued), "not the founder's group"
    assert not admits(credential, candidate, issuer, "zOther", issued), "another group"
    assert not admits("not a credential", candidate, issuer, group, issued)
    assert not admits(credential[:-8] + "AAAAAAA=", candidate, issuer, group, issued), "tampered"


def test_a_credential_under_another_invite_key_is_refused(golden):
    other = social.GroupSecret.random()
    forged = social.issue_delegated(golden["delegation_base64"], other.invite_private_seed(),
                                    golden["candidate_peer_id"])
    assert not social.delegated_credential_admits(
        forged, golden["candidate_peer_id"], golden["founder_peer_id"], golden["group_id"],
        parse_instant_millis(golden["founding_issued"]))


@pytest.mark.parametrize("name, renders", [
    ("invite_key_compact", "compact"),
    ("invite_key_url", "url"),
    ("invite_key_compact_with_host_and_delegation", "compact"),
    ("invite_key_url_with_delegation", "url"),
])
def test_both_renderings_parse_to_the_secret_and_render_back(golden, name, renders):
    key = social.InviteKey.parse(golden[name])
    assert key.secret == _secret(golden)
    assert key.code == golden["code"]
    assert getattr(key, renders)() == golden[name]
    if "delegation" in name:
        assert key.host == "beacon.example.org"
        assert key.delegation == golden["delegation_base64"]
        assert key.document_url() == "https://beacon.example.org/j/" + golden["code"]
    else:
        assert key.host == social.DEFAULT_HOST
        assert key.delegation is None
    # The two renderings of one key are each other's.
    assert social.InviteKey.parse(key.compact()).url() == key.url()
    assert social.InviteKey.parse(key.url()).compact() == key.compact()


def test_a_key_read_aloud_survives(golden):
    compact = golden["invite_key_compact"]
    lower = compact.lower()
    spaced = compact.replace("-000G", "- 000G").replace("G40R", "G40R ")
    for text in (lower, spaced, "  " + compact + "\n"):
        assert social.InviteKey.parse(text).compact() == compact
    # Crockford: O reads as 0, I and L as 1, dashes and case are ignored.
    assert social.base32_decode("o-i-l") == social.base32_decode("011")
    assert social.base32_decode(social.base32_encode(b"\x00\x01\xff").lower()) == b"\x00\x01\xff"
    with pytest.raises(ValueError):
        social.base32_decode("U")


def test_a_code_that_does_not_belong_to_the_secret_is_refused(golden):
    compact = golden["invite_key_compact"]
    wrong = compact.replace("-" + golden["code"] + "-", "-" + golden["code"][:-1] + "0-")
    assert wrong != compact
    with pytest.raises(ValueError):
        social.InviteKey.parse(wrong)
    url = golden["invite_key_url"].replace("/j/" + golden["code"], "/j/" + golden["code"][:-1] + "0")
    with pytest.raises(ValueError):
        social.InviteKey.parse(url)
    for bad in ("", "aspace-inv2-x-y", "https://host/x#y", "https://host/j/" + golden["code"],
                "aspace-inv1-" + golden["code"]):
        with pytest.raises(ValueError):
            social.InviteKey.parse(bad)


def test_a_url_key_keeps_a_non_default_port(golden):
    url = golden["invite_key_url"].replace("https://s.agentspaces.dev/", "https://beacon.test:8443/")
    key = social.InviteKey.parse(url)
    assert key.host == "beacon.test:8443"
    assert key.url() == url
    assert key.compact() == golden["invite_key_compact"] + "@beacon.test:8443"
    assert social.InviteKey.parse(key.compact()).host == "beacon.test:8443"


def test_hints_for_carries_the_credential_under_the_join_key(golden):
    key = social.InviteKey.parse(golden["invite_key_url_with_delegation"])
    hints = social.hints_for(key, key.delegation, golden["candidate_peer_id"])
    assert hints == {"aspace:join": golden["credential"]}


def test_judge_tells_expiry_from_forgery(golden):
    """JoinCredentials.judge in Python: past the window the golden credential is
    "expired", not "invalid", so join_invite no longer refuses a peer the members
    may re-admit from their admission memory (SPEC §5.1, v0.1.20)."""
    credential = golden["credential"]
    issued = parse_instant_millis(golden["founding_issued"])
    not_after = parse_instant_millis(golden["delegation_not_after"])
    judge = social.judge_delegated_credential
    issuer, group = golden["founder_peer_id"], golden["group_id"]
    candidate = golden["candidate_peer_id"]
    assert judge(credential, candidate, issuer, group, issued) == "valid"
    assert judge(credential, candidate, issuer, group, not_after + social.EXPIRY_SKEW_MILLIS) == "valid"
    assert judge(credential, candidate, issuer, group, not_after + social.EXPIRY_SKEW_MILLIS + 1) == "expired"
    assert judge(credential, golden["founder_peer_id"], issuer, group, issued) == "invalid", "another candidate"
    assert judge(credential, candidate, candidate, group, issued) == "invalid", "not the founder's group"
    assert judge("d1:AAAA", candidate, issuer, group, issued) == "invalid"
