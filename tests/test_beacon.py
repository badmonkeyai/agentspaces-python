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

"""The beacon document (SRAD §3.5, appendix C) fetched from a loopback HTTP
server: a signed document verifies, a tampered one is refused, a pinned
beacon is honoured, http needs allow_plain, and the body is capped."""

import base64
import http.server
import json
import threading

import pytest

from agentspaces import beacon
from agentspaces.identity import Identity, found_group


class Served:
    """One document (or any bytes) on a loopback port."""

    def __init__(self, body: bytes, status: int = 200, path: str = beacon.WELL_KNOWN):
        served = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                served.requests.append((self.path, self.headers.get("Accept")))
                if self.path != path:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.requests = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}{path}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _founding(founder: Identity, name: str = "research-fleet") -> dict:
    return found_group(founder, name, "OPEN", "LEASE_RACE", 3, "PT1S",
                       "2026-10-14T00:00:00Z", "PT8760H")


def _document(issuer: Identity, founder: Identity) -> dict:
    from agentspaces import cbor
    signed = _founding(founder)
    group = beacon.document_group(
        "research-fleet", signed["advertisement"]["group"],
        base64.b64encode(cbor.dumps(signed)).decode(),
        [("tls", "seed-a.corp.example:7500"), ("tcp", "127.0.0.1:7500")],
        wire={"session": 1, "batch": 1}, parameters={"region": "eu-west-1"})
    other = beacon.document_group("other", None, None, [("tcp", "127.0.0.1:7600")])
    return beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group, other])


def test_canonical_bytes_are_jacksons():
    issuer = Identity.generate()
    group = beacon.document_group("g", "zG", "AA==", [("tcp", "h:1")], wire={"session": 1, "batch": 1},
                                  multicast="239.255.42.99:7787", parameters={"b": "2", "a": "1"},
                                  invite="QQ==")
    doc = beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group])
    key = base64.b64encode(issuer.public_raw).decode()
    assert beacon.canonical_bytes(doc).decode() == (
        '{"v":1,"issuer":"' + issuer.peer_id + '","issuerKey":"' + key + '",'
        '"issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"g","id":"aspace://zG",'
        '"founding":"AA==","seeds":[{"transport":"tcp","address":"h:1","priority":0}],'
        '"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787",'
        '"parameters":{"a":"1","b":"2"},"invite":"QQ=="}]}')
    # Unknown fields and pretty whitespace do not change the signed bytes.
    reparsed = json.loads(json.dumps({**doc, "extra": 1}, indent=2))
    reparsed["groups"][0]["unknown"] = "x"
    assert beacon.canonical_bytes(reparsed) == beacon.canonical_bytes(doc)
    assert beacon.verify_document(reparsed, issuer.peer_id) == issuer.peer_id
    assert json.loads(beacon.to_json(doc)) == doc
    with pytest.raises(ValueError):
        beacon.document_group("g", parameters={"content-key": "x"})


def test_a_served_signed_document_verifies_and_selects(tmp_path):
    issuer, founder = Identity.generate(), Identity.generate()
    doc = _document(issuer, founder)
    served = Served(beacon.to_json(doc))
    try:
        fetched = beacon.fetch_beacon_document(served.url, allow_plain=True)
        assert fetched == doc
        assert served.requests[0][1] == "application/json"
        group_id = _founding(founder)["advertisement"]["group"]
        by_id = beacon.group_from_document(fetched, group_id=group_id)
        assert by_id["name"] == "research-fleet"
        assert beacon.group_from_document(fetched, group_id="aspace://" + group_id) is by_id
        assert beacon.group_from_document(fetched, name="other")["name"] == "other"
        with pytest.raises(ValueError):
            beacon.group_from_document(fetched)  # two groups: name one
        with pytest.raises(ValueError):
            beacon.group_from_document(fetched, group_id="zNope")
        assert beacon.verified_group_id(by_id) == group_id
        assert beacon.verified_group_id(by_id, group_id) == group_id
        with pytest.raises(ValueError):
            beacon.verified_group_id(by_id, "zOther")
        with pytest.raises(ValueError):
            beacon.verified_group_id(beacon.group_from_document(fetched, name="other"))
        # The tls seed is not this client's; the tcp one is, in priority order.
        assert beacon.seeds_of(by_id) == [("127.0.0.1", 7500)]
        assert beacon.seeds_of(by_id, ("tls", "tcp")) == [("seed-a.corp.example", 7500), ("127.0.0.1", 7500)]
    finally:
        served.close()


def test_a_tampered_signature_or_body_is_refused():
    issuer, founder = Identity.generate(), Identity.generate()
    doc = _document(issuer, founder)
    bad_signature = dict(doc, signature=base64.b64encode(b"\x00" * 64).decode())
    bad_body = json.loads(json.dumps(doc))
    bad_body["groups"][0]["seeds"][1]["address"] = "evil.example:7500"
    wrong_issuer = dict(doc, issuer=Identity.generate().peer_id)
    for body in (bad_signature, bad_body, wrong_issuer):
        served = Served(beacon.to_json(body))
        try:
            with pytest.raises(ValueError):
                beacon.fetch_beacon_document(served.url, allow_plain=True)
        finally:
            served.close()


def test_the_pinned_beacon_is_honoured():
    issuer, founder = Identity.generate(), Identity.generate()
    doc = _document(issuer, founder)
    served = Served(beacon.to_json(doc))
    try:
        assert beacon.fetch_beacon_document(served.url, allow_plain=True, beacon_peer=issuer.peer_id) == doc
        with pytest.raises(ValueError):
            beacon.fetch_beacon_document(served.url, allow_plain=True,
                                         beacon_peer=Identity.generate().peer_id)
    finally:
        served.close()
    # An unsigned document passes unpinned (as the Java reader) and fails a pin.
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    served = Served(beacon.to_json(unsigned))
    try:
        assert beacon.fetch_beacon_document(served.url, allow_plain=True) == unsigned
        with pytest.raises(ValueError):
            beacon.fetch_beacon_document(served.url, allow_plain=True, beacon_peer=issuer.peer_id)
    finally:
        served.close()


def test_plain_http_needs_allow_plain_and_the_body_is_capped():
    issuer, founder = Identity.generate(), Identity.generate()
    doc = _document(issuer, founder)
    served = Served(beacon.to_json(doc))
    try:
        with pytest.raises(ValueError):
            beacon.fetch_beacon_document(served.url)
        assert served.requests == [], "refused before any request"
        with pytest.raises(ValueError):
            beacon.fetch_beacon_document("ftp://127.0.0.1/x", allow_plain=True)
    finally:
        served.close()
    big = Served(b"[" + b"1," * (beacon.MAX_DOCUMENT_BYTES // 2) + b"1]")
    try:
        with pytest.raises(ValueError):
            beacon.fetch_beacon_document(big.url, allow_plain=True)
    finally:
        big.close()
    missing = Served(b"{}", status=404)
    try:
        with pytest.raises(OSError):
            beacon.fetch_beacon_document(missing.url, allow_plain=True)
    finally:
        missing.close()

# A document Java's BeaconDocument.signed wrote for the issuer seeded 0x10..0x2f
# (the golden founder) at 2026-10-14T00:00:00Z, ttl 300: one full group (a
# non-ASCII, quoted, control-character parameter included) and one bare group.
JAVA_SIGNED_DOCUMENT = '{"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \\"q\\" \\u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}],"signature":"7gGY0YkDJfdrSzjbeVZTjkV+zr4o9H1MqVC8Ab7D4qoWMiuFt4qUEF99yidhtIJxzZAcvl3QbA23ST6zY02gAw=="}'
JAVA_CANONICAL_BYTES = '{"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \\"q\\" \\u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}]}'


def test_a_document_java_signed_verifies_and_its_canonical_bytes_are_reproduced():
    doc = json.loads(JAVA_SIGNED_DOCUMENT)
    issuer = Identity.from_seed(bytes(range(0x10, 0x30)))
    assert doc["issuer"] == issuer.peer_id
    assert beacon.canonical_bytes(doc).decode("utf-8") == JAVA_CANONICAL_BYTES
    assert beacon.verify_document(doc, issuer.peer_id) == issuer.peer_id
    assert beacon.to_json(doc).decode("utf-8") == JAVA_SIGNED_DOCUMENT
    # The same document re-signed by the Python issuer carries Java's signature exactly.
    resigned = beacon.sign_document(issuer, doc["issued"], doc["ttl"], doc["groups"])
    assert resigned["signature"] == doc["signature"]


def test_seeds_skip_datagram_schemes_this_client_cannot_dial():
    """SRAD dtls-support DT-C-01: a dtls or udp seed is skipped for the next one this client speaks."""
    group = {"seeds": [
        {"transport": "dtls", "address": "10.0.0.5:7502", "priority": 0},
        {"transport": "udp", "address": "10.0.0.5:7503", "priority": 1},
        {"transport": "tcp", "address": "10.0.0.5:7500", "priority": 2},
    ]}
    assert beacon.seeds_of(group) == [("10.0.0.5", 7500)]


def test_the_client_skips_the_schemes_it_cannot_dial():
    """JS-N-05 (srad/agentspaces-js.md): the Python client dials tcp alone and skips every other
    scheme a beacon document may list, in priority order, so a mixed fleet still reaches it."""
    group = {"seeds": [
        {"transport": "wss", "address": "fleet.example.com:443/aspace", "priority": 0},
        {"transport": "webrtc", "address": "sig", "priority": 1},
        {"transport": "https", "address": "fleet.example.com:443/aspace/h", "priority": 2},
        {"transport": "dtls", "address": "10.0.0.5:7502", "priority": 3},
        {"transport": "ws", "address": "10.0.0.5:7503", "priority": 4},
        {"transport": "http", "address": "10.0.0.5:7503/aspace/h", "priority": 5},
        {"transport": "tcp", "address": "10.0.0.5:7500", "priority": 6},
    ]}
    assert beacon.seeds_of(group) == [("10.0.0.5", 7500)]
    assert beacon.CLIENT_TRANSPORTS == ("tcp",)
