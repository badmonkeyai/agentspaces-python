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

"""The ``@data_use`` hook writes the record type its caller names (neutral vectors, 2026-11-09): the open client
holds no product's record type, so a binder given ``data_use_type`` writes one leased entry of that type per
declaration into ``data_use_space``, and a binder given none writes nothing."""

from agentspaces import cbor
from agentspaces.agents import Binder, agent, data_use
from agentspaces.identity import space_id_local
from fleet import fleet

TYPE = "com.example.governance.DataUse#v1"


@data_use(reads=["orders.lines"], source="jdbc:postgresql://orders/lines", sensitivity="internal", freshness="PT5M")
@data_use(writes=["Shipment"], source="kafka://shipments")
@agent("reader", description="Reads orders")
class Reader:
    pass


def _records(peer, type_name):
    return [d["record"] for d in peer.states.values() if (d.get("record") or {}).get("type") == type_name]


def test_the_binder_writes_each_declaration_under_the_type_the_caller_names():
    peer, _other = fleet("zDataUse", 2)
    bound = Binder(peer, agent_name="reader", data_use_type=TYPE, data_use_space="governance").bind(Reader())
    try:
        written = _records(peer, TYPE)
        assert len(bound.data_use) == 2 and len(written) == 2
        assert {r["spaceId"] for r in written} == {space_id_local("zDataUse/governance")}
        payloads = sorted((cbor.loads(r["payload"]) for r in written), key=lambda p: p["source"])
        assert payloads[0]["reads"] == ["orders.lines"] and payloads[0]["sensitivity"] == "internal"
        assert payloads[1]["writes"] == ["Shipment"] and payloads[1]["agent"] == "reader"
        assert payloads[0]["peer"] == peer.identity.peer_id and payloads[0]["declaredBy"] == "decorator"
    finally:
        bound.close()


def test_a_binder_without_a_type_writes_nothing():
    peer, _other = fleet("zDataUse", 2)
    bound = Binder(peer, agent_name="reader").bind(Reader())
    try:
        assert bound.data_use == [] and not any(d.get("record") for d in peer.states.values()
                                                 if "DataUse" in str((d.get("record") or {}).get("type")))
    finally:
        bound.close()
