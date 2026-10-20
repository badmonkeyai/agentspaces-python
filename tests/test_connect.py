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
"""The connector protocol's agent side from Python (srad/agentspaces-js.md
JS-C-14, JS-F-06): the five entries byte-identical to Java under the golden
vectors, a query answered by a simulated connector over the in-memory fleet
and the identical query served from the space, a result accepted only from
a trusted connector, an invocation answered only by the card's issuer, and
a retry under the same invocation id that never runs the target again. The
end-to-end proof against a Java ``ConnectorRuntime`` is
agentspaces-connect-core's ``PythonConnectorClientTest``."""

import json
import pathlib
import threading

from agentspaces import cbor
from agentspaces.capabilities import connect
from agentspaces.capabilities.connect import (AssetChange, AssetInvocation, AssetInvocationResult, DataQuery,
                                              DataQueryClient, DataResult, asset_cards, canonical_hash, invoke_ops,
                                              peer_of)
from agentspaces.identity import instant_iso
from agentspaces.space import Space, Template, WRITTEN, from_payload, to_payload
from fleet import fleet, until

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())
GROUP = "zPyConnect"
INVOCATION_ID = "6f1d2c3b-4a59-4e8f-9b7a-0c1d2e3f4a5b"
ROWS = [{"id": "1", "region": "eu", "amount": "120.00"}, {"id": "2", "region": "us", "amount": "80.00"},
        {"id": "3", "region": "eu", "amount": "45.50"}]


def _hex(value) -> str:
    return cbor.dumps(to_payload(value)).hex()


class SimulatedConnector:
    """A connector on one peer of the fleet, the shape of the Java and
    TypeScript ``ConnectorRuntime`` over a table asset with one invoke
    operation, ``reserve``: it publishes the AssetCard, answers a DataQuery
    with a DataResult (counting executions), takes each AssetInvocation under
    the claim lattice on its own thread, refuses an operation absent from
    ``invoke-ops`` naming the rule, runs the target once per invocation id,
    answers a repeat from its remembered result, writes the result, and
    completes the take."""

    def __init__(self, peer, asset="orders", rows=ROWS, ops=("reserve",), name="py-connector"):
        self.peer, self.asset, self.rows, self.name = peer, asset, rows, name
        self.space = Space(peer, connect.DEFAULT_DATA_SPACE, agent_name=name)
        self.executed = self.invoked = self.repeated = self.refused = 0
        self.reserved: list[str] = []          # the invocation ids the target ran under
        self.results: dict[str, AssetInvocationResult] = {}
        now_ms = peer._now_ms()
        self.card = {"id": f"aspace://{GROUP}/asset/{asset}", "issuer": peer.identity.peer_id, "group": GROUP,
                     "issued": instant_iso(now_ms - now_ms % 1000), "ttl": "PT15M", "asset": asset,
                     "uri": "postgres://ops/public.orders", "description": "Customer order history",
                     "shape": "com.example.OrderRow#v1", "freshness": "PT5M",
                     "costHints": cbor.canonical_map({"rows": str(len(rows))}),
                     "access": cbor.canonical_map({"mode": "read-only,invoke", "query": connect.DATA_QUERY_CAPABILITY,
                                                   "invoke": connect.ASSET_INVOKE_CAPABILITY,
                                                   connect.INVOKE_OPS: ",".join(ops)})}
        peer.publish_ad(connect.ASSET_CARD_TYPE, self.card)
        self.space.watch(Template(DataQuery, where={"asset": asset}), self._on_query)
        self._running = True
        self._thread = threading.Thread(target=self._serve_invocations, daemon=True)
        self._thread.start()

    def close(self):
        self._running = False
        self._thread.join(5)

    def _on_query(self, event):
        if event.kind != WRITTEN:
            return
        query = event.entry.value
        self.executed += 1
        limit = int(query.parameters.get("limit", len(self.rows)))
        matched = [row for row in self.rows
                   if all(row.get(k) == v for k, v in query.parameters.items() if k != "limit")][:limit]
        self.space.write(DataResult(query.queryHash, self.asset, matched, None, self.name), lease="5m")

    def _serve_invocations(self):
        template = Template(AssetInvocation, where={"asset": self.asset})
        while self._running:
            taken = self.space.take(template, lease="30s", timeout="500ms")
            if taken is None:
                continue
            invocation = taken.value
            remembered = self.results.get(invocation.invocationId)
            if remembered is not None:
                self.repeated += 1
                live = [e for e in self.space.entries(Template(AssetInvocationResult,
                                                               where={"invocationId": invocation.invocationId}))
                        if peer_of(e.issuer) == self.peer.identity.peer_id]
                taken.complete(None if live else remembered, lease="1h")
                continue
            if invocation.operation not in invoke_ops(self.card):
                self.refused += 1
                result = AssetInvocationResult.refused(
                    invocation, "unknown-operation", "invoke-ops",
                    f"'{invocation.operation}' is not in the invoke-ops of asset '{self.asset}' "
                    f"({','.join(invoke_ops(self.card))})")
            else:
                self.invoked += 1
                self.reserved.append(invocation.invocationId)
                result = AssetInvocationResult(invocation.invocationId, self.asset, invocation.operation, True,
                                               {"reserved": invocation.params.get("qty", "0"),
                                                "invocationId": invocation.invocationId}, None)
            self.results[invocation.invocationId] = result
            taken.complete(result, lease="1h")


class Rogue:
    """An admitted peer that forges an answer to every query and invocation it
    sees, synchronously on the write, so its forgery lands before the honest
    connector's answer: what ASF-009 says a client must ignore."""

    def __init__(self, peer):
        self.space = Space(peer, connect.DEFAULT_DATA_SPACE, agent_name="rogue")
        self.forged = 0
        self.space.watch(Template(DataQuery), self._on_query)
        self.space.watch(Template(AssetInvocation), self._on_invocation)

    def _on_query(self, event):
        if event.kind == WRITTEN:
            self.forged += 1
            self.space.write(DataResult(event.entry.value.queryHash, event.entry.value.asset,
                                        [{"id": "forged"}], None, "rogue"), lease="5m")

    def _on_invocation(self, event):
        if event.kind == WRITTEN:
            self.forged += 1
            invocation = event.entry.value
            self.space.write(AssetInvocationResult(invocation.invocationId, invocation.asset, invocation.operation,
                                                   True, {"reserved": "999"}, None), lease="5m")


def _ids(result: DataResult) -> list[str]:
    return [row["id"] for row in result.rows]


# ------------------------------------------------------------ the entries

def test_the_connector_entries_encode_as_java_does_and_readers_drop_unknown_fields():
    query_hash = canonical_hash("orders", {"region": "eu", "limit": "10"})
    assert query_hash == GOLDEN["data_query_canonical_hash"]
    assert canonical_hash("orders", {"limit": "10", "region": "eu"}) == query_hash, "parameter order never splits"
    assert _hex(DataQuery(query_hash, "orders", {"region": "eu", "limit": "10"}, "zPeer/analyst")) \
        == GOLDEN["data_query_cbor"]
    assert _hex(DataResult(query_hash, "orders", [{"id": "1", "region": "eu", "amount": "120.00"},
                                                  {"id": "3", "region": "eu", "amount": "45.50"}], None,
                           "pg-connector")) == GOLDEN["data_result_cbor"]
    assert _hex(AssetChange("orders", "1", {"id": "1", "region": "eu", "amount": "125.00"}, "pg-connector")) \
        == GOLDEN["asset_change_cbor"]
    assert _hex(AssetInvocation("do/Inventory", "reserveStock", {"sku": "A-1", "qty": "2"}, INVOCATION_ID)) \
        == GOLDEN["asset_invocation_cbor"]
    assert _hex(AssetInvocationResult(INVOCATION_ID, "do/Inventory", "reserveStock", True, {"reserved": "2"}, None)) \
        == GOLDEN["asset_invocation_result_cbor"]
    # The bytes decode back to the same values; a field the reader does not know is dropped and a
    # missing version reads as the current one (JS-F-06).
    decoded = cbor.loads(bytes.fromhex(GOLDEN["asset_invocation_cbor"]))
    assert from_payload(AssetInvocation, decoded) \
        == AssetInvocation("do/Inventory", "reserveStock", {"sku": "A-1", "qty": "2"}, INVOCATION_ID)
    later = {**decoded, "idempotency": "once", "cost": "3"}
    del later["v"]
    assert from_payload(AssetInvocation, later).v == connect.ASSET_INVOKE_VERSION
    assert to_payload(from_payload(AssetInvocation, later)) == decoded
    result = cbor.loads(bytes.fromhex(GOLDEN["asset_invocation_result_cbor"]))
    assert from_payload(AssetInvocationResult, {**result, "schema": "x"}).result == {"reserved": "2"}


# -------------------------------------------------------------- the cards

def test_asset_cards_and_invoke_ops_read_the_cards_the_ads_stream_carried():
    connector_peer, agent_peer = fleet(GROUP, 2)
    connector = SimulatedConnector(connector_peer)
    try:
        assert until(2.0, lambda: asset_cards(agent_peer, "orders"))
        (card,) = asset_cards(agent_peer)
        assert card["issuer"] == connector_peer.identity.peer_id and card["asset"] == "orders"
        assert card["access"]["query"] == "aspace:cap/data-query"
        assert card["access"]["invoke"] == "aspace:cap/asset-invoke"
        assert invoke_ops(card) == ["reserve"]
        assert asset_cards(agent_peer, "shipments") == []
        assert invoke_ops({"access": {"invoke-ops": " reserve , release,, "}}) == ["reserve", "release"]
        assert invoke_ops({"access": {}}) == [] and invoke_ops({}) == []
    finally:
        connector.close()


# ------------------------------------------------------------ the queries

def test_a_query_is_answered_by_the_connector_and_the_identical_one_is_served_from_the_space():
    connector_peer, agent_peer = fleet(GROUP, 2)
    connector = SimulatedConnector(connector_peer)
    try:
        client = DataQueryClient(agent_peer, "analyst", trusted_connectors={connector_peer.identity.peer_id})
        fetched = client.fetch("orders", {"region": "eu"}, timeout="5s")
        assert fetched is not None and fetched.from_cache is False
        assert _ids(fetched.result) == ["1", "3"] and fetched.result.servedBy == "py-connector"
        assert fetched.result.error is None and connector.executed == 1
        # The same query, parameters in another order and from another agent: the live result answers.
        again = DataQueryClient(agent_peer, "planner", trusted_connectors={connector_peer.identity.peer_id})
        cached = again.fetch("orders", {"region": "eu"}, timeout="5s")
        assert cached is not None and cached.from_cache is True and _ids(cached.result) == ["1", "3"]
        assert connector.executed == 1 and again.cache_hits == 1 and again.queries_sent == 0
        assert client.cache_hits == 0 and client.queries_sent == 1
        # A different query executes once more.
        limited = client.fetch("orders", {"region": "eu", "limit": "1"}, timeout="5s")
        assert limited is not None and _ids(limited.result) == ["1"] and connector.executed == 2
        # An asset nobody serves: None at the timeout, the query written and left for a connector.
        assert client.fetch("shipments", {}, timeout="300ms") is None
        assert len(client.space.entries(Template(DataQuery, where={"asset": "shipments"}))) == 1
    finally:
        connector.close()


def test_a_result_counts_only_from_a_trusted_connector():
    rogue_peer, connector_peer, agent_peer = fleet(GROUP, 3)  # the rogue hears the query first
    rogue = Rogue(rogue_peer)
    connector = SimulatedConnector(connector_peer)
    try:
        trusting = DataQueryClient(agent_peer, "analyst", trusted_connectors={connector_peer.identity.peer_id})
        fetched = trusting.fetch("orders", {"region": "us"}, timeout="5s")
        assert fetched is not None and _ids(fetched.result) == ["2"] and fetched.result.servedBy == "py-connector"
        assert rogue.forged == 1, "the forgery was written and ignored"
        assert len(trusting.space.entries(Template(DataResult))) == 2
        # The cache check applies the same rule: the forged result under the hash is not a hit.
        assert trusting.fetch("orders", {"region": "us"}, timeout="5s").result.servedBy == "py-connector"
        # A caller's own trust rule, the shape of the authorizer's CONNECTOR_SERVE check.
        ruled = DataQueryClient(agent_peer, "auditor", trust=lambda issuer_peer, asset: issuer_peer == rogue_peer.identity.peer_id)
        assert ruled.fetch("orders", {"region": "us"}, timeout="5s").result.servedBy == "rogue"
    finally:
        connector.close()


# -------------------------------------------------------- the invocations

def test_an_invocation_is_answered_only_by_the_cards_issuer_and_a_retry_never_runs_the_target_again():
    rogue_peer, connector_peer, agent_peer = fleet(GROUP, 3)
    rogue = Rogue(rogue_peer)
    connector = SimulatedConnector(connector_peer)
    try:
        assert until(2.0, lambda: asset_cards(agent_peer, "orders"))
        (card,) = asset_cards(agent_peer, "orders")
        space = Space(agent_peer, connect.DEFAULT_DATA_SPACE, agent_name="planner")
        result = connect.invoke(space, card, "reserve", {"sku": "A-1", "qty": "2"}, timeout="10s")
        assert result is not None and result.ok is True and result.error is None
        assert result.result["reserved"] == "2" and result.result["invocationId"] == result.invocationId
        assert rogue.forged == 1, "the forged result landed first and was ignored"
        assert connector.reserved == [result.invocationId] and connector.invoked == 1
        assert until(2.0, lambda: space.entries(Template(AssetInvocation)) == []), "the take was completed"
        # A forced retry under the same id: answered, the target not run again, one result from the issuer.
        retry = connect.invoke(space, card, "reserve", {"sku": "A-1", "qty": "2"}, timeout="10s",
                               invocation_id=result.invocationId)
        assert retry is not None and retry.ok is True and retry.invocationId == result.invocationId
        assert connector.reserved == [result.invocationId]
        assert until(5.0, lambda: connector.repeated == 1)
        from_issuer = [e for e in space.entries(Template(AssetInvocationResult,
                                                         where={"invocationId": result.invocationId}))
                       if peer_of(e.issuer) == card["issuer"]]
        assert len(from_issuer) == 1
        # An operation the card does not list is refused naming the rule and never run.
        refused = connect.invoke(space, card, "drop", {"table": "orders"}, timeout="10s")
        assert refused is not None and refused.ok is False and refused.error == "unknown-operation"
        assert refused.result["rule"] == "invoke-ops"
        assert "'drop' is not in the invoke-ops of asset 'orders' (reserve)" in refused.result["detail"]
        assert connector.reserved == [result.invocationId] and connector.refused == 1
        # Nobody serves the asset: None at the timeout, and the forgery under that id is not an answer.
        orphan = dict(card, asset="shipments")
        assert connect.invoke(space, orphan, "reserve", {}, timeout="400ms") is None
        assert rogue.forged == 4
    finally:
        connector.close()
