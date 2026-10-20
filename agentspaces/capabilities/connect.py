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
"""The agent side of the connector protocol (srad/agentspaces-js.md JS-C-14,
the Python twin of Java's ``DataQueryClient`` and ``AssetInvocations`` and of
``@agentspaces/connect``'s ``client.ts``): the ``aspace:cap/data-query``
entries of ``DataQueryEntries.java`` and the ``aspace:cap/asset-invoke``
entries of appendix F as ``@entry`` dataclasses in Java record order, so
``Space.write`` encodes the bytes the Java codec writes (golden
``data_query_cbor``, ``data_result_cbor``, ``asset_change_cbor``,
``asset_invocation_cbor``, ``asset_invocation_result_cbor``); the canonical
query hash; a ``DataQueryClient`` that fetches by asset and parameters
pull-once; and ``invoke``, one operation on an asset through its card. A
result counts only when its issuer is trusted (ASF-009): the connectors the
caller names, or, for an invocation, the card's issuer. Readers drop the
fields they do not know (JS-F-06), so later operation metadata needs no
migration. The connector half (``ConnectorRuntime``) stays in Java and
TypeScript.

    client = DataQueryClient(peer, "analyst", trusted_connectors={card["issuer"]})
    fetched = client.fetch("orders", {"region": "eu"}, timeout="30s")
    result = invoke(client.space, card, "reserve", {"sku": "A-1", "qty": "2"})
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from .. import cbor
from ..identity import derive_id
from ..space import Space, Template, WRITTEN, duration_millis, entry, eq

# The schema names the Java SimpleSchemaRegistry gives the records: the binary class name plus #v1.
DATA_QUERY_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataQuery#v1"
DATA_RESULT_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataResult#v1"
ASSET_CHANGE_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$AssetChange#v1"
ASSET_INVOCATION_TYPE = "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocation#v1"
ASSET_INVOCATION_RESULT_TYPE = "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocationResult#v1"

# The capability types the cards name in their access map, and the ad type the cards travel as.
DATA_QUERY_CAPABILITY = "aspace:cap/data-query"
ASSET_INVOKE_CAPABILITY = "aspace:cap/asset-invoke"
ASSET_CARD_TYPE = "AssetCard"
DEFAULT_DATA_SPACE = "data"  # DataSpaces.DEFAULT_NAME

ASSET_INVOKE_VERSION = 1  # AssetInvocations.VERSION (appendix F, JS-F-06)
INVOKE_OPS = "invoke-ops"  # the access key listing a card's operations, a comma list

# The error codes an AssetInvocationResult carries when ok is false (appendix F).
INVOKE_ERRORS = ("unknown-operation", "bad-params", "refused-scope", "target-error", "timeout")


# ------------------------------------------------------------------ entries

def canonical_strings(value: dict | None) -> dict:
    """A string-to-string map as the wire carries it: every value a string, the
    entries in canonical (wire v3) order."""
    return cbor.canonical_map({str(k): str(v) for k, v in (value or {}).items()})


def canonical_hash(asset: str, parameters: dict) -> str:
    """DataQueryEntries.canonicalHash: multibase(sha-256) over the asset name and
    the parameters in sorted key order, so parameter ordering never splits the
    pull-once cache. Keys sort as Java's ``TreeMap<String>`` sorts them, by
    UTF-16 code unit."""
    canonical = asset
    for key in sorted(parameters, key=lambda k: str(k).encode("utf-16-be")):
        canonical += f"|{key}={parameters[key]}"
    return derive_id(canonical.encode("utf-8"))


@entry(DATA_QUERY_TYPE)
@dataclass
class DataQuery:
    """One query awaiting a connector (DataQueryEntries.DataQuery): the canonical
    hash of (asset, parameters), the asset name from the card, the parameters,
    and the asking agent for the audit trail."""
    queryHash: str
    asset: str
    parameters: dict
    requester: str

    def __post_init__(self):
        self.parameters = canonical_strings(self.parameters)


@entry(DATA_RESULT_TYPE)
@dataclass
class DataResult:
    """One answered query, leased for its freshness window
    (DataQueryEntries.DataResult): rows as column-to-value maps, an error
    message when the query failed (None on success), and the connector that
    executed against the source."""
    queryHash: str
    asset: str
    rows: list
    error: str | None
    servedBy: str

    def __post_init__(self):
        self.rows = [canonical_strings(row) for row in (self.rows or [])]


@entry(ASSET_CHANGE_TYPE)
@dataclass
class AssetChange:
    """One change a materializing provider pushed (DataQueryEntries.AssetChange),
    leased for the asset's freshness window so the lease is the retention
    policy; subscribe with ``Template(AssetChange, where={"asset": name})``."""
    asset: str
    key: str
    row: dict
    servedBy: str

    def __post_init__(self):
        self.row = canonical_strings(self.row)


@entry(ASSET_INVOCATION_TYPE)
@dataclass
class AssetInvocation:
    """One operation an agent asks a connector to run (appendix F,
    AssetInvocations.AssetInvocation). ``v`` leads the record on the wire and is
    keyword-only here, defaulting to the current version when a sender omits
    it; ``invocationId`` is minted once by the client and constant across
    retries and takers, so a target deduplicates on it (JS-C-04)."""
    v: int = field(default=ASSET_INVOKE_VERSION, kw_only=True)
    asset: str
    operation: str
    params: dict
    invocationId: str

    def __post_init__(self):
        self.params = canonical_strings(self.params)


@entry(ASSET_INVOCATION_RESULT_TYPE)
@dataclass
class AssetInvocationResult:
    """The connector's answer to an AssetInvocation (appendix F,
    AssetInvocations.AssetInvocationResult), correlated by ``invocationId``.
    When ``ok`` is false, ``error`` is one of ``INVOKE_ERRORS`` and ``result``
    carries ``rule`` (the rule that refused) and ``detail``."""
    v: int = field(default=ASSET_INVOKE_VERSION, kw_only=True)
    invocationId: str
    asset: str
    operation: str
    ok: bool
    result: dict
    error: str | None

    def __post_init__(self):
        self.ok = self.ok is True
        self.result = canonical_strings(self.result)

    @staticmethod
    def refused(invocation: AssetInvocation, error: str, rule: str, detail: str) -> "AssetInvocationResult":
        """An error result naming the rule that refused the invocation."""
        return AssetInvocationResult(invocation.invocationId, invocation.asset, invocation.operation, False,
                                     {"rule": rule, "detail": detail}, error)


# -------------------------------------------------------------------- cards

def asset_cards(peer, asset: str | None = None) -> list[dict]:
    """The live AssetCards the ads stream carried, or only those of one asset."""
    now = peer._now_ms()
    return [e["ad"] for e in list(peer.ads.values())
            if e["type"] == ASSET_CARD_TYPE and e["expires"] > now
            and (asset is None or e["ad"].get("asset") == asset)]


def invoke_ops(card: dict) -> list[str]:
    """AssetInvocations.invokeOps: the operations a card allows, its
    ``invoke-ops`` comma list trimmed, in card order."""
    listed = (card.get("access") or {}).get(INVOKE_OPS) or ""
    return [op.strip() for op in str(listed).split(",") if op.strip()]


def peer_of(issuer: str) -> str:
    """The peer id of an issuer agent id (``<peer>/<name>``)."""
    return str(issuer).split("/", 1)[0]


# ------------------------------------------------------------------ the wait

class _Answer:
    """One awaited entry: set by a watch callback on the reader thread, read by
    the waiter, then re-read from the space between folds so a result whose
    fold landed before the subscription, or whose block arrived late, is found
    (DataQueryClient.await in Java, the read-through loop in TypeScript)."""

    def __init__(self):
        self.value = None
        self.ready = threading.Event()

    def accept(self, value) -> None:
        if not self.ready.is_set():
            self.value = value
            self.ready.set()

    def wait(self, space: Space, read_through, timeout, read):
        """``read()`` is the trusted read of the space; returns the first value
        from either source, or None at the timeout. The space is pulled at most
        once per read-through window and the wait wakes on a fold (JS-V-02)."""
        peer = space.peer
        read_through_seconds = duration_millis(read_through) / 1000
        deadline = time.monotonic() + duration_millis(timeout) / 1000
        while True:
            seen = peer.fold_count
            if self.ready.is_set():
                return self.value
            found = read()
            if found is not None:
                return found
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            peer.pull_space_paced(space.name, read_through_seconds)
            peer.await_fold(min(read_through_seconds, remaining), since=seen)


# ---------------------------------------------------------------- the client

@dataclass(frozen=True)
class Fetched:
    """One fetch's answer (DataQueryClient.Fetched): the result and whether a
    live space result answered it with no new query."""
    result: DataResult
    from_cache: bool


class DataQueryClient:
    """The DataQueryClient of Java: fetch by asset and parameters, pull-once by
    canonical hash. A live result under the hash answers at once and costs the
    source nothing; otherwise a ``DataQuery`` is written and the connector's
    ``DataResult`` awaited. ``trusted_connectors`` names the connector peers
    whose results count (the issuers of their signed AssetCards); empty
    accepts any admitted peer's. ``trust(issuer_peer, asset)`` replaces that
    set with the caller's own rule (the shape of the Java authorizer's
    ``CONNECTOR_SERVE`` check). The counters make the economics observable:
    ``cache_hits`` is money the abstraction returned."""

    def __init__(self, peer, requester: str, data_space: str = DEFAULT_DATA_SPACE, trusted_connectors=(),
                 trust=None, query_lease="1m", read_through="100ms", agent=None):
        self.peer = peer
        self.requester = requester
        self.space = Space(peer, data_space, agent=agent, agent_name=requester)
        trusted = set(trusted_connectors or ())
        self.trust = trust if trust is not None else (lambda issuer_peer, asset: not trusted or issuer_peer in trusted)
        self.query_lease = query_lease
        self.read_through = read_through
        self.cache_hits = 0   # fetches answered by a live space result, with no source execution
        self.queries_sent = 0  # fetches that wrote a query entry for a connector to execute

    def _trusted(self, issuer: str, result: DataResult) -> bool:
        return self.trust(peer_of(issuer), result.asset)

    def _read_trusted(self, template: Template) -> DataResult | None:
        for e in self.space.entries(template, 16):
            if self._trusted(e.issuer, e.value):
                return e.value
        return None

    def fetch(self, asset: str, parameters: dict, timeout="30s") -> Fetched | None:
        """Fetches one asset query, pull-once: a trusted live result for the
        canonical hash answers at once; otherwise a query is written and the
        connector's result awaited. None when no connector answered in time."""
        query_hash = canonical_hash(asset, parameters)
        template = Template(DataResult, where={"queryHash": eq(query_hash)})
        live = self._read_trusted(template)
        if live is not None:
            self.cache_hits += 1
            return Fetched(live, True)
        answer = _Answer()

        # Subscribe before writing the query so the answer cannot slip between the write and the
        # wait; the listener applies the same issuer filter.
        def on_event(event):
            if event.kind == WRITTEN and self._trusted(event.entry.issuer, event.entry.value):
                answer.accept(event.entry.value)
        with self.space.watch(template, on_event):
            self.queries_sent += 1
            self.space.write(DataQuery(query_hash, asset, parameters, self.requester), lease=self.query_lease)
            result = answer.wait(self.space, self.read_through, timeout, lambda: self._read_trusted(template))
        return None if result is None else Fetched(result, False)


def invoke(space: Space, card: dict, operation: str, params: dict, timeout="30s", invocation_id: str | None = None,
           lease="5m", read_through="100ms") -> AssetInvocationResult | None:
    """AssetInvocations.invoke (JS-C-10): writes an ``AssetInvocation`` for the
    card's asset into ``space`` (the connector's task space) and returns the
    ``AssetInvocationResult`` the card's issuer writes for it, or None at the
    timeout. A result from any other peer is ignored (ASF-009). The invocation
    id is minted here and carried in the entry; pass the earlier id as
    ``invocation_id`` to retry an invocation, which reaches the target under
    the same id (JS-C-04) and is answered from the connector's remembered
    result rather than a second run."""
    asset, issuer = str(card["asset"]), str(card["issuer"])
    invocation_id = invocation_id or str(uuid.uuid4())
    template = Template(AssetInvocationResult, where={"invocationId": eq(invocation_id)})

    def from_issuer() -> AssetInvocationResult | None:
        for e in space.entries(template, 16):
            if peer_of(e.issuer) == issuer:
                return e.value
        return None

    answer = _Answer()

    def on_event(event):
        if event.kind == WRITTEN and peer_of(event.entry.issuer) == issuer:
            answer.accept(event.entry.value)
    # Subscribe before writing so the answer cannot slip between the write and the wait; the
    # read-through finds a result that landed before the subscription (a retry of an answered one).
    with space.watch(template, on_event):
        space.write(AssetInvocation(asset, operation, params, invocation_id), lease=lease)
        return answer.wait(space, read_through, timeout, from_issuer)
