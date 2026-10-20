# agentspaces-client (Python)

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

## Quick start: build your first agent in Python

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. In Python the method sits on a class marked with decorators, and entries are dataclasses. A Python peer is a real member of the fleet: it holds its own Ed25519 identity, signs what it writes, and takes work under the same lease rules as a JVM peer. It dials out to a seed, so the quick start starts one.

**1. Install the client.** Python 3.11 or newer.

```
pip install agentspaces-client
```

Until the package is on PyPI, install it from a clone: `pip install ./agentspaces-python`.

**2. Start a seed.** Any AgentSpaces peer with a listener will do. The Node service host is a seed in one command and needs no code. Its fleet file has the same shape as the Spring starter's YAML. The `dev-local` profile signs every frame over plain loopback TCP, which is what this client dials. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local          # signed frames on loopback TCP; never on a shared network
  bind: 127.0.0.1:7700
  tick-millis: 250
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

The first run creates a `keys/` directory beside `seed.yaml` to hold the seed's identity. From a clone of `agentspaces-typescript` (Node 22 or newer), run `node packages/node/build/src/cli.js run seed.yaml` instead.

**3. Write the agent.** `@entry` names each entry's wire schema, and the field names match the wire. `@space_take` says which space the method takes from and how long it may hold an entry.

`fulfiller.py`:

```python
import sys
import threading
import time
from dataclasses import dataclass

from agentspaces.agents import Binder, agent, space_take
from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer
from agentspaces.space import Space, Template, entry


@entry("shop.Order#v1")     # the wire name; field names match the wire too
@dataclass
class Order:
    orderId: str
    item: str


@entry("shop.Shipment#v1")
@dataclass
class Shipment:
    orderId: str
    item: str
    by: str


@agent("fulfiller", description="Ships orders")
class Fulfiller:
    @space_take("orders", lease="30s")
    def ship(self, order: Order) -> Shipment:
        return Shipment(order.orderId, order.item, "fulfiller")


identity = Identity.generate()
peer = Peer(identity, group_id_from_founding(b"shop-v1"))
peer.connect("127.0.0.1", 7700)                     # the seed
time.sleep(1.0)
Binder(peer, agent=identity.renewing_subordinate("fulfiller", "PT24H")).bind(Fulfiller())

if len(sys.argv) > 1:                               # python fulfiller.py kite
    orders = Space(peer, "orders")
    orders.write(Order("o-1", sys.argv[1]))
    print(orders.read(Template(Shipment), timeout="30s"))
    peer.close()
else:
    threading.Event().wait()
```

**4. Run two instances.** The first only ships. The second also writes an order, prints the shipment, and exits.

```
python fulfiller.py
python fulfiller.py kite
```

Either instance can take the order, because both run the same agent.

**5. Kill one.** Add `print("shipping", order.orderId, flush=True)` and `time.sleep(10)` at the top of `ship`. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30 second lease lapses.

The sections below add the rest: joining by GroupID, bootstrap and invite keys, agents with their own keys, the cross-language guarantee, and layers 3 and 4 in Python.

## About agentspaces-client (Python)

The non-JVM wire-compatible client (spec §13, M3): a Python peer that speaks
the AgentSpaces wire protocol (wire version 3) directly. Nothing on the wire
is Java-specific, CBOR (RFC 8949) framing, Ed25519 (RFC 8032) signatures, and
URI naming, and this client is the proof: it joins a running Java fleet over
TCP, introduces its self-advertisement once and stays a live member by
answering SWIM pings, writes signed entries into a replicated space that Java
workers verify and take, and reads the space back through anti-entropy. (A
production client would re-lease its self-advertisement on the advertisement
TTL; the demo client leans on ping liveness and does not.)

## Layout

`agentspaces/cbor.py` encodes byte-identically to the Java codec's Jackson
CBOR (indefinite maps in field order, definite arrays and strings, minimal
integers, float64 doubles, explicit nulls) and decodes both indefinite and
definite forms. `identity.py` holds Ed25519 identity, the self-certifying
derivations (PeerID, GroupID, SpaceID), and the founding-document half of
spec §4.4/§5.1: `found_group` mirrors Java `GroupFounding.found`, and
`verify_signed_group_ad` is the four-check receiver rule (founder key hashes
to the issuer, signature over the canonical founding fields, founding document
derives to `group`, `id` names that group). `wire.py` builds signed envelopes,
membership advertisements, entry-write deltas, the `GROUP_AD_WANT`/`GROUP_AD`
bootstrap frames, and the `aspace:cap/aggregate` and `aspace:cap/gossip-learn`
pipe payloads; `decode_frame` drops any envelope whose `ver` is not 3 before
verifying its signature (spec §9). `peer.py` is the TCP peer.

## Joining by GroupID

A peer that knows only a self-certifying GroupID and one seed endpoint joins
with `Peer.join_by_group_id(host, port, group_id, timeout=10.0)` (spec §5.1,
§10.1): it dials the seed, sends an unaddressed `GROUP_AD_WANT` naming the
group, waits for a `GROUP_AD` whose `SignedGroupAdvertisement` body passes
`verify_signed_group_ad` and derives to exactly that GroupID, ignores every
answer that fails, and only then publishes its self-advertisement. It raises
`TimeoutError` when no seed served a verified document in time, so a hostile
seed can delay a join and can never substitute a policy. The verified document
is kept on `peer.founding`.

```python
from agentspaces.identity import Identity
from agentspaces.peer import Peer

peer = Peer(Identity.generate(), None)
founding = peer.join_by_group_id("127.0.0.1", 7461, "zB3YQedDoaZcNYonit2VWo6gnLjgyyi5YGet8YTxcceN7")
print(founding["advertisement"]["name"])
```

`Peer(identity, group)` with a literal GroupID (`group_id_from_founding` of a
shared founding string) remains the configured-group path and needs no fetch.

## Bootstrap and invite keys

A peer that knows a beacon's URL joins through the beacon document (the
discovery SRAD §3.5, DB-X-01): `agentspaces/beacon.py` fetches it (https
unless `allow_plain`, at most 64 KiB), verifies its Ed25519 signature over the
canonical bytes under a key hashing to its `issuer` (and requires the pinned
`beacon_peer` when given), selects the group, verifies the founding
advertisement with the same four checks `join_by_group_id` applies, and dials
the group's `tcp` seeds in priority order. The verified founding is kept on
`peer.founding` and the founder is known for revocations.

```python
peer = Peer(Identity.generate(), None)
peer.bootstrap("https://agentspaces.corp.example/.well-known/agentspaces/beacon.json",
               group_id="aspace://z7f3a...", beacon_peer="z6Mk...")   # fetch, verify, connect_any(seeds)
```

`connect_any(seeds)` dials `(host, port)` pairs in order until one accepts
(a hostname is resolved to every address, each a seed) and remembers them
all: a lost socket fails over to the next seed inside the reconnect window,
and a bootstrapped peer re-fetches the document once when the window would
expire with nothing reachable. `connect(host, port)` is unchanged underneath.

```python
peer.connect_any([("seed-a.corp.example", 7500), ("seed-b.corp.example", 7500)])
```

A group for friends is joined with an invite key (SRAD §3.8, appendix F,
DB-X-07) in either rendering, `aspace-inv1-<code>-<secret>[-<delegation>][@host]`
or `https://<host>/j/<code>#<secret>[.<delegation>]`. `agentspaces/social.py`
derives from the secret, by HKDF-SHA256 under `aspace-inv1`, the invite
signing key, the content key (epoch 0), and the lookup code; `join_invite`
fetches the social beacon's document at `/j/<code>`, takes the founder's
delegation from the key or the document's `invite` field, signs this peer's
id with the invite key into a delegated credential carried in the
self-advertisement's resource hints under `aspace:join`, verifies the
founding against the delegation's group, and connects to the seeds.

```python
content_key, group_id = peer.join_invite("aspace-inv1-N9BAGDAC8ZW79GD8-000G40R40M30E209185GR38E1W")
save(peer.pinned_invite)   # the key pinned to the delegation joined under; join with it next time
```

Keep `peer.pinned_invite` and pass it to `join_invite` on the next start. The
members that admitted this peer re-admit it after the key's window only under
the same credential (SPEC §5.1, v0.1.20), and the beacon document may carry a
newer delegation by then. The client no longer refuses an expired delegation
itself: re-admitting a peer that joined in time, and refusing a newcomer, is
the members' call.

Every derivation and CBOR shape is bit-identical to Java's `GroupSecret`,
`InviteKey`, and `JoinCredentials`; `tests/social-golden.json` (a copy of
`agentspaces-bootstrap-social/golden/social-golden.json`) pins the code, the
keys, the delegation, the credential, both hashes, and both renderings, and
`tests/test_beacon.py` pins a document Java signed. The client does not yet
decrypt sealed spaces, so the content key is returned for the caller.

## Agents of their own (v0.1.13)

A Python peer can give each agent a key of its own, certified by the peer and
renewed at half-life, so the fleet stores its work `AGENT_ATTESTED` (SPEC §4.2).
Receivers judge a certificate at the signing time of what it certifies, so an
agent's history stays verifiable after its certificate lapses.

```python
identity = Identity.load_or_create("./keys")              # peer.key + peer.pub, Java's layout
agent = identity.renewing_subordinate("py-worker", "PT24H")
peer = Peer(identity, group)
entry_id = peer.take_entry("tasks", TASK_TYPE, agent=agent)
peer.complete_entry("tasks", entry_id, agent=agent)       # an attested take completes as its agent
peer.write_entry("tasks", FINDING_TYPE, finding, agent=agent)
```

- **Attested transitions.** An agent-attested entry's transitions must be signed
  by the agent (A6). The peer's own signature is refused for them, as Java refuses it.
- **Persistent agent keys.** `Identity.agent_keys(dir, peer_id, name)` loads or mints
  an agent key in the layout of Java's `AgentKeystore`. `identity.save_pkcs8(path)`
  writes a key as PKCS#8 DER, atomically and owner-only (0600).
- **Revocations.** The peer applies the group's revocations at merge:
  - It reads the `revocations` and `credential-revocations` streams. A late joiner
    learns the revocations issued before it arrived: the peer pulls both streams once
    on joining, and every `pull_space` names them too.
  - It accepts founder-rooted peer revocations, and agent and agent-key revocations
    from the founder or the agent's own peer. CA-rooted revocations are ignored.
  - A founder-rooted peer revocation needs the founder known. `join_by_group_id`
    sets it from the verified founding document; a peer on a literal group passes
    `Peer(..., founder=<founder PeerID>)`. Without it, peer revocations are ignored.
  - It enforces the freeze rule on every incoming state, held entries included: a
    retired agent's earlier history still folds, its later writes and renewals do
    not, and a revoked holder's claims and completions are refused.
- **What the client does not do yet.** Content-key epochs (`keyEpoch`) and per-agent
  key wrap are pinned by the golden vectors here, but the client does not decrypt
  sealed spaces.

## The cross-language guarantee

`tests/golden.json` holds byte vectors the Java codec produced for fixed
inputs, and `tests/test_golden.py`, `tests/test_founding.py`, and
`tests/test_adversarial.py` prove the Python encoder reproduces every one
exactly, signatures included, because RFC 8032 signing is deterministic. The
v0.1.10 vectors cover the founding document and its derived GroupID, the
signed group advertisement, the `GROUP_AD_WANT`/`GROUP_AD` frames, two
adversarial founding documents every client must refuse, an AgentCard with
`spaceBindings`, a SpaceAdvertisement with `admission` and `replication`, one
aggregate `Frame` per variant (including a negative int64 roster token and
float64 histogram buckets), and one gossip-learn `Exchange` per kind.

Regenerate the vectors after any wire-shape change. The generator,
`agentspaces/tools/golden/GoldenVectors.java`, is a single-file program
outside the Maven reactor that runs against the module classes plus the
capabilities module's runtime dependencies, which Maven assembles (see
`agentspaces/docs/BUILD-ENVIRONMENTS.md`, "Regenerating the golden vectors").
From the `agentspaces/` Maven root, after
`mvn -q install -DskipTests`:

```
mvn -q -pl agentspaces-capabilities dependency:build-classpath \
    -Dmdep.outputFile=/tmp/golden-cp.txt
CP="agentspaces-capabilities/target/classes:$(cat /tmp/golden-cp.txt)"
javac -cp "$CP" -d /tmp/golden tools/golden/GoldenVectors.java
java -cp "/tmp/golden:$CP" GoldenVectors ../agentspaces-spec/golden.json
../agentspaces-spec/sync-golden.sh
```

When the output file already exists the generator reloads the golden private
key (and the adversarial forger's key) from it, so signatures stay stable and
only vectors whose inputs changed differ between regenerations. The Java
`GoldenVectorsConformanceTest` and the TypeScript suite read the same file.

## Layers 3 and 4, Python-shaped

The same AgentSpace and the same capability services the Java annotations
bind, as decorators, dataclasses, and plain functions
(`L3L4-COVERAGE.md` §6.4). An `@entry` class names its wire schema; a
`Space` holds the layer-3 verbs; a `Template` carries the Java matchers
(`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in_`, `contains`, `is_null`,
`not_null`, or any callable) over fields and tags; `watch` delivers
`WRITTEN`, `TAKEN`, and `COMPLETED` once per entry; `TakeContext.current()`
is the take a worker runs under.

```python
from agentspaces.space import Space, Template, entry, gte
from agentspaces.agents import Binder, agent, ballot, bid_function, on_decision, on_estimate, space_notify, space_take

@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1")
@dataclass
class ResearchTask:
    topic: str
    priority: int

@agent("researcher", description="Researches topics", goals=["research"])
class Researcher:
    @space_take("tasks", lease="30s", where={"priority": gte(1)})     # take, call, complete with the result
    def research(self, task: ResearchTask) -> Finding: ...

    @space_notify("tasks")                                            # once per entry, never consuming it
    def audit(self, finding: Finding) -> None: ...

    @bid_function("tasks")                                            # the AUCTION price
    def price(self, task: ResearchTask) -> float: ...

    @ballot("votes", prefix="council:")                               # one ballot per proposal, None abstains
    def judge(self, proposal: Proposal) -> str | None: ...

    @on_decision("votes", prefix="council:")                          # once, when the quorum closes it
    def record(self, decision: Decision) -> None: ...

bound = Binder(peer, agent=identity.renewing_subordinate("py-worker", "PT24H")).bind(Researcher())
```

`Binder.bind` runs the loops the Java `AgentBinder` runs: one thread per
take, reactions off the delivery thread, the ballot cast once per proposal,
the decision once at quorum, and the AgentCard (name, description, goals,
consumes, produces, space bindings, declared actions, the agent certificate)
published on the `ads` stream on bind. `vote.propose`, `vote.cast`, and
`vote.decision` are the procedural forms; the tally rule is Java's.

The return conventions are the Java binder's (ISSUE-WorkflowVerbs,
ISSUE-Motion): `None` writes nothing; `Tagged(value, {"region": "eu"})` is
written with its tags; a list or tuple is the fork, each element written on
its own after the take completes; a `Motion(proposal_id, question, options,
quorum, space=None)` opens a vote once per proposal id in its space or the
binder's `vote_space`. Two more cues: `@propose(space, vote=..., options=...,
quorum=..., prefix=..., key=[...])` opens a vote from a cue once per key (the
method returns the question, `None` to ask nothing, or a `Motion`), and
`@space_join(space, key=..., parts=[Part(Fraud), Part(Coverage), Part(Claim,
optional=True)])` is the LOCAL join: once per key, when every required part
is readable, the method receives a `Joined` (`key`, `get`, `find`, `all`,
`has`). The fleet-wide LEASED and ORDERED join modes, `@SpaceReduce`, and
the decorated `@OrderedTake` need the ticket and the Raft voter and are not
here; an ordered take runs through `Space.take(template,
through=OrderedLog(Pipes(peer)))` instead (below).
`Space.entries(template)` is the metadata view (`Entry`: `entry_id`,
`value`, `tags`, `issuer`, `expires_at_millis`, `taken`), and every event
carries its entry's tags. A watch, and `@space_notify(on=[...])`, deliver
five kinds: `WRITTEN`, `TAKEN`, `COMPLETED`, `EXPIRED` (the write lease
lapsed while the entry was open: a leased entry as a timer), and
`REAPPEARED` (a take claim lapsed), the last two judged by a sweep on the
clock, once per entry and lapse. `Space.notify(template, callback, lease)`
is the leased push subscription of the Java space (JS-V-01): it lapses on
the peer's clock unless `renew()`ed, and the binder renews a notify's, a
propose's, and a join part's at half-lease while the agent is bound. Takes
and `read(timeout=...)` wake on folds rather than polling: at most one
anti-entropy pull per settle window, none while folds arrive (JS-V-02).
The decorators and `Part` take `filters=["priority>=3", "region in eu,us"]`,
the portable grammar of SPEC §7.2, beside the `where` matchers (JS-V-03).
A `Contribution(epoch, value)` return
starts the epoch on the binder's aggregate, and `produces=[...]` on a take or
notify names the card's produced types when the return annotation does not. Maps a signature covers (`tags`, `costHints`,
`spaceBindings`) are sorted by `cbor.canonical_map` (wire version 3).

`agentspaces.capabilities` speaks the layer-4 pipes (`PIPE_DATA` frames
addressed to a member): `Aggregate` (push-sum `avg`, roster `sum` and
`count`, `min`, `max`, `estimate`, `Settle`, `await_settled`, `on_estimate`,
and the `@on_estimate` decorator), `Semantic` (the hashing embedder with
Java's `String.hashCode` so the vectors agree, `query`, `remote_query` over
the query pipe, and answers to other members' queries), and `remote`
(`actions` from the cards the `ads` stream carried, `invoke` through the
task space with the shared-fields correlation), and `OrderedLog` (the Raft
client of `aspace:cap/ordered-log`, JS-V-05: `take` submits a signed
`ClientSubmit` claim command to the leader the advertisements name, or to any
reachable member that forwards it under its leader hint, and holds the entry
once the committed claim folds back from the space; the Raft frame union and
the ClientSubmit are pinned by the golden `raft_*` vectors), and `connect`
(the agent side of the connector protocol, JS-C-14: `DataQuery`,
`DataResult`, `AssetChange`, `AssetInvocation`, and `AssetInvocationResult`
as `@entry` dataclasses in Java record order, pinned by the golden
`data_query_cbor`, `data_result_cbor`, `asset_change_cbor`,
`asset_invocation_cbor`, and `asset_invocation_result_cbor` vectors, with
`canonical_hash` agreeing with `DataQueryEntries.canonicalHash`;
`DataQueryClient.fetch(asset, parameters, timeout)` pull-once by canonical
hash, a live result under the hash answering at once and a `DataQuery`
written otherwise, counting `cache_hits` and `queries_sent`;
`connect.invoke(space, card, operation, params, timeout, invocation_id=None)`
writing an `AssetInvocation` and returning the `AssetInvocationResult` the
card's issuer writes, the same `invocation_id` on a retry so the target runs
once; `asset_cards(peer, asset=None)` and `invoke_ops(card)` over the ads
stream; a result counts only from the named `trusted_connectors`, the
caller's own `trust(issuer_peer, asset)` rule, or, for an invocation, the
card's issuer; readers drop fields they do not know, JS-F-06; the connector
runtime itself stays in Java and TypeScript). MAJORITY_GOSSIP
is `vote.cast_preference` and `vote.leader` over the aggregate's push-sum
shares (JS-V-04), the epochs Java's `VoteCapability` names. A dial-only peer
sends frames to the members it can reach (the seed it dialed), never to a
member it only heard of. Not here: the Raft voter (JS-F-18), so reduces and
the fleet-wide LEASED and ORDERED join modes; the gossip-learning exchange
(its payload is encoded and golden-pinned); and every transport but tcp (the
client skips `ws`, `wss`, `http`, `https`, `webrtc`, and `dtls` endpoints,
JS-N-05).

`demo_council_worker.py` is the whole of it against the Java
`CouncilFleet` coordinator: tasks taken, the council ballot cast, the epoch
contributed to, the semantic query answered, the remote action served.
`tests/test_layer34.py`, `tests/test_layer4.py`, `tests/test_verbs.py`,
`tests/test_verbs_residency.py` (JS-V-01, JS-V-02, JS-V-04, the mixed-scheme
fleet), `tests/test_ordered.py` (JS-V-05 against a simulated log), and
`tests/test_connect.py` (JS-C-14 against a simulated connector: the golden
bytes, a query answered and the identical one served from the space, a
result accepted only from a trusted connector, an invocation answered only
by the card's issuer, a retry that never runs the target again) prove each
piece without a socket; `tests/workers/ordered_worker.py` is the worker the
Java `PythonOrderedTakeTest` spawns against three Java voters, and
`tests/workers/connect_worker.py` the one `PythonConnectorClientTest`
(agentspaces-connect-core) spawns against a Java `ConnectorRuntime`.

## Run it

```
pip install cryptography pytest
python -m pytest tests/            # golden vectors, founding/join, adversarial, codec, layers 3 and 4

# live demo against a Java fleet:
mvn -q -pl examples/example-02-research-fleet exec:java -Dexec.args="worker 7461 0"
python demo_join_fleet.py 127.0.0.1 7461
```

The demo prints the Finding a Java worker produced from the Python-written
task. The client keeps the dial-only posture (no listener, no advertised
endpoints), which is exactly the NAT-restricted peer profile from spec §5.4.

## On a network

The client is generous in what it accepts and cautious in what it sends
(ROBUSTNESS.md). Every verified frame passes a `FrameFilter` first: a stamp
older than five minutes is stale, one further ahead than the HLC drift bound is
refused, and a sender-and-stamp pair seen before is a replay; all three are
dropped without a reply and counted (`peer.frames.stale`, `.ahead`,
`.replayed`). A kind this client does not speak is counted in
`peer.ignored_kinds`, a body that does not decode in `peer.malformed_frames`,
and the reader goes on. A lost socket is a hiccup, not the end: the peer
re-dials the seed every `reconnect_interval_s` (5 s) for `reconnect_window_s`
(10 min), then introduces itself again and pulls again what it had pulled
(revocations, advertisements, spaces), counting in `peer.reconnects`; a `take`
in flight keeps polling across the gap. `close()` by the owner is final.
`tests/test_robustness.py` pins each case against a fake seed over TCP.

## Scope

This client implements what protocol validation needs, and enough of Layer 3
to work: identity, envelopes, self-certifying group founding and join by
GroupID, membership participation, space writes, anti-entropy reads, and
exclusive takes under the LEASE_RACE claim lattice (signed claims, settle
window, the same total order as `TakeClaim.merge`, monotone completion). `demo_python_worker.py` proves the whole loop: a Python
worker drains the six tasks a Java coordinator publishes, and the coordinator
receives all six findings. Above the wire, `agentspaces.space`,
`agentspaces.agents`, and `agentspaces.capabilities` carry the layer 3 and 4
programming model (the section above): the push-sum aggregate, semantic
discovery, and remote actions speak their pipe protocols here, and
`demo_council_worker.py` proves them against the Java council. The
gossip-learn exchange and content-addressed payloads stay Java-side; each is
the same pattern (a CBOR body on an existing kind) when a use case calls for it.
