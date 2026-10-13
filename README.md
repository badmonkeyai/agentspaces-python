# agentspaces-client (Python)

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
`@OrderedTake` need the ticket and the ordered log and are not here.
`Space.entries(template)` is the metadata view (`Entry`: `entry_id`,
`value`, `tags`, `issuer`, `expires_at_millis`, `taken`), and every event
carries its entry's tags. A watch, and `@space_notify(on=[...])`, deliver
five kinds: `WRITTEN`, `TAKEN`, `COMPLETED`, `EXPIRED` (the write lease
lapsed while the entry was open: a leased entry as a timer), and
`REAPPEARED` (a take claim lapsed), the last two judged by a sweep on the
clock, once per entry and lapse. A `Contribution(epoch, value)` return
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
task space with the shared-fields correlation). A dial-only peer sends
frames to the members it can reach (the seed it dialed), never to a member
it only heard of. Not here: the ordered log (the Raft client), so ordered
takes, reduces, and the fleet-wide LEASED and ORDERED join modes; the
gossip-learning exchange (its payload is encoded and golden-pinned); and
MAJORITY_GOSSIP.

`demo_council_worker.py` is the whole of it against the Java
`CouncilFleet` coordinator: tasks taken, the council ballot cast, the epoch
contributed to, the semantic query answered, the remote action served.
`tests/test_layer34.py`, `tests/test_layer4.py`, and `tests/test_verbs.py`
prove each piece without a socket.

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
