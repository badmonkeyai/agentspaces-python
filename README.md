# agentspaces-client (Python)

The non-JVM wire-compatible client (spec §13, M3): a Python peer that speaks
the AgentSpaces wire protocol (wire version 2) directly. Nothing on the wire
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
pipe payloads; `decode_frame` drops any envelope whose `ver` is not 2 before
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

## Run it

```
pip install cryptography pytest
python -m pytest tests/            # golden vectors, founding/join, adversarial, codec

# live demo against a Java fleet:
mvn -q -pl examples/example-02-research-fleet exec:java -Dexec.args="worker 7461 0"
python demo_join_fleet.py 127.0.0.1 7461
```

The demo prints the Finding a Java worker produced from the Python-written
task. The client keeps the dial-only posture (no listener, no advertised
endpoints), which is exactly the NAT-restricted peer profile from spec §5.4.

## Scope

This client implements what protocol validation needs, and enough of Layer 3
to work: identity, envelopes, self-certifying group founding and join by
GroupID, membership participation, space writes, anti-entropy reads, and
exclusive takes under the LEASE_RACE claim lattice (signed claims, settle
window, the same total order as `TakeClaim.merge`, monotone completion). `demo_python_worker.py` proves the whole loop: a Python
worker drains the six tasks a Java coordinator publishes, and the coordinator
receives all six findings. The aggregate and gossip-learn pipe payloads are
encoded here and pinned by the golden vectors, but the capability protocols
themselves (epochs, offer/accept exchange) and content-addressed payloads stay
Java-side for now; each is the same pattern (a CBOR body on an existing kind)
when a use case calls for it.
