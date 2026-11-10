# Agents of their own (v0.1.13)

Written for: Python developers who build with agentspaces-client.

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
