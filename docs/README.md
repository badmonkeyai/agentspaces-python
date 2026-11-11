# agentspaces-python documents

Written for: anyone who read the README and wants the rest of the story.

The README is short by design: what this is, the quick start, and how to add it to a build. Everything else lives here, one topic per document.

| Document | Written for | What it holds |
|---|---|---|
| [About agentspaces-client (Python)](about.md) | Python developers who build with agentspaces-client | What AgentSpaces is, and what this project adds to it. |
| [Layout](layout.md) | Python developers who build with agentspaces-client | `agentspaces/cbor.py` writes and reads the AgentSpaces wire encoding, the image of the Java codec's Jackson CBOR (indefinite maps in field order. |
| [Joining by GroupID](joining-by-group-id.md) | Python developers who build with agentspaces-client | A peer that knows only a self-certifying GroupID and one seed endpoint joins with `Peer.join_by_group_id(host, port, group_id, timeout=10.0)`. |
| [Bootstrap and invite keys](bootstrap-and-invite-keys.md) | Python developers who build with agentspaces-client | A peer that knows a beacon's URL joins through the beacon document: `agentspaces/beacon.py` fetches it. |
| [Agents of their own (v0.1.13)](agent-identities.md) | Python developers who build with agentspaces-client | A Python peer can give each agent a key of its own, certified by the peer and renewed at half-life, so the fleet stores its work `AGENT_ATTESTED`. |
| [The cross-language guarantee](the-cross-language-guarantee.md) | Python developers who build with agentspaces-client | `tests/golden.json` holds byte vectors the Java codec produced for fixed inputs, and `tests/test_golden.py`, `tests/test_founding.py`. |
| [Layers 3 and 4, Python-shaped](spaces-agents-and-capabilities.md) | Python developers who build with agentspaces-client | The same AgentSpace and the same capability services the Java annotations bind, as decorators, dataclasses, and plain functions. |
| [Run it](run-it.md) | Python developers who build with agentspaces-client | The demo prints the Finding a Java worker produced from the Python-written task. |
| [On a network](on-a-network.md) | Python developers who build with agentspaces-client | The client ignores the frame kinds it does not speak and survives every hostile frame (ROBUSTNESS.md). |
| [Scope](scope.md) | Python developers who build with agentspaces-client | This client implements what protocol validation needs, and enough of Layer 3 to work: identity, envelopes. |
