# About agentspaces-client (Python)

Written for: Python developers who build with agentspaces-client.

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

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
