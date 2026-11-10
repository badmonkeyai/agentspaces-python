# Scope

Written for: Python developers who build with agentspaces-client.

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
gossip-learn exchange stays Java-side; it is the same pattern (a CBOR body on
an existing kind) when a use case calls for it. Content-addressed payloads
(blocks and swarm artifacts) are read and written here since v0.1.23.
