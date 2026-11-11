# Layout

Written for: Python developers who build with agentspaces-client.

`agentspaces/cbor.py` writes and reads the AgentSpaces wire encoding, the
image of the Java codec's Jackson CBOR (indefinite maps in field order,
definite arrays and byte strings, shortest heads, float64 doubles, explicit
nulls), and decodes nothing else. `records.py` holds the protocol records this
client reads, with their fields in Java's order, the capability pipe payloads
included, and checks every one it decodes from
the network. `identity.py` holds Ed25519 identity, the self-certifying
derivations (PeerID, GroupID, SpaceID), and the founding-document half of
spec §4.4/§5.1: `found_group` mirrors Java `GroupFounding.found`, and
`verify_signed_group_ad` is the four-check receiver rule (founder key hashes
to the issuer, signature over the canonical founding fields, founding document
derives to `group`, `id` names that group). `wire.py` builds signed envelopes,
membership advertisements, entry-write deltas, the `GROUP_AD_WANT`/`GROUP_AD`
bootstrap frames, and the `aspace:cap/aggregate` and `aspace:cap/gossip-learn`
pipe payloads; `decode_frame` drops any envelope whose `ver` is not 3 before
verifying its signature (spec §9). `peer.py` is the TCP peer.
