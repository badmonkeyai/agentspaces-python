# Joining by GroupID

Written for: Python developers who build with agentspaces-client.

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
