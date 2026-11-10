# Bootstrap and invite keys

Written for: Python developers who build with agentspaces-client.

A peer that knows a beacon's URL joins through the beacon document (the
discovery SRAD §3.5, DB-X-01): `agentspaces/beacon.py` fetches it (https
unless `allow_plain`, at most 64 KiB), verifies its Ed25519 signature over the
canonical bytes under a key hashing to its `issuer` (and requires the pinned
`beacon_peer` when given), refusing a signed document unless it arrives as
exactly its canonical JSON with its signature and key in padded standard
base64 (HLC round seven, 2026-11-08), selects the group, verifies the founding
advertisement with the same four checks `join_by_group_id` applies, and dials
the group's `tcp` seeds in priority order. The verified founding is kept on
`peer.founding` and the founder is known for revocations.

```python
peer = Peer(Identity.generate(), None)
peer.bootstrap("https://agentspaces.corp.example/.well-known/agentspaces/beacon.json",
               group_id="aspace://z7f3a...", beacon_peer="z6Mk...")   # fetch, verify, dial the seeds
```

`bootstrap` keeps asking inside a budget, as the Java join by id does.
`timeout` (3 s) bounds one attempt, one fetch of the document or one dial of
one seed, and `join_timeout` (10 s) bounds the whole call. A first attempt
that succeeds fetches once and dials once. Otherwise the call works in slices
of 1 s, 2 s, 4 s, then 5 s each: at the start of each slice it fetches the
document again when the previous fetch failed or named no `tcp` seed, and it
dials again, once per slice, every seed that refused, so a beacon or a seed
that starts a few seconds after the peer (the usual case in Compose and
Kubernetes) is reached on a later slice. A refusal (a document or a founding
that does not verify, a founding for another id) raises `ValueError` at once.
When the budget runs out the call raises `BootstrapTimeout`, a `TimeoutError`
(so an `OSError`), whose message carries the number of fetches, the seeds
dialed and how many connected, and the last error.

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
