# agentspaces-python changelog

What changed in the Python client, newest first. The Java core's history is in `docs/dvit/CHANGELOG.md` of the AgentSpaces workspace.

## 0.7.0 (2026-11-28, with AgentSpaces 0.7.0)

Work since the 0.6.0 release, for 0.7.0 (SPEC v0.1.34 to v0.1.38, still wire version 3). The client goes with the AgentSpaces 0.7.0 release of 2026-11-28 and installs from a clone; nothing is on PyPI, and `pyproject.toml` still reads 0.6.0.

- **AgentCard `threads` (SPEC v0.1.38).** `bind(obj, threads=...)` names the conversations an agent answers, built with `chat_thread` and `chat_threads` (scopes `exact`, `tree` and `all`). The reader checks `threads` (at most 16, all distinct). The AppCard kind `dynamic` is accepted (in the working tree). A reader before v0.1.38 drops a card that carries either, so this is a flag day.
- **The peer runs on deadlines, two clocks and a process watchdog (SPEC v0.1.36 and v0.1.37).**
  - Space sweeps and aggregate rounds wait for their next deadline instead of a fixed 250 ms tick, and sleep while idle.
  - Local periods use the monotonic clock (`timesource.py`: `TimeSource`, `SystemTime`, `VirtualTime`). Wall deadlines re-anchor after a clock step, and a frozen process counts as a wake.
  - A PING is answered at once with an addressed ACK, including one carried in a relay frame. The self-advertisement names the seed it dialed in `relay.via`.
  - A seed link silent for 45 s is pinged, and dropped and redialed if still silent after 2 s (`links_silent`).
  - Seeds are dialed 250 ms apart and the first to answer wins. Failed rounds follow the 5, 10, 20, 30 s redial table, each spread by a tenth; a wake resets it.
  - A process watchdog (`watchdog.py`) reports slow or wedged loops. A TTL under 60 s warns, or is refused in strict mode (`ttl.py`).
- **Takes and relayed digests.** A result after a take has lapsed completes nothing and counts in `late_takes`. A dial-only peer answers its seed's `DIGEST`, and relayed digests only for displaced claims, paced per asker (`displaced_digest_answers`, `relayed_answers_paced`).
- **Replication by entry (SPEC v0.1.35).** The peer advertises `wire.horizon=1` and collects withdrawn entries at the per-entry horizon, sends a pull budget and reads `remainder`, and keeps the renewal rule (a renewal never shortens a lease). It runs no trie audit and does not advertise `wire.ae`.
- **A2UI 1.0 (SPEC v0.1.34).** The A2UI records and vectors follow A2UI 1.0. No v0.9.1 reading is kept.
