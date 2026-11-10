# The cross-language guarantee

Written for: Python developers who build with agentspaces-client.

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
