# Run it

Written for: Python developers who build with agentspaces-client.

```
pip install cryptography pytest
python -m pytest tests/            # golden vectors, founding/join, adversarial, codec, layers 3 and 4, tls

# live demo against a Java fleet:
mvn -q -pl examples/example-02-research-fleet exec:java -Dexec.args="worker 7461 0"
python demo_join_fleet.py 127.0.0.1 7461
```

The demo prints the Finding a Java worker produced from the Python-written
task. The client keeps the dial-only posture (no listener, no advertised
endpoints), which is exactly the NAT-restricted peer profile from spec §5.4.
