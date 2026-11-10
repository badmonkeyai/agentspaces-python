# agentspaces-client (Python)

**AgentSpaces for Python**, from Bad Monkey AI. A Python peer holds its own key, dials a Node or JVM seed, and takes work from a shared space under the same lease rules as every other peer, with agents written as decorated methods and entries as dataclasses.

## Quick start: build your first agent in Python

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. In Python the method sits on a class marked with decorators, and entries are dataclasses. A Python peer is a real member of the fleet: it holds its own Ed25519 identity, signs what it writes, and takes work under the same lease rules as a JVM peer. It dials out to a seed, so the quick start starts one.

**1. Install the client.** Python 3.11 or newer.

```
pip install agentspaces-client
```

Until the package is on PyPI, install it from a clone: `pip install ./agentspaces-python`.

**2. Start a seed.** Any AgentSpaces peer with a listener will do. The Node service host is a seed in one command and needs no code. Its fleet file has the same shape as the Spring starter's YAML. The `dev-local` profile signs every frame over plain loopback TCP, which is what this client dials. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local          # signed frames on loopback TCP; never on a shared network
  bind: 127.0.0.1:7700
  tick-millis: 250
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

The first run creates a `keys/` directory beside `seed.yaml` to hold the seed's identity. From a clone of `agentspaces-typescript` (Node 22 or newer), run `node packages/node/build/src/cli.js run seed.yaml` instead.

**3. Write the agent.** `@entry` names each entry's wire schema, and the field names match the wire. `@space_take` says which space the method takes from and how long it may hold an entry.

`fulfiller.py`:

```python
import sys
import threading
import time
from dataclasses import dataclass

from agentspaces.agents import Binder, agent, space_take
from agentspaces.identity import Identity, group_id_from_founding
from agentspaces.peer import Peer
from agentspaces.space import Space, Template, entry


@entry("shop.Order#v1")     # the wire name; field names match the wire too
@dataclass
class Order:
    orderId: str
    item: str


@entry("shop.Shipment#v1")
@dataclass
class Shipment:
    orderId: str
    item: str
    by: str


@agent("fulfiller", description="Ships orders")
class Fulfiller:
    @space_take("orders", lease="30s")
    def ship(self, order: Order) -> Shipment:
        return Shipment(order.orderId, order.item, "fulfiller")


identity = Identity.generate()
peer = Peer(identity, group_id_from_founding(b"shop-v1"))
peer.connect("127.0.0.1", 7700)                     # the seed
time.sleep(1.0)
Binder(peer, agent=identity.renewing_subordinate("fulfiller", "PT24H")).bind(Fulfiller())

if len(sys.argv) > 1:                               # python fulfiller.py kite
    orders = Space(peer, "orders")
    orders.write(Order("o-1", sys.argv[1]))
    print(orders.read(Template(Shipment), timeout="30s"))
    peer.close()
else:
    threading.Event().wait()
```

**4. Run two instances.** The first only ships. The second also writes an order, prints the shipment, and exits.

```
python fulfiller.py
python fulfiller.py kite
```

Either instance can take the order, because both run the same agent.

**5. Kill one.** Add `print("shipping", order.orderId, flush=True)` and `time.sleep(10)` at the top of `ship`. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30 second lease lapses.

The [documents](docs/README.md) add the rest: joining by GroupID, bootstrap and invite keys, agents with their own keys, the cross-language guarantee, and layers 3 and 4 in Python.

## What it is

- A pure-Python peer that speaks the AgentSpaces wire protocol, checked against the shared golden vectors.
- Decorators for every verb the Python binder runs, and certified agents with keys of their own.
- The capability clients: vote, aggregate, semantic discovery, remote actions, the ordered log, and the content swarm.
- Persistent values, a reader for databases on refs, and content stores.
- Python 3.11 or newer; one dependency, `cryptography`; dials `tcp` and `tls`.

## Add it to your build

```
pip install agentspaces-client
```

Until the package is on PyPI, install it from a clone: `pip install ./agentspaces-python`. [Layout](docs/layout.md) shows the package, and [Run it](docs/run-it.md) runs the tests and the demos.

## Where to read next

1. **[The developer guide](https://www.badmonkey.ai/agentspaces/developer-guide.html#ol-python)**: its Python section maps this client onto the Java chapters.
2. **[The Python guide](https://www.badmonkey.ai/agentspaces/python-guide.html)**: a newcomer's walk from a seed and a first agent to capabilities, values that change, and stores.
3. **[The examples](https://github.com/badmonkeyai/AgentSpaces/tree/main/examples)**: the core's numbered examples, several with Python workers, such as the cross-language council of example 02.
4. **[The documents](docs/README.md)**: everything this README leaves out, one topic per document, each with the reader it is written for.

## License

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
