# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Seed endpoints (SPEC §5.5): a scheme, a host, and a port. A seed with no
scheme is ``tcp``, as it has always been for this client; ``tls`` dials TLS 1.3
with a channel certificate (SPEC §5.6, ``agentspaces.tls``)."""

import re
from typing import NamedTuple

# The transports this client dials, in the order it prefers them when a
# document or an advertisement lists several at one priority.
CLIENT_TRANSPORTS = ("tcp", "tls")

_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*)://(.+)$", re.IGNORECASE)


class Seed(NamedTuple):
    """One seed to dial: ``(host, port, scheme)``; equal to the plain tuple."""
    host: str
    port: int
    scheme: str = "tcp"

    @property
    def address(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.scheme}://{self.address}"


def seed_address(address: str) -> tuple:
    """``host:port`` (``[v6]:port``) as (host, port)."""
    text = str(address).strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"not a seed address: {address!r}")
    return host, int(port)


def parse_seed(value, default_scheme: str = "tcp") -> Seed:
    """A Seed from a Seed, a ``(host, port)`` or ``(host, port, scheme)`` tuple, or
    the text ``scheme://host:port`` (``host:port`` dials ``default_scheme``). A
    path after the port (``/aspace``) is refused: this client speaks no scheme
    that takes one."""
    if isinstance(value, Seed):
        return value
    if isinstance(value, (tuple, list)):
        if len(value) == 2:
            return Seed(str(value[0]), int(value[1]), default_scheme)
        if len(value) == 3:
            return Seed(str(value[0]), int(value[1]), str(value[2]).lower())
        raise ValueError(f"not a seed: {value!r}")
    text = str(value).strip()
    scheme = default_scheme
    match = _SCHEME.match(text)
    if match:
        scheme, text = match.group(1).lower(), match.group(2)
    if "/" in text:
        raise ValueError(f"a {scheme} seed takes no path: {value!r}")
    host, port = seed_address(text)
    return Seed(host, port, scheme)
