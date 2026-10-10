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
"""Semantic discovery (SPEC §8, SemanticDiscovery) from Python: the hashing
embedder the Java default uses, byte-for-byte the same vectors (Java's
``String.hashCode`` over the same tokens), local ranking of the cached
advertisements, and the query pipe to other members."""

from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass

from .. import cbor

TYPE = "aspace:cap/semantic-discovery"
MIN_SCORE = 0.2
_TOKENS = re.compile(r"[^\w#/.-]+", re.UNICODE)


def java_hash(text: str) -> int:
    """Java's String.hashCode: UTF-16 code units, 31-multiplicative, int32."""
    h = 0
    units = text.encode("utf-16-be")
    for i in range(0, len(units), 2):
        h = (31 * h + ((units[i] << 8) | units[i + 1])) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h


class HashingEmbedder:
    """HashingEmbedder: a signed bag of hashed tokens, L2-normalized."""

    identity = "hashing"

    def __init__(self, dimensions: int = 256):
        if dimensions <= 0:
            raise ValueError("dimensions must be positive")
        self.dimensions = dimensions

    def embed(self, text: str | None) -> list[float]:
        vector = [0.0] * self.dimensions
        if text is None:
            return vector
        for token in _TOKENS.split(text.lower()):
            if not token or token == "_":
                continue
            h = java_hash(token)
            bucket = h % self.dimensions  # Python's % is Java's floorMod
            vector[bucket] += 1.0 if ((h >> 31) & 1) == 0 else -1.0
        norm = math.sqrt(sum(v * v for v in vector))
        return [v / norm for v in vector] if norm > 0 else vector


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def text_of(ad_type: str, ad: dict) -> str:
    """SemanticDiscovery.textOf: what an advertisement is indexed by."""
    if ad_type == "AgentCard":
        text = f"{ad.get('description', '')} {' '.join(ad.get('goals') or [])} " \
               f"{' '.join(ad.get('consumes') or [])} {' '.join(ad.get('produces') or [])}"
        for action in ad.get("actions") or []:
            text += f" {action.get('name', '')} {action.get('description', '')}"
        return text
    if ad_type == "AssetCard":
        return f"{ad.get('description', '')} {ad.get('asset', '')} {ad.get('uri', '')} {ad.get('shape', '')}"
    if ad_type == "CapabilityAdvertisement":
        return f"{ad.get('capabilityType', '')} {ad.get('binding', '')} {ad.get('parameters', {})}"
    if ad_type == "SpaceAdvertisement":
        return f"{ad.get('spaceName', '')} {' '.join(ad.get('schemaHints') or [])}"
    return str(ad.get("id", ""))


@dataclass(frozen=True)
class Match:
    ad_type: str
    ad: dict
    score: float


class Semantic:
    """Queries over the peer's advertisement cache, local and remote."""

    def __init__(self, pipes, embedder: HashingEmbedder | None = None):
        self.pipes = pipes
        self.peer = pipes.peer
        self.embedder = embedder or HashingEmbedder()
        self._nonce = 0
        self._pending: dict[int, threading.Event] = {}
        self._lock = threading.Lock()
        pipes.on_capability(TYPE, self._on_frame)

    def query(self, text: str, limit: int = 10) -> list[Match]:
        """Local-first ranking of the cached advertisements by cosine score."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        q = self.embedder.embed(text)
        now = self.peer._now_ms()
        matches = []
        for entry in list(self.peer.ads.values()):
            if entry["expires"] <= now:
                continue
            score = cosine(q, self.embedder.embed(text_of(entry["type"], entry["ad"])))
            if score >= MIN_SCORE:
                matches.append(Match(entry["type"], entry["ad"], score))
        matches.sort(key=lambda m: -m.score)
        return matches[:limit]

    def remote_query(self, text: str, limit: int = 10, timeout_seconds: float = 2.0) -> list[Match]:
        """Asks up to three members for their best matches (SemQuery), folds
        the hits into the cache, then ranks locally."""
        targets = self.pipes.random_members(3)
        if targets:
            with self._lock:
                self._nonce += 1
                nonce = self._nonce
            answered = threading.Event()
            self._pending[nonce] = answered
            try:
                frame = cbor.dumps({"nonce": nonce, "text": text, "limit": int(limit)})
                for target in targets:
                    self.pipes.send(target, TYPE, frame)
                answered.wait(timeout_seconds)
            finally:
                self._pending.pop(nonce, None)
        return self.query(text, limit)

    def _on_frame(self, sender: str, payload: bytes) -> None:
        try:
            frame = cbor.loads(payload)
        except ValueError:
            return
        if not isinstance(frame, dict):
            return
        if isinstance(frame.get("text"), str):
            self._answer(sender, frame)
        elif isinstance(frame.get("hits"), list):
            for hit in frame["hits"]:
                if isinstance(hit, dict) and hit.get("adType"):
                    self.peer.accept_ad(hit)
            event = self._pending.get(int(frame.get("nonce", -1)))
            if event is not None:
                event.set()

    def _answer(self, sender: str, query: dict) -> None:
        q = self.embedder.embed(query["text"])
        now = self.peer._now_ms()
        scored = []
        for entry in list(self.peer.ads.values()):
            if entry["expires"] <= now:
                continue
            score = cosine(q, self.embedder.embed(text_of(entry["type"], entry["ad"])))
            if score >= MIN_SCORE:
                scored.append((score, entry["stored"]))
        scored.sort(key=lambda s: -s[0])
        limit = max(1, min(int(query.get("limit", 10)), 16))
        hits = [{"adType": st["adType"], "adBytes": st["adBytes"], "publicKey": st["publicKey"],
                 "signature": st["signature"]} for _, st in scored[:limit]]
        self.pipes.send(sender, TYPE, cbor.dumps({"nonce": query.get("nonce", 0), "hits": hits}))
