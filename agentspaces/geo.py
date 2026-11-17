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
"""The GeoFeature of agentspaces-a2ui-geo in the Python client (srad/agentspaces-geo.md §3.1, GEO-F-01).

A ``GeoFeature`` is a GeoJSON Feature (RFC 7946) with the foreign members ``schemaVersion``, ``kind``,
``label``, ``style``, ``at``, ``severity`` and ``links``. It is an ``@entry`` dataclass whose fields are in
Java's declared order, so a feature encodes to the bytes the Java vector pins. ``geo_feature`` refuses what
the Java record refuses, naming the field; ``point``, ``line`` and ``polygon`` build the usual shapes::

    ship = geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087, at=datetime.now(timezone.utc),
                     label="MV Northgate", style={"icon": "ship", "heading": 74})
    space.write(ship, lease="5m", tags={"kind": ship.kind})

``at`` is an aware ``datetime``, or the text Java's ``Instant`` prints (``"2026-11-12T09:14:03Z"``); the
builder writes a ``datetime`` in that text.
"""

import datetime
import json
import math
import re
from dataclasses import dataclass, field

from .cbor import canonical_map, utf16_units
from .records import is_canonical_instant
from .space import entry

NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui-geo/v1/"
SPACE = "features"
MAX_POSITIONS = 10_000
MAX_PROPERTIES_BYTES = 64 * 1024
MAX_LINKS = 64
GEOMETRIES = ("Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon")
SEVERITIES = ("info", "warning", "serious", "critical")
ICONS = ("dot", "pin", "truck", "van", "car", "plane", "ship", "person", "arrow")
_KIND = re.compile(r"[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*")
_HEX = re.compile(r"#[0-9a-fA-F]{6}")
_RANGES = {"opacity": (0, 1), "width": (1, 8), "size": (1, 64), "heading": (0, 360)}


@entry(NAMESPACE + "GeoFeature")
@dataclass
class GeoFeature:
    """An object for a map; build it with ``geo_feature``, ``point``, ``line`` or ``polygon``."""
    __agentspaces_omit_none__ = ("severity", "links")
    schemaVersion: int = 1
    type: str = "Feature"
    id: str = ""
    geometry: dict = field(default_factory=dict)
    properties: dict = field(default_factory=dict)
    kind: str = ""
    label: str = ""
    style: dict = field(default_factory=dict)
    at: str = ""
    severity: str | None = None
    links: list | None = None


@entry(NAMESPACE + "FeatureKind")
@dataclass
class FeatureKind:
    """A kind's look, named once for an app: the legend's label, a default style and the card's fields."""
    schemaVersion: int = 1
    kind: str = ""
    label: str = ""
    style: dict = field(default_factory=dict)
    fields: list = field(default_factory=list)


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _position(p):
    if not isinstance(p, (list, tuple)) or not 2 <= len(p) <= 3 or not all(_number(x) for x in p):
        raise ValueError(f"a position is [longitude, latitude] or [longitude, latitude, altitude]: {p}")
    if not all(math.isfinite(x) for x in p):
        raise ValueError(f"a position's numbers are finite: {p}")
    if not -180 <= p[0] <= 180:
        raise ValueError(f"a position's longitude is from -180 to 180: {p[0]}")
    if not -90 <= p[1] <= 90:
        raise ValueError(f"a position's latitude is from -90 to 90: {p[1]}")


def _list(c, what):
    if not isinstance(c, (list, tuple)) or len(c) < 1:
        raise ValueError(f"{what}'s coordinates are a list of at least 1")
    return c


def _line(c):
    c = _list(c, "a LineString")
    if len(c) < 2:
        raise ValueError("a LineString has at least two positions")
    for p in c:
        _position(p)


def _polygon(c):
    for ring in _list(c, "a Polygon"):
        ring = _list(ring, "a Polygon's ring")
        if len(ring) < 4:
            raise ValueError("a Polygon's ring has at least four positions and is closed (its last is its first)")
        for p in ring:
            _position(p)
        if [float(x) for x in ring[0]] != [float(x) for x in ring[-1]]:
            raise ValueError("a Polygon's ring is closed: its last position is its first")


def _count(c) -> int:
    if isinstance(c, (list, tuple)) and c and _number(c[0]):
        return 1
    return sum(_count(x) for x in c) if isinstance(c, (list, tuple)) else 0


def check_geometry(g: dict):
    """Refuses a geometry outside RFC 7946 and §3.1, naming what breaks."""
    t = g.get("type") if isinstance(g, dict) else None
    if t == "GeometryCollection":
        raise ValueError("a GeoFeature's geometry is not a GeometryCollection; publish one feature per geometry")
    if t not in GEOMETRIES:
        raise ValueError(f"a GeoFeature's geometry.type is one of {GEOMETRIES}: {t}")
    # only the members RFC 7946 gives a geometry: any other would ride past the position and size bounds to every page
    for key, v in g.items():
        if key == "bbox":
            if not isinstance(v, (list, tuple)) or len(v) not in (4, 6) or not all(_number(x) and math.isfinite(x) for x in v):
                raise ValueError(f"a GeoFeature's geometry.bbox is 4 or 6 finite numbers: {v}")
        elif key == "crs":
            raise ValueError("a GeoFeature's geometry.crs is reserved: version 1 has none, and its absence means WGS 84")
        elif key not in ("type", "coordinates"):
            raise ValueError(f"geometry.{key} is not a geometry member; a geometry has type, coordinates and an optional bbox")
    c = g.get("coordinates")
    if t == "Point":
        _position(c)
    elif t == "MultiPoint":
        for p in _list(c, "a MultiPoint"):
            _position(p)
    elif t == "LineString":
        _line(c)
    elif t == "MultiLineString":
        for x in _list(c, "a MultiLineString"):
            _line(x)
    elif t == "Polygon":
        _polygon(c)
    else:
        for x in _list(c, "a MultiPolygon"):
            _polygon(x)
    n = _count(c)
    if n > MAX_POSITIONS:
        raise ValueError(f"a GeoFeature's geometry has at most 10000 positions: {n}")


def check_style(style: dict, prefix="style"):
    """Refuses a style outside the closed grammar of §3.1, naming the key."""
    for k, v in style.items():
        where = f"{prefix}.{k}"
        if k in ("color", "fill", "stroke"):
            if not isinstance(v, str) or not _HEX.fullmatch(v):
                raise ValueError(f"{where} is a hex colour #rrggbb: {v}")
        elif k in _RANGES:
            lo, hi = _RANGES[k]
            if not _number(v) or not math.isfinite(v) or not lo <= v <= hi:
                raise ValueError(f"{where} is a number from {lo} to {hi}: {v}")
        elif k == "icon":
            if v not in ICONS:
                raise ValueError(f"{where} is one of {ICONS}: {v}")
        else:
            raise ValueError(f"{where} is not a style key; the keys are color, fill, stroke, opacity, width, icon, size and heading")


def _depth(where, v, level):
    if isinstance(v, dict):
        if level >= 2 and v:
            raise ValueError(f"{where} nests past a depth of 2; flatten it")
        for k, inner in v.items():
            _depth(f"{where}.{k}", inner, level + 1)
    elif isinstance(v, (list, tuple)):
        if level >= 2 and any(isinstance(x, (dict, list, tuple)) for x in v):
            raise ValueError(f"{where} nests past a depth of 2; flatten it")
        for inner in v:
            _depth(where, inner, level + 1)
    elif v is not None and not isinstance(v, (str, int, float, bool)):
        raise ValueError(f"{where} is a string, a number, a boolean, a list or an object: {type(v).__name__}")


def _no_nulls(values: dict, prefix):
    """Refuses a None value, naming its key: Java's reader refuses a null in a map field, so it would never read it."""
    for k, v in values.items():
        if v is None:
            raise ValueError(f"{prefix}.{k} is None; leave the key out instead")


def instant_text(at) -> str:
    """``at`` as the text Java's ``Instant`` prints and reads back to the same bytes: an aware ``datetime`` is written
    so, and a string must already be so (``"2026-11-12T09:14:03Z"``, a fraction of 3, 6 or 9 digits only when not
    zero)."""
    if isinstance(at, datetime.datetime):
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("a GeoFeature's at is an aware datetime; give it a time zone, such as timezone.utc")
        u = at.astimezone(datetime.timezone.utc)
        text = u.strftime("%Y-%m-%dT%H:%M:%S")
        if u.microsecond == 0:
            return text + "Z"
        if u.microsecond % 1000 == 0:
            return f"{text}.{u.microsecond // 1000:03d}Z"
        return f"{text}.{u.microsecond:06d}Z"
    if not is_canonical_instant(at):
        raise ValueError(f"a GeoFeature's at is an instant as Java prints it, such as 2026-11-12T09:14:03Z: {at!r}")
    return at


def _text(v, most) -> bool:
    """Whether ``v`` is non-blank text of at most ``most`` UTF-16 code units, as Java counts a string's length."""
    return isinstance(v, str) and bool(v.strip()) and utf16_units(v) <= most


def _kind(kind, record):
    if not isinstance(kind, str) or len(kind) > 64 or not _KIND.fullmatch(kind):
        raise ValueError(f"a {record}'s kind is a dotted lower-case name such as track.ship: {kind}")


def geo_feature(id, kind, geometry, at, properties=None, label="", style=None, severity=None, links=None,
                schemaVersion=1, type="Feature") -> GeoFeature:
    """A feature, checked as the Java record checks it."""
    if schemaVersion != 1:
        raise ValueError(f"a GeoFeature has schemaVersion 1: {schemaVersion}")
    if type != "Feature":
        raise ValueError(f"a GeoFeature's type is Feature, as GeoJSON's: {type}")
    if not isinstance(id, str) or not id.strip() or utf16_units(id) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in id):
        raise ValueError("a GeoFeature's id is 1 to 128 characters with no control character")
    _kind(kind, "GeoFeature")
    check_geometry(geometry)
    properties = dict(properties or {})
    _no_nulls(properties, "properties")
    for k, v in properties.items():
        _depth(f"properties.{k}", v, 1)
    size = len(json.dumps(properties, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    if size > MAX_PROPERTIES_BYTES:
        raise ValueError(f"a GeoFeature's properties are at most 64 KiB: {size} bytes")
    label = label or ""
    if utf16_units(label) > 120 or any(ord(c) < 0x20 and c != "\t" for c in label):
        raise ValueError("a GeoFeature's label is at most 120 characters with no control character")
    style = dict(style or {})
    check_style(style)
    if not at:
        raise ValueError("a GeoFeature has an at, an ISO-8601 instant")
    at = instant_text(at)
    if severity is not None and severity not in SEVERITIES:
        raise ValueError(f"a GeoFeature's severity is one of {SEVERITIES}: {severity}")
    out = []
    for link in links or []:
        rel, other = link.get("rel", ""), link.get("id", "")
        if not _text(rel, 64):
            raise ValueError("a link's rel is 1 to 64 characters")
        if not _text(other, 128):
            raise ValueError("a link's id is 1 to 128 characters")
        out.append({"rel": rel, "id": other})
    if len(out) > MAX_LINKS:
        raise ValueError(f"a GeoFeature has at most 64 links: {len(out)}")
    # the map-valued fields in canonical order, as Java's codec writes every map (wire v3, ISSUE-CanonicalMaps)
    return GeoFeature(1, "Feature", id, _canonical(geometry), _canonical(properties), kind, label, canonical_map(style), at, severity, out or None)


def _canonical(v):
    """A value with every map in it, at any depth, in canonical order."""
    if isinstance(v, dict):
        return canonical_map({k: _canonical(x) for k, x in v.items()})
    if isinstance(v, (list, tuple)):
        return [_canonical(x) for x in v]
    return v


def point(id, kind, lon, lat, at, **kw) -> GeoFeature:
    """A point at a longitude and a latitude, WGS 84."""
    return geo_feature(id, kind, {"type": "Point", "coordinates": [lon, lat]}, at, **kw)


def line(id, kind, positions, at, **kw) -> GeoFeature:
    """A line through at least two positions, each [lon, lat]."""
    return geo_feature(id, kind, {"type": "LineString", "coordinates": [list(p) for p in positions]}, at, **kw)


def polygon(id, kind, rings, at, **kw) -> GeoFeature:
    """A polygon: rings of positions, the first the outline, each closed."""
    return geo_feature(id, kind, {"type": "Polygon", "coordinates": [[list(p) for p in r] for r in rings]}, at, **kw)


def bounds(feature: GeoFeature) -> list:
    """The bounds of a feature as [west, south, east, north]."""
    b = [math.inf, math.inf, -math.inf, -math.inf]

    def walk(c):
        if isinstance(c, (list, tuple)) and c and _number(c[0]):
            b[0], b[1], b[2], b[3] = min(b[0], c[0]), min(b[1], c[1]), max(b[2], c[0]), max(b[3], c[1])
        elif isinstance(c, (list, tuple)):
            for x in c:
                walk(x)

    walk(feature.geometry.get("coordinates"))
    return b


def feature_kind(kind, label="", style=None, fields=None, schemaVersion=1) -> FeatureKind:
    """A kind's look, checked as the Java record checks it."""
    if schemaVersion != 1:
        raise ValueError(f"a FeatureKind has schemaVersion 1: {schemaVersion}")
    _kind(kind, "FeatureKind")
    style = dict(style or {})
    check_style(style)
    return FeatureKind(1, kind, label if label and label.strip() else kind, canonical_map(style), list(fields or []))


def kind_matches(pattern: str, kind: str) -> bool:
    """A binding's kind filter: a pattern ending in * takes every kind that starts with what comes before it."""
    if pattern is None or kind is None:
        return False
    return kind.startswith(pattern[:-1]) if pattern.endswith("*") else pattern == kind


def covers(feature_kind_: FeatureKind, kind: str) -> bool:
    """Whether a FeatureKind covers a feature's kind: the same, or it followed by a dot and more."""
    return kind == feature_kind_.kind or kind.startswith(feature_kind_.kind + ".")
