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
"""srad/agentspaces-geo.md GEO-F-01: the GeoFeature in the Python client encodes to the bytes of the Java vector of
agentspaces-a2ui-geo (copied into tests/a2ui_vectors), and its factory refuses what the Java record refuses, naming
the field."""

import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from agentspaces import cbor, geo
from agentspaces.space import schema_of, to_payload

VECTORS = pathlib.Path(__file__).parent / "a2ui_vectors"
AT = "2026-11-12T09:14:03Z"


def test_a_feature_encodes_to_the_java_vector():
    fields = json.loads((VECTORS / "geo_feature.json").read_text())
    hexed = (VECTORS / "geo_feature_cbor.hex").read_text().strip()
    assert cbor.dumps(to_payload(geo.geo_feature(**fields))).hex() == hexed
    assert cbor.loads(bytes.fromhex(hexed)) == fields
    ship = geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087, AT, label="MV Northgate",
                     properties={"mmsi": "235012345", "speed_kn": 11.2, "destination": "Berth 4"},
                     style={"icon": "ship", "color": "#8888cc", "heading": 74}, severity="info", links=[{"rel": "bound-for", "id": "berth-4"}])
    assert cbor.dumps(to_payload(ship)).hex() == hexed, "the point builder gives the same bytes"


def test_the_records_name_the_open_iris():
    assert schema_of(geo.GeoFeature) == "https://badmonkey.ai/agentspaces/a2ui-geo/v1/GeoFeature"
    assert schema_of(geo.FeatureKind) == "https://badmonkey.ai/agentspaces/a2ui-geo/v1/FeatureKind"
    plain = to_payload(geo.point("a", "k", 0.5, 0.5, AT))
    assert "severity" not in plain and "links" not in plain, "absent severity and links are left out, as Java's"


def test_shapes_and_bounds():
    berth = geo.polygon("berth-4", "area.berth", [[[-3.01, 53.40], [-3.00, 53.40], [-3.00, 53.41], [-3.01, 53.41], [-3.01, 53.40]]], AT)
    assert geo.bounds(berth) == [-3.01, 53.40, -3.00, 53.41]
    route = geo.line("route-9", "route.ferry", [[-3.0, 53.4], [-3.1, 53.45]], AT)
    assert route.geometry["type"] == "LineString"


@pytest.mark.parametrize("make, match", [
    (lambda: geo.point("", "track.ship", 0, 0, AT), "id"),
    (lambda: geo.point("x" * 129, "track.ship", 0, 0, AT), "id"),
    (lambda: geo.point("a", "Track Ship", 0, 0, AT), "kind"),
    (lambda: geo.point("a", "k", 181, 0, AT), "longitude"),
    (lambda: geo.point("a", "k", 0, -91, AT), "latitude"),
    (lambda: geo.point("a", "k", float("nan"), 0, AT), "finite"),
    (lambda: geo.line("a", "route", [[0.0, 0.0]], AT), "two positions"),
    (lambda: geo.polygon("a", "area", [[[0, 0], [1, 0], [1, 1], [0, 1]]], AT), "closed"),
    (lambda: geo.geo_feature("a", "k", {"type": "GeometryCollection", "geometries": []}, AT), "GeometryCollection"),
    (lambda: geo.point("a", "k", 0, 0, AT, style={"font": "Comic Sans"}), "style.font"),
    (lambda: geo.point("a", "k", 0, 0, AT, style={"color": "url(javascript:x)"}), "style.color"),
    (lambda: geo.point("a", "k", 0, 0, AT, style={"opacity": 2}), "style.opacity"),
    (lambda: geo.point("a", "k", 0, 0, AT, style={"icon": "skull"}), "style.icon"),
    (lambda: geo.point("a", "k", 0, 0, AT, label="x" * 121), "label"),
    (lambda: geo.point("a", "k", 0, 0, AT, severity="panic"), "severity"),
    (lambda: geo.point("a", "k", 0, 0, AT, properties={"a": {"b": {"c": {"d": 1}}}}), "depth"),
    (lambda: geo.point("a", "k", 0, 0, AT, properties={"blob": "x" * 70_000}), "64 KiB"),
    (lambda: geo.line("a", "route", [[i * 0.00001, 0.0] for i in range(10_001)], AT), "10000 positions"),
    (lambda: geo.point("a", "k", 0, 0, AT, links=[{"rel": "near", "id": f"f-{i}"} for i in range(65)]), "64 links"),
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0]}, AT, schemaVersion=2), "schemaVersion"),
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0]}, AT, type="FeatureCollection"), "type"),
    # a geometry holds only type, coordinates and a bbox, so nothing rides past the bounds to a page (GEO-Q-12)
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0], "blob": "x" * 500_000}, AT), "geometry.blob"),
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0], "crs": {"type": "name"}}, AT), "geometry.crs"),
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0], "bbox": [0, 0, 1]}, AT), "geometry.bbox"),
    (lambda: geo.geo_feature("a", "k", {"type": "Point", "coordinates": [0, 0], "bbox": None}, AT), "geometry.bbox"),
    # Java refuses a null property value, so the builder does
    (lambda: geo.point("a", "k", 0, 0, AT, properties={"eta": None}), "properties.eta"),
    (lambda: geo.point("a", "k", 0, 0, AT, style={"color": None}), "style.color"),
    # at is an instant as Java prints it
    (lambda: geo.point("a", "k", 0, 0, "yesterday"), "at"),
    (lambda: geo.point("a", "k", 0, 0, "2026-11-12"), "at"),
    (lambda: geo.point("a", "k", 0, 0, "2026-11-12T09:14:03.000Z"), "at"),
    (lambda: geo.point("a", "k", 0, 0, "2026-11-12T09:14:03+00:00"), "at"),
    (lambda: geo.point("a", "k", 0, 0, datetime(2026, 11, 12, 9, 14, 3)), "aware"),
    # a link's rel and id are non-blank and counted in UTF-16 units, as Java counts them
    (lambda: geo.point("a", "k", 0, 0, AT, links=[{"rel": " ", "id": "x"}]), "rel"),
    (lambda: geo.point("a", "k", 0, 0, AT, links=[{"rel": "near", "id": "  "}]), "link's id"),
    (lambda: geo.point("a", "k", 0, 0, AT, links=[{"rel": "near", "id": "\U0001F6A2" * 100}]), "link's id"),
])
def test_a_feature_that_breaks_a_rule_is_refused_by_name(make, match):
    with pytest.raises(ValueError, match=match):
        make()


def test_a_feature_kind_names_a_look_once():
    k = geo.feature_kind("track.ship", "Ships", {"icon": "ship", "color": "#8888cc"}, ["mmsi", "speed_kn"])
    assert geo.covers(k, "track.ship.cargo") and not geo.covers(k, "track.shipyard")
    assert geo.kind_matches("track.ship*", "track.ship.cargo") and geo.kind_matches("area.berth", "area.berth")
    assert not geo.kind_matches("area.berth", "area.berths")
    with pytest.raises(ValueError, match="style.color"):
        geo.feature_kind("track.ship", "Ships", {"color": "blue"})


def test_a_feature_kind_encodes_to_the_java_vector():
    fields = json.loads((VECTORS / "feature_kind.json").read_text())
    hexed = (VECTORS / "feature_kind_cbor.hex").read_text().strip()
    k = geo.feature_kind(fields["kind"], label=fields["label"], style=fields["style"], fields=fields["fields"])
    assert cbor.dumps(to_payload(k)).hex() == hexed


def test_at_is_written_as_java_prints_an_instant():
    def at(dt):
        return geo.point("a", "k", 0, 0, dt).at
    assert at(datetime(2026, 11, 12, 9, 14, 3, tzinfo=timezone.utc)) == "2026-11-12T09:14:03Z"
    assert at(datetime(2026, 11, 12, 9, 14, 3, 250_000, tzinfo=timezone.utc)) == "2026-11-12T09:14:03.250Z"
    assert at(datetime(2026, 11, 12, 9, 14, 3, 123_456, tzinfo=timezone.utc)) == "2026-11-12T09:14:03.123456Z"
    assert at(datetime(2026, 11, 12, 10, 14, 3, tzinfo=timezone(timedelta(hours=1)))) == "2026-11-12T09:14:03Z", "in UTC"
    assert at("2026-11-12T09:14:03.120Z") == "2026-11-12T09:14:03.120Z"


def test_a_geometry_may_carry_a_bbox():
    f = geo.geo_feature("a", "k", {"type": "Point", "coordinates": [1, 2], "bbox": [1, 2, 1, 2]}, AT)
    assert f.geometry["bbox"] == [1, 2, 1, 2]
