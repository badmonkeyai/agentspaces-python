"""ISSUE-ModelCard §10: the Python client indexes a ModelCard as data keyed by its kind name."""
from agentspaces.capabilities.semantic import text_of


def test_text_of_indexes_each_advertisement_kind_as_java_does():
    assert text_of("AssetCard", {"description": "d", "asset": "a", "uri": "u", "shape": "s"}) == "d a u s"
    assert text_of("ModelCard", {"name": "m", "version": "1", "tasks": ["classify", "embed"], "modality": "text",
                                 "engine": "onnx", "licence": "Apache-2.0"}) == "m 1 classify embed text onnx Apache-2.0"
    assert text_of("FutureCard", {"id": "aspace://g/x"}) == "aspace://g/x"


def test_an_app_card_is_indexed_by_its_inline_fields_with_origin_and_formats():
    """SPEC §6.1a.2 v0.1.32 (AppCard origin and formats, 2026-11-09): origin's system and ref and every format follow
    the url, as Java's SemanticDiscovery.textOf writes them; a stub is indexed by the fields it keeps."""
    card = {"name": "desk", "kind": "fed", "shape": "static", "owner": "ops", "url": "https://x.example/desk.html"}
    assert text_of("AppCard", card) == "desk fed static ops https://x.example/desk.html"
    origin = {"system": "realm", "ref": "ops/desk", "version": ""}
    assert text_of("AppCard", {**card, "origin": origin, "formats": ["text/html", "urn:realm:ops#"]}) \
        == "desk fed static ops https://x.example/desk.html realm ops/desk text/html urn:realm:ops#"
    assert text_of("AppCard", {**card, "formats": ["text/html"]}) == "desk fed static ops https://x.example/desk.html text/html"
