"""ISSUE-ModelCard §10: the Python client indexes a ModelCard as data keyed by its kind name."""
from agentspaces.capabilities.semantic import text_of


def test_text_of_indexes_each_advertisement_kind_as_java_does():
    assert text_of("AssetCard", {"description": "d", "asset": "a", "uri": "u", "shape": "s"}) == "d a u s"
    assert text_of("ModelCard", {"name": "m", "version": "1", "tasks": ["classify", "embed"], "modality": "text",
                                 "engine": "onnx", "licence": "Apache-2.0"}) == "m 1 classify embed text onnx Apache-2.0"
    assert text_of("FutureCard", {"id": "aspace://g/x"}) == "aspace://g/x"
