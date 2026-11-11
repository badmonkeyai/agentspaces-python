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
"""A user reads the messages of the PDT package. A message says what went wrong and what to do, in plain words,
and names no internal design id such as PD-N-04 or P2-X-06. This guard reads every string in
``agentspaces/pdt``, docstrings and comments aside, and fails on one that names an id."""

import ast
import pathlib
import re

import pytest

from agentspaces.pdt import NodeStore, PMap

PDT = pathlib.Path(__file__).resolve().parent.parent / "agentspaces" / "pdt"

# A design id: a prefix, one or two letter groups, and a number, as in PD-N-04 or P2-Q-SEC-05; or an ISSUE- name.
DESIGN_ID = re.compile(r"\b[A-Z][A-Z0-9]{1,3}-[A-Z](?:-[A-Z]{1,4})?-\d{1,3}\b|\bISSUE-[A-Z][A-Za-z]")


def _docstrings(tree: ast.AST) -> set:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def offences(source: str, name: str = "<source>") -> list:
    tree = ast.parse(source)
    skip = _docstrings(tree)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if DESIGN_ID.search(node.value):
                out.append(f"{name}:{node.lineno}: {node.value!r}")
    return out


def test_no_message_in_the_pdt_package_names_a_design_id():
    files = sorted(PDT.rglob("*.py"))
    assert len(files) > 10, "the pdt package is where it was"
    found = [hit for f in files for hit in offences(f.read_text(encoding="utf-8"), str(f.relative_to(PDT)))]
    assert found == [], "string literals that name a design id; say what to do instead:\n" + "\n".join(found)


def test_the_guard_finds_an_id_in_a_string_and_skips_one_in_a_docstring_or_comment():
    source = '''"""PD-N-04 in a module docstring."""
# P2-X-06 in a comment
def f(x):
    """P2-D-03 in a function docstring."""
    a = "bound (PD-N-04)"
    b = f"{x} (P2-Q-SEC-05)"
    c = "HKDF-SHA-256, UTF-8, PDT 2"
    raise ValueError("see ISSUE-Motion")
'''
    assert [hit.split(":")[1] for hit in offences(source)] == ["5", "6", "8"]


def test_a_value_too_large_for_an_x_node_says_how_to_store_it():
    with pytest.raises(ValueError, match="node bound; store a value this large as a byte string, which becomes a blob"):
        PMap.empty(NodeStore()).assoc("big", "t" * (2 * 1024 * 1024))
