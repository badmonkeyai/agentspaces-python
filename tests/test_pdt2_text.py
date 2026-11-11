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
"""PDT 2 phase 7, P2-C-01 group T (P2-T-01 to P2-T-03, P2-T-05; srad/agentspaces-pdt2.md §3.9, §10.10): ``PText`` in
Python. An insert follows Fugue's rule, a delete keeps the ids, two texts merge by run union whatever each replica
did, a text travels in the value form read strictly, a map value of text above 1 KiB spills to a ``t`` node, and the
key-wise merge of a map takes the union of two texts, raising no conflict."""

import random

import pytest

from agentspaces.pdt import NodeStore, PMap, nodes, text
from agentspaces.pdt.items import TextRun
from agentspaces.pdt.kinds import TextLeaf
from agentspaces.pdt.text import PText


def test_typing_at_the_cursor_extends_one_run_and_a_delete_keeps_the_ids():
    t = PText.empty("alice").insert(0, "Hello").insert(5, " world")
    assert str(t) == "Hello world" and t.length() == 11
    assert len(t.leaf().runs) == 1, "typing at the cursor goes on in one run"
    gone = t.delete(5, 6)
    assert str(gone) == "Hello" and gone.length() == 5 and len(gone.order()) == 11
    assert str(gone.insert(5, "!")) == "Hello!"
    with pytest.raises(IndexError):
        t.insert(12, "x")
    with pytest.raises(IndexError):
        t.delete(10, 2)
    assert t.insert(3, "") is t


def test_code_points_count_as_characters():
    t = PText.empty("alice").insert(0, "a\U0001F600b")
    assert t.length() == 3 and str(t.insert(2, "é")) == "a\U0001F600éb"


def test_two_replicas_converge_whatever_order_they_merge_in_and_keep_each_insert_together():
    rng = random.Random(7)
    for _ in range(40):
        base = PText.empty("base").insert(0, "the quick brown fox")
        a, b = base.with_replica("alice"), base.with_replica("bob")
        for _ in range(8):
            a = a.insert(rng.randint(0, a.length()), "AAA") if rng.random() < 0.7 or not a.length() \
                else a.delete(rng.randrange(a.length()), 1)
            b = b.insert(rng.randint(0, b.length()), "BBB") if rng.random() < 0.7 or not b.length() \
                else b.delete(rng.randrange(b.length()), 1)
        ab, ba = a.merge(b), b.merge(a)
        assert ab.leaf() == ba.leaf() and str(ab) == str(ba)
        assert ab.merge(ab) == ab and ab.merge(a) == ab, "the union is idempotent and absorbs either side"
        assert "AABA" not in str(ab) and "BBAB" not in str(ab), "a replica's contiguous insert is not interleaved"


def test_replica_of_derives_eight_base32_characters_from_an_agent_id():
    replica = text.replica_of("z7ffZx9dmRweYnDbecGybaF66gitu9cbWBsJBzNEWF47v/writer")
    assert len(replica) == 8 and replica == replica.lower()


def test_the_value_form_reads_strictly():
    leaf = PText.empty("alice").insert(0, "hi").leaf()
    form = text.to_wire(leaf)
    assert form.startswith(bytes.fromhex("bf616b6174")) and text.from_wire(form) == leaf and text.is_text(form)
    assert not text.is_text(b"\xbf\x61\x6b\x61\x74\xff")
    for broken in (form[:-1], form + b"\x00", form.replace(b"\x61\x76\x01", b"\x61\x76\x02")):
        assert not text.is_text(broken)
        with pytest.raises(ValueError):
            text.from_wire(broken)


def test_a_map_of_texts_spills_the_long_one_reads_it_back_and_merges_two_texts_by_union():
    store = NodeStore()
    base = PMap.empty(store).assoc("doc", PText.empty("alice").insert(0, "x" * 1100)).assoc("note", "plain")
    root = store.get(base.root())
    (spilled,) = [c for c in nodes.links(root)]
    assert nodes.kind_of(store.get(spilled)) == nodes.KIND_T, "a text value above 1 KiB spills to a t node"
    doc = base.get("doc")
    assert isinstance(doc, PText) and str(doc) == "x" * 1100
    mine = base.assoc("doc", doc.with_replica("alice").insert(0, "A"))
    theirs = base.assoc("doc", doc.with_replica("bob").insert(1100, "B"))
    conflicts = []
    merged = mine.merge3(base, theirs, lambda *args: conflicts.append(args))
    assert str(merged.get("doc")) == "A" + "x" * 1100 + "B" and conflicts == [], "a text merge raises no conflict"
    assert TextLeaf.decode(None, store.get(nodes.links(store.get(merged.root()))[0])).text() == str(merged.get("doc"))


def test_a_text_past_the_node_bound_is_refused_on_the_way_into_a_map():
    """The phase 6 review's T1: a text whose t node would pass 1 MiB is refused when it enters a map."""
    runs = [TextRun(f"replica-{i:024d}", 0, None, TextRun.RIGHT, 1, False, "x") for i in range(40_000)]
    wide = PText.of(TextLeaf(runs), "alice")
    with pytest.raises(ValueError, match="node bound; split it into smaller texts"):
        PMap.empty(NodeStore()).assoc("doc", wide)
