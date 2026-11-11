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
"""ISSUE-A2uiAppComponents FR-11, FR-12, SR-3 (spiral 6 S6-U-26): the open A2UI records in the Python
client encode to the bytes of the Java vectors of agentspaces-a2ui (copied into tests/a2ui_vectors), each
factory refuses what the Java constructor refuses, the hint rule picks the version, and the builders shape
the six components as the Java Surfaces does."""

import json
import pathlib

import pytest

from agentspaces import a2ui, cbor
from agentspaces.space import schema_of, to_payload

VECTORS = pathlib.Path(__file__).parent / "a2ui_vectors"


def vector(name):
    return json.loads((VECTORS / f"{name}.json").read_text()), (VECTORS / f"{name}_cbor.hex").read_text().strip()


@pytest.mark.parametrize("name,make", [
    ("chat_message_v1", a2ui.chat_message), ("chat_message_v2", a2ui.chat_message),
    ("shared_file_v1", a2ui.shared_file), ("shared_file_v2", a2ui.shared_file),
    ("working_on_v1", a2ui.working_on), ("chat_progress_v1", a2ui.chat_progress),
])
def test_each_record_encodes_to_the_java_vector(name, make):
    fields, hexed = vector(name)
    record = make(**fields)
    assert cbor.dumps(to_payload(record)).hex() == hexed, name + " pins the canonical bytes"
    assert cbor.loads(bytes.fromhex(hexed)) == fields


def test_the_records_name_the_open_iris():
    assert schema_of(a2ui.ChatMessage) == "https://badmonkey.ai/agentspaces/a2ui/v1/ChatMessage"
    assert schema_of(a2ui.WorkingOn) == "https://badmonkey.ai/agentspaces/a2ui/v1/WorkingOn"
    assert "format" not in to_payload(a2ui.chat_message(id="m", key="k", at="2026-11-10T09:00:00Z")), "a version 1 line carries no version 2 field"


def test_a_record_that_breaks_a_bound_is_refused():
    at = "2026-11-10T09:00:00Z"
    with pytest.raises(ValueError, match="path must be relative"):
        a2ui.shared_file(schemaVersion=2, id="f", name="x", at=at, path="a/../b")
    with pytest.raises(ValueError, match="version 1 SharedFile"):
        a2ui.shared_file(id="f", name="x", at=at, path="a")
    with pytest.raises(ValueError, match="at most 16"):
        a2ui.chat_message(schemaVersion=2, id="m", key="k", at=at, cites=[{"file": f"f{i}"} for i in range(17)])
    with pytest.raises(ValueError, match="format"):
        a2ui.chat_message(schemaVersion=2, id="m", key="k", at=at, format="text/html")
    with pytest.raises(ValueError, match="at most 20"):
        a2ui.chat_progress(key="k", inReplyTo="m", agent="a", at=at, steps=[{"label": "s", "kind": "read", "at": at}] * 21)
    with pytest.raises(ValueError, match="A2A task states"):
        a2ui.chat_progress(key="k", inReplyTo="m", agent="a", at=at, state="thinking")
    with pytest.raises(ValueError, match="120 characters"):
        a2ui.working_on(agent="a", since=at, task="x" * 121)


@pytest.mark.parametrize("task, units", [
    ("x" * 120, 120),
    ("\U0001F600" * 60, 120),             # an emoji: one code point, two UTF-16 units
    ("x" * 118 + "\U00020000", 120),      # a non-BMP CJK character ends the line
    ("é" * 60, 120),                # a combining sequence: two code points, two units
])
def test_a_task_line_of_120_utf16_units_is_held(task, units):
    assert cbor.utf16_units(task) == units
    assert a2ui.working_on(agent="a", since="2026-11-10T09:00:00Z", task=task).task == task


@pytest.mark.parametrize("task, units", [
    ("x" * 121, 121),
    ("\U0001F600" * 61, 122),             # 61 code points, but 122 units, as Java and TypeScript count
    ("x" * 119 + "\U0001F600", 121),      # 120 code points, 121 units
    ("x" * 119 + "\U00020000", 121),
    ("é" * 60 + "e", 121),          # 61 visible letters would be wrong both ways: units decide
])
def test_a_task_line_past_120_utf16_units_is_refused(task, units):
    with pytest.raises(ValueError, match=f"a task line is at most 120 characters: {units}$"):
        a2ui.working_on(agent="a", since="2026-11-10T09:00:00Z", task=task)


def test_a_writer_writes_version_two_only_when_every_reader_advertises_the_hint():
    assert a2ui.version_for([{"a2ui.records": "2"}, {"a2ui.records": "3"}]) == 2
    assert a2ui.version_for([{"a2ui.records": "2"}, {}]) == 1
    assert a2ui.version_for([]) == 2


@pytest.mark.parametrize("hint", ["٢", "٣٤", "²", "２", "2 ", "+2", "1234567890"])
def test_a_hint_that_is_not_one_to_nine_ascii_digits_reads_as_version_one(hint):
    # Java's \d{1,9} and TypeScript's /^\d{1,9}$/ match ASCII digits only; str.isdigit also takes
    # Arabic-Indic, full-width and superscript digits, and int() refuses the superscript.
    assert a2ui.version_for([{"a2ui.records": hint}]) == 1


def test_the_builders_shape_the_six_components():
    status = a2ui.title_status("/working", "Agent working", "Ready")
    assert a2ui.title_bar("bar", {"path": "/app/title"}, "Claims desk", "briefcase", status, [a2ui.title_action("share", "Share", "share", "share")], "bar-menu") == {
        "id": "bar", "component": "TitleBar", "title": {"path": "/app/title"}, "subtitle": "Claims desk", "icon": "briefcase",
        "status": {"from": "/working", "labels": {"working": "Agent working", "idle": "Ready"}},
        "actions": [{"id": "share", "label": "Share", "icon": "share", "action": {"name": "share"}}], "menu": "bar-menu"}
    assert list(a2ui.title_bar("bar", "Workbench")) == ["id", "component", "title"]
    items = [a2ui.menu_item("new-chat", "New chat", "chat.new", {"shortcut": "Ctrl+Shift+O"}), a2ui.submenu("share", "Share", [a2ui.menu_item("copy", "Copy link", "share.link")])]
    assert a2ui.menu("more", a2ui.trigger("overflow", "More"), items)["items"][0] == {"id": "new-chat", "label": "New chat", "shortcut": "Ctrl+Shift+O", "action": {"name": "chat.new"}}
    with pytest.raises(ValueError, match="one level"):
        a2ui.submenu("a", "A", [items[1]])
    assert a2ui.split("main", "horizontal", "workbench-main", 720, [a2ui.pane("left", "tree", 0.25, 180, True, "Files"), a2ui.pane("right", "chat", 0.75)]) == {
        "id": "main", "component": "Split", "orientation": "horizontal", "persist": "workbench-main", "stackBelow": 720,
        "panes": [{"id": "left", "child": "tree", "size": 0.25, "min": 180, "collapsible": True, "label": "Files"}, {"id": "right", "child": "chat", "size": 0.75}]}
    with pytest.raises(ValueError, match="two or three"):
        a2ui.split("main", "horizontal", "", 0, [a2ui.pane("a", "x", 1.0)])
    assert a2ui.chat("chat", "workbench", "main", {"attach": True, "controls": ["copy", "stop"], "preview": "preview"}) == {
        "id": "chat", "component": "Chat", "agent": "workbench", "key": "main", "attach": True, "controls": ["copy", "stop"], "preview": "preview"}
    assert list(a2ui.chat("chat", "", "main")) == ["id", "component", "key"]
    with pytest.raises(ValueError, match="controls"):
        a2ui.chat("chat", "a", "main", {"controls": ["delete"]})
    with pytest.raises(ValueError, match="colour"):
        a2ui.chat("chat", "a", "main", {"colour": "red"})
    assert a2ui.file_tree("tree", "/files", {"working": "/working", "upload": True}) == {"id": "tree", "component": "FileTree", "reads": "/files", "upload": True, "working": "/working"}
    with pytest.raises(ValueError, match="actions"):
        a2ui.file_tree("tree", "/files", {"actions": ["burn"]})
    assert a2ui.file_preview("preview", {"path": "/selected/file"}, {"files": "/files", "csvRows": 500}) == {
        "id": "preview", "component": "FilePreview", "file": {"path": "/selected/file"}, "csvRows": 500, "files": "/files"}
    with pytest.raises(ValueError, match="16 MiB"):
        a2ui.file_preview("preview", "f-1", {"maxBytes": 17000000})
