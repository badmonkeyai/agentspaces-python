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
"""The open A2UI records and component builders of agentspaces-a2ui in the Python client (SPEC §6.1a.7).

The four records an application's agents write beside its surfaces, ``ChatMessage`` (versions 1 and 2),
``SharedFile`` (versions 1 and 2), ``WorkingOn`` and ``ChatProgress``, are ``@entry`` dataclasses whose
fields are in Java's declared order, so a record encodes to the bytes the Java vectors pin; a version 2 field
is left out of a version 1 record. Each factory refuses what the Java constructor refuses. The builders
shape the components of the open catalogs as ``Surfaces`` does in Java: ``title_bar``, ``menu`` and ``split``
of agentspaces-viz, and ``chat``, ``file_tree`` and ``file_preview`` of agentspaces-widgets.
"""

from dataclasses import dataclass, field

from .cbor import utf16_units
from .space import entry

NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui/v1/"
HINT = "a2ui.records"
HINT_VALUE = "2"
TASK_STATES = ("submitted", "working", "input-required", "completed", "failed", "canceled")
PLAIN = "text/plain"
MARKDOWN = "text/markdown"
MAX_CITES = 16
MAX_STEPS = 20
MAX_TASK = 120
STEP_KINDS = ("read", "tool", "write")


def writes_v2(reader_hints) -> bool:
    """Whether a writer may write version 2: every reader's hints carry ``a2ui.records`` at 2 or later,
    written as 1 to 9 ASCII digits as Java's ``\\d{1,9}`` reads it."""
    for hints in reader_hints:
        v = hints.get(HINT)
        if v is None or not v.isascii() or not v.isdigit() or len(v) > 9 or int(v) < 2:
            return False
    return True


def version_for(reader_hints) -> int:
    """The version a writer writes for these readers: 2 when every one reads it, else 1."""
    return 2 if writes_v2(reader_hints) else 1


def valid_path(path: str) -> bool:
    """A path in a tree of files: relative, ``/``-separated, at most 512 bytes, no empty, ``.`` or ``..``
    segment, no backslash or control character."""
    if not path or len(path.encode("utf-8")) > 512 or path.startswith("/"):
        return False
    if any(c == "\\" or ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return False
    return all(s not in ("", ".", "..") for s in path.split("/"))


def _path(path: str, what: str) -> str:
    if not valid_path(path):
        raise ValueError(f"{what} path must be relative and /-separated, at most 512 bytes, with no empty, . or .. "
                         f"segment and no backslash or control character: {path}")
    return path


def _state(state: str) -> str:
    if state not in TASK_STATES:
        raise ValueError(f"state must be one of the A2A task states {', '.join(TASK_STATES)}: {state}")
    return state


def _version(v: int, record: str) -> int:
    if v not in (1, 2):
        raise ValueError(f"a {record} has schemaVersion 1 or 2: {v}")
    return v


@entry(NAMESPACE + "ChatMessage")
@dataclass
class ChatMessage:
    """One line of a thread in ``conversations``; version 2 adds ``format`` and ``cites``."""
    __agentspaces_wire_names__ = {"from_": "from"}
    __agentspaces_omit_none__ = ("format", "cites")
    schemaVersion: int = 1
    id: str = ""
    key: str = ""
    from_: dict = field(default_factory=lambda: {"kind": "person", "name": "", "peer": ""})
    text: str = ""
    attachments: list = field(default_factory=list)
    inReplyTo: str = ""
    at: str = ""
    format: str | None = None
    cites: list | None = None


def chat_message(id, key, at, schemaVersion=1, text="", attachments=None, inReplyTo="", format=None, cites=None, **kw) -> ChatMessage:
    """A line, checked as the Java record checks it; ``from`` (or ``from_``) is the author's kind, name and peer."""
    v = _version(schemaVersion, "ChatMessage")
    who = kw.get("from", kw.get("from_")) or {}
    kind = who.get("kind") or "person"
    if kind not in ("person", "agent"):
        raise ValueError(f"a chat message is from a person or an agent: {kind}")
    m = ChatMessage(v, id, key, {"kind": kind, "name": who.get("name", ""), "peer": who.get("peer", "")}, text or "", list(attachments or []), inReplyTo or "", at)
    if v == 1:
        if format is not None or cites is not None:
            raise ValueError("a version 1 ChatMessage carries no format and no cites; write version 2 for them")
        return m
    m.format = format or PLAIN
    if m.format not in (PLAIN, MARKDOWN):
        raise ValueError(f"format must be text/plain or text/markdown: {m.format}")
    out = []
    for c in cites or []:
        if not c.get("file"):
            raise ValueError("a cite names its file")
        out.append({"file": c["file"], "path": _path(c["path"], "a cite's") if c.get("path") else "", "name": c.get("name", "")})
    if len(out) > MAX_CITES:
        raise ValueError(f"a ChatMessage cites at most 16 files: {len(out)}")
    m.cites = out
    return m


@entry(NAMESPACE + "SharedFile")
@dataclass
class SharedFile:
    """A file on the content swarm in ``shared``; version 2 adds ``path`` and ``replaces``."""
    __agentspaces_omit_none__ = ("path", "replaces")
    schemaVersion: int = 1
    id: str = ""
    name: str = ""
    mediaType: str = "application/octet-stream"
    bytes: int = 0
    root: str = ""
    sha256: str = ""
    by: str = ""
    sharedWith: list = field(default_factory=list)
    at: str = ""
    path: str | None = None
    replaces: str | None = None


def shared_file(id, name, at, schemaVersion=1, mediaType="", bytes=0, root="", sha256="", by="", sharedWith=None, path=None, replaces=None) -> SharedFile:
    v = _version(schemaVersion, "SharedFile")
    if not name or not name.strip():
        raise ValueError("a shared file has a name")
    if bytes < 0:
        raise ValueError("a file's size is not negative")
    f = SharedFile(v, id, name, mediaType.strip() or "application/octet-stream" if mediaType else "application/octet-stream", bytes, root, sha256, by, list(sharedWith or []), at)
    if v == 1:
        if path is not None or replaces is not None:
            raise ValueError("a version 1 SharedFile carries no path and no replaces; write version 2 for them")
        return f
    f.path = _path(path, "a shared file's") if path else ""
    f.replaces = replaces or ""
    return f


@entry(NAMESPACE + "WorkingOn")
@dataclass
class WorkingOn:
    """What an agent holds while it works, in ``views``: one per agent and key, leased 60 s and renewed every 20 s."""
    schemaVersion: int = 1
    id: str = ""
    agent: str = ""
    key: str = ""
    files: list = field(default_factory=list)
    task: str = ""
    state: str = "working"
    since: str = ""


def working_on_id(agent: str, key: str) -> str:
    return f"working-{agent}-{key}"


def working_on(agent, since, key="", files=None, task="", state="working", id=None, schemaVersion=1) -> WorkingOn:
    """What an agent holds; ``task`` is at most 120 characters counted as UTF-16 code units, as Java and
    TypeScript count them, so a character past U+FFFF counts two."""
    units = utf16_units(task)
    if units > MAX_TASK:
        raise ValueError(f"a task line is at most 120 characters: {units}")
    return WorkingOn(schemaVersion, id or working_on_id(agent, key), agent, key, [_path(p, "a held file's") for p in files or []], task, _state(state), since)


@entry(NAMESPACE + "ChatProgress")
@dataclass
class ChatProgress:
    """An agent's progress on one line of a chat, in ``views``: one per line, leased 30 s and renewed every 10 s while working."""
    schemaVersion: int = 1
    id: str = ""
    key: str = ""
    inReplyTo: str = ""
    agent: str = ""
    state: str = "submitted"
    steps: list = field(default_factory=list)
    at: str = ""


def chat_progress_id(in_reply_to: str) -> str:
    return f"progress-{in_reply_to}"


def chat_progress(key, inReplyTo, agent, at, state="submitted", steps=None, id=None, schemaVersion=1) -> ChatProgress:
    out = []
    for s in steps or []:
        if s.get("kind") not in STEP_KINDS:
            raise ValueError(f"a step's kind is read, tool or write: {s.get('kind')}")
        if not s.get("at"):
            raise ValueError("a step has its time")
        out.append({"label": s.get("label", ""), "kind": s["kind"], "ref": s.get("ref", ""), "at": s["at"]})
    if len(out) > MAX_STEPS:
        raise ValueError(f"a progress entry keeps at most 20 steps: {len(out)}")
    return ChatProgress(schemaVersion, id or chat_progress_id(inReplyTo), key, inReplyTo, agent, _state(state), out, at)


# ---- the component builders, each the shape Surfaces writes in Java

def _comp(id, component):
    return {"id": id, "component": component}


def _put(m, key, value):
    if value and str(value).strip():
        m[key] = value


def _check(component, options, known, maxima=None):
    for k, v in options.items():
        if k not in known:
            raise ValueError(f"{component} has no property {k}; it takes {', '.join(known)}")
        words = known[k]
        if words:
            for w in v if isinstance(v, list) else [v]:
                if str(w) not in words:
                    raise ValueError(f"{component}.{k} takes {', '.join(words)}, not {w}")
        if isinstance(v, (int, float)) and not isinstance(v, bool) and maxima and k in maxima and v > maxima[k]:
            raise ValueError(f"{component}.{k} is at most {maxima[k]}{' (16 MiB)' if maxima[k] == 16777216 else ''}: {v}")


def title_bar(id, title, subtitle="", icon="", status=None, actions=None, menu=""):
    """The page's one bar: a title (a literal or ``{"path": ...}``), a subtitle, an icon, a status, buttons, a menu by id."""
    m = _comp(id, "TitleBar")
    m["title"] = title
    _put(m, "subtitle", subtitle)
    _put(m, "icon", icon)
    if status:
        m["status"] = status
    if actions:
        m["actions"] = list(actions)
    _put(m, "menu", menu)
    return m


def title_status(source, working="", idle=""):
    """A title bar's status: the path of the WorkingOn rows, and the words for working and for idle."""
    labels = {}
    _put(labels, "working", working)
    _put(labels, "idle", idle)
    return {"from": source, "labels": labels} if labels else {"from": source}


def title_action(id, label, icon, action_name):
    """A button in a header: its id, its words, an icon name (blank for none), and the action it dispatches."""
    m = {"id": id, "label": label}
    _put(m, "icon", icon)
    m["action"] = {"name": action_name}
    return m


def menu(id, trigger, items):
    """A menu behind a trigger, over items or the data model path that holds them."""
    m = _comp(id, "Menu")
    m["trigger"] = trigger
    m["items"] = list(items) if isinstance(items, list) else items
    return m


def trigger(kind, label=""):
    """What opens a menu: ``button``, ``overflow``, or ``context``, and its words."""
    m = {"kind": kind}
    _put(m, "label", label)
    return m


def menu_item(id, label, action_name, more=None):
    """A menu item, with ``shortcut``, ``group``, ``disabled``, ``checked`` or an action ``context`` in ``more``."""
    m = {"id": id, "label": label}
    action = {"name": action_name}
    for k, v in (more or {}).items():
        if k == "context":
            action["context"] = v
        elif v is not None and not (isinstance(v, str) and not v.strip()):
            m[k] = v
    m["action"] = action
    return m


def submenu(id, label, items):
    """A submenu: an item whose items open beside it, one level deep."""
    for i in items:
        if "items" in i:
            raise ValueError(f"a menu has one level of submenu: {i.get('id')} holds items of its own")
    return {"id": id, "label": label, "items": list(items)}


def split(id, orientation="horizontal", persist="", stack_below=0, panes=()):
    """Two or three panes, side by side or one over another, kept under ``persist``, stacked below ``stack_below`` pixels."""
    if len(panes) < 2 or len(panes) > 3:
        raise ValueError(f"a split has two or three panes: {len(panes)}")
    o = orientation or "horizontal"
    if o not in ("horizontal", "vertical"):
        raise ValueError(f"a split's orientation is horizontal or vertical: {orientation}")
    m = _comp(id, "Split")
    m["orientation"] = o
    _put(m, "persist", persist)
    if stack_below > 0:
        m["stackBelow"] = stack_below
    m["panes"] = list(panes)
    return m


def pane(id, child, size, min=0, collapsible=False, label=""):
    """One pane of a split: its id, its child (blank for an empty pane), its share, its minimum, whether it collapses, its name."""
    m = {"id": id}
    _put(m, "child", child)
    m["size"] = size
    if min > 0:
        m["min"] = min
    if collapsible:
        m["collapsible"] = True
    _put(m, "label", label)
    return m


_CHAT = {"reads": None, "progress": None, "files": None, "suggestions": None, "placeholder": None, "attach": None, "format": (PLAIN, MARKDOWN),
         "controls": ("copy", "retry", "stop", "feedback"), "max": None, "preview": None, "writeAction": None}
_TREE = {"reads": None, "working": None, "label": None, "upload": None, "preview": None, "chat": None, "actions": ("ask", "download", "share", "rename", "remove"),
         "badges": ("working", "new", "changed", "agent"), "agents": None, "flat": None, "accept": None, "maxBytes": None}
_PREVIEW = {"files": None, "maxBytes": None, "csvRows": None, "kinds": ("text/plain", "text/markdown", "text/csv", "image/png", "image/jpeg", "application/pdf")}


def chat(id, agent, key, options=None):
    """The one agentic chat of agentspaces-widgets: the agent named over the thread, its key, and its other options."""
    options = options or {}
    _check("Chat", options, _CHAT, {"max": 1000})
    m = _comp(id, "Chat")
    _put(m, "agent", agent)
    m["key"] = key or ""
    m.update(dict(sorted(options.items())))
    return m


def file_tree(id, reads="/files", options=None):
    """A tree of files over the SharedFile rows at ``reads``."""
    options = options or {}
    _check("FileTree", options, _TREE)
    m = _comp(id, "FileTree")
    m["reads"] = reads or "/files"
    m.update(dict(sorted(options.items())))
    return m


def file_preview(id, file, options=None):
    """One file by its media type: a file id, or ``{"path": ...}`` where a tree puts the person's choice."""
    options = options or {}
    _check("FilePreview", options, _PREVIEW, {"maxBytes": 16777216, "csvRows": 5000})
    m = _comp(id, "FilePreview")
    m["file"] = file
    m.update(dict(sorted(options.items())))
    return m
