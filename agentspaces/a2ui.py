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
of agentspaces-viz, and ``chat``, ``file_tree`` and ``file_preview`` of agentspaces-widgets. They hold each component to
A2UI 1.0 as Java does: a binding is ``{"@path": ...}``, an id is an identifier, and a component's kept keys carry their ``@``.
"""

import unicodedata
from dataclasses import dataclass, field

from .cbor import utf16_units
from .space import entry

NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui/v1/"
HINT = "a2ui.records"
HINT_VALUE = "3"   # the newest version of the records this client reads (3: the chat's confirm block)
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


def latest(record_type: str) -> int:
    """The newest version of a record by its simple name or IRI: 3 for ChatMessage, 2 for SharedFile, 1 for the rest."""
    simple = record_type[record_type.rfind("/") + 1:]
    return 3 if simple == "ChatMessage" else 2 if simple == "SharedFile" else 1


def version_at(reader_hints, newest: int) -> int:
    """The version a writer writes of a record whose newest is ``newest``: the lowest level its readers
    advertise (1 for none or a level that does not read), never above ``newest``."""
    v = newest
    for hints in reader_hints:
        h = hints.get(HINT)
        level = int(h) if h is not None and h.isascii() and h.isdigit() and len(h) <= 9 else 1
        v = min(v, max(1, level))
    return v


CONFIRM_KINDS = ("approval", "confirm", "review", "choice", "input")
CONFIRM_OPTIONS = ("approve", "reject", "amend")
CONFIRM_REASONS = ("none", "optional", "required")
CONFIRM_VERDICTS = ("approved", "rejected", "amended", "expired", "cancelled")
MAX_CONFIRM_TEXT = 2000


def confirm(invocationId, question, desk="", kind="", action="", arguments="", summary="", deadline=None, options=None, reasons="",
            code="", state="", verdict="", by=None, reason="", approvals=0, quorum=1) -> dict:
    """A desk's request as a chat shows it (ChatMessage version 3, SPEC §6.1a.7), checked as the Java record checks
    it, its keys in Java's declared order; a null deadline is left out, as Java leaves it out."""
    if not invocationId or not str(invocationId).strip():
        raise ValueError("a confirm names the request it is for")
    kind = kind or "approval"
    if kind not in CONFIRM_KINDS:
        raise ValueError(f"a confirm's kind is one of {', '.join(CONFIRM_KINDS)}: {kind}")
    question = question or ""
    if not question.strip():
        raise ValueError("a confirm carries the question a person answers")
    summary = summary or ""
    if utf16_units(question) > MAX_CONFIRM_TEXT or utf16_units(summary) > MAX_CONFIRM_TEXT:
        raise ValueError("a confirm's question and summary are at most 2000 characters each")
    options = list(options) if options else ["approve", "reject"]
    for o in options:
        if o not in CONFIRM_OPTIONS:
            raise ValueError(f"a confirm's options are approve, reject and amend: {o}")
    reasons = reasons or "optional"
    if reasons not in CONFIRM_REASONS:
        raise ValueError(f"a confirm's reasons is none, optional or required: {reasons}")
    state = state or "pending"
    if state not in ("pending", "decided"):
        raise ValueError(f"a confirm's state is pending or decided: {state}")
    verdict = verdict or ""
    if (state == "decided") != (verdict in CONFIRM_VERDICTS):
        raise ValueError(f"a decided confirm carries its verdict, a pending one none: {verdict}")
    if approvals < 0:
        raise ValueError("a confirm's approvals are not negative")
    c = {"invocationId": invocationId, "desk": desk or "", "kind": kind, "question": question, "action": action or "",
         "arguments": arguments if arguments and arguments.strip() else "{}", "summary": summary}
    if deadline is not None:
        c["deadline"] = deadline
    c.update({"options": options, "reasons": reasons, "code": code or "", "state": state, "verdict": verdict, "by": list(by or []),
              "reason": reason or "", "approvals": approvals, "quorum": max(1, quorum)})
    return c


def answer(invocationId, verdict, reason="", amendedArguments="") -> dict:
    """A person's answer to a confirm (ChatMessage version 3), checked as the Java record checks it."""
    if not invocationId or not str(invocationId).strip():
        raise ValueError("an answer names the request it answers")
    if verdict not in CONFIRM_OPTIONS:
        raise ValueError(f"an answer's verdict is approve, reject or amend: {verdict}")
    reason = reason or ""
    if utf16_units(reason) > MAX_CONFIRM_TEXT:
        raise ValueError("an answer's reason is at most 2000 characters")
    amendedArguments = amendedArguments or ""
    if amendedArguments and verdict != "amend":
        raise ValueError("only an amend carries amended arguments")
    return {"invocationId": invocationId, "verdict": verdict, "reason": reason, "amendedArguments": amendedArguments}


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
    """One line of a thread in ``conversations``; version 2 adds ``format`` and ``cites``, version 3 ``confirm`` and ``answer``."""
    __agentspaces_wire_names__ = {"from_": "from"}
    __agentspaces_omit_none__ = ("format", "cites", "confirm", "answer")
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
    confirm: dict | None = None
    answer: dict | None = None


def chat_message(id, key, at, schemaVersion=1, text="", attachments=None, inReplyTo="", format=None, cites=None, confirm=None, answer=None, **kw) -> ChatMessage:
    """A line, checked as the Java record checks it; ``from`` (or ``from_``) is the author's kind, name and peer.
    A version 3 line may carry a ``confirm`` or an ``answer`` (dicts of their fields), never both."""
    if schemaVersion not in (1, 2, 3):
        raise ValueError(f"a ChatMessage has schemaVersion 1, 2 or 3: {schemaVersion}")
    v = schemaVersion
    if v < 3 and (confirm is not None or answer is not None):
        raise ValueError(f"a version {v} ChatMessage carries no confirm and no answer; write version 3 for them")
    if confirm is not None and answer is not None:
        raise ValueError("a ChatMessage carries a confirm or an answer, not both")
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
    if confirm is not None:
        m.confirm = globals()["confirm"](**confirm)
    if answer is not None:
        m.answer = globals()["answer"](**answer)
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


# ---- the component builders, each the shape Surfaces writes in Java, held to A2UI 1.0 as Java holds them

#: A2UI 1.0's component envelope keys (spec 2.9): the only ``@``-prefixed keys at a component's top level. ``id`` and
#: ``component`` stay bare. The open catalogs declare the first three on every component, so a builder takes them as options.
ENVELOPE_KEYS = ("@catalogId", "@accessibility", "@metadata", "@checks")
_OPTION_ENVELOPE_KEYS = ("@catalogId", "@accessibility", "@metadata")


def _id_char(c, first):
    return c == "_" or c.isalpha() or (not first and unicodedata.category(c) == "Nd")


def component_id(id):
    """Refuses a component id A2UI 1.0 refuses, naming a form it takes: an id is a Unicode identifier (UAX #31), so
    ``barMenu`` and ``bar_menu`` pass and ``bar-menu`` does not. Returns the id. Java's pen checks the same rule as it writes."""
    s = "" if id is None else str(id)
    if not s or not _id_char(s[0], True) or not all(_id_char(c, False) for c in s[1:]):
        words, word = [], ""
        for c in s:
            if _id_char(c, False):
                word += c
            elif word:
                words.append(word)
                word = ""
        if word:
            words.append(word)
        hint = words[0] + "".join(w[0].upper() + w[1:] for w in words[1:]) if words else "root"
        raise ValueError(f"component id '{s}' is not an A2UI 1.0 identifier (UAX #31): use letters, digits and _ only, such as {hint}")
    return s


def _reserved(key):
    """A key in 1.0's reserved single-``@`` namespace, ``^@([^@]|$)``; a doubled ``@@`` is a literal."""
    return key.startswith("@") and not key.startswith("@@")


def _binding(where, value, keys_are_names=False):
    """Walks a value to its leaves as Java's ``Surfaces.binding`` does: v0.9.1's ``{"path": ...}`` binding and
    ``{"call": ...}`` function call are refused, naming where they sit, as is a key in 1.0's reserved ``@`` namespace
    other than ``@path`` and ``@call`` (a literal one is written doubled, ``@@type``). An action's ``context`` is a record
    whose keys are names, so an entry called ``path`` there passes, and its values are walked like any other."""
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _binding(f"{where}[{i}]", v)
        return
    if not isinstance(value, dict):
        return
    if not keys_are_names and "path" in value and "@path" not in value:
        raise ValueError(f'{where} binds with A2UI 1.0\'s {{"@path": ...}}, not v0.9.1\'s {{"path": ...}}')
    if not keys_are_names and "call" in value and "@call" not in value:
        raise ValueError(f'{where} calls a function with A2UI 1.0\'s {{"@call": ...}}, not v0.9.1\'s {{"call": ...}}')
    for k, v in value.items():
        k = str(k)
        if _reserved(k) and k not in ("@path", "@call"):
            raise ValueError(f"{where}.{k} is a reserved A2UI 1.0 key; a literal key that starts with @ is written @{k}")
        _binding(f"{where}.{k}", v, k == "context" and not keys_are_names and "name" in value)


def _checked(m):
    """Holds one built component to A2UI 1.0, as Java's ``Surfaces.bindings`` does: its id is an identifier, its kept
    keys carry their ``@`` (a bare ``catalogId``, ``accessibility``, ``metadata`` or ``checks`` is refused, naming the
    ``@`` key), no other top-level key starts with a single ``@``, and every property is walked. Returns the component."""
    name = str(m["component"])
    component_id(m["id"])
    for k, v in m.items():
        if "@" + k in ENVELOPE_KEYS:
            raise ValueError(f"{name}.{k} is A2UI 1.0's @{k} envelope key, not {k}")
        if _reserved(k) and k not in ENVELOPE_KEYS:
            raise ValueError(f"{name}.{k} is a reserved A2UI 1.0 key; a component's top level takes only {', '.join(ENVELOPE_KEYS)}")
        if k not in ("id", "component"):
            _binding(f"{name}.{k}", v)
    return m


def _comp(id, component):
    return {"id": id, "component": component}


def _put(m, key, value):
    if value and str(value).strip():
        m[key] = value


def _check(component, options, known, maxima=None):
    """Refuses an option a component does not take, or a word outside its list, as the Java builders check the catalog.
    The envelope keys the open catalogs declare on every component are taken, and a bare one is refused naming its ``@`` key."""
    for k, v in options.items():
        if k in _OPTION_ENVELOPE_KEYS:
            continue
        if k not in known and "@" + k in ENVELOPE_KEYS:
            raise ValueError(f"{component}.{k} is A2UI 1.0's @{k} envelope key, not {k}")
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
    """The page's one bar: a title (a literal or ``{"@path": ...}``), a subtitle, an icon, a status, buttons, a menu by id."""
    m = _comp(id, "TitleBar")
    m["title"] = title
    _put(m, "subtitle", subtitle)
    _put(m, "icon", icon)
    if status:
        m["status"] = status
    if actions:
        m["actions"] = list(actions)
    _put(m, "menu", menu)
    return _checked(m)


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
    return _checked(m)


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
    _binding("Menu.items[]", m)
    return m


def submenu(id, label, items):
    """A submenu: an item whose items open beside it, one level deep."""
    for i in items:
        if "items" in i:
            raise ValueError(f"a menu has one level of submenu: {i.get('id')} holds items of its own")
    m = {"id": id, "label": label, "items": list(items)}
    _binding("Menu.items[]", m)
    return m


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
    return _checked(m)


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
    _suggestions(options.get("suggestions"))
    m = _comp(id, "Chat")
    _put(m, "agent", agent)
    m["key"] = key or ""
    m.update(dict(sorted(options.items())))
    return _checked(m)


def _suggestions(value):
    """A Chat's ``suggestions`` is a list of strings, or one binding ``{"@path": "/..."}`` to the rows the agent writes,
    as the catalog's ``oneOf`` says; anything else is refused here, and an old form is named by the binding walk."""
    if value is None:
        return
    _binding("Chat.suggestions", value)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return
    if isinstance(value, dict) and len(value) == 1 and isinstance(value.get("@path"), str) and value["@path"].startswith("/"):
        return
    raise ValueError(f'Chat.suggestions is a list of strings or one binding {{"@path": "/..."}} to the agent\'s rows, not {value!r}')


def file_tree(id, reads="/files", options=None):
    """A tree of files over the SharedFile rows at ``reads``."""
    options = options or {}
    _check("FileTree", options, _TREE)
    m = _comp(id, "FileTree")
    m["reads"] = reads or "/files"
    m.update(dict(sorted(options.items())))
    return _checked(m)


def file_preview(id, file, options=None):
    """One file by its media type: a file id, or ``{"@path": ...}`` where a tree puts the person's choice."""
    options = options or {}
    _check("FilePreview", options, _PREVIEW, {"maxBytes": 16777216, "csvRows": 5000})
    m = _comp(id, "FilePreview")
    m["file"] = file
    m.update(dict(sorted(options.items())))
    return _checked(m)
