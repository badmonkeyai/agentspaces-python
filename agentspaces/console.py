"""The Bad Monkey console records as data (enterprise platform, spiral 3
S3-H-06): the entry types the console and its agents write into a group's
``constraints``, ``policy``, ``decisions``, and ``findings`` spaces, named by
the console namespace ``https://badmonkey.ai/console#<Record>`` so a Python
peer reads them with the same ``Template`` it uses for its own entries. A
field the wire carries that a class here does not declare is ignored.

    from agentspaces.console import Constraint, rules
    space = Space(peer, "constraints")
    for c in space.entries(Template(Constraint)):
        print(c.value.template, c.value.a, c.value.b)
    counts = {k: len(v) for k, v in rules(peer).items()}
"""

import re
from dataclasses import dataclass, field

from .space import Space, Template, entry

NAMESPACE = "https://badmonkey.ai/console#"


def console_type(name: str) -> str:
    """The wire schema name of a console record, by its record name."""
    return NAMESPACE + name


@entry(console_type("Vocabulary"))
@dataclass
class Vocabulary:
    """The conditions a rule book names, one version at a time."""
    schemaVersion: int = 1
    book: str = ""
    version: int = 0
    hash: str = ""
    conditions: dict = field(default_factory=dict)


@entry(console_type("Constraint"))
@dataclass
class Constraint:
    """One compiled sentence of a rule book: a template over two conditions,
    its guards, its window, the key it correlates on, and its enforcement."""
    schemaVersion: int = 1
    book: str = ""
    version: int = 0
    unit: str = ""
    template: str = ""
    a: str = ""
    aGuard: list = field(default_factory=list)
    b: str = ""
    bGuard: list = field(default_factory=list)
    n: int = 0
    within: str = ""
    key: str = ""
    enforcement: list = field(default_factory=list)
    jury: dict = field(default_factory=dict)


@entry(console_type("AgentConfiguration"))
@dataclass
class AgentConfiguration:
    """A configuration version the console carries to an agent instance."""
    schemaVersion: int = 1
    agent: str = ""
    instance: str = ""
    group: str = ""
    version: int = 0
    hash: str = ""
    body: dict = field(default_factory=dict)
    scope: dict = field(default_factory=dict)
    approval: str = ""
    publishedBy: str = ""
    publishedAt: object = None


@entry(console_type("JuryDecision"))
@dataclass
class JuryDecision:
    """A jury's verdict on one unit of a rule book under a key."""
    schemaVersion: int = 1
    book: str = ""
    version: int = 0
    unit: str = ""
    key: str = ""
    motion: str = ""
    verdict: str = ""
    ballots: list = field(default_factory=list)
    at: object = None


@entry(console_type("Finding"))
@dataclass
class Finding:
    """What the console or an agent noticed, with what to do about it."""
    schemaVersion: int = 1
    id: str = ""
    kind: str = ""
    subject: str = ""
    severity: str = ""
    text: str = ""
    suggested: str = ""
    at: object = None


#: Where the console writes each record, by record name.
SPACES = {
    "Vocabulary": "constraints",
    "Constraint": "constraints",
    "AgentConfiguration": "policy",
    "JuryDecision": "decisions",
    "Finding": "findings",
}

TYPES = {
    "Vocabulary": Vocabulary,
    "Constraint": Constraint,
    "AgentConfiguration": AgentConfiguration,
    "JuryDecision": JuryDecision,
    "Finding": Finding,
}


def rules(peer, limit: int = 100, names=("Vocabulary", "Constraint", "AgentConfiguration", "JuryDecision"),
          settle_seconds: float = 2.0) -> dict:
    """The rule entries of the peer's group as data: a list of values per
    record name, read from the space the console writes each into. A late
    joiner holds nothing of a space until it pulls it, so each space named is
    pulled (at most once per ``settle_seconds``) before the read; what the
    pull brings arrives on the next call."""
    spaces: dict[str, Space] = {}
    out: dict[str, list] = {}
    for name in names:
        space_name = SPACES[name]
        space = spaces.get(space_name)
        if space is None:
            peer.pull_space_paced(space_name, settle_seconds)
            space = spaces[space_name] = Space(peer, space_name)
        out[name] = [e.value for e in space.entries(Template(TYPES[name]), limit=limit)]
    return out

# ---- spiral 4 (S4-B-02): the standard entries of the Apps tier, under their own namespace

APPS_NAMESPACE = "https://badmonkey.ai/ns/apps/v1/"
APPS_SPACES = {"ChatMessage": "conversations", "ResearchRequest": "research", "ResearchResult": "research",
               "SharedObject": "shared", "SharedFile": "shared"}


def apps_type(name: str) -> str:
    """The wire schema name of a standard Apps entry, by its record name."""
    return APPS_NAMESPACE + name


@entry(apps_type("ChatMessage"))
@dataclass
class ChatMessage:
    __agentspaces_wire_names__ = {"from_": "from"}
    """One line of a thread in a group's ``conversations`` space; ``from_`` is
    ``{"kind": "person"|"agent", "name", "peer"}`` and lands on the wire as ``from``."""
    schemaVersion: int = 1
    id: str = ""
    key: str = ""
    from_: dict = field(default_factory=lambda: {"kind": "person", "name": "", "peer": ""})
    text: str = ""
    attachments: list = field(default_factory=list)
    inReplyTo: str = ""
    at: str = ""


@entry(apps_type("ResearchRequest"))
@dataclass
class ResearchRequest:
    """A question over named sources for named agents under a budget and a deadline, in ``research``."""
    schemaVersion: int = 1
    id: str = ""
    key: str = ""
    question: str = ""
    sources: list = field(default_factory=list)
    agents: list = field(default_factory=list)
    budget: dict = field(default_factory=lambda: {"scope": "", "limit": 0.0, "currency": "USD"})
    deadline: str = ""
    requestedBy: str = ""
    at: str = ""


@entry(apps_type("ResearchResult"))
@dataclass
class ResearchResult:
    """One agent's answer to a ResearchRequest, with citations and shared objects, in ``research``."""
    schemaVersion: int = 1
    id: str = ""
    request: str = ""
    agent: str = ""
    text: str = ""
    citations: list = field(default_factory=list)
    objects: list = field(default_factory=list)
    confidence: float | None = None
    at: str = ""


@entry(apps_type("SharedObject"))
@dataclass
class SharedObject:
    """A reference to an entry, never a copy, in ``shared``."""
    schemaVersion: int = 1
    id: str = ""
    type: str = ""
    key: str = ""
    title: str = ""
    summary: str = ""
    by: str = ""
    sharedWith: list = field(default_factory=list)
    entry: dict | None = None
    at: str = ""


@entry(apps_type("SharedFile"))
@dataclass
class SharedFile:
    """A file on the content swarm, named by its root and digest, in ``shared``."""
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

# ---- spiral 4 (S4-B-16): the A2UI records of agentspaces-a2ui, named by the console as before


@entry(console_type("Surface"))
@dataclass
class Surface:
    """One A2UI envelope of a surface in a group's ``views`` space: the app, the
    surface id, the catalog, the sequence number, the message (one of
    createSurface, updateComponents, updateDataModel, deleteSurface, with its
    ``version``), and the protocol version."""
    schemaVersion: int = 1
    app: str = ""
    surfaceId: str = ""
    catalogId: str = ""
    seq: int = 0
    message: dict = field(default_factory=dict)
    version: str = "v0.9.1"
    at: str = ""


@entry(console_type("SurfaceAction"))
@dataclass
class SurfaceAction:
    """A renderer's action on a surface, with the session it came through."""
    schemaVersion: int = 1
    app: str = ""
    surfaceId: str = ""
    session: str = ""
    action: dict = field(default_factory=dict)
    at: str = ""


# ---- spiral 4 §3.6 (S4-P-03): the prompt library on the client side

PROMPTS_KIND = "bma-console/prompts"
PROMPTS_INSTANCE = "prompts"
PROMPT_HINT_PREFIX = "prompt."
_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.-]*)\}")


def render_prompt(text: str, variables, values) -> str:
    """The text with its ``{placeholders}`` filled from ``values``; a required
    variable that is missing is refused, an optional one is filled with an
    empty string. ``variables`` is the list of ``{name, type, required, example}``
    the prompt declares (the Java ``Prompt.render`` rule)."""
    values = values or {}
    for v in variables or ():
        name = v.get("name") if isinstance(v, dict) else getattr(v, "name", "")
        required = v.get("required") if isinstance(v, dict) else getattr(v, "required", False)
        if required and not str(values.get(name, "") or "").strip():
            raise ValueError("the prompt needs {" + str(name) + "}")
    return _PLACEHOLDER.sub(lambda m: "" if values.get(m.group(1)) is None else str(values.get(m.group(1))), text or "")


def prompt_set(peer, limit: int = 64, settle_seconds: float = 2.0):
    """The group's ``PromptSet`` in force (the newest ``AgentConfiguration`` of
    kind ``bma-console/prompts`` in the ``policy`` space), as the dict the console
    published (``group``, ``prompts`` of ``{id, version, hash, kind, text, variables}``),
    or ``None`` before any arrived."""
    peer.pull_space_paced(SPACES["AgentConfiguration"], settle_seconds)
    space = Space(peer, SPACES["AgentConfiguration"])
    newest = None
    for e in space.entries(Template(AgentConfiguration), limit=limit):
        c = e.value
        if c.agent == PROMPTS_KIND and c.instance == PROMPTS_INSTANCE and (newest is None or c.version > newest.version):
            newest = c
    return None if newest is None else newest.body


class PromptRef:
    """A reference to a prompt of the library: the version in force from the
    group's set through ``loader`` (a callable returning the set dict or None),
    or the fallback the agent ships with. ``render`` fills the placeholders;
    ``hint`` is the ``prompt.<id>=<version>`` pair an agent reports."""

    def __init__(self, ref: str, fallback: str = "", loader=None):
        self.ref = ref
        self.fallback = fallback or ""
        self._loader = loader or (lambda: None)

    def entry(self):
        s = self._loader()
        for e in (s or {}).get("prompts", []) if s else []:
            if e.get("id") == self.ref:
                return e
        return None

    @property
    def version(self) -> int:
        e = self.entry()
        return int(e.get("version", 0)) if e else 0

    @property
    def text(self) -> str:
        e = self.entry()
        return e.get("text", "") if e else self.fallback

    def render(self, values=None) -> str:
        e = self.entry()
        return render_prompt(e["text"], e.get("variables", []), values) if e else render_prompt(self.fallback, [], values)

    @property
    def hint(self):
        return (PROMPT_HINT_PREFIX + self.ref, str(self.version))


def prompt(peer, ref: str, fallback: str = "") -> PromptRef:
    """A ``PromptRef`` reading the peer's group for its set on every use."""
    return PromptRef(ref, fallback, lambda: prompt_set(peer))

