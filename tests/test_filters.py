"""The portable field filter grammar (SPEC §7.2; srad/agentspaces-js.md JS-V-03): the cases the Java
FieldFilter decides, from the golden vector ``filter_grammar_cases`` once regenerated and from this inline
copy of the generator's list meanwhile."""

import json
import pathlib

import pytest

from agentspaces.space import Template, entry, parse_filter

GOLDEN = json.loads((pathlib.Path(__file__).parent / "golden.json").read_text())

CASES = [
    ("priority>=3", 3, True), ("priority>=3", 2.5, False), ("priority=3", 3.0, True), ("priority=3", "3", True),
    ("priority<10", 9, True), ("priority<10", "9", True), ("priority<10", "abc", False), ("priority > 1.5", 2, True),
    ("topic=index", "index", True), ("topic!=index", "other", True), ("topic!=index", None, True),
    ("topic=index", None, False), ("name<m", "alpha", True), ("name>m", "alpha", False), ("name<=alpha", "alpha", True),
    ("region in eu, us", "us", True), ("region in eu, us", "ap", False), ("n in 1,2,3", 2.0, True),
    ("flag=true", True, True), ("flag!=true", False, True), ("topic=a=b", "a=b", True), ("count>=0", 0, True),
    ("count<-1", -2, True), ("ratio>=0.5", 0.75, True), ("ratio>=0.5", "0.25", False),
]


def test_every_grammar_case_decides_as_java_does():
    for clause, value, expected in CASES:
        _, test = parse_filter(clause)
        assert test(value) == expected, (clause, value)
    for case in GOLDEN.get("filter_grammar_cases", []):
        assert parse_filter(case["filter"])[1](case["value"]) == case["matches"], case


def test_a_template_takes_clauses_beside_matchers_and_refuses_a_malformed_one():
    @entry("com.acme.Task#v1")
    class Task:
        def __init__(self, topic="", priority=0, region=""):
            self.topic, self.priority, self.region = topic, priority, region

    template = Template(Task, {"topic": "index"}, filters=["priority>=3", "region in eu,us"])
    assert template.matches({"topic": "index", "priority": 5, "region": "eu"})
    assert not template.matches({"topic": "index", "priority": 2, "region": "eu"})
    assert not template.matches({"topic": "index", "priority": 5, "region": "ap"})
    assert not template.matches({"topic": "other", "priority": 5, "region": "eu"})
    with pytest.raises(ValueError):
        parse_filter("nonsense")
    # the earliest operator wins: "!=x" is malformed, not the field "!" compared with "x"
    for clause in ["!=x", "=3", "<x", " in a,b", "topic!", ""] + GOLDEN.get("filter_grammar_malformed", []):
        with pytest.raises(ValueError, match="malformed field filter"):
            parse_filter(clause)
    assert parse_filter("a<b<=c")[1]("a")
    assert parse_filter("topic=a in b")[1]("a in b")
    with pytest.raises(ValueError):
        parse_filter("=3")


def test_the_binder_applies_the_grammar_to_takes_notifies_proposals_and_join_parts():
    """JS-V-03: ``filters=[...]`` on the decorators and on a ``Part`` reach the binding's template as
    Java's ``where`` strings reach ``AgentBinder.templateFor``; a malformed clause fails at bind time."""
    import time
    from dataclasses import dataclass

    from agentspaces import cbor, vote
    from agentspaces.agents import Binder, Joined, Part, agent, propose, space_join, space_notify, space_take
    from agentspaces.space import Space, Template
    from fleet import fleet

    @entry("com.acme.Job#v1")
    @dataclass
    class Job:
        topic: str
        priority: int
        region: str

    @entry("com.acme.Done#v1")
    @dataclass
    class Done:
        topic: str

    @entry("com.acme.Check#v1")
    @dataclass
    class Check:
        topic: str
        score: int

    @agent("filtered")
    class Filtered:
        def __init__(self):
            self.taken, self.noticed, self.joined = [], [], []

        @space_take("jobs", lease="1m", poll_timeout="300ms", filters=["priority>=3", "region in eu,us"])
        def work(self, job: Job) -> Done:
            self.taken.append(job.topic)
            return Done(job.topic)

        @space_notify("jobs", filters=["priority<3"])
        def notice(self, job: Job) -> None:
            self.noticed.append(job.topic)

        @propose("jobs", vote="votes", options=["yes", "no"], quorum=1, prefix="p:", key="topic",
                 filters=["region=ap"])
        def ask(self, job: Job) -> str:
            return f"ship {job.topic}?"

        @space_join("jobs", key="topic", parts=[Part(Job, filters=["priority>=3"]), Part(Check, filters=["score>50"])])
        def pair(self, joined: Joined) -> None:
            self.joined.append(joined.key)

    writer, worker = fleet("zPyFilters", 2)
    bound_agent = Filtered()
    bound = Binder(worker, publish_card=False).bind(bound_agent)
    space = Space(writer, "jobs")
    space.write(Job("eu-high", 5, "eu"))
    space.write(Job("eu-low", 1, "eu"))
    space.write(Job("ap-high", 5, "ap"))
    space.write(Check("eu-high", 80))
    space.write(Check("eu-low", 80))
    space.write(Check("ap-high", 10))
    deadline = time.time() + 6
    while time.time() < deadline and (len(bound_agent.taken) < 1 or not bound_agent.joined):
        time.sleep(0.05)
    bound.close()
    assert bound_agent.taken == ["eu-high"], "priority>=3 and region in eu,us: the eu-high job alone"
    assert bound_agent.noticed == ["eu-low"], "priority<3"
    assert list(vote.proposals(writer.states)) == ["p:ap-high"], "region=ap"
    assert bound_agent.joined == ["eu-high"], "both parts filtered: priority>=3 with score>50"
    assert space.read_all(Template(Done)) == [Done("eu-high")]
    assert "ap-high" in {cbor.loads(d["record"]["payload"])["topic"] for d in writer.states.values()
                         if d["record"]["type"] == "com.acme.Job#v1" and not d["completed"]}

    class Malformed:
        @space_take("jobs", filters=["!=x"])
        def work(self, job: Job) -> None:
            return None

    with pytest.raises(ValueError, match="malformed field filter"):
        Binder(worker, publish_card=False).bind(Malformed())
