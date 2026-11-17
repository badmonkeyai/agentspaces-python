"""A loaded version that a loaded head supersedes through a version still loading is no head (Java's Refs.heads).

Java's spoiler scenario SC-I4 found the defect: with the middle of a chain late at a reader, heads_among read base links
only among the versions that loaded, so the version below the late one was read as a head and merged in, and a key a
later version removed came back for that read. Every port reads heads the same way, so each carries the same fold.
"""

from agentspaces.pdt import refs
from test_pdt_refs_round_five import _Graph


def _chain_with_a_late_middle():
    # A <- X <- H, and F beside them; X is still loading at this reader, the rest loaded
    g = _Graph()
    a = g.version()
    x = g.version(a.root)
    h = g.version(x.root)
    f = g.version()
    live = [a, x, h, f]
    g.ref._live_entries = lambda: live
    g.ref._loadable = lambda heads, wait: [v for v in heads if v is not x]
    return g, a, x, h, f, live


def test_the_rule_alone_reads_the_version_below_a_late_middle_as_a_head():
    # the precondition the fold answers: base links among the loaded versions only cannot see that H supersedes A
    g, a, x, h, f, live = _chain_with_a_late_middle()
    assert {v.root for v in refs.heads_among([a, h, f])} == {a.root, h.root, f.root}


def test_a_late_middle_version_makes_no_ancestor_a_head():
    g, a, x, h, f, live = _chain_with_a_late_middle()
    heads = g.ref.heads()
    assert {v.root for v in heads} == {h.root, f.root}
    assert a.root not in {v.root for v in heads}, "A is superseded by H through X, which is still loading"


def test_the_fold_finds_every_version_a_loaded_one_supersedes_through_live_ones():
    g, a, x, h, f, live = _chain_with_a_late_middle()
    folded = refs.superseded_by([a, h, f], live)
    assert (a.root, a.entry_id) in folded and (x.root, x.entry_id) in folded
    assert (h.root, h.entry_id) not in folded and (f.root, f.entry_id) not in folded


def test_with_nothing_loading_the_heads_are_the_rule_s_own():
    g, a, x, h, f, live = _chain_with_a_late_middle()
    g.ref._loadable = lambda heads, wait: list(heads)
    assert {v.root for v in g.ref.heads()} == {v.root for v in refs.heads_among(live)} == {h.root, f.root}
