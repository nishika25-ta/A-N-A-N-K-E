"""Properties of assembly and labels: never over budget, policy never truncated, labels monotone."""

from __future__ import annotations

from hypothesis import event, given, settings
from hypothesis import strategies as st

from ananke.domain import Sensitivity, Trust
from ananke.memory import (
    BudgetExceededError,
    MemoryEntry,
    Origin,
    Salience,
    ScriptedSummarizer,
    assemble,
    derive_labels,
    estimate_lines,
    raw_entry,
)

text = st.text(alphabet="abcdefgh POLICY=:.\n", min_size=1, max_size=120).map(
    lambda s: s.strip() or "x"
)
entries = st.lists(
    st.tuples(st.sampled_from(list(Origin)), text, st.sampled_from(list(Sensitivity))),
    max_size=25,
).map(lambda xs: [raw_entry(f"m-{i}", o, c, i, sensitivity=s) for i, (o, c, s) in enumerate(xs)])
policies = st.none() | st.lists(text, max_size=15)


@settings(max_examples=300, deadline=None)
@given(entries, policies, st.integers(20, 3000) | st.integers(20, 160), st.booleans())
def test_never_over_budget_and_policy_complete(
    mem: list[MemoryEntry], policy: list[str] | None, budget: int, quarantine: bool
) -> None:
    try:
        ctx = assemble(
            strategy="p",
            now=1,
            epoch=1,
            system=["s"],
            tools=["t"],
            policy=policy,
            policy_label="",
            memory=mem,
            budget=budget,
            reserve_output=16,
            quarantine=quarantine,
        )
    except BudgetExceededError:
        event("budget-exceeded")
        need = estimate_lines(policy or []) + estimate_lines(["s", "t", "now=1"]) + 16
        assert need > budget - 20  # only when the mandatory part genuinely does not fit
        return
    event("assembled")
    assert ctx.total_tokens <= budget
    if policy is not None:
        pol = next(s for s in ctx.sections if s.name == "POLICY")
        assert list(pol.lines) == policy  # never truncated or reordered
    assert set(ctx.included_entry_ids) | set(ctx.dropped_entry_ids) == {e.entry_id for e in mem}


@settings(max_examples=200, deadline=None)
@given(entries, st.sampled_from(list(Salience)), st.integers(1, 8), st.booleans())
def test_summaries_never_promote_labels(
    mem: list[MemoryEntry], profile: Salience, n: int, partition: bool
) -> None:
    if not mem:
        return
    known = {e.entry_id: e for e in mem}
    out = ScriptedSummarizer(profile, n, partition).summarize(
        mem, id_prefix="s", now=99, cycle=1, known=known
    )
    for s in out:
        srcs = [known[i] for i in s.source_ids]
        assert s.trust.rank <= min(x.trust.rank for x in srcs)
        assert s.sensitivity.rank >= max(x.sensitivity.rank for x in srcs)
        assert len(s.content.splitlines()) <= n
        lines_in = {ln.strip() for x in srcs for ln in x.content.splitlines()}
        assert set(s.content.splitlines()) <= lines_in  # extractive: no invented content


@settings(max_examples=200, deadline=None)
@given(
    st.lists(st.sampled_from([f"m-{i}" for i in range(8)]), max_size=8),
    st.lists(st.sampled_from(list(Trust)), min_size=8, max_size=8),
)
def test_derive_labels_monotone(claimed: list[str], trusts: list[Trust]) -> None:
    known = {
        f"m-{i}": MemoryEntry.model_validate(
            {**raw_entry(f"m-{i}", Origin.TOOL_RESULT, "x", 0).model_dump(), "trust": t}
        )
        for i, t in enumerate(trusts)
        if i % 2 == 0
    }  # odd ids are unknown
    lab = derive_labels(claimed, known)
    if not claimed or any(c not in known for c in claimed):
        assert (lab.trust, lab.sensitivity) == (Trust.UNTRUSTED, Sensitivity.RESTRICTED)
    else:
        assert lab.trust.rank == min(known[c].trust.rank for c in claimed)
