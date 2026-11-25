"""The offline enforcement demo runs from a clean state, deterministically, with no network."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from ananke.bench.demo_gateway import run_demo, run_demo_in_tempdir
from ananke.cli import app


def test_demo_outcomes_match_declared_expectations() -> None:
    result = run_demo_in_tempdir(42)
    agent_steps = [s for s in result["steps"] if s["actor"] == "agent"]
    assert result["all_outcomes_as_expected"] is True
    assert all(s["as_expected"] for s in agent_steps)
    assert result["ledger_verification"] == {
        "ok": True,
        "epoch": 4,
        "events": 4,
        "authenticity": "signed",
    }
    assert [(e["tool"], e["operation"]) for e in result["committed_effects"]] == [
        ("ticket", "read"),
        ("report", "read"),
        ("report", "publish_mock"),
    ]
    stale = next(s for s in agent_steps if s["label"].startswith("stale"))
    assert (stale["outcome"], stale["reason"], stale["epoch"]) == ("DENY", "GRANT_REVOKED", 2)
    assert "scope_note" in result and "No memory/compaction" in result["scope_note"]


def test_demo_is_deterministic() -> None:
    assert run_demo_in_tempdir(42)["trace_digest"] == run_demo_in_tempdir(42)["trace_digest"]


def test_demo_cli_exit_code_and_kept_workdir(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["demo-gateway", "--offline", "--seed", "7", "--workdir", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["all_outcomes_as_expected"] is True
    rows = sqlite3.connect(tmp_path / "demo.sqlite").execute("SELECT canonical FROM decisions")
    assert not any(b"SYNTHETIC-SECRET" in r[0] for r in rows)


def test_demo_cli_refuses_online_and_nonempty_workdir(tmp_path: Path) -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["demo-gateway", "--no-offline"]).exit_code == 2
    (tmp_path / "x").write_text("occupied")
    assert runner.invoke(app, ["demo-gateway", "--workdir", str(tmp_path)]).exit_code == 2


def test_demo_function_with_explicit_dir(tmp_path: Path) -> None:
    assert run_demo(tmp_path, 1)["all_outcomes_as_expected"] is True
