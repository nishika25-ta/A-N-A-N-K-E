"""CLI contract tests: ledger init/apply/verify/show and policy validate, with exit codes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ananke.cli import app
from ananke_testkit import raw_attacker_connection, restore_triggers

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
runner = CliRunner()


def run(*args: str) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, list(args))
    return result.exit_code, json.loads(result.output)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "l.sqlite"
    code, out = run("ledger", "init", "--db", str(path), "--operator", "op-admin")
    assert code == 0 and out["status"] == "ok"
    return path


def test_full_operator_workflow(db: Path) -> None:
    code, out = run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(EXAMPLES / "policy.json"),
        "--at",
        "0",
    )
    assert code == 0 and len(out["committed"]) == 2  # type: ignore[arg-type]
    code, out = run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(EXAMPLES / "revoke.json"),
        "--at",
        "10",
    )
    assert code == 0
    code, out = run("ledger", "verify", "--db", str(db))
    assert code == 0 and out["ok"] is True and out["epoch"] == 4
    code, out = run("ledger", "show", "--db", str(db), "--at", "12")
    rules = {r["rule_id"]: r for r in out["rules"]}  # type: ignore[union-attr]
    assert rules["grant-001"]["status"] == "REVOKED"
    assert rules["grant-001"]["effective_at_tick"] is False
    assert rules["grant-002"]["effective_at_tick"] is True


def test_apply_rejects_unknown_operator_and_invalid_transition(db: Path) -> None:
    code, out = run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "agent-lab-01",
        "--changes",
        str(EXAMPLES / "policy.json"),
        "--at",
        "0",
    )
    assert code == 1 and out["code"] == "UNKNOWN_OPERATOR"
    code, out = run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(EXAMPLES / "revoke.json"),
        "--at",
        "0",
    )
    assert code == 1 and out["code"] == "TARGET_UNKNOWN"
    _, out = run("ledger", "verify", "--db", str(db))
    assert out["event_count"] == 0  # nothing partially committed


def test_apply_rejects_malformed_file(db: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('[{"kind": "GRANT", "rule_id": "g", "valid_from": 1.5}]')
    code, out = run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(bad),
        "--at",
        "0",
    )
    assert code == 1 and out["code"] == "POLICY_INVALID"


def test_verify_detects_tampering(db: Path) -> None:
    run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(EXAMPLES / "policy.json"),
        "--at",
        "0",
    )
    conn = raw_attacker_connection(db)
    conn.execute("UPDATE policy_events SET kind = 'DENY' WHERE sequence = 1")
    restore_triggers(conn)
    conn.close()
    code, out = run("ledger", "verify", "--db", str(db))
    assert code == 1 and out["ok"] is False
    code, out = run("ledger", "show", "--db", str(db))
    assert code == 1 and out["code"] == "POLICY_INVALID"


def test_missing_db_exit_2(tmp_path: Path) -> None:
    for args in (("ledger", "verify"), ("ledger", "show")):
        code, out = run(*args, "--db", str(tmp_path / "none.sqlite"))
        assert code == 2 and out["code"] == "LEDGER_UNAVAILABLE"


def test_init_refuses_existing(db: Path) -> None:
    code, _ = run("ledger", "init", "--db", str(db), "--operator", "op-admin")
    assert code == 1


def test_policy_validate(tmp_path: Path) -> None:
    code, out = run("policy", "validate", str(EXAMPLES / "policy.json"))
    assert code == 0 and out["resulting_epoch"] == 2
    code, out = run("policy", "validate", str(EXAMPLES / "revoke.json"))
    assert code == 1 and out["code"] == "TARGET_UNKNOWN"
    code, out = run("policy", "validate", str(tmp_path / "missing.json"))
    assert code == 2


def test_policy_validate_on_top_of_ledger(db: Path) -> None:
    run(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "op-admin",
        "--changes",
        str(EXAMPLES / "policy.json"),
        "--at",
        "0",
    )
    code, out = run("policy", "validate", str(EXAMPLES / "revoke.json"), "--db", str(db))
    assert code == 0 and out["resulting_epoch"] == 4
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM policy_events").fetchone()[0] == 2
