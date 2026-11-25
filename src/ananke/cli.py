"""ANANKE command-line interface.

Only commands that are implemented are exposed. Target commands from MASTERPLAN.md section 10
(``demo``, ``policy validate``, ``ledger verify``, ``bench run`` ...) are added in the phase that
implements them, never as placeholders.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import TypeAdapter, ValidationError

from ananke import __version__
from ananke.audit import AuditReport, audit_connection
from ananke.domain import (
    CANONICALIZATION_VERSION,
    CanonicalizationError,
    ClockError,
    InvalidIdentifierError,
    LogicalClock,
    PolicyChange,
    digest,
    validate_resource,
)
from ananke.ledger import (
    EMPTY_STATE,
    LedgerIntegrityError,
    LedgerUnavailableError,
    OperatorChannel,
    PolicyState,
    PolicyTransitionError,
    SchemaError,
    UnknownOperatorError,
    init_ledger,
    load_state,
    open_ledger,
    validate_changes,
    verify_ledger,
)

app = typer.Typer(
    name="ananke",
    help="ANANKE research prototype (synthetic, offline).",
    no_args_is_help=True,
    add_completion=False,
)
ledger_app = typer.Typer(
    help="Policy ledger (operator-side, local, trusted).", no_args_is_help=True
)
policy_app = typer.Typer(help="Policy change files.", no_args_is_help=True)
bench_app = typer.Typer(help="Offline benchmark harness (scripted agent).", no_args_is_help=True)
app.add_typer(ledger_app, name="ledger")
app.add_typer(policy_app, name="policy")
app.add_typer(bench_app, name="bench")
REPO_ROOT = Path(__file__).resolve().parents[2]

EXIT_OK, EXIT_FAIL, EXIT_UNAVAILABLE = 0, 1, 2
MAX_SAFE_INT = 2**53 - 1


def audit_ledger(db: Path) -> AuditReport:
    """Open the ledger read-only-in-practice and run the evidence audit."""
    conn = open_ledger(db)
    try:
        return audit_connection(conn)
    finally:
        conn.close()


_CHANGES = TypeAdapter(list[PolicyChange])
DbOpt = Annotated[Path, typer.Option("--db", help="Path to the ledger SQLite file.")]


def _emit(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _fail(code: str, detail: str, exit_code: int = EXIT_FAIL) -> NoReturn:
    _emit({"status": "error", "code": code, "detail": detail})
    raise typer.Exit(code=exit_code)


def _read_changes(path: Path) -> list[PolicyChange]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _fail("FILE_UNREADABLE", f"{path.name}: {exc.strerror}", EXIT_UNAVAILABLE)
    try:
        return _CHANGES.validate_json(raw)
    except ValidationError as exc:
        errors = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"]} for e in exc.errors()[:20]]
        _emit({"status": "error", "code": "POLICY_INVALID", "errors": errors})
        raise typer.Exit(code=EXIT_FAIL) from None


def _state_summary(state: PolicyState, at: int | None) -> dict[str, object]:
    rules = []
    for rule_id, r in sorted(state.rules.items()):
        entry: dict[str, object] = {
            "rule_id": rule_id,
            "effect": r.effect.value,
            "status": r.status.value,
            "principal_id": r.principal_id,
            "tool_id": r.tool_id,
            "operation": r.operation,
            "resource_scope": r.resource_scope,
            "valid_from": r.valid_from,
            "valid_until": r.valid_until,
            "requires_approval": r.requires_approval,
            "replaced_by": r.replaced_by,
        }
        if at is not None:
            entry["effective_at_tick"] = r.status.value == "ACTIVE" and r.in_validity_window(at)
        rules.append(entry)
    return {
        "epoch": state.epoch,
        "last_sequence": state.last_sequence,
        "head_hash": state.head_hash,
        "state_digest": state.state_digest(),
        "rules": rules,
    }


# Fixed test vector: the trusted example event from MASTERPLAN.md section 8.
SELFCHECK_VECTOR = {
    "kind": "GRANT",
    "principal_id": "agent-lab-01",
    "rule_id": "grant-001",
    "tool_id": "ticket",
    "operation": "read",
    "resource_scope": "ticket:demo-42",
    "valid_from": 0,
    "valid_until": 20,
    "requires_approval": False,
}
SELFCHECK_DIGEST = "sha256:f45d73cad23965b1fffed61db1db099b4f80139d16c9ced3e04831fb655260d8"


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


def _run_selfcheck() -> dict[str, bool]:
    checks: dict[str, bool] = {}
    checks["canonical_digest_vector"] = digest(SELFCHECK_VECTOR) == SELFCHECK_DIGEST
    reordered = dict(reversed(list(SELFCHECK_VECTOR.items())))
    checks["canonical_order_independent"] = digest(reordered) == SELFCHECK_DIGEST

    try:
        digest({"x": float("nan")})
        checks["rejects_nonfinite"] = False
    except CanonicalizationError:
        checks["rejects_nonfinite"] = True

    clock = LogicalClock()
    clock.advance(10)
    try:
        clock.advance_to(5)
        checks["clock_monotonic"] = False
    except ClockError:
        checks["clock_monotonic"] = clock.now() == 10

    rejected = 0
    bad = ["ticket:../demo-42", "ticket:*", "ticket:demo 42", "/etc/passwd", "ticket:demo/42"]
    for candidate in bad:
        try:
            validate_resource(candidate)
        except InvalidIdentifierError:
            rejected += 1
    checks["rejects_ambiguous_resources"] = rejected == len(bad)
    return checks


@app.command()
def selfcheck(
    offline: Annotated[
        bool, typer.Option("--offline/--no-offline", help="Must be offline in Phase 0.")
    ] = True,
) -> None:
    """Run deterministic offline self-checks of domain primitives. Exit 1 on any failure."""
    if not offline:
        typer.echo("error: only --offline is supported", err=True)
        raise typer.Exit(code=2)
    checks = _run_selfcheck()
    ok = all(checks.values())
    report = {
        "ananke_version": __version__,
        "canonicalization": CANONICALIZATION_VERSION,
        "checks": checks,
        "status": "pass" if ok else "fail",
    }
    typer.echo(json.dumps(report, indent=2, sort_keys=True))
    if not ok:
        raise typer.Exit(code=1)


# ----------------------------------------------------------------------------- demo


@app.command("demo-gateway")
def demo_gateway(
    offline: Annotated[bool, typer.Option("--offline/--no-offline")] = True,
    seed: Annotated[int, typer.Option("--seed", min=0)] = 42,
    workdir: Annotated[
        Path | None, typer.Option("--workdir", help="Keep demo.sqlite in this empty directory.")
    ] = None,
) -> None:
    """Offline enforcement demo (scripted agent, synthetic tools). Exit 1 if any outcome
    deviates from the declared expectations or the ledger fails verification."""
    from ananke.bench.demo_gateway import run_demo, run_demo_in_tempdir

    if not offline:
        _fail("OFFLINE_ONLY", "only --offline is supported", EXIT_UNAVAILABLE)
    if workdir is not None:
        if not workdir.is_dir() or any(workdir.iterdir()):
            _fail(
                "WORKDIR_INVALID", "--workdir must be an existing empty directory", EXIT_UNAVAILABLE
            )
        result = run_demo(workdir, seed)
    else:
        result = run_demo_in_tempdir(seed)
    _emit(result)
    if not (result["all_outcomes_as_expected"] and result["ledger_verification"]["ok"]):
        raise typer.Exit(code=EXIT_FAIL)


# ----------------------------------------------------------------------------- ledger


@ledger_app.command("init")
def ledger_init(
    db: DbOpt,
    operator: Annotated[
        list[str], typer.Option("--operator", help="Operator identity (repeatable).")
    ],
) -> None:
    """Create a new ledger with registered operator identities (trusted setup)."""
    try:
        init_ledger(db, operator)
    except (LedgerUnavailableError, ValueError, sqlite3.Error) as exc:
        _fail("INIT_FAILED", str(exc))
    _emit({"status": "ok", "db": db.name, "operators": sorted(operator)})


@ledger_app.command("apply")
def ledger_apply(
    db: DbOpt,
    operator: Annotated[str, typer.Option("--operator", help="Registered operator identity.")],
    changes: Annotated[Path, typer.Option("--changes", help="JSON array of policy changes.")],
    at: Annotated[
        int, typer.Option("--at", min=0, max=MAX_SAFE_INT, help="Logical tick of recording.")
    ],
) -> None:
    """Append policy changes atomically through the operator channel (all or nothing)."""
    parsed = _read_changes(changes)
    try:
        conn = open_ledger(db)
    except (LedgerUnavailableError, SchemaError) as exc:
        _fail("LEDGER_UNAVAILABLE", str(exc), EXIT_UNAVAILABLE)
    try:
        channel = OperatorChannel(conn, operator, lambda: at)
        events = channel.submit_many(parsed)
    except (UnknownOperatorError, InvalidIdentifierError) as exc:
        _fail("UNKNOWN_OPERATOR", str(exc))
    except PolicyTransitionError as exc:
        _fail(exc.code.value, exc.detail)
    except LedgerIntegrityError as exc:
        _fail("POLICY_INVALID", str(exc))
    except LedgerUnavailableError as exc:
        _fail("LEDGER_UNAVAILABLE", str(exc), EXIT_UNAVAILABLE)
    except (ValidationError, CanonicalizationError, ValueError) as exc:
        _fail("POLICY_INVALID", type(exc).__name__)
    finally:
        conn.close()
    _emit(
        {
            "status": "ok",
            "committed": [
                {
                    "sequence": e.sequence,
                    "epoch": e.epoch,
                    "kind": e.kind.value,
                    "rule_id": e.rule_id,
                    "target_rule_id": e.target_rule_id,
                    "event_hash": e.event_hash,
                }
                for e in events
            ],
        }
    )


@ledger_app.command("verify")
def ledger_verify(db: DbOpt) -> None:
    """Verify chains (policy, approvals, decisions) and audit all evidence by replay.

    Exit 0 if everything is consistent, 1 on any integrity or audit failure, 2 if unavailable.
    """
    try:
        report = verify_ledger(db)
        audit = audit_ledger(db) if report.ok else None
    except LedgerUnavailableError as exc:
        _fail("LEDGER_UNAVAILABLE", str(exc), EXIT_UNAVAILABLE)
    except sqlite3.DatabaseError as exc:
        _fail("LEDGER_CORRUPT", f"database file is not a valid ledger: {exc}")
    ok = report.ok and audit is not None and audit.ok
    _emit(
        {
            "status": "ok" if ok else "fail",
            **report.as_dict(),
            "ok": ok,
            "audit": audit.as_dict() if audit is not None else None,
        }
    )
    if not ok:
        raise typer.Exit(code=EXIT_FAIL)


@ledger_app.command("show")
def ledger_show(
    db: DbOpt,
    at: Annotated[
        int | None, typer.Option("--at", min=0, help="Also report effectiveness at this tick.")
    ] = None,
) -> None:
    """Show the verified current policy state (read-only)."""
    try:
        state = load_state(db)
    except (LedgerUnavailableError, SchemaError) as exc:
        _fail("LEDGER_UNAVAILABLE", str(exc), EXIT_UNAVAILABLE)
    except LedgerIntegrityError as exc:
        _fail("POLICY_INVALID", str(exc))
    except sqlite3.DatabaseError as exc:
        _fail("LEDGER_CORRUPT", f"database file is not a valid ledger: {exc}")
    _emit({"status": "ok", **_state_summary(state, at)})


# ----------------------------------------------------------------------------- policy


@policy_app.command("validate")
def policy_validate(
    file: Annotated[Path, typer.Argument(help="JSON array of policy changes.")],
    db: Annotated[
        Path | None, typer.Option("--db", help="Validate on top of this ledger's state.")
    ] = None,
) -> None:
    """Validate schema and transitions of a change file without writing anything."""
    parsed = _read_changes(file)
    start = EMPTY_STATE
    if db is not None:
        try:
            start = load_state(db)
        except (LedgerUnavailableError, SchemaError) as exc:
            _fail("LEDGER_UNAVAILABLE", str(exc), EXIT_UNAVAILABLE)
        except LedgerIntegrityError as exc:
            _fail("POLICY_INVALID", str(exc))
    try:
        final = validate_changes(parsed, start)
    except PolicyTransitionError as exc:
        _fail(exc.code.value, exc.detail)
    _emit(
        {
            "status": "ok",
            "changes": len(parsed),
            "resulting_epoch": final.epoch,
            "active_rules": [r.rule_id for r in final.active_rules()],
        }
    )


# ----------------------------------------------------------------------------- bench


@bench_app.command("generate")
def bench_generate(
    out: Annotated[Path, typer.Option("--out", help="Scenario root directory.")] = Path(
        "scenarios"
    ),
    variants: Annotated[int, typer.Option("--variants", min=1, max=50)] = 4,
) -> None:
    """Write dev + holdout scenario files and manifests. The holdout manifest is frozen once."""
    from ananke.bench.store import ScenarioStoreError, write_scenarios

    try:
        summary = write_scenarios(out, variants)
    except ScenarioStoreError as exc:
        _fail("HOLDOUT_FROZEN", str(exc))
    _emit({"status": "ok", **summary})


@bench_app.command("verify-scenarios")
def bench_verify_scenarios(
    root: Annotated[Path, typer.Option("--root")] = Path("scenarios"),
) -> None:
    """Verify every scenario file against the manifest and the frozen holdout manifest."""
    from ananke.bench.scenario import Split
    from ananke.bench.store import ScenarioStoreError, load_split

    try:
        counts = {s.value: len(load_split(root, s)) for s in Split}
    except (ScenarioStoreError, OSError, ValidationError) as exc:
        _fail("SCENARIOS_INVALID", str(exc))
    _emit({"status": "ok", "verified": counts})


@bench_app.command("run")
def bench_run(
    config: Annotated[Path, typer.Option("--config", help="Bench config JSON.")],
    offline: Annotated[bool, typer.Option("--offline/--no-offline")] = True,
    scenarios: Annotated[Path, typer.Option("--scenarios")] = Path("scenarios"),
    out: Annotated[Path, typer.Option("--out")] = Path("results/runs"),
) -> None:
    """Run a config offline. Exit 0 means the run *completed*, not that results are favourable."""
    from ananke.bench.config import BenchConfig
    from ananke.bench.run import HoldoutLockedError, execute
    from ananke.bench.store import ScenarioStoreError

    if not offline:
        _fail("OFFLINE_ONLY", "only --offline is supported", EXIT_UNAVAILABLE)
    try:
        cfg = BenchConfig.model_validate_json(config.read_bytes())
    except OSError as exc:
        _fail("CONFIG_UNREADABLE", exc.strerror or str(exc), EXIT_UNAVAILABLE)
    except ValidationError as exc:
        _fail("CONFIG_INVALID", f"{exc.error_count()} validation errors")
    try:
        result = execute(cfg, scenarios_root=scenarios, out_root=out, repo_root=REPO_ROOT)
    except HoldoutLockedError as exc:
        _fail("HOLDOUT_LOCKED", str(exc), EXIT_UNAVAILABLE)
    except ScenarioStoreError as exc:
        _fail("SCENARIOS_INVALID", str(exc))
    _emit(result)


@bench_app.command("report")
def bench_report(
    run_dir: Annotated[Path, typer.Option("--run-dir")],
    endpoint: Annotated[str, typer.Option("--endpoint")] = "unauthorized_proposal_rate",
) -> None:
    """Print one endpoint per condition (num/den/rate/CI) plus the paired comparisons."""
    try:
        metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail("RUN_UNREADABLE", str(exc), EXIT_UNAVAILABLE)
    rows = {k: v.get(endpoint) for k, v in metrics["conditions"].items()}
    if any(v is None for v in rows.values()):
        _fail("UNKNOWN_ENDPOINT", endpoint)
    _emit(
        {
            "status": "ok",
            "run_id": metrics["run_id"],
            "scope": metrics["scope"],
            "endpoint": endpoint,
            "conditions": rows,
            "comparisons": metrics["comparisons"],
        }
    )


@bench_app.command("power")
def bench_power(
    run_dir: Annotated[Path, typer.Option("--run-dir")],
    a: Annotated[str, typer.Option("--a")] = "M5_PROJECTION",
    b: Annotated[str, typer.Option("--b")] = "M4_FRESH_FULL_POLICY",
    gateway: Annotated[str, typer.Option("--gateway")] = "G1_ENFORCED",
    budget: Annotated[int, typer.Option("--budget")] = 1100,
    respects_quarantine: Annotated[bool, typer.Option("--quarantine/--no-quarantine")] = True,
    scenarios: Annotated[str, typer.Option("--scenarios", help="Comma-separated sizes.")] = (
        "36,72,108,144,216"
    ),
    sims: Annotated[int, typer.Option("--sims", min=100, max=100_000)] = 2000,
) -> None:
    """Cluster-resampling power of the exact McNemar test for A vs B, from a pilot run."""
    from ananke.bench.power import paired_clusters, simulate_power
    from ananke.bench.runner import CheckpointRecord

    try:
        lines = (run_dir / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
        records = [CheckpointRecord(**json.loads(x)) for x in lines if x.strip()]
        sizes = [int(x) for x in scenarios.split(",")]
    except (OSError, ValueError, TypeError) as exc:
        _fail("RUN_UNREADABLE", str(exc), EXIT_UNAVAILABLE)
    clusters = paired_clusters(
        records, a, b, gateway=gateway, budget=budget, respects_quarantine=respects_quarantine
    )
    _emit(
        {
            "status": "ok",
            "a": a,
            "b": b,
            "gateway": gateway,
            "budget": budget,
            "respects_quarantine": respects_quarantine,
            "pilot_scenarios": len(clusters),
            "pilot_a_only": sum(c[0] for c in clusters),
            "pilot_b_only": sum(c[1] for c in clusters),
            "power": simulate_power(clusters, sizes, sims=sims),
            "caveat": "Assumes the pilot's per-scenario discordance carries over; scripted-agent "
            "discordance is structural, so this sizes the benchmark design, not an LLM study.",
        }
    )
