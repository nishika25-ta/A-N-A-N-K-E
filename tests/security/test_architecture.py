"""Static architecture invariants enforced over the source tree (AST, no imports executed)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "ananke"

# Inward dependency rule (MASTERPLAN section 7): domain -> ledger/policy/memory -> runtime -> outer.
ALLOWED_INTERNAL = {
    "domain": {"domain"},
    "ledger": {"domain", "ledger"},
    "policy": {"domain", "ledger", "policy"},
    "memory": {"domain", "ledger", "policy", "memory"},
    "lab": {"domain", "lab"},
    "runtime": {"domain", "ledger", "policy", "memory", "lab", "runtime", "audit"},
    "audit": {"domain", "audit", "ledger", "policy", "lab"},
    "providers": {"domain", "providers", "runtime"},  # runtime: AgentPort only (checked below)
}
NETWORK_MODULES = {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib", "smtplib"}
NETWORK_ALLOWED_PACKAGES = {"providers", "api"}  # future, opt-in adapters only
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
# Agent-side code (providers, future memory/agent loops) may reach the runtime only via AgentPort.
AGENT_SIDE = {"providers"}
AGENT_SIDE_FORBIDDEN = ("ananke.ledger", "ananke.runtime.gateway", "ananke.lab", "ananke.memory")


def _modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _package_of(path: Path) -> str | None:
    rel = path.relative_to(SRC).parts
    return rel[0] if len(rel) > 1 else None


def test_source_tree_found() -> None:
    assert (SRC / "domain" / "canonical.py").exists()


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_inward_dependencies(path: Path) -> None:
    pkg = _package_of(path)
    if pkg not in ALLOWED_INTERNAL:
        return
    for name in _imports(path):
        parts = name.split(".")
        if parts[0] == "ananke" and len(parts) > 1:
            assert parts[1] in ALLOWED_INTERNAL[pkg], f"{path}: {pkg} must not import {name}"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_oracle_does_not_import_evaluator(path: Path) -> None:
    if not path.stem.startswith("oracle"):
        return
    for name in _imports(path):
        assert not name.startswith(("ananke.policy", "ananke.runtime", "ananke.memory")), (
            f"{path}: benchmark oracle must be independent of the evaluator under test ({name})"
        )


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_network_imports_in_core(path: Path) -> None:
    if _package_of(path) in NETWORK_ALLOWED_PACKAGES:
        return
    for name in _imports(path):
        assert name.split(".")[0] not in NETWORK_MODULES, f"{path}: network import {name}"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_dynamic_code_execution(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"{path}: {node.func.id}() forbidden"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(SRC)))
def test_agent_side_code_cannot_reach_authority_or_lab(path: Path) -> None:
    if _package_of(path) not in AGENT_SIDE:
        return
    for name in _imports(path):
        assert not name.startswith(AGENT_SIDE_FORBIDDEN), f"{path}: agent-side import {name}"
        if name.startswith("ananke.runtime"):
            assert name == "ananke.runtime.port", f"{path}: agent code may only use AgentPort"


def test_lab_tools_have_no_side_channel_imports() -> None:
    forbidden = {"os", "subprocess", "shutil", "pathlib", "time", "datetime", "random"}
    for path in (SRC / "lab").rglob("*.py"):
        for name in _imports(path):
            assert name.split(".")[0] not in forbidden, f"{path}: {name}"


def _module_path(name: str) -> Path | None:
    parts = name.split(".")
    if parts[0] != "ananke":
        return None
    base = SRC.joinpath(*parts[1:])
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.exists():
            return cand
    return None


def test_oracle_is_transitively_independent_of_the_evaluator() -> None:
    """The oracle may not reach policy/runtime/memory/ledger even through intermediate modules."""
    forbidden = ("ananke.policy", "ananke.runtime", "ananke.memory", "ananke.ledger")
    for oracle in (SRC / "bench").glob("oracle*.py"):
        seen: set[Path] = set()
        stack = [oracle]
        while stack:
            path = stack.pop()
            if path in seen:
                continue
            seen.add(path)
            for name in _imports(path):
                assert not name.startswith(forbidden), f"{oracle.name} reaches {name} via {path}"
                nxt = _module_path(name)
                if nxt is not None:
                    stack.append(nxt)
        assert len(seen) > 1  # non-vacuous: it does import the scenario model


def test_rule_fires_on_violation(tmp_path: Path) -> None:
    """Guard against a vacuous checker: the import scanner must see a planted violation."""
    planted = tmp_path / "oracle_bad.py"
    planted.write_text("from ananke.policy import evaluator\nimport socket\n", encoding="utf-8")
    found = _imports(planted)
    assert "ananke.policy" in found
    assert "socket" in found
