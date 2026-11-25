"""Minimal offline smoke test: package imports and the CLI self-check passes end to end."""

from __future__ import annotations

import importlib
import json
import socket

import pytest
from typer.testing import CliRunner

from ananke.cli import app

SUBPACKAGES = [
    "domain",
    "ledger",
    "policy",
    "memory",
    "runtime",
    "providers",
    "lab",
    "bench",
    "audit",
    "api",
]

pytestmark = pytest.mark.smoke


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackages_import(name: str) -> None:
    importlib.import_module(f"ananke.{name}")


def test_selfcheck_offline_passes() -> None:
    result = CliRunner().invoke(app, ["selfcheck", "--offline"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["status"] == "pass"
    assert all(report["checks"].values())
    assert report["canonicalization"] == "ananke-cjson-1"


def test_selfcheck_refuses_online_mode() -> None:
    result = CliRunner().invoke(app, ["selfcheck", "--no-offline"])
    assert result.exit_code == 2


def test_version() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == "0.0.1"


def test_network_guard_active() -> None:
    with pytest.raises(RuntimeError, match="network access is forbidden"):
        socket.create_connection(("127.0.0.1", 9))
