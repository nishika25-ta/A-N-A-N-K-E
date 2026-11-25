"""Benchmark harness (Phase 4): scenarios, independent oracle, runner, metrics, manifests.

Invariant: any module named ``oracle*`` must not import ananke.policy, ananke.runtime or
ananke.memory (enforced by tests/security/test_architecture.py).
"""
