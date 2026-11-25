"""Deterministic token *estimate* for offline budgeting (ADR-0004).

``ceil(utf8_bytes / 4)`` per line plus 1 per line break. It is clearly labelled as an estimate and
is not a provider tokenizer. Real-model runs must record provider-reported usage alongside it.
"""

from __future__ import annotations

from collections.abc import Iterable

ESTIMATOR_LABEL = "bytes/4 heuristic (offline estimate, not a provider tokenizer)"


def estimate_tokens(line: str) -> int:
    return -(-len(line.encode("utf-8")) // 4) + 1


def estimate_lines(lines: Iterable[str]) -> int:
    return sum(estimate_tokens(line) for line in lines)
