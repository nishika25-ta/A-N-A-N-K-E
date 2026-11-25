"""Scripted, deterministic, *lossy* summarizer: a declared stress model (ADR-0011).

It is not a model of any real LLM summarizer. Each profile encodes one documented failure mode, so
memory strategies can be compared under explicit compression behaviour:

* ``keep-capabilities``: keeps task and GRANT/DENY lines first and drops REVOKE/SUPERSEDE notices
  first. This models "the summary remembers what I may do, forgets what was taken away".
* ``recency``: keeps the newest lines (constraint eviction by age).
* ``fifo``: keeps the oldest lines (anchoring on early context).

Lines are de-duplicated and kept in chronological order. ``partition_by_trust=True`` (used by M5)
summarizes each trust class separately, so operator notices never merge with tool text. Labels are
always recomputed by :func:`derive_labels`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from ananke.domain import MemoryEntryType
from ananke.memory.entries import MemoryEntry, Origin, derive_labels


class Salience(StrEnum):
    KEEP_CAPABILITIES = "keep-capabilities"
    RECENCY = "recency"
    FIFO = "fifo"


def _priority(line: str, profile: Salience) -> int:
    if profile is not Salience.KEEP_CAPABILITIES:
        return 0
    if line.startswith(("TASK ", "POLICY GRANT", "POLICY DENY", "POLICY SNAPSHOT")):
        return 2
    if line.startswith(("POLICY REVOKE", "POLICY SUPERSEDE")):
        return 0
    return 1


@dataclass(frozen=True, slots=True)
class ScriptedSummarizer:
    profile: Salience = Salience.KEEP_CAPABILITIES
    max_lines: int = 6
    partition_by_trust: bool = False

    def summarize(
        self,
        entries: Sequence[MemoryEntry],
        *,
        id_prefix: str,
        now: int,
        cycle: int,
        known: Mapping[str, MemoryEntry],
    ) -> list[MemoryEntry]:
        if not entries:
            return []
        groups: list[list[MemoryEntry]]
        if self.partition_by_trust:
            by_trust: dict[str, list[MemoryEntry]] = {}
            for e in entries:
                by_trust.setdefault(e.trust.value, []).append(e)
            groups = [by_trust[k] for k in sorted(by_trust)]
        else:
            groups = [list(entries)]
        out = []
        for i, group in enumerate(groups):
            out.append(self._one(group, f"{id_prefix}-{i}", now, cycle, known))
        return out

    def _one(
        self,
        group: Sequence[MemoryEntry],
        entry_id: str,
        now: int,
        cycle: int,
        known: Mapping[str, MemoryEntry],
    ) -> MemoryEntry:
        candidates: list[tuple[int, int, int, str]] = []  # (priority, time, order, line)
        seen: set[str] = set()
        order = 0
        for e in sorted(group, key=lambda x: (x.created_at, x.entry_id)):
            for line in e.content.splitlines():
                line = line.strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                candidates.append((_priority(line, self.profile), e.created_at, order, line))
                order += 1
        if self.profile is Salience.FIFO:
            ranked = sorted(candidates, key=lambda c: (c[2],))
        else:  # KEEP_CAPABILITIES / RECENCY: higher priority, then newer first
            ranked = sorted(candidates, key=lambda c: (-c[0], -c[1], -c[2]))
        kept = sorted(ranked[: self.max_lines], key=lambda c: c[2])
        labels = derive_labels([e.entry_id for e in group], known)
        return MemoryEntry(
            entry_id=entry_id,
            kind=MemoryEntryType.SUMMARY,
            origin=Origin.SUMMARY,
            content="\n".join(c[3] for c in kept),
            source_ids=labels.source_ids,
            trust=labels.trust,
            sensitivity=labels.sensitivity,
            resource_refs=labels.resource_refs,
            created_at=now,
            cycle=cycle,
        )
