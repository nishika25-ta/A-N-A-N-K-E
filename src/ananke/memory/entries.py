"""Memory entries and conservative provenance labels (MASTERPLAN sections 4.7, 9).

Labels are computed by trusted code only, never by a model:

* a derived entry's ``source_ids`` are the union of its sources' identifiers;
* ``trust`` is the *minimum* of the sources' trust and ``sensitivity`` the *maximum*;
* any claimed source id that cannot be resolved makes the result UNTRUSTED and RESTRICTED.

This is coarse information-flow tracking. It says nothing about whether a summary is *accurate*.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, Field, StrictStr

from ananke.domain import MemoryEntryType, Sensitivity, Trust
from ananke.domain.models import Identifier, PositiveInt, Resource, StrictModel, Tick

MAX_CONTENT_CHARS = 4000


def validate_content(value: str) -> str:
    """Multi-line text: NFC, <= 4000 chars, only \\n and \\t among control/format characters."""
    if len(value) > MAX_CONTENT_CHARS:
        raise ValueError(f"content exceeds {MAX_CONTENT_CHARS} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("content must be NFC-normalized")
    for ch in value:
        if ch in "\n\t":
            continue
        if unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            raise ValueError(f"content: disallowed character U+{ord(ch):04X}")
    return value


Content = Annotated[StrictStr, AfterValidator(validate_content)]


class Origin(StrEnum):
    TASK = "TASK"  # assignment from the scenario controller / user
    OPERATOR_NOTICE = "OPERATOR_NOTICE"  # in-band policy notification from the operator
    TOOL_RESULT = "TOOL_RESULT"  # content returned by a mediated tool (untrusted content)
    AGENT = "AGENT"  # the agent's own notes/outputs
    SUMMARY = "SUMMARY"  # produced by a compactor


DEFAULT_TRUST: Mapping[Origin, Trust] = {
    Origin.TASK: Trust.OPERATOR,
    Origin.OPERATOR_NOTICE: Trust.OPERATOR,
    Origin.TOOL_RESULT: Trust.TOOL_OUTPUT,
    Origin.AGENT: Trust.UNTRUSTED,
    Origin.SUMMARY: Trust.UNTRUSTED,  # always recomputed from sources; this is the fallback
}


class MemoryEntry(StrictModel):
    entry_id: Identifier
    kind: MemoryEntryType
    origin: Origin
    content: Content
    source_ids: tuple[Identifier, ...] = ()
    trust: Trust
    sensitivity: Sensitivity
    resource_refs: tuple[Resource, ...] = ()
    created_at: Tick
    revision: PositiveInt = 1
    cycle: int = Field(default=0, ge=0)  # compaction cycle that produced it (0 = raw)


@dataclass(frozen=True, slots=True)
class DerivedLabels:
    source_ids: tuple[str, ...]
    trust: Trust
    sensitivity: Sensitivity
    resource_refs: tuple[str, ...]
    unresolved: tuple[str, ...]


def derive_labels(claimed: Iterable[str], known: Mapping[str, MemoryEntry]) -> DerivedLabels:
    """Conservative label propagation for a derived entry claiming ``claimed`` as its sources."""
    ids = sorted(set(claimed))
    resolved = [known[i] for i in ids if i in known]
    unresolved = tuple(i for i in ids if i not in known)
    if not resolved or unresolved:
        trust, sens = Trust.UNTRUSTED, Sensitivity.RESTRICTED
    else:
        trust = min((e.trust for e in resolved), key=lambda t: t.rank)
        sens = max((e.sensitivity for e in resolved), key=lambda s: s.rank)
    refs = sorted({r for e in resolved for r in e.resource_refs})
    # Only resolvable identifiers are kept as sources (unknown ids are discarded, not trusted).
    return DerivedLabels(tuple(e.entry_id for e in resolved), trust, sens, tuple(refs), unresolved)


def raw_entry(
    entry_id: str,
    origin: Origin,
    content: str,
    created_at: int,
    *,
    kind: MemoryEntryType = MemoryEntryType.OBSERVATION,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    resource_refs: Sequence[str] = (),
) -> MemoryEntry:
    """A first-hand entry whose trust is fixed by its origin channel (not by its content)."""
    return MemoryEntry(
        entry_id=entry_id,
        kind=kind,
        origin=origin,
        content=content,
        source_ids=(),
        trust=DEFAULT_TRUST[origin],
        sensitivity=sensitivity,
        resource_refs=tuple(sorted(set(resource_refs))),
        created_at=created_at,
    )
