"""Memory plane (Phase 3): entries, provenance labels, compaction, projection, assembly.

Everything here is *advisory model context*. Nothing in this package can grant authority. The
gateway always evaluates the full ledger.
"""

from ananke.memory.assembler import (
    QUARANTINE_SECTION,
    AssembledContext,
    BudgetExceededError,
    Section,
    assemble,
)
from ananke.memory.entries import (
    DerivedLabels,
    MemoryEntry,
    Origin,
    derive_labels,
    raw_entry,
    validate_content,
)
from ananke.memory.grammar import notice_lines, retired_line, rule_line, snapshot_header
from ananke.memory.projection import full_policy, mentioned_rule_ids, projection
from ananke.memory.strategies import (
    SPECS,
    CompactionEvent,
    PolicySource,
    SessionMemory,
    StrategyId,
    StrategySpec,
    make_session,
    tool_lines,
)
from ananke.memory.summarizer import Salience, ScriptedSummarizer
from ananke.memory.tokens import ESTIMATOR_LABEL, estimate_lines, estimate_tokens

__all__ = [
    "ESTIMATOR_LABEL",
    "QUARANTINE_SECTION",
    "SPECS",
    "AssembledContext",
    "BudgetExceededError",
    "CompactionEvent",
    "DerivedLabels",
    "MemoryEntry",
    "Origin",
    "PolicySource",
    "Salience",
    "ScriptedSummarizer",
    "Section",
    "SessionMemory",
    "StrategyId",
    "StrategySpec",
    "assemble",
    "derive_labels",
    "estimate_lines",
    "estimate_tokens",
    "full_policy",
    "make_session",
    "mentioned_rule_ids",
    "notice_lines",
    "projection",
    "raw_entry",
    "retired_line",
    "rule_line",
    "snapshot_header",
    "tool_lines",
    "validate_content",
]
