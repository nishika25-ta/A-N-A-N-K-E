# Architecture decision records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-policy-precedence.md) | Policy precedence and matching | Accepted (v0) |
| [0002](0002-linearization.md) | Effect linearization in a single SQLite transaction | Accepted (v0) |
| [0003](0003-isolation.md) | In-process capability separation first, OS isolation later | Accepted (v0) |
| [0004](0004-token-accounting.md) | Token accounting and matched budgets | Accepted (v0) |
| [0005](0005-scope-exclusions.md) | MVP scope exclusions | Accepted (v0) |
| [0006](0006-provider-integration.md) | Scripted provider first; paid/remote gated | Accepted (v0) |
| [0007](0007-research-positioning.md) | Reposition as policy-transition × compaction benchmark | **Proposed: owner decision needed** |
| [0008](0008-identity-binding.md) | Identity bound by AgentPort, never by the proposal | Accepted (v0) |
| [0009](0009-idempotency-and-failure-semantics.md) | Idempotency binds committed effects; failures are recorded or raised | Accepted (v0) |
| [0010](0010-operator-signatures.md) | Operator signatures + external checkpoints | **Proposed: threat-model change, owner decision** |
| [0011](0011-belief-agent-model.md) | Deterministic belief agent for offline memory evaluation | Accepted (v0); not an LLM model |
| [0012](0012-generator-versioning.md) | Versioned generator; holdout pinned to v1 until regenerated | Accepted (v0) |

Status "Accepted (v0)" means accepted by the implementer for the prototype, subject to owner review.
