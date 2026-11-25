# ADR-0003: In-process capability separation first, OS isolation later

**Context.** The masterplan asks for gateway isolation. Process and container isolation adds complexity before core correctness exists.

**Decision.** In Phases 1 to 6, the agent loop gets only a narrow `propose(action)` interface. The operator channel, ledger writer, clock and database connection are separate objects, never passed to agent or provider code. Static tests forbid imports from provider or agent modules into ledger or runtime internals. In Phase 7 or 8, the gateway runs as a separate process with a non-root user, a read-only filesystem where possible, and default-deny egress. That isolation is tested separately.

**Consequences.** Until then, the separation protects against *model-mediated* attacks in the lab, not against malicious Python code in the same process. Documentation must say so, and no claim of container isolation is made before it is tested.
