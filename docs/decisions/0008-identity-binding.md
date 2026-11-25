# ADR-0008: Identity is bound by the AgentPort, never by the proposal

**Context.** If a proposal could name its own `principal_id` or `session_id`, an injected instruction
could impersonate a more privileged principal, and no policy evaluation would catch it.

**Decision.** Agent code receives only an `AgentPort`, constructed by trusted code with a fixed principal
and session. `Proposal` has no identity fields, and the strict schema rejects any unknown key, so a
proposal carrying `principal_id` is denied with `INVALID_ARGUMENTS`. The port alone constructs the
`ActionRequest` (with a fresh `request_id`). Static tests require that `providers/` imports nothing from the
runtime except `ananke.runtime.port`, and nothing from `ledger` or `lab`.

**Consequences.** Multi-principal experiments need one port per principal. In-process, this guards against
model-mediated misuse, not hostile code in the same interpreter (ADR-0003).
