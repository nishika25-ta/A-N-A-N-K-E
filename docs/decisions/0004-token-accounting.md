# ADR-0004: Token accounting and matched budgets

**Decision.** The context assembler accounts separately for the system prompt, tool schemas, policy projection, task memory, conversation and reserved output, against one total model-visible budget that is identical across strategies (M1 to M5). M0 (full history) is reported separately. Offline runs use a deterministic, clearly labelled estimator (to be specified in Phase 3). When a provider tokenizer or billed usage is available, it is recorded alongside the estimate. Compressor calls are counted in the total input and output tokens. Unused budget is never silently given to one strategy. If a strategy's mandatory content cannot fit, the run records `BUDGET_EXCEEDED` instead of truncating policy.

**Consequences.** Comparisons are fair by construction. Estimates may differ from billed tokens, and the difference is reported.
