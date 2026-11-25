# Sample: dev-split engineering pilot, generator v2 (run-d11292703954)

This sample contains the metrics, the manifest and two power estimates from
`uv run ananke bench run --config research/experiments/pilot-dev.json --offline`.
It covers 36 dev scenarios (generator v2, ADR-0012) × 108 conditions = 7,776 checkpoint records.
The budgets are 450, 1,100 and 2,600 estimated tokens. The full `checkpoints.jsonl` is regenerable and gitignored.

**This is not** evidence about LLM behaviour, a holdout result, or a preregistered test. The agent is the deterministic
belief agent, and the summarizer is a declared synthetic stress model (ADR-0011). The holdout stays locked and pinned to v1.

The v1 pilot (`results/sample-dev-pilot/`) is kept as history.
