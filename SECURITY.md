# Security policy

ANANKE is a research prototype, not a certified security product. It operates only on synthetic local mock tools.

**Reporting:** until a public release and contact channel exist, report issues privately to the repository owner. Do not open public issues for vulnerabilities.

**In scope:** bypasses of the reference monitor within the documented threat model (`docs/threat-model.md`), such as an unauthorized mock effect, approval replay, ledger mutation from untrusted content, or oracle/evaluator coupling.

**Out of scope:** the exclusions listed in `docs/threat-model.md` section 4.

Never include real credentials, personal data or real exploit payloads in issues, fixtures or traces.
