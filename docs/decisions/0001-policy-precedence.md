# ADR-0001: Policy precedence and matching

**Context.** Grants, denies, revocations, expiry and supersession interact. Ambiguous semantics make both the gateway and the oracle unreliable.

**Decision.**
- Default deny. Fail closed on unknown tools, fields, schema versions or principals, on a missing ledger, and on a broken chain.
- An applicable DENY wins over any GRANT.
- Resource matching is exact. There is no prefix or wildcard matching in v0.
- Validity is `valid_from <= now < valid_until`. A null `valid_until` means no expiry. Expiry is evaluated at decision time and does not advance the epoch.
- REVOKE and SUPERSEDE are explicit ledger events. A regrant uses a new `rule_id`. IDs are never reused.
- If **any** applicable grant requires approval, approval is required. This is the conservative union.
- Any accepted policy event invalidates all outstanding approvals.
- Diagnostic reasons (`GRANT_REVOKED` > `GRANT_EXPIRED` > `NO_MATCHING_GRANT`) are derived only from ledger facts.

**Consequences.** The rules are simple and easy for the oracle to reproduce. Approval invalidation adds friction, which is measured as a secondary endpoint. Prefix scopes would need a new ADR and property tests.
