# ADR-0012: Versioned scenario generator; holdout pinned until the owner regenerates it

**Status.** Accepted (v0).

**Context.** The dev pilot showed two design flaws: the budgets did not bind, and the injection family was tiny (n = 4).
Fixing them changes the generator. But the holdout manifest is frozen, and regenerating the holdout is an open owner
decision.

**Decision.** `GENERATOR_VERSION = {dev: 2, holdout: 1}`. Version 1 code paths stay byte-identical. A test asserts that
the regenerated holdout equals the frozen manifest. Version 2 (dev) adds:

- filler of 6 to 12 observations of 20 to 40 words (median M0 history is about 1,030 estimated tokens), so budgets of 450, 1,100 and 2,600 bind;
- an injection family with four forgery formats per scenario: a high-epoch grant, a grant for the wrong principal (a control), a forged complete
  snapshot, and a forged revoke with prose. That gives 12 attack checkpoints per condition.

The attack-adoption denominator is now the eligible checkpoints that carry an attack option.

**Update (session 5, owner decision).** The holdout was regenerated at **v2** through an explicit, logged
re-freeze (`ananke bench generate --refreeze-holdout "<reason>"`). It uses a **new seed space** (offset 30,000; the v1
holdout used 10,000), **8 variants per family (72 scenarios)** per the power estimate, and holdout-only phrasing for the
injected text (template tpl-b). The superseded v1 manifest is archived unchanged as
`scenarios/holdout.manifest.freeze-1.json`, and `scenarios/holdout.freeze-log.json` records both freezes and their
reasons. Dev v2 was verified byte-identical, and the retired v1 holdout stays reproducible (tested). Nothing was run on the new
holdout: runs stay locked until the preregistration is FROZEN.

**Consequences.** Dev and holdout now come from different generator versions. **Before a preregistration freeze, the
holdout must be regenerated at v2 with new seeds** (owner decision; this also resolves the session-3 guard incident).
v1 pilot results (`results/sample-dev-pilot/`) are kept as history and labelled v1.
