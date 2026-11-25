# ADR-0011: A deterministic belief agent for offline memory-strategy evaluation

**Status.** Accepted (v0) for offline engineering evaluation. **Not a model of LLM behaviour.**

**Context.** Phase 3 must compare memory strategies (M0 to M5) offline, with no paid model calls. A scripted
agent that ignores its context would make every strategy look identical. We need an agent whose proposals
are a *function of the model-visible context only*. Then differences between strategies come purely from
what information survives compaction, which is the information-availability component of RQ1.

**Decision.**
1. **Policy statement grammar** (`docs/policy-spec.md` section 9). Policy facts appear in context as single lines:
   `POLICY GRANT <rule> <tool>.<op> <resource> from=<t> until=<t|none> approval=<yes|no> epoch=<e>`,
   `POLICY DENY ...`, `POLICY REVOKE <rule> epoch=<e>`, `POLICY SUPERSEDE <old> epoch=<e>`, and
   `POLICY SNAPSHOT epoch=<e> principal=<p> complete=yes` (the start of an authoritative complete view).
2. **The belief agent** (`providers/belief.py`) parses those lines from every non-quarantined section. It resolves
   them per rule with *latest epoch wins*. A complete snapshot retires every known rule absent from it at or below its
   epoch. At a checkpoint it proposes the task's action if, and only if, it believes the action is permitted at
   `now`. Otherwise it abstains. It never reads the ledger.
3. **Quarantine assumption, made explicit.** The agent ignores POLICY lines inside a section marked
   `UNTRUSTED DATA`. This flatters provenance-aware strategies, so a variant agent `respects_quarantine=False`
   must be reported alongside it (sensitivity analysis).
4. **The scripted summarizer** is a declared synthetic stress model with named salience profiles (e.g.
   `keep-capabilities`: retain GRANT lines, drop REVOKE notices first under pressure). It is not an empirical
   model of any LLM summarizer.
5. Agent-side code may not import `ananke.memory`, so the parser is independent of the renderer and a grammar
   bug cannot hide itself (enforced by a static test).

**Consequences.** Offline results measure *what the context makes knowable*, under stated compressor and
agent assumptions. Claims about LLM behaviour need real-model runs (opt-in, owner-approved, ADR-0006).
