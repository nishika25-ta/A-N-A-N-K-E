# Related work and novelty assessment (Phase 0)

**Compiled:** 2026-11-25 · **Status:** preliminary. **No primary source was read in full this session.**
Every entry needs re-verification against the primary text before preregistration freeze (Phase 5).

## 1. Access record (what was and was not reachable)

| Source / channel | Result |
|---|---|
| `export.arxiv.org` from the container (curl) | **Blocked**: egress proxy HTTP 403 (host not allowed for this session) |
| `arxiv.org`, `nic.csc.fi` via fetch tool | **Failed**: DNS `ENOTFOUND` for both hosts |
| Web search tool | **Worked**: returns titles, URLs and machine-written summaries of abstracts and secondary pages |
| Google Scholar, Semantic Scholar, ACM DL, IEEE Xplore, GitHub search | **Not attempted** this session (time-boxed); to do |
| Claude Code hooks docs (code.claude.com) | Not fetched. Installed CLI version recorded: `2.1.332 (Claude Code)`. Adapter is Phase 8. |

**Evidence levels used below:**
- **S**: secondary only: a search-engine summary of the abstract or of mirror and blog pages. Numbers quoted at S level
  are *as reported by summaries* and may be wrong.
- **M**: from the implementer's prior knowledge (training data, cutoff mid-2026), not re-retrieved this session.
- **N**: searched for and not found.
- **P**: primary text read. **No entries are at P yet.**

### Exact search queries executed (2026-11-25)

1. `"Compaction Cliff" long-running AI agent memory security rules arXiv`
2. `MemSecBench memory poisoning lifecycle agents benchmark arXiv 2607.27080`
3. `origin-bound authority agent memory preprint arXiv 2606.24322`
4. `CompactionBench Microsoft Research long-horizon agent context compaction benchmark`
5. `arXiv 2611.25673 CompAct-Bench compaction benchmark agents`
6. `arXiv 2610.31710 Compact-Bench`
7. `LLM agent policy revocation stale permission context compaction enforcement reference monitor 2026` (extended)
8. `draft-durga-agent-ephemeral-lineage compaction receipts IETF`
9. `"Temporary Authority, Permanent Effects" commit-time authorization LLM agents revocation`
10. `"Do Agents Still Follow the Rules" rule compliance compaction benchmark 2611.03223`
11. `"Governance Decay" context compaction safety constraints long-horizon agents 2606.22528`
12. `"Ghost in the Context" policy-carriage integrity LLM agents`
13. `Progent programmable privilege control LLM agents dynamic policy update arXiv`
14. `ARCBench agent rule compliance context compaction GitHub code release pi agent harness`
15. `benchmark LLM agent permission revocation mid-session policy change stale authorization evaluation 2026` (extended)
16. `ACON optimizing context compression long-horizon LLM agents arXiv 2510.00615`
17. `AgentDojo dynamic environment prompt injection benchmark arXiv 2406.13352 NeurIPS`
18. `RevBench mid-task permission revocation AI agents context memory compaction timing Zenodo` (extended)
19. `agent-revocation-lag-benchmark RevocationLag synthetic benchmark dynamic agent permissions`
20. `"Revocation Is Not Complete at Receipt" executable outcome contract agent-tool gateways`
21. `revoked permission persists in agent summary after compaction stale grant benchmark recall versus enforcement`

## 2. Literature matrix

Columns: **Dyn** = models dynamic grants, revocations or expiry within a session. **RC** = repeated context compaction.
**TB** = enforcement at the tool/effect boundary. "?" = unknown until the primary text is read.

| # | Work (ID, date) | Ev. | Problem | Dyn | RC | TB | Evaluation (as reported) | Code | Overlap with ANANKE / possible difference |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **The Compaction Cliff in Long-Running AI Agent Memory**, Zerhoudi, Mitrović, Granitzer, arXiv 2608.22752, Aug 2026 (reportedly CIKM) | S | Safety-rule survival across repeated compaction | ? | **Yes** (1 to 5 rounds) | ? | Reported: Claude Code `/compact` on Sonnet 4.6 keeps 53% of rules after 1 round and 10% after 5; 20 production configs; AgentArtifactCorpus (396,934 configs) | Reportedly released (corpus, classifier, ref. impl.) | **Direct overlap** on retention under repeated compaction. Gap to check: policy *transitions*, effect-level outcomes |
| 2 | **Governance Decay: How Context Compaction Silently Erases Safety Constraints in Long-Horizon LLM Agents**, arXiv 2606.22528, Jun 2026 | S | Compaction erases constraints; in-context adversary can trigger it | ? | Yes | ? (sandbox) | Reported: 1,323 episodes, 7 models; 0% to ~30% violations after compaction (up to 59%); no decay when policy sits in system message. LLM-judge scoring | ? | **Direct overlap.** Proposes **Constraint Pinning**, which is effectively ANANKE's M4 "fresh full-policy" baseline. Treat it as prior art for M4, not as a contribution |
| 3 | **Do Agents Still Follow the Rules? Benchmarking Rule Compliance under Agent Context Compaction (ARCBench)**, reportedly arXiv Nov 2026 (ID 2611.03223 unconfirmed) | S | Rule compliance measured from executed actions after compaction | ? | Yes | Measures actions | Reported: violations 9.6% to 37.8% across 17 scenarios; 21.1% of runs violate *with the rule still in the summary*; policy-tool delivery 22.2% vs in-conversation 56.3% | ? | **Strongest benchmark competitor.** It already measures action-level compliance. Its finding that recall is not compliance supports ANANKE's split of recall and proposal metrics |
| 4 | **Ghost in the Context: Measuring Policy-Carriage Failures in Decision-Time Assembly**, Santos-Grueiro, arXiv 2605.12535 v2, May 2026 | S | Policy lost or corrupted while assembling bounded context (truncate, summarize, reorder) | ? | ? | Partial (SafeContext control layer) | ? | ? | Overlaps ANANKE's context assembler and projection idea |
| 5 | **Temporary Authority, Permanent Effects: Commit-Time Authorization for LLM Agents**, Santos-Grueiro, arXiv 2607.10487, Jul 2026 | S | Stale approvals or snapshots authorizing durable effects; requires current justification at commit | **Yes** (expiry, mutation, supersession) | ? (apparently not the focus) | **Yes** (CommitGuard, fail-closed) | Reported: 54 clean controls authorized; 54-run authority-preserving check with 0 unauthorized commits; 5-model study on timely notice | ? | **Direct overlap with ANANKE Runtime/G1** (exact-effect binding, commit-time check). ANANKE's gateway is a reimplementation of a known design, not a contribution |
| 6 | **Authorization Revocation for Long-Running AI Agents: Root-Scoped Quiescence under Delegation and Asynchronous Execution**, arXiv 2609.21284, Sep 2026 | S (title + one summary line) | Revocation across delegation and async execution | **Yes** | ? | Yes | ? | ? | Overlaps revocation semantics. Goes beyond ANANKE scope (delegation) |
| 7 | **Assurance-Conditioned Continuous Authorization for Autonomous AI Agents**, arXiv 2611.05632, Nov 2026 | S (title only) | Continuous authorization | likely | ? | ? | ? | ? | To read |
| 8 | **CONTINUITY: Security-Context Contracts for Composable LLM Agent Controls**, arXiv 2609.05269 v1, Sep 2026 | S | "Security-context discontinuity" when controls compose; recheck at finality | **Yes** (policy change, revocation, caller substitution) | ? | Yes | ? | ? | Overlaps ANANKE's invariant 4 (revalidate at commit) |
| 9 | **Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees (TMA-NM)**, arXiv 2606.24322, Jun 2026 | S | Authority laundering through summarization, trusted-tool echo or corroboration; origin binding at write time | ? | Summarization as a laundering channel | ? | Reported: MEM-INV-Bench, 12 domains, 5 tool types, 8 models; machine-checked theorems | ? | **Supersedes ANANKE's provenance labels** in rigor. ANANKE's coarse labels are a weaker approach to the same property; do not claim novelty |
| 10 | **Agent Memory Is a Surface for Endogenous Authorization Laundering**, arXiv 2609.01836, Sep 2026 (NeurIPS 2026 listing) | S | Memory errors create false authority; forgotten revocation keeps dead authority | **Yes** (revocation forgetting) | Summarization | ? | ? | ? | **Close overlap** with ANANKE's "stale grant in summary" failure |
| 11 | **MemSecBench: Tracking Agent Memory Poisoning from Persistence to Consequence and Repair**, Chen et al., arXiv 2607.27080, Jul 2026 | S | Lifecycle memory poisoning | no (poisoning, not policy churn) | ? | Verified external consequence | Reported: 310 cases, 48 contexts; 84.2% poisoning, 50.3% end-to-end ASR | ? | Shares metric philosophy (persistence, then adoption, then consequence) |
| 12 | **Benchmarking Long-Horizon Agent Context Compaction with CompactionBench**, Liu, Choukse et al., Microsoft Research | S | Repeated compaction in persistent coding sessions; APEC async compaction | no | **Yes** | n/a | Reported: motivated by 13.5M Copilot sessions | ? | Utility-side compaction benchmark, no security transitions |
| 13 | **CompactBench** (compactbench.github.io, PyPI `compactbench`) | S | Open benchmark for conversation compaction; multi-cycle drift | no | **Yes** | n/a | Hidden ranked test set | Yes (open source) | Possible harness reuse for drift testing; check license |
| 14 | **What to Keep, What to Forget: A Rate–Distortion View of Memory Compaction (COMPACT-Bench)**, arXiv 2607.08032 | S | Rate–distortion view of compaction | no | ? | n/a | Extends SCBench/KVPress | ? | Theory and budget framing |
| 15 | arXiv **2611.25673** ("CompAct-Bench") and **2610.31710** ("Compact-Bench") as cited in MASTERPLAN | **N** | Search did not confirm what these IDs are | | | | | | **Unverified citations in the masterplan.** Do not cite until confirmed |
| 16 | **ACON: Optimizing Context Compression for Long-horizon LLM Agents**, Kang et al. (KAIST, Microsoft, Cambridge), arXiv 2510.00615, Oct 2025; ICLR 2026 / PMLR v306 | S | Learned compression guidelines for agent context | no | Yes | n/a | Reported: AppWorld, OfficeBench, multi-objective QA; 26 to 54% peak-token reduction | Yes (github.com/microsoft/acon) | Strong utility-side compressor. Candidate M2 summarizer comparator (license check needed) |
| 17 | **AgentDojo** (Debenedetti et al., NeurIPS 2024 D&B; arXiv 2406.13352 v3, Nov 2024) | S | Prompt-injection benchmark for tool agents | no | no | Utility and security per task | 97 tasks, 629 security cases; deterministic state-based utility checks | Yes (ethz-spylab/agentdojo) | Scenario and oracle design reference. ANANKE adds policy timelines and compaction |
| 18 | **CaMeL: Defeating Prompt Injections by Design** (Debenedetti et al., arXiv 2503.18813) | M | Capability and data-flow separation of control vs data | no | no | **Yes** (interpreter-level policies) | On AgentDojo | Yes | Same principle as the three-plane split: the model never grants authority |
| 19 | **Progent: Programmable Privilege Control for LLM Agents**, Shi, He et al., arXiv 2504.11703 v2, Aug 2025 | S | Tool-level privilege DSL (allow/forbid, fallbacks); policy updates as agent state changes; optional LLM-generated policies | partial (policy *updates*, LLM-generated) | no | **Yes** | AgentDojo, ASB | ? | Close to the ANANKE gateway; check its dynamic-update semantics |
| 20 | **FIDES: Securing AI Agents with Information-Flow Control** (Costa et al., arXiv 2505.23643) | M | IFC labels for agent planners | no | no | Yes | ? | ? | ANANKE's coarse label propagation is a simplified version |
| 21 | **Design Patterns for Securing LLM Agents against Prompt Injections** (Beurer-Kellner et al., arXiv 2506.08837) | M | Architectural patterns | no | no | Yes | Case studies | n/a | Design guidance |
| 22 | **MemGPT** (Packer et al., arXiv 2310.08560) | M | Hierarchical memory and paging for LLMs | no | Yes | n/a | | Yes | Memory-management ancestor |
| 23 | IETF drafts: agent action receipts (draft-sahu-agent-action-receipts-00), delegation receipts (draft-nelson-agent-delegation-receipts-15), succession receipts (draft-sabey-succession-receipts), signed decision receipts (draft-farley-acta-signed-receipts-02) | S | Signed, hash-chained agent action and authority records | some (delegation, succession) | no | n/a | n/a | n/a | Receipts and hash chains are **not novel**; ANANKE's chain is plain tamper-evidence |
| 24 | `draft-durga-agent-ephemeral-lineage-01` (cited in MASTERPLAN) | **N** | Not found by search; host unreachable | | | | | | **Unverified**; do not cite until retrieved from the IETF Datatracker |
| 25 | OWASP AI Agent Security and MCP Security cheat sheets | M | Guidance | | | | | | Design guidance only |
| 26 | Context-to-Execution Integrity for LLM Agents (arXiv 2607.06000); Policy-Invisible Violations in LLM-Based Agents (arXiv 2604.12177); MemoryDojo (2611.09721); MemForm (2610.14431) | S (titles only) | Adjacent | ? | ? | ? | | | To screen |
| 27 | **RevBench** / "Revoking Access Does Not Revoke Knowledge", Zenodo record 23854360, v1.0, 1 Nov 2026 | S | After a mid-task revocation the platform blocks the next read, but the agent keeps the data it already retrieved (in context, drafts and memory) | **Yes** (timing: before retrieval vs after delivery) | not mentioned | Yes (9 enforcement designs: access control, IFC, unlearning) | Reported: 6 frontier models, 6,048 runs; per-call checks failed in 417/720 runs (57.9%); 34.4% vs 72.8% depending on timing | **Yes** (code, scenarios, logs, judgments) | **Very close competitor on revocation timing.** It focuses on *knowledge retention* after revocation, which bears directly on ANANKE's "no old content after revocation" rule. Compaction is not mentioned in the summary; this must be checked |
| 28 | **TaskFence**, GitHub mohdmuzeeb/taskfence (ICICyTA 2026) | S | Revocation-safe side effects: commit-time authorization inside the application's own DB transaction | **Yes** | no | **Yes** | ? | **Yes** | **Same design as ANANKE ADR-0002.** Treat it as prior art for the gateway transaction |
| 29 | **Lingering Authority: Revocable Resource-and-Effect Capabilities for Coding Agents**, arXiv 2606.22504, Jun 2026 | S | Authority stays exposed after its grant episode closes; a "no-stale-use" rule (remove it from later interfaces *and* invalidate it at execution) | **Yes** | ? | **Yes** | ? | ? | **Close overlap:** the interface-removal vs execution-invalidation split maps onto ANANKE's recall vs enforcement split |
| 30 | **Revocation Is Not Complete at Receipt: An Executable Outcome Contract for Distributed Agent-Tool Gateways**, arXiv 2610.15991, Oct 2026 | S | Revocation completes in stages (C0 recorded, then C4 every gateway installs deny, then C5 no guarded effect within an observation window) | **Yes** | no | **Yes** (distributed) | ? | ? | Gives a stronger completion definition than ANANKE's single-gateway lab; worth borrowing its C5-style "no effect after revocation" metric |
| 31 | **ResidualAuth: What Authorization State Must Language Agents Preserve under Revocable Delegation?**, arXiv 2609.08062 | S (title only) | Which authorization state must survive | likely | ? | ? | ? | ? | Possibly the closest on *what must be preserved in context*. Read first |
| 32 | **Authorization Closure Graph: Minimal Repair for LLM Agents with Evolving User Instructions**, arXiv 2609.32428 | S (title only) | Evolving instructions | **Yes** | ? | ? | ? | ? | To screen |
| 33 | **VERA** (2608.30091), **Authorization for Self-Modifying Agent Populations** (2610.00347), **revsim** (Zenodo 24091916), **Clearance Bench** (HF dataset NagaYu/clearance-bench, grant/revoke timeline over a synthetic corpus) | S | Revocation propagation, federation, retrieval | **Yes** | no | various | | some | Adjacent revocation literature. Clearance Bench is a synthetic grant/revoke timeline design worth comparing against |
| 34 | **Rethinking Access Control for AI Agents: Recent Advances and Open Challenges** (survey), arXiv 2611.06764 | S | Survey | | | | | | Use it to check coverage |
| 35 | IETF drafts on execution finality and causal-effect receipts (draft-das-causal-effect-receipts-00, draft-agentic-ai-tool-execution-finality-00, draft-das-interoperable-consequence-authority-00) | S | Effect finality and receipts | | | | | | More receipts prior art |

## 3. Novelty assessment

The search found **substantial prior art for every architectural component of ANANKE**. This is still
subject to primary-text verification:

| Candidate claim | Verdict | Strongest prior work |
|---|---|---|
| Compaction degrades policy retention and compliance | **Not novel** | #1 Compaction Cliff, #2 Governance Decay, #3 ARCBench, #4 Ghost in the Context |
| Keep policy outside compactable history and re-inject after compaction | **Not novel** | #2 Constraint Pinning, #3 policy-tool delivery, #4 SafeContext |
| Commit-time authorization of exact effects against current policy, fail-closed | **Not novel** | #5 CommitGuard, #8 CONTINUITY, #6 |
| Summaries can launder authority; provenance or origin binding | **Not novel** (and prior work is more rigorous) | #9 TMA-NM, #10 |
| Hash-chained decision and compaction receipts | **Not novel** | #23, #35 |
| Benchmarks of mid-task revocation and its timing | **Not novel** | #27 RevBench (released code and logs), #5, #30, #33 |
| Separating removal from the interface (recall) from invalidation at execution | **Not novel as a concept** | #29 Lingering Authority, #3 ARCBench ("rule present but violated") |
| Commit-time check inside the application DB transaction | **Not novel** | #28 TaskFence |

**What may remain open (hypothesis to verify, not a claimed gap).** The second search round narrowed this
considerably. RevBench (#27) already varies revocation timing across 6 models with released code, and Lingering
Authority (#29) already names the recall/enforcement split. What remains *unconfirmed*, and is a candidate gap only
if the primary texts of #1–#3, #27, #29 and #31 show it is absent:

1. **Policy transitions crossed with the compaction schedule.** Compaction studies (#1 to #3) appear to use
   *static* rule sets. Commit-time work (#5) appears to vary *invalidation* without varying *compaction*. A
   controlled design that crosses {revoke, expire, supersede/narrow, regrant} with {timing relative to
   compaction} × {0/1/3/5 compactions} × {matched budget} may not exist yet.
2. **Separating three endpoints in one design:** (a) structured policy recall, (b) proposal-level
   stale-authority rate on predeclared checkpoints, and (c) committed-effect rate under G0 vs G1. Separating
   them shows exactly how much safety comes from memory and how much from enforcement. ARCBench's
   "rule present but violated" result suggests (a) and (b) diverge.
3. **Revocation-aware compaction using provenance.** When a grant is revoked, the compactor drops or redacts
   memory entries whose `source_ids` derive from the revoked resource. This tests whether compaction can *reduce*
   RevBench-style knowledge retention instead of merely surviving it. It is a concrete, testable use of the
   provenance labels. Check RevBench's IFC and unlearning baselines first.
4. **Budget-matched comparison of a compact, transition-aware projection** (including explicit revocation
   warnings) vs Constraint-Pinning-style full re-injection at tight budgets. This is a narrow question and
   could well return a null result. That would be a legitimate result to publish.

## 4. Accepted repositioning (owner decision, ADR-0007)

Reposition ANANKE from "a new revocation-aware runtime" to **a controlled benchmark and comparative study of
policy transitions under repeated context compaction**. Working title: *Do Agents Remember Revocations? A
controlled benchmark of policy transitions under repeated context compaction.* Under this framing:

- **M4 is explicitly a Constraint-Pinning-style baseline** (cite #2), and **G1 is explicitly a CommitGuard-style
  monitor** (cite #5). Both are reimplementations, labelled as approximate, not official.
- M5 (compact projection with revocation warnings) is one candidate under test, not the headline.
- The headline contribution would be the benchmark design (transition × compaction × budget, three separated
  endpoints, independent oracle, frozen holdout), plus honest results including nulls.
- Before Phase 5 freeze, we need primary texts of #1 to #5, #8 to #10, ideally their code, and an attempt to
  reproduce the strongest feasible comparator (likely ARCBench or the Governance Decay protocol).

The engineering in Phases 1 to 4 (ledger, reducer, gateway, mock tools, oracle) is **needed under either
framing**. The pivot changes positioning, baselines and endpoints, not the core build order.

## 5. Open actions

- [ ] Obtain primary texts. Either the owner allows `arxiv.org` (and `datatracker.ietf.org`) in this
      environment's network policy, or supplies the PDFs locally.
- [ ] Fill in the Dyn/RC/TB "?" cells and the license and code columns from the primary texts.
- [ ] Resolve the masterplan's unverified citations (#15, #24).
- [ ] Run the queries on Semantic Scholar, Google Scholar, ACM, IEEE and GitHub; record them here.
- [ ] Check trademark and package-name availability before any public release (the "ANANKE" name is already used).
