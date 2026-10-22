# Phase 2 Reconciliation Analysis — Line A (origin/main) vs Line B (codex/edd-tooling)

Status: **DECISION DOCUMENT — analysis and recommendation only. Nothing is merged by this
document.** Written on the `codex/edd-tooling` branch (Line B content, commit `5123d14`)
while `origin/main` (Line A, commit `4e30b08`) is examined read-only via git.

Scope: the 5/5 divergence that begins at merge base `ffd35e1`. Line A = `d54dfb8`,
`74998e7`, `b7b39d5`, `49ad74d`, `4e30b08`. Line B = `d754ed1`, `5cf875c`, `e8a372a`,
`86f6547`, `5123d14`. Both lines independently implement multi-resource grants with
different APIs and carry parallel EDD (evaluation-driven development) tooling lines. This
document compares them precisely and recommends a single reconciliation that serves
Phase 2 of `governed-ai-platform/docs/ECOSYSTEM_ROADMAP.md` (§4: one qualification stack;
the evaluation card as the single qualification artifact; EAK's EDD executed as the
authority-leg gate; exit criterion "one capability qualified via card … that EAK then
grants authority from").

---

## 1. Executive summary

| Question | Recommendation |
| --- | --- |
| Which grants implementation? | **Line A (origin/main), wholesale.** Its journal validates removal metadata (`removed_targets`) against the prior aggregate with 49 adversarial tests; Line B stores an unvalidated `targets` passthrough. Line A has 514 passing tests (77 multi-resource/journal cases) vs Line B's 457 (12 cases), an independent review cycle that found and fixed five real defects in this exact area, and the later, broader live BDD evidence (live-013, BDD-031 complete, 52 cases / 37 IDs vs Line B's live-011). |
| What to salvage from Line B (grants)? | `has_skill()` helper; `Runtime.execute` routed through `select_grant`; optionally the anchor-mismatch `BINDING_MISMATCH` taxonomy and `select_grant` qualification filters. Drop B's `targets` journal field, `target_view` projection (incompatible with A's journal validation), and `withdrawals` re-key migration (superseded by A's `withdrawal_causes`). |
| Which EDD line is primary? | **Line A** (executed pilots 001–007, routing 001–002, sequential 001–003, 114 harness tests, readiness gating, CLI fencing, independent review artifacts). **Adopt Line B's manual-comparator tooling** (episode console, operator runbook, card sets, family manifest, grader CLI) as the human-baseline leg — it implements exactly what Line A's `HUMAN_BASELINE.md` proposes and what Line A's readiness gate `actual_human_baseline_plan` requires. |
| Episode-card vs eval-cards format (G-07)? | Confirmed **structurally different and legitimately different lifecycle stages** (task payloads vs self-hashing result records). Reconcile by *renaming* EAK's task payloads away from "card" and by *emitting* `evaluation-card/v1` result records from the EDD harness/grader for eval-cards validation and notarization — one format, two scopes, shared schema lineage — **before** further EDD execution, as the roadmap requires. Cheap now: Line B's cards were never executed. |
| Merge plan shape? | Build `reconcile/phase2` **on top of origin/main** and port Line B's deltas (license, demos, retention work, runtime `select_grant`, `has_skill`, manual EDD tooling). A naive tip-merge conflicts in 27 files (24 content + 3 add/add, including `grants.py` and its test); the port plan reduces hand-work to mechanical import/call-site rewrites, one rename, doc text merges, and report regeneration. |

One-paragraph recommendation: **Keep Line A as the base for everything it touches —
grants, journal, connected adapter, wire contracts, and the EDD harness — because it is
the more rigorously validated, independently reviewed, and actually executed
implementation, and because Phase 2's exit criteria ("EAK grants authority from a card",
"EDD executed with results on record") are already materially satisfied by Line A's
evidence. Port Line B's genuinely additive, non-overlapping work onto it: the Apache-2.0
license (a roadmap 0.4 mandate), the demos, the receipt-retention/reconstruction proofs,
the `has_skill` helper, the fixture-runtime `select_grant` integration, and — most
valuably — the entire manual-comparator EDD tooling, which is the missing prerequisite
for Line A's own confirmatory readiness gate. Resolve the two parallel formats by
renaming Line B's unexecuted episode task payloads and adding an eval-cards `evaluation-card/v1`
emitter to the EDD tooling before any further EDD execution, satisfying G-07 and §2.1 of
the roadmap. Do not attempt a symmetric merge; the divergence contains two incompatible
journal wire formats (`removed_targets` vs `targets`) and two incompatible withdrawal
queue schemas, so one side must win wholesale and the other must be ported.**

---

## 2. Multi-resource grants: precise comparison

Both lines derive from the same base and make `ConnectedRuntime` normalize Passport scope
sets into a **list** of grants (previously a skill-keyed dict), add a shared
`earned_authority/grants.py`, route `_check` through exact selection, make revocation
anchor-bound, audit every grant of a skill, and re-key the withdrawal queue. They differ
in API shape, validation depth, persistence format, and test coverage.

### 2.1 API shape

| Helper | Line A (`origin/main`) | Line B (local) |
| --- | --- | --- |
| slot key | `grant_slot(grant)` — public | `slot(grant)` — module-private convention (`_SLOT`) |
| iterate/validate | `iter_grants` (dict-or-list, duplicate id/slot/scope rejection) | same, plus tuple acceptance and `Denied` passthrough |
| per-skill | `grants_for_skill` | `grants_for_skill` + **`has_skill`** (B-only) |
| by id | `grant_by_id` — first match (safe: `iter_grants` rejects duplicate ids) | `grant_by_id` — raises `BINDING_MISMATCH` on duplicates (defensive dead code) |
| unique | `unique_grant` (`AMBIGUOUS_GRANT`) | identical |
| selection | `select_grant(authority, *, skill, version, context, action, resource, grant_id=None)` — **grant pin inside selection**; no match → `SCOPE_MISMATCH`; >1 → `AMBIGUOUS_GRANT`; context compared by digest; unserializable context → `SCOPE_MISMATCH` | `select_grant(..., grant_id=None, qualification_id=None, qualification_digest=None)` — **extra qualification filters**; requires raw `context` equality *and* digest match; >1 → `BINDING_MISMATCH`; no try/except around digest |
| upsert | `upsert_grant` (slot replace + append, validated) | identical |
| projection | — | **`target_view(grant)`** (B-only; used by B's revoke) |

### 2.2 Validation and selection semantics

- **Context matching.** A compares `context_digest` only (typed: `{'enabled': True}` and
  `{'enabled': 1}` produce different digests, with a dedicated regression test). B
  requires raw dict equality **and** digest equality; the digest leg makes B equally
  type-safe, so this is redundant-but-safe in B.
- **Anchor pinning.** A passes `grant_id=intent.get('grant_id')` into `select_grant`, so
  a pinned-but-wrong id surfaces as `SCOPE_MISMATCH` from one code path. B calls
  `select_grant` without the pin, then checks `grant_id`/`qualification_id`/
  `qualification_digest` after selection in `connected._check`, raising `BINDING_MISMATCH`.
  B's taxonomy is arguably more precise (anchor mismatch ≠ scope miss) and its
  qualification-digest check is stronger than A's post-hoc `eligibility` call; A's is the
  simpler single-path design. Either can be adapted; A's is what 77 tests cover.
- **Ambiguity taxonomy.** A: `AMBIGUOUS_GRANT`; B: `BINDING_MISMATCH`. In a validated
  authority both branches are unreachable (duplicate slots are rejected at iteration), so
  this is naming, not semantics.

### 2.3 Journal and persistence integration (the hard fork)

- **Line A** adds `removed_targets` to `_new_authority_operation` with full validation:
  field completeness, duplicate/skill checks, anchor containment, and
  `_validate_removed_target_request`, which binds the removal set to the **prior
  aggregate** (predecessor tuple match, "removed targets differ from complete prior
  skill"), forbids a REVOKE that would discard another live skill, and for ISSUE
  replacements verifies retained bindings byte-exactly and forbids shortening a
  survivor's absolute expiry. Tampering with a persisted intent is rejected at recovery
  (`AUTHORITY_INTENT_UNAUTHENTICATED` / `AUTHORITY_INTENT_BINDING_MISMATCH`).
- **Line B** adds `targets` as an unvalidated passthrough:
  `if targets is not None: operation['targets']=targets`. The invariant lives only in
  the caller. B's `revoke` supplies `[target_view(g) for g in removed]` — and
  `target_view` omits `skill_digest`, `context_digest`, `qualification_digest`, and
  `policy_digest`, so B's payloads would **fail A's journal validation** ("incomplete
  removed target"). The two lines write incompatible journal/event wire formats.
- **Withdrawal queue.** A introduces a new `withdrawal_causes` table (PK includes
  `attempt_id` + both anchor fields), migrates legacy rows, and empties `withdrawals`.
  B keeps the `withdrawals` name with a re-keyed PK `(agent, skill, target_grant_id)` and
  a careful rename-and-rebuild legacy migration. Both preserve legacy data; A's key
  retains multiple queued causes per anchor, B's collapses them. A's shape is paired
  with its tests; keep A's.

### 2.4 Connected-adapter behavior differences

- **Audit of a non-ELIGIBLE qualification.** A records a `HELD` event, queues
  `withdrawal_causes`, and drains — the withdrawal is enforced. B's early-return branch
  reports `requires_hold` **without queueing or draining** (only the evidence-failure
  path enforces). A is stricter and more consistent.
- **`_held_reason` (hold diagnostics).** A matches prior targets by `context_digest`
  and reads the anchor qualification from `target_qualification_id`; B compares raw
  context and reads it from the prior grant. A survived a review cycle that specifically
  fixed a "typed-context diagnostic mismatch" here.
- **`_normalize`.** Both convert to lists and run `iter_grants`; A additionally rejects
  non-integer inner expiry (`test_noninteger_inner_expiry_cannot_hide_behind_outer_cap`).
- **Wire contracts.** A sorts exports by `grant_id` and selects multi-attempt identity
  by an explicit per-kind field map (review fix: "two attempts under one passport remain
  distinct"); B sorts by `(skill, action, resource, grant_id)` and uses a `.get()` chain.
  A's identity handling is more rigorous.
- **`runtime.py`.** B-only change: `Runtime.execute` selects via `select_grant` instead
  of skill-keyed map lookup + manual field checks. A left the fixture runtime on manual
  checks. B's change is call-compatible with A's `select_grant` and should be ported.

### 2.5 Test coverage and evidence

| | Line A | Line B |
| --- | --- | --- |
| `tests/test_multi_resource_grants.py` | 28 cases (unittest style): preservation, exact execution, borrow denial, wrong dimensions, typed bool/int context, same-slot replace, duplicate id/scope/slot, digest/outer-scope mismatch, stale-then-fresh recompute, concurrent CAS, skill-wide revoke + `removed_targets` round-trip, replaced-anchor reconciliation, incomplete-anchor rejection, two queued causes, legacy migration, distinct-qualification audit/reevaluate, per-resource hold diagnostics, non-integer expiry, outage reevaluation, lost-response restart, complete wire export, procedure-revision hashing | 12 cases (pytest style): broadly the same themes, minus journal tamper/rebind/lifetime coverage, typed-context, non-integer expiry, concurrency, restart recovery |
| `tests/test_multi_grant_journal.py` | **49 cases (A-only)**: signed isolation from caller mutation, lost-reply restart, persisted-metadata rebinding (parametrized edits), unsigned tamper blocks recovery, historical records stay unenriched, invalid target descriptions never persist, targets must exactly describe the complete prior skill (10 parametrized cases), resulting scope set must preserve other live grants (10), lifetime-shortening rejection, ceil-safe fractional-second replacement | absent |
| Total suite | **514 PASS** (`reports/component-verification.json` on origin/main) | **457 PASS** (local `reports/component-verification.json`) |
| Live BDD | `service-bdd-live-012/013` + `013-031-wire`; BDD-031 **complete** (52 cases / 37 IDs per `docs/MULTI_RESOURCE_GRANTS.md`) | `service-bdd-live-009/010/011` (earlier, narrower) |
| Independent review | `evidence/edd-harness-review*.md/.json`, `evidence/edd-grader-red.log` etc. — a review cycle that "reproduced and fixed incomplete withdrawal anchors, known-failure downgrading, typed-context diagnostic mismatch, malformed expiry hiding behind a cap, and retained-grant lifetime shortening" | none recorded for the grants work |

### 2.6 Dependent consumers (port cost if Line A wins)

- Line A `connected.py` imports `iter_grants, grants_for_skill, grant_by_id, select_grant, upsert_grant`.
- Line B `connected.py` imports `grants_for_skill, iter_grants, select_grant, target_view, upsert_grant` and inlines anchor lookups.
- Line B `runtime.py` (execute path) and B's tests/tools depend on **`has_skill`**: `tests/test_authority_observations.py`, `test_connected_evidence.py`, `test_connected_security.py`, and `tools/validate_connected.py`, `validate_authority_recovery.py`, `validate_bdd_connected.py` (A's versions of these files use `grants_for_skill(...)` truthiness — the six test-file and four tool-file merge conflicts are almost entirely this rename plus import lines).
- Both `authority_journal.py` and `wire_contracts.py` import only `iter_grants` (same shape on both lines).

Keeping A therefore costs: one `has_skill` shim in `grants.py` (or mechanical call-site
renames in ~10 files) plus the `runtime.py` port. Keeping B would cost re-deriving A's
journal validation and 49 tests. The asymmetry is decisive.

### 2.7 Grants verdict

**Keep Line A.** It is the implementation with defense-in-depth at the persistence
boundary, the larger and adversarially-reviewed test suite, the later live evidence, and
the single-path selection semantics. Salvage from B: `has_skill`, the `runtime.py`
`select_grant` integration, and (optionally, as a small reviewed patch) the
anchor-mismatch `BINDING_MISMATCH` taxonomy and the `select_grant` qualification
filters. Explicitly discard: B's `targets` journal field and `target_view` projection,
B's `withdrawals` re-key migration, and B's external post-selection anchor check (its
semantics are covered by A's in-selection pin).

---

## 3. EDD lines: executed harness (A) vs manual console (B)

### 3.1 Line A — automated, executed, reviewed, fenced

`evaluations/harness/` (`controller`, `design`, `grader`, `runner`, `readiness`,
`lookup`, `sequential`, `routing`, `routing_audit`), `evaluations/tests/`
(**114 tests**: grader/pilot/readiness/routing/sequential), plans
(`pilot-plan.json` v1 — executed then honestly *rejected*; `pilot-plan-v2.json` — frozen
and executed; `confirmatory-design.json`; `routing-plan.json`; `sequential-plan.json`),
CLIs (`tools/run_edd_pilot.py`, `verify_edd.py`, `check_edd_readiness.py`,
`run_edd_routing.py`, `run_edd_sequential.py`), docs (`README`, `PILOT.md`,
`HUMAN_BASELINE.md` *proposal*, `ROUTING.md`, `SEQUENTIAL.md`).

Executed evidence at the tip: `reports/edd-pilot-001..007` (pilot-007: 300 episodes,
100/arm, 10 strata × 10 seeds; general-fixed and adaptive tie 40/70 legitimate tasks,
legacy pinned 20/70, 50/50 correct denials, **zero unauthorized commits**;
engineering acceptance GREEN, value acceptance honestly AMBER), `edd-routing-001/002`
(context-conditioned nano-agent selection), `edd-sequential-001..003` (retained-outcome
sequences with seal-before-next-support), `edd-confirmatory-readiness-001..003`, plus
red/green logs and independent review artifacts in `evidence/`.

Properties Line A has that Line B does not: frozen comparator design with a strengthened
general fixed baseline (the earlier engineered advantage was removed and the old plan
rejected rather than silently redefined); an independent read-only grader with
authenticated authority snapshots and mutation-boundary checks; partition/leakage
auditing and ancestry fencing; a readiness checker that **exposes confirmatory
prerequisites and never authorizes execution**; CLI fencing that rejects held-out and
confirmatory modes; sequential and routing evaluation legs; source-fingerprint
before/after checks on every run.

### 3.2 Line B — manual comparator, complete but never executed

`evaluations/console.py` (`EpisodeConsole` with timed runbook actions — evidence,
qualify, grant, release, read, withdraw, lookup, intervene, stop — plus intervention log
and trace; `prepare_episode` session-lead setup; `grade_episode` independent readback),
`evaluations/operator-runbook.md` (the procedure a timed human follows),
`evaluations/manifest.json` (5 families across development/calibration/held_out splits,
with split-binding checks and held-out rejection), `evaluations/cards/` (3 development
card sets in public/labels/prepare separation), `evaluations/pilot-plan.json` (manual
pilot plan, honestly marked `executed: false`, `human_timed: false`,
`held_out_opened: false`), `tools/episode_console.py` + `tools/grade_episode.py` CLIs,
`tests/test_episode_console.py` (6 tests). `evaluations/protocol.json` on this line
states `execution_status: NOT_EXECUTED` and its `next_gate` names exactly this manual
path.

Properties Line B has that Line A does not: an **implementable manual comparator**. Line
A's `HUMAN_BASELINE.md` is a proposal ("a script may enforce the chosen action and
collect timings; it may not replace the choice and be labelled human" — operator
unassigned), and Line A's readiness gate `actual_human_baseline_plan` *requires*
`PLANNED_WITH_OPERATOR` with a counterbalancing plan for confirmatory status. Line B
built that script, that runbook, and the card/label/prepare separation that keeps grade
labels out of the operator's path. The two EDD lines are **complementary, not
competing**: A is the executed automated evidence line; B is the missing human-baseline
leg that A's own readiness checker demands.

### 3.3 EDD verdict

**Line A is the primary EDD line** (executed, tested, reviewed, fenced — and the roadmap's
"EDD executed with results on record" is already satisfied by its pilot reports).
**Adopt Line B's manual-comparator tooling wholesale** as the human-baseline leg, placed
under a clearly-named home (recommendation: `evaluations/manual/`) with its plan renamed
to `manual-pilot-plan.json` so the `evaluations/pilot-plan.json` add/add conflict
dissolves (A's v1 file stays as executed-then-rejected history; A's v2 remains the
automated plan of record). Line B's honest NOT_EXECUTED protocol status must be
preserved verbatim — it becomes the truthful baseline for the first actually-timed run.

---

## 4. Format overlap: EAK episode cards vs eval-cards (G-07)

### 4.1 What each format actually is

**EAK `evaluations/cards/*.card.json`** (Line B): *episode task payloads* — inputs for
one assignment. Fields: `episode_id`, `split`, `family_id`, `seed`, `agent`, `skill`,
`version`, `context`, `action`, `resource`, `requested_digest`, `attempt_id`,
`deadline_ms`, `other_resources`. Sidecars: `.labels.json` (private reference label +
initial registry state) and `.prepare.json` (session-lead registry rows, shadow
observations, procedure reports, policy flag). No digests, no metrics, no self-hash.

**eval-cards `schemas/evaluation-card-v1.schema.json`**: *self-hashing result records*
emitted after a qualification run. `schema_version: fabric.evaluation-card/v1`;
`card_sha256` = SHA-256 of the canonical JSON **without** the digest field; mandatory
`construct` (statement / metric / gaming_analysis, each substantive); `evaluation`
binding digests to the frozen plan and measured report; `systems[]` with
`scaffold`/`model_binding`, evidence labels (LIVE / REHEARSAL / OFFLINE — replay may
never be labelled live), `repetition`, `single_attempt_rate` / `pass_at_k` / `pass_all_k`
with Wilson 95% intervals, `reliability_claimable`, performance, gates, color;
`uncertainty`; `holdout_policy`; `verdict.authorizes_execution` (const **false**);
`limits`. Notarization chains the exact bytes into an append-only ledger and returns a
receipt that proves recording — never truth, never authority.

### 4.2 Confirmation and assessment

The earlier analysis is **confirmed**: the two are structurally different because they
occupy different lifecycle stages — assignment-time task inputs vs post-run,
self-hashing, notarizable evidence. Neither can be replaced by the other, and forcing
the task payload into the result-record schema would be a category error.

They are nevertheless **not legitimately free to share the name "card"**, and the
ecosystem decision is already made: roadmap §2.1 — "EAK's episode-cards are reconciled
into the eval-cards format **before** its EDD executes (G-07) — one format, two scopes
(model-qualification vs episode-qualification), shared schema lineage." The governed-ai
platform's G-07 gap row rates this "Medium — reconcile before EAK EDD runs."

### 4.3 Format verdict

1. **Rename the task payloads** so "card" unambiguously means the ecosystem
   qualification artifact: e.g. `evaluations/manual/episodes/*.task.json` with
   `.labels.json` / `.prepare.json` sidecars unchanged. This is free *now* because Line
   B's cards were never executed and Line A's pilots never consumed them.
2. **Add an emitter, not a reformat**: the EDD grader (Line A's harness grader and/or
   Line B's `grade_episode`) should produce `evaluation-card/v1` result records for EDD
   runs — episode-qualification scope, with the EDD plan digest as
   `evaluation.source_id`/binding, honest evidence labels (fixture runs are not LIVE
   invocations of a production system), Wilson intervals on the recorded rates, and
   `verdict.authorizes_execution: false`. Validate and notarize through eval-cards
   (MCP or CLI). `governed-agent-fabric`'s `evaluation_card.py` is the reference
   producer pattern.
3. **Sequence it before further EDD execution**, per the roadmap. Line A's already
   executed development pilots remain valid internal engineering evidence (their reports
   are source-bound and were never notarized artifacts); the emitter applies to runs
   from the reconciled tree forward, which is what Phase 2's "results on record" and the
   GAF→eval-cards→ARE→EAK chain need.

---

## 5. Reconciliation recommendation (consolidated)

1. **Grants core (grants.py, connected.py, authority_journal.py, wire_contracts.py):
   Line A wholesale.** Rationale: §2.3–§2.5 (journal defense-in-depth, 77 vs 12
   adversarial cases, 514 vs 457 total, independent review fixing five real defects in
   this exact area, later live evidence). B's parallel wire format (`targets`) and queue
   schema are consciously abandoned.
2. **Salvage from Line B (grants):** `has_skill()`; `Runtime.execute` → `select_grant`;
   optionally the `BINDING_MISMATCH` anchor taxonomy and `select_grant`
   qualification-id/digest filters as a small follow-up patch with tests. Discard
   `target_view` (fails A's journal field-completeness validation), the `targets`
   passthrough, and the `withdrawals` re-key migration.
3. **EDD: Line A primary; Line B's manual line adopted** as the human-baseline leg under
   `evaluations/manual/`, feeding Line A's `actual_human_baseline_plan` readiness
   prerequisite. Preserve B's honest NOT_EXECUTED status; the first timed operator run
   becomes new evidence rather than a retroactive claim.
4. **Format (G-07):** rename task payloads off "card"; emit `evaluation-card/v1`
   records from the EDD tooling; do both before further EDD execution.
5. **Line B hygiene commits are kept as-is:** Apache-2.0 LICENSE (`5123d14`, a roadmap
   §0.4 mandate), `demos/pythonized` (`86f6547`), and the retention/reconstruction
   proofs (`5cf875c`: `retention.py`, `passport_client.py` cited-receipt compaction,
   `deploy/reference/validate_backup_restore.py` + `validate_issuer_cutover.py`,
   `patches/passport-historical-issuer.patch`, reference-report trees). None of these
   conflict with Line A's grants/EDD work except shared doc/report/manifest files.

---

## 6. Merge plan

**Direction: port Line B onto Line A, not a symmetric merge.** A symmetric merge must
arbitrate two incompatible journal wire formats and two withdrawal-queue schemas
hunk-by-hunk; a port resolves them by construction.

### 6.1 Conflict surface (measured)

`git merge-tree --write-tree origin/main main` (single tip-merge simulation) yields
**27 conflicting files** — 24 content conflicts and 3 add/add:

- add/add: `earned_authority/grants.py`, `tests/test_multi_resource_grants.py`,
  `evaluations/pilot-plan.json`
- source: `connected.py`, `authority_journal.py`, `wire_contracts.py`
- tests (import/`has_skill` lines): `test_authority_observations.py`,
  `test_connected_binding.py`, `test_connected_evidence.py`,
  `test_connected_security.py`, `test_evidence_wire.py`, `test_policy_windows.py`
- tools: `report.py`, `validate_authority_recovery.py`, `validate_bdd_connected.py`,
  `validate_connected.py`
- docs/reports (regenerable or text-merge): `README.md`, `docs/BOUNDARIES.md`,
  `docs/MULTI_RESOURCE_GRANTS.md`, `docs/ROADMAP.md`, `features/README.md`,
  `reports/README.md`, `reports/component-verification.json`, `reports/kit-tests.log`,
  `reports/readiness.json`, `reports/source-manifest.json`, `roadmap.html`

The earlier rebase attempt reported 21 conflicting files; a rebase replays five commits
whose conflicts partially overlap, so both numbers describe the same surface.

### 6.2 Ordered steps

1. **Branch:** `git fetch origin`; `git switch -c reconcile/phase2 origin/main` (from
   `4e30b08`). All work below lands on this branch; main is untouched until the final
   reviewed merge.
2. **Port B-only, zero-conflict assets:** LICENSE; `demos/pythonized`; from `5cf875c`
   the B-only files (`earned_authority/retention.py`, `passport_client.py` changes,
   `deploy/reference/validate_backup_restore.py`, `validate_issuer_cutover.py`,
   `patches/passport-historical-issuer.patch`, reference-report trees, new reports).
   Conflicts here reduce to shared README/docs/report-manifest text — merge narrative,
   regenerate reports.
3. **Grants resolution:** take A's `grants.py`, `connected.py`, `authority_journal.py`,
   `wire_contracts.py` as-is (i.e., no-op for steps 1–2 of the branch). Then apply two
   small ports: (a) B's `runtime.py` `select_grant` change (call-compatible with A's
   API); (b) add `has_skill` to `grants.py`. Resolve the six test files and four tools
   by adopting A's text and, where B used `has_skill`, either the shim or
   `grants_for_skill(...)` truthiness (mechanical).
4. **Drop B's grants test file** (`tests/test_multi_resource_grants.py`, 12 cases) in
   favor of A's 28 + 49; before dropping, diff case-by-case — every B theme is covered
   by A's suite except the anchor-mismatch `BINDING_MISMATCH` assertion, which only
   applies if step 3 optionally adopts B's taxonomy (if adopted, port that one case
   with it).
5. **EDD port:** copy B's manual line to `evaluations/manual/` (`console.py`,
   `operator-runbook.md`, `manifest.json`, cards → `evaluations/manual/episodes/`),
   plus `tools/episode_console.py`, `tools/grade_episode.py`,
   `tests/test_episode_console.py`. Rename B's `pilot-plan.json` →
   `evaluations/manual/manual-pilot-plan.json` (defuses the add/add; A's v1 stays as
   rejected-plan history). Fix the module's internal path references and its 6 tests.
6. **G-07 format work (same branch, own commit):** task-payload rename (step 5 already
   moves them; finish by renaming `*.card.json` → `*.task.json`) and the
   `evaluation-card/v1` emitter wired into the EDD grader output path, with the
   construct sidecar authored for the episode-qualification scope and
   `verdict.authorizes_execution: false`. Validate a sample card against the eval-cards
   schema (local `evalcards.py` / MCP `validate_evaluation_card`) before notarizing
   anything.
7. **Docs:** merge the four doc files' narratives — A's status sections win for grants
   and EDD; add B's reconstruction, demos, license, and manual-tooling notes; document
   the journal wire-format decision (`removed_targets`) and the archived status of
   B-line live reports 009–011.
8. **Regenerate, never hand-merge, reports:** run `tools/verify.py`,
   `tools/verify_edd.py`, `tools/verify_report_provenance.py`, `tools/report.py` on the
   reconciled tree to produce fresh `component-verification.json`, `kit-tests.log`,
   `readiness.json`, `source-manifest.json`. Expect roughly 514 + retention +
   episode-console + ported cases (≈ 530+). Then one fresh live BDD run (next number,
   014) because `procedure_revision` hashes change with the reconciled source —
   existing qualifications must be re-earned, which the kit treats as normal renewal.
9. **Merge to main:** reviewed merge commit (no fast-forward) of `reconcile/phase2`
   into `main`, preserving both histories. Historical B-line reports (`source-b-*`,
   `service-bdd-live-009..011`) remain in place as archived evidence of the source they
   measured; no history is rewritten.

### 6.3 Estimated effort and residual risk

- True manual work: the two small ports (§6.2 step 3), the manual-tooling move + test
  wiring (step 5), the emitter (step 6), and doc narrative merges. The 27-file conflict
  list otherwise collapses into "take A" plus regenerated artifacts.
- **Journal wire-format fork:** any database written by B-line code is unreadable under
  A's journal semantics. B's live runs 009–011 are recorded reports of that source, not
  live systems to migrate; acceptable, but it must be stated in `docs/ROADMAP.md` during
  step 7.
- **Procedure-revision churn:** merging changes `procedure_revision`; all
  qualifications in fresh runs must be re-earned (expected, by design).
- **Phase 2 dependency:** the exit criterion "one capability qualified via card … that
  EAK then grants authority from" needs the §4.3 emitter; schedule it in the same branch
  so no EDD execution happens before the format reconciliation, exactly as the roadmap
  requires.

---

## 7. Phase 2 alignment check

| Roadmap §4 item | How this reconciliation serves it |
| --- | --- |
| 2.1 evaluation card = single qualification artifact; EAK episode-cards reconciled **before** EDD executes (G-07) | §4.3: rename task payloads off "card"; emit `evaluation-card/v1` from EDD tooling; sequenced before further execution in the merge plan (§6.2 step 6). |
| 2.2 EAK executes its EDD workstream ("the tooling exists — console, grader, card sets, runbook") | The roadmap names Line B's tooling; this plan keeps all of it and mounts it on Line A's executed, reviewed harness, so "run it" produces evidence that satisfies both the automated and the manual/readiness legs. |
| Exit: capability qualified via card that EAK grants authority from | Stable grants API = Line A's (validated selection + journal), plus the card emitter, gives EAK a card reference to grant from. |
| Exit: EAK EDD executed with results on record | Already satisfied by Line A pilots 001–007 / routing / sequential; the manual baseline and confirmatory readiness remain the open gates this plan positions them to close. |

---

## 8. Artifacts examined

- Line A: `origin/main` (`4e30b08`) — `earned_authority/grants.py`, `connected.py`,
  `authority_journal.py`, `wire_contracts.py`, `runtime.py`;
  `tests/test_multi_resource_grants.py`, `tests/test_multi_grant_journal.py`;
  `reports/component-verification.json` (514 PASS);
  `reports/service-bdd-live-012/013*`; `evaluations/` (harness, tests, plans, docs,
  protocol); `reports/edd-*` (pilots 001–007, routing 001–002, sequential 001–003,
  confirmatory-readiness 001–003); `evidence/edd-*` (reviews, red/green logs).
- Line B: local branch (`5123d14`) — same core files;
  `reports/component-verification.json` (457 PASS); `reports/service-bdd-live-009..011`;
  `evaluations/` (console, cards, manifest, runbook, pilot-plan, protocol);
  `tools/episode_console.py`, `tools/grade_episode.py`; `tests/test_episode_console.py`;
  `earned_authority/retention.py`; `demos/pythonized/`; `LICENSE`.
- Ecosystem: `governed-ai-platform/docs/ECOSYSTEM_ROADMAP.md` §4 (Phase 2) and
  `docs/ECOSYSTEM_ANALYSIS.md` G-02/G-07; `eval-cards` repository
  (`schemas/evaluation-card-v1.schema.json`, `AGENTS.md`, reference-producer notes).
- Merge simulation: `git merge-tree --write-tree origin/main main` (27 conflicts:
  24 content + 3 add/add).

*This document makes no claim about unexecuted work. Line B's EDD tooling remains
NOT_EXECUTED until an operator is actually timed; the first executed manual run will be
new evidence, recorded under the protocol's amendment rules.*
