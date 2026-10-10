# Earned-authority acceptance specifications

**Status: BDD-001 through BDD-037 have executable M1 local-fixture acceptance
bindings in `tests/test_lifecycle_bdd.py`.** The `.feature` files remain behavior
specifications; this kit uses explicit unittest bindings, not a Gherkin step
interpreter. `bindings.json` maps all 37 current IDs to 51 separately reported
behavioral cases. A further test verifies that the mapping covers the actual
specifications. `reports/m1-bdd-green.log` and `reports/m1-bdd-report.json` record
the initial executed snapshot. The final `reports/component-verification.json`
also records all 52 BDD-module tests as passing within its 203-case component run;
the environment coverage file cites their individual case IDs. BDD-038 remains
unbound future robot-simulation scope.

Real canonical-service runners now also exist. Their 23 lifecycle checks and 17
fault checks are recorded in `reports/connected-lifecycle.json` and
`reports/connected-adversarial.json`. They include independent readback, actual
Passport/OPA decisions, canonical Cascade/GCL calls, Ledger receipts, durable
recovery and mutation-fence interleavings. They are not the 37-scenario BDD suite.
`reports/bdd-environment-coverage.json` maps explicit partial evidence to 17 IDs
and leaves 20 UNMAPPED. It certifies zero complete connected scenarios: all 37
remain AMBER for full real-adapter acceptance and their complete outline rows.

The fresh same-host kit repeats those 40 checks and adds policy/service/restart
checks, for 61 checks in `reports/clean-reference-combined.json`. This is M3
reconstruction evidence on separate local state and service instances; it does
not establish an independent installer, another host, OpenShift or robot safety.

This is a separate local integration kit. ARE Foundation remains the
S0/S1 identity, passport, scope, policy, and proof-before-execution boundary. Its
current check-only proof (`executed=false`, `receipt_created=false`) is not proof
that a registry action occurred or that a ledger receipt was issued. Nothing here
asserts production readiness, Red Hat support, or physical robot safety.

The connected integration uses the standalone Passport service as the canonical
authority and the standalone Ledger as the canonical evidence store. Foundation
is their facade at its public boundary; a second independent authority store in
the facade must not determine whether a command can commit. The M1 acceptance
suite retains explicitly labeled local fixture adapters. Its passes cannot be
transferred to real adapters merely because the shared controller code is used.

## Common vocabulary and fixture policy

- A **skill revision** is a content-addressed deterministic procedure version.
- A **qualification** binds that revision to its tested task, context, evidence
  window, independent checker revision, and qualification-policy revision.
  Its contract disposition is `ELIGIBLE`, `HOLD`, or `INELIGIBLE`; reasons such
  as `INSUFFICIENT_EVIDENCE` are recorded separately in lifecycle evidence.
- Every command binds exact content digests for skill, context, qualification,
  and authorization policy, plus a monotonic authority revision. Readable names
  such as `skill-v1` and `demo-a` in the scenarios denote immutable fixture
  digests, not mutable tags or names that may be silently reassigned.
- A **grant** is a logical permission bound to one qualification, actor, action,
  resource, context, and validity window. A passport may carry several grants.
  Replacing one active passport must preserve unaffected grants while invalidating
  the previous authority revision. These scenarios do not require multiple active
  passports per agent.
- An **attempt ID** identifies one logical requested registry mutation. Retries
  use that ID and the same payload digest. Separate attempts get distinct IDs.
  Individual transport requests can have separate request IDs.
- **PASS**, **FAIL**, and **UNKNOWN** are outcome-evidence states. UNKNOWN is
  insufficient knowledge, never a recorded failure or success.
- The local demo policy requires three fresh, independently verified shadow
  outcomes for initial qualification, no known failure in the selected window,
  and separate policy approval for authority. This threshold is test data, not a
  recommendation about statistically adequate production evidence.
- The default local policy holds new mutations when required evidence becomes
  stale or unknown. It records the reason and requires review or fresh evidence;
  it does not count such a hold as failure-based demotion.
- A **HELD** decision denies new mutations while preserving the distinction
  between missing knowledge and a known negative result. It is not permission
  to queue an execution that later resumes without reevaluating authority.
  `HELD` is a lifecycle/decision description, not an extra qualification enum
  or an extra attempt state: qualification uses `HOLD`, and an uncommitted
  refused attempt is `DENIED` with a hold reason in its lifecycle evidence.
- Explicit known failure demotes the affected skill and revokes its grant. Every
  mutation checks the authoritative current grant revision at the registry's
  commit boundary. Cached admission alone cannot authorize that commit.
- Decision D8 requires a durable, authenticated **local intent/outbox record**
  before mutation. If local durability or authentication cannot be established,
  the mutation is denied. A remote ledger receipt is not a prerequisite.
- A remote ledger outage leaves delivery `PENDING` and never fabricates a receipt
  or delays authority revocation. Local intent, execution, and outcome evidence
  remain durable for idempotent delivery. A confirmed independent `PASS` remains
  `PASS` while its ledger delivery is pending; delivery availability and observed
  task outcome are separate states.
- Recovery reconciles the actual registry state and its durable attempt record
  before any execution retry. It retries delivery without repeating a confirmed
  mutation. Uncertain actual state remains `UNKNOWN`; a remote delivery failure
  alone does not make known actual state unknown or hold otherwise valid authority.

Deployment-specific policies requiring a remote ledger receipt before execution
are outside this kit's current scope. They must be designed and tested separately.

These are the implemented bounded demo decisions. A deployment choosing a
different policy must define and test that policy explicitly. The M1 adapter is
a disposable local model registry with a controlled clock and deterministic
fault hooks; the connected registry uses persisted SQLite state, separate reader
access and a same-host mutation fence shared with canonical authority changes.

## Files and stable IDs

- `qualification.feature`: BDD-001 through BDD-007.
- `authority.feature`: BDD-008 through BDD-015.
- `execution_and_evidence.feature`: BDD-016 through BDD-022.
- `withdrawal_and_requalification.feature`: BDD-023 through BDD-027.
- `concurrency.feature`: BDD-028 through BDD-032.
- `ledger_integrity.feature`: BDD-033 through BDD-037.
- `future_robot_simulation.feature`: BDD-038, future scope only.

Current scenarios carry `@specified @m1_fixture_bound`. The robot scenario carries
`@specified @unbound @future @simulation_only` and is excluded from current release gates.
Preserve scenario IDs when renaming or moving scenarios. Scenario-outline rows
are separate cases under one ID and must retain their case labels in reports.

## Binding and evidence requirements

Bindings must exercise the public contract of the kit and independent observer
reads. They must not pass by setting the expected result directly in a mock. A
test fixture can inject clock movement, dependency failure, and controlled
interleavings. Record the injected event, authoritative state before and after,
policy and skill revisions, attempt and request IDs, checker result, and ledger
receipt verification status. Use synthetic identifiers and redacted evidence in
shareable reports.

These scenarios specify required behavior across services. The draft JSON
schemas check individual record structure plus selected local invariants, and
the wire producer/consumer tests validate actual record bindings, authenticated
sources and receipts. Neither shape validity nor a wire check alone establishes
an entire multi-step BDD scenario. The BDD
scenarios complement **evaluation-driven development (EDD)** with measurable
outcome and challenge cases. The meaning of CUT remains an open terminology
decision and is not assumed by these files.

Preregistered held-out EDD value comparisons remain AMBER. The deterministic
engineering fault schedule is useful evaluation evidence, but does not establish
cost, throughput, reliability or reduced-LLM benefits against a matched baseline.

Each report must distinguish **specified**, **executed/pass**, **executed/fail**,
and **not executed/blocked**. A missing adapter, skipped scenario, unavailable
database, or absent binding cannot count as a pass. A simulated adapter pass
cannot count as a live Foundation, Passport, Ledger, or robot integration pass.

The initial RED log records the absent runtime implementation; a later recovery
RED log records failing behavioral assertions for unfinished observation recovery,
uncertain reconciliation, reinstatement linkage, and tamper audit. The M1 GREEN
report is scoped to the exact hashes it records. It must not be reused to claim
that a different source revision or live integration passed.

## Source boundaries reviewed

- ARE Foundation: `docs/foundation-scope-and-limitations.md`.
- ARE Foundation: `docs/deployment-boundary.md`.
- ARE Foundation: `docs/governance-strata-integration.md`.

Source checkout: `/Users/jkershaw/Documents/are-foundation`.
