# Earned Authority roadmap

Prepared 2026-10-09; evidence update 2026-10-10 UTC. This is a milestone plan, not a calendar estimate. The bounded local build has three executed milestones. The original G0–G4 acceptance ambitions below remain in force; a local milestone does not silently close a broader gate.

## Objective and first demonstration

A deterministic procedure earns eligibility from independently observed outcomes. Policy can issue limited authority for that exact procedure version and context. The executor checks that authority at the mutation boundary. A failed or unresolved outcome changes eligibility under explicit policy; revoked authority cannot permit a subsequent mutation. Requalification creates a new, auditable authority revision.

First task: promote one selected model version in a disposable registry with independent state/health readback. Fix task inputs, action/resource scope, and postconditions before comparing performance. No LLM is required on this deterministic path. GCL is a proposal/constraint check where configured; its judgment is not outcome evidence or authorization.

## Operating decisions for this build

D1. Standalone Agent Passport is the target lifecycle owner; standalone ARE Immutable Ledger is the target receipt/append owner. Foundation is the gateway, policy/scope surface, and integration facade. Pin consumed versions. Foundation's embedded copies must not become independently maintained competing authorities. The initial fallback regression patch is tactical protection of the current demo path, not completion of delegation.

D2. Higher-stage qualification and lifecycle coordination live in this separate integration kit. Preserve Foundation's published S0/S1 boundary. Add integration via adapters and documented versioned contracts.

D3. Qualification binds skill artifact digest, exact context digest/schema, evaluator revision, qualification policy digest, observed evidence, validity window, and qualification revision. Changing any qualification subject requires new qualification. A PASS outcome alone does not imply statistical adequacy, independence, or policy approval.

D4. One active passport per agent may contain several skill grants. Selective demotion atomically replaces the aggregate, preserves unaffected grants, advances a monotonic authority revision, and never publishes a partial replacement. Signer/policy/storage failure leaves an explicit, consistent state. Do not revoke the predecessor halfway through an uncommitted replacement.

D5. First execution guarantee: after revocation is acknowledged, no new mutation commits with the old authority revision. The bounded registry must enforce a revision fence in its mutation transaction or serialize mutation and revocation. A REST pre-check alone is insufficient. Already committed actions stay in history; in-flight ambiguous outcomes must reconcile before retry. Distributed adapters that cannot implement this guarantee remain amber and cannot borrow the fixture's green status.

D6. UNKNOWN, missing, stale, conflicting, unauthenticated, or self-reported outcome evidence cannot qualify a new grant. The demo policy holds the affected skill and denies new mutations pending resolution. UNKNOWN is never counted as observed FAIL. Unaffected grants remain usable if their own evidence and authority remain valid.

D7. Evidence has an authenticated producer and an independent readback source. A boolean independence declaration, a digest, and a ledger receipt prove different things; none alone proves that the observed business outcome occurred. Bind events with flow/correlation ID, unique attempt ID, idempotency key, subject revision, and payload digest; agent ID alone is insufficient.

D8. Mutation requires a durable local intent/outbox entry in the first real-service design. If local durable intent cannot be recorded, deny the mutation. Remote ledger unavailability can leave delivery PENDING and be retried; it cannot fabricate a receipt, postpone revocation, or turn a completed mutation into an unexecuted action. Scope of this operating policy must remain explicit.

D9. All timestamps are UTC integer milliseconds in the new contract. Adapters normalize legacy RFC3339/millisecond fields, reject conflicts/missing expiry, and test boundary equality. The draft digest encoding uses compact UTF-8 JSON, sorted string keys, integer numbers, no Unicode normalization, and no duplicate keys. It is not a cryptographic signature or a claim of compliance with an external canonicalization standard. Cross-language fixtures are mandatory before consumer adoption.

D10. Contract version is `0.1.0-draft.1`. Unknown mandatory versions/fields fail validation. Shape validity never grants authority. Full signed envelopes must bind context, scope expiry, policy and qualification digests, and authority revision; signatures must be checked against the stored canonical subject. Mock signatures are fixture-only.

## Parallel work packages and ownership

WP0 — Integration lead: shared contracts, fixtures, manifest, rubric and compatibility decisions. Owns `contracts/`, readiness tooling, roadmap, and acceptance runner. May merge schema changes only with consumer fixture updates. The draft is now consumed by actual runtime mappings. Gate: producer and consumer tests agree on exact semantics, canonical bytes, time, ID/retry behavior, and error codes. Schema tests alone do not freeze a multi-service contract.

WP1 — Authority engineer: Passport + Foundation adapters. Owns expiry/context correctness, signature envelope binding, true delegated verification/revocation, status propagation, cache invalidation/fencing, atomic selective replacement, and database upgrade path. Starts independent regressions immediately; contract-dependent work waits for G0. Gate: expiry equality, malformed expiry, context mismatch, warm-cache revoke, old credential replay, failed signer/policy replacement, concurrent replacements, and upgrade-from-current-data cases all pass. Test both fallback and delegated modes; execution mode must never silently fall back.

WP2 — Qualification engineer: Cascade adapter + configured GCL constraints. Owns exact skill/context qualification, evidence trust and deduplication, policy thresholds, eligibility/hold/demotion/requalification. Starts fixture design immediately; shared payload implementation waits for G0. Gate: duplicate observations never increase qualification count, changed artifacts/context cannot reuse qualification, GCL approval cannot masquerade as observed success, and promotion never directly grants authority.

WP3 — Executor engineer: bounded registry adapter, authoritative readback and mutation fencing. Owns command binding, live authority checks, exact arguments digest, idempotent mutation, retry reconciliation, and postcondition queries. Starts disposable resource and negative tests immediately; consumes G0 contracts before integration. Gate: missing/unavailable/revoked authority, changed arguments, stale context, reused decision, duplicate attempt, and revoke-vs-mutate races cause no forbidden commits.

WP4 — Evidence engineer: Ledger adapter + local durable outbox. Owns event correlation, retry semantics, pending/recorded/failed delivery, consumer verification, and tamper checks. Can implement existing ledger client contract immediately; new event mapping waits for G0. Gate: retries do not duplicate logical events; mismatched issuer/payload/attempt is rejected; hash-chain verification detects tampering; remote outage never delays withdrawal.

WP5 — Evaluation/acceptance engineer: BDD bindings + EDD runner. Owns Given/When/Then scenarios, held-out splits, baseline comparison, fault injection, metrics, and evidence provenance. BDD and evaluation protocol are written now. Bind scenarios as each lane becomes available. Gate: observed complete lifecycle and predefined EDD criteria on a pinned stack. Unbound Gherkin is amber.

WP6 — Deployment engineer: repeatable local services, then optional Red Hat reference deployment. Owns fresh-install/restart/upgrade scripts, pinned images and configuration, identity/secrets integration, diagnostics, rollback, and operational runbook. Can plan topology now; active packaging waits for G2. Gate: a clean environment reproduces the lifecycle and preserves authority/evidence semantics across restart. Any OpenShift profile is a tested reference configuration only, not an implied support entitlement.

## Executed local milestones and remaining acceptance

M1 — Local fixture lifecycle: GREEN for the recorded fixture snapshot. BDD-001–037 map to 51 separately reported behavioral cases; the coverage assertion makes 52 passing tests, with no skips. All 52 also pass in the final 235-case component run in `reports/component-verification.json`, with unchanged source hashes during that run. The fixture uses controlled time, SQLite state, independently checked readback and explicit faults. It establishes the specified local behavior at its recorded source hashes. It does not establish equivalent coverage on real service adapters. Initial red/green provenance remains in `reports/m1-bdd-report.json`, `reports/m1-bdd-green.log`, and the initial/recovery RED logs.

M2 — Canonical local lifecycle: GREEN for the bounded connected engineering checks. Actual standalone Passport, Foundation/PostgreSQL/OPA, Cascade scoring/lifecycle, deterministic GCL capacity constraints, and canonical Ledger/PostgreSQL connect to the fenced local SQLite registry. `reports/operations-reference-connected.json` records 23 passing checks, including actual wire producer/consumer and historical-qualification bindings. `reports/operations-reference-adversarial.json` records 17 passing fault checks, including UNKNOWN withdrawal, expiry, remote ledger outage, real issuance conflicts, post-commit process crash/reconciliation and both revocation orderings. These are 40 named checks, not 40 BDD scenarios or a value evaluation.

M3 — Fresh same-host reference kit: GREEN for 123 recorded checks; use `reports/operations-reference-combined.json` for the current source snapshot and its seven child reports. The documented bootstrap reconstructs five pinned upstream repositories with explicit patches, separate environment, keys, state, ports, networks and volumes on this same host. Acceptance includes policy, service interfaces, connected lifecycle, fault schedule, authority-operation recovery, retained-state restart and historical receipt revalidation. The earlier `clean-reference-combined.json` is retained as historical evidence. Repeated checks are additional environment evidence, not additional scenario coverage. This does not demonstrate a second operator, another host, disk-loss/backup recovery, OpenShift or production operation.

`reports/service-bdd-live-002.json` records 39 passing executed cases, zero failing cases and 12 explicitly unrun cases. It completely binds 22 of 37 scenario IDs; seven are partial and eight unbound. `reports/bdd-environment-coverage.json` traces each ID and outline row to exact assertions and artifacts. All 37 remain a combined AMBER gate until every scenario is complete; no matching count or shared runtime supplies missing assertions. The service suite's nonzero incomplete-acceptance exit is intentional and is not an observed behavior failure.

Authority-operation recovery now uses a durable signed local intent, an idempotent canonical operation RPC, an atomically persisted signed receipt, and a local event/APPLIED transaction. Tests exercise process exits before dispatch, after canonical commit and after local event commit, selective and empty withdrawal, later authority replacement, actual lost mutation reply, local write failure and eventual receipt-verified Ledger delivery. The fresh-reference recovery reports determine the exact accepted paths. The [boundary review](BOUNDARIES.md) retains limits: separate service commits, unresolved operations that must hold, same-OS fencing, trusted monotonic state, legacy writers without receipts and no hostile rollback protection.

The remaining AMBER acceptance work is full real-adapter BDD binding, preregistered evaluation-driven development (EDD) with held-out cases and policy-matched baselines, independent-operator/cross-host reproduction, broader operational recovery, any OpenShift reference profile, and robotics. No business-value, statistical adequacy, distributed-fencing or physical-safety claim follows from M1–M3. CUT remains unconfirmed.

## Original dependency gates retained

G0 — Contract readiness. Draft schemas, state transitions, error taxonomy, trust boundaries, canonical owner and signed-field coverage agreed through executable consumer fixtures. Actual local producer/consumer bindings now run against fixture and connected records. Wider consumer adoption, complete cross-language vectors and a published stable protocol remain amber. Independent regression fixes and scenario/evaluation writing do not wait on G0.

G1 — Component correctness. After G0, WP1, WP2, WP3 and WP4 proceed in parallel against the same contract snapshot. Each lane delivers a red regression, green correction, negative tests, artifact hashes, exact revisions, and a change note. EDD prepares held-out data independently to prevent implementation leakage. Required component checks must be green before their adapter enters integration.

G2 — Connected lifecycle. Join WP1/2/3/4 with WP5. Qualify → policy grant → fenced mutation → independent readback → demotion/hold → rejected next mutation → requalification. Add a second skill to prove selective withdrawal. Run against real local services and persistent storage. The fixture-only milestone cannot satisfy G2.

Current G2 evidence is the M2 bounded lifecycle and fault reports above. Full BDD real-adapter acceptance remains a separately tracked requirement.

G3 — Adversarial and value evaluation. Run EDD protocol on held-out cases and seeded repeats. Exercise revoke races, stale caches, failed replacement, crashes, duplicate delivery, changed versions/contexts, and unavailable verifier/ledger. Compare against policy-matched fixed and human-approved baselines. Stop on any forbidden mutation or evidence misattribution. Benefit thresholds and sample-size risk budget must be registered before final scoring. No partial averages can override hard gate failures.

The executed engineering fault schedule supplies limited adversarial evidence. Preregistered held-out value evaluation and its baselines are still AMBER; the demo-three-pass policy is not a statistical reliability result.

G4 — Repeatable deployment. WP6 packages the proven local topology; a second person/clean environment reproduces G2/G3 with pinned dependencies. Record setup effort, resource use and operational recovery. Red Hat reference profile follows selected environment compatibility testing. Hardware robotics is a separate later project gate with controller/safety ownership and domain qualification; BDD-038 is only future simulation.

M3 supplies a fresh same-host reconstruction and retained-state restart. Independent-operator/cross-host acceptance, broader recovery, Red Hat/OpenShift compatibility, and robotics remain AMBER under G4.

Critical path: G0 → authority + qualification + fenced executor + durable evidence → G2 → EDD/robustness → G4. Packaging, fixtures, BDD specifications, and evaluation preparation can proceed beside the implementation lanes. There are no invented calendar commitments.

## Definition of done per work package

Every handoff includes requirement IDs, component under test, source revision including dirty snapshot hash, contract version, environment and real/mock dependencies, exact command, before/after regression output, negative controls, durable raw artifacts with hashes, limitations, and next dependency. One reviewer other than the implementer checks authority/evidence boundaries. Patches must apply cleanly to their recorded baseline and preserve unrelated user changes.

TDD: failing behavioral regression then minimal correction and refactor. CDD: shared producer/consumer compatibility and negative schema/binding vectors. BDD: executable multi-step behavior with measured state changes. EDD: evaluation-driven development using preregistered metrics, baselines, held-out cases and failure injection. Evidence collection supports all four. CUT expansion is pending; name the component under test without assuming the acronym's intended definition.

## Red, amber, green

Track implementation, test execution, evidence environment, and acceptance separately. RED means a required invariant has an observed failure on the named target (or an explicitly labeled confirmed source defect). AMBER means specified, unimplemented, unexecuted, skipped, stale, incompatible revision, fixture-only relative to a service gate, or insufficient evidence. GREEN requires all named checks for that target/environment with reproducible artifacts. No averaging of colors; required red dominates, required amber prevents release, all required green is scoped acceptance only.

The initial baseline review identified REST expiry/context, delegated revocation, status propagation, incomplete signed binding, replacement atomicity and migration risks. Subsequent isolated source patches and consumer regressions address the demonstrated local paths; use the source manifest, patch artifacts and exact target reports to identify what was changed and executed. The original baseline findings are not a current claim that every listed defect remains open, and connected success does not close untested deployment or migration cases.

## Next dispatch order

1. Preserve source pins, patch provenance and the three scoped milestone reports; rerun after relevant source changes.
2. In parallel, complete the seven partial and eight unbound real-adapter BDD scenarios and design operational extensions for receipt retention, issuer rotation and backup/rollback recovery. Preserve the tested operation journal and exact historical-receipt boundary. Keep BDD-038 deferred.
3. Preregister the EDD baselines, held-out split, cost/latency/quality metrics, sample-size risk budget and stopping rules before claiming product value.
4. Have an independent operator reproduce the kit on another clean host, then test upgrade, backup/restore and failure recovery at the chosen deployment boundary.
5. Select and validate any OpenShift reference environment separately. Treat robotics simulation and hardware assurance as later, separate gates. Confirm the intended expansion of CUT.
