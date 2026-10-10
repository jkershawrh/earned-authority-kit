# Acceptance evidence index

Reports are recorded runs, not live status. Source hashes, artifact bindings and the environment determine whether a previous run applies. `tools/report.py` checks these bindings, exact named live check sets and evidence age to produce `readiness.json` and the visual roadmap. Re-rendering does not execute tests or renew timestamps.

## Current engineering evidence

- `component-verification.json` and `kit-tests.log`: 321 tests, zero failures/errors/skips, collecting both pytest and unittest cases with unchanged source hashes. Per-module outcomes identify the relevant proof.
- `evidence-reference-combined.json`: fresh same-host reconstruction and validation completed with 123 checks across seven SHA-bound `evidence-reference-v2-*` child reports: policy 8, interfaces 7, lifecycle 23, fault/race 17, authority recovery 41, persistent restart 6 and historical operation evidence 21.
- `evidence-reference-v2-bootstrap.json` and `evidence-reference-v2-build-manifest.json`: five pinned canonical sources, verified patches, toolchain, builds and separate environment. No bit-identical-build or independent-human-installation claim.
- `evidence-reference-v2-authority-recovery.json`: actual process exits, lost committed RPC reply, local storage failure and signed operation reconciliation. `evidence-reference-v2-authority-recovery-restored.json` rechecks 20 prior operation receipts and preservation of prior events and Ledger receipts after full restart.
- `service-bdd-live-004.json`: 49 passing executed cases, zero failures and 2 unrun cases. Completely demonstrates 30 scenario IDs; six partial IDs and one unbound ID keep full acceptance AMBER. Every executed case asserts independent registry version, health and mutation count. Assertion and receipt counts describe observations within this run, not independent outcome trials.
- `bdd-environment-coverage.json`: exact per-scenario and outline-case pointers for fixture and service environments, remaining assertion gaps and current source bindings.
- `evidence-admission-unit.json`: 86 relevant cases extracted from the final component run: producer trust/binding/freshness, independent evidence versus self-report, intake recovery/deduplication, quarantine at publication and consumption, and actual wire producer contracts. Retained red logs include two audit races and the empty-evidence reason regression.
- `authority-journal-unit.json`: 31 relevant tests extracted from the final component run, including 17 journal cases. Unit qualifications now contain real signed observation references; focused development red/green logs remain separately labeled.
- `../evidence/foundation-policy-only-results.json`: 85 BFF and 37 gateway leaf cases in normal and race runs, plus 3 OPA engine cases. Actual policy responses declare no execution or receipt. `evidence-original-image-cutover.json` verifies the rebuilt service images were running before BDD.
- `../evidence/canonical-passport-operations-result.json`: 44 Go tests / 76 leaf cases, repeated with race detection; 24 Python Passport tests; exact patch replay, migration and original source preservation.
- `report-provenance-checks.json`: isolated altered-evidence checks ensure missing/stale/expired/shortened/duplicated reports, altered Foundation logs and arbitrary BDD IDs cannot pass the corresponding gate.
- `evidence-reference-cleanup.json`: owned service teardown and retained-state preservation after validation.

Normal and race-detector tests often exercise the same cases. Multiple successful service runs are repeats. Do not sum them into a unique-test or independent-trial count. This index is not an externally signed attestation.

## Historical evidence

Earlier reports, including `clean-reference-combined.json`, `operations-reference-combined.json`, the original connected runs, fixture reports and retained red logs, describe their recorded source snapshots. `service-bdd-live-001.json` and `service-bdd-live-002.json` have narrower assertion coverage. `service-bdd-live-003.json` retains 48 passing cases and one actual failure: an empty-evidence hold was mislabeled stale. Live004 passes the corrected behavior. The first evidence-reference run and its `evidence-reference-combined-pre-freeze2.json` aggregate are retained before that correction; the current aggregate points to the later v2 children. Historical artifacts explain regressions without overriding the current matrix.

## Acceptance still open

Full real-service execution of all 37 scenarios, preregistered held-out value evaluation, independent operator/host reproduction, backup/rollback protection, receipt-retention/key-rotation operations, OpenShift compatibility and robotics transfer remain open. The tested authority crash paths do not provide a distributed transaction or protection against privileged state rollback. See `../docs/BOUNDARIES.md` and `../evaluations/README.md`.
