# Acceptance evidence index

Reports are recorded runs, not live status. Source hashes, artifact bindings and the environment determine whether a previous run applies. `tools/report.py` checks these bindings, exact named live check sets and evidence age to produce `readiness.json` and the visual roadmap. Re-rendering does not execute tests or renew timestamps.

## Current engineering evidence

- `component-verification.json` and `kit-tests.log`: 369 tests, zero failures/errors/skips, collecting pytest and unittest cases with unchanged source hashes. Per-module outcomes identify the relevant proof.
- `boundary-reference-combined.json`: fresh same-host reconstruction and validation with 123 checks across seven SHA-bound children: policy 8, interfaces 7, lifecycle 23, fault/race 17, authority recovery 41, persistent restart 6 and historical operation evidence 21.
- `boundary-reference-bootstrap.json` and `boundary-reference-build-manifest.json`: five pinned canonical sources, verified patches, builds and separate environment. `boundary-reference-images.json` verifies fresh running images; `boundary-original-image-verification.json` checks the original BDD stack. No bit-identical-build or independent-operator claim.
- `boundary-reference-authority-recovery.json`: actual process exits, lost committed RPC reply, local storage failure and signed operation reconciliation. `boundary-reference-authority-recovery-restored.json` rechecks 20 prior operation receipts and preservation of events and Ledger receipts after full restart.
- `service-bdd-live-006.json`: 52 executed cases pass, with no failures, blocked or unrun cases. It fully demonstrates 33 scenario IDs; BDD-009, 015, 016 and 031 remain partial because named assertions are still absent. Implemented cases passing does not complete those scenarios.
- `bdd-environment-coverage.json`: per-scenario and outline-case pointers, explicit gaps and source bindings. BDD-021 includes an additional actual post-commit outcome-persistence fault. BDD-033 verifies actual SQLite failure and signing-key rejection; BDD-025 checks exact current-revision hold reasons.
- `execution-boundary-unit.json`: 48 cases from the final component run: 11 mutation/retry negatives, 10 hold-diagnosis checks and 27 transient-response contract cases. Red logs preserve the pre-mutation signature gap, post-commit authentication classification and missing-database creation regressions.
- `evidence-admission-unit.json`: 86 evidence cases from the current component run; prior focused red/green logs remain historical. `authority-journal-unit.json` extracts 31 current journal/security/binding cases.
- `../evidence/reconciliation-wire-results.json`: actual local UNKNOWN response producers, strict rejection cases, no fabricated proof/receipt, and recovery of the original durable attempt.
- `../evidence/foundation-policy-only-results.json`: 85 BFF and 37 gateway leaf cases in normal and race runs, plus 3 OPA cases. The canonical patch is unchanged in this increment. `../evidence/canonical-passport-operations-result.json` retains the unchanged Passport component evidence.
- `report-provenance-checks.json`: isolated controls for missing/stale/expired/shortened/duplicated reports, altered Foundation logs and arbitrary BDD IDs.
- `boundary-reference-cleanup.json`: owned service teardown and retained-state preservation after validation.

Normal and race-detector tests often exercise the same cases. Multiple successful service runs are repeats. Do not sum them into a unique-test or independent-trial count. This index is not an externally signed attestation.

## Historical evidence

Earlier reports, including the clean, operations and evidence reference runs, fixture reports and retained red logs, describe their recorded snapshots. Service BDD runs 001/002 have narrower coverage. Live003 retains the empty-evidence reason defect fixed before live004. Live005 retains 49 passes and three failed storage-fault precondition assertions; retained SQLite connections prevented the intended permission fault. Live006 fixes the test setup, requires the actual SQLite failure, restores owned database/sidecar modes and passes the target behavior. Runtime source did not change between live005 and live006. Historical artifacts explain corrections without overriding the current matrix.

## Acceptance still open

Full real-service execution of all 37 scenarios, preregistered held-out value evaluation, independent operator/host reproduction, backup/rollback protection, receipt-retention/key-rotation operations, OpenShift compatibility and robotics transfer remain open. The tested authority crash paths do not provide a distributed transaction or protection against privileged state rollback. See `../docs/BOUNDARIES.md` and `../evaluations/README.md`.
