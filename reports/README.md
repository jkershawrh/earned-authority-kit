# Acceptance evidence index

Reports are recorded runs, not live status. Source hashes, artifact bindings and the environment determine whether a previous run applies. `tools/report.py` checks these bindings, exact named live check sets and evidence age to produce `readiness.json` and the visual roadmap. Re-rendering does not execute tests or renew timestamps.

## Current engineering evidence

- `component-verification.json` and `kit-tests.log`: 235 tests, zero failures/errors/skips, collecting both pytest and unittest cases with unchanged source hashes. Per-module outcomes identify the relevant proof.
- `operations-reference-combined.json`: fresh same-host reconstruction and validation completed with 123 checks across seven SHA-bound child reports: policy 8, interfaces 7, lifecycle 23, fault/race 17, authority recovery 41, persistent restart 6 and historical operation evidence 21.
- `operations-reference-bootstrap.json` and `operations-reference-build-manifest.json`: five pinned canonical sources, verified patches, toolchain, builds and separate environment. No bit-identical-build or independent-human-installation claim.
- `operations-reference-authority-recovery.json`: actual process exits, lost committed RPC reply, local storage failure and signed operation reconciliation. `operations-reference-authority-recovery-restored.json` rechecks 20 prior operation receipts and preservation of prior events and Ledger receipts after full restart.
- `service-bdd-live-002.json`: 39 passing executed cases, zero failures and 12 unrun cases. Completely demonstrates 22 scenario IDs; seven partial and eight unbound IDs keep full acceptance AMBER. Every executed case asserts independent registry version, health and mutation count. Its 825 assertions include setup/receipt checks; 358 verified canonical event receipts are records, not independent outcome trials.
- `bdd-environment-coverage.json`: exact per-scenario and outline-case pointers for fixture and service environments, remaining assertion gaps and current source bindings.
- `authority-journal-unit.json`: 31 relevant tests extracted from the final component run, including 17 journal cases; focused development red/green logs retained separately.
- `../evidence/canonical-passport-operations-result.json`: 44 Go tests / 76 leaf cases, repeated with race detection; 24 Python Passport tests; exact patch replay, migration and original source preservation.
- `report-provenance-checks.json`: isolated altered-evidence checks ensure missing/stale/expired/shortened/duplicated reports and arbitrary BDD IDs cannot pass the corresponding gate.
- `operations-reference-cleanup.json`: owned service teardown and retained-state preservation after validation.

Normal and race-detector tests often exercise the same cases. Multiple successful service runs are repeats. Do not sum them into a unique-test or independent-trial count. This index is not an externally signed attestation.

## Historical evidence

Earlier reports, including `clean-reference-combined.json`, the original `connected-lifecycle.json` and `connected-adversarial.json`, fixture red/green reports and retained red logs, describe their recorded source snapshots. `service-bdd-live-001.json` recorded correct postconditions but omitted some explicit assertions; the strengthened live002 run supplies current certification. Historical artifacts explain regressions and corrections without overriding the current matrix.

## Acceptance still open

Full real-service execution of all 37 scenarios, preregistered held-out value evaluation, independent operator/host reproduction, backup/rollback protection, receipt-retention/key-rotation operations, OpenShift compatibility and robotics transfer remain open. The tested authority crash paths do not provide a distributed transaction or protection against privileged state rollback. See `../docs/BOUNDARIES.md` and `../evaluations/README.md`.
