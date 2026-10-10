# Acceptance evidence index

Reports are recorded runs, not live status. Source hashes and the environment determine whether a previous run applies. `tools/report.py` checks current source/artifact bindings and produces `readiness.json` and the visual roadmap. Re-rendering does not execute tests or renew their timestamps.

## Current engineering evidence

- `component-verification.json` and `kit-tests.log`: 203 tests, zero failures/errors/skips, collecting both pytest and unittest cases. Per-module outcomes identify the relevant proof; a global pass is not substituted for an unrelated method or environment.
- `clean-reference-combined.json`: the documented bootstrap/validation command completed successfully against freshly reconstructed canonical sources and separate state on the same host. Its five child reports record 8 policy, 7 interface, 23 lifecycle, 17 fault/race and 6 restart checks.
- `clean-reference-bootstrap.json` and `clean-reference-build-manifest.json`: source, patch, toolchain, build and fresh-environment provenance. Reconstruction is not a claim of bit-identical builds or an independent human installation.
- `wire-contracts-report.json`: 60 schema and actual producer/consumer proof checks. Canonical service mapping is separately exercised in the connected run.
- `qualification-client-report.json`: actual canonical Cascade and isolated deterministic GCL checks. The explicit demo-three-pass policy is not a sample-size justification.
- `bdd-environment-coverage.json`: separate fixture and real-service mapping. Partial connected check matches do not certify an entire BDD scenario.
- `../evidence/source-preservation-final.json`: original tracked Foundation and Passport checkout preservation. Untracked/ignored contents were not claimed verified.

Normal and race-detector tests often exercise the same cases. Multiple successful service runs are repeats. Do not sum them into a unique-test or independent-trial count.

## Historical evidence

Other report files, including `m1-bdd-report.json`, early `connected-*-run.json`, earlier interface/build reports and retained red logs, are development history. Their source snapshots can differ from the final kit. They are retained to explain regressions and corrections; their colors do not override the current matrix. `connected-lifecycle.json` and `connected-adversarial.json` record the original service stack; the final clean-reference combined reports are the packaging acceptance reference.

## Acceptance still open

The three engineering milestones cover a bounded local reference. Full real-service execution of all 37 BDD scenarios, complete authority-update audit recovery across process crashes, preregistered held-out value evaluation, independent operator/host reproduction, OpenShift compatibility and robotics transfer are not certified by these files. See `../docs/BOUNDARIES.md` and `../evaluations/README.md`.
