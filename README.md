# Earned Authority — validated local reference kit

This kit connects a deterministic procedure's qualification to bounded authority, enforced mutation, independent readback, selective withdrawal and requalification. It uses ARE Foundation, Agent Passport, ARE Immutable Ledger, Cascade Compression and deterministic GCL. Foundation keeps its S0/S1 role; higher-stage qualification lives in the integration layer.

**Three bounded engineering milestones have executable evidence:** a local fixture; connected canonical services; and a fresh same-host reference installation with persistent restart. The latest component run passes **321 tests**, and the fresh-reference deployment passes **123 checks**. The dedicated service behavior run passes 49 executed cases and completes **30 of 37 scenarios**; six scenarios remain partial and one unbound. These counts describe different suites and are not statistical trials. The full roadmap remains **AMBER**: business value has not been evaluated, complete real-service coverage is not established, and broader deployment/recovery gates remain open.

Start with [the visual roadmap](roadmap.html), [the parallel work plan](docs/ROADMAP.md), [deployment instructions](deploy/reference/README.md) and [scope and remaining gaps](docs/BOUNDARIES.md). **EDD means evaluation-driven development.** The [evaluation protocol](evaluations/README.md) is drafted but unexecuted; it needs a chosen value target, actual human baseline and preregistered sample/risk criteria.

## Reproduce the reference

Prerequisites, dependency versions, topology and teardown instructions are in [the deployment runbook](deploy/reference/README.md). From this kit directory:

```sh
python3 deploy/reference/bootstrap.py --workspace /absolute/path/to/new-reference-workspace --instance ea-reference --port-offset 2000 --validate
```

This reconstructs pinned upstream sources with the supplied explicit patches, creates private keys/configuration outside the kit, builds actual services and validates lifecycle, faults and full stop/restore. Choose unused ports and a unique instance name. The validated profile runs Passport and the registry executor on the **same host operating system** so they share the mutation/revocation lock. It is a local model-registry reference, not an OpenShift or robotics deployment.

For component checks, use Python 3.12 with the pinned development dependencies in an isolated environment. The canonical qualification tests also require the pinned Cascade and GCL sources; the bootstrap creates these. Then run:

```sh
python tools/verify.py
python tools/report.py
```

`verify.py` collects both unittest and pytest tests, including the Ledger adapter, and records per-module outcomes and before/after source hashes. `report.py` reads existing evidence and verifies its source/artifact bindings; it does not rerun services. Stale evidence becomes amber. Neither command performs held-out business-value evaluation.

## What was validated

- **M1 — local fixture:** BDD-001–037 bindings, draft schemas, producer/consumer proofs, qualification history, durable registry mutation and readback recovery.
- **M2 — connected services:** 23 lifecycle checks and 17 fault/race checks, plus policy/interface checks and a separate authority-operation recovery schedule. Actual canonical Cascade qualifies and demotes; deterministic GCL checks capacity constraints. Neither substitutes for independently observed outcomes or grants permission.
- **M3 — reference packaging:** five freshly fetched source pins, verified patches, separate state/keys/volumes, and a documented single-command validation. Full stop/restore preserves prior identity, authority revision/scopes, registry mutations and ledger receipts. Historical authority-operation evidence is rechecked separately after restart.

The demonstration uses an explicit **three-pass qualification profile**. Upstream defaults remain unchanged. Passing this profile establishes the tested behavior, not statistical confidence or product readiness.

Authority updates now persist a signed local intent before dispatch. Canonical Passport atomically stores the transition and its signed operation receipt; reconciliation uses that exact receipt to recover the lifecycle event without repeating the transition. An uncertain dispatched operation blocks further local action until resolved. Historical receipts never supply current permission. This closes the tested process-crash paths while retaining separate service commits and explicit same-host trust assumptions; see [the boundary review](docs/BOUNDARIES.md).

Independent evidence now has a receipt-backed admission path. Procedure self-reports stay separate, trusted outcome producers are pinned, and every imported record is bound to its attempt, procedure revision, context and validity window. Auditing can quarantine corrupted evidence and withdraw the affected grant. Publication, grant and execution checks prevent reuse through an older eligible qualification. Remote Ledger unavailability remains distinct from an observed task failure.

## Layout and evidence

- `earned_authority/`: fixture and connected runtimes, canonical service adapters, signed proof mapping and conservative readiness assessment.
- `contracts/`: version `0.1.0-draft.1` schemas, canonical byte vectors, synthetic examples and actual producer fixtures.
- `features/`: 38 behavior specifications; 001–037 have local bindings, 038 is deferred robotics simulation. Connected coverage is separately mapped.
- `evaluations/`: evaluation-driven development protocol, comparators, metrics and stopping rules; no measured business-value results.
- `deploy/`: pinned sources, dependency locks, local service profiles and repeatable validation/recovery commands.
- `patches/` and `evidence/`: reviewable Passport/Foundation patches and retained red/green evidence. Original tracked user source was preserved.
- `reports/`: [321-test component run](reports/component-verification.json), [fresh-reference run](reports/evidence-reference-combined.json), [service behavior run](reports/service-bdd-live-004.json), [environment coverage](reports/bdd-environment-coverage.json) and [readiness matrix](reports/readiness.json).

## Color rules

**RED:** a demonstrated required failure on the named target, or an explicitly historical failing baseline. **AMBER:** missing, unexecuted, stale, partial, incompatible or insufficient evidence. **GREEN:** all checks declared for that exact scope passed with recorded evidence. A correct refusal passes its denial test. A successful local demonstration does not pass a value, independent-operator, distributed-system or hardware-safety gate.

TDD is test-driven, CDD contract-driven, BDD behavior-driven, and EDD evaluation-driven development. Evidence collection supports all four. CUT's expansion remains unconfirmed; the roadmap names each component under test without assuming the intended expansion.
