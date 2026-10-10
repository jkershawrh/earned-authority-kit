# Reference boundaries and remaining acceptance work

This kit demonstrates earned authority for a disposable model registry. It connects real canonical Passport, Foundation/PostgreSQL/OPA and Immutable Ledger services to pinned Cascade and deterministic GCL code. The target registry, independent readback connection, qualification history and local signed outbox use SQLite. This is a local reference implementation, not a production authorization system or a robot controller.

## What the observed runs establish

The recorded [connected lifecycle](../reports/connected-lifecycle.json) passed 23 checks and the [connected adversarial run](../reports/connected-adversarial.json) passed 17 checks. The [clean reconstruction report](../reports/clean-reference-combined.json) records a second workspace on the same host, including its own connected, adversarial and stop/restore evidence. Read each report's source hashes, environment and check list before reusing its result. A clean workspace is not an independently operated installation on a different machine.

These runs exercise qualification, signed grants, current authority checks, bounded execution, independent registry readback, selective withdrawal, requalification, receipt verification and the specific injected faults named in the reports. Component tests additionally exercise signer/persistence failure, canonical field binding and concurrent mutations. They do not imply every possible fault was tested. The 37 local fixture BDD scenarios are not asserted to have all run against real services. Hardware robotics remains deferred.

## Local registry durability and authority audit are different boundaries

For a registry attempt, the local transaction records its intent event, registry mutation, mutation count, committed result and commit event together. The executor rechecks current signed authority while holding the shared authority fence. A retry of the same committed attempt reconciles its result rather than applying a second registry mutation. Independent observation occurs after the transaction; a crash can therefore leave a committed attempt whose outcome is still unknown. The recovery path must preserve that distinction. Ledger delivery occurs from the durable local outbox after the local transaction and does not turn an unavailable receipt into a known business failure.

Passport issuance/revocation and local lifecycle-event persistence are separate commits. In `ConnectedRuntime.grant`, canonical issuance completes before the local `GRANTED` event is stored. In `revoke`, canonical replacement/revocation completes before the local `REVOKED` event is stored. A process crash or local persistence failure in that interval can leave a real authority transition without its corresponding local lifecycle event. A lost RPC response also requires reconciliation of the actual authority state before deciding what happened.

**This authority-to-audit crash gap was identified by source review. It has not been reproduced by terminating the running process at that boundary.** The registry transaction guarantee does not close it, and successful local outbox delivery cannot recover an event that was never stored. The reference does not provide one atomic transaction spanning Passport, SQLite and Ledger.

The durable withdrawal queue targets a particular grant and qualification. If an old queued withdrawal resumes after a new grant replaces its target, it records `WITHDRAWAL_RECONCILED` with `TARGET_NOT_CURRENT` rather than revoking the new grant. This prevents an obsolete withdrawal from retracting an independently requalified grant. It does not by itself reconstruct the missing original transition event or prove exactly-once authority audit history.

## Operating and trust assumptions

- Passport and the registry executor must share the **same operating-system advisory-lock domain**, the same fence file, and a filesystem with working `flock` semantics. On the validated macOS/Podman topology, Passport stays on the host with the executor; moving one into the Linux VM would break this assumption. All authority writers must acquire the fence before their service mutex. This is not a distributed lease or a multi-host revocation protocol.
- Host and container administrators, process configuration and installed trust roots remain trusted. Signatures do not prevent an administrator from replacing an issuer key, rolling back durable authority state, changing executable code, or bypassing the executor to write the registry directly. Anti-rollback anchoring, hardware key protection and hostile-operator resilience are separate work.
- OPA loads a frozen source and its binding data together. Its administrative network writes are denied, the mount is read-only, and file watching is disabled. Decisions carry the evaluated request and policy digest; the consumer pins that digest. The binding guarantee depends on that deployment discipline and trusted host administration.
- Host-facing HTTP and gRPC use loopback reference transport. Foundation uses a real local JWT/JWKS flow and gateway-to-BFF mTLS, but this does not establish secure remote access. Local key files and tokens, their rotation, backup, expiration and trust distribution are reference provisioning concerns, not a production secret-management design.
- Scope enforcement uses the earliest applicable signed scope, passport, embedded grant and qualification deadline. A parent passport may remain valid after an individual grant expires. Replacing an aggregate must not extend an unaffected grant's absolute bound; authority presence alone is insufficient to authorize it.
- Restart checks cover retained local process/container state and volumes. They do not establish recovery from disk loss, filesystem corruption, backup rollback, cross-host failover, every legacy database migration, or high availability.

## Qualification and evaluation claims

The connected demo explicitly selects a **three-pass qualification profile**. It overrides Cascade's candidate and nano sample thresholds to three, requires accuracy 1 and zero false positives/negatives, and uses authenticated independent outcomes. The pinned canonical defaults instead require 50 samples for candidate and 200 for nano, with different accuracy/error thresholds; higher tiers have further requirements. Passing the demo profile does not demonstrate statistical adequacy or qualify a production procedure under those defaults.

GCL checks a declared, context-bound deployment-capacity proposal deterministically. It does not independently discover all real-world constraints, attest the business outcome, or issue authority. Ledger receipts authenticate recorded assertions; they do not prove that the assertions are true.

**EDD means evaluation-driven development. The planned EDD comparison has not run.** Held-out datasets, risk budget, sample-size adequacy, preregistered benefit thresholds and comparisons with fixed or human-approved policies remain acceptance work in [the evaluation protocol](../evaluations/README.md). There is no measured customer-value, operator-effort, economic advantage, robotics-safety, Red Hat support or production-readiness claim.

## Follow-on authority recovery acceptance tests

The following are planned acceptance tests, not passed results:

1. Persist an authority-operation intent before invoking Passport. Bind its unique operation identity to the agent, exact target grant/qualification, expected active passport and revision, requested change and intended lifecycle event. Stop the process before the RPC, restart, and prove it does not invent a successful transition.
2. Terminate immediately after canonical issuance or revocation persists but before the local event transaction commits. After restart, reconcile the current signed authority and operation identity, recover the correct event or an explicit unresolved state, and prove neither duplicate authority changes nor fabricated outcomes occur. Repeat for selective replacement and an empty aggregate.
3. Lose the mutation response after canonical persistence. Test retries, two-field CAS conflicts, an intervening replacement and the empty-state ABA case. Recovery must distinguish the intended transition from a different actor's later transition without assuming that a current revision alone identifies the original operation.
4. Stop between canonical withdrawal and queue deletion, then install a separately requalified grant before recovery. Verify target-bound reconciliation, retained correlation history and no revocation of the new grant. Demonstrate the actual process-crash path in addition to the existing deterministic unit regression.
5. Inject local storage failure before intent persistence, before canonical invocation and after canonical success. New actions must fail closed where state is uncertain; recovery must distinguish a known authority transition from missing evidence. Verify the resulting events are delivered and independently checked when Ledger returns.
6. Exercise key/state backup restoration and revision rollback under a declared recovery policy. Either establish an external monotonic trust anchor or retain an explicit limitation; do not label a successful ordinary restart as rollback protection.

These follow-ons need frozen acceptance criteria and fault schedules before execution. Their results should identify source revisions, process boundaries and actual durable states, with unknown outcomes retained as unknown.

## Original source preservation

[The final preservation report](../evidence/source-preservation-final.json) rechecked the two original repositories assigned to this lane. Foundation's 241 recorded tracked-file hashes and Agent Passport's 24 match their baselines; HEAD, tracked inventories, Git status and working-diff hashes also match. Foundation's nine pre-existing modified tracked files remain as found. All implementation changes were made in isolated working copies and exported as patches.

Untracked and ignored file contents were excluded from the original snapshots and were not content-hashed. The unchanged Git status establishes the recorded untracked path inventory, not a content-integrity claim for those excluded files. This verification covers Foundation and Agent Passport only.
