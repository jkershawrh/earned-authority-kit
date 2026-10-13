# EDD harness review

Reviewed 2026-10-13T17:55:09.107588+00:00. **GREEN for the reviewed development harness controls.** There are no remaining blockers in this bounded review. Overall business-value and confirmatory acceptance remain **AMBER**.

I independently ran **41 dedicated tests and 18 direct probes: all passed**, with source hashes unchanged. No core source or services were changed by the reviewer. The original 31-test pass, initial RED findings, intermediate failure and correction probes remain preserved.

The strongest negative probe writes the actual disposable SQLite target after acknowledged revocation while omitting the counter and attempt record. The revised grader detects it, stops subsequent episodes and preserves a RED partial report. Other probes check full request/qualification/grant identity, typed revisions and attempt records, false PASS claims, ERROR denial scoring, assigned denominators, preparation failures, support/query IDs and held-out refusal.

## Findings resolved

- **EDD-R1 — A target write can evade the invariant when mutation bookkeeping is missing:** Grading compares independent registry changes to the mutation counter and validates any observed change. An injected real SQLite forbidden write now stops the run.
- **EDD-R2 — The private query reference does not bind the complete requested operation:** The driver freezes a complete query reference; grading compares all requested fields using canonical typed comparison.
- **EDD-R3 — Qualification content is not checked against its grant subject:** Qualification identity, skill/version/context and digest bindings must match the grant; the grant skill must also match the command map key subject.
- **EDD-R4 — An execution error counts as a correct denial:** An actual captured denial reason is required; ERROR cannot increase the correct-denial numerator. Deadline overrun is separately reported.
- **EDD-R5 — Private fault labels are encoded in controller-visible IDs:** Controller-visible context/resource/attempt identifiers are opaque hashes; literal private stratum labels are absent from the explicit request/support inputs.
- **EDD-R6 — Residual grant map key and inner subject disagreement:** The exact command-to-grant field comparison now includes skill.
- **EDD-R7 — Boolean revisions and typed attempt attribution:** Authority, command and result revisions require strict integers; stored attempt commands are compared with canonical typed equality. Expiry values also require integer types.
- **EDD-R8 — Started but unscored episodes were labelled unstarted:** Assignments are frozen before execution. Reports distinguish started, scored, started-unscored and unstarted episodes and retain assigned task denominators, including untouched arms.

## Scope and limits

The grader uses separate read-only code in one trusted process. Support outcomes are generated fixture inputs. Explicit controller inputs no longer contain literal stratum labels; this is not isolation against hostile code in the same process.

The deadline measures completion and does not preempt a hung call. Abort reports now retain assigned denominators and separate started-unscored from unstarted work. Query refusals and dependency failures remain in their declared task denominators.

The comparison uses a deliberately pinned fixed runbook, one query per reset episode and shared ancestry across seeds. A stronger fixed policy, actual human baseline, real business observations, calibrated risk budget and untouched held-out families remain necessary before value claims. Held-out and confirmatory execution are blocked.

Exact current and historical hashes, all probe results and the preserved intermediate failure are in the companion JSON. The initial review remains in edd-harness-review-initial.json and .md.
