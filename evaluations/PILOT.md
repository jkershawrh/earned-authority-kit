# Development EDD pilot

The pilot runs the existing durable SQLite Runtime with fixture Passport and Ledger ownership. It is executable engineering evidence for the evaluation harness, not a held-out evaluation or a canonical-service performance result. The confirmatory protocol in protocol.json remains draft and unexecuted.

## Reproduce

From the kit root, with its Python dependencies installed:

```sh
python tools/verify_edd.py
python tools/run_edd_pilot.py --workspace /absolute/path/to/new-pilot-state --report /absolute/path/to/new-pilot-report.json
```

Both paths must be new. The runner refuses to reuse an episode workspace or overwrite a report. Raw SQLite state contains fixture signing keys and belongs outside the kit/package. The delivered report contains read-only snapshots, public signatures and references, not private keys.

pilot-plan-v2.json fixes ten development strata, ten seeds, three automatic comparators, a 30-second query scoring deadline and zero query retries before execution. The frozen plan and source fingerprints are recorded in the private workspace before the first episode and checked again after the run. Each arm uses a fresh registry, authority, qualification and ledger. Comparator order is deterministically shuffled per seed. A committed forbidden mutation or an integrity mismatch stops further mutation episodes and preserves the partial RED report.

## Declared comparator roles

The primary fixed baseline is now a general frozen deterministic rule: ingest the same fresh support, qualify the requested exact procedure/context, request the same scoped authority, and execute under the same enforcement. Adaptive qualification uses the same exact rule for this single-query experiment. Neither updates a learned policy from earlier episodes, and the workload cannot distinguish an advantage from accumulated outcomes.

The old pinned baseline is retained under the explicit name pinned_runbook as a diagnostic third arm. It can request only its original exact version/context and therefore cannot complete the new-version/new-context tasks. The previous fixed_deterministic label in pilots001–003 referred to that pinned policy. Current plan v2 names a stronger general fixed policy; the old plan is rejected rather than silently executing under new semantics.

The stronger comparator removes the earlier engineered advantage. Matching fixed/adaptive results are useful evidence of a workload limitation, not proof that either approach is universally equivalent. A sequential support/query design and meaningful independent workload variation are still needed to evaluate accumulated-outcome value.

The human comparator is NOT EXECUTED. A script is never labelled manual, operator minutes/interventions remain null, and no human-effort benefit is claimed. LLM calls and costs also remain null: the deterministic path has no LLM integration, but this harness does not instrument an external-call boundary and cannot report measured zero calls.

## Support, query and independent grading

The driver generates labelled development fixtures. Only requests and public support observations reach controller.prepare; reference labels and fault strata are not arguments to the controller. The controller does not receive the separate query grade or private stratum labels (identifiers are opaque). Runtime applies the query outcome for its shared withdrawal rule; each episode ends afterward, so that outcome cannot inform another scored query. There is one disjoint query after support per episode. This first pilot does not establish sequential learning or recovery/requalification value.

The grader uses a separate read-only database connection and separate grading code. It authenticates the fixture authority with the episode's pinned public key, reads the actual commit/attempt row, compares exact current permission and qualification bindings at the mutation boundary, reads the actual registry target and health, and checks an unrelated sentinel. A procedure PASS claim cannot supply a missing mutation or conceal a revoked/expired binding. The grader also compares actual registry changes independently of the mutation counter, validates the complete immutable query and qualification subject, and rejects boolean/integer aliases in authority revisions and typed context bindings. Postcondition failure is distinct from an unauthorized mutation.

This is independent code/readback within one trusted host process. It is not a different operator, process isolation, security principal or external truth source. Shadow support outcomes are controlled fixture inputs, not real business observations. Caller-provided reference labels are not production evidence.

## Recorded pilot 004

reports/edd-pilot-004.json records 300 completed development episodes: 100 per arm across ten strata and ten seeds. Each of the three arms had 70 legitimate task requests and 50 requests requiring denial (these sets overlap for missing support evidence and authority outages). Adaptive qualification and the general fixed baseline each completed 40/70 legitimate tasks. The legacy pinned diagnostic completed 20/70. All three correctly denied 50/50 requests requiring denial, with zero observed unauthorized commits. Each arm had ten deliberately wrong-postcondition failures. The stronger fixed and adaptive rules tie on this single-query workload; the pinned gap does not measure customer value.

The report retains every assigned legitimate request, including missing evidence and dependency outages, in its task-success denominator. Required denial is a separate overlapping category: a safe denial may still leave a legitimate task incomplete. All assignments are recorded before execution; aborted runs retain unstarted and started-but-unscored counts and the original assigned denominator. It reports preparation separately from query admission-decision/completion latency, groups terminal-state timing, and uses nearest-rank p50/p95 with observation counts. Query scoring deadlines include terminal independent grading but exclude support preparation; they are scoring deadlines, not preemptive cancellation guarantees. Revocation is injected after admission and timed through acknowledgement before the attempted commit. Expiry advances a controlled logical clock; elapsed timings use the host monotonic clock.

All seeds share one procedure ancestry and one context ancestry. Nominally different targets and shuffled run order do not create 300 independent samples. No confidence interval, reliability bound or sample-size adequacy claim is made. Engineering acceptance is GREEN for the recorded development execution; held-out value acceptance remains AMBER.

## Tests and remaining gates

The dedicated harness suite has 50 tests, separate from the unchanged 514-test component baseline. Genuine RED grader regressions are retained in evidence/edd-grader-red.log; the corrected run and source-bound verification are in evidence/edd-harness-green.log and evidence/edd-harness-verification.json. Tests cover authoritative grading, malformed/expired/revoked bindings, wrong targets, unrelated side effects, hard stopping, preserved denominators, forbidden held-out execution and ancestry leakage.

The CLI rejects held-out and confirmatory modes. It cannot silently promote this pilot into a final evaluation. To proceed: choose the primary business outcome and meaningful effect; retain the general fixed comparator and assign an actual human baseline; create genuinely separate calibration/held-out families and a leakage review; freeze thresholds, risk budgets, sample counts and stopping rules; add real human effort and cost/LLM instrumentation where relevant; then implement the confirmatory adapter and independently review it before scoring. Preserve this development history and use untouched held-out cases.

## Preserved corrections

Pilot001 is historical development evidence from before independent review. Its weaker grader missed counter-free writes and some request/qualification binding mismatches; its legitimate denominator incorrectly excluded missing-evidence and dependency-outage tasks. Pilot002 reran the first corrections but predates the final skill/revision-type and abort-phase fixes. Neither is current acceptance evidence. Original red grader tests, review regression logs and independent probe records are retained; Pilot003 re-executed all 200 episodes after those grader corrections. Pilot004 reruns 300 episodes with the general fixed comparator; pilots001–003 are now historical comparator/source snapshots. The current report does not erase earlier failures or relabel their source snapshots.

The measured decision interval covers admission; the mutation-fence check occurs inside the completion interval and is not separately instrumented. The source-bound aggregate is ../reports/edd-development-acceptance.json, with final independent review in ../evidence/edd-harness-review.json.

## Confirmatory prerequisite diagnostics

confirmatory-design.json is an explicit proposal with unset business thresholds, risk/sample decisions, family partitions and operator. tools/check_edd_readiness.py records named blockers in ../reports/edd-confirmatory-readiness-001.json. It checks declared field shapes and ancestry; it does not verify external reviewer credentials, empirical sample adequacy or dataset independence. Even an all-filled local proposal cannot authorize execution: the reviewed confirmatory adapter is absent and always blocks. HUMAN_BASELINE.md gives a real-operator runbook proposal without claiming measured human work. No held-out cases were created by renaming inspected pilot fixtures.
