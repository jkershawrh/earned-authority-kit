# Evaluation-driven development protocol

This directory defines how to test whether earned authority is useful for a bounded task. The protocol is a draft, has not been preregistered, and has not been executed. All measurements are absent. Overall evaluation readiness and sample-size adequacy are **AMBER**.

The machine-readable source is [protocol.json](protocol.json). Its first task is a disposable model registry: a deterministic procedure changes an alias to an exact model digest under current, scoped authority. A separate observation interface checks the resulting registry state and unrelated resources.

The test asks whether adaptive qualification improves task completion or reduces operator work relative to existing ways of operating the same bounded resource. Passing contract fixtures or a lifecycle demonstration alone cannot answer that question.

## Three comparisons

1. **Manual:** an actual operator follows [the operator runbook](manual/operator-runbook.md) at `tools/episode_console.py`. Record active handling time and interventions. An oracle script is not a manual baseline. The runbook, the development-split console, the independent grader and the family manifest exist; the evaluation remains unpreregistered and unexecuted. No episode has been timed.
2. **Fixed deterministic:** a frozen procedure and grant/withdrawal runbook operate without learning from accumulated evaluation outcomes.
3. **Adaptive qualification:** a frozen controller uses permitted support observations to qualify an exact procedure/context, request policy-approved grants, withdraw affected authority, and requalify it.

All three use the same authority, policy, scope, revocation, and mutation enforcement. Task inputs, fault schedules, deadlines, retry budgets, and starting states are paired. This keeps a comparison of workflow value from becoming a comparison against a deliberately unsafe baseline.

An LLM-assisted arm is optional and disabled in the initial protocol. If introduced, preregister its model, prompts, sampling, allowed context, tools, and accounting. It receives the same enforcement boundary. No LLM calls are required for the first bounded task.

## Holdout and leakage rules

Partition **procedure-version families and context families** into development, calibration, and held-out sets before generating examples. Related versions and near-duplicate fixtures remain together; giving a copied fixture a new digest does not make it independent.

Use development for implementation, calibration for selecting thresholds, and held-out data for frozen comparisons. Freeze source, policy, checker, generator, manifest, fault schedule, seeds, budgets, and acceptance criteria before looking at held-out results. A post-inspection change requires a new protocol version and an untouched holdout for confirmatory claims.

Held-out adaptive episodes have explicit support and query phases. All comparators receive the same permitted support observations. The controller can qualify from those observations, then performs disjoint scored query attempts. Query grading labels and outcomes do not enter its state before that episode is sealed. A later sequential adaptation experiment can alternate support and query phases under a preregistered schedule.

Reference labels come from registry preconditions, authoritative readback, and a separately reviewed reference evaluator. The controller cannot grade its own eligibility decision. Ambiguous or missing observations remain `UNKNOWN`; sufficient evidence is required before a new grant. `HOLD` is distinct from a demonstrated failure.

## What will be measured

- **Unauthorized mutation:** count every committed change that violates a required binding, policy, scope, expiry, or current authority revision. Report all attempted and committed mutations and each fault stratum. The hard gate is zero observed violations in tested cases.
- **Promotion false acceptance:** incorrectly eligible decisions divided by all independently labelled ineligible candidates. Also report incorrect decisions divided by all eligible decisions, erroneous actual grants, and the separate unknown-label count.
- **False demotion:** erroneous withdrawals for asserted skill failure at predefined checkpoints where the reference confirms continuing eligibility and fresh evidence. Report conservative holds and avoidable loss of availability separately; a correct withdrawal due to missing evidence or context change is not a false demotion.
- **Held-out task success:** independently verified, on-time completions divided by all legitimate assigned requests. Include refusals, timeouts, unknowns, and dependency failures in the denominator. Score required denials separately so refusing every request cannot look successful.
- **LLM escalation:** requests causing one or more LLM calls divided by all assigned requests, with total calls and available token counts. Until instrumented execution occurs, the measured value is absent even for arms designed to make no LLM calls.
- **Latency:** p50 and p95 for enforcement decisions, independently verified task completion, and revocation acknowledgement. Use monotonic clocks and nearest-rank quantiles; publish the count and request categories. Report timeouts, missing instrumentation, and cold-start results explicitly rather than silently dropping them.
- **Operator effort:** actual handling minutes and intervention count per assigned task and per verified successful task.

The JSON gives each metric's numerator, denominator, unit, and limitations. No thresholds or measured results have been fabricated.

## Confidence and sample size

Zero observed unauthorized mutations is a required local invariant, not proof that no unauthorized mutation is possible. When independent Bernoulli assumptions hold and zero events occur in `n` trials, a proposed one-sided 95% exact upper confidence bound is `1 - 0.05^(1/n)`. With no observations there is no estimate. Attempts inside an episode can be correlated: use independent episode/family units or an appropriate clustered uncertainty method rather than pretending every retry is independent.

The ten proposed seed values provide reproducible pilot runs. They are not a statistical sample-size justification. A risk budget, minimum meaningful effect, independent family counts, tail-latency precision target, and confirmatory sample counts remain unset. Therefore sample-size adequacy remains **AMBER**.

Before confirmatory runs, select acceptable false-acceptance and false-demotion limits, task-success improvement or noninferiority margin, and effort/latency tradeoffs. Freeze the analysis and stopping rule. Do not stop after a favorable result or repeatedly add samples until it appears significant.

## Faults and negative controls

The planned suite injects revocation races; stale or altered contexts; passport, policy, checker, and ledger outages; forged or replayed evidence; failed or concurrent authority replacement; and revocation after caches are warm.

The first executor must enforce revision fencing inside its atomic mutation boundary. A check immediately before an ordinary tool call is insufficient for the stated race guarantee. After revocation acknowledgement, an old-revision mutation cannot commit. A mutation committed before withdrawal is not retroactively undone.

Missing authority or policy prevents mutation. Missing outcome evidence yields `UNKNOWN` and prevents a new grant. Ledger unavailability records pending evidence and must not delay withdrawal. An accepted ledger hash proves integrity of the stored assertion, not that its source told the truth.

Useful ablations compare adaptive requalification with none, selective demotion with whole-agent withdrawal, and eventually receipt reuse with rechecking. A deliberately defective admission rule belongs only in an isolated, mutation-disabled negative control. It must not become a deployed comparator.

## Stopping and reporting

An unauthorized commit stops mutation execution and turns that gate **RED**. Preserve the full trace and the failing version. A successful retry does not erase it. Leakage, corrupted grading, or missing critical instrumentation invalidates confirmatory scoring and must be reported. Episode deadlines and attempt budgets are fixed in advance; interrupted or failed episodes remain visible.

Every result records separate dimensions: execution state, environment, observation state, integrity state, outcome, and acceptance color. A score and a receipt are different evidence properties. An independently observed failure is still valid evidence of a failure. A correct refusal can be a passed safety scenario while contributing no task completion.

**RED** means a required behavior demonstrably fails or evidence is misrepresented. **AMBER** includes unrun work, insufficient evidence, unresolved acceptance thresholds, and inadequate sampling. **GREEN** applies only to a named gate that passed its declared criteria in its declared environment. A green fixture check or local simulator result does not establish production readiness or customer value.

Before running the pilot, complete the manifest and leakage review, implement independent grading and metric instrumentation, and select the risk and sampling assumptions. **No EDD evaluation was run in this increment.**

## Executable development pilot

[PILOT.md](PILOT.md) documents the separate development harness and reports/edd-pilot-007.json. It runs 300 fixture episodes with independent persisted-state grading and three declared automatic policies. The current 114 dedicated harness tests are separate from the 514-test baseline. The human baseline, confirmatory protocol, risk budget, held-out split and business-value evaluation remain unexecuted/AMBER. The machine-readable draft above is not relabelled as completed by this pilot.

[SEQUENTIAL.md](SEQUENTIAL.md) records 20 retained-state sequences and 140 graded queries. Both deterministic arms share the same observations and retention rules. Lifecycle engineering passes; adaptive business value remains unproven.

The [context-conditioned selection development comparison](ROUTING.md) adds a pooled-outcome baseline that also updates from retained outcomes. The current independent review passes 114 tests and 42 probes. Earlier single-query and sequential reports retain their original scoped source snapshots. Business and confirmatory acceptance remain AMBER.

## Manual comparator leg (adopted, NOT_EXECUTED)

The manual comparator's implementable tooling now exists under [manual/](manual/): an episode console with the runbook's timed actions (evidence, qualify, grant, release, read, withdraw, lookup, intervene, stop), the [operator runbook](manual/operator-runbook.md) a timed human follows, the [family manifest](manual/manual-pilot-plan.json) with split bindings and held-out rejection, and three development practice episodes as `*.task.json` with private `.labels.json` / `.prepare.json` sidecars that keep grade labels out of the operator's path. This is the missing prerequisite the confirmatory readiness gate `actual_human_baseline_plan` names. It stays **NOT_EXECUTED** until an operator is actually timed; the first timed run will be new evidence under the protocol's amendment rules, never a retroactive claim. A scripted walkthrough of the console is practice, not a manual baseline.

## Evaluation cards (G-07)

"Card" unambiguously means the ecosystem qualification artifact (`fabric.evaluation-card/v1`). The harness's task payloads are `*.task.json`, not cards. Every completed development run — pilot, sequential, routing — emits a self-hashing `evaluation-card/v1` result record next to its report (`<report-stem>.card.json`), binding the frozen plan and measured report by digest, using OFFLINE evidence labels (fixture episodes are deterministic local computation, never LIVE), Wilson 95% intervals on the recorded rates, `reliability_claimable: false` at one trial per case, and `verdict.authorizes_execution: false`. Construct sidecars are authored under [constructs/](constructs/) before runs and bound by digest. Validate cards through the eval-cards platform before notarizing; a receipt proves recording, never truth, and never authorizes anything.
