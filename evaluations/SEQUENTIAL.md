# Retained-outcome development sequence

The frozen [sequential-plan.json](sequential-plan.json) exercises one real SQLite Runtime across seven phases per arm. [edd-sequential-004.json](../reports/edd-sequential-004.json) records 20 completed sequences (003 is the prior scoped snapshot; the reconciled tree re-earned the identical results) and 140 independently graded queries, with ten seeds and two automatic arms. Each arm completed 30/70 legitimate requests and correctly denied 30/30 policy-blocked requests. Zero unauthorized commits were observed. Ten deliberately wrong-postcondition commits per arm failed task grading and triggered withdrawal.

The fixed and adaptive arms intentionally use the same deterministic qualification rules and retain the same grants and public outcomes. They reuse authority after success, respond to the same withdrawal, and receive identical fresh support. There is no learned policy update, tuning between phases or engineered fixed-baseline handicap. Equal results demonstrate lifecycle mechanics on this fixture; they cannot establish an adaptive advantage.

## Frozen phases

1. Three independent passing shadow observations qualify the exact procedure/context/resource; the first query succeeds.
2. A second query reuses the exact qualification and live grant, with current authority checked again at admission and commit.
3. A deliberately wrong registry postcondition produces a retained FAIL, demotes qualification and acknowledges withdrawal.
4. The next legitimate request is denied under the withdrawn authority.
5. Three new passing shadow observations are added. Qualification remains INELIGIBLE because the failure is still fresh, and the request remains denied.
6. The controlled clock advances by the full evidence window. Existing observations remain in the database but are stale; without fresh support, qualification is HOLD and execution is denied.
7. Three fresh passing observations permit requalification and a successful recovery query. Historical failure evidence remains intact.

Every query is sealed before preparation for the next phase. The controller receives public requests and support observations, while the shared Runtime retains its own independently checked outcomes. Private grading references and query grades are never passed to the controller. Sealing is recorded ordering inside a trusted process, not cryptographic isolation between principals.

The independent grader reads the persisted state through a separate read-only connection, authenticates the current authority, checks immutable request/grant/qualification bindings at commit, verifies the actual mutation and target, and checks the unrelated sentinel. FAIL task outcomes are distinct from unauthorized commits. The sequence stops on unauthorized mutation, integrity errors or a critical execution error.

All 140 assignments are declared before execution. Each of the seven requests is legitimate, including the three safely denied during withdrawal/recovery. Those requests remain in the completion denominator. On a crash or hard stop, unstarted and started-unscored queries remain represented. The inherited summary calls queries “episodes”; `expected_sequences` and `counts.scored_queries` distinguish them explicitly in this report.

## Reproduce

From the kit root, use an environment with requirements-dev.txt installed and fresh absent paths:

```sh
python tools/run_edd_sequential.py --workspace /tmp/ea-sequence-new --report /tmp/ea-sequence-new.json
python tools/verify_edd.py
```

The CLI supports only the frozen development plan. It rejects held-out/confirmatory modes, changed phases, reused paths, boolean/duplicate seeds and retry changes. Source and plan hashes are frozen before execution and checked afterward. Reports cannot overwrite prior evidence.

## Scope

The sequential acceptance snapshot contained 70 tests, including eighteen sequence controls and two new boundary controls in the original pilot. The current dedicated suite has 119 tests, separate from the reconciled 522-test component baseline. [edd-sequential-red.log](../evidence/edd-sequential-red.log) records the absent implementation before creation; [edd-sequential-green.log](../evidence/edd-sequential-green.log) records the eighteen implemented sequence controls. The before-routing verification and review preserve that acceptance snapshot. Current verification and review cover the additional routing increment.

This is one development family with shared generator, procedure and context ancestry; nominal seed variation is not independent sampling. Deadlines are retrospective, logical time is controlled, and timing excludes support preparation and the final grade calculation. No actual human comparison, measured cost, operator effort, instrumented LLM usage, production or robotics acceptance is supplied. The confirmatory design remains AMBER and does not authorize execution.

The next value experiment needs a defined adaptive policy that changes a useful choice from accumulated outcomes, a strong fixed policy with the same permitted state and inputs, and a workload where that choice can matter. Freeze that contrast before selecting unseen families or claiming a completion, cost or latency advantage.

The first sequence report (001) and pilot005 preserve the pre-review snapshot. Independent negative controls found missing lifecycle gating, support-preparation mutation checks, a reported disposition assumption and failure-observation retention checks. These findings and actual RED regression logs are retained. Report002 and pilot007 rerun the corrected source; earlier reports do not satisfy current acceptance.

Residual review also added guards around admission, continuity between sealed phases, post-support evidence retention and typed observation content. Those executed RED controls and the intermediate float-contract failure are retained. Current retention compares canonical typed content and rejects malformed observations.
