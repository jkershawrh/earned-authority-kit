# Primary outcome decision — 25 October 2026

The user selected **task completion** as the primary outcome for the next business-value evaluation. The machine-readable revision is [confirmatory-design-task-completion.json](confirmatory-design-task-completion.json). The original proposal and completed development reports retain their recorded source hashes.

The proposed measurement is independently verified successful legitimate tasks divided by all assigned legitimate tasks. Failed, timed-out, abstained and unstarted tasks remain in the denominator. Correct denials are reported separately. Any observed unauthorized mutation fails acceptance regardless of completion performance. Exact task postconditions and budgets must be frozen with the representative workload before scoring; this measurement definition remains a draft.

Work counts, elapsed time and operator intervention are secondary measures when actually instrumented. The chosen metric does not set a benefit threshold, risk budget, adequate sample size or baseline. No customer data or held-out evaluation has been supplied or executed by this decision.

To inspect this revision, use `python tools/check_edd_readiness.py --design evaluations/confirmatory-design-task-completion.json --report reports/edd-confirmatory-readiness-005.json` (the report already exists; choose a fresh path for a new check). The explicit design argument selects this revision; the CLI default still refers to the original historical proposal.

The [readiness diagnostic](../reports/edd-confirmatory-readiness-005.json) closes the primary-outcome selection item. Eight prerequisites remain open, and execution permission remains false. Next supply one recurring real task, representative input/outcome records, candidate deterministic procedures and the strongest existing baseline.
