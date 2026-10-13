# Sequential EDD review — initial findings

Reviewed 2026-10-13T18:34:19.173764+00:00. **RED** pending four corrections. Existing harness tests passed all 61 cases, but independent actual-SQLite negative probes exposed missing acceptance checks. No production source was edited.

## SEQ-R1 — Missing phase acceptance gate

Forcing only retained_success admission to deny still produced COMPLETED/GREEN. Invariant-only checks do not establish the named lifecycle behavior.

Gate declared expected phase success/denial and observed withdrawal/requalification states in the runner, retaining the failing row and stopping subsequent phases.

## SEQ-R2 — Support preparation writes are outside the grading window

A Runtime.shadow wrapper performed an actual unauthorized write to the unrelated sentinel. Every sequence phase and the whole report remained GREEN with no integrity errors.

Read registry/counter before preparation, compare after preparation, and forbid any preparation mutation before querying. Preserve prior-query continuity. Apply the same boundary to independent pilot preparation.

## SEQ-R3 — Qualification disposition is fabricated for the withdrawn phase

After leaving actual persisted qualification ELIGIBLE while retaining the revoked authority, withdrawn_query reported qualification_disposition=INELIGIBLE even though prepared_qualification.disposition=ELIGIBLE, and the report remained GREEN.

Read the actual disposition and compare against the declared expected transition; do not insert expected labels as observed results.

## SEQ-R4 — Retained failure deletion is not detected

Deleting the actual SQLite FAIL observation during recovery support preserved all expected task/denial outcomes and COMPLETED/GREEN; recovery observations contained no FAIL despite the explicit retention claim.

Require every previously retained observation identity and canonical content to remain through preparation and query boundaries; detect removal or alteration before continuing.

Scope is the disposable local SQLite fixture. Both arms use the same deterministic policy; these are engineering checks, not a demonstration of learned or business value. Exact hashes and probe results are in the companion JSON.
