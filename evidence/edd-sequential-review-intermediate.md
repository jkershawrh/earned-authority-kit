# Sequential EDD review — intermediate findings

**RED.** Three additional actual-SQLite probes exposed admission-window, newly supplied evidence retention and typed-content gaps. The companion JSON preserves exact source hashes and results. These findings concern the development harness, not an observed canonical-service incident.

**SEQ-R5 — Admission mutation can escape the grading window**

An actual unrelated sentinel mutation inside admit is incorporated into a replacement before snapshot; the corrected runner still returned COMPLETED/GREEN. Preserve and compare the registry/counter baseline across admission and maintain continuity from the prior sealed phase.

**SEQ-R6 — New support observations can be deleted during their first query**

Deleting all three newly added support observations after query0 left only the query observation. Because retention compared pre-support observations, the entire run returned COMPLETED/GREEN. Capture post-preparation observations and require that exact evidence to survive the query.

**SEQ-R7 — Python equality permits typed observation alteration**

Changing the retained FAIL observed_at_ms from integer 1000000 to floating-point 1000000.0 passed retained_observations and the entire run returned COMPLETED/GREEN. Use canonical typed content equality for retention, including report provenance checks.
