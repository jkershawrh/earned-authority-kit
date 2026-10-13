# Routing EDD review — initial findings

Reviewed 2026-10-13T19:03:10.303147+00:00. **RED** pending four corrections. The initial94-test suite passed, but independent actual SQLite and meter probes exposed gaps.

## ROUTE-R1 — Publication can discard retained signed evidence

After sealed query0, a wrapper around actual record_cost deleted an existing support cost and linked SQLite observation. All32 assigned tasks still completed GREEN because post-publication state replaced prior baselines without a retention comparison.

Preserve observations and costs through publication, require exactly the intended new record, and compare before accepting a new baseline.

## ROUTE-R2 — Signed non-independent observation accepted as independent cost evidence

verified_costs accepted a trusted-checker-signed observation with independent=false and its signed cost record.

Require the exact trusted independent observation contract, not merely a valid checker signature.

## ROUTE-R3 — Procedure can rewrite the host meter trace

An adversarial forward procedure made9 actual instrumented catalog reads, then rewrote public catalog.trace to [0]. execute reported1 read and check_reads accepted it.

Keep the measurement event sink outside the procedure-writable catalog API. Continue to disclose same-process trust limits.

## ROUTE-R4 — Cost publication lacks an independent exact job binding

A cost record re-signed by the trusted checker with a different resource passed verification. This is a misbound-producer probe, not a forged-signature attack; the verifier has no independently registered expected job/candidate direction to compare.

Register the expected job, candidate direction and exact resource/catalog/key binding before execution and verify cost publication against it, or explicitly narrow the binding claim.

The replay duplicate probe is rejected after the author added its guard. The review found no additional flaw in the stated pooled-versus-contextual mean-ranking contrast. Support reuses the first six generated query inputs, so no held-out generalization follows. Catalog reads are not elapsed cost or business value.
