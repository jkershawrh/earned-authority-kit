# Observation boundary review

The review identified and checked fixes for per-attempt evidence attribution, older wire bundles, strict check-version typing, exact event identity for checks and commits, and ordering of cached authority observations. BDD-031 remains **AMBER** because successful recomputation with multiple resources under one skill is not implemented.

The review inspected source and tests and reproduced issues in temporary local fixtures. The final event-identity regression ran independently with two passes. It did not start services. Component and live-service acceptance are separate evidence. Exact reviewed file hashes and finding details are in [the machine-readable review](observation-boundary-review.json).

## Per-attempt evidence

A trusted producer could create an internally signed command naming the wrong grant. Before the fix, a temporary fixture committed one mutation and its historical proof consumer accepted that grant attribution. This required using the fixture's trusted authority key and changing its stored command; it was not an unauthenticated external bypass. The consumer still returned `authorizes_execution:false`.

The mutation boundary now derives bindings from the actual authority and grant, then compares every relevant signed-command field before recording checks or mutating the registry. The regression covers invented grant/passport IDs and changed skill, context, and policy digests.

Previously serialized legacy attempt bundles can omit the new check input only when the authenticated command has no execution-check version marker. New marked attempts cannot remove proofs to claim legacy treatment. The version must be an integer with the supported value; booleans and floating-point equivalents are rejected.

The final consumer review also found that an authenticated event with the right type and attempt label could substitute for the actual proof event. The parent identified this for check records; the independent review reproduced the same gap for a COMMITTED record. The consumer now requires the exact event IDs from both check proofs and the commit proof to be present among the exported lifecycle records. Both substitution regressions pass. This binds historical attribution; it does not make the proof a permission token.

Qualification and authorization check records describe what was consumed at the attempt's boundary. They do not rewrite earlier qualification or grant issuance, and they do not grant permission. Persistence failures roll back their transaction before mutation; retries retain one check pair.

## Cached authority observations

The cache records signed historical diagnostics. Explicit refresh obtains verified current canonical authority. Cached reads are read-only and make no service request. Admission and commit continue to query current canonical authority; a cached ACTIVE snapshot cannot authorize during a service outage, and a corrupt cache is not consulted by live authorization.

Two same-revision refreshes could previously persist in reverse order and regress the observation timestamp. The fix retains the prior record when its timestamp is strictly newer and its authority revision/digest match. Regression cases also cover an actual readonly cache write and a trigger substituting another valid signed observation.

## Policy windows

No blocking defect was found in the inspected window path. Future interval approval is insufficient for an immediate grant. Grant creation, durable-operation preflight, and execution check the active interval; the signed scope contains the requested interval and caps effective expiry at its exclusive end. Exact operation replay preserves its request and window. Historical receipts establish past transitions, not current permission.

Additional window-specific cases were recommended to the implementation owner: PREPARED expiry without issue; uncertain DISPATCHED expiry without blind replay; late receipt recovery without execution; and a policy call crossing the execution-window end. The owner added the PREPARED-expiry and execution-policy-crossing cases, reported 57 focused passes, and the review inspected their assertions. These use explicit unit service seams. Remaining execution evidence belongs in the owner and live-validation reports.

The source-configured first minute of 2100 UTC is a demo blackout, not a business maintenance calendar supplied by the user. Enforcement trusts the local clock. This review does not establish cross-host clock synchronization or universal distributed atomicity.

## Deferred multi-resource support

The current adapter keeps one grant per skill. BDD-031 proves stale CAS rejection but does not yet add a second read resource through a fresh recomputation while retaining the first. The coordinated representation, withdrawal, audit, proof-export, compatibility, and validation work is specified in [the implementation plan](../docs/MULTI_RESOURCE_GRANTS.md). No partial additional-grant projection was introduced.

Successful checks in this reference profile are evidence about their named cases. They do not establish customer value, statistical outcome improvements, hardware safety, or a production deployment guarantee.
