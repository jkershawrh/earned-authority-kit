# Restore diagnostic review

No blocking issue was found in the snapshot change. **Eight direct client/cryptographic probes and 19 existing tests passed**, with unchanged source hashes. This review did not restart services.

The diagnostic path still verifies the installer-pinned signature, agent identity, exact canonical/wire fields, current revision binding and stored ACTIVE status. Canonical Passport reads the active pointer and revision under one read lock. The change permits an expired credential to be compared before and after restart.

Execution remains separate: `ConnectedRuntime.authority()` still uses the default validity check, and admission/commit retain current-authority and expiry enforcement. The restore report explicitly declares `authorizes_execution:false`.

The diagnostic call intentionally skips the separate validity RPC, including time and registry-eligibility checks. Stored ACTIVE status therefore means the current credential pointer, not permission to execute. An empty revoked aggregate has trusted service revision metadata and no signed active credential. Freshness relies on the configured local service and host assumptions.

This is a review of same-host persistence diagnostics. Fresh deployment acceptance is recorded by the running validation pipeline; backups, disaster recovery and independent-host acceptance are outside this claim.

[Checks, caveats and exact source hashes](restore-diagnostic-review.json).
