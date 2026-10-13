# Multi-resource boundary review

The final independent review found no unresolved blocker in the inspected paths. **221 tests and 19 subtests passed**, with zero failures, errors or skips and unchanged source hashes. This is local unit and contract evidence; current-source live service acceptance is separate.

Five independently reproduced issues were fixed and rechecked:

- Incomplete revoke anchors now fail before any side effect. A qualification-only anchor cannot silently become a manual skill-wide revoke.
- Reevaluation preserves a known failure while authority withdrawal is unavailable.
- Hold diagnostics compare canonical context digests, keeping boolean and integer values distinct.
- Signed inner expiry types are checked before clamping.
- Replacement Passport and scope lifetimes must contain each unaffected grant’s exact absolute expiry. Zero-TTL fallback and fractional-second rounding are covered.

A final denial-priority check confirms that an old executable reports `SKILL_REVISION_MISMATCH` before scope selection. An independently executed stale-command probe still reports `REVOKED_AUTHORITY` first, with zero mutations. The [preceding review](multi-resource-review-before-revision-priority.json) remains unchanged as historical evidence.

The review also checked complete removal-target binding to the prior aggregate and replacement request, explicit wire identity by record kind, exact grant selection, composite queue migration, stale-anchor handling, sibling evidence auditing, and historical fixture/journal compatibility. Full grant export and recovery are covered by the regression run.

The service doubles are explicitly unit seams. These results do not establish live deployment acceptance, independent-host reproduction, product value or universal safety. Local host, signer provisioning and clock assumptions still apply.

[Exact findings, command and source hashes](multi-resource-review.json) are recorded with the verification result. No core files were edited during this review.
