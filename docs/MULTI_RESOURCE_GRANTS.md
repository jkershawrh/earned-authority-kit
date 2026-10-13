# Multiple resource grants under one skill

Status: **GREEN for the recorded local engineering profile**. Multi-resource support is implemented and BDD-031 is complete in reports/service-bdd-live-013.json. Broader deployment and evaluation gates remain AMBER.

## Gap closed by this increment

BDD-031 requires a stale revision-4 replacement to lose after release authority is revoked at revision 5. A replacement recomputed from revision 5 must then add a second read resource while retaining the first read grant and preserving the release revocation.

The prior connected test proved stale replacement rejection, release revocation, and continued use of the original read resource. The current test also performs successful recomputation, independent execution of both resources, and complete evidence consumption. Canonical Agent Passport already carries several scopes in one signed aggregate and provides active-passport-ID plus agent-revision compare-and-swap. The previous kit adapter indexed grants by skill and rejected or overwrote same-skill resources. The adapter now retains every exact grant in a list. Removing the duplicate check alone would leave other consumers incomplete.

No canonical Passport protocol change is proposed. Passport remains the only authority source. The ledger and historical operation receipts remain evidence of assertions and transitions, not current permission.

## Complete representation

Represent the connected adapter's normalized `grants` as a complete list of grant records, matching the existing public wire authority's list semantics. Each entry retains the current exact signed inner binding: grant ID, skill and version, skill/context digests, context, qualification ID/digest, policy digest, action, resource, and absolute expiry. Canonical scope ID may be retained as derived metadata. Do not flatten the list to one representative grant per skill.

The shared earned_authority/grants.py module provides:

```python
iter_grants(authority) -> tuple[dict, ...]
grants_for_skill(authority, skill) -> tuple[dict, ...]
grant_by_id(authority, grant_id) -> dict | None
select_grant(authority, *, skill, version, context, action, resource,
             grant_id=None) -> dict
```

`select_grant` requires one exact matching binding; zero matches deny and multiple matches deny as an ambiguous binding. It must never select the first candidate or use wildcard resource matching. When checking an admitted command, it additionally requires the command's grant ID and qualification/digest fields to match that entry. Aggregate passport ID/revision and expiry remain mandatory checks.

During migration `iter_grants` may read the old fixture's skill-keyed dictionary by iterating all its values. It may not collapse a new list back into that dictionary. Existing connected callers and tests must move together to the helpers. A convenience lookup by skill alone may return a grant only when exactly one exists; ambiguity must be explicit. This is a deliberate normalized-adapter interface change, not a silent compatibility projection.

Normalize and reject duplicate grant IDs, duplicate canonical scope IDs, and duplicate logical slots. The proposed slot is `(skill, action, exact resource, context_digest)`. A new grant for the same slot replaces the prior grant/version/qualification; a new resource adds a slot. Different versions must not coexist ambiguously in one slot. Context equality must still be checked against its digest.

## Grant and recomputation contract

The public `grant(qid, ..., action, resource, expected_revision, operation_id)` signature can remain unchanged.

1. Reconcile the operation journal and target-bound withdrawals before constructing a new change.
2. Verify the qualification's current procedure, evidence, context, and policy binding. Obtain an actual policy decision for the exact new action/resource.
3. Read the current canonical aggregate. If a supplied expected revision differs, reject before dispatching a new authority change.
4. Upsert only the exact logical slot in that current aggregate. Preserve all other live grants' IDs, qualification/policy bindings, contexts, and absolute expiry values. Do not import grants from the caller's stale snapshot.
5. Construct one complete canonical ISSUE replacement using the current active ID and revision. Keep the existing containing-TTL rounding and inner absolute expiry cap; replacement must neither extend nor shorten unaffected effective lifetimes.
6. Persist the exact full request and operation ID before dispatch. Apply through the canonical signed operation API and require its verified historical receipt before writing the local lifecycle event.

A CAS conflict never permits changing the request attached to an existing operation ID. After a definitive conflict is reconciled, an explicitly recomputed attempt uses a new operation ID and a newly read aggregate. An unresolved dispatched operation remains pending. Response loss is recovered through its original signed receipt; it does not trigger a replacement assembled from guessed current state.

For the BDD-031 sequence, revision 6 contains both read resources and no release grant. There is still one active passport. The original read grant's effective binding and expiry are unchanged even though the containing passport and canonical scope IDs may be newly issued.

## Withdrawal, audit, and hold semantics

The selected conservative policy is **skill-wide demotion**: a confirmed failure or required-evidence hold removes every current grant of the affected skill, preserving grants of other skills. This is broader than revoking only one resource and must be explicit in the API and evidence.

Automatic withdrawal remains anchored to the failed or held command's exact grant ID and qualification ID. If that anchor is no longer current, reconcile the historical withdrawal without withdrawing a replacement grant. If it is current, derive the complete set of same-skill targets from the freshly read canonical aggregate and bind that target set in the signed local intent. The canonical request already binds the complete resulting scope set and predecessor tuple. Add an explicit target list to the journal/lifecycle assertion for reviewability; do not describe a multi-grant removal as one unexplained target.

Recomputation after a competing authority change must recheck the anchor. It may not replay an old target list against a new aggregate. An administrative `revoke(skill)` intentionally targets all current grants of that skill. A separate resource-specific revocation API, if later needed, needs an explicit distinct contract; do not infer it from a skill-wide demotion call.

Evidence audit and reevaluation must inspect every current grant of the selected skill, deduplicating qualification work only when its exact ID/digest match. A bad qualification triggers the specified skill-wide withdrawal. The result should identify each inspected grant and affected qualification. The durable withdrawal_causes table retains each exact (agent, skill, attempt_id, target_grant_id, target_qualification_id) cause separately. Startup atomically migrates every legacy withdrawal row and empties the old table. A stale/replaced cause cannot overwrite or delete a current sibling failure. Reevaluation preserves a stronger confirmed failure. Targeted revoke requires both nonempty anchor fields; omission of both intentionally requests administrative skill-wide withdrawal.

The hold diagnostic must recognize each removed target's version/context/action/resource from the authenticated applied operation. It remains restricted to new matching requests at the exact acknowledged current canonical tuple. Older admitted commands remain revoked; a valid replacement grant takes precedence. A historical receipt never supplies permission.

## Integration boundaries

- `connected.py`: normalization, grant upsert, exact execution selection, skill-wide revoke, audit, reevaluation, and held-reason selection.
- `authority_journal.py`: immutable multi-target metadata, exact replay binding, event content, historical receipt reconciliation, and backward reading of existing single-target operations.
- `wire_contracts.py`: export every current grant and every required qualification; consume exact grant IDs. Existing public authority records already use an array, the exporter now iterates the complete normalized list.
- `runtime.py` and fixtures: use shared grant iteration/selection where the public and fixture paths overlap. A fixture that still supports one resource per skill must stay explicitly limited; its passes cannot certify the connected multi-resource behavior.
- BDD, recovery, and deployment runners: migrate consumers atomically, retain old reports, and rerun against the final source fingerprints.

Do not ship a partial `extra_grants` field or a compatibility map that hides scopes from audit, revocation, or wire export. No dependency should discover a second authority source.

## Required acceptance gates

### TDD and negative cases

- Add a second read resource from the current revision: retain both exact read bindings and the first expiry; keep release revoked; increment authority once.
- Reject the revision-4 update after revision-5 revocation without issuing another current passport, advancing a revision, or fabricating an applied lifecycle event.
- Race recomputation with another canonical update: exactly one CAS winner; the loser cannot restore release or erase the first read resource.
- Execute both resources through exact scope selection. A command for one resource cannot borrow the other grant, action, context, version, qualification, or policy binding.
- Reject duplicate grant IDs, duplicate slots, contradictory inner/outer scope bindings, and ambiguous selection.
- Demote one skill with multiple current resource grants: remove all its grants, preserve unrelated skills and their absolute expiries, and record the exact removed set.
- Deliver a delayed failure from a replaced anchor: preserve the replacement authority and record historical reconciliation rather than revoking the replacement.
- Audit a bad qualification behind either resource: no hidden sibling survives the defined skill-wide hold. Unsolicited rejected evidence and remote-ledger outages retain their existing semantics.
- Lose the successful replacement response, restart the coordinator, and recover its original receipt: no double revision, duplicate lifecycle event, missing scope, or replay of a later replacement.

### Contract and behavior gates

CDD must round-trip a real canonical two-resource passport, both qualifications when distinct, and attempts referencing each exact grant. Negative exports/consumption must fail if any current scope or required proof is dropped. Existing historical single-target journal records remain readable without invented multi-target metadata.

BDD-031 becomes complete only after the live runner performs stale rejection **and** a successful newly computed update, independently checks both read resources, verifies release remains revoked, and checks the preserved grant binding/expiry. All existing execution, evidence-admission, hold, and authority-recovery scenarios must remain green.

After source freeze, reproduce the connected seven-part deployment suite in a distinct workspace with new validation state, verified image identity, exact source hashes, real restart, and readback of earlier receipts. Preserve the original bounded-check count unless changed assertions justify a reviewed update.

### Evaluation and status

These checks establish the tested authority and evidence behavior. They do not establish held-out task success, business value, or universal distributed safety. Evaluation-driven development remains separate: its preregistered comparator protocol and unselected risk budget still apply.

RED means a demonstrated invariant failure. AMBER means any integration dependency, negative case, live behavior, or evidence binding above remains unimplemented or unexecuted. GREEN is limited to the reviewed, source-bound test profile after every gate passes. BDD-031 is GREEN for the exact recorded profile. EDD, independent installation, operations and robotics remain AMBER.

## Recorded acceptance and interface migration

The final component run passes 514 tests, including 77 new multi-resource and journal cases. The full service behavior run passes 52 cases across all 37 implemented IDs. The isolated reconstructed reference passes 123 checks across seven stages, including full-stack restart and readback of earlier operation receipts. Each report records exact before/after source hashes. The full behavior run in that isolated workspace is the same live013 evidence, not additional trials.

Consumers of normalized ConnectedRuntime authority must use the complete grants list and shared helpers. The public wire authority already used an array. The local fixture remains explicitly limited to one resource per skill; all its map values can be iterated without projecting a connected list back to a map. The grant helper source participates in procedure revision hashing, so existing qualification must be renewed after this executable change. Historical journal entries remain readable without invented removal metadata.

Independent review reproduced and fixed incomplete withdrawal anchors, known-failure downgrading, typed-context diagnostic mismatch, malformed expiry hiding behind a cap, and retained-grant lifetime shortening. The first full live run also exposed the old-version denial priority regression; all cases were rerun after the fix. Multi-attempt wire identity is now selected by record kind, so two attempts under one passport remain distinct.
