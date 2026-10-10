# Draft contracts and runtime bindings

The unpublished contract version remains `0.1.0-draft.1`. Its revision hashes are
recorded in `reports/wire-schema-revision.json`; this draft has not been released
as a stable external protocol.

`earned_authority.wire_contracts.export_runtime` exports actual qualifications,
current active credentials, requested or committed attempts, signed independent
observations, and authenticated local lifecycle events. `consume_bundle` checks
both the schemas and the mappings against trusted original records. A successful
consumer result explicitly returns `authorizes_execution: false`. The runtime
still needs a fresh policy decision and current authority at its mutation fence.

## Trust and references

- A `WireBundle` contains public normalized `records` and a private `proof_store`.
  The proof store includes raw signatures; reports should contain `records` only.
  Each public envelope binds its original source digest and content-addressed
  proof inputs. Changing a source and recomputing its digest does not make it
  trusted: the consumer independently resolves it through `RuntimeTrust`.
- `RuntimeTrust` trusts the local coordinator store for unsigned qualification
  and result metadata. It verifies checker and command signatures, local event
  signatures, the canonical Passport service's provisioned issuer/current status,
  and remote Ledger receipts when delivery is claimed. This is a local reference
  adapter, not a self-contained portable identity protocol.
- Grant `qualification_digest` remains the digest of the original runtime
  qualification. It is deliberately different from the normalized wire record's
  digest. Attempts resolve their exact original revision from immutable durable
  qualification history even after the current qualification changes.
- Each grant includes its exact authorization `policy_digest`. The top-level
  authority `policy_digest` is the digest of the sorted list of
  `{grant_id, policy_digest}` bindings. It is an aggregate integrity binding;
  consumers use per-grant policy digests for scope checks. The qualification's
  policy digest describes its evidence policy and is a different policy domain.
- Runtime action `release` maps to canonical `model.promote_to_production`;
  `read` and `read-health` map to `demo.read`. This mapping does not grant a scope.

## Evidence and lifecycle semantics

ELIGIBLE requires actual independent evidence references, a nonempty ordered
observation window, and expiry after that window. The reference demo uses three
PASS observations and makes no statistical adequacy claim. HOLD and INELIGIBLE
may have no references and a null observation window. Both window endpoints must
be null together. Evidence-bearing noneligible records retain an ordered window;
delayed negative or unknown observations may follow the original expiry without
extending authority. UNKNOWN produces no failure count.

Only an actual active current credential is exported as an authority. A revoked
aggregate/tombstone does not become a fabricated signed credential. Export with
`include_authority=False` to describe prior execution and evidence after
withdrawal. An export that includes current authority requires included attempts
to match that exact current credential and revision.

`mutation_receipt_ref` points to a signed durable local COMMITTED event, which can
exist while remote ledger delivery is PENDING. For a read action this records
completed execution with no registry mutation. PENDING events have no remote
receipt reference. An independently confirmed PASS remains PASS during remote
delivery failure; inability to verify a claimed remote receipt makes that bundle
unverified and does not rewrite the underlying outcome.

Lifecycle `subject_id` identifies the immutable source event itself and its
`subject_revision` is 1. Mutable authority/qualification revisions remain in the
authenticated payload; the adapter does not infer absent historical revisions.
INTENT, CANONICAL_QUALIFICATION_EVALUATED, and WITHDRAWAL_RECONCILED are included.

The evidence-boundary revision adds `PROCEDURE_REPORTED`, `EVIDENCE_ADMITTED`
and `EVIDENCE_REJECTED` to the lifecycle enum. These are actual signed runtime
events: a procedure's unverified claim remains separate from an independent
outcome, and evidence admission or rejection describes an intake decision. None
of these events grants authority, confirms business execution or creates an
independent outcome by itself. A recorded Ledger receipt authenticates the event
assertion and its binding; it does not change that meaning.

This is an additive change within the unpublished `0.1.0-draft.1` working draft,
identified by its schema content hash. A consumer pinned to the prior closed enum
is expected to reject these new event types. Producer and consumer revisions must
be updated together; no stable published compatibility or version-negotiation
claim is made. `tests/test_evidence_wire.py` tests actual producer/export/consumer
records with explicit unit service seams, including pending/recorded delivery,
rehashed-copy rejection, durable-source signature checks and old-enum rejection.

## Validation evidence

The individual five fixture files are schema examples. `runtime-wire-records.json`
is a captured public export from a disposable real M1 fixture execution; its
private proof store is not distributed with it. Validating that capture proves
shape only. The executable tests create fresh runtimes, perform shadow execution,
qualification, grants and mutations, then consume their actual authenticated
records and exercise negative substitutions, omission, expiry, withdrawal,
unknown outcomes, history, and receipt integrity. Connected service validation
uses the same mapper and consumer with the actual service clients.
