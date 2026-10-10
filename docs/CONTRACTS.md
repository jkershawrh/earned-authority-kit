# Draft contract handoff

The five schemas define structural messages, not service implementations or an authorization protocol already proven in production.

- Qualification: version/context-bound eligibility with observed evidence references and evaluator/policy revision.
- Authority: a signed aggregate of per-skill grants, one current aggregate per agent, monotonic revision.
- Attempt: one intended action with exact arguments digest, selected grant/revision and policy decision.
- Outcome: independently sourced postcondition observation; declared independence must be authenticated by an adapter.
- Lifecycle event: appendable assertion with separate pending/recorded delivery and receipt reference.

Consumers must additionally validate all references, matching digests, actor ownership, trust roots, signature subject, freshness, policy, current authoritative revision, and per-skill state. These relationships are not established by JSON Schema. Invalid or missing data denies admission. A normal policy denial is a successful behavior when denial was expected.

Suggested error taxonomy for G0: INVALID_CONTRACT, UNSUPPORTED_VERSION, BINDING_MISMATCH, EXPIRED, REVOKED, STALE_AUTHORITY, CONTEXT_MISMATCH, POLICY_DENIED, EVIDENCE_UNTRUSTED, OUTCOME_UNKNOWN, DEPENDENCY_UNAVAILABLE, IDEMPOTENCY_CONFLICT. Mapping to each service's current transport remains an adapter task.

Compatibility gate: each producer emits accepted positive fixtures; each consumer rejects altered agent, skill, context, arguments, grant revision, evidence and policy binding. Test seconds-vs-milliseconds errors, duplicate JSON keys, unknown mandatory fields, canonical encoding vectors, and replay of old signatures. Pin schema and consumer versions together; migrations must not silently widen permissions.

Qualification thresholds and trust policies are configuration with versioned digests. The three-pass BDD fixture is a deterministic scenario device, not empirical proof of qualification adequacy.
