"""Conservative evidence scoring. Green is scoped to a revision and environment.

This evaluates local test records; it does not establish evidence-issuer trust,
cryptographic authenticity, runtime authorization, or production readiness.
"""
import hashlib
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def verify_artifact(record, root):
    """Recompute a local artifact hash; never trust an input 'verified' flag."""
    try:
        base = Path(root).resolve()
        relative = Path(record["artifact"])
        if relative.is_absolute():
            return False
        path = (base / relative).resolve()
        path.relative_to(base)
        return path.is_file() and "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == record["artifact_digest"]
    except (KeyError, TypeError, ValueError, OSError):
        return False


def assess(requirement, evidence, now_ms, artifact_root):
    methods = set(requirement["required_methods"])
    if not methods or requirement["max_age_ms"] < 0:
        raise ValueError("required methods and a nonnegative evidence age are required")
    relevant = [e for e in evidence if
                e.get("requirement_id") == requirement["id"] and
                e.get("revision") == requirement["target_revision"] and
                e.get("environment") == requirement["environment"]]
    # A known failure cannot age out or disappear behind a passing retry.
    # Supersede the tested revision (including fixes) and rerun to clear it.
    if any(e.get("outcome") == "FAIL" and e.get("executed") is True for e in relevant):
        return {"requirement_id": requirement["id"], "status": "RED", "reason": "Known failure on the target revision/environment", "missing_methods": []}
    accepted = set()
    for method in methods:
        candidates = [e for e in relevant if e.get("method") == method]
        if not candidates or any(type(e.get("timestamp_ms")) is not int for e in candidates):
            continue
        latest_time = max(e["timestamp_ms"] for e in candidates)
        latest = [e for e in candidates if e["timestamp_ms"] == latest_time]
        # New UNKNOWN/SKIP or contradictory same-time evidence supersedes an
        # older pass. Every tied latest record must establish the same pass.
        if all(e.get("executed") is True and e.get("outcome") == "PASS" and
               0 <= now_ms - e["timestamp_ms"] <= requirement["max_age_ms"] and
               verify_artifact(e, artifact_root) for e in latest):
            accepted.add(method)
    missing = sorted(methods - accepted)
    if missing:
        return {"requirement_id": requirement["id"], "status": "AMBER", "reason": "Missing current, executed, artifact-verified evidence", "missing_methods": missing}
    return {"requirement_id": requirement["id"], "status": "GREEN", "reason": "All required methods passed for this revision and environment", "missing_methods": []}


def release_status(results, expected_ids):
    """Aggregate an explicit required manifest; omitted rows remain amber."""
    expected = set(expected_ids)
    actual = [r["requirement_id"] for r in results]
    if len(actual) != len(set(actual)) or set(actual) - expected:
        raise ValueError("duplicate or unexpected requirement")
    statuses = [r["status"] for r in results]
    if any(s not in {"RED", "AMBER", "GREEN"} for s in statuses):
        raise ValueError("unknown readiness status")
    if "RED" in statuses:
        return "RED"
    if not expected or set(actual) != expected or "AMBER" in statuses:
        return "AMBER"
    return "GREEN"
