"""Pinned canonical Cascade lifecycle and deterministic GCL proposal adapter.

Authenticated independent outcomes remain the caller's source of truth. Cascade
scores them using an explicit demo policy; GCL challenges a context-bound
supporting deployment plan. Neither engine issues permission or executes work.
"""
import asyncio
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

from .contracts import canonical_digest

CASCADE_REVISION = "3efd16e053ef2a8a95b1b1ba6c1d1acdd873a3cb"
GCL_REVISION = "a8ae67ee1198e8b86bf7458119723c0af2d74792"
PINNED_FILES = {
    "cascade": {"cascade_compression/cascade/promotion.py": "e9aac54a4ed7fab236d87337fc627bcb62ecae7c83f693590c1592fc7c63f443"},
    "gcl": {
        "gcl/falsification/gate.py": "b062a429a326d885d0093147e7f32430e25d109868df065b334a646e0c250231",
        "gcl/falsification/checks.py": "7393cea6ab6c897ace296c653f6f052ac689e76fc09b28c505fbfbb8f19cc9fb",
        "gcl/domain/contracts.py": "3b759bf69b7ebbf007459dd3c2b1add48241cdf51789143b0f6a0276d30c30d3",
        "gcl/domain/enums.py": "e4d45cdea95678df1b5722ca3318ab923111328a6df13f92dc6aca780a9be91c",
        "gcl/config.py": "30b26da0fb95772a5c1120347808d4e1429ebc4e4346bd3d258c31edbff2f508",
        "gcl/inference/client.py": "776d8afa7b4af6942a9b7481dfe29a14bff884dd587fff7c2f49d85d7b6550b6",
        "gcl/falsification/llm_adversary.py": "b59ae332c74a599462df91d287371577a862f6ec8d3caaa914a2f3ef8410bbde",
        "config/defaults/loop.yaml": "4cfe968794c666c943a157096e76f08306da67ec53c7d56f34e6bd2e57b5f895",
    },
}
_IMPORT_LOCK = threading.RLock()


class QualificationAdapterError(RuntimeError):
    pass


def _checked_source(root, family):
    root = Path(root).resolve()
    for relative, expected in PINNED_FILES[family].items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise QualificationAdapterError(f"Pinned {family} source mismatch: {relative}")
    return root


def _load_cascade(root):
    with _IMPORT_LOCK:
        sys.path.insert(0, str(root))
        try:
            module = importlib.import_module("cascade_compression.cascade.promotion")
        finally:
            sys.path.remove(str(root))
        if Path(module.__file__).resolve() != root / "cascade_compression/cascade/promotion.py":
            raise QualificationAdapterError("A different Cascade module was already imported")
        return module


def _portable_numbers(value):
    """Keep reports compatible with the kit's integer-only digest encoding."""
    if type(value) is float:
        return str(value)
    if isinstance(value, dict):
        return {k: _portable_numbers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_portable_numbers(v) for v in value]
    return value


class QualificationClient:
    mode = "CANONICAL_IN_PROCESS_WITH_ISOLATED_GCL"
    evidence_window_ms = 600_000
    source_revisions = {"cascade": CASCADE_REVISION, "gcl": GCL_REVISION}

    def __init__(self, cascade_root=None, gcl_root=None, min_samples=3):
        if type(min_samples) is not int or min_samples < 1:
            raise ValueError("min_samples must be a positive integer")
        workspace = Path(__file__).resolve().parents[3]
        self.cascade_root = _checked_source(cascade_root or os.environ.get("CASCADE_SOURCE_ROOT") or workspace / "work/cascade-compression-oss", "cascade")
        self.gcl_root = _checked_source(gcl_root or os.environ.get("GCL_SOURCE_ROOT") or workspace / "work/governed-cognitive-loop-oss", "gcl")
        self.canonical = _load_cascade(self.cascade_root)
        self.canonical_defaults = copy.deepcopy(self.canonical.DEFAULT_THRESHOLDS)
        self.min_samples = min_samples
        self.thresholds = copy.deepcopy(self.canonical.DEFAULT_THRESHOLDS)
        for tier in ("candidate", "nano"):
            self.thresholds[tier] = dict(min_samples=min_samples, min_accuracy=1, max_false_positive=0, max_false_negative=0)
        self.states = {}
        self.lock = threading.RLock()

    def _state(self, skill_digest, context_digest):
        key = (skill_digest, context_digest)
        if key not in self.states:
            self.states[key] = {"engine": self.canonical.PromotionEngine(thresholds=copy.deepcopy(self.thresholds)),
                "agent": self.canonical.AgentMetrics(name=skill_digest + ":" + context_digest), "seen": {}}
        return self.states[key]

    def _cascade_report(self, state):
        agent = state["agent"]
        return {"implementation": "cascade_compression.cascade.promotion.PromotionEngine", "source_revision": CASCADE_REVISION,
            "tier": agent.tier, "active": agent.tier in self.canonical.ACTIVATED_TIERS and not agent.deactivated,
            "deactivated": agent.deactivated, "samples_tested": agent.samples_tested,
            "false_negative_count": agent.false_negative_count,
            "events": _portable_numbers([e.to_dict() for e in state["engine"].events])}

    def evaluate(self, qualification, observations, *, verify_observation, now_ms, proposal=None, require_gcl=True):
        if not callable(verify_observation): raise TypeError("An authenticating observation verifier is required")
        if type(now_ms) is not int: raise TypeError("now_ms must be an integer")
        q = qualification
        expected_skill = canonical_digest({"skill": q["skill"], "version": q["version"]})
        expected_context = canonical_digest({"environment": q["context"]})
        if q.get("skill_digest") != expected_skill or q.get("context_digest") != expected_context:
            raise QualificationAdapterError("Qualification binding digest mismatch")
        with self.lock:
            state = self._state(expected_skill, expected_context)
            selected = [o for o in observations if o.get("skill_digest") == expected_skill and o.get("context_digest") == expected_context]
            by_attempt, rejected, conflicts = {}, set(), False
            for observation in selected:
                attempt_id = observation.get("attempt_id")
                if not isinstance(attempt_id, str) or not attempt_id: continue
                digest = canonical_digest({k: v for k, v in observation.items() if k != "evidence_digest"})
                if attempt_id in by_attempt and by_attempt[attempt_id][1] != digest: conflicts = True
                if verify_observation(observation) is not True or observation.get("independent") is not True or observation.get("evidence_digest") != digest:
                    rejected.add(attempt_id); continue
                by_attempt[attempt_id] = (observation, digest)
            references = {r["attempt_id"]: r["evidence_digest"] for r in q.get("outcome_refs", [])}
            missing_refs = set(references) - set(by_attempt)
            wrong_refs = {attempt for attempt, digest in references.items() if attempt in by_attempt and by_attempt[attempt][1] != digest}
            fresh, stale_count = [], 0
            for observation, digest in by_attempt.values():
                timestamp = observation.get("observed_at_ms")
                if type(timestamp) is not int or not 0 <= now_ms - timestamp < self.evidence_window_ms:
                    stale_count += 1; continue
                if observation.get("outcome") not in ("PASS", "FAIL", "UNKNOWN"):
                    rejected.add(observation["attempt_id"]); continue
                fresh.append((observation, digest))
            passes = sum(o["outcome"] == "PASS" for o, _ in fresh)
            failures = sum(o["outcome"] == "FAIL" for o, _ in fresh)
            unknown = sum(o["outcome"] == "UNKNOWN" for o, _ in fresh)
            signals = []
            for observation, digest in fresh:
                attempt_id = observation["attempt_id"]
                if attempt_id in state["seen"]:
                    if state["seen"][attempt_id] != digest: conflicts = True
                    continue
                if observation["outcome"] == "UNKNOWN": continue
                state["seen"][attempt_id] = digest
                # Expected success is a negative failure prediction. An independently
                # observed failure becomes a false negative in canonical scoring.
                signals.append({"signal_type": "verified_registry_outcome", "features": {
                    "observed_failure": 1 if observation["outcome"] == "FAIL" else 0, "predicted_failure": 0}})
            baseline = self.canonical.Baseline(normal_ranges={"verified_registry_outcome": {"observed_failure": {"low": 0, "high": 0}}})
            rule = self.canonical.RuleAgent({"name": "expected-registry-postcondition", "condition": {"field": "predicted_failure", "operator": "eq", "value": 1}})
            if signals: state["engine"].validate(state["agent"], rule, signals, baseline, batch_id=q["qualification_id"])
            valid_current = not (missing_refs or wrong_refs or rejected or conflicts or unknown or failures)
            if valid_current and passes >= self.min_samples and q.get("disposition") == "ELIGIBLE" and q.get("expires_at_ms", 0) > now_ms:
                for _ in range(2):
                    if state["agent"].tier in self.canonical.ACTIVATED_TIERS: break
                    state["engine"].check_promotion(state["agent"])
            gcl = self.challenge(proposal)
            disposition, reason = "HOLD", "INSUFFICIENT_EVIDENCE"
            if failures: disposition, reason = "INELIGIBLE", "KNOWN_FAILURE"
            elif conflicts or wrong_refs: reason = "EVIDENCE_BINDING_MISMATCH"
            elif missing_refs: reason = "MISSING_REFERENCED_EVIDENCE"
            elif rejected: reason = "UNTRUSTED_OR_NONINDEPENDENT_EVIDENCE"
            elif unknown: reason = "EVIDENCE_UNCONFIRMED"
            elif q.get("expires_at_ms", 0) <= now_ms or (stale_count and not fresh): reason = "STALE_EVIDENCE"
            elif not self._proposal_matches(q, proposal) and proposal is not None: reason = "PROPOSAL_CONTEXT_MISMATCH"
            elif require_gcl and gcl["verdict"] == "NOT_CONFIGURED": reason = "GCL_NOT_CONFIGURED"
            elif gcl["verdict"] == "fails": disposition, reason = "INELIGIBLE", "GCL_PROPOSAL_REJECTED"
            elif gcl["verdict"] not in ("survives", "NOT_CONFIGURED"): reason = "GCL_CHECK_UNAVAILABLE"
            elif q.get("disposition") != "ELIGIBLE": reason = q.get("reason", "QUALIFICATION_NOT_ELIGIBLE")
            elif passes >= self.min_samples and self._cascade_report(state)["active"]:
                disposition, reason = "ELIGIBLE", "CANONICAL_CHECKS_PASSED"
            return {"disposition": disposition, "reason": reason, "eligible_for_authority_review": disposition == "ELIGIBLE",
                "qualification_id": q["qualification_id"], "skill_digest": expected_skill, "context_digest": expected_context,
                "passes": passes, "failures": failures, "unknown": unknown,
                "policy_profile": "demo-three-pass" if self.min_samples == 3 else f"configured-{self.min_samples}-pass",
                "statistical_adequacy_claim": False, "cascade": self._cascade_report(state), "gcl": gcl,
                "source_revisions": {"cascade": CASCADE_REVISION, "gcl": GCL_REVISION}, "executed": False, "authority_created": False}

    @staticmethod
    def _proposal_matches(qualification, proposal):
        if proposal is None: return True
        context = qualification.get("context")
        return (isinstance(context, dict) and proposal.get("context") == context
                and proposal.get("context_digest") == qualification.get("context_digest")
                and proposal.get("replicas") == context.get("desired_replicas")
                and proposal.get("max_replicas") == context.get("max_replicas")
                and isinstance(context.get("model_version"), str) and bool(context["model_version"]))

    @staticmethod
    def capacity_proposal(context):
        """Bind the actual planned deployment and configured capacity facts.

        Confidence is 1 for the supplied deterministic configuration snapshot;
        this does not predict operational success or substitute for readback.
        """
        if not isinstance(context, dict) or not context.get("environment") or not context.get("model_version"):
            raise QualificationAdapterError("Deployment context must name environment and model_version")
        if any(type(context.get(k)) is not int or context[k] < 1 for k in ("desired_replicas", "max_replicas")):
            raise QualificationAdapterError("Deployment context must provide positive integer replica facts")
        return {"action_type": "scale", "replicas": context["desired_replicas"], "max_replicas": context["max_replicas"],
                "confidence": 1, "confidence_basis": "deterministic-current-configuration",
                "context": copy.deepcopy(context), "context_digest": canonical_digest({"environment": context})}

    def demote(self, skill, version, context, reason="KNOWN_FAILURE"):
        with self.lock:
            state = self._state(canonical_digest({"skill": skill, "version": version}), canonical_digest({"environment": context}))
            state["engine"].demote(state["agent"], reason=reason)
            return self._cascade_report(state)

    def challenge(self, proposal):
        base = {"implementation": "gcl.falsification.gate.FalsificationGate", "source_revision": GCL_REVISION,
                "scope": "supporting-deployment-capacity", "advisory": True, "executed": False,
                "outcome": None, "authority": None, "network_calls": 0}
        if proposal is None: return {**base, "verdict": "NOT_CONFIGURED", "failed_check": None}
        if proposal.get("action_type") != "scale" or any(type(proposal.get(k)) is not int or proposal[k] < 1 for k in ("replicas", "max_replicas")):
            return {**base, "verdict": "INVALID_PROPOSAL", "failed_check": "invalid_capacity_input"}
        if type(proposal.get("confidence")) not in (int, float) or not 0 <= proposal["confidence"] <= 1:
            return {**base, "verdict": "INVALID_PROPOSAL", "failed_check": "invalid_confidence"}
        env = {k: v for k, v in os.environ.items() if not k.startswith("GCL_")}
        env["GCL_FORCE_DETERMINISTIC"] = "true"
        completed = subprocess.run([sys.executable, "-m", "earned_authority.qualification_client", "--gcl-worker"],
            input=json.dumps({"root": str(self.gcl_root), "proposal": proposal}), text=True,
            capture_output=True, timeout=15, cwd=Path(__file__).resolve().parents[1], env=env)
        if completed.returncode: raise QualificationAdapterError("Canonical deterministic GCL worker failed: " + completed.stderr[-1000:])
        result = json.loads(completed.stdout)
        if result.get("network_calls") != 0: raise QualificationAdapterError("GCL attempted a prohibited network call")
        return {**base, **result}


def _gcl_worker(payload):
    root = _checked_source(payload["root"], "gcl")
    sys.path.insert(0, str(root))
    from gcl.domain.contracts import ActionStep, Constraint, Evidence, Trajectory, TrajectoryPoint
    from gcl.domain.enums import ConstraintSource, ConstraintType
    from gcl.falsification.gate import FalsificationGate
    from gcl.inference.client import set_force_rules
    set_force_rules(True)
    calls = []
    original_connect = socket.socket.connect
    def no_network(sock, address):
        calls.append(str(address)); raise RuntimeError("Network is prohibited in deterministic GCL mode")
    proposal = payload["proposal"]
    evidence = Evidence(metric="max_replicas", value=proposal["max_replicas"], source="context-bound-deployment-capacity")
    constraint = Constraint(type=ConstraintType.CAPACITY, bound=proposal["max_replicas"], hard=True,
        justification_evidence_ids=[evidence.id], confidence=1, source=ConstraintSource.DETERMINISTIC)
    action = ActionStep(step_index=0, action_type="scale", parameters={"replicas": proposal["replicas"]})
    trajectory = Trajectory(points=[TrajectoryPoint(step=0, value=proposal["replicas"])], horizon_steps=1, confidence=proposal["confidence"])
    socket.socket.connect = no_network
    try: result = asyncio.run(FalsificationGate().falsify(action, trajectory, [constraint], [evidence]))
    finally: socket.socket.connect = original_connect
    return {"verdict": result.verdict.value, "failed_check": result.failed_check,
            "reasoning": result.reasoning, "network_calls": len(calls), "deterministic": True,
            "proposal_digest": "sha256:" + hashlib.sha256(json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


if __name__ == "__main__":
    if sys.argv[1:] != ["--gcl-worker"]: raise SystemExit("Only the isolated GCL worker entry point is supported")
    print(json.dumps(_gcl_worker(json.load(sys.stdin))))
