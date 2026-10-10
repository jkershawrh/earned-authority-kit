"""Actual canonical in-process Cascade and isolated deterministic GCL calls.

The independent observations come from executed SQLite fixture procedures and
Ed25519 checker signatures. Canonical engines are not replaced with stubs.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from earned_authority.qualification_client import QualificationAdapterError, QualificationClient
from earned_authority.runtime import ControlledClock, Runtime


class QualificationClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.clock = ControlledClock(now_ms=1_000_000)
        self.rt = Runtime(Path(self.tmp.name) / "runtime.sqlite", clock=self.clock)
        self.addCleanup(self.rt.close)
        self.client = QualificationClient()
        self.context = {"environment": "demo-a", "model_version": "model-v2", "desired_replicas": 1, "max_replicas": 2}
        self.seq = 0

    def observe(self, **changes):
        self.seq += 1
        args = dict(skill="release-model", version="skill-v1", context=self.context,
                    attempt_id=f"shadow-{self.seq}", expected="model-v2", actual="model-v2")
        args.update(changes)
        return self.rt.shadow(**args)

    def qualification(self, count=3, **changes):
        for _ in range(count): self.observe(**changes)
        return self.rt.qualify("release-model", changes.get("version", "skill-v1"), self.context)

    def proposal(self, q, **changes):
        p = dict(action_type="scale", replicas=self.context["desired_replicas"],
                 max_replicas=self.context["max_replicas"], confidence=1.0,
                 context=copy.deepcopy(self.context), context_digest=q["context_digest"])
        p.update(changes)
        return p

    def assess(self, q, proposal=True, observations=None):
        return self.client.evaluate(q, self.rt.observations() if observations is None else observations,
            verify_observation=lambda o: self.rt._verified(o, {"checker"}),
            now_ms=self.clock.now_ms, proposal=self.proposal(q) if proposal is True else proposal)

    def test_CDD_Q01_actual_cascade_promotes_demo_three_verified_passes(self):
        q = self.qualification(); result = self.assess(q)
        self.assertEqual("ELIGIBLE", result["disposition"])
        self.assertEqual("nano", result["cascade"]["tier"])
        self.assertTrue(result["cascade"]["active"])
        self.assertEqual(3, result["cascade"]["samples_tested"])
        self.assertEqual(["candidate", "nano"], [e["to_tier"] for e in result["cascade"]["events"]])
        self.assertEqual("cascade_compression.cascade.promotion.PromotionEngine", result["cascade"]["implementation"])
        self.assertEqual("demo-three-pass", result["policy_profile"])

    def test_CDD_Q02_actual_gcl_capacity_gate_is_advisory_and_network_free(self):
        q = self.qualification(); result = self.assess(q)
        gcl = result["gcl"]
        self.assertEqual("survives", gcl["verdict"])
        self.assertEqual("gcl.falsification.gate.FalsificationGate", gcl["implementation"])
        self.assertIs(gcl["advisory"], True)
        self.assertIs(gcl["executed"], False)
        self.assertIsNone(gcl["outcome"])
        self.assertIsNone(gcl["authority"])
        self.assertEqual(0, gcl["network_calls"])
        self.assertEqual("supporting-deployment-capacity", gcl["scope"])

    def test_CDD_Q03_real_gcl_capacity_failure_blocks_eligibility_not_outcome(self):
        self.context["desired_replicas"] = 3
        q = self.qualification(); result = self.assess(q)
        self.assertEqual("INELIGIBLE", result["disposition"])
        self.assertEqual("GCL_PROPOSAL_REJECTED", result["reason"])
        self.assertEqual("capacity_overcommit", result["gcl"]["failed_check"])
        self.assertTrue(all(o["outcome"] == "PASS" for o in self.rt.observations()))
        self.assertFalse(self.rt.authority("agent-a")["grants"])

    def test_CDD_Q04_missing_gcl_is_not_claimed_as_pass(self):
        q = self.qualification(); result = self.assess(q, proposal=None)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual("GCL_NOT_CONFIGURED", result["reason"])
        self.assertEqual("NOT_CONFIGURED", result["gcl"]["verdict"])

    def test_CDD_Q05_changed_capacity_cannot_reuse_context_qualification(self):
        q = self.qualification()
        changed = self.proposal(q, max_replicas=1)
        result = self.assess(q, proposal=changed)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual("PROPOSAL_CONTEXT_MISMATCH", result["reason"])

    def test_CDD_Q06_unknown_does_not_enter_cascade_failure_counts(self):
        self.observe(); self.observe(); self.observe(observer_available=False)
        q = self.rt.qualify("release-model", "skill-v1", self.context)
        result = self.assess(q)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual("EVIDENCE_UNCONFIRMED", result["reason"])
        self.assertEqual(0, result["failures"])
        self.assertEqual(2, result["passes"])
        self.assertFalse(result["cascade"]["deactivated"])

    def test_CDD_Q07_known_miss_calls_canonical_instant_demotion(self):
        q = self.qualification(); self.assess(q)
        self.observe(actual="model-v1")
        q2 = self.rt.qualify("release-model", "skill-v1", self.context)
        result = self.assess(q2)
        self.assertEqual("INELIGIBLE", result["disposition"])
        self.assertEqual("draft", result["cascade"]["tier"])
        self.assertTrue(result["cascade"]["deactivated"])
        self.assertTrue(any(e["event_type"] == "demotion" for e in result["cascade"]["events"]))
        self.assertEqual(1, result["failures"])

    def test_CDD_Q08_untrusted_signed_observations_cannot_promote(self):
        q = self.qualification(signer="untrusted-checker")
        result = self.assess(q)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual(0, result["passes"])
        self.assertFalse(result["cascade"]["active"])

    def test_CDD_Q09_authenticated_self_report_is_not_independent(self):
        q = self.qualification(independent=False); result = self.assess(q)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual(0, result["passes"])
        self.assertFalse(result["cascade"]["active"])

    def test_CDD_Q10_duplicate_delivery_does_not_inflate_canonical_samples(self):
        q = self.qualification(); observations = self.rt.observations()
        first = self.assess(q, observations=observations * 3)
        second = self.assess(q, observations=observations * 2)
        self.assertEqual(3, first["cascade"]["samples_tested"])
        self.assertEqual(3, second["cascade"]["samples_tested"])

    def test_CDD_Q11_changed_signed_evidence_cannot_be_counted(self):
        q = self.qualification(); observations = copy.deepcopy(self.rt.observations())
        observations[0]["readback"]["version"] = "tampered"
        result = self.assess(q, observations=observations)
        self.assertEqual("HOLD", result["disposition"])
        self.assertFalse(result["cascade"]["active"])

    def test_CDD_Q12_stale_evidence_holds_without_failure(self):
        q = self.qualification(); self.clock.advance(600_001)
        result = self.assess(q)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual("STALE_EVIDENCE", result["reason"])
        self.assertEqual(0, result["failures"])

    def test_CDD_Q13_referenced_outcome_cannot_be_silently_omitted(self):
        q = self.qualification(); result = self.assess(q, observations=self.rt.observations()[:2])
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual("MISSING_REFERENCED_EVIDENCE", result["reason"])

    def test_CDD_Q14_new_skill_revision_requires_fresh_canonical_metrics(self):
        q = self.qualification(); self.assess(q)
        q2 = self.qualification(count=1, version="skill-v2")
        result = self.assess(q2)
        self.assertEqual("HOLD", result["disposition"])
        self.assertEqual(1, result["cascade"]["samples_tested"])
        self.assertFalse(result["cascade"]["active"])

    def test_CDD_Q15_canonical_threshold_defaults_remain_unchanged(self):
        self.assertEqual(200, self.client.canonical_defaults["nano"]["min_samples"])
        self.assertEqual(50, self.client.canonical_defaults["candidate"]["min_samples"])
        self.assertEqual(0.0, self.client.canonical_defaults["nano"]["max_false_negative"])

    def test_CDD_Q16_portable_capacity_fixtures_use_actual_canonical_checks(self):
        cases = json.loads((Path(__file__).resolve().parents[1] / "contracts/fixtures/qualification-client-cases.json").read_text())
        for case in cases["cases"]:
            with self.subTest(case=case["id"]):
                self.context = case["context"]
                q = self.qualification()
                result = self.assess(q, proposal=self.client.capacity_proposal(self.context))
                self.assertEqual(case["expected_disposition"], result["disposition"])
                self.assertEqual(case["expected_gcl_verdict"], result["gcl"]["verdict"])
                self.assertTrue(all(o["outcome"] == case["independent_outcome"] for o in self.rt.observations()))

    def test_CDD_Q17_changed_canonical_source_is_rejected(self):
        wrong_root = Path(self.tmp.name) / "changed-cascade"
        wrong_file = wrong_root / "cascade_compression/cascade/promotion.py"
        wrong_file.parent.mkdir(parents=True)
        wrong_file.write_text("# modified source cannot inherit a canonical pin\n")
        with self.assertRaises(QualificationAdapterError):
            QualificationClient(cascade_root=wrong_root)


if __name__ == "__main__": unittest.main(verbosity=2)
