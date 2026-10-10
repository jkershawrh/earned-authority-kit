"""M1 local-fixture bindings for BDD-001..037; BDD-038 remains future scope.

These bindings exercise the controller and persisted fixture state, including
independent readback. They do not establish live Foundation/service integration
or production readiness. Outline rows have separate unittest method names.
"""
import copy
import json
import re
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from earned_authority.runtime import ControlledClock, Denied, Runtime
from earned_authority.contracts import canonical_digest


class LifecycleBDD(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "runtime.sqlite"
        self.clock = ControlledClock(now_ms=1_000_000)
        self.rt = Runtime(self.path, clock=self.clock)
        self.addCleanup(lambda: self.rt.close())
        self.seq = 0

    def next_id(self, prefix="shadow"):
        self.seq += 1
        return f"{prefix}-{self.seq}"

    def shadow(self, **changes):
        args = dict(skill="release-model", version="skill-v1", context="demo-a",
                    attempt_id=self.next_id(), expected="model-v2", actual="model-v2")
        args.update(changes)
        return self.rt.shadow(**args)

    def qualify(self, skill="release-model", version="skill-v1", context="demo-a"):
        for _ in range(3):
            self.shadow(skill=skill, version=version, context=context)
        q = self.rt.qualify(skill, version, context)
        self.assertEqual("ELIGIBLE", q["disposition"], q)
        return q

    def granted(self, **grant_args):
        q = self.qualify()
        authority = self.rt.grant(q["qualification_id"], **grant_args)
        return q, authority

    def admit(self, attempt_id=None, **changes):
        args = dict(agent="agent-a", skill="release-model", version="skill-v1",
                    context="demo-a", action="release", resource="registry-a/model-a",
                    target="model-v2", attempt_id=attempt_id or self.next_id("attempt"))
        args.update(changes)
        return self.rt.admit(**args)

    def execute(self, attempt_id=None, **changes):
        return self.rt.commit(self.admit(attempt_id, **changes))

    def deny_unchanged(self, callback, reason=None):
        before = copy.deepcopy(self.rt.read("registry-a/model-a"))
        count = self.rt.mutation_count
        with self.assertRaises(Denied) as caught:
            callback()
        if reason:
            self.assertEqual(reason, caught.exception.reason)
        self.assertEqual(before, self.rt.read("registry-a/model-a"))
        self.assertEqual(count, self.rt.mutation_count)
        return caught.exception

    def restart(self):
        ledger = self.rt.ledger
        self.rt.close()
        self.rt = Runtime(self.path, clock=self.clock, ledger=ledger)

    def two_grants(self):
        release_q, _ = self.granted()
        read_q = self.qualify("read-health", "read-v1")
        self.rt.grant(read_q["qualification_id"], action="read", resource="registry-a/model-a")
        return release_q, read_q

    def assert_read_allowed(self):
        count = self.rt.mutation_count
        self.execute(skill="read-health", version="read-v1", action="read")
        self.assertEqual(count, self.rt.mutation_count)

    def recorded_event(self):
        rows = [row for row in self.rt.events() if row["delivery"] == "RECORDED"]
        self.assertTrue(rows, "An actual local-fixture ledger receipt is required")
        return rows[-1]

    def test_BDD_001_fresh_independent_outcomes_qualify_only(self):
        observations = [self.shadow() for _ in range(3)]
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual("ELIGIBLE", q["disposition"])
        self.assertEqual(3, q["passes"])
        self.assertEqual(3, len(q["outcome_refs"]))
        self.assertEqual(3, len({o["attempt_id"] for o in observations}))
        actual_refs = {r["attempt_id"]: r["evidence_digest"] for r in q["outcome_refs"]}
        expected_refs = {}
        for observation in observations:
            signed_payload = {k: v for k, v in observation.items() if k != "evidence_digest"}
            recomputed = canonical_digest(signed_payload)
            self.assertEqual(recomputed, observation["evidence_digest"])
            expected_refs[observation["attempt_id"]] = recomputed
        self.assertEqual(expected_refs, actual_refs)
        self.assertEqual({o["observation_id"] for o in observations}, {r["observation_id"] for r in q["outcome_refs"]})
        for key in ("skill_digest", "context_digest", "evaluator_digest", "policy_digest"):
            self.assertTrue(q[key].startswith("sha256:"), key)
        self.assertFalse(self.rt.authority("agent-a")["grants"])
        self.assertEqual(0, self.rt.mutation_count)
        self.assertEqual("model-v1", self.rt.read("registry-a/model-a")["version"])

    def test_BDD_002_self_report_is_not_independent_evidence(self):
        for _ in range(3):
            self.shadow(independent=False)
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual("HOLD", q["disposition"])
        self.assertEqual("INSUFFICIENT_EVIDENCE", q["reason"])
        self.assertEqual(0, q["passes"])
        self.deny_unchanged(lambda: self.rt.grant(q["qualification_id"]))

    def _eligibility_mismatch(self, version, context, reason):
        q = self.qualify()
        with self.assertRaises(Denied) as caught:
            self.rt.eligibility(q["qualification_id"], version, context)
        self.assertEqual(reason, caught.exception.reason)
        self.assertEqual("ELIGIBLE", self.rt.eligibility(q["qualification_id"], "skill-v1", "demo-a")["disposition"])

    def test_BDD_003_changed_skill(self):
        self._eligibility_mismatch("skill-v2", "demo-a", "SKILL_REVISION_MISMATCH")

    def test_BDD_003_changed_environment(self):
        self._eligibility_mismatch("skill-v1", "demo-b", "QUALIFICATION_CONTEXT_MISMATCH")

    def test_BDD_004_unknown_is_neither_pass_nor_failure(self):
        self.shadow(); self.shadow(); unknown = self.shadow(observer_available=False)
        self.assertEqual("UNKNOWN", unknown["outcome"])
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual("HOLD", q["disposition"])
        self.assertEqual((2, 0), (q["passes"], q["failures"]))
        self.assertTrue(unknown["reason"])
        self.deny_unchanged(lambda: self.rt.grant(q["qualification_id"]))

    def test_BDD_005_stale_passes_hold_qualification(self):
        for _ in range(3): self.shadow()
        self.clock.advance(self.rt.evidence_window_ms + 1)
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual("HOLD", q["disposition"])
        self.assertEqual("STALE_EVIDENCE", q["reason"])
        self.assertTrue(all(o["outcome"] == "PASS" for o in self.rt.observations()))
        self.deny_unchanged(lambda: self.rt.grant(q["qualification_id"]))

    def test_BDD_006_duplicate_attempt_cannot_inflate_qualification(self):
        for _ in range(3): self.shadow(attempt_id="one-shadow")
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual(1, q["passes"])
        self.assertEqual("HOLD", q["disposition"])
        self.assertEqual("INSUFFICIENT_EVIDENCE", q["reason"])

    def test_BDD_007_known_failure_prevents_qualification(self):
        for _ in range(3): self.shadow()
        self.shadow(actual="model-v1")
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual("INELIGIBLE", q["disposition"])
        self.assertEqual("KNOWN_FAILURE", q["reason"])
        self.assertEqual((3, 1), (q["passes"], q["failures"]))
        self.assertEqual(4, len(self.rt.observations()))

    def test_BDD_008_policy_grants_exact_bounded_authority(self):
        q, a = self.granted(ttl_ms=300_000)
        g = a["grants"]["release-model"]
        self.assertEqual("release", g["action"])
        self.assertEqual("registry-a/model-a", g["resource"])
        self.assertEqual(q["qualification_id"], g["qualification_id"])
        self.assertEqual(q["skill_digest"], g["skill_digest"])
        self.assertEqual(q["context_digest"], g["context_digest"])
        self.assertLessEqual(a["expires_at_ms"], self.clock.now_ms + 300_000)
        self.assertLessEqual(g["expires_at_ms"], q["expires_at_ms"])
        command = self.admit()
        for key in ("skill_digest", "context_digest", "qualification_digest", "policy_digest"):
            self.assertTrue(command[key].startswith("sha256:"), key)
        self.assertEqual(a["revision"], command["authority_revision"])

    def test_BDD_009_qualification_cannot_override_policy_denial(self):
        q = self.qualify()
        self.deny_unchanged(lambda: self.rt.grant(q["qualification_id"], policy_allow=False))
        self.assertFalse(self.rt.authority("agent-a")["grants"])
        self.assertEqual("ELIGIBLE", self.rt.eligibility(q["qualification_id"], "skill-v1", "demo-a")["disposition"])

    def _wrong_grant(self, **changes):
        self.granted()
        self.deny_unchanged(lambda: self.execute(**changes))

    def test_BDD_010_wrong_action(self): self._wrong_grant(action="delete")
    def test_BDD_010_wrong_resource(self): self._wrong_grant(resource="registry-a/model-b")
    def test_BDD_010_wrong_context(self): self._wrong_grant(context="demo-b")
    def test_BDD_010_changed_revision(self): self._wrong_grant(version="skill-v2")

    def test_BDD_011_expiry_equality_denies_passport(self):
        _, authority = self.granted(ttl_ms=300_000)
        self.clock.advance(authority["expires_at_ms"] - self.clock.now_ms)
        self.deny_unchanged(lambda: self.execute(), "EXPIRED_PASSPORT")

    def test_BDD_012_scope_expiry_precedes_passport(self):
        _, authority = self.granted(ttl_ms=300_000, scope_ttl_ms=60_000)
        self.clock.advance(60_000)
        self.assertGreater(authority["expires_at_ms"], self.clock.now_ms)
        self.deny_unchanged(lambda: self.execute(), "EXPIRED_SCOPE")

    def test_BDD_013_revocation_invalidates_prior_admission(self):
        self.granted(); command = self.admit()
        self.rt.revoke("agent-a", "release-model")
        self.deny_unchanged(lambda: self.rt.commit(command), "REVOKED_AUTHORITY")

    def _invalid_expiry(self, value, remove=False):
        _, snapshot = self.granted()
        snapshot = copy.deepcopy(snapshot)
        if remove: snapshot.pop("expires_at_ms")
        else: snapshot["expires_at_ms"] = value
        with self.assertRaises(Denied) as caught: self.rt.validate_authority(snapshot)
        self.assertEqual("INVALID_AUTHORITY", caught.exception.reason)

    def test_BDD_014_missing_expiry(self): self._invalid_expiry(None, remove=True)
    def test_BDD_014_invalid_expiry(self): self._invalid_expiry("not-a-timestamp")

    def test_BDD_015_unconfirmed_authority_denies_new_mutation(self):
        self.granted(); self.rt.authority_available = False
        self.deny_unchanged(lambda: self.execute(), "AUTHORITY_UNCONFIRMED")

    def test_BDD_016_independent_postcondition_and_correlation(self):
        self.granted(); command = self.admit("attempt-1")
        result = self.rt.commit(command)
        self.assertEqual("COMMITTED", result["state"])
        self.assertEqual("PASS", result["outcome"]["outcome"])
        self.assertEqual({"version": "model-v2", "healthy": True}, self.rt.read("registry-a/model-a"))
        self.assertEqual("attempt-1", result["attempt_id"])
        self.assertEqual("attempt-1", result["outcome"]["attempt_id"])
        self.assertEqual(command["authority_revision"], result["authority_revision"])
        self.assertEqual(1, self.rt.mutation_count)
        self.assertTrue([r for r in self.rt.events() if r["event"].get("attempt_id") == "attempt-1"])

    def test_BDD_017_wrong_observed_postcondition_is_failure(self):
        self.granted()
        result = self.rt.commit(self.admit(), actual="model-v1")
        self.assertEqual("model-v1", self.rt.read("registry-a/model-a")["version"])
        self.assertEqual("FAIL", result["outcome"]["outcome"])
        self.assertEqual("POSTCONDITION_NOT_MET", result["outcome"]["reason"])

    def test_BDD_017_correct_version_with_unhealthy_state_is_failure(self):
        self.granted()
        result = self.rt.commit(self.admit(), healthy=False)
        self.assertEqual({"version": "model-v2", "healthy": False}, self.rt.read("registry-a/model-a"))
        self.assertEqual("FAIL", result["outcome"]["outcome"])
        self.assertEqual("POSTCONDITION_NOT_MET", result["outcome"]["reason"])

    def test_BDD_018_unavailable_observer_is_unknown_and_holds(self):
        self.granted()
        result = self.rt.commit(self.admit("unknown-1"), observer_available=False)
        self.assertEqual("COMMITTED", result["state"])
        self.assertEqual("UNKNOWN", result["outcome"]["outcome"])
        self.assertEqual("OBSERVATION_UNAVAILABLE", result["outcome"]["reason"])
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])
        self.rt.apply_outcome("unknown-1")
        self.deny_unchanged(lambda: self.execute())
        self.assertFalse(any(o["outcome"] == "FAIL" for o in self.rt.observations()))

    def test_BDD_019_completed_retry_returns_result_without_mutation(self):
        self.granted(); first = self.execute("attempt-1")
        second = self.execute("attempt-1")
        self.assertEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(first["state"], second["state"])
        self.assertEqual(1, self.rt.mutation_count)

    def test_BDD_020_changed_retry_payload_is_rejected(self):
        self.granted(); self.execute("attempt-1")
        self.deny_unchanged(lambda: self.execute("attempt-1", target="model-v3"), "IDEMPOTENCY_CONFLICT")

    def test_BDD_021_lost_response_reconciles_after_restart(self):
        self.granted(); command = self.admit("attempt-1")
        with self.assertRaises(TimeoutError): self.rt.commit(command, lose_response=True)
        self.restart()
        result = self.execute("attempt-1")
        self.assertEqual("COMMITTED", result["state"])
        self.assertEqual(1, self.rt.mutation_count)
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])

    def test_BDD_021_crash_after_mutation_before_observation_reconciles(self):
        self.granted(); command = self.admit("observer-crash")
        original_read = self.rt.read
        def crash_during_read(resource):
            raise RuntimeError("injected observer process crash after registry commit")
        self.rt.read = crash_during_read
        with self.assertRaises(RuntimeError): self.rt.commit(command)
        self.rt.read = original_read
        self.assertEqual(1, self.rt.mutation_count)
        self.restart()
        result = self.execute("observer-crash")
        self.assertEqual("COMMITTED", result["state"])
        self.assertIsNotNone(result["outcome"], "A durable unfinished observation must be reconciled")
        self.assertEqual("PASS", result["outcome"]["outcome"])
        self.assertEqual(1, self.rt.mutation_count)
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])

    def test_BDD_021_unavailable_reconciliation_never_blindly_repeats(self):
        self.granted(); command = self.admit("uncertain-retry")
        with self.assertRaises(TimeoutError): self.rt.commit(command, lose_response=True)
        self.restart()
        self.rt.reconciliation_available = False
        before = self.rt.mutation_count
        try:
            result = self.execute("uncertain-retry")
        except Denied as exc:
            self.assertEqual("RECONCILIATION_UNAVAILABLE", exc.reason)
        else:
            self.assertEqual("UNKNOWN", result["state"])
        self.assertEqual(before, self.rt.mutation_count)

    def test_BDD_022_foundation_check_only_is_not_execution(self):
        result = self.rt.record_check_only("check-1", dict(decision="ALLOW", executed=False, receipt_created=False))
        self.assertEqual("AUTHORIZATION_CHECKED", result["state"])
        self.assertIs(result["executed"], False)
        self.assertIs(result["receipt_created"], False)
        self.assertIsNone(result["outcome"])
        self.assertEqual("NONE", result["delivery"])
        self.assertEqual(0, self.rt.mutation_count)
        self.assertEqual("model-v1", self.rt.read("registry-a/model-a")["version"])

    def test_BDD_023_known_failure_demotes_despite_remote_outage(self):
        self.two_grants()
        self.rt.ledger.available = False
        before = self.rt.authority("agent-a")["revision"]
        result = self.rt.commit(self.admit("bad-1"), actual="model-v1")
        self.assertEqual("FAIL", result["outcome"]["outcome"])
        revoked_revision = self.rt.authority("agent-a")["revision"]
        self.assertGreater(revoked_revision, before)
        self.rt.apply_outcome("bad-1")
        self.assertEqual(revoked_revision, self.rt.authority("agent-a")["revision"])
        self.deny_unchanged(lambda: self.execute())
        pending = [r for r in self.rt.events() if r["delivery"] == "PENDING"]
        self.assertTrue(any(r["event"].get("event_type") == "REVOKED" for r in pending))

    def test_BDD_024_selective_withdrawal_preserves_other_grant(self):
        _, read_q = self.two_grants(); old_command = self.admit()
        self.rt.revoke("agent-a", "release-model")
        current = self.rt.authority("agent-a")
        self.assertNotIn("release-model", current["grants"])
        self.assertEqual(read_q["qualification_id"], current["grants"]["read-health"]["qualification_id"])
        self.assert_read_allowed()
        self.deny_unchanged(lambda: self.rt.commit(old_command))

    def _evidence_hold(self, state):
        release_q, _ = self.two_grants()
        self.rt.reevaluate("agent-a", "release-model", state=state)
        self.assertEqual("HOLD", self.rt.qualification(release_q["qualification_id"])["disposition"])
        self.deny_unchanged(lambda: self.execute())
        self.assertFalse(any(o["outcome"] == "FAIL" for o in self.rt.observations()))
        self.assert_read_allowed()

    def test_BDD_025_missing_result(self): self._evidence_hold("UNKNOWN")
    def test_BDD_025_old_result(self): self._evidence_hold("STALE")

    def test_BDD_026_revised_skill_requalifies_under_new_grant(self):
        self.granted(); self.rt.revoke("agent-a", "release-model")
        new_q = self.qualify(version="skill-v2")
        a = self.rt.grant(new_q["qualification_id"])
        self.assertEqual(new_q["qualification_id"], a["grants"]["release-model"]["qualification_id"])
        self.deny_unchanged(lambda: self.execute(version="skill-v1"))
        self.assertEqual("COMMITTED", self.execute(version="skill-v2")["state"])
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])
        reinstatements = [r["event"] for r in self.rt.events() if r["event"]["event_type"] == "REQUALIFIED"]
        self.assertTrue(reinstatements, "Reinstatement must link to its prior withdrawal")
        self.assertEqual(new_q["qualification_id"], reinstatements[-1]["qualification_id"])
        prior = reinstatements[-1]["prior_withdrawal_event_id"]
        self.assertTrue(any(r["event_id"] == prior and r["event"]["event_type"] == "REVOKED" for r in self.rt.events()))

    def test_BDD_027_manual_reactivation_cannot_bypass_qualification(self):
        self.granted(); self.rt.revoke("agent-a", "release-model")
        self.deny_unchanged(lambda: self.rt.reactivate("agent-a", "release-model"))
        self.deny_unchanged(lambda: self.execute())

    def test_BDD_028_concurrent_issue_has_one_current_revision(self):
        q, initial = self.granted(); barrier = threading.Barrier(2)
        def issue(resource):
            barrier.wait(timeout=5)
            try:
                return self.rt.grant(q["qualification_id"], resource=resource, expected_revision=initial["revision"])
            except Denied as exc:
                return exc
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(issue, ["registry-a/model-a", "registry-a/model-b"]))
        accepted = [r for r in results if isinstance(r, dict)]
        denied = [r for r in results if isinstance(r, Denied)]
        self.assertEqual((1, 1), (len(accepted), len(denied)))
        current = self.rt.authority("agent-a")
        self.assertEqual(initial["revision"] + 1, current["revision"])
        self.assertEqual(accepted[0]["passport_id"], current["passport_id"])
        self.assertEqual(accepted[0]["grants"], current["grants"])

    def test_BDD_029_acknowledged_revocation_fences_paused_commit(self):
        self.granted(); command = self.admit()
        admission_finished = threading.Event(); resume_commit = threading.Event()
        def paused_executor():
            admission_finished.set()
            self.assertTrue(resume_commit.wait(timeout=5))
            return self.rt.commit(command)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(paused_executor)
            self.assertTrue(admission_finished.wait(timeout=5))
            revoked = self.rt.revoke("agent-a", "release-model")
            self.assertGreater(revoked["revision"], command["authority_revision"])
            resume_commit.set()
            self.deny_unchanged(lambda: future.result(timeout=5))

    def test_BDD_030_prior_commit_remains_completed_after_revocation(self):
        self.granted(); command = self.admit("before-revoke")
        result = self.rt.commit(command)
        revoked = self.rt.revoke("agent-a", "release-model")
        self.assertEqual("COMMITTED", result["state"])
        self.assertEqual("COMMITTED", self.rt.attempts("before-revoke")["state"])
        self.assertGreater(revoked["revision"], result["authority_revision"])
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])
        self.deny_unchanged(lambda: self.execute())

    def test_BDD_031_stale_update_cannot_revive_revoked_skill(self):
        _, read_q = self.two_grants(); old = self.rt.authority("agent-a")
        self.rt.revoke("agent-a", "release-model")
        self.deny_unchanged(lambda: self.rt.grant(read_q["qualification_id"], action="read", resource="registry-a/model-b", expected_revision=old["revision"]))
        self.assertNotIn("release-model", self.rt.authority("agent-a")["grants"])
        self.assert_read_allowed()

    def test_BDD_032_concurrent_duplicate_attempt_commits_once(self):
        self.granted(); commands = [self.admit("one-attempt"), self.admit("one-attempt")]
        barrier = threading.Barrier(2)
        def commit(command):
            barrier.wait(timeout=5)
            return self.rt.commit(command)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(commit, commands))
        self.assertEqual(1, self.rt.mutation_count)
        self.assertEqual({"one-attempt"}, {r["attempt_id"] for r in results})
        self.assertEqual(1, len([o for o in self.rt.observations() if o["attempt_id"] == "one-attempt"]))
        self.assertTrue(all(r["outcome"] and r["outcome"]["outcome"] == "PASS" for r in results))
        self.assertEqual(1, len({r["outcome"]["observation_id"] for r in results}))
        # Resolving the same durable attempt remains stable after both callers finish.
        resolved = [self.execute("one-attempt") for _ in results]
        self.assertTrue(all(r["outcome"] and r["outcome"]["outcome"] == "PASS" for r in resolved))
        self.assertEqual(1, len({r["outcome"]["observation_id"] for r in resolved}))
        self.assertEqual(1, self.rt.mutation_count)

    def _local_intent_failure(self, fault, reason):
        self.granted(); setattr(self.rt, fault, False)
        self.deny_unchanged(lambda: self.execute(), reason)

    def test_BDD_033_local_store_down(self):
        self._local_intent_failure("local_durability_available", "LOCAL_DURABILITY_UNAVAILABLE")

    def test_BDD_033_unauthenticated_writer(self):
        self._local_intent_failure("local_writer_authenticated", "LOCAL_INTENT_UNAUTHENTICATED")

    def _remote_outage(self, after_commit):
        self.granted(); command = self.admit("ledger-outage")
        def disconnect(): self.rt.ledger.available = False
        if not after_commit: disconnect()
        result = self.rt.commit(command, before_delivery=disconnect if after_commit else None)
        self.assertEqual("COMMITTED", result["state"])
        self.assertEqual("PASS", result["outcome"]["outcome"])
        self.assertEqual("PENDING", result["delivery"])
        self.assertIsNone(result["receipt"])
        self.assertTrue(any(r["delivery"] == "PENDING" for r in self.rt.events()))
        self.assertIn("release-model", self.rt.authority("agent-a")["grants"])
        self.restart()
        self.assertEqual("model-v2", self.rt.read("registry-a/model-a")["version"])
        self.assertEqual("PASS", self.rt.attempts("ledger-outage")["outcome"]["outcome"])
        self.assertEqual(1, self.rt.mutation_count)
        self.rt.ledger.available = True
        self.rt.flush_outbox(); self.rt.flush_outbox()
        self.assertFalse(any(r["delivery"] == "PENDING" for r in self.rt.events()))
        self.assertEqual(1, self.rt.mutation_count)
        self.assertEqual(1, len([o for o in self.rt.observations() if o["attempt_id"] == "ledger-outage"]))

    def test_BDD_034_before_intent_send(self): self._remote_outage(False)
    def test_BDD_034_after_commit(self): self._remote_outage(True)

    def test_BDD_034_remote_audit_unavailable_preserves_known_outcome(self):
        q, _ = self.granted(); self.execute("known-pass")
        self.rt.ledger.available = False
        self.rt.audit_evidence("known-pass")
        self.assertEqual("PASS", self.rt.attempts("known-pass")["outcome"]["outcome"])
        self.assertEqual("ELIGIBLE", self.rt.qualification(q["qualification_id"])["disposition"])
        self.assertIn("release-model", self.rt.authority("agent-a")["grants"])

    def test_BDD_035_modified_ledger_evidence_fails_verification(self):
        q, _ = self.granted(); self.execute("tampered-attempt")
        row = self.recorded_event()
        self.assertTrue(self.rt.ledger.verify(row["receipt"], row["event"]))
        # Tamper with the persisted ledger copy, not the expected test result.
        self.rt.ledger.tamper(len(self.rt.ledger.entries) - 1)
        self.assertFalse(self.rt.ledger.verify(row["receipt"], row["event"]))
        with self.assertRaises(Denied) as caught:
            self.rt.audit_evidence("tampered-attempt")
        self.assertEqual("TAMPER_DETECTED", caught.exception.reason)
        self.assertEqual("HOLD", self.rt.qualification(q["qualification_id"])["disposition"])
        self.deny_unchanged(lambda: self.execute())

    def _receipt_replay(self, binding):
        self.granted(); self.execute("attempt-original")
        row = self.recorded_event(); expected = copy.deepcopy(row["event"])
        self.assertTrue(self.rt.ledger.verify(row["receipt"], expected))
        if binding == "attempt": expected["attempt_id"] = "attempt-other"
        elif binding == "skill": expected["skill_digest"] = "sha256:" + "f" * 64
        elif binding == "stale": self.clock.advance(600_001)
        else: self.fail("Unknown replay case")
        self.assertFalse(self.rt.ledger.verify(row["receipt"], expected, max_age_ms=600_000))
        self.assertEqual(1, self.rt.mutation_count)

    def test_BDD_036_other_attempt(self): self._receipt_replay("attempt")
    def test_BDD_036_old_skill(self): self._receipt_replay("skill")
    def test_BDD_036_expired_proof(self): self._receipt_replay("stale")

    def test_BDD_037_untrusted_signer_cannot_qualify(self):
        for _ in range(3): self.shadow(signer="untrusted-checker")
        self.rt.flush_outbox()
        recorded_observations = [r for r in self.rt.events() if r["event"]["event_type"] == "OUTCOME_OBSERVED"]
        self.assertEqual(3, len(recorded_observations))
        self.assertTrue(all(r["delivery"] == "RECORDED" for r in recorded_observations))
        self.assertTrue(all(self.rt.ledger.verify(r["receipt"], r["event"]) for r in recorded_observations))
        q = self.rt.qualify("release-model", "skill-v1", "demo-a")
        self.assertEqual(0, q["passes"])
        self.assertEqual("HOLD", q["disposition"])
        self.assertEqual("UNTRUSTED_ATTESTATION", q["reason"])
        self.deny_unchanged(lambda: self.rt.grant(q["qualification_id"]))


# Machine-readable scenario -> unittest-method map. Outline rows remain distinct.
BDD_BINDINGS = {}
for _method in unittest.defaultTestLoader.getTestCaseNames(LifecycleBDD):
    _scenario = "BDD-" + _method.split("_")[2]
    BDD_BINDINGS.setdefault(_scenario, []).append("LifecycleBDD." + _method)


class BindingCoverage(unittest.TestCase):
    def test_all_current_scenarios_have_explicit_bindings(self):
        feature_dir = Path(__file__).resolve().parents[1] / "features"
        required = set()
        for feature in feature_dir.glob("*.feature"):
            text = feature.read_text()
            if "@future" not in text:
                required.update(re.findall(r"@(BDD-\d{3})", text))
        self.assertEqual({f"BDD-{i:03}" for i in range(1, 38)}, required)
        self.assertEqual(required, set(BDD_BINDINGS))
        self.assertNotIn("BDD-038", BDD_BINDINGS)
        manifest = json.loads((feature_dir / "bindings.json").read_text())
        self.assertEqual(BDD_BINDINGS, manifest["bindings"])
        self.assertEqual(sum(map(len, BDD_BINDINGS.values())), manifest["behavioral_test_count"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
