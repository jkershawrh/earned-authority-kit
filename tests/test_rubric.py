import hashlib
import tempfile
from pathlib import Path
import unittest
from earned_authority.rubric import assess, release_status, verify_artifact


class RubricTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root / "reports").mkdir()
        (self.root / "reports/run.log").write_bytes(b"test output")
        digest = "sha256:" + hashlib.sha256(b"test output").hexdigest()
        self.req = {
            "id": "AUTH-01", "target_revision": "snapshot-a", "environment": "integration",
            "required_methods": ["TDD", "CDD"], "max_age_ms": 1000,
        }
        self.now = 10000
        self.records = [dict(requirement_id="AUTH-01", revision="snapshot-a", environment="integration",
                             method=m, outcome="PASS", timestamp_ms=9500, executed=True,
                             artifact="reports/run.log", artifact_digest=digest)
                        for m in self.req["required_methods"]]

    def check_status(self, status, records=None):
        result = assess(self.req, self.records if records is None else records, self.now, self.root)
        self.assertEqual(status, result["status"], result)
        self.assertTrue(result["reason"])

    def test_complete_current_evidence_is_green(self):
        self.check_status("GREEN")

    def test_missing_evidence_is_amber(self):
        self.check_status("AMBER", [])

    def test_one_missing_method_is_amber(self):
        self.check_status("AMBER", self.records[:1])

    def test_known_failure_dominates_pass(self):
        self.records.append(dict(self.records[0], outcome="FAIL"))
        self.check_status("RED")

    def test_component_pass_cannot_satisfy_integration(self):
        for r in self.records: r["environment"] = "component"
        self.check_status("AMBER")

    def test_previous_revision_cannot_satisfy_current(self):
        for r in self.records: r["revision"] = "snapshot-old"
        self.check_status("AMBER")

    def test_stale_pass_is_amber(self):
        for r in self.records: r["timestamp_ms"] = 8999
        self.check_status("AMBER")

    def test_stale_failure_remains_red_until_revision_changes(self):
        self.records.append(dict(self.records[0], outcome="FAIL", timestamp_ms=1))
        self.check_status("RED")

    def test_future_timestamp_is_amber(self):
        for r in self.records: r["timestamp_ms"] = 10001
        self.check_status("AMBER")

    def test_unexecuted_scenario_is_amber(self):
        for r in self.records: r["executed"] = False
        self.check_status("AMBER")

    def test_unknown_and_skipped_are_amber(self):
        for outcome in ("UNKNOWN", "SKIP"):
            with self.subTest(outcome=outcome):
                self.check_status("AMBER", [dict(r, outcome=outcome) for r in self.records])

    def test_no_artifact_digest_cannot_be_green(self):
        for r in self.records: r.pop("artifact_digest")
        self.check_status("AMBER")

    def test_different_requirement_does_not_count(self):
        for r in self.records: r["requirement_id"] = "OTHER"
        self.check_status("AMBER")

    def test_empty_required_methods_are_invalid(self):
        self.req["required_methods"] = []
        with self.assertRaises(ValueError): assess(self.req, [], self.now, self.root)

    def test_release_is_worst_required_status(self):
        green = {"requirement_id":"A", "status":"GREEN"}
        self.assertEqual("AMBER", release_status([], []))
        self.assertEqual("GREEN", release_status([green], ["A"]))
        self.assertEqual("AMBER", release_status([green], ["A", "B"]))
        self.assertEqual("AMBER", release_status([green,{"requirement_id":"B","status":"AMBER"}], ["A","B"]))
        self.assertEqual("RED", release_status([green,{"requirement_id":"B","status":"RED"}], ["A","B"]))
        with self.assertRaises(ValueError): release_status([dict(green,status="PURPLE")], ["A"])
        with self.assertRaises(ValueError): release_status([green, green], ["A"])


class ArtifactTests(unittest.TestCase):
    def test_hash_is_recomputed_and_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "run.log"
            artifact.write_bytes(b"measured output")
            record = {"artifact":"run.log", "artifact_digest":"sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest()}
            self.assertTrue(verify_artifact(record, folder))
            artifact.write_bytes(b"changed output")
            self.assertFalse(verify_artifact(record, folder))

    def test_external_artifacts_cannot_satisfy_local_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            for path in ("../outside.log", "/etc/hosts"):
                self.assertFalse(verify_artifact({"artifact":path, "artifact_digest":"sha256:"+"a"*64}, folder))

    def test_unverified_pass_cannot_turn_green(self):
        case = RubricTests(); case.setUp(); self.addCleanup(case.doCleanups)
        for record in case.records:
            record["artifact_verified"] = True
            record["artifact"] = "nonexistent.log"
        case.check_status("AMBER")


class ReviewRegressions(unittest.TestCase):
    def test_claimed_artifact_verification_cannot_forge_green(self):
        case = RubricTests(); case.setUp(); self.addCleanup(case.doCleanups)
        for r in case.records:
            r["artifact"] = "reports/does-not-exist.log"
            r["artifact_verified"] = True
        case.check_status("AMBER")

    def test_newer_unknown_supersedes_old_pass(self):
        case = RubricTests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.records.append(dict(case.records[0], outcome="UNKNOWN", timestamp_ms=9999))
        case.check_status("AMBER")


class SkippedRunRegression(unittest.TestCase):
    def test_newer_unexecuted_skip_blocks_old_pass(self):
        case = RubricTests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.records.append(dict(case.records[0], outcome="SKIP", timestamp_ms=9999, executed=False))
        case.check_status("AMBER")
