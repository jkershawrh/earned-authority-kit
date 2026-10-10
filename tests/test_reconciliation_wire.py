"""CDD for real retry-produced uncertainty, separate from durable wire evidence.

Runtime is the explicit local unit fixture. Faults use actual SQLite read-only
connections and an obstructed filesystem path; no successful service is faked.
"""
import copy
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from earned_authority.contracts import CONTRACTS, canonical_digest
from earned_authority.runtime import Runtime
from earned_authority.wire_contracts import (
    RuntimeTrust, WireContractError, consume_bundle, export_runtime,
)


@pytest.fixture
def prepared(tmp_path):
    runtime = Runtime(tmp_path / "store" / "state.sqlite")
    for i in range(3):
        runtime.shadow(attempt_id=f"retry-shadow-{i}")
    qualification = runtime.qualify()
    runtime.grant(qualification["qualification_id"])
    command = runtime.admit(attempt_id="retry-contract")
    return runtime, qualification, command


def validate_unknown(value):
    schema = json.loads((CONTRACTS / "unknown-reconciliation-result.schema.json").read_text())
    canonical_digest(value)
    Draft202012Validator(schema).validate(value)


def durable_snapshot(runtime):
    with runtime._db() as db:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: db.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall() for name in tables}


def obstructed_retry(runtime, command):
    """The actual database directory becomes an ordinary file during lookup."""
    directory = Path(runtime.path).parent
    saved = directory.with_name(directory.name + "-unavailable")
    directory.rename(saved)
    directory.write_text("database directory temporarily inaccessible")
    try:
        return runtime.retry(command)
    finally:
        directory.unlink()
        saved.rename(directory)


def assert_unknown(response, command, *, reason="RECONCILIATION_UNAVAILABLE", committed=None):
    validate_unknown(response)
    assert response == {
        "state": "UNKNOWN", "reason": reason,
        "attempt_id": command["attempt_id"], "request_digest": command["request_digest"],
        "command_digest": canonical_digest(command), "committed": committed,
        "outcome": None, "delivery": "UNKNOWN", "receipt": None,
        "persisted": False, "next_action": "RECONCILE", "reexecution_permitted": False,
    }


def test_obstructed_durable_lookup_produces_unknown_without_writes(prepared):
    runtime, _, command = prepared
    before = durable_snapshot(runtime)
    response = obstructed_retry(runtime, command)
    assert_unknown(response, command)
    assert durable_snapshot(runtime) == before
    assert runtime.mutation_count == 0
    assert runtime.attempts(command["attempt_id"])["state"] == "REQUESTED"
    recovered = runtime.retry(command)
    assert recovered["state"] == "COMMITTED"
    assert recovered["outcome"]["outcome"] == "PASS"
    assert runtime.mutation_count == 1
    assert runtime.retry(command) == recovered
    assert runtime.mutation_count == 1


def test_sqlite_readonly_retry_cannot_manufacture_commit_or_receipt(prepared, monkeypatch):
    runtime, _, command = prepared
    before = durable_snapshot(runtime)
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "_db", lambda **kwargs: sqlite3.connect(Path(runtime.path).as_uri() + "?mode=ro", uri=True))
        response = runtime.retry(command)
    assert_unknown(response, command)
    assert durable_snapshot(runtime) == before
    assert runtime.mutation_count == 0


def test_missing_database_lookup_does_not_create_replacement_database(prepared):
    runtime, _, command = prepared
    before = durable_snapshot(runtime)
    directory = Path(runtime.path).parent
    saved = directory.with_name(directory.name + "-missing")
    directory.rename(saved)
    directory.mkdir()
    try:
        response = runtime.retry(command)
        created = list(directory.iterdir())
    finally:
        shutil.rmtree(directory)
        saved.rename(directory)
    assert_unknown(response, command)
    assert created == [], "a reconciliation read must not create a replacement database"
    assert durable_snapshot(runtime) == before


def test_missing_durable_attempt_is_unknown_and_never_readmitted(prepared):
    runtime, _, command = prepared
    with runtime._tx() as db:
        db.execute("DELETE FROM attempts WHERE id=?", (command["attempt_id"],))
    before = durable_snapshot(runtime)
    response = runtime.retry(command)
    assert_unknown(response, command, reason="ATTEMPT_UNCONFIRMED")
    assert durable_snapshot(runtime) == before
    assert runtime.attempts(command["attempt_id"]) is None
    with pytest.raises(WireContractError, match="attempt missing"):
        export_runtime(runtime, attempt_ids=[command["attempt_id"]], include_authority=False)


def test_postcommit_storage_failure_preserves_known_commit_without_claiming_outcome(prepared, monkeypatch):
    runtime, _, command = prepared
    with monkeypatch.context() as patch:
        # The real commit and readback finish first. Delivery then attempts a
        # real SQLite write through a read-only connection and cannot persist.
        def readonly_after_commit():
            patch.setattr(runtime, "_db", lambda **kwargs: sqlite3.connect(Path(runtime.path).as_uri() + "?mode=ro", uri=True))
        patch.setattr(runtime, "_after_commit", readonly_after_commit)
        response = runtime.retry(command)
    assert_unknown(response, command, committed=True)
    stored = runtime.attempts(command["attempt_id"])
    assert stored["state"] == "COMMITTED"
    assert stored["outcome"]["outcome"] == "PASS"
    assert stored["delivery"] == "PENDING"
    assert runtime.mutation_count == 1
    recovered = runtime.retry(command)
    assert recovered["outcome"] == stored["outcome"]
    assert recovered["delivery"] == "RECORDED"
    assert runtime.mutation_count == 1


def test_execution_uncertainty_does_not_erase_existing_commit(prepared):
    runtime, qualification, command = prepared
    committed = runtime.commit(command)
    before = durable_snapshot(runtime)
    response = obstructed_retry(runtime, command)
    assert_unknown(response, command)
    assert durable_snapshot(runtime) == before
    assert runtime.attempts(command["attempt_id"]) == committed
    assert runtime.retry(command) == committed
    bundle = export_runtime(runtime, qualification_ids=[qualification["qualification_id"]], attempt_ids=[command["attempt_id"]])
    attempt = next(r for r in bundle.records if r["kind"] == "attempt")
    assert attempt["value"]["state"] == "COMMITTED"
    assert attempt["value"]["mutation_receipt_ref"].startswith("local-event:")
    consumed = consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)
    assert consumed["verified"] and consumed["authorizes_execution"] is False
    assert runtime.mutation_count == 1


def test_unknown_outcome_is_a_durable_commit_not_unknown_execution(prepared):
    runtime, qualification, command = prepared
    result = runtime.commit(command, observer_available=False)
    assert result["state"] == "COMMITTED"
    assert result["outcome"]["outcome"] == "UNKNOWN"
    assert result["outcome"]["reason"] == "OBSERVATION_UNAVAILABLE"
    with pytest.raises(ValidationError):
        validate_unknown(result)
    bundle = export_runtime(runtime, qualification_ids=[qualification["qualification_id"]], attempt_ids=[command["attempt_id"]], include_authority=False)
    assert next(r for r in bundle.records if r["kind"] == "attempt")["value"]["state"] == "COMMITTED"
    consumed = consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)
    assert consumed["verified"] and consumed["authorizes_execution"] is False


def test_transient_unknown_cannot_be_exported_as_durable_attempt(prepared, monkeypatch):
    runtime, _, command = prepared
    response = obstructed_retry(runtime, command)
    assert_unknown(response, command)
    # An adapter incorrectly returning the transient response as durable storage
    # must fail export, even though the attempt schema itself permits UNKNOWN.
    monkeypatch.setattr(runtime, "attempts", lambda _: response)
    with pytest.raises(WireContractError, match="incomplete or invalid"):
        export_runtime(runtime, attempt_ids=[command["attempt_id"]], include_authority=False)


def test_rehashed_unknown_cannot_replace_authenticated_attempt_proof(prepared):
    runtime, _, command = prepared
    runtime.commit(command)
    response = obstructed_retry(runtime, command)
    bundle = export_runtime(runtime, attempt_ids=[command["attempt_id"]])
    record = next(r for r in bundle.records if r["kind"] == "attempt")
    source = {"kind": "attempt", "body": response}
    ref = "source:" + canonical_digest(source)
    bundle.proof_store[ref] = source
    record["inputs"]["attempt"] = ref
    record["source_digest"] = canonical_digest(response)
    with pytest.raises(WireContractError, match="source authentication rejected"):
        consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)


@pytest.mark.parametrize("field,value", [
    ("state", "COMMITTED"), ("reason", "POSTCONDITION_MET"), ("committed", False),
    ("outcome", "PASS"), ("outcome", {"outcome": "UNKNOWN"}), ("delivery", "RECORDED"),
    ("receipt", {"receipt_id": "invented"}), ("persisted", True), ("next_action", "EXECUTE"),
    ("attempt_id", ""), ("request_digest", "wrong"), ("command_digest", "sha256:" + "A" * 64),
    ("authority", {"status": "ACTIVE"}), ("signature", "invented"),
    ("mutation_receipt_ref", "local-event:invented"), ("proof_store", {}),
    ("reexecution_permitted", True),
])
def test_transient_schema_rejects_fabricated_evidence_or_permission(prepared, field, value):
    runtime, _, command = prepared
    response = obstructed_retry(runtime, command)
    validate_unknown(response)
    malformed = copy.deepcopy(response)
    malformed[field] = value
    with pytest.raises(ValidationError):
        validate_unknown(malformed)


def test_missing_attempt_must_not_claim_confirmed_commit(prepared):
    runtime, _, command = prepared
    response = obstructed_retry(runtime, command)
    malformed = {**response, "reason": "ATTEMPT_UNCONFIRMED", "committed": True}
    with pytest.raises(ValidationError):
        validate_unknown(malformed)
