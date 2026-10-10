"""Draft CDD using actual producers; connected services use explicit UNIT seams.

These tests exercise signed durable events, the real exporter and the real
consumer. The imported connected fixture does not claim live service acceptance.
"""
import base64
import copy
import json

import pytest
from jsonschema import Draft202012Validator, ValidationError

from earned_authority.contracts import CONTRACTS, canonical_digest, validate
from earned_authority.runtime import Runtime, encoded
from earned_authority.wire_contracts import (
    RuntimeTrust, WireContractError, consume_bundle, export_runtime,
)
from test_connected_evidence import CONTEXT, outcome_row, rt  # explicit UNIT fixture


NEW_EVENTS = ("PROCEDURE_REPORTED", "EVIDENCE_ADMITTED", "EVIDENCE_REJECTED")


@pytest.fixture(params=NEW_EVENTS)
def produced(request, tmp_path, rt):
    kind = request.param
    if kind == "PROCEDURE_REPORTED":
        runtime = Runtime(tmp_path / "procedure-wire.sqlite")
        report = runtime.record_procedure_report("self-report", reported_outcome="PASS")
        assert report["independent"] is False
        assert runtime.observations() == []
    else:
        runtime = rt
        observation = runtime.shadow(context=CONTEXT, attempt_id="import-wire")
        runtime.flush_outbox()
        row = outcome_row(runtime, observation["attempt_id"])
        if kind == "EVIDENCE_REJECTED":
            observation = copy.deepcopy(observation)
            observation["readback"]["healthy"] = False
        decision = runtime.admit_evidence(
            observation, row["event"], row["receipt"],
            expected_attempt_id=observation["attempt_id"], context=CONTEXT,
        )
        assert decision["admitted"] is (kind == "EVIDENCE_ADMITTED")
    rows = [r for r in runtime.events() if r["event"]["event_type"] == kind]
    assert len(rows) == 1
    assert runtime.mutation_count == 0 and runtime.authority()["grants"] == {}
    return runtime, kind, rows[0]["event_id"]


def event_record(bundle, event_id):
    return next(r for r in bundle.records
                if r["kind"] == "lifecycle-event" and r["value"]["event_id"] == event_id)


@pytest.mark.parametrize("recorded", [False, True], ids=["pending", "recorded"])
def test_evidence_events_round_trip_actual_signed_producers(produced, recorded):
    runtime, kind, event_id = produced
    if recorded:
        runtime.flush_outbox()
    bundle = export_runtime(runtime, include_authority=False)
    record = event_record(bundle, event_id)
    source = bundle.proof_store[record["inputs"]["event"]]["body"]
    actual = next(row for row in runtime.events() if row["event_id"] == event_id)
    assert source == actual
    assert record["source_digest"] == canonical_digest(actual)
    assert record["value"]["payload_digest"] == canonical_digest(actual["event"])
    assert record["value"]["event_type"] == kind
    assert record["value"]["subject_id"] == event_id
    assert record["value"]["subject_revision"] == 1
    with runtime._db() as db:
        body, signature = db.execute("SELECT body,signature FROM events WHERE id=?", (event_id,)).fetchone()
    runtime.keys["writer"].public_key().verify(base64.b64decode(signature), encoded(json.loads(body)))
    assert record["value"]["delivery_state"] == ("RECORDED" if recorded else "PENDING")
    if recorded:
        assert runtime.ledger.verify(actual["receipt"], actual["event"])
        assert record["value"]["ledger_receipt_ref"] == "ledger-receipt:" + canonical_digest(actual["receipt"])
    else:
        assert "ledger_receipt_ref" not in record["value"]
    consumed = consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)
    assert consumed["verified"] and consumed["authorizes_execution"] is False
    assert not any(r["kind"] in ("authority", "attempt", "outcome", "qualification") for r in bundle.records)


def test_rehashed_evidence_event_copy_still_requires_original_source(produced):
    runtime, _, event_id = produced
    bundle = export_runtime(runtime, include_authority=False)
    record = event_record(bundle, event_id)
    forged = copy.deepcopy(bundle.proof_store[record["inputs"]["event"]])
    forged["body"]["event"]["reason"] = "invented-acceptance"
    ref = "source:" + canonical_digest(forged)
    bundle.proof_store[ref] = forged
    record["inputs"]["event"] = ref
    record["source_digest"] = canonical_digest(forged["body"])
    record["value"]["payload_digest"] = canonical_digest(forged["body"]["event"])
    record["value"]["reason_code"] = "invented-acceptance"
    validate("lifecycle-event", record["value"])
    with pytest.raises(WireContractError, match="source authentication rejected"):
        consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)


def test_mutated_durable_evidence_event_requires_original_writer_signature(produced):
    runtime, _, event_id = produced
    with runtime._tx() as db:
        body = json.loads(db.execute("SELECT body FROM events WHERE id=?", (event_id,)).fetchone()[0])
        body["reason"] = "tampered-in-storage"
        db.execute("UPDATE events SET body=? WHERE id=?", (json.dumps(body), event_id))
    # Re-exporting obtains current bytes and hashes; the unchanged signature must
    # still reject those bytes, even when every normalized digest is consistent.
    bundle = export_runtime(runtime, include_authority=False)
    with pytest.raises(WireContractError, match="LOCAL_INTENT_UNAUTHENTICATED"):
        consume_bundle(bundle, trust=RuntimeTrust(runtime), now_ms=runtime.clock.now_ms)


def test_pre_evidence_enum_consumer_rejects_new_producer_events(produced):
    runtime, _, event_id = produced
    record = event_record(export_runtime(runtime, include_authority=False), event_id)
    legacy = json.loads((CONTRACTS / "lifecycle-event.schema.json").read_text())
    legacy["properties"]["event_type"]["enum"] = [
        name for name in legacy["properties"]["event_type"]["enum"] if name not in NEW_EVENTS
    ]
    with pytest.raises(ValidationError):
        Draft202012Validator(legacy).validate(record["value"])
