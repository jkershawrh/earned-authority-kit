"""Admission tests use real signatures/client verification and a labeled SDK double."""
import base64
import copy
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from earned_authority.contracts import canonical_digest
from earned_authority.evidence_admission import EvidenceAdmission
from earned_authority.ledger_client import LedgerClient, canonical_entry_hash


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class MemoryTransport:
    """Explicit unit-only canonical SDK transport double; never live evidence."""
    def issue_receipt(self, entry_type, agent_id, content, **metadata):
        self.entry = SimpleNamespace(entry_id="entry-1", entry_type=entry_type,
            agent_id=agent_id, content=content, previous_hash="previous", chain_position=1,
            written_ts=1000, hash_version="ARE_LEDGER_ENTRY_HASH_V3", **metadata)
        self.entry.entry_hash = canonical_entry_hash(self.entry)
        return self.entry

    def get_entry(self, entry_id):
        assert entry_id == self.entry.entry_id
        return self.entry

    def verify_proof(self, *args):
        return SimpleNamespace(valid=True)

    def verify_entry(self, *args):
        return SimpleNamespace(hash_valid=True, chain_link_valid=True)


@pytest.fixture
def setup():
    producer, writer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    transport = MemoryTransport()
    ledger = LedgerClient("127.0.0.1:29492", "unit-token", signer_private_key=writer,
        signer_key_id="writer", trusted_writers={"writer": writer.public_key()}, sdk_client=transport)
    evaluator = canonical_digest({"checker": "independent-registry-readback-v1"})
    observation = {"observation_id": "observation-1", "attempt_id": "attempt-current",
        "skill": "release-model", "version": "skill-v1", "context": "demo-a",
        "skill_digest": canonical_digest({"skill": "release-model", "version": "skill-v1"}),
        "context_digest": canonical_digest({"environment": "demo-a"}),
        "outcome": "PASS", "readback": {"version": "model-v2", "healthy": True},
        "independent": True, "observed_at_ms": 1000, "evaluator_digest": evaluator}
    gate = EvidenceAdmission(ledger, trusted_producers={"checker": producer.public_key()},
        trusted_evaluators={evaluator}, max_age_ms=100)
    return SimpleNamespace(producer=producer, ledger=ledger, transport=transport,
        gate=gate, observation=observation, evaluator=evaluator)


def package(s, *, key=None, signer="checker", **changes):
    observation = {**copy.deepcopy(s.observation), **changes, "signer": signer}
    observation["signature"] = base64.b64encode((key or s.producer).sign(encoded(observation))).decode()
    observation["evidence_digest"] = canonical_digest(observation)
    event = {"event_id": "event-1", "event_type": "OUTCOME_OBSERVED", "agent_id": "agent-1",
        "attempt_id": observation["attempt_id"], "correlation_id": observation["attempt_id"],
        "occurred_at_ms": 1000, "outcome": copy.deepcopy(observation)}
    receipt = s.ledger.append(event, "event-1")
    return observation, event, receipt


def verify(s, values, **expected):
    return s.gate.verify(*values, expected_attempt_id=expected.get("attempt", "attempt-current"),
        expected_skill_digest=expected.get("skill", s.observation["skill_digest"]),
        expected_context_digest=expected.get("context", s.observation["context_digest"]),
        now_ms=expected.get("now", 1050))


def rejected(result, reason, *, hold=True):
    assert result["admitted"] is False
    assert result["reason"] == reason
    assert result["outcome"] == "UNKNOWN"
    assert result["counts_as_pass"] is False
    assert result["requires_hold"] is hold


@pytest.mark.parametrize("outcome", ["PASS", "FAIL", "UNKNOWN"])
def test_actual_producer_signature_and_ledger_proof_admit_distinct_outcome(setup, outcome):
    result = verify(setup, package(setup, outcome=outcome))
    assert result["admitted"] is True
    assert result["status"] == "VERIFIED"
    assert result["outcome"] == outcome
    assert result["counts_as_pass"] is (outcome == "PASS")
    assert result["requires_hold"] is (outcome == "UNKNOWN")
    assert result["ledger_verification"]["verified"] is True


def test_altered_local_observation_does_not_match_recorded_receipt(setup):
    values = package(setup)
    values[0]["readback"]["healthy"] = False
    result = verify(setup, values)
    rejected(result, "TAMPER_DETECTED")
    assert result["integrity"] == "MISMATCH"


def test_rewritten_event_and_digest_do_not_defeat_producer_signature(setup):
    obs, event, receipt = package(setup)
    obs["outcome"] = "FAIL"
    obs["evidence_digest"] = canonical_digest({k:v for k,v in obs.items() if k != "evidence_digest"})
    event["outcome"] = copy.deepcopy(obs)
    rejected(verify(setup, (obs, event, receipt)), "TAMPER_DETECTED")


def test_other_valid_producer_signature_cannot_impersonate_pinned_signer(setup):
    values = package(setup, key=Ed25519PrivateKey.generate())
    rejected(verify(setup, values), "TAMPER_DETECTED")


def test_intact_ledger_does_not_establish_producer_trust(setup):
    values = package(setup, key=Ed25519PrivateKey.generate(), signer="outsider")
    assert setup.ledger.verify(values[2], values[1])
    result = verify(setup, values)
    rejected(result, "UNTRUSTED_ATTESTATION")
    assert result["integrity"] == "UNKNOWN"


@pytest.mark.parametrize("changes", [{"independent": False}, {"independent": 1},
    {"evaluator_digest": canonical_digest({"checker": "unapproved"})}])
def test_trusted_key_alone_does_not_attest_approved_independent_evaluator(setup, changes):
    rejected(verify(setup, package(setup, **changes)), "UNTRUSTED_ATTESTATION")


@pytest.mark.parametrize("expected,reason", [({"attempt":"attempt-other"},"ATTEMPT_MISMATCH"),
    ({"skill":canonical_digest({"skill":"release-model","version":"skill-v2"})},"SKILL_REVISION_MISMATCH"),
    ({"context":canonical_digest({"environment":"demo-b"})},"QUALIFICATION_CONTEXT_MISMATCH")])
def test_valid_receipt_cannot_be_repurposed(setup, expected, reason):
    values = package(setup)
    assert setup.ledger.verify(values[2], values[1])
    rejected(verify(setup, values, **expected), reason)


@pytest.mark.parametrize("now", [999, 1100, 1101])
def test_signed_timestamp_future_or_exact_expiry_boundary_is_stale(setup, now):
    rejected(verify(setup, package(setup), now=now), "STALE_EVIDENCE")


def test_new_receipt_does_not_refresh_old_observation(setup):
    rejected(verify(setup, package(setup, observed_at_ms=900)), "STALE_EVIDENCE")


def test_old_receipt_does_not_pass_with_a_new_signed_observation(setup):
    rejected(verify(setup, package(setup, observed_at_ms=1090), now=1100), "STALE_EVIDENCE")


def test_missing_observation_is_unknown(setup):
    _, event, receipt = package(setup)
    rejected(verify(setup, (None,event,receipt)), "MISSING_EVIDENCE")


def test_pending_delivery_does_not_make_local_outcome_a_failure_or_trigger_hold(setup):
    obs,event,_ = package(setup)
    rejected(verify(setup, (obs,event,None)), "RECEIPT_UNAVAILABLE", hold=False)


def test_actual_transport_read_failure_is_unknown_not_tamper(setup):
    values=package(setup)
    def offline(*args): raise ConnectionError("unit outage")
    setup.transport.get_entry=offline
    result=verify(setup,values)
    rejected(result,"EVIDENCE_UNCONFIRMED",hold=False)
    assert result["integrity"] == "UNKNOWN"
    assert result["ledger_verification"]["status"] == "UNAVAILABLE"


def test_positive_remote_content_mismatch_is_tamper(setup):
    values=package(setup)
    setup.transport.entry.content += b" "
    rejected(verify(setup,values),"TAMPER_DETECTED")


def test_ledger_writer_trust_is_separate_from_producer_trust(setup):
    values=package(setup)
    setup.ledger.trusted_writers={}
    rejected(verify(setup,values),"UNTRUSTED_ATTESTATION")


@pytest.mark.parametrize("change", [{"version":"skill-v2"},{"context":"demo-b"},
    {"observed_at_ms":True},{"outcome":"SUCCESS"}])
def test_signature_over_internally_inconsistent_or_malformed_claim_does_not_make_it_valid(setup, change):
    rejected(verify(setup,package(setup,**change)),"INVALID_EVIDENCE")


def test_event_attempt_must_match_its_nested_observation(setup):
    obs,event,_=package(setup)
    event["attempt_id"]="different"
    receipt=setup.ledger.append(event,"different-key")
    rejected(verify(setup,(obs,event,receipt)),"ATTEMPT_MISMATCH")


def test_other_event_type_is_not_outcome_evidence(setup):
    obs,event,_=package(setup)
    event["event_type"]="GRANTED"
    receipt=setup.ledger.append(event,"different-key")
    rejected(verify(setup,(obs,event,receipt)),"INVALID_EVIDENCE")


def test_boolean_ledger_verifier_cannot_claim_receipt_verification(setup):
    values=package(setup)
    setup.ledger.verify_detailed=lambda *args,**kwargs:True
    rejected(verify(setup,values),"EVIDENCE_UNCONFIRMED",hold=False)


@pytest.mark.parametrize("age", [True,0,-1,"100"])
def test_invalid_consumer_freshness_policy_cannot_be_created(setup,age):
    with pytest.raises(ValueError):
        EvidenceAdmission(setup.ledger,trusted_producers={"checker":setup.producer.public_key()},
            trusted_evaluators={setup.evaluator},max_age_ms=age)


def local_verify(s, observation, *, now=1050):
    return s.gate.verify_observation(observation, expected_attempt_id="attempt-current",
        expected_skill_digest=s.observation["skill_digest"],
        expected_context_digest=s.observation["context_digest"], now_ms=now)


def test_local_attestation_audit_never_requires_remote_delivery(setup):
    observation,_,_=package(setup)
    setup.ledger.verify_detailed=lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError("no remote audit allowed"))
    result=local_verify(setup,observation)
    assert result["admitted"] and result["counts_as_pass"]
    assert result["ledger_verification"] is None
    assert result["verification_basis"] == "SIGNED_OBSERVATION"


def test_local_attestation_audit_detects_tamper_without_ledger(setup):
    observation,_,_=package(setup)
    observation["readback"]["healthy"]=False
    rejected(local_verify(setup,observation),"TAMPER_DETECTED")


@pytest.mark.parametrize("field,value", [("version","skill-v2"),("context","demo-b"),
    ("independent",False),("evaluator_digest",canonical_digest({"checker":"changed"}))])
def test_changed_signed_claim_is_tamper_even_when_changed_claim_would_be_untrusted(setup,field,value):
    observation,_,_=package(setup)
    observation[field]=value
    rejected(local_verify(setup,observation),"TAMPER_DETECTED")


@pytest.mark.parametrize("case,reason", [("missing","MISSING_EVIDENCE"),("stale","STALE_EVIDENCE"),
    ("wrong-attempt","ATTEMPT_MISMATCH"),("untrusted","UNTRUSTED_ATTESTATION")])
def test_local_audit_preserves_missing_stale_binding_and_trust_distinctions(setup,case,reason):
    changes={"attempt_id":"other"} if case=="wrong-attempt" else {}
    values=package(setup,signer="outsider" if case=="untrusted" else "checker",**changes)
    observation=None if case=="missing" else values[0]
    rejected(local_verify(setup,observation,now=1100 if case=="stale" else 1050),reason)
