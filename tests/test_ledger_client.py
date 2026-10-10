"""Unit tests use an explicitly fake transport; real service evidence is separate."""

import copy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from earned_authority.ledger_client import LedgerClient, LedgerError, canonical_entry_hash


class FakeTransport:
    """Transport double, never used by the connected-service harness."""

    def __init__(self):
        self.entries = {}
        self.calls = 0
        self.remote_valid = True

    def issue_receipt(self, entry_type, agent_id, content, **metadata):
        key = (entry_type, metadata["idempotency_key"])
        self.calls += 1
        if key in self.entries:
            entry = self.entries[key]
            if entry.content != content:
                raise RuntimeError("idempotency conflict")
        else:
            entry = SimpleNamespace(
                entry_id="00000000-0000-4000-8000-000000000001",
                entry_type=entry_type, agent_id=agent_id, content=content,
                previous_hash="previous", chain_position=1, written_ts=1700000000000,
                hash_version="ARE_LEDGER_ENTRY_HASH_V3", **metadata,
            )
            entry.entry_hash = canonical_entry_hash(entry)
            self.entries[key] = entry
        return entry

    def get_entry(self, entry_id):
        return next(e for e in self.entries.values() if e.entry_id == entry_id)

    def verify_proof(self, entry_hash, entry_type):
        return SimpleNamespace(valid=self.remote_valid)

    def verify_entry(self, entry_id):
        return SimpleNamespace(hash_valid=self.remote_valid, chain_link_valid=self.remote_valid)


@pytest.fixture
def setup():
    key = Ed25519PrivateKey.generate()
    sdk = FakeTransport()
    client = LedgerClient(
        "127.0.0.1:29492", "unit-test-token", signer_private_key=key,
        signer_key_id="local-test-writer", trusted_writers={"local-test-writer": key.public_key()},
        sdk_client=sdk,
    )
    event = {"agent_id": "agent-1", "attempt_id": "attempt-1", "correlation_id": "run-1",
             "event_type": "outcome", "outcome": "PASS", "authority_revision": 2}
    return client, sdk, event


def test_round_trip_and_idempotent_receipt(setup):
    client, sdk, event = setup
    receipt = client.append(event, "key-1")
    assert client.verify(receipt, event)
    assert client.append(event, "key-1") == receipt
    assert len(sdk.entries) == 1


def test_conflicting_idempotent_content_fails(setup):
    client, _, event = setup
    client.append(event, "key-1")
    with pytest.raises(LedgerError):
        client.append({**event, "outcome": "FAIL"}, "key-1")


@pytest.mark.parametrize("field,value", [("attempt_id", "another"), ("agent_id", "other"),
                                            ("authority_revision", 9), ("outcome", "FAIL")])
def test_receipt_cannot_be_rebound_to_changed_event(setup, field, value):
    client, _, event = setup
    receipt = client.append(event, "key-1")
    assert not client.verify(receipt, {**event, field: value})


@pytest.mark.parametrize("field", ["entry_hash", "entry_id", "input_hash", "writer_signature",
                                      "signer_key_reference", "attempt_id", "content_sha256",
                                      "idempotency_key", "correlation_id", "agent_id"])
def test_changed_receipt_fails(setup, field):
    client, _, event = setup
    receipt = client.append(event, "key-1")
    receipt[field] = "tampered"
    assert not client.verify(receipt, event)


def test_stored_bytes_tampering_fails_independent_hash_check(setup):
    client, sdk, event = setup
    receipt = client.append(event, "key-1")
    next(iter(sdk.entries.values())).content += b" "
    assert not client.verify(receipt, event)


def test_untrusted_writer_is_not_accepted_even_when_ledger_proof_passes(setup):
    client, _, event = setup
    receipt = client.append(event, "key-1")
    client.trusted_writers = {}
    assert not client.verify(receipt, event)


def test_valid_hash_does_not_make_a_bad_signature_valid(setup):
    client, sdk, event = setup
    receipt = client.append(event, "key-1")
    entry = next(iter(sdk.entries.values()))
    entry.writer_signature = b"bad-signature"
    entry.entry_hash = canonical_entry_hash(entry)
    receipt["entry_hash"] = entry.entry_hash
    import base64
    receipt["writer_signature"] = base64.b64encode(entry.writer_signature).decode()
    assert not client.verify(receipt, event)


def test_remote_failure_or_unsupported_hash_version_fails_closed(setup):
    client, sdk, event = setup
    receipt = client.append(event, "key-1")
    sdk.remote_valid = False
    assert not client.verify(receipt, event)
    sdk.remote_valid = True
    next(iter(sdk.entries.values())).hash_version = "ARE_LEDGER_ENTRY_HASH_V2"
    assert not client.verify(receipt, event)


def test_no_append_without_explicit_authentication_and_signer(setup):
    client, _, event = setup
    client.signer_private_key = None
    with pytest.raises(LedgerError):
        client.append(event, "key-1")
    with pytest.raises(ValueError):
        LedgerClient("127.0.0.1:29492", "", sdk_client=FakeTransport())


def test_required_attempt_binding_and_nonfinite_json_rejected(setup):
    client, sdk, event = setup
    missing = copy.copy(event)
    missing.pop("attempt_id")
    with pytest.raises((ValueError, LedgerError)):
        client.append(missing, "key-1")
    with pytest.raises((ValueError, LedgerError)):
        client.append({**event, "value": float("nan")}, "key-2")
    assert sdk.calls == 0


def test_dependency_outage_is_unknown_not_tamper(setup):
    client, sdk, event = setup
    receipt = client.append(event, "key-1")
    def offline(_entry_id):
        raise ConnectionError("offline")
    sdk.get_entry = offline
    result = client.verify_detailed(receipt, event)
    assert result == {"verified": False, "status": "UNAVAILABLE",
                      "reason": "LEDGER_READ_UNAVAILABLE", "integrity": "UNKNOWN"}


def test_expired_receipt_is_stale_not_tamper(setup):
    client, _, event = setup
    receipt = client.append(event, "key-1")
    result = client.verify_detailed(receipt, event, max_age_ms=100, now_ms=receipt["written_ts"] + 101)
    assert result["status"] == "STALE"
    assert result["integrity"] == "UNKNOWN"
    assert result["reason"] == "RECEIPT_EXPIRED"


def test_positive_content_mismatch_is_distinct_from_missing_trust(setup):
    client, _, event = setup
    receipt = client.append(event, "key-1")
    result = client.verify_detailed(receipt, {**event, "outcome": "FAIL"})
    assert result["status"] == "REJECTED"
    assert result["integrity"] == "MISMATCH"
    client.trusted_writers = {}
    result = client.verify_detailed(receipt, event)
    assert result["reason"] == "UNTRUSTED_WRITER"
    assert result["integrity"] == "UNKNOWN"
