"""Signed lifecycle assertions stored in the canonical ARE Ledger over gRPC.

This adapter verifies assertion integrity and a pinned writer key. It does not
establish that an observation is true and never grants execution authority.
The canonical server remains the sole ledger; ``sdk_client`` is a unit-test seam.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HASH_VERSION = "ARE_LEDGER_ENTRY_HASH_V3"
SIGNATURE_DOMAIN = "earned-authority-ledger-writer-v1"


class LedgerError(RuntimeError):
    """No receipt can be represented as verified after this failure."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_entry_hash(entry: Any) -> str:
    """Independently reconstruct the canonical server's length-delimited V3 hash."""
    if entry.hash_version != HASH_VERSION:
        raise ValueError("only proof envelopes binding writer signatures (V3) are accepted")
    names = ["hash_version", "entry_id", "entry_type", "agent_id", "content", "content_type",
             "source_id", "correlation_id", "idempotency_key", "input_hash", "writer_signature",
             "signer_key_reference", "attestation_report", "chain_position", "written_ts_ms",
             "previous_hash"]
    encoded = bytearray(HASH_VERSION.encode() + b"\n")
    for name in names:
        value = getattr(entry, "written_ts" if name == "written_ts_ms" else name)
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
        encoded.extend(name.encode() + b":" + str(len(raw)).encode() + b":" + raw + b"\n")
    return hashlib.sha256(encoded).hexdigest()


def _event_bytes(event: dict) -> bytes:
    if not isinstance(event, dict):
        raise ValueError("event must be a mapping")
    for key in ("agent_id", "attempt_id", "correlation_id", "event_type"):
        if not isinstance(event.get(key), str) or not event[key].strip():
            raise ValueError(f"event requires a nonempty {key}")
    return canonical_json(event)


def _signature_payload(event: dict, content: bytes, entry_type: str, source_id: str,
                       idempotency_key: str, signer_key_reference: str) -> bytes:
    return canonical_json({
        "domain": SIGNATURE_DOMAIN,
        "entry_type": entry_type,
        "source_id": source_id,
        "agent_id": event["agent_id"],
        "attempt_id": event["attempt_id"],
        "correlation_id": event["correlation_id"],
        "event_type": event["event_type"],
        "idempotency_key": idempotency_key,
        "signer_key_reference": signer_key_reference,
        "content_type": "application/json",
        "content_sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
    })


def _load_sdk(sdk_path: str | Path, endpoint: str, token: str, timeout_seconds: float):
    sdk_file = Path(sdk_path).resolve() / "ledger_client.py"
    spec = importlib.util.spec_from_file_location("_canonical_are_ledger_sdk", sdk_file)
    if spec is None or spec.loader is None:
        raise ValueError("canonical SDK path is not loadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class DeadlineClient(module.LedgerClient):
        def _call(self, method, request):
            return method(request, metadata=self.metadata, timeout=timeout_seconds)

    return DeadlineClient(endpoint=endpoint, api_token=token)


class LedgerClient:
    """Authenticated loopback client with an explicit Ed25519 writer trust policy.

    append(event, idempotency_key) -> JSON-safe receipt dict
    verify(receipt, event) -> bool, false on mismatch or dependency failure

    The upstream SDK uses plaintext gRPC. Therefore this local reference adapter
    requires a loopback endpoint. A remote deployment needs a TLS-aware transport
    and separately validated key distribution; do not disable this check.
    """

    def __init__(self, endpoint: str, api_token: str, *, sdk_path: str | Path | None = None,
                 signer_private_key=None, signer_key_id: str = "", trusted_writers=None,
                 source_id: str = "earned-authority-kit", timeout_seconds: float = 5.0,
                 sdk_client=None):
        if not api_token or not api_token.strip():
            raise ValueError("an explicit ledger API bearer token is required")
        host, _, port = endpoint.rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError("endpoint must include a valid port")
        host = host.strip("[]")
        if host != "localhost":
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise ValueError("plaintext canonical SDK is restricted to loopback")
            except ValueError as exc:
                raise ValueError("plaintext canonical SDK is restricted to loopback") from exc
        if timeout_seconds <= 0 or not source_id:
            raise ValueError("positive timeout and explicit source_id are required")
        if sdk_client is None and sdk_path is None:
            raise ValueError("supply the pinned canonical SDK directory")
        self.sdk = sdk_client if sdk_client is not None else _load_sdk(
            sdk_path, endpoint, api_token, timeout_seconds)
        self.signer_private_key = signer_private_key
        self.signer_key_id = signer_key_id
        self.trusted_writers = dict(trusted_writers or {})
        self.source_id = source_id

    def append(self, event: dict, idempotency_key: str) -> dict:
        content = _event_bytes(event)
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("a stable caller-supplied idempotency key is required")
        if self.signer_private_key is None or not self.signer_key_id:
            raise LedgerError("an explicit writer signing key is required")
        entry_type = "earned_authority." + event["event_type"]
        content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        signature = self.signer_private_key.sign(_signature_payload(
            event, content, entry_type, self.source_id, idempotency_key, self.signer_key_id))
        try:
            response = self.sdk.issue_receipt(
                entry_type, event["agent_id"], content, content_type="application/json",
                source_id=self.source_id, correlation_id=event["correlation_id"],
                idempotency_key=idempotency_key, input_hash=content_hash,
                writer_signature=signature, signer_key_reference=self.signer_key_id,
                attestation_report=b"",
            )
            receipt = {
                "entry_id": response.entry_id, "entry_hash": response.entry_hash,
                "entry_type": response.entry_type, "chain_position": response.chain_position,
                "written_ts": response.written_ts, "input_hash": response.input_hash,
                "writer_signature": base64.b64encode(response.writer_signature).decode("ascii"),
                "signer_key_reference": response.signer_key_reference,
                "attestation_report": base64.b64encode(response.attestation_report).decode("ascii"),
                "hash_version": response.hash_version, "attempt_id": event["attempt_id"],
                "content_sha256": content_hash, "agent_id": event["agent_id"],
                "correlation_id": event["correlation_id"], "idempotency_key": idempotency_key,
            }
            if not self.verify(receipt, event):
                raise LedgerError("ledger returned proof that failed local verification")
            return receipt
        except LedgerError:
            raise
        except Exception as exc:
            raise LedgerError("ledger append failed; no verified receipt available") from exc

    def verify(self, receipt: dict, event: dict) -> bool:
        """Boolean compatibility wrapper; use verify_detailed for audit decisions."""
        return self.verify_detailed(receipt, event)["verified"]

    def verify_detailed(self, receipt: dict, event: dict, *, max_age_ms=None, now_ms=None) -> dict:
        """Separate positively detected mismatch from outage or stale evidence.

        A rejected trust policy or unavailable dependency is UNKNOWN integrity;
        callers must not turn it into a claim that stored evidence was tampered.
        max_age_ms is an optional consumer reuse policy, not ledger retention.
        """
        def result(status, reason, integrity="UNKNOWN"):
            return {"verified": status == "VERIFIED", "status": status,
                    "reason": reason, "integrity": integrity}

        try:
            content = _event_bytes(event)
            content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        except (ValueError, TypeError):
            return result("REJECTED", "INVALID_EVENT")
        try:
            if receipt["hash_version"] != HASH_VERSION:
                return result("REJECTED", "UNSUPPORTED_HASH_VERSION")
            if max_age_ms is not None:
                if not isinstance(max_age_ms, int) or isinstance(max_age_ms, bool) or max_age_ms < 0:
                    return result("REJECTED", "INVALID_FRESHNESS_POLICY")
                now = int(time.time() * 1000) if now_ms is None else now_ms
                age = now - receipt["written_ts"]
                if age < 0:
                    return result("STALE", "RECEIPT_FROM_FUTURE")
                if age >= max_age_ms:
                    return result("STALE", "RECEIPT_EXPIRED")
        except (KeyError, TypeError):
            return result("REJECTED", "MALFORMED_RECEIPT")
        try:
            entry = self.sdk.get_entry(receipt["entry_id"])
        except Exception:
            return result("UNAVAILABLE", "LEDGER_READ_UNAVAILABLE")
        try:
            for field in ("entry_id", "entry_hash", "entry_type", "chain_position", "written_ts",
                          "input_hash", "signer_key_reference", "hash_version", "idempotency_key",
                          "agent_id", "correlation_id"):
                if receipt[field] != getattr(entry, field):
                    return result("REJECTED", "RECEIPT_METADATA_MISMATCH", "MISMATCH")
            for field in ("writer_signature", "attestation_report"):
                if base64.b64decode(receipt[field], validate=True) != getattr(entry, field):
                    return result("REJECTED", "RECEIPT_PROOF_MISMATCH", "MISMATCH")
            if not (entry.content == content and entry.content_type == "application/json"
                    and entry.source_id == self.source_id
                    and entry.entry_type == "earned_authority." + event["event_type"]
                    and entry.agent_id == event["agent_id"]
                    and entry.correlation_id == event["correlation_id"]
                    and receipt["attempt_id"] == event["attempt_id"]
                    and receipt["content_sha256"] == content_hash == entry.input_hash):
                return result("REJECTED", "EVENT_BINDING_MISMATCH", "MISMATCH")
            if entry.hash_version != HASH_VERSION:
                return result("REJECTED", "UNSUPPORTED_HASH_VERSION")
            if canonical_entry_hash(entry) != entry.entry_hash:
                return result("REJECTED", "STORED_HASH_MISMATCH", "MISMATCH")
            key = self.trusted_writers.get(entry.signer_key_reference)
            if key is None:
                return result("REJECTED", "UNTRUSTED_WRITER")
            if isinstance(key, bytes):
                key = Ed25519PublicKey.from_public_bytes(key)
            key.verify(entry.writer_signature, _signature_payload(
                event, content, entry.entry_type, entry.source_id,
                entry.idempotency_key, entry.signer_key_reference))
        except InvalidSignature:
            return result("REJECTED", "WRITER_SIGNATURE_MISMATCH", "MISMATCH")
        except Exception:
            return result("REJECTED", "MALFORMED_PROOF_OR_TRUST_POLICY")
        try:
            proof = self.sdk.verify_proof(entry.entry_hash, entry.entry_type)
            stored = self.sdk.verify_entry(entry.entry_id)
        except Exception:
            return result("UNAVAILABLE", "LEDGER_VERIFICATION_UNAVAILABLE")
        if not proof.valid:
            reason = getattr(proof, "failure_reason", "")
            if reason == "entry_hash_mismatch":
                return result("REJECTED", "REMOTE_HASH_MISMATCH", "MISMATCH")
            return result("REJECTED", "REMOTE_PROOF_REJECTED")
        if not stored.hash_valid or not stored.chain_link_valid:
            return result("REJECTED", "REMOTE_ENTRY_OR_CHAIN_MISMATCH", "MISMATCH")
        return result("VERIFIED", "VERIFIED", "INTACT")

    def close(self):
        close = getattr(self.sdk, "close", None)
        if close:
            close()
