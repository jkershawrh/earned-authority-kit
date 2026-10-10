"""Authenticate reusable outcome evidence; this module never grants authority.

The ledger proves recorded bytes and writer attribution. Separately provisioned
producer keys and evaluator pins authorize an independent checker to attest an
outcome. Neither a hash chain nor this verifier independently establishes that
the checker's claim describes reality. The checker implementation is evaluated
elsewhere, and the credential/host trust boundary remains explicit.

Receipt-backed import/reuse uses verify; local audits use verify_observation.
Authentic local observations remain valid while remote delivery is pending. A caller
must persist any admission and audit only the qualification references actually
bound to its active grant before applying a selective hold. An unsolicited bad
submission must not be allowed to revoke arbitrary authority.
"""
import base64
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_digest


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _encoded(value):
    # Validate the exact same integer-only format used for evidence digests.
    canonical_digest(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _result(reason, *, admitted=False, status="REJECTED", integrity="UNKNOWN",
            outcome="UNKNOWN", hold=True, ledger_verification=None,
            verification_basis="SIGNED_OBSERVATION"):
    return {"admitted": admitted, "status": status, "reason": reason,
            "integrity": integrity, "outcome": outcome,
            "counts_as_pass": admitted and outcome == "PASS", "requires_hold": hold,
            "ledger_verification": ledger_verification, "verification_basis": verification_basis}


class EvidenceAdmission:
    def __init__(self, ledger, *, trusted_producers, trusted_evaluators, max_age_ms=600000):
        if type(max_age_ms) is not int or max_age_ms <= 0:
            raise ValueError("a positive integer evidence reuse window is required")
        if not callable(getattr(ledger, "verify_detailed", None)):
            raise ValueError("a detailed ledger verifier is required")
        self.ledger = ledger
        self.max_age_ms = max_age_ms
        self.trusted_producers = {}
        for signer, key in trusted_producers.items():
            if not isinstance(signer, str) or not signer:
                raise ValueError("producer signer IDs must be nonempty strings")
            if isinstance(key, bytes):
                key = Ed25519PublicKey.from_public_bytes(key)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("producer trust requires a pinned Ed25519 public key")
            self.trusted_producers[signer] = key
        self.trusted_evaluators = frozenset(trusted_evaluators)
        if any(not _digest(d) for d in self.trusted_evaluators):
            raise ValueError("evaluator trust requires explicit SHA256 digests")

    def verify_observation(self, observation, *, expected_attempt_id,
                           expected_skill_digest, expected_context_digest, now_ms):
        """Verify a producer attestation without consulting remote delivery.

        Expected bindings come from the consumer's durable attempt or existing
        qualification, never from this submitted envelope. Equality at either
        timestamp's expiry boundary is stale. Rejections have UNKNOWN effective
        outcome; an authentication/integrity failure is not a task failure.
        """
        if (not isinstance(expected_attempt_id, str) or not expected_attempt_id
                or not _digest(expected_skill_digest) or not _digest(expected_context_digest)
                or type(now_ms) is not int or now_ms < 0):
            raise ValueError("consumer must supply a valid attempt, skill/context digests and time")
        result = _result
        if observation is None:
            return result("MISSING_EVIDENCE", status="UNKNOWN")
        if not isinstance(observation, dict):
            return result("INVALID_EVIDENCE")
        try:
            _encoded(observation)
            for field in ("observation_id", "attempt_id", "skill", "version", "signer"):
                if not isinstance(observation.get(field), str) or not observation[field]:
                    return result("INVALID_EVIDENCE")
            if (type(observation.get("observed_at_ms")) is not int
                    or observation["observed_at_ms"] < 0
                    or observation.get("outcome") not in ("PASS", "FAIL", "UNKNOWN")
                    or "context" not in observation):
                return result("INVALID_EVIDENCE")
            key = self.trusted_producers.get(observation["signer"])
            if key is None:
                return result("UNTRUSTED_ATTESTATION")
            signed = {k: v for k, v in observation.items() if k != "evidence_digest"}
            if observation.get("evidence_digest") != canonical_digest(signed):
                return result("TAMPER_DETECTED", integrity="MISMATCH")
            signature = base64.b64decode(signed.pop("signature"), validate=True)
            key.verify(signature, _encoded(signed))
            if (observation.get("skill_digest") != canonical_digest({"skill": observation["skill"], "version": observation["version"]})
                    or observation.get("context_digest") != canonical_digest({"environment": observation["context"]})):
                return result("INVALID_EVIDENCE")
            if (observation.get("independent") is not True
                    or observation.get("evaluator_digest") not in self.trusted_evaluators):
                return result("UNTRUSTED_ATTESTATION")
        except InvalidSignature:
            return result("TAMPER_DETECTED", integrity="MISMATCH")
        except (ValueError, TypeError, KeyError):
            return result("INVALID_EVIDENCE")

        if observation["attempt_id"] != expected_attempt_id:
            return result("ATTEMPT_MISMATCH", integrity="INTACT")
        if observation["skill_digest"] != expected_skill_digest:
            return result("SKILL_REVISION_MISMATCH", integrity="INTACT")
        if observation["context_digest"] != expected_context_digest:
            return result("QUALIFICATION_CONTEXT_MISMATCH", integrity="INTACT")
        if not 0 <= now_ms - observation["observed_at_ms"] < self.max_age_ms:
            return result("STALE_EVIDENCE", status="STALE", integrity="INTACT")
        return result("OUTCOME_ATTESTED", admitted=True, status="VERIFIED", integrity="INTACT",
                      outcome=observation["outcome"], hold=observation["outcome"] == "UNKNOWN")

    def verify(self, observation, event, receipt, *, expected_attempt_id,
               expected_skill_digest, expected_context_digest, now_ms):
        """Add canonical receipt checks to the same producer admission policy.

        Returned admission authenticates reusable evidence, never permission to
        mutate a resource. The supplied observation must be the exact signed
        nested payload of an OUTCOME_OBSERVED event recorded by the ledger.
        """
        local = self.verify_observation(observation, expected_attempt_id=expected_attempt_id,
            expected_skill_digest=expected_skill_digest, expected_context_digest=expected_context_digest,
            now_ms=now_ms)
        if not local["admitted"]:
            return local
        ledger_result = None

        def result(reason, **kwargs):
            return _result(reason, ledger_verification=ledger_result,
                           verification_basis="CANONICAL_RECEIPT", **kwargs)

        if event is None:
            return result("MISSING_EVIDENCE", status="UNKNOWN")
        if not isinstance(event, dict):
            return result("INVALID_EVIDENCE")
        try:
            _encoded(event)
            if (event.get("event_type") != "OUTCOME_OBSERVED"
                    or not isinstance(event.get("outcome"), dict)):
                return result("INVALID_EVIDENCE")
            if canonical_digest(event["outcome"]) != canonical_digest(observation):
                return result("TAMPER_DETECTED", integrity="MISMATCH")
        except (ValueError, TypeError):
            return result("INVALID_EVIDENCE")

        # No remote receipt is fabricated, and an outage alone does not hold an
        # otherwise authentic local observation or revoke its authority.
        if receipt is None:
            return result("RECEIPT_UNAVAILABLE", status="UNKNOWN", hold=False)
        if not isinstance(receipt, dict):
            return result("INVALID_EVIDENCE")
        try:
            ledger_result = self.ledger.verify_detailed(receipt, event)
        except Exception:
            return result("EVIDENCE_UNCONFIRMED", status="UNKNOWN", hold=False)
        if not isinstance(ledger_result, dict):
            ledger_result = None
            return result("EVIDENCE_UNCONFIRMED", status="UNKNOWN", hold=False)
        if ledger_result.get("integrity") == "MISMATCH":
            return result("TAMPER_DETECTED", integrity="MISMATCH")
        if ledger_result.get("status") == "STALE":
            return result("STALE_EVIDENCE", status="STALE")
        if ledger_result.get("reason") == "UNTRUSTED_WRITER":
            return result("UNTRUSTED_ATTESTATION")
        if not (ledger_result.get("verified") is True and ledger_result.get("status") == "VERIFIED"
                and ledger_result.get("integrity") == "INTACT"):
            return result("EVIDENCE_UNCONFIRMED", status="UNKNOWN", hold=False)
        if event.get("attempt_id") != observation["attempt_id"]:
            return result("ATTEMPT_MISMATCH", integrity="INTACT")
        if type(receipt.get("written_ts")) is not int or receipt["written_ts"] < 0:
            return result("INVALID_EVIDENCE")
        if not 0 <= now_ms - receipt["written_ts"] < self.max_age_ms:
            return result("STALE_EVIDENCE", status="STALE", integrity="INTACT")
        return result("OUTCOME_VERIFIED", admitted=True, status="VERIFIED", integrity="INTACT",
                      outcome=observation["outcome"], hold=observation["outcome"] == "UNKNOWN")
