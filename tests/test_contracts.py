import copy
import json
import unittest
from earned_authority.contracts import CONTRACTS, validate, canonical_digest, load_unique_json
from jsonschema import ValidationError, Draft202012Validator

KINDS = ("qualification", "authority", "attempt", "outcome", "lifecycle-event")


def fixture(kind):
    return json.loads((CONTRACTS / "fixtures" / (kind + ".json")).read_text())


class ContractTests(unittest.TestCase):
    def test_each_schema_and_its_individual_fixture_are_valid(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                Draft202012Validator.check_schema(json.loads((CONTRACTS / (kind + ".schema.json")).read_text()))
                validate(kind, fixture(kind))

    def test_unknown_contract_version_rejected(self):
        for kind in KINDS:
            value = fixture(kind); value["schema_version"] = "999.0.0"
            with self.assertRaises(ValidationError): validate(kind, value)

    def test_unknown_fields_rejected(self):
        value = fixture("attempt"); value["authority_override"] = True
        with self.assertRaises(ValidationError): validate("attempt", value)

    def test_malformed_binding_rejected(self):
        value = fixture("qualification"); value["skill_digest"] = "unversioned-latest"
        with self.assertRaises(ValidationError): validate("qualification", value)

    def test_committed_attempt_requires_receipt(self):
        value = fixture("attempt"); value["state"] = "COMMITTED"
        with self.assertRaises(ValidationError): validate("attempt", value)
        value["mutation_receipt_ref"] = "fixture-only"
        validate("attempt", value)

    def test_pending_ledger_is_not_recorded(self):
        value = fixture("lifecycle-event"); value["delivery_state"] = "RECORDED"
        with self.assertRaises(ValidationError): validate("lifecycle-event", value)

    def test_duplicate_observation_cannot_inflate_reference_count(self):
        value = fixture("qualification"); value["outcome_refs"] *= 2
        with self.assertRaises(ValidationError): validate("qualification", value)

    def test_validity_window_must_follow_observations(self):
        value = fixture("qualification"); value['disposition'] = 'ELIGIBLE'; value["expires_at_ms"] = value["observed_until_ms"]
        with self.assertRaises(ValueError): validate("qualification", value)

    def test_scope_cannot_outlive_parent_authority(self):
        value = fixture("authority"); value["grants"][0]["expires_at_ms"] += 1
        with self.assertRaises(ValueError): validate("authority", value)

    def test_duplicate_grants_rejected(self):
        value = fixture("authority"); value["grants"] *= 2
        with self.assertRaises(ValueError): validate("authority", value)

    def test_order_independent_digest_binds_changed_context(self):
        a = {"skill":"v1","context":"site-A"}
        b = {"context":"site-A","skill":"v1"}
        self.assertEqual(canonical_digest(a), canonical_digest(b))
        self.assertNotEqual(canonical_digest(a), canonical_digest(dict(a,context="site-B")))

    def test_float_and_ambiguous_duplicate_json_rejected(self):
        with self.assertRaises(ValueError): canonical_digest({"timestamp":1.1})
        with self.assertRaises(ValueError): load_unique_json('{"skill":"v1","skill":"v2"}')
        with self.assertRaises(ValueError): load_unique_json('{"value":NaN}')


class EncodingRegressions(unittest.TestCase):
    def test_trailing_newline_in_digest_is_rejected(self):
        value = fixture("qualification"); value["skill_digest"] += "\n"
        with self.assertRaises((ValidationError, ValueError)): validate("qualification", value)

    def test_integral_float_timestamp_is_rejected(self):
        value = fixture("qualification"); value["observed_from_ms"] = 1000.0
        with self.assertRaises((ValidationError, ValueError)): validate("qualification", value)


class RuntimeShapeRegressions(unittest.TestCase):
    def empty_evidence(self, disposition):
        value = fixture('qualification')
        value.update(disposition=disposition, outcome_refs=[], observed_from_ms=None, observed_until_ms=None)
        return value

    def test_hold_without_observations_is_representable(self):
        validate('qualification', self.empty_evidence('HOLD'))

    def test_ineligible_without_observations_is_representable(self):
        validate('qualification', self.empty_evidence('INELIGIBLE'))

    def test_eligible_cannot_have_empty_evidence(self):
        value = self.empty_evidence('ELIGIBLE')
        with self.assertRaises(ValidationError): validate('qualification', value)

    def test_partial_null_window_is_rejected(self):
        value = self.empty_evidence('HOLD'); value['observed_until_ms'] = 2000
        with self.assertRaises(ValueError): validate('qualification', value)

    def test_empty_evidence_cannot_invent_observation_time(self):
        value = self.empty_evidence('HOLD'); value.update(observed_from_ms=1000, observed_until_ms=2000)
        with self.assertRaises(ValueError): validate('qualification', value)

    def test_evidence_refs_require_observation_time(self):
        value = fixture('qualification'); value.update(observed_from_ms=None, observed_until_ms=None)
        with self.assertRaises(ValueError): validate('qualification', value)

    def test_every_grant_requires_exact_policy_digest(self):
        value = fixture('authority'); del value['grants'][0]['policy_digest']
        with self.assertRaises(ValidationError): validate('authority', value)

    def test_pending_event_cannot_claim_ledger_receipt(self):
        value = fixture('lifecycle-event'); value['ledger_receipt_ref'] = 'fabricated'
        with self.assertRaises(ValidationError): validate('lifecycle-event', value)

    def test_requested_attempt_cannot_claim_mutation_receipt(self):
        value = fixture('attempt'); value['mutation_receipt_ref'] = 'fabricated'
        with self.assertRaises(ValidationError): validate('attempt', value)

    def test_actual_runtime_intent_and_canonical_evaluation_events_validate(self):
        for kind in ('INTENT', 'CANONICAL_QUALIFICATION_EVALUATED', 'WITHDRAWAL_RECONCILED'):
            with self.subTest(kind=kind):
                value = fixture('lifecycle-event'); value['event_type'] = kind
                validate('lifecycle-event', value)

    def test_noneligible_late_evidence_does_not_extend_expired_authority(self):
        value = fixture('qualification'); value.update(disposition='INELIGIBLE', expires_at_ms=1500)
        validate('qualification', value)
        self.assertEqual(value['expires_at_ms'], 1500)

    def test_noneligible_window_still_cannot_be_reversed(self):
        value = fixture('qualification'); value.update(observed_from_ms=3000, observed_until_ms=2000)
        with self.assertRaises(ValueError): validate('qualification', value)
