"""CDD across real fixture-produced records; this is not a hand-written fixture test."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from earned_authority.contracts import CONTRACTS, canonical_digest, validate
from earned_authority.runtime import ControlledClock, Runtime
from earned_authority.wire_contracts import (
    RuntimeTrust, WireContractError, consume_bundle, export_runtime,
)


class WireContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = ControlledClock()
        self.rt = Runtime(Path(self.temp.name) / 'runtime.sqlite', clock=self.clock)
        self.q = self.qualify()
        self.a = self.rt.grant(self.q['qualification_id'])

    def qualify(self, skill='release-model'):
        for i in range(3):
            self.rt.shadow(skill=skill, attempt_id=f'{skill}-shadow-{i}')
        return self.rt.qualify(skill=skill)

    def bundle(self, *, attempt=True, include_authority=True):
        if attempt:
            self.rt.execute(attempt_id='live-1')
        return export_runtime(self.rt, qualification_ids=[self.q['qualification_id']],
                              attempt_ids=['live-1'] if attempt else [],
                              include_authority=include_authority)

    def consume(self, bundle):
        return consume_bundle(bundle, trust=RuntimeTrust(self.rt), now_ms=self.clock.now_ms)

    def record(self, bundle, kind):
        return next(r for r in bundle.records if r['kind'] == kind)

    def reject(self, bundle):
        with self.assertRaises(WireContractError):
            self.consume(bundle)

    def test_all_five_actual_producers_validate_and_consume(self):
        bundle = self.bundle()
        self.assertEqual({r['kind'] for r in bundle.records},
                         {'qualification', 'authority', 'attempt', 'outcome', 'lifecycle-event'})
        for record in bundle.records:
            validate(record['kind'], record['value'])
        result = self.consume(bundle)
        self.assertTrue(result['verified'])
        self.assertFalse(result['authorizes_execution'])
        self.assertEqual(result['records_verified'], len(bundle.records))
        self.assertEqual(self.rt.read()['version'], 'model-v2')
        self.assertEqual(self.record(bundle, 'attempt')['value']['action_class'], 'model.promote_to_production')
        self.assertEqual(self.record(bundle, 'authority')['value']['grants'][0]['action_class'], 'model.promote_to_production')

    def test_qualification_digest_preserves_authenticated_raw_source_binding(self):
        bundle = self.bundle()
        q = self.record(bundle, 'qualification')
        a = self.record(bundle, 'authority')['value']
        self.assertEqual(a['grants'][0]['qualification_digest'], canonical_digest(self.q))
        self.assertNotEqual(canonical_digest(q['value']), a['grants'][0]['qualification_digest'])
        self.assertEqual(q['source_digest'], canonical_digest(self.q))
        self.consume(bundle)

    def test_empty_hold_has_null_window_and_no_fabricated_evidence(self):
        hold = self.rt.qualify(skill='unobserved-skill')
        bundle = export_runtime(self.rt, qualification_ids=[hold['qualification_id']], include_authority=False)
        value = self.record(bundle, 'qualification')['value']
        self.assertEqual(value['disposition'], 'HOLD')
        self.assertEqual(value['outcome_refs'], [])
        self.assertIsNone(value['observed_from_ms'])
        self.assertIsNone(value['observed_until_ms'])
        self.consume(bundle)

    def test_unknown_is_hold_without_failure_evidence(self):
        self.rt.shadow(attempt_id='unknown-shadow', observer_available=False)
        hold = self.rt.qualify()
        bundle = export_runtime(self.rt, qualification_ids=[hold['qualification_id']], include_authority=False)
        self.assertEqual(self.record(bundle, 'qualification')['value']['disposition'], 'HOLD')
        self.assertEqual(hold['failures'], 0)
        self.assertIn('UNKNOWN', [r['value']['outcome'] for r in bundle.records if r['kind'] == 'outcome'])
        self.consume(bundle)

    def test_revoked_authority_has_no_fabricated_active_credential(self):
        self.rt.revoke()
        with self.assertRaises(WireContractError):
            self.bundle(attempt=False)
        bundle = self.bundle(attempt=False, include_authority=False)
        self.assertFalse(any(r['kind'] == 'authority' for r in bundle.records))
        self.consume(bundle)

    def test_each_skill_keeps_its_exact_policy_binding(self):
        read_q = self.qualify('read-health')
        authority = self.rt.grant(read_q['qualification_id'], action='read')
        bundle = self.bundle(attempt=False)
        value = self.record(bundle, 'authority')['value']
        policies = {g['skill_id']: g['policy_digest'] for g in value['grants']}
        self.assertEqual(policies, {k: v['policy_digest'] for k, v in authority['grants'].items()})
        self.assertEqual(len(set(policies.values())), 2)
        self.consume(bundle)

    def test_pending_ledger_keeps_confirmed_pass_and_local_commit_receipt(self):
        self.rt.ledger.available = False
        bundle = self.bundle()
        attempt = self.record(bundle, 'attempt')['value']
        self.assertEqual(attempt['state'], 'COMMITTED')
        self.assertTrue(attempt['mutation_receipt_ref'].startswith('local-event:'))
        live = [r['value'] for r in bundle.records if r['kind'] == 'outcome' and r['value']['attempt_id'] == 'live-1'][0]
        self.assertEqual(live['outcome'], 'PASS')
        for row in (r['value'] for r in bundle.records if r['kind'] == 'lifecycle-event'):
            self.assertEqual(row['delivery_state'], 'PENDING')
            self.assertNotIn('ledger_receipt_ref', row)
        self.consume(bundle)

    def test_requested_attempt_is_not_a_commit(self):
        self.rt.admit(attempt_id='requested')
        bundle = export_runtime(self.rt, qualification_ids=[self.q['qualification_id']], attempt_ids=['requested'])
        value = self.record(bundle, 'attempt')['value']
        self.assertEqual(value['state'], 'REQUESTED')
        self.assertNotIn('mutation_receipt_ref', value)
        self.assertEqual(self.rt.mutation_count, 0)
        self.consume(bundle)

    def test_committed_attempt_uses_actual_boundary_policy_decision(self):
        bundle = self.bundle()
        source = self.rt.attempts('live-1')
        self.assertNotEqual(source['policy_decision_id'], source['command']['policy_decision_id'])
        self.assertEqual(self.record(bundle, 'attempt')['value']['policy_decision_id'], source['policy_decision_id'])
        self.consume(bundle)

    def test_read_outcome_uses_health_condition_without_registry_mutation(self):
        read_q = self.qualify('read-health')
        self.rt.grant(read_q['qualification_id'], action='read')
        self.rt.execute(skill='read-health', action='read', target='irrelevant-model', attempt_id='read-1')
        bundle = export_runtime(self.rt, qualification_ids=[read_q['qualification_id']], attempt_ids=['read-1'])
        self.assertEqual(self.rt.mutation_count, 0)
        self.consume(bundle)

    def test_public_records_omit_raw_signature_material(self):
        bundle = self.bundle()
        encoded = json.dumps(bundle.records)
        for source in bundle.proof_store.values():
            if source['body'].get('signature'):
                self.assertNotIn(source['body']['signature'], encoded)

    def test_changed_context_in_valid_shape_is_rejected(self):
        bundle = self.bundle()
        record = self.record(bundle, 'attempt')
        record['value']['context_digest'] = canonical_digest({'environment': 'other'})
        validate('attempt', record['value'])
        self.reject(bundle)

    def test_changed_policy_decision_in_valid_shape_is_rejected(self):
        bundle = self.bundle()
        self.record(bundle, 'attempt')['value']['policy_decision_id'] = 'invented-policy-decision'
        self.reject(bundle)

    def test_wrong_qualification_digest_is_rejected(self):
        bundle = self.bundle()
        self.record(bundle, 'authority')['value']['grants'][0]['qualification_digest'] = canonical_digest({})
        self.reject(bundle)

    def test_missing_proof_is_rejected(self):
        bundle = self.bundle()
        ref = self.record(bundle, 'qualification')['inputs']['qualification']
        del bundle.proof_store[ref]
        self.reject(bundle)

    def test_source_digest_tampering_is_rejected(self):
        bundle = self.bundle()
        self.record(bundle, 'qualification')['source_digest'] = canonical_digest({})
        self.reject(bundle)

    def test_raw_evidence_tamper_is_rejected_even_before_cross_binding(self):
        bundle = self.bundle()
        ref = self.record(bundle, 'outcome')['inputs']['observation']
        bundle.proof_store[ref]['body']['readback']['version'] = 'tampered'
        self.reject(bundle)

    def test_replayed_ledger_receipt_is_rejected(self):
        bundle = self.bundle()
        events = [r for r in bundle.records if r['kind'] == 'lifecycle-event']
        events[-1]['value']['ledger_receipt_ref'] = events[0]['value']['ledger_receipt_ref']
        self.reject(bundle)

    def test_remote_tamper_is_rejected_by_receipt_verification(self):
        bundle = self.bundle()
        self.rt.ledger.tamper(len(self.rt.ledger.entries) - 1)
        self.reject(bundle)

    def test_pending_delivery_cannot_claim_recorded_receipt(self):
        self.rt.ledger.available = False
        bundle = self.bundle()
        record = self.record(bundle, 'lifecycle-event')
        record['value']['delivery_state'] = 'RECORDED'
        record['value']['ledger_receipt_ref'] = 'invented-remote-receipt'
        self.reject(bundle)

    def test_current_authority_revocation_invalidates_active_credential_export(self):
        bundle = self.bundle()
        self.rt.revoke()
        self.reject(bundle)

    def test_qualification_revision_change_invalidates_old_source(self):
        bundle = self.bundle()
        self.rt.reevaluate(state='UNKNOWN')
        self.assertGreater(self.rt.qualification(self.q['qualification_id'])['qualification_revision'], self.q['qualification_revision'])
        self.reject(bundle)

    def test_expired_active_credential_is_rejected_at_consumer_time(self):
        bundle = self.bundle()
        self.clock.advance(300000)
        self.reject(bundle)

    def test_new_draft_events_export_without_fabricated_mutable_revision(self):
        bundle = self.bundle()
        events = [r['value'] for r in bundle.records if r['kind'] == 'lifecycle-event']
        self.assertIn('INTENT', [e['event_type'] for e in events])
        # subject is the immutable event itself, not an invented authority epoch.
        for event in events:
            self.assertEqual(event['subject_id'], event['event_id'])
            self.assertEqual(event['subject_revision'], 1)
        self.consume(bundle)

    def test_empty_bundle_cannot_report_verification(self):
        bundle = self.bundle(); bundle.records.clear()
        self.reject(bundle)

    def test_qualification_cannot_omit_its_outcome_records(self):
        bundle = self.bundle()
        bundle.records = [r for r in bundle.records if r['kind'] != 'outcome']
        self.reject(bundle)

    def test_committed_attempt_cannot_omit_local_commit_lifecycle_record(self):
        bundle = self.bundle()
        bundle.records = [r for r in bundle.records if not
                          (r['kind'] == 'lifecycle-event' and r['value']['event_type'] == 'COMMITTED')]
        self.reject(bundle)

    def test_changed_source_and_rehashed_envelope_still_need_external_trust(self):
        bundle = self.bundle(); record = self.record(bundle, 'qualification')
        original_ref = record['inputs']['qualification']
        source = copy.deepcopy(bundle.proof_store[original_ref]); source['body']['qualification_revision'] += 1
        ref = 'source:' + canonical_digest(source); bundle.proof_store[ref] = source
        record['inputs']['qualification'] = ref; record['source_digest'] = canonical_digest(source['body'])
        record['value']['qualification_revision'] += 1
        self.reject(bundle)

    def test_signed_but_wrong_postcondition_label_is_rejected(self):
        # A producer regression remains detectable even with an authentic checker signature.
        with self.rt._tx() as db:
            row = db.execute('SELECT body FROM observations WHERE attempt_id=?', ('release-model-shadow-0',)).fetchone()
            o = json.loads(row[0]); o.pop('evidence_digest'); o['readback']['version'] = 'wrong-model'
            o = self.rt._seal(o, 'checker'); o['evidence_digest'] = canonical_digest(o)
            db.execute('UPDATE observations SET body=? WHERE attempt_id=?', (json.dumps(o), o['attempt_id']))
        bad_q = self.rt.qualify()
        self.assertEqual(bad_q['disposition'], 'ELIGIBLE')  # fixture currently trusts signed outcome label
        with self.assertRaises(WireContractError):
            export_runtime(self.rt, qualification_ids=[bad_q['qualification_id']], include_authority=False)

    def test_historical_attempt_binds_original_eligible_revision_after_fail(self):
        self.rt.commit(self.rt.admit(attempt_id='bad'), actual='wrong-model')
        current = self.rt.qualification(self.q['qualification_id'])
        self.assertEqual(current['disposition'], 'INELIGIBLE')
        self.assertEqual(current['failures'], 1)
        self.assertTrue(any(r['attempt_id'] == 'bad' for r in current['outcome_refs']))
        bundle = export_runtime(self.rt, qualification_ids=[self.q['qualification_id']],
                                attempt_ids=['bad'], include_authority=False)
        source_ref = self.record(bundle, 'attempt')['inputs']['qualification']
        original = bundle.proof_store[source_ref]['body']
        self.assertEqual(original, self.q)
        self.assertEqual(original['disposition'], 'ELIGIBLE')
        self.consume(bundle)

    def test_historical_unknown_remains_hold_without_a_fail_count(self):
        self.rt.commit(self.rt.admit(attempt_id='unknown-live'), observer_available=False)
        current = self.rt.qualification(self.q['qualification_id'])
        self.assertEqual(current['disposition'], 'HOLD'); self.assertEqual(current['failures'], 0)
        bundle = export_runtime(self.rt, qualification_ids=[self.q['qualification_id']],
                                attempt_ids=['unknown-live'], include_authority=False)
        self.consume(bundle)

    def test_historical_qualification_digest_substitution_is_rejected(self):
        bundle = self.bundle()
        record = self.record(bundle, 'attempt')
        ref = record['inputs']['qualification']
        body = copy.deepcopy(bundle.proof_store[ref]['body']); body['context'] = 'other'
        record['inputs']['qualification'] = bundle.proof('qualification-history', body)
        self.reject(bundle)

    def test_late_failure_readback_does_not_extend_expired_qualification(self):
        command = self.rt.admit(attempt_id='late-recovery')
        read = self.rt.read
        def crash(_): raise RuntimeError('observer interrupted after commit')
        self.rt.read = crash
        with self.assertRaises(RuntimeError): self.rt.commit(command, actual='wrong-model')
        self.rt.read = read; self.clock.advance(600001)
        self.rt.commit(command)
        current = self.rt.qualification(self.q['qualification_id'])
        self.assertEqual(current['expires_at_ms'], self.q['expires_at_ms'])
        self.assertEqual(current['disposition'], 'INELIGIBLE')
        bundle = export_runtime(self.rt, qualification_ids=[self.q['qualification_id']],
                                attempt_ids=['late-recovery'], include_authority=False)
        self.consume(bundle)


class CapturedWireFixtureTests(unittest.TestCase):
    def test_actual_capture_is_only_shape_example_not_transferable_authority(self):
        fixture = json.loads((CONTRACTS / 'fixtures/runtime-wire-records.json').read_text())
        self.assertEqual(fixture['scope'], 'M1_LOCAL_FIXTURE_CAPTURE')
        self.assertFalse(fixture['consumer_checked_at_capture']['authorizes_execution'])
        self.assertNotIn('proof_store', fixture)
        self.assertEqual({r['kind'] for r in fixture['records']},
                         {'qualification', 'authority', 'attempt', 'outcome', 'lifecycle-event'})
        for record in fixture['records']:
            validate(record['kind'], record['value'])


if __name__ == '__main__':
    unittest.main()
