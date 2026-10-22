"""Receipt compaction refuses to drop a receipt an applied operation or event still cites."""
import tempfile
import unittest
from pathlib import Path
from earned_authority.contracts import canonical_digest
from earned_authority.retention import compact_receipts, retain_receipt
from earned_authority.runtime import Denied
from test_authority_journal import OperationPassport, Policy
from test_connected_security import bound_unit_qualification, configure_unit_evidence_ledger
from earned_authority.connected import ConnectedRuntime
from earned_authority.runtime import ControlledClock


def run_proof():
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'registry.sqlite'
        passport = OperationPassport()
        clock = ControlledClock(1000000)
        passport.now = lambda: clock.now_ms
        runtime = ConnectedRuntime(path, passport=passport, policy=Policy(), ledger=None, qualification_client=None, fence_path=Path(tmp.name) / 'fence')
        runtime.clock = clock
        configure_unit_evidence_ledger(runtime)
        context = {'model_version': 'model-v2', 'desired_replicas': 1, 'max_replicas': 2}
        qualification = bound_unit_qualification(runtime, 'release-model', context, 300000)
        runtime.grant(qualification['qualification_id'], operation_id='op-grant')
        applied = runtime.authority_operations()[0]
        cited = retain_receipt(runtime, applied['receipt'], disposable=True)
        disposable = []
        for index in range(4):
            disposable.append(retain_receipt(runtime, {'disposable': index, 'note': 'uncited'}, disposable=True))
        before = compact_receipts(runtime, drop_ids=[])['archive']
        try:
            compact_receipts(runtime, drop_ids=disposable + [cited])
            refused = False
        except Denied as exc:
            refused = exc.reason == 'RECEIPT_STILL_CITED'
        after_refusal = compact_receipts(runtime, drop_ids=[])['archive']
        removed = compact_receipts(runtime)
        runtime._verify_local_events()
        reread = runtime.authority_operations()[0]
        event = next(row['event'] for row in runtime.events() if row['event']['event_type'] == 'GRANTED')
        return {
            'refused': refused,
            'refusal_kept_archive': after_refusal == before,
            'removed': removed['removed'],
            'cited_retained': cited in removed['archive'] and cited in removed['cited'],
            'disposable_removed': disposable == removed['removed'] and all(item not in removed['archive'] for item in disposable),
            'journal_receipt_unchanged': reread['state'] == 'APPLIED' and reread['receipt'] == applied['receipt'],
            'event_receipt_unchanged': event['operation_receipt'] == applied['receipt'],
            'receipt_digest': canonical_digest(reread['receipt']),
        }
    finally:
        tmp.cleanup()


class ReceiptRetentionTests(unittest.TestCase):
    def test_compaction_removes_only_uncited_disposable_receipts(self):
        proof = run_proof()
        self.assertTrue(proof['refused'] and proof['refusal_kept_archive'])
        self.assertTrue(proof['cited_retained'] and proof['disposable_removed'])
        self.assertTrue(proof['journal_receipt_unchanged'] and proof['event_receipt_unchanged'])
        self.assertEqual(4, len(proof['removed']))


if __name__ == '__main__':
    unittest.main()
