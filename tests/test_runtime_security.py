"""Recovery and authentication negatives beyond the lifecycle examples."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from earned_authority.runtime import Runtime, Denied

class RecoverySecurity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'state.sqlite'
        self.rt=Runtime(self.path)
        for _ in range(3): self.rt.shadow()
        self.q=self.rt.qualify(); self.rt.grant(self.q['qualification_id'])

    def test_recovery_cannot_attribute_a_later_mutation_to_old_attempt(self):
        old=self.rt.admit(attempt_id='old',target='model-v2')
        read=self.rt.read
        def crash(resource): raise RuntimeError('crash before observation')
        self.rt.read=crash
        with self.assertRaises(RuntimeError): self.rt.commit(old)
        self.rt.read=read
        self.rt.execute(attempt_id='new',target='model-v2')
        recovered=self.rt.commit(old)
        self.assertEqual('UNKNOWN',recovered['outcome']['outcome'])
        self.assertEqual('OUTCOME_UNATTRIBUTABLE',recovered['outcome']['reason'])
        self.assertEqual(2,self.rt.mutation_count)

    def test_tampered_local_outbox_is_not_resigned_and_delivered(self):
        with sqlite3.connect(self.path) as db:
            eid,raw=db.execute('SELECT id,body FROM events ORDER BY rowid LIMIT 1').fetchone()
            event=json.loads(raw); event['event_type']='FORGED'
            db.execute('UPDATE events SET body=? WHERE id=?',(json.dumps(event),eid))
        with self.assertRaises(Denied) as got: self.rt.flush_outbox()
        self.assertEqual('LOCAL_INTENT_UNAUTHENTICATED',got.exception.reason)
        self.assertFalse(self.rt.ledger.entries)

    def test_observation_digest_is_verified_not_trusted_as_unsigned_label(self):
        with sqlite3.connect(self.path) as db:
            for aid,raw in db.execute('SELECT attempt_id,body FROM observations').fetchall():
                obs=json.loads(raw); obs['evidence_digest']='sha256:'+'0'*64
                db.execute('UPDATE observations SET body=? WHERE attempt_id=?',(json.dumps(obs),aid))
        result=self.rt.qualify()
        self.assertEqual(0,result['passes'])
        self.assertEqual('HOLD',result['disposition'])

if __name__=='__main__': unittest.main(verbosity=2)

class QualificationHistory(unittest.TestCase):
    def test_failure_keeps_earlier_grant_evidence_and_records_trigger(self):
        from earned_authority.contracts import canonical_digest
        with tempfile.TemporaryDirectory() as tmp:
            rt=Runtime(Path(tmp)/'state.sqlite')
            for _ in range(3):rt.shadow()
            original=rt.qualify();digest=canonical_digest(original)
            rt.grant(original['qualification_id'])
            result=rt.commit(rt.admit(),actual='wrong')
            latest=rt.qualification(original['qualification_id'])
            prior=rt.qualification_at(original['qualification_id'],digest=digest)
            self.assertEqual(original,prior)
            self.assertEqual(2,latest['qualification_revision'])
            self.assertEqual(1,latest['failures'])
            self.assertIn(result['outcome']['evidence_digest'],[r['evidence_digest'] for r in latest['outcome_refs']])
            rt.apply_outcome(result['attempt_id'])
            self.assertEqual(2,len(rt.qualification_history()))

    def test_shadow_retry_at_later_time_reuses_original_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            rt=Runtime(Path(tmp)/'state.sqlite')
            original=rt.shadow(attempt_id='shadow-id')
            rt.clock.advance(500)
            self.assertEqual(original,rt.shadow(attempt_id='shadow-id'))
            self.assertEqual(1,len(rt.observations()))
