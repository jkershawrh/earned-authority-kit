import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from server import Experiment

class BridgeTests(unittest.TestCase):
    def setUp(self): self.e=Experiment(); self.addCleanup(self.e.close)
    def qualify_grant(self):
        for _ in range(3): self.e.act('shadow')
        self.e.act('qualify'); return self.e.act('grant')
    def test_qualification_is_not_permission(self):
        for _ in range(3): self.e.act('shadow')
        s=self.e.act('qualify'); self.assertEqual(s['qualification']['disposition'],'ELIGIBLE');self.assertEqual(s['authority']['grants'],{})
        s=self.e.act('admit');self.assertFalse(s['last']['ok']);self.assertEqual(s['mutations'],0)
    def test_self_report_and_unknown_cannot_qualify(self):
        for _ in range(3): self.e.act('shadow',{'kind':'self'})
        s=self.e.act('qualify');self.assertEqual(s['qualification']['passes'],0)
        self.e.act('reset');self.e.act('shadow');self.e.act('shadow');self.e.act('shadow',{'kind':'unknown'})
        s=self.e.act('qualify');self.assertEqual(s['qualification']['reason'],'EVIDENCE_UNCONFIRMED')
    def test_revocation_between_admit_and_commit_fences_mutation(self):
        self.qualify_grant();self.e.act('admit');self.e.act('revoke');s=self.e.act('commit')
        self.assertFalse(s['last']['ok']);self.assertEqual(s['mutations'],0)
    def test_pass_readback_and_receipt(self):
        self.qualify_grant();self.e.act('admit');s=self.e.act('commit');self.assertEqual(s['execution']['outcome']['outcome'],'PASS');self.assertEqual(s['mutations'],1)
        self.assertTrue(self.e.act('audit')['audit']);self.assertEqual(self.e.act('read')['registry']['version'],'model-v2')
    def test_selective_withdrawal_preserves_read_skill(self):
        self.qualify_grant();self.e.act('read_grant');self.e.act('admit');self.e.act('commit',{'wrong_result':True});s=self.e.act('apply')
        self.assertNotIn('release-model',s['authority']['grants']);self.assertIn('read-health',s['authority']['grants'])
        self.assertTrue(self.e.act('read_skill')['last']['ok'])
    def test_expired_grant_cannot_hold_the_visual_gate_open(self):
        self.qualify_grant();self.assertTrue(self.e.snapshot()['release_check']['allowed'])
        s=self.e.act('expire');self.assertFalse(s['release_check']['allowed']);self.assertEqual(s['release_check']['reason'],'EXPIRED_PASSPORT')
    def test_requalification_requires_new_policy_grant(self):
        self.qualify_grant();self.e.act('revoke');s=self.e.act('requalify');self.assertEqual(s['qualification']['disposition'],'ELIGIBLE');self.assertNotIn('release-model',s['authority']['grants'])
        s=self.e.act('grant');self.assertEqual(s['authority']['grants']['release-model']['version'],'skill-v2')

if __name__=='__main__': unittest.main()
