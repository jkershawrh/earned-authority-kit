"""Mutation-boundary binding unit regressions; real-service reruns are separate."""
import unittest
from earned_authority.connected import ConnectedRuntime
from earned_authority.runtime import ControlledClock,Denied
from earned_authority.contracts import canonical_digest

class BindingRegression(unittest.TestCase):
    def test_a_signed_grant_cannot_borrow_another_skills_qualification(self):
        rt=ConnectedRuntime.__new__(ConnectedRuntime);rt.clock=ControlledClock();rt.procedure_revision='rev1'
        rt._assert_authority_ready=lambda db,agent:None  # this test isolates skill binding
        q={'qualification_id':'q1','skill':'original-skill','version':'rev1','context':{'model_version':'model-v2'},
           'skill_digest':canonical_digest({'skill':'original-skill','version':'rev1'}),
           'context_digest':canonical_digest({'environment':{'model_version':'model-v2'}})}
        grant={**q,'grant_id':'grant-1','skill':'different-skill',
               'skill_digest':canonical_digest({'skill':'different-skill','version':'rev1'}),
               'action':'release','resource':'model/champion',
               'qualification_digest':canonical_digest(q),'policy_digest':'policy','expires_at_ms':2000000}
        rt.authority=lambda agent:{'grants':[grant],'status':'ACTIVE','revision':1,'expires_at_ms':2000000}
        rt.eligibility=lambda *args:q
        class Policy:
            policy_digest='policy'
            def check(self,*args):return {'decision':{'decision_id':'policy-1'}}
        rt.policy=Policy()
        intent={'agent':'agent','skill':'different-skill','version':'rev1','context':q['context'],
                'action':'release','resource':'model/champion','target':'model-v2'}
        with self.assertRaises(Denied) as got:rt._check(None,intent,1)
        self.assertEqual('BINDING_MISMATCH',got.exception.reason)

class PolicyDecisionBinding(unittest.TestCase):
    def policy(self,change):
        from earned_authority.connected import FoundationPolicy
        p=FoundationPolicy('http://127.0.0.1:1','test','http://127.0.0.1:2','sha256:'+'1'*64,'policy/id')
        p._inventory=lambda:{'policy/id':p.policy_digest}
        def response(path,body):
            decision={**body,'effect':'ALLOW','reason':'test','policy_id':'policy/id','policy_digest':p.policy_digest}
            change(decision)
            return {'decision':decision}
        p.request=response
        return p
    def test_missing_evaluated_policy_binding_denies(self):
        p=self.policy(lambda d:d.pop('policy_digest'))
        with self.assertRaises(Denied):p.check('agent','release','model/champion')
    def test_decision_for_another_subject_denies(self):
        p=self.policy(lambda d:d.update(agent_id='other'))
        with self.assertRaises(Denied):p.check('agent','release','model/champion')
    def test_another_evaluated_policy_denies(self):
        p=self.policy(lambda d:d.update(policy_digest='sha256:'+'2'*64))
        with self.assertRaises(Denied):p.check('agent','release','model/champion')
    def test_matching_evaluation_binding_passes(self):
        p=self.policy(lambda d:None)
        self.assertEqual('ALLOW',p.check('agent','release','model/champion')['decision']['effect'])
