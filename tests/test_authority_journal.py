"""Coordinator journal regressions. Stateful UNIT seam, not service evidence."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from earned_authority.connected import ConnectedRuntime
from earned_authority.runtime import ControlledClock, Denied
from earned_authority.contracts import canonical_digest

class Crash(BaseException): pass

class Policy:
    policy_digest='sha256:'+'a'*64
    allowed=True
    def check(self,*args):
        if not self.allowed:raise Denied('POLICY_DENIED')
        return {'decision':{'decision_id':'unit-policy'}}

class OperationPassport:
    """Unit seam with durable-in-test state and idempotent historical receipts."""
    def __init__(self):
        self.state={'subject':None,'revision':0,'status':'REVOKED','signature':None}
        self.operations={};self.issues=0;self.revokes=0;self.now=lambda:1000000
        self.lose_response=False;self.lookup_available=True
        self.reject_without_revision=False
    def current(self,agent,require_valid=True):return copy.deepcopy(self.state)
    def operation(self,agent,oid,expected_request=None):
        if not self.lookup_available:raise Denied('AUTHORITY_OPERATION_UNCONFIRMED')
        value=self.operations.get(oid)
        if value and (value['agent_id']!=agent or expected_request is not None and value['request']!=expected_request):raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        return copy.deepcopy(value)
    def issue(self,agent,scopes,ttl,current,reason,operation_id=None):
        from earned_authority.passport_client import issue_operation_request
        request=issue_operation_request(agent,scopes,ttl,current,reason,operation_id)
        old=self.operation(agent,operation_id,request) if operation_id else None
        if old:return copy.deepcopy(old['authority'])
        if self.reject_without_revision:raise Denied('REVISION_CONFLICT')
        if current['revision']!=self.state['revision']:raise Denied('REVISION_CONFLICT')
        self.issues+=1;revision=self.state['revision']+1
        self.state={'revision':revision,'status':'ACTIVE','signature':'UNIT','subject':{
            'passport_id':'unit-passport-'+str(revision),'agent_id':agent,'issued_ts':self.now(),
            'expires_ts':self.now()+ttl*1000,'reason':reason,
            'scope_set':[{**s,'scope_id':'scope-'+str(i),'granted_ts':self.now(),'expires_ts':self.now()+s['scope_ttl_seconds']*1000} for i,s in enumerate(scopes)]}}
        self._receipt(request,current)
        if self.lose_response:raise Denied('AUTHORITY_UNCONFIRMED')
        return copy.deepcopy(self.state)
    def revoke(self,current,reason,operation_id=None):
        from earned_authority.passport_client import revoke_operation_request
        request=revoke_operation_request(current,reason,operation_id);agent=request['agent_id']
        old=self.operation(agent,operation_id,request) if operation_id else None
        if old:return old
        if current['revision']!=self.state['revision']:raise Denied('REVISION_CONFLICT')
        self.revokes+=1
        self.state={'subject':None,'revision':self.state['revision']+1,'status':'REVOKED','signature':None}
        self._receipt(request,current)
        if self.lose_response:raise Denied('AUTHORITY_UNCONFIRMED')
        return self.operations.get(operation_id,self.state['revision'])
    def _receipt(self,request,previous):
        if not request['operation_id']:return
        subject=self.state['subject'];old=previous['subject']
        self.operations[request['operation_id']]={'canonical_version':'UNIT_RECEIPT',
            'operation_id':request['operation_id'],'agent_id':request['agent_id'],'request':request,
            'request_digest':canonical_digest(request),'agent_revision':self.state['revision'],
            'previous_active_passport_id':old['passport_id'] if old else '',
            'active_passport_id':subject['passport_id'] if subject else '',
            'result':{'action':request['action'],'passport_id':subject['passport_id'] if subject else old['passport_id'],
                      'status':self.state['status'],'completed_ts':self.now()},'authority':copy.deepcopy(self.state)}

class AuthorityJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'registry.sqlite';self.passport=OperationPassport();self.policy=Policy()
        self.clock=ControlledClock(1000000);self.passport.now=lambda:self.clock.now_ms
        self.rt=self.runtime();self.q=self.qualify()
    def runtime(self):
        rt=ConnectedRuntime(self.path,passport=self.passport,policy=self.policy,ledger=None,qualification_client=None,fence_path=Path(self.tmp.name)/'fence')
        rt.clock=self.clock;return rt
    def qualify(self,skill='release-model',model='model-v2'):
        context={'model_version':model,'desired_replicas':1,'max_replicas':2}
        q={'qualification_id':'q-'+skill+'-'+model,'qualification_revision':1,'skill':skill,
           'version':self.rt.procedure_revision,'context':context,
           'skill_digest':canonical_digest({'skill':skill,'version':self.rt.procedure_revision}),
           'context_digest':canonical_digest({'environment':context}),'expires_at_ms':self.clock.now_ms+300000,
           'disposition':'ELIGIBLE','reason':'UNIT_ELIGIBLE'}
        with self.rt._tx() as db:self.rt._save_qualification(db,q)
        return q
    def stop_at(self,stage):
        def hook(actual,operation):
            if actual==stage:raise Crash(stage)
        self.rt.authority_checkpoint=hook
    def events(self,kind):return [r['event'] for r in self.rt.events() if r['event']['event_type']==kind]
    def grant(self,**kwargs):return self.rt.grant(self.q['qualification_id'],operation_id='op-grant',**kwargs)
    def test_crash_after_intent_before_rpc_recovers_once(self):
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.grant()
        self.assertEqual(0,self.passport.issues);self.assertEqual('PREPARED',self.rt.authority_operations()[0]['state'])
        self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(1,self.passport.issues);self.assertEqual(1,len(self.events('GRANTED')))
    def test_remote_success_before_local_event_recovers_from_receipt(self):
        self.stop_at('remote_committed')
        with self.assertRaises(Crash):self.grant()
        self.assertEqual(1,self.passport.issues);self.assertEqual([],self.events('GRANTED'))
        pending=self.rt.authority_operations()[0];self.assertEqual('DISPATCHED',pending['state'])
        self.rt=self.runtime();self.rt.recover_authority_intents();self.rt.recover_authority_intents()
        self.assertEqual(1,self.passport.issues);event=self.events('GRANTED')[0]
        self.assertEqual(pending['event_id'],event['event_id']);self.assertEqual('op-grant',event['authority_operation_id'])
        self.assertEqual('APPLIED',self.rt.authority_operations()[0]['state'])
    def test_event_and_applied_marker_commit_atomically(self):
        self.stop_at('event_committed')
        with self.assertRaises(Crash):self.grant()
        self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(1,len(self.events('GRANTED')));self.assertEqual(1,self.passport.issues)
    def test_lost_response_recovers_without_new_revision(self):
        self.passport.lose_response=True
        with self.assertRaises(Denied):self.grant()
        self.passport.lose_response=False;self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(1,self.passport.issues);self.assertEqual(1,self.passport.state['revision'])
        self.assertEqual(1,len(self.events('GRANTED')))
    def test_revoke_to_empty_has_its_own_historical_receipt(self):
        self.grant();self.stop_at('remote_committed')
        with self.assertRaises(Crash):self.rt.revoke(operation_id='op-revoke')
        self.assertIsNone(self.passport.state['subject']);self.assertEqual([],self.events('REVOKED'))
        self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(1,self.passport.revokes);self.assertEqual(1,len(self.events('REVOKED')))
        self.assertEqual('op-revoke',self.events('REVOKED')[0]['authority_operation_id'])
    def test_later_replacement_does_not_erase_old_operation_evidence(self):
        self.stop_at('remote_committed')
        with self.assertRaises(Crash):self.grant()
        raw=self.passport.current('agent-a');scopes=[{k:v for k,v in s.items() if k not in ('scope_id','granted_ts','expires_ts')} for s in raw['subject']['scope_set']]
        self.passport.issue('agent-a',scopes,300,raw,'another trusted writer',operation_id='other-writer')
        self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(2,self.passport.state['revision']);self.assertEqual(1,self.events('GRANTED')[0]['authority_revision'])
        self.assertEqual(2,self.rt.authority()['revision'])
    def test_idempotent_public_retry_does_not_reissue(self):
        self.grant();self.grant()
        self.assertEqual(1,self.passport.issues);self.assertEqual(1,len(self.events('GRANTED')))
    def test_operation_id_cannot_be_rebound(self):
        self.grant();other=self.qualify(model='model-v3')
        with self.assertRaises(Denied) as got:self.rt.grant(other['qualification_id'],operation_id='op-grant')
        self.assertEqual('IDEMPOTENCY_CONFLICT',got.exception.reason);self.assertEqual(1,self.passport.issues)
    def test_pending_operation_blocks_existing_authority(self):
        self.grant();other=self.qualify('read-health')
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.rt.grant(other['qualification_id'],action='read',resource='urn:dataset/health')
        with self.assertRaises(Denied) as got:self.rt.admit(version=self.rt.procedure_revision,context=self.q['context'],resource='model/champion')
        self.assertEqual('AUTHORITY_OPERATION_PENDING',got.exception.reason);self.assertEqual(0,self.rt.mutation_count)
    def test_failed_local_intent_never_calls_canonical_mutation(self):
        self.rt.local_durability_available=False
        with self.assertRaises(Denied):self.grant()
        self.assertEqual(0,self.passport.issues);self.assertEqual([],self.rt.authority_operations())
    def test_untrusted_local_writer_cannot_revoke(self):
        self.grant();self.rt.local_writer_authenticated=False
        with self.assertRaises(Denied):self.rt.revoke()
        self.assertEqual(0,self.passport.revokes)
    def test_local_intent_tamper_blocks_recovery_and_execution(self):
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.grant()
        with self.rt._tx() as db:
            row=db.execute('SELECT record FROM authority_operations').fetchone();body=json.loads(row[0]);body['invocation']['qid']='other'
            db.execute('UPDATE authority_operations SET record=?',(json.dumps(body),))
        self.rt=self.runtime()
        with self.assertRaises(Denied):self.rt.recover_authority_intents()
        self.assertEqual(0,self.passport.issues)
    def test_missing_lookup_never_infers_success_from_current_revision(self):
        self.stop_at('remote_committed')
        with self.assertRaises(Crash):self.grant()
        self.passport.lookup_available=False;self.rt=self.runtime()
        with self.assertRaises(Denied):self.rt.recover_authority_intents()
        self.assertEqual([],self.events('GRANTED'))
        self.assertEqual('DISPATCHED',self.rt.authority_operations()[0]['state'])
    def test_never_dispatched_intent_is_cancelled_when_policy_changes(self):
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.grant()
        self.policy.allowed=False;self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual('CANCELLED',self.rt.authority_operations()[0]['state']);self.assertEqual(0,self.passport.issues)
    def test_dispatched_unknown_is_not_cancelled_when_policy_changes(self):
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.grant()
        # Validly signed DISPATCHED models a crash after dispatch marker but before call.
        operation=self.rt.authority_operations()[0]
        with self.rt._tx() as db:self.rt._store_authority_operation(db,{**operation,'state':'DISPATCHED'})
        self.policy.allowed=False;self.rt=self.runtime()
        with self.assertRaises(Denied):self.rt.recover_authority_intents()
        self.assertEqual('DISPATCHED',self.rt.authority_operations()[0]['state']);self.assertEqual(0,self.passport.issues)

    def test_precondition_refusal_without_cas_advance_cannot_cancel_unknown_dispatch(self):
        self.passport.reject_without_revision=True
        with self.assertRaises(Denied):self.grant()
        self.assertEqual('DISPATCHED',self.rt.authority_operations()[0]['state'])
        self.assertEqual(0,self.passport.state['revision'])

    def test_advanced_authority_without_matching_operation_cancels_stale_cas(self):
        self.stop_at('intent_committed')
        with self.assertRaises(Crash):self.grant()
        op=self.rt.authority_operations()[0]
        request=op['request']['issue']
        self.passport.issue('agent-a',request['requested_scopes'],request['ttl_seconds'],op['prior_authority'],'different operation',operation_id='intervening-op')
        self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual('CANCELLED',self.rt.authority_operations()[0]['state'])
        self.assertEqual([],self.events('GRANTED'));self.assertEqual(1,self.passport.state['revision'])

if __name__=='__main__':unittest.main()
