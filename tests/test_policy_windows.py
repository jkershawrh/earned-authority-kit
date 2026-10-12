"""Window transport and grant boundaries with explicit UNIT service seams.

Real Rego denial is covered by canonical OPA tests and the separate live runner.
"""
import copy
import json
import pytest
from earned_authority.connected import FoundationPolicy, BINDING
from earned_authority.grants import unique_grant
from earned_authority.runtime import Denied
from test_connected_evidence import rt, qualify, CONTEXT

DEMO={"not_before_ms":4102444800000,"not_after_ms":4102444860000}


def foundation(change=lambda d:None):
    p=FoundationPolicy('http://127.0.0.1:1','unit','http://127.0.0.1:2','sha256:'+'1'*64,'policy/id')
    p._inventory=lambda:{'policy/id':p.policy_digest}
    def response(path,body):
        d={**copy.deepcopy(body),'policy_id':'policy/id','policy_digest':p.policy_digest,'effect':'DENY','reason':'POLICY_WINDOW_DENIED','evaluated_at_ms':1000000}
        change(d);return {'decision':d,'executed':False,'receipt_created':False}
    p.request=response;return p


def denied(call,reason):
    with pytest.raises(Denied) as got:call()
    assert got.value.reason==reason


def test_foundation_propagates_only_bound_window_denial():
    denied(lambda:foundation().check('agent','release','model/champion',requested_window=DEMO),'POLICY_WINDOW_DENIED')


@pytest.mark.parametrize('change',[
    lambda d:d.update(agent_id='other'),lambda d:d.update(policy_digest='sha256:'+'2'*64),
    lambda d:d.pop('requested_window'),lambda d:d.update(requested_window={'not_before_ms':1,'not_after_ms':2}),
    lambda d:d.pop('evaluated_at_ms'),lambda d:d.update(evaluated_at_ms=True),
    lambda d:d.update(evaluated_at_ms=-1),lambda d:d.update(evaluated_at_ms=1.5),
    lambda d:d.update(evaluated_at_ms=9007199254740992),
    lambda d:d['requested_window'].update(not_before_ms=float(DEMO['not_before_ms'])),
])
def test_unbound_denial_cannot_claim_policy_window_reason(change):
    denied(lambda:foundation(change).check('agent','release','model/champion',requested_window=DEMO),'POLICY_DECISION_BINDING_MISMATCH')


class WindowPolicy:
    policy_digest='unit-window-policy'
    def __init__(self):self.calls=[];self.reject=False;self.after=lambda:None
    def check(self,agent,action,resource,requested_window=None):
        self.calls.append(copy.deepcopy(requested_window));self.after()
        if self.reject:raise Denied('POLICY_WINDOW_DENIED')
        return {'decision':{'decision_id':'unit-window-check'}}


@pytest.fixture
def ready(rt):
    rt.policy=WindowPolicy();q=qualify(rt);return rt,q


@pytest.mark.parametrize('window',[{}, {'not_before_ms':True,'not_after_ms':2},
    {'not_before_ms':1.5,'not_after_ms':2},{'not_before_ms':2,'not_after_ms':2},
    {'not_before_ms':-1,'not_after_ms':2},{'not_before_ms':1,'not_after_ms':9007199254740992},
    {'not_before_ms':1,'not_after_ms':2,'now_ms':1}])
def test_invalid_grant_window_is_rejected_before_authority_or_policy(ready,window):
    rt,q=ready;denied(lambda:rt.grant(q['qualification_id'],requested_window=window),'INVALID_REQUESTED_WINDOW')
    assert rt.policy.calls==[] and rt.passport.issues==0


def test_policy_window_denial_preserves_eligibility_and_creates_no_authority(ready):
    rt,q=ready;rt.policy.reject=True
    denied(lambda:rt.grant(q['qualification_id'],requested_window=DEMO),'POLICY_WINDOW_DENIED')
    assert rt.qualification(q['qualification_id'])==q and rt.passport.issues==0
    assert rt.authority_operations()==[] and rt.mutation_count==0


def test_future_window_allow_does_not_schedule_or_issue_immediate_authority(ready):
    rt,q=ready;denied(lambda:rt.grant(q['qualification_id'],requested_window=DEMO),'WINDOW_NOT_ACTIVE')
    assert rt.policy.calls==[DEMO] and rt.passport.issues==0 and rt.authority_operations()==[]


def test_active_window_is_signed_and_caps_scope_exactly(ready):
    rt,q=ready;window={'not_before_ms':rt.clock.now_ms,'not_after_ms':rt.clock.now_ms+5123}
    a=rt.grant(q['qualification_id'],requested_window=window,operation_id='window-operation')
    grant=unique_grant(a,'release-model');assert grant['requested_window']==window
    assert grant['expires_at_ms']==window['not_after_ms']
    signed=json.loads(a['canonical']['subject']['scope_set'][0]['context_constraints'][BINDING])
    assert signed['requested_window']==window
    op=rt.authority_operations()[0];assert op['invocation']['requested_window']==window
    assert all(c==window for c in rt.policy.calls)
    cmd=rt.admit(version=rt.procedure_revision,context=CONTEXT,resource='model/champion',attempt_id='window-attempt')
    rt.clock.advance(5123)
    denied(lambda:rt.commit(cmd),'EXPIRED_SCOPE');assert rt.mutation_count==0
    # A repeated already-applied operation describes history; it does not issue
    # another credential or turn the expired credential into current permission.
    issued=rt.passport.issues
    rt.grant(q['qualification_id'],requested_window=window,operation_id='window-operation')
    assert rt.passport.issues==issued
    denied(lambda:rt.grant(q['qualification_id'],requested_window={**window,'not_after_ms':window['not_after_ms']+1},operation_id='window-operation'),'IDEMPOTENCY_CONFLICT')


def test_preflight_rechecks_window_after_synchronous_policy(ready):
    rt,q=ready;window={'not_before_ms':rt.clock.now_ms,'not_after_ms':rt.clock.now_ms+2000}
    def after():
        if len(rt.policy.calls)==2:rt.clock.advance(2000)
    rt.policy.after=after
    with pytest.raises(Denied):rt.grant(q['qualification_id'],requested_window=window)
    assert rt.passport.issues==0


def test_legacy_grant_keeps_prior_invocation_and_signed_shape(ready):
    rt,q=ready;a=rt.grant(q['qualification_id'])
    assert 'requested_window' not in unique_grant(a,'release-model')
    assert 'requested_window' not in rt.authority_operations()[0]['invocation']


def test_window_rechecked_at_execution_even_when_scope_and_passport_live(ready):
    rt,q=ready;window={'not_before_ms':rt.clock.now_ms,'not_after_ms':rt.clock.now_ms+5000}
    rt.grant(q['qualification_id'],requested_window=window)
    cmd=rt.admit(version=rt.procedure_revision,context=CONTEXT,resource='model/champion',attempt_id='window-rollback-clock')
    rt.clock.now_ms-=1
    denied(lambda:rt.commit(cmd),'WINDOW_NOT_ACTIVE');assert rt.mutation_count==0


def test_prepared_window_grant_recovery_after_expiry_cancels_without_issuance(ready):
    rt,q=ready;window={'not_before_ms':rt.clock.now_ms,'not_after_ms':rt.clock.now_ms+2000}
    def interrupt(stage,operation):
        if stage=='intent_committed':raise RuntimeError('unit crash checkpoint before remote dispatch')
    rt.authority_checkpoint=interrupt
    with pytest.raises(RuntimeError,match='unit crash checkpoint'):
        rt.grant(q['qualification_id'],requested_window=window,operation_id='prepared-window-expiry')
    assert rt.authority_operations()[0]['state']=='PREPARED' and rt.passport.issues==0
    rt.authority_checkpoint=None;rt.clock.advance(2000)
    rt.recover_authority_intents()
    operation=rt.authority_operations()[0]
    assert operation['state']=='CANCELLED' and operation['last_error']=='EXPIRED_SCOPE'
    assert rt.passport.issues==0 and rt.authority()['grants']==[] and rt.mutation_count==0
    assert not any(r['event']['event_type']=='GRANTED' for r in rt.events())


def test_execution_policy_crossing_window_end_denies_before_mutation(ready):
    rt,q=ready;window={'not_before_ms':rt.clock.now_ms,'not_after_ms':rt.clock.now_ms+5000}
    rt.grant(q['qualification_id'],requested_window=window)
    cmd=rt.admit(version=rt.procedure_revision,context=CONTEXT,resource='model/champion',attempt_id='window-policy-race')
    rt.policy.after=lambda:rt.clock.advance(5000)
    denied(lambda:rt.commit(cmd),'WINDOW_NOT_ACTIVE')
    assert rt.mutation_count==0 and rt.attempts(cmd['attempt_id'])['state']=='REQUESTED'
    assert not any(r['event']['event_type']=='COMMITTED' and r['event']['attempt_id']==cmd['attempt_id'] for r in rt.events())
