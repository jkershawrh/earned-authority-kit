"""Coordinator evidence integration with explicit local service seams."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from earned_authority.connected import ConnectedRuntime
from earned_authority.runtime import ControlledClock
from earned_authority.runtime import Denied
from earned_authority.contracts import canonical_digest
from earned_authority.grants import has_skill, unique_grant
from test_connected_security import UnitPassport, UnitPolicy


@pytest.fixture
def rt(tmp_path):
    passport=UnitPassport()
    qualifier=SimpleNamespace(evaluate=lambda q,*args,**kwargs:{'disposition':q['disposition'],'reason':q['reason'],'cascade':{}})
    runtime=ConnectedRuntime(tmp_path/'state.sqlite',passport=passport,policy=UnitPolicy(),ledger=None,qualification_client=qualifier,fence_path=tmp_path/'fence')
    runtime.clock=ControlledClock();runtime.ledger.clock=runtime.clock
    passport.now=lambda:runtime.clock.now_ms
    ledger=runtime.ledger
    append,verify=ledger.append,ledger.verify
    def receipt_append(*args,**kwargs):
        value=append(*args,**kwargs)
        return {**value,'written_ts':value['written_at_ms']}
    ledger.append=receipt_append
    ledger.verify=lambda receipt,event:verify({k:v for k,v in receipt.items() if k!='written_ts'},event)
    def detailed(receipt,event,**kwargs):
        if not ledger.available:return {'verified':False,'status':'UNAVAILABLE','reason':'LEDGER_READ_UNAVAILABLE','integrity':'UNKNOWN'}
        ok=ledger.verify(receipt,event)
        return {'verified':ok,'status':'VERIFIED' if ok else 'REJECTED','reason':'VERIFIED' if ok else 'EVENT_BINDING_MISMATCH','integrity':'INTACT' if ok else 'MISMATCH'}
    ledger.verify_detailed=detailed
    return runtime


CONTEXT={'model_version':'model-v2'}


def qualify(rt,skill='release-model'):
    for i in range(3):rt.shadow(skill=skill,context=CONTEXT,attempt_id=skill+'-'+str(i))
    return rt.qualify(skill=skill,context=CONTEXT)


def ready(rt):
    q=qualify(rt);rt.grant(q['qualification_id'])
    read=qualify(rt,'read-health');rt.grant(read['qualification_id'],action='read',resource='urn:dataset/health')
    rt.flush_outbox()
    return q,read


def outcome_row(rt,aid):
    return next(r for r in rt.events() if r['event']['event_type']=='OUTCOME_OBSERVED' and r['event']['attempt_id']==aid)


def test_verified_import_is_durable_and_deduplicated(rt):
    obs=rt.shadow(context=CONTEXT,attempt_id='imported');rt.flush_outbox();row=outcome_row(rt,'imported')
    with rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',('imported',))
    result=rt.admit_evidence(obs,row['event'],row['receipt'],expected_attempt_id='imported',context=CONTEXT)
    assert result['admitted'] and result['counts_as_pass']
    assert rt.admit_evidence(obs,row['event'],row['receipt'],expected_attempt_id='imported',context=CONTEXT)==result
    assert len(rt.observations())==1 and len(rt.evidence_intakes())==1 and rt.mutation_count==0
    assert rt.authority()['grants']==[]


def test_no_observations_remain_insufficient_when_canonical_evaluation_runs_later(rt):
    from earned_authority.qualification_client import QualificationClient
    client=QualificationClient()
    def later(q,*args,**kwargs):
        rt.clock.advance(1)
        return client.evaluate(q,*args,**{**kwargs,'now_ms':rt.clock.now_ms})
    rt.qualifier=SimpleNamespace(evaluate=later)
    for i in range(3):rt.record_procedure_report('claim-'+str(i),version=rt.procedure_revision,context=CONTEXT)
    q=rt.qualify(context=CONTEXT)
    assert (q['passes'],q['disposition'],q['reason'])==(0,'HOLD','INSUFFICIENT_EVIDENCE')
    assert rt.observations()==[] and rt.authority()['grants']==[] and rt.mutation_count==0


def test_rejected_copy_does_not_quarantine_valid_stored_observation(rt):
    q,_=ready(rt);obs=rt.observations()[0];row=outcome_row(rt,obs['attempt_id'])
    bad=copy.deepcopy(obs);bad['readback']['healthy']=False
    rejected=rt.admit_evidence(bad,row['event'],row['receipt'],expected_attempt_id=obs['attempt_id'],context=CONTEXT)
    assert not rejected['admitted'] and rejected['reason']=='TAMPER_DETECTED'
    assert rt.qualification(q['qualification_id'])['disposition']=='ELIGIBLE'
    assert unique_grant(rt.authority(),'release-model')['qualification_id']==q['qualification_id']
    assert rt._observation_admissible(obs)


def test_stored_tamper_is_excluded_and_only_affected_grant_is_held(rt):
    q,read=ready(rt)
    with rt._tx() as db:
        aid,raw=db.execute('SELECT attempt_id,body FROM observations ORDER BY rowid LIMIT 1').fetchone()
        bad=json.loads(raw);bad['readback']['healthy']=False
        db.execute('UPDATE observations SET body=? WHERE attempt_id=?',(json.dumps(bad),aid))
    result=rt.audit_qualification_evidence()
    assert result['reason']=='TAMPER_DETECTED' and not result['verified']
    assert rt.qualification(q['qualification_id'])['disposition']=='HOLD'
    assert not has_skill(rt.authority(),'release-model')
    assert unique_grant(rt.authority(),'read-health')['qualification_id']==read['qualification_id']
    assert rt.qualify(context=CONTEXT)['passes']==2
    assert rt.mutation_count==0


def test_missing_required_observation_holds_without_task_failure(rt):
    q,read=ready(rt)
    with rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',(q['outcome_refs'][0]['attempt_id'],))
    result=rt.audit_qualification_evidence()
    assert result['reason']=='EVIDENCE_UNCONFIRMED'
    assert rt.qualification(q['qualification_id'])['failures']==0
    assert rt.qualification(q['qualification_id'])['disposition']=='HOLD'
    assert unique_grant(rt.authority(),'read-health')['qualification_id']==read['qualification_id']


def test_remote_outage_does_not_hold_authentic_local_evidence(rt):
    q,read=ready(rt);rt.ledger.available=False
    result=rt.audit_qualification_evidence()
    assert result['reason']=='LEDGER_READ_UNAVAILABLE' and not result['verified']
    assert not result['requires_hold']
    assert rt.qualification(q['qualification_id'])['disposition']=='ELIGIBLE'
    assert {g['skill'] for g in rt.authority()['grants']}=={'release-model','read-health'}


def test_local_pending_delivery_does_not_require_remote_receipt(rt):
    q=qualify(rt);rt.grant(q['qualification_id']);rt.ledger.available=False
    result=rt.audit_qualification_evidence()
    assert result['verified'] and not result['requires_hold']
    assert rt.qualification(q['qualification_id'])['disposition']=='ELIGIBLE'


def test_receipt_import_retries_after_remote_verification_recovers(rt):
    obs=rt.shadow(context=CONTEXT,attempt_id='delayed');rt.flush_outbox();row=outcome_row(rt,'delayed')
    with rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',('delayed',))
    rt.ledger.available=False
    first=rt.admit_evidence(obs,row['event'],row['receipt'],expected_attempt_id='delayed',context=CONTEXT)
    assert not first['admitted'] and rt.observations()==[]
    rt.ledger.available=True
    recovered=rt.admit_evidence(obs,row['event'],row['receipt'],expected_attempt_id='delayed',context=CONTEXT)
    assert recovered['admitted'] and len(rt.observations())==1
    assert rt.evidence_intakes()[0]['prior_decisions'][0]['decision']==first


def test_audit_cannot_downgrade_known_failure_while_withdrawal_is_pending(rt):
    q,_=ready(rt)
    command=rt.admit(version=rt.procedure_revision,context=CONTEXT,resource='model/champion')
    rt.passport.fail_mutations=True
    with pytest.raises(Denied):rt.commit(command,actual='wrong-version')
    before=rt.qualification(q['qualification_id'])
    assert before['disposition']=='INELIGIBLE' and before['reason']=='KNOWN_FAILURE'
    result=rt.audit_qualification_evidence()
    assert result['status']=='INELIGIBLE' and result['reason']=='KNOWN_FAILURE'
    assert rt.qualification(q['qualification_id'])==before


def test_failure_during_remote_audit_is_preserved_at_final_transaction(rt):
    q,_=ready(rt)
    command=rt.admit(version=rt.procedure_revision,context=CONTEXT,resource='model/champion')
    committed=[]
    def interleaved(*args,**kwargs):
        rt.passport.fail_mutations=True
        with pytest.raises(Denied):rt.commit(command,actual='wrong-version')
        committed.append(rt.qualification(q['qualification_id']))
        return {'verified':False,'status':'REJECTED','reason':'STORED_HASH_MISMATCH','integrity':'MISMATCH'}
    rt.ledger.verify_detailed=interleaved
    result=rt.audit_qualification_evidence()
    assert committed[0]['disposition']=='INELIGIBLE' and committed[0]['reason']=='KNOWN_FAILURE'
    assert result['status']=='INELIGIBLE' and result['reason']=='KNOWN_FAILURE'
    assert rt.qualification(q['qualification_id'])==committed[0]


def quarantine_first(rt):
    original=rt.ledger.verify_detailed
    rt.ledger.verify_detailed=lambda *a,**k:{'verified':False,'status':'REJECTED','reason':'STORED_HASH_MISMATCH','integrity':'MISMATCH'}
    try:assert rt.audit_qualification_evidence()['reason']=='TAMPER_DETECTED'
    finally:rt.ledger.verify_detailed=original


def test_preexisting_eligible_qualification_cannot_reuse_quarantined_evidence(rt):
    ready(rt);other=rt.qualify(context=CONTEXT)
    quarantine_first(rt)
    with pytest.raises(Denied,match='TAMPER_DETECTED'):
        rt.grant(other['qualification_id'])
    assert not has_skill(rt.authority(),'release-model')


def test_quarantine_during_evaluation_prevents_stale_eligibility_publication(rt):
    ready(rt);evaluate=rt.qualifier.evaluate
    def interleaved(q,*args,**kwargs):
        result=evaluate(q,*args,**kwargs)
        quarantine_first(rt)
        return result
    rt.qualifier.evaluate=interleaved
    other=rt.qualify(context=CONTEXT)
    assert other['disposition']=='HOLD' and other['reason']=='TAMPER_DETECTED'
    assert other['passes']==2 and len(other['outcome_refs'])==2
    with pytest.raises(Denied):rt.grant(other['qualification_id'])


def test_conflicting_valid_import_retries_do_not_duplicate_rejection(rt):
    obs=rt.shadow(context=CONTEXT,attempt_id='collision');rt.flush_outbox()
    body={k:v for k,v in obs.items() if k not in ('signature','evidence_digest')};body['observation_id']='other-observation'
    other=rt._seal(body,'checker');other['evidence_digest']=canonical_digest(other)
    with rt._tx() as db:event=rt._event(db,'OUTCOME_OBSERVED',attempt_id='collision',outcome=other)
    receipt=rt.ledger.append(event,event['event_id'])
    first=rt.admit_evidence(other,event,receipt,expected_attempt_id='collision',context=CONTEXT)
    assert first['reason']=='IDEMPOTENCY_CONFLICT'
    count=len(rt.events())
    assert rt.admit_evidence(other,event,receipt,expected_attempt_id='collision',context=CONTEXT)==first
    assert len(rt.events())==count and rt.evidence_intakes()[0]['prior_decisions']==[]
