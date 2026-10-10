"""Public evidence boundaries; local unit controls are not service acceptance."""
import tempfile
from pathlib import Path
from types import SimpleNamespace
import pytest
from earned_authority.runtime import Runtime, Denied
from earned_authority.connected import ConnectedRuntime


@pytest.fixture
def runtime():
    with tempfile.TemporaryDirectory() as tmp:
        yield Runtime(Path(tmp)/'registry.sqlite')


def test_self_reports_cannot_supply_qualification_passes(runtime):
    for i in range(3):
        runtime.record_procedure_report('claim-'+str(i), reported_outcome='PASS')
    q=runtime.qualify()
    assert (q['passes'],q['disposition'],q['reason']) == (0,'HOLD','INSUFFICIENT_EVIDENCE')
    assert runtime.observations()==[] and runtime.mutation_count==0
    assert runtime.authority()['grants']=={}


def test_report_retry_retains_identity_and_rebinding_is_rejected(runtime):
    report=runtime.record_procedure_report('claim')
    runtime.clock.advance(10)
    assert runtime.record_procedure_report('claim')==report
    assert len(runtime.events())==1
    with pytest.raises(Denied,match='IDEMPOTENCY_CONFLICT'):
        runtime.record_procedure_report('claim',reported_outcome='FAIL')


@pytest.mark.parametrize('kwargs',[{'agent':''},{'agent':'   '},{'attempt_id':'   '},{'skill':''},{'version':''}])
def test_invalid_procedure_report_cannot_poison_outbox(runtime,kwargs):
    args={'attempt_id':'claim',**kwargs}
    with pytest.raises(Denied,match='INVALID_PROCEDURE_REPORT'):
        runtime.record_procedure_report(**args)
    assert runtime.events()==[] and runtime.procedure_reports()==[]


def test_self_report_never_overrides_independent_failure(runtime):
    for i in range(3):runtime.shadow(attempt_id='shadow-'+str(i))
    q=runtime.qualify();runtime.grant(q['qualification_id'])
    command=runtime.admit(attempt_id='live')
    runtime.record_procedure_report('live',reported_outcome='PASS')
    result=runtime.commit(command,actual='wrong-version')
    assert result['outcome']['outcome']=='FAIL'
    assert result['outcome']['reason']=='POSTCONDITION_NOT_MET'
    assert runtime.qualification(q['qualification_id'])['disposition']=='INELIGIBLE'


@pytest.mark.parametrize('field,value',[('executed',True),('executed',None),('receipt_created',True),('receipt_created',None)])
def test_check_only_rejects_missing_or_positive_side_effect_claims(runtime,field,value):
    response={'executed':False,'receipt_created':False};response[field]=value
    with pytest.raises(Denied,match='INVALID_CHECK_ONLY_PROOF'):
        runtime.record_check_only('check',response)
    assert runtime.events()==[] and runtime.mutation_count==0


def test_check_only_keeps_outcome_and_delivery_separate(runtime):
    proof=runtime.record_check_only('check',{'executed':False,'receipt_created':False})
    assert proof['state']=='AUTHORIZATION_CHECKED'
    assert proof['outcome'] is None and proof['delivery']=='NONE'
    assert proof['receipt_created'] is False and runtime.events()==[]


def test_connected_boundary_maps_invalid_canonical_authority():
    rt=ConnectedRuntime.__new__(ConnectedRuntime);rt.authority_available=True
    def invalid(*args,**kwargs):raise Denied('INVALID_CANONICAL_AUTHORITY')
    rt.passport=SimpleNamespace(current=invalid)
    with pytest.raises(Denied,match='^INVALID_AUTHORITY$'):
        rt.authority()
