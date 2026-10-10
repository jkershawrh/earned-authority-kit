"""A hold reason is a bounded diagnosis, never a new source of permission."""
import copy
import json
import pytest
from earned_authority.runtime import Denied
from test_connected_evidence import rt,ready,CONTEXT


def admit(rt,**changes):
    return rt.admit(**{'version':rt.procedure_revision,'context':CONTEXT,'resource':'model/champion',**changes})


def hold(rt,cause='missing'):
    q,read=ready(rt);old=admit(rt)
    if cause=='missing':
        with rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',(q['outcome_refs'][0]['attempt_id'],))
        reason='EVIDENCE_UNCONFIRMED'
    else:
        rt.clock.now_ms=q['expires_at_ms'];reason='STALE_EVIDENCE'
    rt.audit_qualification_evidence()
    return q,old,reason


@pytest.mark.parametrize('cause',['missing','stale'])
def test_new_matching_request_gets_precise_hold_but_old_command_remains_revoked(rt,cause):
    q,old,reason=hold(rt,cause)
    with pytest.raises(Denied,match='^'+reason+'$'):admit(rt)
    with pytest.raises(Denied,match='^REVOKED_AUTHORITY$'):rt.commit(old)
    assert rt.qualification(q['qualification_id'])['reason']==reason and rt.mutation_count==0
    if cause=='missing':
        read=admit(rt,skill='read-health',action='read',resource='urn:dataset/health')
        assert rt.commit(read)['outcome']['outcome']=='PASS'


@pytest.mark.parametrize('changes',[{'version':'other'},{'context':{'model_version':'other'}},{'action':'read'},{'resource':'model/other'}])
def test_hold_diagnosis_cannot_be_borrowed_by_a_different_request(rt,changes):
    hold(rt)
    with pytest.raises(Denied,match='^REVOKED_AUTHORITY$'):admit(rt,**changes)
    assert rt.mutation_count==0


def test_manual_revoke_reason_is_not_a_qualification_hold(rt):
    ready(rt);rt.revoke(reason='EVIDENCE_UNCONFIRMED')
    with pytest.raises(Denied,match='^REVOKED_AUTHORITY$'):admit(rt)


def test_later_authority_change_does_not_reuse_old_hold_diagnosis(rt):
    hold(rt);rt.revoke(skill='read-health',reason='operator-request')
    with pytest.raises(Denied,match='^REVOKED_AUTHORITY$'):admit(rt)


def test_valid_replacement_grant_takes_precedence_over_historical_hold(rt):
    hold(rt)
    for i in range(3):rt.shadow(context=CONTEXT,attempt_id='replacement-'+str(i))
    q=rt.qualify(context=CONTEXT);rt.grant(q['qualification_id'])
    assert rt.commit(admit(rt))['outcome']['outcome']=='PASS'


def test_tampered_revoke_journal_cannot_supply_a_hold_diagnosis(rt):
    hold(rt)
    with rt._tx() as db:
        oid,raw=db.execute("SELECT operation_id,record FROM authority_operations WHERE state='APPLIED' ORDER BY rowid DESC LIMIT 1").fetchone()
        body=json.loads(raw);body['reason']='invented-hold'
        db.execute('UPDATE authority_operations SET record=? WHERE operation_id=?',(json.dumps(body),oid))
    with pytest.raises(Denied,match='^AUTHORITY_INTENT_UNAUTHENTICATED$'):admit(rt)
    assert rt.mutation_count==0
