"""Per-attempt checks are consumption evidence, never retroactive issuance."""
import base64
import copy
import json
import sqlite3
import pytest
from earned_authority.contracts import canonical_digest
from earned_authority.runtime import Runtime, Denied, encoded
from earned_authority.wire_contracts import export_runtime, consume_bundle, RuntimeTrust, WireContractError, WireBundle

CHECKS={'QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED'}

@pytest.fixture
def rt(tmp_path):
    rt=Runtime(tmp_path/'state.sqlite')
    for i in range(3):rt.shadow(attempt_id='training-'+str(i))
    q=rt.qualify();rt.grant(q['qualification_id'])
    return rt

def rows(rt,aid):
    return [r for r in rt.events() if r['event']['attempt_id']==aid and r['event']['event_type'] in CHECKS]

def bundle(rt,aid):
    return export_runtime(rt,attempt_ids=[aid],include_authority=False)

def test_checks_bind_actual_boundary_without_rewriting_prior_qualification_or_grant(rt):
    before=copy.deepcopy(rt.events());cmd=rt.admit(attempt_id='live')
    q=rt.qualification_at(cmd['qualification_id'],digest=cmd['qualification_digest'])
    rt.clock.advance(1);result=rt.commit(cmd);checks=rows(rt,'live')
    assert {r['event']['event_type'] for r in checks}==CHECKS and len(checks)==2
    for row in checks:
        e=row['event']
        assert e['attempt_id']==e['correlation_id']=='live'
        assert e['command_digest']==canonical_digest(cmd)
        assert e['qualification_revision']==q['qualification_revision']
        for key in ('skill_digest','context_digest','qualification_id','qualification_digest','passport_id','grant_id','authority_revision','policy_digest','action','resource'):
            assert e[key]==cmd[key]
        assert e['policy_decision_id']==result['policy_decision_id']!=cmd['policy_decision_id']
        assert row['delivery']=='RECORDED' and rt.ledger.verify(row['receipt'],e)
        assert e['check_stage']=='MUTATION_BOUNDARY' and e['authorizes_execution'] is False
    assert [r['event'] for r in rt.events()[:len(before)]]==[r['event'] for r in before]
    assert rt.qualification_at(cmd['qualification_id'],digest=cmd['qualification_digest'])==q
    assert consume_bundle(bundle(rt,'live'),trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)['verified']
    assert rt.mutation_count==1

def test_retry_and_restart_preserve_one_check_pair(rt):
    cmd=rt.admit(attempt_id='live');rt.commit(cmd);first=rows(rt,'live')
    restarted=Runtime(rt.path,clock=rt.clock)
    restarted.retry(cmd)
    assert len(first)==2 and rows(restarted,'live')==first and restarted.mutation_count==1

@pytest.mark.parametrize('key,value',[
    ('grant_id','invented-grant'),('passport_id','invented-passport'),
    ('skill_digest','sha256:'+'0'*64),('context_digest','sha256:'+'0'*64),
    ('policy_digest','sha256:'+'0'*64),
])
def test_authenticated_command_cannot_misattribute_the_actual_authorization_check(rt,key,value):
    cmd=rt.admit(attempt_id='live');cmd[key]=value;cmd=rt._seal(cmd,'authority')
    # A trusted producer can make a semantic mistake; a valid signature alone
    # must not let an attempt name a different current grant or policy.
    with rt._db() as db:db.execute('UPDATE attempts SET command=? WHERE id=?',(json.dumps(cmd),'live'))
    with pytest.raises(Denied,match='BINDING_MISMATCH'):rt.commit(cmd)
    assert rt.mutation_count==0 and rows(rt,'live')==[] and rt.attempts('live')['state']=='REQUESTED'

@pytest.mark.parametrize('kind',sorted(CHECKS))
def test_actual_check_write_failure_rolls_back_checks_intent_and_mutation(rt,kind):
    cmd=rt.admit(attempt_id='live')
    with rt._db() as db:
        db.execute("CREATE TRIGGER refuse_check BEFORE INSERT ON events WHEN json_extract(NEW.body,'$.event_type')='"+kind+"' BEGIN SELECT RAISE(ABORT,'check persistence unavailable'); END")
    with pytest.raises(Denied,match='LOCAL_DURABILITY_UNAVAILABLE'):rt.commit(cmd)
    assert rows(rt,'live')==[] and rt.mutation_count==0 and rt.read()['version']=='model-v1'
    assert rt.attempts('live')['state']=='REQUESTED'
    assert not [r for r in rt.events() if r['event']['attempt_id']=='live']

@pytest.mark.parametrize('key,value',[
    ('qualification_revision',999),('qualification_digest','sha256:'+'0'*64),
    ('grant_id','borrowed-grant'),('policy_decision_id','admission-only-decision'),
    ('command_digest','sha256:'+'0'*64),('correlation_id','another-attempt'),
    ('resource','another-resource'),('authorizes_execution',True),
])
def test_authenticated_but_misattributed_check_cannot_be_exported_as_attempt_proof(rt,key,value):
    cmd=rt.admit(attempt_id='live');rt.commit(cmd)
    checks=rows(rt,'live');assert len(checks)==2
    event=copy.deepcopy(checks[0]['event']);event[key]=value
    signature=base64.b64encode(rt.keys['writer'].sign(encoded(event))).decode()
    with rt._db() as db:db.execute('UPDATE events SET body=?,signature=?,delivery=?,receipt=NULL WHERE id=?',
                                  (json.dumps(event),signature,'PENDING',event['event_id']))
    with pytest.raises(WireContractError):bundle(rt,'live')

def test_consumer_rejects_omitted_check_record_even_with_retained_authenticated_proof(rt):
    rt.execute(attempt_id='live');b=bundle(rt,'live')
    b.records=[r for r in b.records if not (r['kind']=='lifecycle-event' and r['value']['event_type']=='QUALIFICATION_CHECKED')]
    with pytest.raises(WireContractError):consume_bundle(b,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)

@pytest.mark.parametrize('kind',['QUALIFICATION_CHECKED','COMMITTED'])
def test_same_attempt_label_cannot_substitute_a_different_authenticated_check_event(rt,kind):
    rt.execute(attempt_id='live');b=bundle(rt,'live')
    source=next(r['event'] for r in rt.events() if r['event']['attempt_id']=='live' and r['event']['event_type']==kind)
    fields={k:v for k,v in source.items() if k not in ('event_id','event_type','agent_id','attempt_id','occurred_at_ms')}
    fields['authority_revision']=999
    with rt._tx() as db:other=rt._event(db,kind,'agent-a','live',**fields)
    row=next(r for r in rt.events() if r['event_id']==other['event_id'])
    replacement=WireBundle();replacement.add('lifecycle-event','event',event=replacement.proof('event',row))
    b.records=[r for r in b.records if not (r['kind']=='lifecycle-event' and r['value']['event_type']==kind)]
    b.records.extend(replacement.records);b.proof_store.update(replacement.proof_store)
    with pytest.raises(WireContractError):consume_bundle(b,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)

def test_requested_attempt_has_no_claim_of_completed_checks(rt):
    rt.admit(attempt_id='pending');b=bundle(rt,'pending')
    assert rows(rt,'pending')==[] and rt.mutation_count==0
    assert consume_bundle(b,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)['verified']

def test_pre_upgrade_committed_attempt_remains_historical_without_fabricated_checks(rt):
    cmd=rt.admit(attempt_id='old')
    assert cmd.get('execution_checks_version')==1
    legacy={k:v for k,v in cmd.items() if k not in ('execution_checks_version','signature','signer')}
    legacy=rt._seal(legacy,'authority')
    with rt._db() as db:db.execute('UPDATE attempts SET command=? WHERE id=?',(json.dumps(legacy),'old'))
    rt.commit(legacy)
    with rt._db() as db:db.execute("DELETE FROM events WHERE json_extract(body,'$.event_type') IN ('QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED')")
    b=bundle(rt,'old')
    next(r for r in b.records if r['kind']=='attempt')['inputs'].pop('checks')
    assert consume_bundle(b,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)['verified']
    assert rows(rt,'old')==[]

def test_new_attempt_cannot_remove_checks_proof_input_to_claim_legacy_format(rt):
    rt.execute(attempt_id='live');b=bundle(rt,'live')
    next(r for r in b.records if r['kind']=='attempt')['inputs'].pop('checks')
    with pytest.raises(WireContractError):consume_bundle(b,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)

@pytest.mark.parametrize('version',[True,1.0,2,None])
def test_unknown_or_ambiguous_check_version_denies_before_mutation(rt,version):
    cmd=rt.admit(attempt_id='live');cmd['execution_checks_version']=version;cmd=rt._seal(cmd,'authority')
    with rt._db() as db:db.execute('UPDATE attempts SET command=? WHERE id=?',(json.dumps(cmd),'live'))
    with pytest.raises(Denied,match='BINDING_MISMATCH'):rt.commit(cmd)
    assert rt.mutation_count==0 and rows(rt,'live')==[]
