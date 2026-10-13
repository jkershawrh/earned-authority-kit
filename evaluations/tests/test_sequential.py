import copy
import json
import pytest
from evaluations.harness.sequential import PHASES, validate_plan, run, run_sequence
from evaluations.harness.runner import KIT


def plan():
    return json.loads((KIT/'evaluations/sequential-plan.json').read_text())


@pytest.mark.parametrize('field,value', [('mode','CONFIRMATORY'),('split','held_out'),('seeds',[True]),('seeds',[1,1]),('phases',[]),('retry_budget',1)])
def test_sequence_rejects_unfrozen_design(field,value):
    p=plan(); p[field]=value
    with pytest.raises(ValueError): validate_plan(p)


@pytest.mark.parametrize('arm',['fixed_deterministic','adaptive_qualification'])
def test_retained_failure_blocks_recovery_until_window_expires(tmp_path,arm):
    rows=run_sequence(tmp_path/arm,arm,17,30000)
    assert [r['phase'] for r in rows]==list(PHASES)
    assert [r['grade']['success'] for r in rows]==[True,True,False,False,False,False,True]
    assert [r['grade']['correct_denial'] for r in rows]==[False,False,False,True,True,True,False]
    assert all(not r['grade']['integrity_errors'] and not r['grade']['unauthorized_commits'] for r in rows)
    assert rows[1]['prepared_qualification']['qualification_id']==rows[0]['prepared_qualification']['qualification_id']
    assert rows[2]['withdrawal_acknowledged'] is True
    assert rows[4]['qualification_disposition']=='INELIGIBLE'
    assert rows[5]['qualification_disposition']=='HOLD'
    assert rows[6]['qualification_disposition']=='ELIGIBLE'
    assert len(rows[6]['observations_after'])>len(rows[4]['observations_after'])
    assert any(o['outcome']=='FAIL' for o in rows[6]['observations_after'])
    assert all(r['query_grades_returned_to_controller'] is False for r in rows)
    assert all(r['prior_query_sealed'] for r in rows)


def test_sequence_hard_stop_preserves_assigned_query_denominators(tmp_path,monkeypatch):
    import evaluations.harness.sequential as seq
    original=seq.grade
    def violate(*args):
        result=original(*args); result['unauthorized_commits']=1; return result
    monkeypatch.setattr(seq,'grade',violate)
    p=plan(); p['seeds']=[7]
    path=tmp_path/'plan.json'; path.write_text(json.dumps(p))
    report=run(path,tmp_path/'work',tmp_path/'report.json')
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['scored_queries']==1
    assert report['counts']['assigned_queries']==14
    assert sum(m['task_success']['denominator'] for m in report['metrics'].values())==14
    assert report['counts']['unstarted_queries']==13


def test_sequence_retains_started_unscored_query_on_preparation_crash(tmp_path,monkeypatch):
    import evaluations.harness.sequential as seq
    def fail(*args,**kwargs): raise RuntimeError('preparation unavailable')
    monkeypatch.setattr(seq,'prepare',fail)
    p=plan(); p['seeds']=[7]
    path=tmp_path/'plan.json'; path.write_text(json.dumps(p))
    report=run(path,tmp_path/'work',tmp_path/'report.json')
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['started_unscored_queries']==1
    assert report['counts']['unstarted_queries']==13


def test_sequence_fresh_paths_required(tmp_path):
    output=tmp_path/'existing.json'; output.write_text('original')
    with pytest.raises(ValueError): run(KIT/'evaluations/sequential-plan.json',tmp_path/'work',output)
    assert output.read_text()=='original'


def single_seed_run(tmp_path):
    p=plan(); p['seeds']=[7]
    path=tmp_path/'plan.json'; path.write_text(json.dumps(p))
    return run(path,tmp_path/'work',tmp_path/'report.json')


def test_unexpected_retained_success_denial_cannot_pass(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime,Denied
    original=Runtime.admit
    def deny(self,**request):
        if request['attempt_id'].endswith('-query-1'): raise Denied('INJECTED_DENIAL')
        return original(self,**request)
    monkeypatch.setattr(Runtime,'admit',deny)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['scored_queries']==2


def test_support_mutation_is_detected_before_first_query(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.shadow
    def mutate(self,**kwargs):
        result=original(self,**kwargs)
        with self._tx() as db:
            db.execute("UPDATE registry SET version='unauthorized' WHERE resource='unrelated/sentinel'")
        return result
    monkeypatch.setattr(Runtime,'shadow',mutate)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['scored_queries']==0
    assert 'preparation' in report['error'].lower()


def test_withdrawn_disposition_reads_actual_persisted_qualification(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.apply_outcome
    def corrupt(self,attempt_id):
        result=original(self,attempt_id)
        if result['outcome']['outcome']=='FAIL':
            with self._tx() as db:
                qid=result['command']['qualification_id']
                q=json.loads(db.execute('SELECT body FROM qualifications WHERE id=?',(qid,)).fetchone()[0])
                q['disposition']='ELIGIBLE'
                db.execute('UPDATE qualifications SET body=? WHERE id=?',(json.dumps(q),qid))
        return result
    monkeypatch.setattr(Runtime,'apply_outcome',corrupt)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'transition' in report['error'].lower()


def test_recovery_cannot_delete_retained_failure_observations(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.shadow
    def delete_failure(self,**kwargs):
        result=original(self,**kwargs)
        if '-query-6-support-' in kwargs['attempt_id']:
            with self._tx() as db:
                for attempt,body in db.execute('SELECT attempt_id,body FROM observations').fetchall():
                    if json.loads(body)['outcome']=='FAIL':
                        db.execute('DELETE FROM observations WHERE attempt_id=?',(attempt,))
        return result
    monkeypatch.setattr(Runtime,'shadow',delete_failure)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'retained observation' in report['error'].lower()


def test_admission_cannot_mutate_unrelated_registry(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.admit
    def mutate(self,**kwargs):
        command=original(self,**kwargs)
        with self._tx() as db:
            db.execute("UPDATE registry SET version='unauthorized' WHERE resource='unrelated/sentinel'")
        return command
    monkeypatch.setattr(Runtime,'admit',mutate)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['queries'][0]['grade']['unauthorized_commits']>0


def test_new_support_observations_must_survive_query(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.commit
    def remove(self,command,**kwargs):
        result=original(self,command,**kwargs)
        if command['attempt_id'].endswith('-query-0'):
            with self._tx() as db:
                db.execute("DELETE FROM observations WHERE attempt_id LIKE '%support%'")
        return result
    monkeypatch.setattr(Runtime,'commit',remove)
    report=single_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'retained observation' in report['error'].lower()
    assert report['counts']['scored_queries']==1


def test_observation_retention_preserves_types():
    from evaluations.harness.sequential import retained_observations
    original=[dict(observation_id='o',observed_at_ms=1,outcome='FAIL')]
    alias=[dict(observation_id='o',observed_at_ms=1.0,outcome='FAIL')]
    assert not retained_observations(original,alias)
