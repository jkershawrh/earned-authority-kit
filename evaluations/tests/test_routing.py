import copy
import json
import pytest
from evaluations.harness.routing import ARMS, KIT, validate_plan, select, run, run_sequence, routing_sources
from evaluations.harness.lookup import execute, check_reads


def plan():
    return json.loads((KIT/'evaluations/routing-plan.json').read_text())


def evidence(candidate,context,reads):
    return dict(candidate=candidate,context=context,reads=reads,version='lookup-v1',resource='registry/demo',outcome='PASS',observed_at_ms=0)


def test_contextual_choice_uses_requested_context_and_baseline_uses_all_same_evidence():
    rows=[evidence('a','x',1),evidence('b','x',9),evidence('a','y',9),evidence('b','y',1)]
    assert select('pooled_outcome',['a','b'],rows,'y','registry/demo',0,600000)=='a'
    assert select('contextual_outcome',['a','b'],rows,'y','registry/demo',0,600000)=='b'
    assert select('contextual_outcome',['a'],rows,'y','registry/demo',0,600000)=='a'
    assert select('contextual_outcome',[],rows,'y','registry/demo',0,600000) is None


@pytest.mark.parametrize('change',[{'reads':True},{'reads':0},{'reads':1.0},{'outcome':'UNKNOWN'},{'observed_at_ms':-600000},{'version':'wrong'},{'resource':'other'}])
def test_invalid_stale_or_wrong_binding_cost_cannot_select(change):
    row=evidence('a','x',1);row.update(change)
    assert select('contextual_outcome',['a'],[row],'x','registry/demo',0,600000) is None


@pytest.mark.parametrize('direction',['forward','reverse'])
def test_read_count_comes_from_actual_catalog_accesses_and_trace_is_checked(direction):
    catalog=[dict(key=str(i),model='model-'+str(i)) for i in range(9)]
    result=execute(direction,catalog,'7')
    assert result['model']=='model-7'
    assert result['reads']==(8 if direction=='forward' else 2)
    assert check_reads(direction,catalog,'7',result)
    fake=copy.deepcopy(result);fake['reads']=1
    assert not check_reads(direction,catalog,'7',fake)
    fake=copy.deepcopy(result);fake['trace'][0]=True
    assert not check_reads(direction,catalog,'7',fake)


@pytest.mark.parametrize('field,value',[('mode','CONFIRMATORY'),('split','held_out'),('seeds',[True]),('seeds',[1,1]),('profiles',[]),('retry_budget',1)])
def test_routing_rejects_unfrozen_or_heldout_plan(field,value):
    p=plan();p[field]=value
    with pytest.raises(ValueError): validate_plan(p)


@pytest.mark.parametrize('profile',['opposing','homogeneous'])
def test_real_routing_sequence_keeps_success_and_compares_real_work(tmp_path,profile):
    sequences={a:run_sequence(tmp_path/a,a,17,profile,30000) for a in ARMS}
    for rows in sequences.values():
        assert len(rows)==8
        assert all(q['grade']['success'] and not q['grade']['unauthorized_commits'] and not q['grade']['integrity_errors'] for q in rows)
        assert all(q['work_verified'] and not q['query_grades_returned_to_controller'] and q['prior_query_sealed'] for q in rows)
    counts={a:sum(q['lookup']['reads'] for q in rows) for a,rows in sequences.items()}
    assert (counts['contextual_outcome']<counts['pooled_outcome']) if profile=='opposing' else (counts['contextual_outcome']==counts['pooled_outcome'])


def one_seed_run(tmp_path):
    p=plan();p['seeds']=[17]
    path=tmp_path/'plan.json';path.write_text(json.dumps(p))
    return run(path,tmp_path/'work',tmp_path/'report.json')


def test_routing_hard_stop_retains_all_assigned_tasks(tmp_path,monkeypatch):
    import evaluations.harness.routing as routing
    original=routing.grade
    def corrupt(*args):
        result=original(*args);result['unauthorized_commits']=1;return result
    monkeypatch.setattr(routing,'grade',corrupt)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['scored_queries']==1
    assert report['counts']['assigned_queries']==32
    assert sum(m['task_success']['denominator'] for m in report['metrics'].values())==32


def test_routing_support_mutation_fails_before_query(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.shadow
    def corrupt(self,**kwargs):
        result=original(self,**kwargs)
        with self._tx() as db: db.execute("UPDATE registry SET version='wrong' WHERE resource='unrelated/sentinel'")
        return result
    monkeypatch.setattr(Runtime,'shadow',corrupt)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['started_unscored_queries']==1


def test_routing_admission_mutation_fails(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.admit
    def corrupt(self,**kwargs):
        command=original(self,**kwargs)
        with self._tx() as db: db.execute("UPDATE registry SET version='wrong' WHERE resource='unrelated/sentinel'")
        return command
    monkeypatch.setattr(Runtime,'admit',corrupt)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['queries'][0]['grade']['unauthorized_commits']>0


def test_routing_no_candidate_cannot_fake_success(tmp_path,monkeypatch):
    import evaluations.harness.routing as routing
    monkeypatch.setattr(routing,'select',lambda *args:None)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['queries'][0]['terminal_state']=='DENIED'
    assert report['queries'][0]['lookup'] is None
    assert report['metrics']['contextual_outcome']['lookup_reads']['observed_queries']==0


def test_cost_signature_corruption_stops_run(tmp_path,monkeypatch):
    import evaluations.harness.routing as routing
    original=routing.cost_history
    def corrupt(runtime):
        rows=original(runtime)
        if rows: rows[0]['reads']+=1
        return rows
    monkeypatch.setattr(routing,'cost_history',corrupt)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'cost evidence' in report['error'].lower()


def test_current_sources_include_plan_cli_and_both_procedures():
    hashes=routing_sources()
    assert all(n in hashes for n in ('evaluations/routing-plan.json','tools/run_edd_routing.py','evaluations/harness/lookup.py','evaluations/harness/routing.py'))


def test_replayed_cost_observation_cannot_change_ranking(tmp_path,monkeypatch):
    import evaluations.harness.routing as routing
    original=routing.cost_history
    def duplicate(runtime):
        rows=original(runtime)
        return rows+[copy.deepcopy(rows[0])] if rows else rows
    monkeypatch.setattr(routing,'cost_history',duplicate)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'cost evidence' in report['error'].lower()


def test_known_failure_removes_candidate_from_both_live_policy_choices(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    from evaluations.harness.routing import specification
    bad=sorted(specification(17,'opposing')[1])[0]
    original=Runtime.shadow
    def fail(self,**kwargs):
        result=original(self,**kwargs)
        if kwargs['skill']=='lookup-'+bad:
            failed={**kwargs,'attempt_id':kwargs['attempt_id']+'-known-failure','actual':'wrong-model'}
            original(self,**failed)
        return result
    monkeypatch.setattr(Runtime,'shadow',fail)
    for arm in ARMS:
        rows=run_sequence(tmp_path/arm,arm,17,'opposing',30000)
        assert all(q['choice']!=bad and bad not in q['eligible_candidates'] for q in rows)
        assert all(q['grade']['success'] for q in rows)


def test_revocation_after_admission_prevents_commit(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.admit
    def revoke(self,**request):
        command=original(self,**request)
        self.revoke(agent=request['agent'],skill=request['skill'],reason='INJECTED_REVOCATION')
        return command
    monkeypatch.setattr(Runtime,'admit',revoke)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    q=report['queries'][0]
    assert q['terminal_state']=='DENIED' and q['grade']['unauthorized_commits']==0
    assert q['after_query']['mutations']==q['before_commit']['mutations']


def test_procedure_cannot_replace_host_owned_read_trace(monkeypatch):
    import evaluations.harness.lookup as lookup
    def dishonest(catalog,key):
        found=None
        for i in range(len(catalog)):
            record=catalog[i]
            if record['key']==key: found=record['model']
        try: catalog.trace=[0]
        except AttributeError: pass
        return found
    monkeypatch.setattr(lookup,'scan_forward',dishonest)
    records=[dict(key=str(i),model='model-'+str(i)) for i in range(9)]
    result=lookup.execute('forward',records,'0')
    assert result['reads']==9
    assert not lookup.check_reads('forward',records,'0',result)


def test_cost_publication_cannot_delete_existing_evidence(tmp_path,monkeypatch):
    import evaluations.harness.routing as routing
    original=routing.record_cost
    def delete(runtime,candidate,direction,job,result,observation):
        cost=original(runtime,candidate,direction,job,result,observation)
        if '-query-0' in observation['attempt_id']:
            with runtime._tx() as db:
                old=db.execute("SELECT attempt_id FROM routing_costs WHERE attempt_id LIKE '%support%' LIMIT 1").fetchone()[0]
                db.execute('DELETE FROM routing_costs WHERE attempt_id=?',(old,))
                db.execute('DELETE FROM observations WHERE attempt_id=?',(old,))
        return cost
    monkeypatch.setattr(routing,'record_cost',delete)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert report['counts']['scored_queries']==1


def test_nonindependent_signed_observation_cannot_supply_cost(tmp_path,monkeypatch):
    from earned_authority.runtime import Runtime
    original=Runtime.shadow
    def dependent(self,**kwargs):
        kwargs['independent']=False
        return original(self,**kwargs)
    monkeypatch.setattr(Runtime,'shadow',dependent)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'cost evidence' in report['error'].lower()


@pytest.mark.parametrize('field,value',[('resource','registry/other'),('direction','reverse')])
def test_signed_cost_rebinding_cannot_override_independent_work_receipt(tmp_path,monkeypatch,field,value):
    import evaluations.harness.routing as routing
    original=routing.record_cost
    def rebind(runtime,*args):
        cost=original(runtime,*args);cost[field]=value if cost[field]!=value else 'forward'
        cost=runtime._seal(cost,'checker')
        with runtime._tx() as db: db.execute('UPDATE routing_costs SET body=? WHERE attempt_id=?',(json.dumps(cost),cost['attempt_id']))
        return cost
    monkeypatch.setattr(routing,'record_cost',rebind)
    report=one_seed_run(tmp_path)
    assert report['engineering_acceptance']=='RED'
    assert 'cost evidence' in report['error'].lower()


@pytest.fixture(scope='module')
def audited_routing_run(tmp_path_factory):
    root=tmp_path_factory.mktemp('audited-routing')
    report=one_seed_run(root)
    p=plan();p['seeds']=[17]
    return report,p


def test_complete_public_report_can_be_independently_rechecked(audited_routing_run):
    from evaluations.harness.routing_audit import valid_report
    report,p=audited_routing_run
    assert report['engineering_acceptance']=='GREEN'
    assert valid_report(report,p)


@pytest.mark.parametrize('change',['missing_query','fake_reads','signature','wrong_resource','future_feedback','metric','wrong_choice','unsealed_query'])
def test_public_report_does_not_accept_altered_evidence(audited_routing_run,change):
    from evaluations.harness.routing_audit import valid_report
    original,p=audited_routing_run;report=copy.deepcopy(original);q=report['queries'][0]
    if change=='missing_query': report['queries'].pop()
    elif change=='fake_reads': q['lookup']['reads']=1 if q['lookup']['reads']!=1 else 2
    elif change=='signature': q['public_cost_input'][0]['signature']='bad'
    elif change=='wrong_resource': q['public_cost_input'][0]['resource']='other'
    elif change=='future_feedback': q['public_cost_input'].append(copy.deepcopy(q['published_cost']))
    elif change=='metric': report['metrics'][q['comparator']]['lookup_reads']['total']=0
    elif change=='wrong_choice': q['choice']=next(c for c in q['candidate_directions'] if c!=q['choice'])
    elif change=='unsealed_query': q['query_seal']['state']='UNSEALED'
    assert not valid_report(report,p)


@pytest.mark.parametrize('copies',['public','public_and_snapshots'])
def test_report_cannot_fabricate_competitor_ineligibility(audited_routing_run,copies):
    from evaluations.harness.routing_audit import valid_report
    original,p=audited_routing_run;report=copy.deepcopy(original);q=report['queries'][0]
    other=next(c for c in q['qualifications'] if c!=q['choice'])
    qualification=q['qualifications'][other];qualification['disposition']='HOLD'
    q['eligible_candidates'].remove(other)
    if copies=='public_and_snapshots':
        for field in ('preparation_after','before_commit'):
            q[field]['qualifications'][qualification['qualification_id']]['disposition']='HOLD'
    assert not valid_report(report,p)


def test_candidate_orientation_is_counterbalanced_and_manifest_bound():
    from evaluations.harness.routing import specification
    p=plan();mapping=p['first_candidate_direction_by_seed']
    assert sum(v=='forward' for v in mapping.values())==sum(v=='reverse' for v in mapping.values())==5
    for seed in p['seeds']:
        candidates=specification(seed,'opposing')[1]
        assert candidates[sorted(candidates)[0]]==mapping[str(seed)]
    p['first_candidate_direction_by_seed']={}
    with pytest.raises(ValueError): validate_plan(p)
