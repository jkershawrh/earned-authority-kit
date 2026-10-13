"""Development-only retained-outcome sequence; identical strong policies in both arms."""
import hashlib
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from earned_authority.runtime import Runtime, ControlledClock, Denied
from earned_authority.contracts import canonical_digest
from .controller import prepare
from .grader import grade, snapshot, summarize, registry_unchanged
from .runner import source_hashes, digest

PHASES = ('initial_qualification','retained_success','observed_failure','withdrawn_query',
          'fresh_passes_blocked','expired_without_support','requalified_recovery')
ARMS = ['fixed_deterministic','adaptive_qualification']


def validate_plan(plan):
    if (plan.get('version')!='sequential-development-1' or plan.get('mode')!='DEVELOPMENT_SEQUENTIAL'
            or plan.get('split')!='development' or plan.get('comparators')!=ARMS
            or plan.get('phases')!=list(PHASES) or plan.get('feedback_rule')!='SEAL_EACH_QUERY_BEFORE_NEXT_PHASE'
            or plan.get('policy')!='Both arms retain exact grants and outcomes; identical deterministic qualification rules. No learned policy update.'):
        raise ValueError('Only the frozen development sequence is supported')
    seeds=plan.get('seeds')
    if not isinstance(seeds,list) or not seeds or any(type(s) is not int or s<0 for s in seeds) or len(set(seeds))!=len(seeds):
        raise ValueError('Unique integer seeds required')
    if type(plan.get('deadline_ms')) is not int or plan['deadline_ms']<=0 or type(plan.get('retry_budget')) is not int or plan['retry_budget']!=0:
        raise ValueError('Positive deadline and zero retries required')
    if plan.get('family')!=dict(family_id='registry-sequential-demo',procedure_ancestors=['fixture-model-release-demo'],context_ancestors=['fixture-context-demo'],split='development'):
        raise ValueError('Only the declared development family is supported')
    return plan


def request_for(seed,index):
    opaque=hashlib.sha256(('registry-sequential-demo-'+str(seed)).encode()).hexdigest()[:24]
    return dict(agent='sequential-agent',skill='release-model',version='skill-v1',context=opaque,
                action='release',resource='registry/'+opaque,target='model-'+str(seed)+'-'+str(index),attempt_id=opaque+'-query-'+str(index))


def reference_for(seed,index):
    request=request_for(seed,index)
    blocked=index in (3,4,5)
    return dict(legitimate=True,allowed_to_commit=not blocked,
                candidate_label='INELIGIBLE' if index in (3,4) else 'UNKNOWN' if index==5 else 'ELIGIBLE',
                resource=request['resource'],target=request['target'],attempt_id=request['attempt_id'],request=request)


def retained_observations(previous,current):
    try:
        indexed={o['observation_id']:o for o in current}
        return len(indexed)==len(current) and all(canonical_digest(indexed.get(o['observation_id']))==canonical_digest(o) for o in previous)
    except (KeyError,TypeError,ValueError):
        return False


def run_sequence(workspace,comparator,seed,deadline_ms,on_start=None,on_sealed=None):
    if comparator not in ARMS: raise ValueError('Unsupported comparator')
    workspace=Path(workspace); workspace.mkdir(parents=True,exist_ok=False)
    path=workspace/'registry.sqlite'; rt=Runtime(path,ControlledClock())
    public_key=rt.keys['authority'].public_key()
    with rt._tx() as db:
        db.execute("INSERT INTO registry VALUES ('unrelated/sentinel','keep-v1',1,'setup')")
    rows=[]; prepared=None
    prior_registry=snapshot(path,'sequential-agent',public_key)
    for index,phase in enumerate(PHASES):
        if on_start: on_start(index)
        request=request_for(seed,index); reference=reference_for(seed,index)
        # No grade/reference is passed to the policy. Phase schedule is fixture control.
        if index==5: rt.clock.advance(rt.evidence_window_ms)
        support=[]
        if index in (0,4,6):
            support=[dict(skill=request['skill'],version=request['version'],context=request['context'],
                          attempt_id=request['attempt_id']+'-support-'+str(i),expected=request['target'],actual=request['target']) for i in range(3)]
        retained_before=rt.observations()
        if rows and not retained_observations(rows[-1]['observations_after'],retained_before):
            raise RuntimeError('Retained observation changed between phases')
        preparation_before=snapshot(path,request['agent'],public_key)
        if not registry_unchanged(prior_registry,preparation_before):
            raise RuntimeError('Unauthorized registry mutation between sealed phases')
        prep_start=time.perf_counter_ns()
        if index in (0,4,5,6):
            prepared=prepare(rt,comparator,request,support,request['version'],request['context'])
        elif index==3:
            # Retained outcome has already withdrawn the exact live grant.
            persisted=rt.qualification(prepared['qualification']['qualification_id'])
            prepared={'qualification':persisted,'requested_disposition':persisted['disposition']}
        preparation_ms=(time.perf_counter_ns()-prep_start)/1e6
        before=snapshot(path,request['agent'],public_key)
        if not registry_unchanged(preparation_before,before):
            raise RuntimeError('Unauthorized registry mutation during support preparation')
        observations_prepared=rt.observations()
        if not retained_observations(retained_before,observations_prepared):
            raise RuntimeError('Retained observation removed or altered during preparation')
        command=None; returned={}; denial=None; error=None
        start=time.perf_counter_ns(); admission=time.perf_counter_ns(); decision_ms=None
        try:
            try: command=rt.admit(**request)
            finally: decision_ms=(time.perf_counter_ns()-admission)/1e6
            admitted=snapshot(path,request['agent'],public_key)
            if not registry_unchanged(before,admitted):
                raise RuntimeError('Unauthorized registry mutation during admission')
            before=admitted
            returned=rt.commit(command,actual='wrong-model' if index==2 else None)
        except Denied as exc: denial=exc.reason
        except Exception as exc: error=type(exc).__name__+': '+str(exc)
        after=snapshot(path,request['agent'],public_key)
        task_ms=(time.perf_counter_ns()-start)/1e6
        scored=grade(reference,before,after,command,{**returned,'denial_reason':denial,'error':error},rt.clock.now_ms)
        withdrew=bool(before['authority'].get('grants')) and request['skill'] not in after['authority'].get('grants',{})
        row=dict(comparator=comparator,seed=seed,family_id='registry-sequential-demo',phase=phase,phase_index=index,
                 stratum='stable' if index in (0,1,6) else phase,split='development',reference=reference,request=request,
                 support=support,prepared_qualification=prepared['qualification'],qualification_disposition=prepared['requested_disposition'],
                 preparation_ms=preparation_ms,decision_ms=decision_ms,task_ms=task_ms,timed_out=task_ms>deadline_ms,
                 terminal_state='ERROR' if error else 'DENIED' if denial else scored['controller_outcome'] or 'UNCONFIRMED',
                 denial_reason=denial,error=error,grade=scored,before_commit=before,after_query=after,
                 withdrew_skill=withdrew,withdrawal_acknowledged=withdrew and returned.get('lifecycle_applied') is True,
                 observations_after=rt.observations(),logical_commit_time_ms=rt.clock.now_ms,
                 preparation_before=preparation_before,preparation_after=before,observations_prepared=observations_prepared,
                 sealed_at_utc=datetime.now(timezone.utc).isoformat(),prior_query_sealed=index==0 or bool(rows[-1]['sealed_at_utc']),
                 query_grades_returned_to_controller=False,revocation_ack_ms=None)
        rows.append(row)
        if on_sealed: on_sealed(index,row)
        if scored['unauthorized_commits'] or scored['integrity_errors'] or error:
            raise RuntimeError('Hard invariant or critical query error; sequence stopped')
        expected_disposition='INELIGIBLE' if index in (3,4) else 'HOLD' if index==5 else 'ELIGIBLE'
        persisted_q=after['qualifications'].get(prepared['qualification']['qualification_id'],{})
        if not retained_observations(observations_prepared,row['observations_after']):
            raise RuntimeError('Retained observation removed or altered during query')
        transition_ok=(scored['success']==(index in (0,1,6))
                       and scored['correct_denial']==(index in (3,4,5))
                       and not row['timed_out'] and prepared['requested_disposition']==expected_disposition)
        if index==2:
            transition_ok=transition_ok and withdrew and row['withdrawal_acknowledged'] and persisted_q.get('disposition')=='INELIGIBLE' and scored['controller_outcome']=='FAIL'
        if not transition_ok:
            raise RuntimeError('Expected lifecycle transition failed; sequence stopped')
        prior_registry=after
    return rows


def run(plan_path,workspace,report_path):
    plan_path,workspace,report_path=map(lambda p:Path(p).resolve(),(plan_path,workspace,report_path))
    plan=validate_plan(json.loads(plan_path.read_text()))
    if workspace.exists() or report_path.exists(): raise ValueError('Fresh workspace and report required')
    workspace.mkdir(parents=True); report_path.parent.mkdir(parents=True,exist_ok=True)
    before=source_hashes(); plan_digest=digest(plan_path)
    (workspace/'frozen-input.json').write_text(json.dumps(dict(plan=plan,plan_digest=plan_digest,source_hashes=before),indent=2)+'\n')
    assignments=[]; order=[]
    for seed in plan['seeds']:
        arms=list(ARMS); random.Random(seed).shuffle(arms)
        for arm in arms:
            order.append((seed,arm))
            assignments.extend(dict(comparator=arm,seed=seed,family_id='registry-sequential-demo',phase=phase,
                                    phase_index=i,started=False,reference=reference_for(seed,i)) for i,phase in enumerate(PHASES))
    rows=[]
    report=dict(mode=plan['mode'],split='development',plan_digest=plan_digest,source_hashes_before=before,
                started_at_utc=datetime.now(timezone.utc).isoformat(),assignments=assignments,queries=rows,
                expected_sequences=len(order),expected_queries=len(assignments),execution_order=order,
                held_out=dict(status='NOT_EXECUTED',episodes=0),manual_baseline=dict(status='NOT_EXECUTED'),
                overall_value_acceptance='AMBER',confirmatory_acceptance='AMBER',
                limits=['Both arms use identical retained-state deterministic policy; no learned policy update or adaptive advantage is demonstrated.',
                        'Development fixture with one shared procedure/context ancestry; seeds are not independent populations.',
                        'All seven requested tasks per sequence remain in the legitimate denominator, including policy denials.',
                        'Recovery requires expiry of retained failure plus fresh evidence; failures are never deleted.',
                        'Runtime public outcomes are retained; private read-only grades are not passed to either controller.',
                        'Trusted same-process fixture; sealing records ordering, not cryptographic process isolation.',
                        'Deadline is retrospective; logical time is controlled. Human effort, cost and LLM usage are unmeasured.',
                        'No production, robotics, canonical-service or confirmatory value acceptance.'])
    def persist(): report_path.write_text(json.dumps(report,indent=2)+'\n')
    persist()
    try:
        for seed,arm in order:
            assigned=[a for a in assignments if a['seed']==seed and a['comparator']==arm]
            def started(index): assigned[index]['started']=True; persist()
            def sealed(index,row): rows.append(row); persist()
            run_sequence(workspace/(str(seed)+'-'+arm),arm,seed,plan['deadline_ms'],started,sealed)
        report.update(execution_state='COMPLETED',engineering_acceptance='GREEN')
    except Exception as exc:
        report.update(execution_state='ABORTED',engineering_acceptance='RED',error=type(exc).__name__+': '+str(exc))
    after=source_hashes(); report['source_hashes']=after
    report['source_unchanged_during_run']=before==after and plan_digest==digest(plan_path)
    if not report['source_unchanged_during_run']: report.update(execution_state='ABORTED',engineering_acceptance='RED',error='Source or plan changed')
    started_count=sum(a['started'] for a in assignments)
    report['counts']=dict(assigned_queries=len(assignments),started_queries=started_count,scored_queries=len(rows),
                          started_unscored_queries=started_count-len(rows),unstarted_queries=len(assignments)-started_count)
    report['metrics']=summarize(rows,assignments)
    report['finished_at_utc']=datetime.now(timezone.utc).isoformat(); persist()
    return report
