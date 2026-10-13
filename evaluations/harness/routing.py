"""Frozen development experiment: pooled versus context-conditioned outcome routing."""
import json
import base64
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import hashlib
import random
import time
from fractions import Fraction
from pathlib import Path
from datetime import datetime,timezone
from earned_authority.runtime import Runtime,ControlledClock,Denied
from earned_authority.contracts import canonical_digest
from .runner import KIT,digest,source_hashes
from .grader import snapshot,grade,registry_unchanged
from .sequential import retained_observations
from .lookup import execute,check_reads

ARMS=['pooled_outcome','contextual_outcome']
PROFILES=['opposing','homogeneous']
POLICY='Rank live-eligible candidates by mean verified fresh catalog reads; pooled across contexts or exact requested context; stable candidate-ID ties.'
ORIENTATIONS={'104729': 'forward', '130363': 'reverse', '155921': 'forward', '181081': 'reverse', '208351': 'forward', '233021': 'reverse', '259033': 'forward', '284723': 'reverse', '310019': 'forward', '335999': 'reverse'}


def routing_sources():
    return {**source_hashes(),**{n:digest(KIT/n) for n in ('evaluations/routing-plan.json','tools/run_edd_routing.py')}}


def validate_plan(p):
    if (p.get('version')!='routing-development-1' or p.get('mode')!='DEVELOPMENT_ROUTING' or p.get('split')!='development'
            or p.get('comparators')!=ARMS or p.get('profiles')!=PROFILES or p.get('policy')!=POLICY
            or p.get('feedback_rule')!='SEAL_QUERY_BEFORE_RETAINING_ITS_COST'
            or p.get('support_task_indices')!=[100,102,104] or p.get('first_candidate_direction_by_seed')!=ORIENTATIONS
            or p.get('family')!=dict(family_id='directional-lookup-demo',procedure_ancestors=['directional-catalog-scan-v1'],context_ancestors=['catalog-position-generator-v1'],split='development')):
        raise ValueError('Only the frozen development routing design is supported')
    seeds=p.get('seeds')
    if not isinstance(seeds,list) or not seeds or any(type(s) is not int or s<0 for s in seeds) or len(set(seeds))!=len(seeds): raise ValueError('Unique integer seeds required')
    for name,value in (('queries_per_sequence',8),('catalog_size',9),('retry_budget',0)):
        if type(p.get(name)) is not int or p[name]!=value: raise ValueError('Frozen attempt/work budget required')
    if type(p.get('deadline_ms')) is not int or p['deadline_ms']<=0: raise ValueError('Positive integer deadline required')
    return p


def select(arm,eligible,evidence,context,resource,now_ms,window_ms):
    if arm not in ARMS: raise ValueError('Unknown routing policy')
    means={}
    for candidate in sorted(eligible):
        selected=[e['reads'] for e in evidence if e.get('candidate')==candidate and e.get('version')=='lookup-v1'
                  and e.get('resource')==resource and e.get('outcome')=='PASS'
                  and type(e.get('reads')) is int and e['reads']>0 and type(e.get('observed_at_ms')) is int
                  and 0<=now_ms-e['observed_at_ms']<window_ms and (arm=='pooled_outcome' or e.get('context')==context)]
        if selected: means[candidate]=Fraction(sum(selected),len(selected))
    return min(means,key=lambda candidate:(means[candidate],candidate)) if means else None


def opaque(value): return hashlib.sha256(value.encode()).hexdigest()[:24]


def specification(seed,profile):
    prefix=opaque('lookup-demo-'+profile+'-'+str(seed))
    candidates=sorted([opaque(prefix+'-candidate-one'),opaque(prefix+'-candidate-two')])
    first=ORIENTATIONS.get(str(seed),'forward' if seed%2 else 'reverse')
    directions=[first,'reverse' if first=='forward' else 'forward']
    contexts=[opaque(prefix+'-context-one'),opaque(prefix+'-context-two')]
    return prefix,dict(zip(candidates,directions)),contexts


def task(seed,profile,index):
    prefix,candidates,contexts=specification(seed,profile)
    context_index=index%2
    position=(0 if index%4<2 else 1) if profile=='homogeneous' or context_index==0 else (8 if index%4<2 else 7)
    catalog=[dict(key=opaque(prefix+'-key-'+str(i)),model='model-'+prefix+'-'+str(index)+'-'+str(i)) for i in range(9)]
    return dict(context=contexts[context_index],resource='registry/'+prefix,attempt_id=prefix+'-query-'+str(index),
                key=catalog[position]['key'],catalog=catalog,target=catalog[position]['model'])


def cost_history(runtime):
    with runtime._db() as db:
        return [json.loads(row[0]) for row in db.execute('SELECT body FROM routing_costs ORDER BY rowid')]


def bodies(runtime,table):
    if table not in ('routing_jobs','routing_work','routing_seals'): raise ValueError('Unknown evidence table')
    with runtime._db() as db:
        return [json.loads(row[0]) for row in db.execute('SELECT body FROM '+table+' ORDER BY rowid')]


def register_job(runtime,candidate,direction,job,attempt_id,phase='SUPPORT'):
    intent=runtime._seal(dict(kind='HOST_JOB_FIXTURE',phase=phase,candidate=candidate,skill='lookup-'+candidate,version='lookup-v1',
                             context=job['context'],resource=job['resource'],attempt_id=attempt_id,direction=direction,
                             catalog=job['catalog'],key=job['key'],expected=job['target']),'writer')
    with runtime._tx() as db: db.execute('INSERT INTO routing_jobs VALUES (?,?)',(attempt_id,json.dumps(intent)))
    return intent


def record_work(runtime,candidate,direction,job,result,observation):
    intents={j['attempt_id']:j for j in bodies(runtime,'routing_jobs')}
    intent=intents[observation['attempt_id']]
    if (any(intent[k]!=value for k,value in dict(candidate=candidate,direction=direction,context=job['context'],resource=job['resource'],
                                                catalog=job['catalog'],key=job['key'],expected=job['target']).items())
            or not check_reads(direction,job['catalog'],job['key'],result)):
        raise RuntimeError('Independent work differs from registered job')
    receipt=runtime._seal(dict(kind='HOST_WORK_RECEIPT_FIXTURE',job_digest=canonical_digest(intent),
                              attempt_id=observation['attempt_id'],lookup=result,observation_digest=canonical_digest(observation)),'checker')
    with runtime._tx() as db: db.execute('INSERT INTO routing_work VALUES (?,?)',(receipt['attempt_id'],json.dumps(receipt)))
    return receipt


def record_cost(runtime,candidate,direction,job,result,observation):
    receipt=next(w for w in bodies(runtime,'routing_work') if w['attempt_id']==observation['attempt_id'])
    intent=next(j for j in bodies(runtime,'routing_jobs') if j['attempt_id']==observation['attempt_id'])
    body=dict(candidate=candidate,skill='lookup-'+candidate,version='lookup-v1',context=job['context'],resource=job['resource'],
              attempt_id=observation['attempt_id'],observation_id=observation['observation_id'],observation_digest=canonical_digest(observation),
              outcome=observation['outcome'],observed_at_ms=observation['observed_at_ms'],direction=direction,
              catalog=job['catalog'],key=job['key'],lookup=result,reads=result['reads'],
              job_digest=canonical_digest(intent),work_digest=canonical_digest(receipt))
    body=runtime._seal(body,'checker')
    with runtime._tx() as db: db.execute('INSERT INTO routing_costs VALUES (?,?)',(body['attempt_id'],json.dumps(body)))
    return body


def verified_costs(runtime,records):
    observations={o['attempt_id']:o for o in runtime.observations()}
    jobs={j['attempt_id']:j for j in bodies(runtime,'routing_jobs')}
    work={w['attempt_id']:w for w in bodies(runtime,'routing_work')}
    seals={w['attempt_id']:w for w in bodies(runtime,'routing_seals')}
    if len({c.get('attempt_id') for c in records})!=len(records) or len({c.get('observation_id') for c in records})!=len(records):
        raise RuntimeError('Replayed independent cost evidence')
    for c in records:
        o=observations.get(c.get('attempt_id'));j=jobs.get(c.get('attempt_id'));w=work.get(c.get('attempt_id'))
        if (not runtime._verified(c,{'checker'}) or not o or not runtime._verified(o,{'checker'})
                or o.get('independent') is not True or not j or not w
                or not runtime._verified(j,{'writer'}) or not runtime._verified(w,{'checker'})
                or c.get('job_digest')!=canonical_digest(j) or c.get('work_digest')!=canonical_digest(w)
                or w.get('job_digest')!=canonical_digest(j) or w.get('observation_digest')!=canonical_digest(o)
                or canonical_digest(c.get('lookup'))!=canonical_digest(w.get('lookup'))
                or any(canonical_digest(c.get(k))!=canonical_digest(j.get(k)) for k in ('candidate','skill','version','context','resource','direction','catalog','key'))
                or c.get('observation_digest')!=canonical_digest(o) or c.get('observation_id')!=o['observation_id']
                or any(c.get(k)!=o.get(k) for k in ('skill','version','context','outcome','observed_at_ms'))
                or c.get('skill')!='lookup-'+c.get('candidate','') or c.get('version')!='lookup-v1'
                or not check_reads(c.get('direction'),c.get('catalog'),c.get('key'),c.get('lookup'))
                or type(c.get('reads')) is not int or c['reads']!=c['lookup']['reads']
                or (o.get('readback') or {}).get('version')!=c['lookup']['model']
                or (o.get('shadow') is True and o.get('expected')!=j.get('expected'))
                or j.get('phase') not in ('SUPPORT','QUERY')):
            raise RuntimeError('Invalid signed independent cost evidence')
        if j['phase']=='QUERY':
            seal=seals.get(c['attempt_id'])
            if not seal or not runtime._verified(seal,{'writer'}) or seal.get('state')!='SEALED' or seal.get('task_success') is not True or seal.get('job_digest')!=canonical_digest(j) or seal.get('observation_digest')!=canonical_digest(o):
                raise RuntimeError('Unsealed query cost evidence')
    return records


def retained_costs(previous,current):
    try:
        indexed={c['attempt_id']:canonical_digest(c) for c in current}
        return len(indexed)==len(current) and all(indexed.get(c['attempt_id'])==canonical_digest(c) for c in previous)
    except (KeyError,TypeError,ValueError): return False


def run_sequence(workspace,arm,seed,profile,deadline_ms,on_start=None,on_sealed=None):
    if arm not in ARMS or profile not in PROFILES: raise ValueError('Undeclared routing sequence')
    workspace=Path(workspace);workspace.mkdir(parents=True,exist_ok=False)
    rt=Runtime(workspace/'registry.sqlite',ControlledClock());public_key=rt.keys['authority'].public_key()
    with rt._tx() as db:
        db.execute("INSERT INTO registry VALUES ('unrelated/sentinel','keep-v1',1,'setup')")
        db.execute('CREATE TABLE routing_costs(attempt_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
        db.execute('CREATE TABLE routing_jobs(attempt_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
        db.execute('CREATE TABLE routing_work(attempt_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
        db.execute('CREATE TABLE routing_seals(attempt_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
    prefix,candidates,contexts=specification(seed,profile)
    rows=[];prior_registry=snapshot(rt.path,'no-agent',public_key);prior_observations=[];prior_costs=[];prior_jobs=[];prior_work=[];prior_seals=[]
    for index in range(8):
        if on_start: on_start(index)
        job=task(seed,profile,index)
        entry=snapshot(rt.path,'no-agent',public_key)
        if not registry_unchanged(prior_registry,entry) or not retained_observations(prior_observations,rt.observations()) or not retained_costs(prior_costs,cost_history(rt)) or not retained_costs(prior_jobs,bodies(rt,'routing_jobs')) or not retained_costs(prior_work,bodies(rt,'routing_work')) or not retained_costs(prior_seals,bodies(rt,'routing_seals')):
            raise RuntimeError('State changed between sealed queries')
        prep_start=time.perf_counter_ns()
        if index==0:
            # Both arms run the same support jobs for every candidate/context.
            for context_index,context in enumerate(contexts):
                for support_index in (100,102,104):
                    support_job=task(seed,profile,support_index+context_index)
                    for candidate,direction in candidates.items():
                        support_attempt=prefix+'-support-'+candidate+'-'+str(context_index)+'-'+str(support_index)
                        register_job(rt,candidate,direction,support_job,support_attempt)
                        result=execute(direction,support_job['catalog'],support_job['key'])
                        if not check_reads(direction,support_job['catalog'],support_job['key'],result): raise RuntimeError('Support read trace invalid')
                        obs=rt.shadow(skill='lookup-'+candidate,version='lookup-v1',context=context,
                                      attempt_id=support_attempt,
                                      expected=support_job['target'],actual=result['model'])
                        record_work(rt,candidate,direction,support_job,result,obs)
                        support_observations=rt.observations();support_costs=cost_history(rt);support_jobs=bodies(rt,'routing_jobs');support_work=bodies(rt,'routing_work')
                        record_cost(rt,candidate,direction,support_job,result,obs)
                        if not retained_observations(support_observations,rt.observations()) or not retained_costs(support_costs,cost_history(rt)) or not retained_costs(support_jobs,bodies(rt,'routing_jobs')) or not retained_costs(support_work,bodies(rt,'routing_work')):
                            raise RuntimeError('Support cost evidence publication altered retained evidence')
        qualifications={candidate:rt.qualify(skill='lookup-'+candidate,version='lookup-v1',context=job['context']) for candidate in candidates}
        costs=verified_costs(rt,cost_history(rt))
        available=[candidate for candidate,q in qualifications.items() if q['disposition']=='ELIGIBLE']
        # Private target/reference and profile/index are not policy inputs.
        choice=select(arm,available,costs,job['context'],job['resource'],rt.clock.now_ms,rt.evidence_window_ms)
        if choice is not None and choice not in available: raise RuntimeError('Selector bypassed live qualification')
        if choice is not None: rt.grant(qualifications[choice]['qualification_id'],agent=choice,resource=job['resource'])
        selected=choice or sorted(candidates)[0]
        request=dict(agent=selected,skill='lookup-'+selected,version='lookup-v1',context=job['context'],action='release',
                     resource=job['resource'],target=job['target'],attempt_id=job['attempt_id'])
        prepared=snapshot(rt.path,selected,public_key);observations_prepared=rt.observations();costs_prepared=cost_history(rt)
        if not registry_unchanged(entry,prepared) or not retained_observations(prior_observations,observations_prepared) or not retained_costs(prior_costs,costs_prepared):
            raise RuntimeError('State altered during preparation')
        preparation_ms=(time.perf_counter_ns()-prep_start)/1e6
        reference=dict(legitimate=True,allowed_to_commit=choice is not None,candidate_label='ELIGIBLE' if choice else 'UNKNOWN',
                       resource=job['resource'],target=job['target'],attempt_id=job['attempt_id'],request=dict(request))
        lookup=None;command=None;returned={};denial=None;error=None;before=prepared
        start=time.perf_counter_ns()
        try:
            if choice is None: raise Denied('NO_ELIGIBLE_COSTED_CANDIDATE')
            command=rt.admit(**request)
            admitted=snapshot(rt.path,selected,public_key)
            if not registry_unchanged(prepared,admitted): raise RuntimeError('Registry altered during admission')
            before=admitted
            register_job(rt,choice,candidates[choice],job,job['attempt_id'],phase='QUERY')
            lookup=execute(candidates[choice],job['catalog'],job['key'])
            if not check_reads(candidates[choice],job['catalog'],job['key'],lookup): raise RuntimeError('Query read trace invalid')
            # Expected intent stays immutable; independently grade the actual result.
            returned=rt.commit(command,actual=lookup['model'])
        except Denied as exc: denial=exc.reason
        except Exception as exc: error=type(exc).__name__+': '+str(exc)
        after=snapshot(rt.path,selected,public_key);task_ms=(time.perf_counter_ns()-start)/1e6
        scored=grade(reference,before,after,command,{**returned,'denial_reason':denial,'error':error},rt.clock.now_ms)
        row=dict(comparator=arm,seed=seed,profile=profile,query_index=index,split='development',choice=choice,
                 request=request,reference=reference,catalog=job['catalog'],key=job['key'],lookup=lookup,
                 candidate_directions=candidates,qualifications=qualifications,eligible_candidates=available,
                 command=command,logical_commit_time_ms=rt.clock.now_ms,
                 checker_public_key=base64.b64encode(rt.keys['checker'].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),
                 writer_public_key=base64.b64encode(rt.keys['writer'].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),
                 cost_witnesses={c['attempt_id']:dict(job=next(j for j in bodies(rt,'routing_jobs') if j['attempt_id']==c['attempt_id']),work=next(w for w in bodies(rt,'routing_work') if w['attempt_id']==c['attempt_id']),seal=next((m for m in bodies(rt,'routing_seals') if m['attempt_id']==c['attempt_id']),None)) for c in costs},
                 public_cost_input=costs,preparation_before=entry,preparation_after=prepared,before_commit=before,after_query=after,
                 observations_prepared=observations_prepared,observations_after=rt.observations(),
                 work_verified=lookup is not None and check_reads(candidates[selected],job['catalog'],job['key'],lookup),
                 preparation_ms=preparation_ms,task_ms=task_ms,timed_out=task_ms>deadline_ms,grade=scored,
                 terminal_state='ERROR' if error else 'DENIED' if denial else scored['controller_outcome'] or 'UNCONFIRMED',
                 denial_reason=denial,error=error,sealed_at_utc=datetime.now(timezone.utc).isoformat(),
                 prior_query_sealed=index==0 or bool(rows[-1]['sealed_at_utc']),query_grades_returned_to_controller=False)
        rows.append(row)
        if on_sealed: on_sealed(index,row)
        if scored['unauthorized_commits'] or scored['integrity_errors'] or error: raise RuntimeError('Hard invariant or critical query error')
        if not retained_observations(observations_prepared,rt.observations()) or not retained_costs(costs_prepared,cost_history(rt)):
            raise RuntimeError('Retained evidence removed or altered during query')
        if not scored['success'] or row['timed_out'] or not row['work_verified']: raise RuntimeError('Expected legitimate lookup query failed')
        # Public outcome cost enters ranking only after independent query sealing.
        intent=next(j for j in bodies(rt,'routing_jobs') if j['attempt_id']==request['attempt_id'])
        seal=rt._seal(dict(attempt_id=request['attempt_id'],state='SEALED',task_success=True,job_digest=canonical_digest(intent),observation_digest=canonical_digest(returned['outcome']),sealed_at_utc=row['sealed_at_utc']),'writer')
        with rt._tx() as db: db.execute('INSERT INTO routing_seals VALUES (?,?)',(request['attempt_id'],json.dumps(seal)))
        sealed_observations=rt.observations();sealed_costs=cost_history(rt);sealed_jobs=bodies(rt,'routing_jobs');sealed_work=bodies(rt,'routing_work');sealed_markers=bodies(rt,'routing_seals')
        record_work(rt,selected,candidates[selected],job,lookup,returned['outcome'])
        expected_work=bodies(rt,'routing_work')
        published=record_cost(rt,selected,candidates[selected],job,lookup,returned['outcome'])
        row.update(published_cost=published,published_job=intent,published_work=expected_work[-1],query_seal=seal)
        if not retained_observations(sealed_observations,rt.observations()) or not retained_costs(sealed_costs,cost_history(rt)) or not retained_costs(sealed_jobs,bodies(rt,'routing_jobs')) or not retained_costs(expected_work,bodies(rt,'routing_work')) or not retained_costs(sealed_markers,bodies(rt,'routing_seals')):
            raise RuntimeError('Post-seal publication altered retained evidence')
        if not registry_unchanged(after,snapshot(rt.path,selected,public_key)): raise RuntimeError('Cost publication altered registry')
        prior_registry=after;prior_observations=rt.observations();prior_costs=verified_costs(rt,cost_history(rt));prior_jobs=bodies(rt,'routing_jobs');prior_work=bodies(rt,'routing_work');prior_seals=bodies(rt,'routing_seals')
    return rows


def metrics(rows,assignments):
    result={}
    for arm in ARMS:
        assigned=[a for a in assignments if a['comparator']==arm];selected=[r for r in rows if r['comparator']==arm]
        work=[r['lookup']['reads'] for r in selected if r['lookup'] is not None and r['work_verified']]
        support=[r for r in selected if r['query_index']==0]
        support_reads=sum(c['reads'] for r in support for c in r['public_cost_input']) if support else None
        result[arm]=dict(task_success=dict(numerator=sum(r['grade']['success'] and not r['timed_out'] for r in selected),denominator=len(assigned)),
                        lookup_reads=dict(observed_queries=len(work),total=sum(work),mean=sum(work)/len(work) if work else None),
                        support_lookup_reads=dict(observed_sequences=len(support),total=support_reads),
                        observed_support_and_query_reads=support_reads+sum(work) if support_reads is not None else None,
                        unauthorized_commits=sum(r['grade']['unauthorized_commits'] for r in selected),
                        profiles={p:dict(assigned_queries=sum(a['profile']==p for a in assigned),scored_queries=sum(r['profile']==p for r in selected),
                                         lookup_reads=sum(r['lookup']['reads'] for r in selected if r['profile']==p and r['work_verified'])) for p in PROFILES},
                        operator_effort_minutes=None,monetary_cost=None,llm_calls=None)
    return result


def run(plan_path,workspace,report_path):
    plan_path,workspace,report_path=map(lambda p:Path(p).resolve(),(plan_path,workspace,report_path))
    plan=validate_plan(json.loads(plan_path.read_text()))
    if workspace.exists() or report_path.exists(): raise ValueError('Fresh workspace/report required')
    workspace.mkdir(parents=True);report_path.parent.mkdir(parents=True,exist_ok=True)
    sources=routing_sources();pd=digest(plan_path)
    (workspace/'frozen-input.json').write_text(json.dumps(dict(plan=plan,plan_digest=pd,source_hashes=sources),indent=2)+'\n')
    assignments=[];order=[];rows=[]
    for seed in plan['seeds']:
        for profile in PROFILES:
            arms=list(ARMS);random.Random(str(seed)+profile).shuffle(arms)
            for arm in arms:
                order.append((seed,profile,arm))
                assignments.extend(dict(seed=seed,profile=profile,comparator=arm,query_index=i,started=False) for i in range(8))
    report=dict(mode=plan['mode'],split='development',plan_digest=pd,source_hashes_before=sources,assignments=assignments,queries=rows,
                expected_sequences=len(order),expected_queries=len(assignments),execution_order=order,
                started_at_utc=datetime.now(timezone.utc).isoformat(),business_value='AMBER',confirmatory_acceptance='AMBER',
                manual_baseline=dict(status='NOT_EXECUTED'),held_out=dict(status='NOT_EXECUTED',episodes=0),
                limits=['Development-only positional catalog fixture; no customer or statistical value claim.',
                        'Pooled baseline also retains outcomes and updates ranking; contrast tests context conditioning, not all adaptive learning.',
                        'Catalog-read counts are actual instrumented operations, not elapsed speed, monetary cost, effort or LLM savings.',
                        'Both policies receive the same complete support evidence and share qualification/current authority/mutation enforcement.',
                        'Successful query costs are retained after sealing; outcomes are policy inputs only through signed public evidence.',
                        'Trusted same-process checker and read instrumentation; no hostile-controller process isolation.',
                        'One generator/procedure/context ancestry and dependent repeated queries; seeds are not independent populations.'])
    def persist(): report_path.write_text(json.dumps(report,indent=2)+'\n')
    persist()
    try:
        for seed,profile,arm in order:
            assigned=[a for a in assignments if a['seed']==seed and a['profile']==profile and a['comparator']==arm]
            def started(i): assigned[i]['started']=True;persist()
            def sealed(i,row): rows.append(row);persist()
            run_sequence(workspace/(str(seed)+'-'+profile+'-'+arm),arm,seed,profile,plan['deadline_ms'],started,sealed)
        report.update(execution_state='COMPLETED',engineering_acceptance='GREEN')
    except Exception as exc: report.update(execution_state='ABORTED',engineering_acceptance='RED',error=type(exc).__name__+': '+str(exc))
    report['source_hashes']=routing_sources();report['source_unchanged_during_run']=sources==report['source_hashes'] and pd==digest(plan_path)
    if not report['source_unchanged_during_run']: report.update(execution_state='ABORTED',engineering_acceptance='RED',error='Source or plan changed')
    started=sum(a['started'] for a in assignments)
    report['counts']=dict(assigned_queries=len(assignments),started_queries=started,scored_queries=len(rows),started_unscored_queries=started-len(rows),unstarted_queries=len(assignments)-started)
    report['metrics']=metrics(rows,assignments);report['finished_at_utc']=datetime.now(timezone.utc).isoformat();persist()
    return report
