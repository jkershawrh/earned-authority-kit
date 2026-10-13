"""Fail-closed consumer checks for published development routing evidence."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from earned_authority.contracts import canonical_digest
from earned_authority.runtime import encoded
from .routing import ARMS,PROFILES,validate_plan,task,specification,select,metrics
from .lookup import check_reads
from .grader import grade,registry_unchanged
from .sequential import retained_observations


def signed(value,key,signer):
    try:
        body=dict(value);evidence_digest=body.pop('evidence_digest',None)
        if evidence_digest is not None and evidence_digest!=canonical_digest(body): return False
        canonical_digest(body)
        signature=base64.b64decode(body.pop('signature'),validate=True)
        if body.get('signer')!=signer: return False
        key.verify(signature,encoded(body));return True
    except Exception: return False


def cost_valid(cost,witness,observations,checker,writer):
    try:
        job,work,seal=witness['job'],witness['work'],witness['seal']
        observation=next(o for o in observations if o['attempt_id']==cost['attempt_id'])
        if not all((signed(cost,checker,'checker'),signed(job,writer,'writer'),signed(work,checker,'checker'),signed(observation,checker,'checker'))): return False
        if observation['independent'] is not True: return False
        if cost['job_digest']!=canonical_digest(job) or cost['work_digest']!=canonical_digest(work) or work['job_digest']!=canonical_digest(job): return False
        if work['observation_digest']!=canonical_digest(observation) or cost['observation_digest']!=canonical_digest(observation): return False
        if cost['observation_id']!=observation['observation_id'] or any(canonical_digest(cost[k])!=canonical_digest(observation[k]) for k in ('skill','version','context','outcome','observed_at_ms')): return False
        if any(canonical_digest(cost[k])!=canonical_digest(job[k]) for k in ('candidate','skill','version','context','resource','direction','catalog','key','attempt_id')): return False
        if not check_reads(job['direction'],job['catalog'],job['key'],cost['lookup']) or cost['lookup']!=work['lookup']: return False
        if type(cost['reads']) is not int or cost['reads']!=cost['lookup']['reads'] or (observation.get('readback') or {}).get('version')!=cost['lookup']['model']: return False
        if job['phase']=='SUPPORT': return observation.get('shadow') is True and observation.get('expected')==job['expected']
        return (job['phase']=='QUERY' and signed(seal,writer,'writer') and seal['state']=='SEALED' and seal['task_success'] is True
                and seal['job_digest']==canonical_digest(job) and seal['observation_digest']==canonical_digest(observation))
    except (KeyError,TypeError,ValueError,StopIteration): return False


def qualification_valid(q,candidate,context,observations,checker,now_ms):
    if q.get('skill')!='lookup-'+candidate or q.get('version')!='lookup-v1' or q.get('context')!=context: return False
    selected=[o for o in observations if o.get('skill')==q['skill'] and o.get('version')==q['version'] and o.get('context')==context]
    trusted=[o for o in selected if o.get('independent') is True and signed(o,checker,'checker')]
    fresh=[o for o in trusted if type(o.get('observed_at_ms')) is int and 0<=now_ms-o['observed_at_ms']<600000]
    passes=sum(o['outcome']=='PASS' for o in fresh);failures=sum(o['outcome']=='FAIL' for o in fresh)
    if failures: disposition,reason='INELIGIBLE','KNOWN_FAILURE'
    elif any(o['outcome']=='UNKNOWN' for o in fresh): disposition,reason='HOLD','EVIDENCE_UNCONFIRMED'
    elif trusted and not fresh: disposition,reason='HOLD','STALE_EVIDENCE'
    elif passes>=3: disposition,reason='ELIGIBLE','SUFFICIENT_INDEPENDENT_EVIDENCE'
    elif any(o.get('independent') is True and not signed(o,checker,'checker') for o in selected): disposition,reason='HOLD','UNTRUSTED_ATTESTATION'
    else: disposition,reason='HOLD','INSUFFICIENT_EVIDENCE'
    expected=dict(disposition=disposition,reason=reason,passes=passes,failures=failures,
                  expires_at_ms=min((o['observed_at_ms']+600000 for o in fresh),default=now_ms),evaluated_at_ms=now_ms,
                  qualification_revision=1,skill_digest=canonical_digest(dict(skill=q['skill'],version=q['version'])),
                  context_digest=canonical_digest(dict(environment=context)),
                  evaluator_digest=canonical_digest({'checker':'independent-registry-readback-v1'}),
                  policy_digest=canonical_digest({'required_passes':3,'window_ms':600000,'version':1}),
                  outcome_refs=[{k:o[k] for k in ('attempt_id','observation_id','evidence_digest')} for o in fresh])
    return all(canonical_digest(q.get(k))==canonical_digest(v) for k,v in expected.items())


def valid_report(report,plan):
    try:
        validate_plan(plan)
        expected={(s,p,a,i) for s in plan['seeds'] for p in PROFILES for a in ARMS for i in range(8)}
        key=lambda q:(q['seed'],q['profile'],q['comparator'],q['query_index'])
        rows=report['queries'];assignments=report['assignments']
        if (report['mode']!='DEVELOPMENT_ROUTING' or report['split']!='development' or report['execution_state']!='COMPLETED'
                or report['engineering_acceptance']!='GREEN' or report['source_unchanged_during_run'] is not True
                or report['source_hashes_before']!=report['source_hashes'] or not report['source_hashes']
                or report['expected_queries']!=len(expected) or report['expected_sequences']!=len(expected)//8
                or len(rows)!=len(expected) or {key(q) for q in rows}!=expected
                or len(assignments)!=len(expected) or {key(q) for q in assignments}!=expected
                or any(a.get('started') is not True for a in assignments)
                or report['counts']!=dict(assigned_queries=len(expected),started_queries=len(expected),scored_queries=len(expected),started_unscored_queries=0,unstarted_queries=0)
                or report['held_out']['episodes']!=0 or report['business_value']!='AMBER' or report['confirmatory_acceptance']!='AMBER'
                or report['metrics']!=metrics(rows,assignments)): return False
        for seed in plan['seeds']:
            for profile in PROFILES:
                first_support=[]
                for arm in ARMS:
                    chain=[q for q in rows if q['seed']==seed and q['profile']==profile and q['comparator']==arm]
                    if [q['query_index'] for q in chain]!=list(range(8)): return False
                    prefix,candidates,contexts=specification(seed,profile)
                    support_ids={prefix+'-support-'+c+'-'+str(ctx)+'-'+str(i) for c in candidates for ctx in range(2) for i in (100,102,104)}
                    previous=None;prior_ids=set()
                    for q in chain:
                        j=task(seed,profile,q['query_index']);choice=q['choice']
                        if choice not in candidates or q['candidate_directions']!=candidates or q['error'] is not None or q['timed_out'] is not False or q['work_verified'] is not True or q['query_grades_returned_to_controller'] is not False or q['prior_query_sealed'] is not True or not q['sealed_at_utc']: return False
                        req=q['request'];want=dict(agent=choice,skill='lookup-'+choice,version='lookup-v1',context=j['context'],action='release',resource=j['resource'],target=j['target'],attempt_id=j['attempt_id'])
                        if req!=want or q['reference']!=dict(legitimate=True,allowed_to_commit=True,candidate_label='ELIGIBLE',resource=req['resource'],target=req['target'],attempt_id=req['attempt_id'],request=req): return False
                        if q['catalog']!=j['catalog'] or q['key']!=j['key'] or not check_reads(candidates[choice],j['catalog'],j['key'],q['lookup']): return False
                        if not registry_unchanged(q['preparation_before'],q['preparation_after']) or not registry_unchanged(q['preparation_after'],q['before_commit']): return False
                        if not retained_observations(q['observations_prepared'],q['observations_after']): return False
                        if previous and (not registry_unchanged(previous['after_query'],q['preparation_before']) or not retained_observations(previous['observations_after'],q['observations_prepared']) or previous['checker_public_key']!=q['checker_public_key'] or previous['writer_public_key']!=q['writer_public_key']): return False
                        costs=q['public_cost_input']
                        if len(costs)!=len(support_ids)+len(prior_ids) or {c['attempt_id'] for c in costs}!=support_ids|prior_ids or len({c['observation_id'] for c in costs})!=len(costs): return False
                        checker=Ed25519PublicKey.from_public_bytes(base64.b64decode(q['checker_public_key'],validate=True));writer=Ed25519PublicKey.from_public_bytes(base64.b64decode(q['writer_public_key'],validate=True))
                        if not all(cost_valid(c,q['cost_witnesses'][c['attempt_id']],q['observations_prepared'],checker,writer) for c in costs): return False
                        if set(q['qualifications'])!=set(candidates): return False
                        for candidate,qualification in q['qualifications'].items():
                            qid=qualification['qualification_id']
                            if (not qualification_valid(qualification,candidate,j['context'],q['observations_prepared'],checker,q['logical_commit_time_ms'])
                                    or any(canonical_digest(snapshot['qualifications'].get(qid))!=canonical_digest(qualification) for snapshot in (q['preparation_after'],q['before_commit']))): return False
                        eligible=sorted(c for c,qualification in q['qualifications'].items() if qualification['disposition']=='ELIGIBLE')
                        if sorted(q['eligible_candidates'])!=eligible or q['choice']!=select(arm,eligible,costs,j['context'],j['resource'],q['logical_commit_time_ms'],600000): return False
                        record=q['after_query']['attempts'][req['attempt_id']]['result']
                        if grade(q['reference'],q['before_commit'],q['after_query'],q['command'],record,q['logical_commit_time_ms'])!=q['grade'] or q['grade']['success'] is not True or q['grade']['unauthorized_commits'] or q['grade']['integrity_errors']: return False
                        witness=dict(job=q['published_job'],work=q['published_work'],seal=q['query_seal'])
                        if not cost_valid(q['published_cost'],witness,q['observations_after'],checker,writer) or q['query_seal']['sealed_at_utc']!=q['sealed_at_utc']: return False
                        if q['query_index']==0:
                            projection=[{k:c[k] for k in ('candidate','context','resource','version','outcome','reads','catalog','key','direction')} for c in costs]
                            first_support.append(projection)
                        prior_ids.add(req['attempt_id']);previous=q
                if first_support[0]!=first_support[1]: return False
        return True
    except (KeyError,TypeError,ValueError,IndexError): return False
