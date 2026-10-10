#!/usr/bin/env python3
"""Exercise the actual local stack; failures are retained, never replaced by stubs."""
import argparse
import hashlib
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from earned_authority.connected import ConnectedRuntime,FoundationPolicy
from earned_authority.passport_client import PassportClient
from earned_authority.qualification_client import QualificationClient
from earned_authority.runtime import Denied,ident
from deploy.ledger.validate import read_config,client_from_config
from cryptography.hazmat.primitives import serialization


def build_runtime(args,state_path):
    config=read_config(args.config)
    policy=FoundationPolicy(config['ARE_FOUNDATION_BASE_URL'],config['ARE_FOUNDATION_TOKEN'],config['ARE_OPA_BASE_URL'],config['ARE_OPA_POLICY_DIGEST'],config.get('ARE_OPA_POLICY_ID'),config.get('ARE_OPA_AUTHZ_POLICY_ID'),config.get('ARE_OPA_AUTHZ_POLICY_DIGEST'))
    pubpath=config.get('ARE_PASSPORT_PUBLIC_KEY_PATH')
    if pubpath:
        public=Path(pubpath).read_text()
    else:
        # Provisioning trust is sourced from the locally installed issuer, never the wire.
        key=serialization.load_pem_private_key(Path(config['ARE_PASSPORT_KEY_PATH']).read_bytes(),None)
        public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    task=ROOT.parents[1]
    passport=PassportClient('127.0.0.1:'+config['ARE_PASSPORT_GRPC_PORT'],config['ARE_PASSPORT_MUTATION_TOKEN'],public,
        sdk_path=config.get('PASSPORT_SDK_DIR',str(task/'work/passport-python-sdk')))
    ledger=client_from_config(read_config(args.ledger_config))
    qualifier=QualificationClient(cascade_root=config.get('CASCADE_SOURCE_DIR',str(task/'work/cascade-compression-oss')),
        gcl_root=config.get('GCL_SOURCE_DIR','/Users/jkershaw/Documents/governed-cognitive-loop'),min_samples=3)
    return ConnectedRuntime(state_path,passport=passport,policy=policy,ledger=ledger,qualification_client=qualifier,
        fence_path=config['ARE_PASSPORT_FENCE_LOCK_PATH'])


def run(args):
    args.state_dir.mkdir(parents=True,exist_ok=True)
    tracked_sources=[Path(__file__)]+list((ROOT/'earned_authority').glob('*.py'))
    before_hashes={str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_sources}
    report={'run_id':ident('connected'),'environment':'REAL_LOCAL_SERVICES','started_at':datetime.now(timezone.utc).isoformat(),
        'checks':[],'scope':'Real Passport, Foundation/PostgreSQL/OPA, Cascade, deterministic GCL constraint, canonical Ledger/PostgreSQL; local fenced SQLite registry. No product-value or distributed guarantee.'}
    checks=report['checks'];rt=None
    def check(name,passed,**evidence):
        checks.append({'check':name,'passed':bool(passed),'evidence':evidence})
        if not passed:raise AssertionError(name)
    def deny(name,callback,reason=None):
        before=rt.mutation_count
        try:callback()
        except Denied as e:
            check(name,(reason is None or e.reason==reason) and rt.mutation_count==before,reason=e.reason,mutations=rt.mutation_count)
        else:check(name,False)
    try:
        state=args.state_dir/(report['run_id']+'.sqlite')
        rt=build_runtime(args,state)
        registration=rt.policy.request('/v1/identity/agents',{'agent_type':'earned-authority.registry-procedure','owner_id':'reference-operator'})
        agent=registration['agent']['agent_id']
        check('canonical_identity_is_active',registration['agent']['status']=='ACTIVE',agent_id=agent)
        context={'environment':'disposable-reference','model_version':'model-v2','desired_replicas':1,'max_replicas':2}
        def qualify(skill='release-model',ctx=None):
            ctx=context if ctx is None else ctx
            for _ in range(3):rt.shadow(skill=skill,context=ctx)
            q=rt.qualify(skill=skill,context=ctx)
            check('canonical_qualification_'+skill+'_'+str(len(checks)),q['disposition']=='ELIGIBLE',qualification_id=q['qualification_id'],report=q['canonical_evaluation'])
            return q
        def admit(aid=None,**changes):
            args=dict(agent=agent,version=rt.procedure_revision,context=context,action='release',resource='model/champion',target=context['model_version'],attempt_id=aid or ident('attempt'))
            args.update(changes);return rt.admit(**args)
        q=qualify()
        check('qualification_does_not_issue_authority',not rt.authority(agent)['grants'])
        deny('real_opa_policy_denial',lambda:rt.grant(q['qualification_id'],agent=agent,resource='model/experimental'),'POLICY_DENIED')
        a=rt.grant(q['qualification_id'],agent=agent)
        check('canonical_signed_grant',a['revision']>0 and q['qualification_id']==a['grants']['release-model']['qualification_id'],revision=a['revision'])
        cmd=admit();result=rt.commit(cmd)
        check('fenced_commit_and_independent_pass',rt.mutation_count==1 and result['outcome']['outcome']=='PASS',attempt_id=result['attempt_id'])
        check('canonical_ledger_records_real_lifecycle',result['delivery']=='RECORDED' and result['receipt'] is not None)
        from earned_authority.wire_contracts import export_runtime,consume_bundle,RuntimeTrust
        bundle=export_runtime(rt,qualification_ids=[q['qualification_id']],agent=agent,attempt_ids=[result['attempt_id']])
        consume_bundle(bundle,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)
        wire_path=args.report.with_name(args.report.stem+'-wire.json');wire_path.write_text(json.dumps(bundle.records,indent=2)+'\n')
        check('actual_wire_producer_consumer_bindings',True,records_artifact=str(wire_path))
        original_count=rt.mutation_count
        retried=rt.commit(cmd)
        check('duplicate_attempt_no_second_mutation',retried['outcome']['observation_id']==result['outcome']['observation_id'] and rt.mutation_count==original_count)
        deny('wrong_context_denied',lambda:admit(context={**context,'max_replicas':3}))
        deny('context_cannot_authorize_another_target',lambda:admit(target='model-unqualified'),'CONTEXT_TARGET_MISMATCH')
        read_q=qualify('read-health')
        rt.grant(read_q['qualification_id'],agent=agent,action='read',resource='urn:dataset/health')
        old=admit()
        rt.revoke(agent,'release-model')
        deny('acknowledged_revoke_fences_prior_admission',lambda:rt.commit(old),'REVOKED_AUTHORITY')
        read_result=rt.commit(admit(skill='read-health',action='read',resource='urn:dataset/health'))
        check('selective_withdrawal_preserves_unrelated_skill',read_result['outcome']['outcome']=='PASS' and rt.mutation_count==original_count)
        # Requalification is new evidence/context; no silent reuse of withdrawn grant.
        context={**context,'model_version':'model-v3'}
        newq=qualify()
        rt.grant(newq['qualification_id'],agent=agent)
        fail=rt.commit(admit(),actual='wrong-version')
        check('known_failure_demotes_and_withdraws',fail['outcome']['outcome']=='FAIL' and 'release-model' not in rt.authority(agent)['grants'])
        historical=export_runtime(rt,qualification_ids=[newq['qualification_id']],agent=agent,attempt_ids=[fail['attempt_id']],include_authority=False)
        consume_bundle(historical,trust=RuntimeTrust(rt),now_ms=rt.clock.now_ms)
        check('historical_wire_preserves_prior_qualification_binding',True)
        deny('next_mutation_after_failure_denied',lambda:admit())
        check('failure_preserves_other_skill','read-health' in rt.authority(agent)['grants'])
        # Reopen all consumer adapters against the same durable state.
        mutations=rt.mutation_count
        rt.passport.close();rt.ledger.close();rt.close()
        rt=build_runtime(args,state)
        check('restart_preserves_outcomes_and_demotion',rt.mutation_count==mutations and rt.attempts(fail['attempt_id'])['outcome']['outcome']=='FAIL' and 'release-model' not in rt.authority(agent)['grants'])
        context={**context,'model_version':'model-v4'}
        q4=qualify();rt.grant(q4['qualification_id'],agent=agent)
        paused=admit();ready=threading.Event();go=threading.Event()
        def later():
            ready.set();go.wait(5)
            return rt.commit(paused)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(later);assert ready.wait(5)
            rt.revoke(agent,'release-model');go.set()
            deny('controlled_revocation_race_denied',lambda:future.result(10),'REVOKED_AUTHORITY')
        rt.flush_outbox()
        rows=rt.events()
        check('all_outbox_events_have_verified_canonical_receipts',all(r['delivery']=='RECORDED' and rt.ledger.verify(r['receipt'],r['event']) for r in rows),events=len(rows))
        report.update(execution_state='COMPLETED',acceptance_color='GREEN',agent_id=agent,state_path=str(state),mutation_count=rt.mutation_count,
            procedure_revision=rt.procedure_revision,canonical_sources=rt.qualifier.source_revisions if hasattr(rt.qualifier,'source_revisions') else None)
    except Exception as exc:
        import traceback
        report.update(execution_state='ABORTED',acceptance_color='RED',error=type(exc).__name__+': '+str(exc),traceback=traceback.format_exc())
    finally:
        if rt:
            rt.passport.close();rt.ledger.close();rt.close()
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    report['source_hashes_before']=before_hashes
    report['source_hashes']={str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_sources}
    if before_hashes!=report['source_hashes']:
        report.update(execution_state='ABORTED',acceptance_color='AMBER',error='SOURCE_CHANGED_DURING_RUN')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'report':str(args.report),'status':report['acceptance_color'],'checks':len(checks),'error':report.get('error')}))
    return 0 if report['execution_state']=='COMPLETED' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--ledger-config',type=Path,required=True)
    p.add_argument('--state-dir',type=Path,required=True);p.add_argument('--report',type=Path,default=ROOT/'reports/connected-lifecycle.json')
    raise SystemExit(run(p.parse_args()))
