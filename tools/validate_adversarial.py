#!/usr/bin/env python3
"""Deterministic fault schedules on the actual connected local reference."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from validate_connected import build_runtime,ROOT
from earned_authority.runtime import Denied,ident
from deploy.ledger.validate import read_config,client_from_config


def run(args):
    args.state_dir.mkdir(parents=True,exist_ok=True)
    tracked_sources=[Path(__file__)]+list((ROOT/'earned_authority').glob('*.py'))
    before_hashes={str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_sources}
    report={'run_id':ident('adversarial'),'environment':'REAL_LOCAL_SERVICES','started_at':datetime.now(timezone.utc).isoformat(),
        'scope':'Bounded engineering fault evaluation; no comparator value or statistical reliability claim','checks':[]}
    rt=None;checks=report['checks']
    def check(name,ok,**evidence):
        checks.append({'check':name,'passed':bool(ok),'evidence':evidence})
        if not ok:raise AssertionError(name)
    try:
        state=args.state_dir/(report['run_id']+'.sqlite');rt=build_runtime(args,state)
        def ready(label,scope_ttl_ms=None):
            agent=rt.policy.request('/v1/identity/agents',{'agent_type':'earned-authority.fault-'+label,'owner_id':'reference-operator'})['agent']['agent_id']
            context={'environment':'fault-'+label+'-'+report['run_id'],'model_version':'model-'+label,'desired_replicas':1,'max_replicas':2}
            for _ in range(3):rt.shadow(context=context)
            q=rt.qualify(context=context)
            if q['disposition']!='ELIGIBLE':raise AssertionError(q['reason'])
            grant=rt.grant(q['qualification_id'],agent=agent,scope_ttl_ms=scope_ttl_ms)
            command=rt.admit(agent=agent,version=rt.procedure_revision,context=context,resource='model/champion',target=context['model_version'])
            return agent,q,grant,command
        def denied(name,callback):
            count=rt.mutation_count
            try:callback()
            except Denied as e:check(name,rt.mutation_count==count,reason=e.reason)
            else:check(name,False)
        agent,q,a,cmd=ready('unknown')
        result=rt.commit(cmd,observer_available=False)
        check('missing_observation_is_unknown_and_withdraws',result['outcome']['outcome']=='UNKNOWN' and rt.qualification(q['qualification_id'])['disposition']=='HOLD' and not rt.authority(agent)['grants'])
        denied('unknown_cannot_permit_new_attempt',lambda:rt.admit(agent=agent,version=rt.procedure_revision,context=cmd['context'],resource=cmd['resource'],target=cmd['target']))
        agent,q,a,cmd=ready('expiry',scope_ttl_ms=1600)
        time.sleep(1.7)
        denied('real_scope_expiry_denies_admitted_command',lambda:rt.commit(cmd))
        # A real refused gRPC endpoint injects transport unavailability, without a fake service.
        agent,q,a,cmd=ready('ledger-outage')
        good_ledger=rt.ledger
        unavailable=dict(read_config(args.ledger_config));unavailable['LEDGER_GRPC_PORT']='1'
        rt.ledger=client_from_config(unavailable)
        before=time.monotonic()
        result=rt.commit(cmd,actual='wrong')
        elapsed=time.monotonic()-before
        check('known_failure_with_unreachable_ledger_still_withdraws',result['outcome']['outcome']=='FAIL' and result['delivery']=='PENDING' and not rt.authority(agent)['grants'],elapsed_ms=round(elapsed*1000),fault='canonical SDK endpoint set to unused loopback port')
        check('actual_cascade_demoted',rt.qualification(q['qualification_id'])['canonical_demotion']['deactivated'])
        rt.ledger.close();rt.ledger=good_ledger;rt.flush_outbox()
        check('ledger_recovery_records_without_second_mutation',rt.attempts(cmd['attempt_id'])['delivery']=='RECORDED')
        # A valid issuer signature cannot let one skill borrow another skill's qualification.
        agent,q,a,cmd=ready('crossed-binding')
        from earned_authority.connected import BINDING
        from earned_authority.runtime import encoded
        raw=rt.passport.current(agent,require_valid=False)
        scopes=rt._requests(a['grants'])
        binding=json.loads(scopes[0]['context_constraints'][BINDING]);binding['skill']='unqualified-skill'
        scopes[0]['context_constraints'][BINDING]=encoded(binding).decode()
        rt.passport.issue(agent,scopes,300,raw,'negative signed binding control')
        denied('signed_cross_skill_qualification_borrowing_denied',lambda:rt.admit(agent=agent,skill='unqualified-skill',version=rt.procedure_revision,context=cmd['context'],resource=cmd['resource'],target=cmd['target']))
        # Competing replacements read identical starting revision, so only one may win.
        agent,q,a,cmd=ready('cas');barrier=threading.Barrier(2)
        def issue(resource):
            barrier.wait(5)
            try:return rt.grant(q['qualification_id'],agent=agent,resource=resource,expected_revision=a['revision'])
            except Denied as e:return e
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(issue,['model/champion','model/alternate']))
        check('real_canonical_concurrent_cas_has_one_winner',sum(isinstance(v,dict) for v in results)==1 and sum(isinstance(v,Denied) for v in results)==1)
        # A real process exits after SQLite commit and before observer readback.
        agent,q,a,cmd=ready('crash');command_path=args.state_dir/(report['run_id']+'-command.json')
        command_path.write_text(json.dumps(cmd));before_count=rt.mutation_count
        child=[sys.executable,str(Path(__file__).resolve()),'--config',str(args.config.resolve()),'--ledger-config',str(args.ledger_config.resolve()),
               '--state-dir',str(args.state_dir.resolve()),'--crash-state',str(state.resolve()),'--crash-command',str(command_path.resolve())]
        exited=subprocess.run(child,capture_output=True,text=True,timeout=30)
        check('subprocess_crash_occurs_after_durable_commit',exited.returncode==23 and rt.mutation_count==before_count+1,exit_code=exited.returncode)
        recovered=rt.commit(cmd)
        check('post_crash_observation_reconciles_without_reexecution',recovered['outcome']['outcome']=='PASS' and rt.mutation_count==before_count+1)
        # Hold the actual mutation fence after commit, before readback; revocation must wait.
        agent,q,a,cmd=ready('fence-order');committed=threading.Event();resume=threading.Event();ack=threading.Event()
        original_read=rt.read
        def paused_read(resource):
            committed.set()
            if not resume.wait(10):raise TimeoutError('test barrier')
            return original_read(resource)
        rt.read=paused_read
        def revoke():
            result=rt.revoke(agent,'release-model');ack.set();return result
        with ThreadPoolExecutor(max_workers=2) as pool:
            future=pool.submit(rt.commit,cmd);assert committed.wait(10)
            revoke_future=pool.submit(revoke)
            time.sleep(.15)
            check('revoke_waits_for_prior_fenced_commit',not ack.is_set())
            resume.set();result=future.result(20);revoked=revoke_future.result(20)
        rt.read=original_read
        check('earlier_commit_preserved_after_revoke_ack',result['outcome']['outcome']=='PASS' and revoked['revision']>result['authority_revision'])
        denied('no_new_command_after_ack',lambda:rt.admit(agent=agent,version=rt.procedure_revision,context=cmd['context'],resource=cmd['resource'],target=cmd['target']))
        # Pause delivery alone and demonstrate it does not hold the authority fence.
        agent,q,a,cmd=ready('delivery-order');delivery=threading.Event();continue_delivery=threading.Event()
        def pause_delivery():
            delivery.set()
            if not continue_delivery.wait(10):raise TimeoutError('test barrier')
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(rt.commit,cmd,before_delivery=pause_delivery);assert delivery.wait(10)
            before=time.monotonic();revoked=rt.revoke(agent,'release-model');elapsed=time.monotonic()-before
            check('revocation_ack_does_not_wait_for_remote_delivery',not pending.done() and revoked['status']=='REVOKED',elapsed_ms=round(elapsed*1000))
            continue_delivery.set();pending.result(20)
        # A GCL capacity failure must veto eligibility but never fabricate a failed observed outcome.
        ctx={'environment':'capacity-negative','model_version':'model-capacity','desired_replicas':3,'max_replicas':2}
        for _ in range(3):rt.shadow(context=ctx)
        rejected=rt.qualify(context=ctx)
        check('real_gcl_capacity_veto_not_outcome_failure',rejected['disposition']=='INELIGIBLE' and rejected['reason']=='GCL_PROPOSAL_REJECTED' and rejected['failures']==0)
        check('gcl_deterministic_path_no_network_calls',rejected['canonical_evaluation']['gcl']['network_calls']==0)
        rt.flush_outbox()
        check('final_outbox_all_recorded',all(e['delivery']=='RECORDED' for e in rt.events()),event_count=len(rt.events()))
        report.update(execution_state='COMPLETED',acceptance_color='GREEN',state_path=str(state),mutation_count=rt.mutation_count)
    except Exception as exc:
        import traceback
        report.update(execution_state='ABORTED',acceptance_color='RED',error=type(exc).__name__+': '+str(exc),traceback=traceback.format_exc())
    finally:
        if rt:rt.passport.close();rt.ledger.close();rt.close()
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    report['source_hashes_before']=before_hashes
    report['source_hashes']={str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_sources}
    if before_hashes!=report['source_hashes']:
        report.update(execution_state='ABORTED',acceptance_color='AMBER',error='SOURCE_CHANGED_DURING_RUN')
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'report':str(args.report),'status':report['acceptance_color'],'checks':len(checks),'error':report.get('error')}))
    return 0 if report['execution_state']=='COMPLETED' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--ledger-config',type=Path,required=True)
    p.add_argument('--state-dir',type=Path,required=True);p.add_argument('--report',type=Path,default=ROOT/'reports/connected-adversarial.json')
    p.add_argument('--crash-state',type=Path);p.add_argument('--crash-command',type=Path)
    args=p.parse_args()
    if args.crash_state:
        rt=build_runtime(args,args.crash_state)
        rt.read=lambda resource:os._exit(23)
        rt.commit(json.loads(args.crash_command.read_text()))
        raise SystemExit('crash injection did not execute')
    raise SystemExit(run(args))
