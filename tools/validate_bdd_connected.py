#!/usr/bin/env python3
"""Explicit BDD bindings against the real owned local service stack.

No report is a pass before execution. Each case gets a new coordinator database,
canonical identity and qualified context. Faults are named in the case evidence.
Real Passport, Foundation/OPA, Cascade/GCL and Ledger clients are never replaced
with fabricated successful services. Local clock/observer/reconciliation faults
exercise the local enforcement boundary; they do not prove remote fault behavior.
"""
import argparse
import base64
import copy
import gc
import hashlib
import importlib
import importlib.util
import json
import re
import sqlite3
import stat
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validate_connected import build_runtime
from deploy.ledger.validate import client_from_config, read_config
from earned_authority.contracts import canonical_digest
from earned_authority.passport_client import PassportClient, PAYLOAD_HEADER
from earned_authority.runtime import ControlledClock, Denied, ident, encoded


# These cases remain unbound until the exact requirement has an observable API.
UNBOUND = {}
PARTIAL = {
    31: 'The current public aggregate has one resource grant per skill. Stale changed-resource rejection is exercised, but adding a second read-health resource while retaining the first is not represented.',
}


class MalformedPassportRelay:
    """Forward the real service, corrupt only its response, and never sign one.

    This is a transport negative-control, not a stand-in canonical issuer. The
    unmodified upstream reply and the wire mutation are recorded by digest.
    """
    def __init__(self, original, fault):
        self.original, self.fault, self.calls = original, fault, []
        grpc = original.grpc
        relay = self
        class Handler(grpc.GenericRpcHandler):
            def service(self, details):
                method = details.method
                if method not in ('/are.passport.v1.PassportIssuanceService/GetAgentPassport',
                                  '/are.passport.v1.PassportIssuanceService/VerifyPassport'):
                    return None
                def forward(raw, context):
                    try:
                        response, call = original.channel.unary_unary(method).with_call(
                            raw, metadata=list(context.invocation_metadata()), timeout=original.timeout)
                    except grpc.RpcError as exc:
                        if exc.trailing_metadata():context.set_trailing_metadata(exc.trailing_metadata())
                        context.abort(exc.code(), exc.details())
                    metadata = list(call.initial_metadata() or ())
                    upstream_digest = 'sha256:' + hashlib.sha256(response).hexdigest()
                    before_metadata = canonical_digest({str(i):[k,v.hex() if isinstance(v,bytes) else v]
                                                        for i,(k,v) in enumerate(metadata)})
                    if method.endswith('/GetAgentPassport'):
                        if fault == 'missing-expiry':
                            parsed=original.pb.GetAgentPassportResponse.FromString(response)
                            parsed.passport.ClearField('expires_ts')
                            response=parsed.SerializeToString()
                        elif fault == 'invalid-expiry':
                            altered=[]
                            for key,value in metadata:
                                if key==PAYLOAD_HEADER:
                                    body=json.loads(value);body['expires_ts']='not-an-integer-timestamp'
                                    value=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
                                altered.append((key,value))
                            metadata=altered
                        else:raise ValueError('unknown malformed response fault')
                    context.send_initial_metadata(metadata)
                    relay.calls.append({'method':method,'upstream_response_digest':upstream_digest,
                        'forwarded_response_digest':'sha256:'+hashlib.sha256(response).hexdigest(),
                        'upstream_metadata_digest':before_metadata,
                        'forwarded_metadata_digest':canonical_digest({str(i):[k,v.hex() if isinstance(v,bytes) else v]
                                                                     for i,(k,v) in enumerate(metadata)}),
                        'fault':fault,'source':'actual canonical service','resigned':False})
                    return response
                return grpc.unary_unary_rpc_method_handler(forward)
        self.server=grpc.server(ThreadPoolExecutor(max_workers=2))
        self.server.add_generic_rpc_handlers((Handler(),))
        self.port=self.server.add_insecure_port('127.0.0.1:0')
        self.server.start()

    def close(self):self.server.stop(0).wait(5)
CASES = {
    3: ['changed-skill', 'changed-environment'],
    10: ['wrong-action', 'wrong-resource', 'wrong-context', 'changed-revision'],
    14: ['missing-expiry', 'invalid-expiry'],
    17: ['wrong-version', 'unhealthy'],
    21: ['lost-response', 'observer-interruption', 'reconciliation-unavailable', 'postcommit-store-readonly'],
    25: ['missing-result', 'old-result'],
    33: ['local-store-down', 'unauthenticated'],
    34: ['before-intent-send', 'after-commit', 'audit-unavailable'],
    36: ['other-attempt', 'old-skill', 'expired-proof'],
}


def feature_requirements():
    result = {}
    for path in sorted((ROOT / 'features').glob('*.feature')):
        current = None
        background = []
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.search(r'@BDD-(\d{3})', line)
            if match:
                current = int(match.group(1))
                result[current] = {'feature': str(path.relative_to(ROOT)), 'line': line_number,
                                   'background': list(background), 'steps': []}
            elif current and re.match(r'\s*(Given|When|Then|And|But)\s', line):
                result[current]['steps'].append(line.strip())
            elif current is None and re.match(r'\s*(Given|When|Then|And|But)\s', line):
                background.append(line.strip())
    return result


def public(value):
    """Preserve evidence fields without publishing raw transferable signatures."""
    if isinstance(value,dict):
        return {key:({'redacted_digest':canonical_digest({'value':item})} if key in
                     {'signature','writer_signature','attestation_report','public_key_pem'} else public(item))
                for key,item in value.items()}
    if isinstance(value,(list,tuple)):return [public(item) for item in value]
    return value


class Case:
    def __init__(self, args, number, label, run_id):
        self.args, self.number, self.label = args, number, label
        self.path = args.state_dir / (run_id + '-' + f'{number:03}' + '-' + label + '.sqlite')
        self.rt = build_runtime(args, self.path)
        try:
            registration = self.rt.policy.request('/v1/identity/agents', {
                'agent_type': 'earned-authority.bdd', 'owner_id': 'reference-operator'})['agent']
        except Exception:
            self.rt.passport.close();self.rt.ledger.close();self.rt.close()
            raise
        self.agent = registration['agent_id']
        self.context = {'environment': run_id + '-' + f'{number:03}' + '-' + label,
                        'model_version': 'model-v2', 'desired_replicas': 1, 'max_replicas': 2}
        self.assertions, self.faults, self.receipts, self.artifacts = [], [], [], []
        self.denied_types=(Denied,)
        self.q = None
        self.eq('real canonical agent is active',registration['status'],'ACTIVE')
        self.eq('no initial canonical authority before policy-approved grant',self.authority()['grants'],{})

    def check(self, name, condition, **evidence):
        self.assertions.append({'assertion': name, 'passed': bool(condition), 'evidence': public(evidence)})
        if not condition:
            raise AssertionError(name)

    def eq(self, name, actual, expected):
        self.check(name, actual == expected, actual=actual, expected=expected)

    def shadow(self, skill='release-model', **changes):
        args = dict(skill=skill, context=self.context, attempt_id=ident('bdd-shadow'))
        args.update(changes)
        return self.rt.shadow(**args)

    def qualify(self, skill='release-model', samples=3):
        for _ in range(samples): self.shadow(skill)
        q = self.rt.qualify(skill=skill, context=self.context)
        self.eq('fresh qualification is eligible: ' + skill, q['disposition'], 'ELIGIBLE')
        if skill == 'release-model': self.q = q
        return q

    def ready(self, second=False, **grant_args):
        q = self.qualify()
        a = self.rt.grant(q['qualification_id'], agent=self.agent, **grant_args)
        if second:
            read = self.qualify('read-health')
            a = self.rt.grant(read['qualification_id'], agent=self.agent, action='read', resource='urn:dataset/health')
        return a

    def admit(self, **changes):
        args = dict(agent=self.agent, version=self.rt.procedure_revision, context=self.context,
                    resource='model/champion', target=self.context['model_version'], attempt_id=ident('bdd-attempt'))
        args.update(changes)
        return self.rt.admit(**args)

    def state(self):
        return {'registry': self.rt.read('model/champion'), 'mutations': self.rt.mutation_count}

    def independent_connection(self):
        """Keep a real reader open before a case-local filesystem access fault."""
        return sqlite3.connect(self.path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)

    def sqlite_modes(self):
        # sqlite3 connection contexts end transactions but can leave cycle-held
        # connections. Release those closed-scope handles before a real OS fault.
        gc.collect()
        return {str(path):stat.S_IMODE(path.stat().st_mode) for path in
                (self.path,Path(str(self.path)+'-wal'),Path(str(self.path)+'-shm')) if path.exists()}

    def restore_sqlite_modes(self, modes):
        # SQLite can create WAL/SHM during the fault with the main file's 0444
        # mode. Restore only this case's files, including those new sidecars.
        for path in (self.path,Path(str(self.path)+'-wal'),Path(str(self.path)+'-shm')):
            if path.exists():path.chmod(modes.get(str(path),modes[str(self.path)]))
        gc.collect()

    def connection_state(self, connection):
        row=connection.execute('SELECT version,healthy FROM registry WHERE resource=?',('model/champion',)).fetchone()
        return {'registry':{'version':row[0],'healthy':bool(row[1])} if row else {'version':'model-v1','healthy':True},
                'mutations':connection.execute("SELECT value FROM meta WHERE name='mutation_count'").fetchone()[0]}

    def assert_unknown_retry(self, result, command, committed=None, reason='RECONCILIATION_UNAVAILABLE'):
        self.eq('unavailable reconciliation returns explicit unknown state',result['state'],'UNKNOWN')
        self.eq('uncertainty has exact reason',result['reason'],reason)
        self.eq('unknown response remains bound to original attempt',result['attempt_id'],command['attempt_id'])
        self.eq('unknown response retains original request digest',result['request_digest'],command['request_digest'])
        self.eq('unknown response retains exact authenticated command digest',result['command_digest'],canonical_digest(command))
        self.eq('unknown response claims only established commitment',result['committed'],committed)
        self.eq('unknown response does not fabricate outcome, delivery or receipt',
                (result['outcome'],result['delivery'],result['receipt']),(None,'UNKNOWN',None))
        self.eq('unpersisted response explicitly requires reconciliation',(result['persisted'],result['next_action']),(False,'RECONCILE'))
        self.eq('unknown response explicitly forbids replay',result['reexecution_permitted'],False)

    def assert_sqlite_fault(self, write=False):
        """Prove the filesystem fault reaches SQLite, without faking a DB error."""
        connection=None
        try:
            connection=sqlite3.connect(self.path,timeout=2)
            if write:
                connection.execute('BEGIN IMMEDIATE')
                connection.execute("UPDATE meta SET value=value WHERE name='mutation_count'")
            else:connection.execute('SELECT id FROM attempts LIMIT 1').fetchone()
        except sqlite3.Error as exc:
            code=getattr(exc,'sqlite_errorcode',None)
            self.check('actual SQLite rejects '+('write' if write else 'read')+' during filesystem fault',
                isinstance(code,int) and (code & 255)==(sqlite3.SQLITE_READONLY if write else sqlite3.SQLITE_CANTOPEN),
                sqlite_errorcode=code,sqlite_errorname=getattr(exc,'sqlite_errorname',None),message=str(exc))
        else:self.check('filesystem fault must cause actual SQLite error',False)
        finally:
            if connection:connection.rollback();connection.close()

    def assert_final_registry(self):
        """Check actual effects, independently of returned controller outcomes."""
        committed={16,17,18,19,20,21,23,24,26,27,30,32,34}
        expected_version='model-v2' if self.number in committed else 'model-v1'
        expected_healthy=True
        if self.number in {23,24,26,27}:expected_version='wrong-model'
        if self.number==17:
            if self.label=='wrong-version':expected_version='model-v1'
            else:expected_healthy=False
        self.eq('exact actual registry postcondition from independent reader',self.rt.read('model/champion'),
                {'version':expected_version,'healthy':expected_healthy})
        self.eq('exact registry mutation count for scenario',self.rt.mutation_count,1 if self.number in committed else 0)

    def deny(self, name, action, reason=None):
        before = self.state()
        try: action()
        except self.denied_types as exc:
            self.check(name, reason is None or exc.reason == reason, reason=exc.reason, expected_reason=reason)
        else: self.check(name, False, reason='no denial')
        self.eq(name + ': independent registry unchanged', self.state(), before)

    def authority(self):
        return self.rt.authority(self.agent)

    def read_other(self):
        before = self.rt.mutation_count
        result = self.rt.commit(self.admit(skill='read-health', action='read', resource='urn:dataset/health'))
        self.eq('unaffected read remains authorized', result['outcome']['outcome'], 'PASS')
        self.eq('read does not mutate registry', self.rt.mutation_count, before)
        return result

    def events(self, kind=None, aid=None):
        return [r for r in self.rt.events() if (kind is None or r['event']['event_type'] == kind)
                and (aid is None or r['event']['attempt_id'] == aid)]

    def verify_events(self):
        self.rt.flush_outbox()
        rows = self.rt.events()
        self.check('all local events authenticated', self.rt._verify_local_events() is None)
        for row in rows:
            valid = row['delivery'] == 'RECORDED' and row['receipt'] is not None and self.rt.ledger.verify(row['receipt'], row['event'])
            self.check('canonical receipt verifies: ' + row['event_id'], valid)
            self.receipts.append({'event_id': row['event_id'], 'event_type': row['event']['event_type'],
                                  'attempt_id': row['event']['attempt_id'], 'entry_id': row['receipt']['entry_id'],
                                  'entry_hash': row['receipt']['entry_hash'], 'verified': valid})

    def observed_receipt(self, observation):
        self.rt.flush_outbox()
        rows=self.events('OUTCOME_OBSERVED',observation['attempt_id'])
        self.eq('exactly one canonical outcome event for source observation',len(rows),1)
        row=rows[0]
        self.eq('canonical event contains the exact signed observation',row['event']['outcome'],observation)
        self.check('source receipt independently verifies before reuse or corruption',
                   row['delivery']=='RECORDED' and self.rt.ledger.verify(row['receipt'],row['event']))
        return row

    def reopen(self):
        self.rt.passport.close(); self.rt.ledger.close(); self.rt.close()
        self.rt = build_runtime(self.args, self.path)

    def refuse_ledger(self):
        config = dict(read_config(self.args.ledger_config)); config['LEDGER_GRPC_PORT'] = '1'
        good = self.rt.ledger; self.rt.ledger = client_from_config(config)
        self.faults.append('Actual canonical SDK connection refused on unused loopback port 1; no fake server.')
        return good

    def restore_ledger(self, good):
        self.rt.ledger.close(); self.rt.ledger = good

    def clock_at(self, timestamp):
        previous = self.rt.clock; self.rt.clock = ControlledClock(timestamp)
        self.faults.append('Local coordinator clock fixed at ' + str(timestamp) + '; canonical services retain real wall time.')
        return previous

    def exact_revision_four(self):
        while self.authority()['revision'] < 4:
            self.rt.grant(self.q['qualification_id'], agent=self.agent)
        self.eq('starting canonical authority revision', self.authority()['revision'], 4)

    def switch_to_changed_procedure(self):
        """Run an isolated, preserved artifact with an executable validation change.

        Both copies are made only while this live run is executing. No version
        property is assigned and no source repository is edited.
        """
        original=self.rt
        report_path=self.args.report.resolve()
        artifact_root=report_path.parent/(report_path.stem+'-procedure-revisions')/(f'{self.number:03}-'+self.label)
        baseline=artifact_root/'baseline'/'earned_authority'
        revised=artifact_root/'revised'/'earned_authority'
        for directory in (baseline,revised):
            directory.mkdir(parents=True,exist_ok=False)
            for path in sorted((ROOT/'earned_authority').glob('*.py')):
                (directory/path.name).write_bytes(path.read_bytes())
        source=(revised/'connected.py').read_text()
        needle="        if claims: raise Denied('CALLER_CANNOT_ATTEST_OUTCOME')\n"
        change="        if type(healthy) is not bool: raise Denied('INVALID_HEALTH_STATE')\n"
        self.eq('exact executable revision patch location',source.count(needle),1)
        self.check('new validation is a behavior change',change not in source)
        (revised/'connected.py').write_text(source.replace(needle,needle+change,1))

        def load(directory):
            alias=ident('bdd_procedure').replace('-','_')
            spec=importlib.util.spec_from_file_location(alias,directory/'__init__.py',submodule_search_locations=[str(directory)])
            package=importlib.util.module_from_spec(spec);sys.modules[alias]=package;spec.loader.exec_module(package)
            connected=importlib.import_module(alias+'.connected')
            runtime_module=importlib.import_module(alias+'.runtime')
            instance=connected.ConnectedRuntime(self.path,passport=original.passport,policy=original.policy,ledger=original.ledger,
                qualification_client=original.qualifier,fence_path=original.fence_path)
            self.denied_types=self.denied_types+(runtime_module.Denied,)
            return instance

        baseline_rt=load(baseline)
        self.eq('copied baseline computes original procedure digest',baseline_rt.procedure_revision,original.procedure_revision)
        old_probe=baseline_rt.shadow(context=self.context,attempt_id=ident('baseline-health-type'),healthy=1)
        self.eq('original executable accepts integer health input',old_probe['outcome'],'PASS')
        baseline_rt.close()
        self.rt=load(revised)
        self.check('revised executable computes a different procedure digest',self.rt.procedure_revision!=original.procedure_revision,
                   baseline_revision=original.procedure_revision,revised_revision=self.rt.procedure_revision)
        self.deny('revised executable enforces its added validation',lambda:self.rt.shadow(
            context=self.context,attempt_id=ident('revised-health-type'),healthy=1),'INVALID_HEALTH_STATE')
        manifests=[]
        for label,directory,revision in [('baseline',baseline,original.procedure_revision),('revised',revised,self.rt.procedure_revision)]:
            manifests.append({'kind':label,'directory':str(directory.relative_to(ROOT)),
                'procedure_revision':revision,'sources':{str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
                                                       for p in sorted(directory.glob('*.py'))}})
        manifest_path=artifact_root/'manifest.json'
        manifest_path.write_text(json.dumps({'change':'Require an actual bool for shadow health input before execution.','artifacts':manifests},indent=2)+'\n')
        self.artifacts.append({'path':str(manifest_path.relative_to(ROOT)),
                               'sha256':'sha256:'+hashlib.sha256(manifest_path.read_bytes()).hexdigest(),'procedure_artifacts':manifests})
        self.faults.append('A copied controller package executes an added health-type validation; original sources and signatures are untouched, and versions are computed from file bytes.')
        return original.procedure_revision

    def run(self):
        n, rt = self.number, self.rt
        if n == 1:
            before = self.state(); observations = [self.shadow() for _ in range(3)]
            q = rt.qualify(context=self.context)
            self.eq('qualification disposition', q['disposition'], 'ELIGIBLE')
            self.eq('exact procedure digest', q['skill_digest'], canonical_digest({'skill': 'release-model', 'version': rt.procedure_revision}))
            self.eq('exact context digest', q['context_digest'], canonical_digest({'environment': self.context}))
            self.eq('distinct independent outcome references', q['outcome_refs'], [
                {k: o[k] for k in ('attempt_id', 'observation_id', 'evidence_digest')} for o in observations])
            self.check('all observations independently signed and fresh', all(rt._verified(o, {'checker'}) and o['independent'] and
                       o['outcome'] == 'PASS' and 0 <= rt.clock.now_ms-o['observed_at_ms'] < rt.evidence_window_ms for o in observations))
            self.eq('checker revision bound',q['evaluator_digest'],observations[0]['evaluator_digest'])
            self.eq('qualification policy revision bound',q['policy_digest'],canonical_digest({'required_passes':3,'window_ms':rt.evidence_window_ms,'version':1}))
            self.eq('qualification creates no authority', self.authority()['grants'], {})
            self.eq('shadow creates no live mutation', self.state(), before)
        elif n == 2:
            reports=[rt.record_procedure_report(ident('self-report'),reported_outcome='PASS',agent=self.agent,
                       skill='release-model',version=rt.procedure_revision,context=self.context) for _ in range(3)]
            self.eq('three distinct procedure reports',len({r['attempt_id'] for r in reports}),3)
            self.check('procedure reports claim PASS',all(r['reported_outcome']=='PASS' for r in reports))
            self.check('procedure claims are explicitly non-independent',all(r['independent'] is False for r in reports))
            self.reopen();rt=self.rt
            self.eq('procedure claims persist separately across restart',rt.procedure_reports(),reports)
            self.eq('self reports create no independent observations',rt.observations(),[])
            q=rt.qualify(context=self.context)
            self.eq('self reports cannot qualify',q['disposition'],'HOLD')
            self.eq('missing independent evidence remains insufficient',q['reason'],'INSUFFICIENT_EVIDENCE')
            self.eq('self reports count as neither passes nor failures',(q['passes'],q['failures']),(0,0))
            self.eq('no independent outcome reference fabricated',q['outcome_refs'],[])
            self.eq('no passport from self reports',self.authority()['grants'],{})
        elif n == 3:
            q = self.qualify(); original = copy.deepcopy(q)
            version, context = rt.procedure_revision, self.context
            if self.label == 'changed-skill': version = canonical_digest({'changed-procedure': True}); reason = 'SKILL_REVISION_MISMATCH'
            else: context = {**context, 'environment': 'different-environment'}; reason = 'QUALIFICATION_CONTEXT_MISMATCH'
            self.deny('qualification cannot transfer binding', lambda: rt.eligibility(q['qualification_id'], version, context), reason)
            self.eq('original qualification unchanged', rt.qualification(q['qualification_id']), original)
        elif n in (4, 5, 6, 7):
            old_clock = None
            if n == 4:
                self.shadow(); self.shadow(); unknown = self.shadow(observer_available=False)
                self.faults.append('Independent shadow observer availability injection; actual shadow state persisted.')
                expected, reason, passes, failures = 'HOLD', 'EVIDENCE_UNCONFIRMED', 2, 0
            elif n == 5:
                observed = [self.shadow() for _ in range(3)]
                old_clock = self.clock_at(max(o['observed_at_ms'] for o in observed) + rt.evidence_window_ms)
                expected, reason, passes, failures = 'HOLD', 'STALE_EVIDENCE', 0, 0
            elif n == 6:
                aid = ident('same-shadow'); copies = [self.shadow(attempt_id=aid) for _ in range(3)]
                self.eq('duplicate shadow deliveries return same observation', copies, [copies[0]]*3)
                expected, reason, passes, failures = 'HOLD', 'INSUFFICIENT_EVIDENCE', 1, 0
            else:
                for _ in range(3): self.shadow()
                self.shadow(actual='wrong-model')
                expected, reason, passes, failures = 'INELIGIBLE', 'KNOWN_FAILURE', 3, 1
            try:
                q = rt.qualify(context=self.context)
                for key, value in [('disposition',expected),('reason',reason),('passes',passes),('failures',failures)]: self.eq(key, q[key], value)
                self.eq('no authority from ineligible evidence', self.authority()['grants'], {})
                if n == 4: self.eq('unknown reason retained', unknown['reason'], 'OBSERVATION_UNAVAILABLE')
                if n == 5: self.check('historical observations remain PASS', all(o['outcome']=='PASS' for o in rt.observations()))
                if n == 6: self.eq('one distinct observed attempt', len(rt.observations()), 1)
                if n == 7: self.eq('all four observations retained', len(q['outcome_refs']), 4)
            finally:
                if old_clock: rt.clock = old_clock
        elif n == 8:
            self.qualify(); before = rt.clock.now_ms
            a = rt.grant(self.q['qualification_id'], agent=self.agent, ttl_ms=300000); g = a['grants']['release-model']
            cmd = self.admit()
            self.eq('grant actor bound', a['agent_id'], self.agent)
            self.eq('grant exact scope', (g['version'],g['context'],g['action'],g['resource']), (rt.procedure_revision,self.context,'release','model/champion'))
            self.eq('grant exact qualification ID',g['qualification_id'],self.q['qualification_id'])
            self.eq('qualified evidence digest bound', g['qualification_digest'], canonical_digest(self.q))
            self.eq('live policy revision bound', g['policy_digest'], rt.policy.policy_digest)
            for key in ('skill_digest','context_digest','qualification_digest','policy_digest','grant_id'):
                self.eq('command binds '+key, cmd[key], g[key])
            self.eq('command current authority revision', cmd['authority_revision'], a['revision'])
            self.check('bounded validity from signed issuance', 0 < g['expires_at_ms']-a['issued_at_ms'] <= 300000
                       and g['expires_at_ms'] <= self.q['expires_at_ms'], request_started_at_ms=before,
                       issued_at_ms=a['issued_at_ms'], grant_expires_at_ms=g['expires_at_ms'],
                       qualification_expires_at_ms=self.q['expires_at_ms'])
            self.check('independent evidence refs resolve', all(any(o['evidence_digest']==ref['evidence_digest'] and rt._verified(o,{'checker'})
                       for o in rt.observations()) for ref in self.q['outcome_refs']))
        elif n == 9:
            q=self.qualify();before_authority=self.authority();before_operations=rt.authority_operations(self.agent)
            allowed=rt.policy.check(self.agent,'release','model/champion')
            self.eq('same actor action and resource pass ordinary current policy',allowed['decision']['effect'],'ALLOW')
            window={'not_before_ms':4102444800000,'not_after_ms':4102444860000}
            request={'decision_id':ident('bdd-window-decision'),'agent_id':self.agent,
                     'action_class':'model.promote_to_production','resource':'model/champion','requested_window':window}
            before=rt.clock.now_ms
            response=rt.policy.request('/v1/policy/evaluations',request)
            after=rt.clock.now_ms;decision=response['decision']
            self.eq('actual canonical policy denies requested blackout window',(decision['effect'],decision['reason']),('DENY','POLICY_WINDOW_DENIED'))
            for field,value in request.items():self.eq('canonical temporal decision binds '+field,decision[field],value)
            self.eq('temporal decision binds loaded source policy',(decision['policy_id'],decision['policy_digest']),(rt.policy.policy_id,rt.policy.policy_digest))
            evaluated=decision['evaluated_at_ms']
            self.check('evaluation time comes from actual service near request time',type(evaluated) is int and before-5000<=evaluated<=after+5000,
                       evaluated_at_ms=evaluated,request_started_at_ms=before,response_received_at_ms=after,clock_tolerance_ms=5000)
            self.eq('policy denial is check-only and creates no execution receipt',(response['executed'],response['receipt_created']),(False,False))
            self.deny('verified temporal denial prevents otherwise eligible grant',lambda:rt.grant(q['qualification_id'],agent=self.agent,resource='model/champion',requested_window=window),'POLICY_WINDOW_DENIED')
            self.eq('no active grant', self.authority()['grants'], {})
            self.eq('temporal denial leaves canonical authority unchanged',self.authority(),before_authority)
            self.eq('temporal denial creates no authority operation',rt.authority_operations(self.agent),before_operations)
            self.eq('temporal denial creates no grant event',self.events('GRANTED'),[])
            self.eq('qualification remains eligible', rt.eligibility(q['qualification_id'],rt.procedure_revision,self.context),q)
            self.eq('subsequent ordinary policy evaluation remains allowed',rt.policy.check(self.agent,'release','model/champion')['decision']['effect'],'ALLOW')
        elif n == 10:
            self.ready()
            changes = {'wrong-action':{'action':'delete'},'wrong-resource':{'resource':'model/other'},
                       'wrong-context':{'context':{**self.context,'environment':'elsewhere'}},'changed-revision':{'version':'different-procedure'}}[self.label]
            self.deny('out-of-scope next mutation denied',lambda:rt.commit(self.admit(**changes)))
        elif n in (11,12):
            a = self.ready(scope_ttl_ms=60000 if n==12 else None); cmd = self.admit()
            t = a['expires_at_ms'] if n==11 else a['grants']['release-model']['expires_at_ms']
            if n == 12: self.check('scope expires before passport', t<a['expires_at_ms'])
            clock = self.clock_at(t)
            try: self.deny('exact local enforcement expiry equality',lambda:rt.commit(cmd),'EXPIRED_PASSPORT' if n==11 else 'EXPIRED_SCOPE')
            finally: rt.clock = clock
        elif n in (13,29):
            self.ready()
            if n == 29:self.exact_revision_four()
            command = self.admit(); old = command['authority_revision']
            acknowledged = rt.revoke(self.agent,'release-model')
            self.check('canonical revocation acknowledged', acknowledged['revision']>old and not acknowledged['grants'])
            if n == 29:self.eq('revocation advances exact current revision',acknowledged['revision'],5)
            self.deny('prior admitted command refused at actual mutation fence',lambda:rt.commit(command),'REVOKED_AUTHORITY')
        elif n == 14:
            self.ready();known=self.authority();original=rt.passport
            self.eq('malformed-response test starts without diagnostic cache',rt.cached_authority_observation(self.agent),None)
            relay=MalformedPassportRelay(original,self.label)
            config=read_config(self.args.config)
            proxy=PassportClient('127.0.0.1:'+str(relay.port),original.token,original.public_key,
                sdk_path=config['PASSPORT_SDK_DIR'],timeout_seconds=3)
            rt.passport=proxy
            self.faults.append('Loopback forwarding proxy corrupts expiry in an actual canonical reply; original signature is retained and no credential is fabricated or re-signed.')
            try:
                for _ in range(2):
                    aid=ident('malformed-authority-attempt')
                    self.deny('invalid expiry response denied at public authority boundary',
                              lambda:rt.commit(self.admit(attempt_id=aid)),'INVALID_AUTHORITY')
                    self.eq('invalid authority creates no cached executable attempt',rt.attempts(aid),None)
                self.check('fault actually forwarded real service replies',len(relay.calls)>=2,calls=relay.calls)
                self.check('expiry fault changed wire content',all(c['upstream_response_digest']!=c['forwarded_response_digest']
                           or c['upstream_metadata_digest']!=c['forwarded_metadata_digest'] for c in relay.calls))
                self.deny('invalid canonical response cannot populate diagnostic cache',lambda:rt.refresh_authority_observation(self.agent),'INVALID_AUTHORITY')
                self.eq('invalid authority leaves no cached observation',rt.cached_authority_observation(self.agent),None)
            finally:rt.passport=original;proxy.close();relay.close()
            self.eq('valid canonical authority remains unchanged after removing bad transport',self.authority(),known)
        elif n == 15:
            self.ready();known=self.authority();before_events=copy.deepcopy(rt.events())
            observed=rt.refresh_authority_observation(self.agent)
            self.eq('cached snapshot was actually fetched from current canonical authority',observed['authority'],known)
            self.eq('observed grant was marked active',observed['authority']['status'],'ACTIVE')
            self.eq('cache binds exact authority snapshot',observed['authority_digest'],canonical_digest(known))
            self.check('cached release grant is present','release-model' in observed['authority']['grants'])
            self.check('diagnostic observation is authenticated by pinned local writer',rt._verified(observed,{'writer'}))
            self.eq('diagnostic data explicitly cannot authorize execution',(observed['can_authorize_execution'],observed['requires_current_check']),(False,True))
            self.eq('diagnostic refresh does not create execution or ledger events',rt.events(),before_events)
            self.reopen();rt=self.rt
            self.eq('locally cached active observation survives restart',rt.cached_authority_observation(self.agent),observed)
            old_command=self.admit();original=rt.passport
            config = read_config(self.args.config)
            refused = PassportClient('127.0.0.1:1',original.token,original.public_key,
                sdk_path=config.get('PASSPORT_SDK_DIR',str(ROOT.parents[1]/'work/passport-python-sdk')),timeout_seconds=1)
            rt.passport = refused; self.faults.append('Actual Passport current-status SDK connection refused on unused loopback port 1. An authenticated ACTIVE observation is durably cached and survives restart for offline diagnostics; it is explicitly non-authorizing and is never an executable fallback.')
            try:
                aid=ident('cached-authority-new-attempt')
                self.eq('offline diagnostic cache remains available while service is unreachable',rt.cached_authority_observation(self.agent),observed)
                self.deny('new mutation held despite cached active grant',lambda:rt.commit(self.admit(attempt_id=aid)),'AUTHORITY_UNCONFIRMED')
                self.eq('cached status cannot create an admitted attempt',rt.attempts(aid),None)
                self.eq('cached status cannot create an intent',self.events('INTENT',aid),[])
                self.deny('prior admitted mutation also needs current authority',lambda:rt.commit(old_command),'AUTHORITY_UNCONFIRMED')
                self.deny('failed diagnostic refresh cannot fabricate current authority',lambda:rt.refresh_authority_observation(self.agent),'AUTHORITY_UNCONFIRMED')
                self.eq('unavailable refresh preserves exact historical observation and time',rt.cached_authority_observation(self.agent),observed)
            finally:refused.close();rt.passport=original
            self.eq('canonical authority was not changed by diagnostic outage',self.authority(),known)
        elif n == 16:
            self.ready()
            qualification=copy.deepcopy(self.q)
            original_records={row['event_id']:copy.deepcopy(row['event']) for row in rt.events()}
            cmd=self.admit();result=rt.commit(cmd)
            self.eq('new command requires per-attempt boundary check evidence',cmd['execution_checks_version'],1)
            self.eq('one committed mutation',rt.mutation_count,1)
            self.eq('independent actual registry postcondition',rt.read('model/champion'),{'version':'model-v2','healthy':True})
            self.eq('observed outcome PASS',result['outcome']['outcome'],'PASS')
            self.eq('outcome attempt correlation',result['outcome']['attempt_id'],cmd['attempt_id'])
            self.eq('outcome exact skill binding',result['outcome']['skill_digest'],cmd['skill_digest'])
            self.eq('execution exact authority revision',result['authority_revision'],cmd['authority_revision'])
            self.check('actual boundary policy decision is fresh',bool(result['policy_decision_id']) and result['policy_decision_id']!=cmd['policy_decision_id'])
            trace={}
            for kind in ('QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED','INTENT','COMMITTED','OUTCOME_OBSERVED'):
                rows=self.events(kind,cmd['attempt_id'])
                self.eq('one correlated '+kind+' record',len(rows),1)
                row=rows[0];event=row['event'];trace[kind]=event
                self.eq(kind+' exact attempt and correlation binding',(event['attempt_id'],event['correlation_id']),(cmd['attempt_id'],cmd['attempt_id']))
                self.check(kind+' has an authentic canonical receipt for these exact bytes',row['delivery']=='RECORDED'
                           and row['receipt'] is not None and rt.ledger.verify(row['receipt'],event))
            for kind,expected_result in (('QUALIFICATION_CHECKED','ELIGIBLE'),('AUTHORIZATION_CHECKED','ALLOW')):
                event=trace[kind]
                self.eq(kind+' is a check at the mutation boundary',(event['check_stage'],event['result'],event['authorizes_execution']),('MUTATION_BOUNDARY',expected_result,False))
                self.eq(kind+' binds exact authenticated command',event['command_digest'],canonical_digest(cmd))
                self.eq(kind+' binds immutable qualification revision',event['qualification_revision'],qualification['qualification_revision'])
                self.eq(kind+' binds actual boundary policy decision',event['policy_decision_id'],result['policy_decision_id'])
                for field in ('skill_digest','context_digest','qualification_id','qualification_digest','passport_id','grant_id','authority_revision','policy_digest','action','resource'):
                    self.eq(kind+' exact '+field,event[field],cmd[field])
            self.eq('durable intent retains exact command',trace['INTENT']['command'],cmd)
            self.eq('outcome event retains exact independent observation',trace['OUTCOME_OBSERVED']['outcome'],result['outcome'])
            current_records={row['event_id']:row['event'] for row in rt.events()}
            self.eq('prior issuance and qualification records retain original IDs, times and contents',
                    {key:current_records[key] for key in original_records},original_records)
            self.eq('original qualification remains the immutable referenced evaluation',
                    rt.qualification_at(cmd['qualification_id'],digest=cmd['qualification_digest']),qualification)
            self.check('per-attempt check records are distinct from original qualification and issuance',
                       all(trace[kind]['event_id'] not in original_records for kind in ('QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED')))
        elif n == 17:
            self.ready();cmd=self.admit()
            report=rt.record_procedure_report(cmd['attempt_id'],reported_outcome='PASS',agent=self.agent,
                      skill='release-model',version=rt.procedure_revision,context=self.context)
            self.eq('procedure explicitly reports success for this attempt',(report['attempt_id'],report['reported_outcome']),
                    (cmd['attempt_id'],'PASS'))
            result=rt.commit(cmd,actual='model-v1' if self.label=='wrong-version' else None,healthy=self.label!='unhealthy')
            self.faults.append('Actual disposable registry writer receives wrong-version or unhealthy-state fault; independent reader observes persisted result.')
            self.eq('wrong actual postcondition is FAIL',result['outcome']['outcome'],'FAIL')
            self.eq('failed postcondition reason',result['outcome']['reason'],'POSTCONDITION_NOT_MET')
            self.eq('observation equals independently read state',result['outcome']['readback'],rt.read('model/champion'))
            self.eq('procedure success report cannot override finalized independent outcome',rt.attempts(cmd['attempt_id'])['outcome']['outcome'],'FAIL')
            self.eq('original procedure success claim remains separate and auditable',rt.procedure_reports(cmd['attempt_id']),[report])
        elif n == 18:
            self.ready();before=copy.deepcopy(self.q);cmd=self.admit();result=rt.commit(cmd,observer_available=False)
            self.faults.append('Independent live observer availability injection after actual durable commit.')
            self.eq('mutation completed',result['state'],'COMMITTED');self.eq('one actual mutation',rt.mutation_count,1)
            self.eq('unavailable readback outcome',result['outcome']['outcome'],'UNKNOWN')
            self.eq('unavailable reason',result['outcome']['reason'],'OBSERVATION_UNAVAILABLE')
            q=rt.qualification(self.q['qualification_id'])
            self.eq('unknown adds no pass or failure',(q['passes'],q['failures']),(before['passes'],before['failures']))
            self.eq('unknown holds qualification',q['disposition'],'HOLD')
            self.deny('held authority denies next mutation',lambda:rt.commit(self.admit()))
        elif n in (19,20):
            self.ready();cmd=self.admit();original=rt.commit(cmd);before=self.state()
            if n == 19:
                returned=rt.commit(cmd)
                self.eq('retry returns exact durable attempt result',returned,original)
                self.eq('retry never repeats mutation',self.state(),before)
                self.eq('one intent retains logical attempt',len(self.events('INTENT',cmd['attempt_id'])),1)
            else:self.deny('changed payload cannot reuse attempt ID',lambda:self.admit(attempt_id=cmd['attempt_id'],target='changed-model'),'IDEMPOTENCY_CONFLICT')
        elif n == 21:
            self.ready();cmd=self.admit()
            durable_before_retry=None
            if self.label=='lost-response':
                try:rt.commit(cmd,lose_response=True)
                except TimeoutError:pass
                else:self.check('response loss fault occurred',False)
                self.faults.append('Transport response-loss hook throws only after actual durable commit/result.')
                durable_before_retry=copy.deepcopy(rt.attempts(cmd['attempt_id']))
            elif self.label=='observer-interruption':
                original_read=rt.read
                def interrupted(_):raise RuntimeError('injected observer interruption after durable commit')
                rt.read=interrupted
                try:
                    try:rt.commit(cmd)
                    except RuntimeError:pass
                    else:self.check('observer interruption occurred',False)
                finally:rt.read=original_read
                self.faults.append('Local observer exception after durable commit; restart uses new connections.')
                self.eq('durable incomplete result has no invented outcome',rt.attempts(cmd['attempt_id'])['outcome'],None)
            elif self.label=='reconciliation-unavailable':
                try:rt.commit(cmd,lose_response=True)
                except TimeoutError:pass
                else:self.check('response loss precedes reconciliation outage',False)
                durable_before_retry=copy.deepcopy(rt.attempts(cmd['attempt_id']))
                modes=self.sqlite_modes();reader=self.independent_connection();before=self.connection_state(reader)
                self.faults.append('After actual committed response loss, collect closed-scope SQLite connection cycles, then chmod only this case SQLite file to 000. New SQLite reads actually fail; a separate already-open read-only connection measures registry and mutation count. Restore exact case-file modes and collect afterward. No availability flag is used; garbage collection is test setup, not a production recovery guarantee.')
                try:
                    self.path.chmod(0);self.assert_sqlite_fault()
                    self.assert_unknown_retry(rt.retry(cmd),cmd)
                    self.eq('unavailable retry cannot replay through a new store',self.connection_state(reader),before)
                finally:reader.close();self.restore_sqlite_modes(modes)
                self.eq('unknown response does not replace confirmed durable result',rt.attempts(cmd['attempt_id']),durable_before_retry)
            else:
                modes=None;original_read=rt.read;calls=[]
                def read_then_disable_writes(resource):
                    nonlocal modes
                    readback=original_read(resource)
                    calls.append(readback)
                    self.eq('postcommit fault starts after independently confirmed mutation',
                            {'registry':readback,'mutations':rt.mutation_count},
                            {'registry':{'version':'model-v2','healthy':True},'mutations':1})
                    modes=self.sqlite_modes();self.path.chmod(0o444);self.assert_sqlite_fault(write=True)
                    return readback
                self.faults.append('After actual durable registry commit, the actual independent reader observes state, then collect closed-scope SQLite connection cycles and make only this case SQLite file read-only. Outcome persistence encounters a real SQLITE_READONLY. Restore original case-file modes, including newly created WAL/SHM, and collect afterward; garbage collection is test setup, not a production recovery guarantee. No invented outcome or boolean fault flag is used.')
                rt.read=read_then_disable_writes
                try:
                    result=rt.commit(cmd)
                    self.eq('observer reached exactly once before persistence failure',len(calls),1)
                    self.assert_unknown_retry(result,cmd,committed=True)
                finally:
                    rt.read=original_read
                    if modes:self.restore_sqlite_modes(modes)
                self.eq('actual durable commit survives failed outcome persistence',rt.attempts(cmd['attempt_id'])['state'],'COMMITTED')
                self.eq('persistence uncertainty cannot fabricate durable outcome',rt.attempts(cmd['attempt_id'])['outcome'],None)
                self.eq('failed persistence adds no independent observation',[o for o in rt.observations() if o['attempt_id']==cmd['attempt_id']],[])
            count=rt.mutation_count;self.reopen();rt=self.rt
            recovered=rt.retry(cmd)
            self.eq('restart recovery returns original attempt',recovered['attempt_id'],cmd['attempt_id'])
            self.eq('reconciled actual postcondition is PASS',recovered['outcome']['outcome'],'PASS')
            self.eq('recovery never repeats mutation',rt.mutation_count,count)
            if durable_before_retry is not None:self.eq('retry returns exact original durable result',recovered,durable_before_retry)
            self.eq('one logical intent after uncertainty and restart',len(self.events('INTENT',cmd['attempt_id'])),1)
            self.eq('one logical commit after uncertainty and restart',len(self.events('COMMITTED',cmd['attempt_id'])),1)
            self.eq('one independent observation for reconciled attempt',len([o for o in rt.observations() if o['attempt_id']==cmd['attempt_id']]),1)
        elif n == 22:
            self.ready();aid=ident('check-only-attempt')
            response=rt.policy.check(self.agent,'release','model/champion')
            self.eq('actual Foundation decision allows the check',response['decision']['effect'],'ALLOW')
            self.check('actual Foundation explicitly says not executed',response.get('executed') is False,response=response)
            self.check('actual Foundation explicitly says no receipt created',response.get('receipt_created') is False)
            evidence=rt.record_check_only(aid,response)
            self.eq('check-only state',evidence['state'],'AUTHORIZATION_CHECKED')
            self.eq('executor, outcome and delivery remain separate',
                (evidence['executed'],evidence['receipt_created'],evidence['outcome'],evidence['delivery']),
                (False,False,None,'NONE'))
            self.eq('no completed execution record for check',rt.attempts(aid),None)
            self.eq('no fabricated execution or observation event',self.events(aid=aid),[])
        elif n == 23:
            self.ready(second=True);cmd=self.admit();good=self.refuse_ledger()
            try:
                result=rt.commit(cmd,actual='wrong-model');current=self.authority();q=rt.qualification(self.q['qualification_id'])
                self.eq('known actual failure',result['outcome']['outcome'],'FAIL')
                self.eq('canonical Cascade deactivated',q['canonical_demotion']['deactivated'],True)
                self.eq('affected qualification ineligible',q['disposition'],'INELIGIBLE')
                self.check('affected grant revoked', 'release-model' not in current['grants'])
                self.check('revocation revision advances',current['revision']>cmd['authority_revision'])
                rows=self.events('REVOKED',cmd['attempt_id'])
                self.check('revocation is durably pending for exact failed attempt',bool(rows) and all(r['delivery']=='PENDING' and r['receipt'] is None for r in rows))
                self.check('revocation evidence names current revision',any(r['event']['authority_revision']==current['revision'] for r in rows))
                self.deny('next release denied before mutation',lambda:rt.commit(self.admit()))
            finally:self.restore_ledger(good)
        elif n == 24:
            prior=self.ready(second=True);read=prior['grants']['read-health'];old=self.admit()
            rt.commit(self.admit(),actual='wrong-model');current=self.authority()
            preserved=current['grants']['read-health']
            for key in ('grant_id','qualification_id','qualification_digest','policy_digest','skill_digest','context_digest','action','resource','expires_at_ms'):
                self.eq('unaffected grant keeps '+key,preserved[key],read[key])
            self.check('passport replaced monotonically',current['passport_id']!=prior['passport_id'] and current['revision']>prior['revision'])
            self.read_other();self.deny('old revision cannot revive failed release',lambda:rt.commit(old),'REVOKED_AUTHORITY')
        elif n == 25:
            restored_clock=None
            if self.label=='old-result':
                restored_clock=self.clock_at(rt.clock.now_ms-rt.evidence_window_ms+10000)
                self.qualify();rt.clock=restored_clock;restored_clock=None
                rt.grant(self.q['qualification_id'],agent=self.agent)
                readq=self.qualify('read-health')
                prior=rt.grant(readq['qualification_id'],agent=self.agent,action='read',resource='urn:dataset/health')
                old_command=self.admit()
                self.check('release evidence expires before unrelated evidence',self.q['expires_at_ms']<readq['expires_at_ms'])
                restored_clock=self.clock_at(self.q['expires_at_ms'])
                reason='STALE_EVIDENCE'
            else:
                prior=self.ready(second=True);reason='EVIDENCE_UNCONFIRMED'
                old_command=self.admit()
                removed=self.q['outcome_refs'][0]['attempt_id']
                with rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',(removed,))
                self.faults.append('Actual case-local SQLite observation row removed while its original signed event and canonical receipt remain.')
                self.check('required observation is actually missing',all(o['attempt_id']!=removed for o in rt.observations()))
            try:
                before=[o for o in rt.observations() if o['outcome']=='FAIL']
                audit=rt.audit_qualification_evidence(self.agent,'release-model')
                self.eq('actual required-evidence audit holds affected qualification',(audit['status'],audit['reason'],audit['requires_hold']),('HOLD',reason,True))
                q=rt.qualification(self.q['qualification_id']);self.eq('qualification held',q['disposition'],'HOLD')
                self.eq('hold reason',q['reason'],reason)
                self.eq('hold never invents failed evidence',[o for o in rt.observations() if o['outcome']=='FAIL'],before)
                current=self.authority()
                for field in ('grant_id','qualification_id','qualification_digest'):
                    self.eq('detector preserves unrelated '+field,current['grants']['read-health'][field],prior['grants']['read-health'][field])
                self.deny('new matching release reports exact evidence hold',lambda:rt.commit(self.admit()),reason)
                self.deny('already admitted command remains generically revoked',lambda:rt.commit(old_command),'REVOKED_AUTHORITY')
                self.read_other()
            finally:
                if restored_clock:rt.clock=restored_clock
        elif n == 26:
            self.ready(second=True);oldq=copy.deepcopy(self.q);old_command=self.admit()
            failed=rt.commit(self.admit(),actual='wrong-model')
            self.eq('old procedure independently failed',failed['outcome']['outcome'],'FAIL')
            withdrawn=self.authority();withdrawals=self.events('REVOKED',failed['attempt_id'])
            self.check('old release grant withdrawn before revision change','release-model' not in withdrawn['grants'] and bool(withdrawals))
            withdrawal_id=withdrawals[-1]['event_id']
            old_revision=self.switch_to_changed_procedure();rt=self.rt
            q=self.qualify();self.check('revised procedure has a new qualification',q['qualification_id']!=oldq['qualification_id'])
            self.eq('new qualification exact computed revision',q['version'],rt.procedure_revision)
            observations={o['observation_id']:o for o in rt.observations()}
            self.eq('new qualification has three fresh exact-revision outcomes',len(q['outcome_refs']),3)
            self.check('old evidence is not borrowed',all(observations[ref['observation_id']]['version']==rt.procedure_revision
                       and observations[ref['observation_id']]['outcome']=='PASS' for ref in q['outcome_refs']))
            issued=rt.grant(q['qualification_id'],agent=self.agent);grant=issued['grants']['release-model']
            self.eq('new grant binds new executable and evidence',(grant['version'],grant['qualification_id'],grant['qualification_digest']),
                    (rt.procedure_revision,q['qualification_id'],canonical_digest(q)))
            self.check('new grant is a later canonical authority revision',issued['revision']>withdrawn['revision'])
            command=self.admit();self.check('new separate policy approval is bound',bool(command['policy_decision_id']))
            self.deny('old executable revision remains unauthorized',lambda:self.admit(version=old_revision),'SKILL_REVISION_MISMATCH')
            self.deny('old admitted authority cannot return',lambda:rt.commit(old_command),'REVOKED_AUTHORITY')
            reinstatement=self.events('REQUALIFIED')
            self.check('reinstatement links new evidence and prior withdrawal',any(row['event'].get('qualification_id')==q['qualification_id']
                       and row['event'].get('prior_withdrawal_event_id')==withdrawal_id for row in reinstatement))
        elif n == 27:
            self.ready(second=True);rt.commit(self.admit(),actual='wrong-model');before=self.authority()
            self.deny('manual activation cannot bypass evidence or policy',lambda:rt.reactivate(self.agent,'release-model'),'QUALIFICATION_AND_POLICY_REQUIRED')
            self.eq('withdrawn authority remains ineffective',self.authority(),before)
        elif n == 28:
            self.ready();self.exact_revision_four();before=self.authority();barrier=threading.Barrier(2);observed=[]
            def replace(index):
                revision=self.authority()['revision'];observed.append(revision)
                barrier.wait(10)
                try:return rt.grant(self.q['qualification_id'],agent=self.agent,expected_revision=revision,
                                    scope_ttl_ms=240000+index*10000)
                except Denied as exc:return exc
            with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(replace,range(2)))
            self.eq('both independent callers observed revision four',sorted(observed),[4,4])
            winners=[r for r in results if isinstance(r,dict)];losers=[r for r in results if isinstance(r,Denied)]
            self.eq('one replacement winner',len(winners),1);self.eq('one replacement conflict',len(losers),1)
            self.eq('losing update conflicts',losers[0].reason,'REVISION_CONFLICT')
            current=self.authority();self.eq('one effective next revision',current['revision'],5)
            self.eq('acknowledged winner is current passport',current['passport_id'],winners[0]['passport_id'])
            self.eq('every acknowledged grant represented',current['grants'],winners[0]['grants'])
            self.check('predecessor not current',current['passport_id']!=before['passport_id'])
        elif n == 30:
            self.ready();self.exact_revision_four();cmd=self.admit();result=rt.commit(cmd);before=self.state()
            revoked=rt.revoke(self.agent,'release-model');self.eq('revocation follows revision four',revoked['revision'],5)
            self.eq('committed result preserved',rt.attempts(cmd['attempt_id']),result)
            self.eq('independent outcome established',result['outcome']['outcome'],'PASS')
            self.eq('revocation does not undo committed state',self.state(),before)
            self.deny('next old-revision mutation denied',lambda:rt.admit(agent=self.agent,version=rt.procedure_revision,context=self.context,
                      resource='model/champion',target='model-v2',expected_revision=4),'REVOKED_AUTHORITY')
            events=rt.events();commits=[i for i,r in enumerate(events) if r['event']['event_type']=='COMMITTED'];revokes=[i for i,r in enumerate(events) if r['event']['event_type']=='REVOKED']
            self.check('durable event order preserves prior commit',bool(commits) and bool(revokes) and max(commits)<max(revokes))
        elif n == 31:
            self.ready(second=True);self.exact_revision_four();stale=self.authority();readq=stale['grants']['read-health']['qualification_id']
            rt.revoke(self.agent,'release-model');self.eq('selective revoke revision',self.authority()['revision'],5)
            self.deny('stale changed-resource update cannot restore old aggregate',lambda:rt.grant(readq,agent=self.agent,action='read',resource='urn:dataset/health-extra',expected_revision=4),'REVISION_CONFLICT')
            current=self.authority();self.check('release remains revoked','release-model' not in current['grants']);self.read_other()
            self.eq('unaffected original read resource preserved',current['grants']['read-health']['resource'],stale['grants']['read-health']['resource'])
        elif n == 32:
            self.ready();cmd=self.admit();barrier=threading.Barrier(2)
            def execute(_):barrier.wait(10);return rt.commit(cmd)
            with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(execute,range(2)))
            self.eq('concurrent duplicate exact results',results[0],results[1]);self.eq('one registry mutation',rt.mutation_count,1)
            self.eq('one observed logical attempt',len([o for o in rt.observations() if o['attempt_id']==cmd['attempt_id']]),1)
            self.eq('one durable intent',len(self.events('INTENT',cmd['attempt_id'])),1)
            q=rt.qualify(context=self.context)
            self.eq('one attempt contributes once to qualification',len([r for r in q['outcome_refs'] if r['attempt_id']==cmd['attempt_id']]),1)
        elif n == 33:
            prior=self.ready();cmd=self.admit();aid=cmd['attempt_id'];before=self.state()
            requested=copy.deepcopy(rt.attempts(aid))
            self.eq('attempt is admitted but not committed',requested['state'],'REQUESTED')
            self.eq('no durable local intent before fault',self.events('INTENT',aid),[])
            if self.label=='local-store-down':
                modes=self.sqlite_modes()
                self.faults.append('After admission, collect closed-scope SQLite connection cycles and chmod only this case SQLite file to 0444. An actual SQL write probe must fail SQLITE_READONLY before the mutation boundary is exercised. Restore original case-file modes, including newly created WAL/SHM, and collect afterward; garbage collection is test setup, not a production recovery guarantee. No durability flag is used.')
                try:
                    self.path.chmod(0o444);self.assert_sqlite_fault(write=True)
                    self.deny('actual local intent write failure blocks registry mutation',lambda:rt.commit(cmd),'LOCAL_DURABILITY_UNAVAILABLE')
                finally:self.restore_sqlite_modes(modes)
            else:
                trusted=rt.keys['writer'];wrong=Ed25519PrivateKey.generate()
                trusted_bytes=trusted.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
                wrong_bytes=wrong.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
                self.check('replacement writer key differs from configured trust',trusted_bytes!=wrong_bytes,
                    trusted_public_key_digest=canonical_digest({'key':trusted_bytes.hex()}),
                    wrong_public_key_digest=canonical_digest({'key':wrong_bytes.hex()}))
                self.eq('runtime verification trust is pinned to original writer',
                        rt._trusted_local_signers['writer'].public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),trusted_bytes.hex())
                challenge=encoded({'attempt_id':aid,'purpose':'verify wrong writer fault'})
                signature=wrong.sign(challenge)
                self.eq('injected writer produces a valid signature under its own key',wrong.public_key().verify(signature,challenge),None)
                try:trusted.public_key().verify(signature,challenge)
                except InvalidSignature:self.check('wrong writer signature is rejected by pinned trust',True)
                else:self.check('wrong writer signature is rejected by pinned trust',False)
                self.faults.append('Active local signing private key replaced by a newly generated Ed25519 key. Pinned writer verification trust is unchanged; actual signed intent must fail authentication inside the write transaction. No writer-authenticated flag is used.')
                rt.keys['writer']=wrong
                try:self.deny('actual unauthorized intent signer blocks registry mutation',lambda:rt.commit(cmd),'LOCAL_INTENT_UNAUTHENTICATED')
                finally:rt.keys['writer']=trusted
                self.eq('fault did not replace pinned verification trust',
                        rt._trusted_local_signers['writer'].public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),trusted_bytes.hex())
            self.eq('failed intent has no durable outbox record',self.events('INTENT',aid),[])
            self.eq('failed intent has no execution record',self.events('COMMITTED',aid),[])
            self.eq('failed intent has no independent outcome', [o for o in rt.observations() if o['attempt_id']==aid],[])
            self.eq('failed intent leaves original admitted attempt unchanged',rt.attempts(aid),requested)
            self.eq('failed intent cannot change canonical permission',self.authority(),prior)
            self.eq('independent registry state and count are unchanged',self.state(),before)
        elif n == 34:
            self.ready();cmd=self.admit();good=None
            try:
                if self.label=='before-intent-send':good=self.refuse_ledger();result=rt.commit(cmd)
                elif self.label=='after-commit':
                    def before_delivery():
                        nonlocal good
                        good=self.refuse_ledger()
                    result=rt.commit(cmd,before_delivery=before_delivery)
                else:
                    result=rt.commit(cmd);good=self.refuse_ledger();current=self.authority();q=rt.qualification(self.q['qualification_id'])
                    checked=rt.audit_evidence(cmd['attempt_id'])
                    self.check('unavailable remote audit is unknown integrity',isinstance(checked,dict) and checked['integrity']=='UNKNOWN')
                    self.eq('audit outage preserves current grant',self.authority(),current)
                    self.eq('audit outage preserves known qualification',rt.qualification(self.q['qualification_id']),q)
                self.eq('completed mutation remains committed',result['state'],'COMMITTED')
                self.eq('known independent outcome remains PASS',result['outcome']['outcome'],'PASS')
                if self.label!='audit-unavailable':
                    self.eq('remote delivery pending',result['delivery'],'PENDING');self.eq('no fabricated receipt',result['receipt'],None)
                    self.check('durable exact outcome queued',any(r['event'].get('outcome')==result['outcome'] and r['delivery']=='PENDING' for r in self.events('OUTCOME_OBSERVED',cmd['attempt_id'])))
                self.eq('remote outage does not hold qualification',rt.qualification(self.q['qualification_id'])['disposition'],'ELIGIBLE')
                self.check('remote outage does not revoke grant','release-model' in self.authority()['grants'])
            finally:
                if good:self.restore_ledger(good)
            count=rt.mutation_count;observation=copy.deepcopy(result['outcome']);self.reopen();rt=self.rt
            recovered=rt.commit(cmd)
            self.eq('retry preserves exact independent outcome',recovered['outcome'],observation)
            self.eq('retry does not repeat mutation',rt.mutation_count,count)
            self.eq('recovered delivery recorded',recovered['delivery'],'RECORDED')
            rows=self.events(aid=cmd['attempt_id'])
            for row in rows:self.eq('duplicate delivery preserves canonical receipt',rt.ledger.append(row['event'],row['event_id']),row['receipt'])
            self.eq('one outcome for the logical attempt',len([o for o in rt.observations() if o['attempt_id']==cmd['attempt_id']]),1)
        elif n == 35:
            prior=self.ready(second=True)
            observation=next(o for o in rt.observations() if o['attempt_id']==self.q['outcome_refs'][0]['attempt_id'])
            row=self.observed_receipt(observation)
            altered=copy.deepcopy(observation);altered['readback']['version']='altered-without-receipt'
            self.eq('fault retains original evidence digest',altered['evidence_digest'],observation['evidence_digest'])
            with rt._tx() as db:db.execute('UPDATE observations SET body=? WHERE attempt_id=?',(json.dumps(altered),altered['attempt_id']))
            self.faults.append('Actual case-local stored signed observation payload changed without changing its signature, evidence digest, original event, or remote receipt; canonical ledger remains intact.')
            self.check('altered payload is actually stored',any(o==altered for o in rt.observations()))
            self.check('receipt still binds original recorded bytes',rt.ledger.verify(row['receipt'],row['event']))
            audit=rt.audit_qualification_evidence(self.agent,'release-model')
            self.eq('stored-payload verification reports tamper',audit['reason'],'TAMPER_DETECTED')
            self.eq('positive tamper holds affected authority',(audit['status'],audit['requires_hold']),('HOLD',True))
            self.eq('affected qualification is held',rt.qualification(self.q['qualification_id'])['disposition'],'HOLD')
            q=rt.qualify(context=self.context)
            self.eq('tampered evidence is excluded from pass count',q['passes'],2)
            self.check('tampered observation is excluded from new qualification references',all(ref['attempt_id']!=observation['attempt_id'] for ref in q['outcome_refs']))
            self.eq('remaining evidence cannot qualify a replacement',q['disposition'],'HOLD')
            self.deny('held affected grant cannot mutate without confirmed evidence',lambda:rt.commit(self.admit()),'EVIDENCE_UNCONFIRMED')
            self.eq('unrelated qualification preserved',self.authority()['grants']['read-health']['qualification_id'],prior['grants']['read-health']['qualification_id'])
            self.read_other()
        elif n == 36:
            observation=self.shadow();row=self.observed_receipt(observation)
            expected_attempt=observation['attempt_id'];restored_clock=None
            if self.label=='other-attempt':expected_attempt=ident('attempt-current');reason='ATTEMPT_MISMATCH'
            elif self.label=='old-skill':
                previous=self.switch_to_changed_procedure();rt=self.rt
                self.eq('offered receipt belongs to actually executed prior code',observation['version'],previous)
                reason='SKILL_REVISION_MISMATCH'
            else:
                restored_clock=self.clock_at(observation['observed_at_ms']+rt.evidence_window_ms)
                reason='STALE_EVIDENCE'
            try:
                before=copy.deepcopy(rt.observations())
                decision=rt.admit_evidence(observation,row['event'],row['receipt'],expected_attempt_id=expected_attempt,context=self.context)
                self.eq('receipt purpose is rejected with exact reason',decision['reason'],reason)
                self.eq('rejected receipt is not a counted outcome',(decision['admitted'],decision['counts_as_pass']),(False,False))
                self.eq('receipt rejection cannot add or modify observations',rt.observations(),before)
                records=[record for record in rt.evidence_intakes() if record['intake_id']==decision['intake_id']]
                self.eq('purpose rejection durably recorded exactly once',len(records),1)
                self.eq('durable rejection retains exact reason',records[0]['decision']['reason'],reason)
                self.eq('receipt cannot issue any authority',self.authority()['grants'],{})
                self.deny('receipt alone cannot authorize a new mutation',lambda:rt.commit(self.admit()),'REVOKED_AUTHORITY')
            finally:
                if restored_clock:rt.clock=restored_clock
        elif n == 37:
            aid=ident('untrusted-outcome');key=Ed25519PrivateKey.generate()
            observation={'observation_id':ident('observation'),'attempt_id':aid,'skill':'release-model','version':rt.procedure_revision,
                'context':self.context,'skill_digest':canonical_digest({'skill':'release-model','version':rt.procedure_revision}),
                'context_digest':canonical_digest({'environment':self.context}),'expected':'model-v2',
                'readback':{'version':'model-v2','healthy':True},'outcome':'PASS','reason':'POSTCONDITION_MET','independent':True,
                'shadow':True,'observed_at_ms':rt.clock.now_ms,'evaluator_digest':canonical_digest({'checker':'independent-registry-readback-v1'}),
                'signer':'bdd-untrusted-outcome-producer'}
            observation['signature']=base64.b64encode(key.sign(encoded(observation))).decode()
            observation['evidence_digest']=canonical_digest(observation)
            self.eq('untrusted producer signature is cryptographically valid',key.public_key().verify(
                base64.b64decode(observation['signature']),encoded({k:v for k,v in observation.items() if k not in ('signature','evidence_digest')})),None)
            self.check('valid producer key is outside configured trust',observation['signer'] not in rt._trusted_outcome_producers)
            event={'event_id':ident('untrusted-event'),'event_type':'OUTCOME_OBSERVED','agent_id':self.agent,'attempt_id':aid,
                   'correlation_id':aid,'occurred_at_ms':rt.clock.now_ms,'outcome':observation}
            receipt=rt.ledger.append(event,event['event_id'])
            self.check('actual canonical chain and writer verify for untrusted inner claim',rt.ledger.verify(receipt,event))
            self.receipts.append({'event_id':event['event_id'],'event_type':event['event_type'],'attempt_id':aid,
                'entry_id':receipt['entry_id'],'entry_hash':receipt['entry_hash'],'verified':True,'external_untrusted_outcome_negative_control':True})
            self.faults.append('An outcome signed by a newly generated untrusted Ed25519 key is actually recorded by the authorized canonical ledger writer. The ledger signature is valid; the independent attester is not trusted.')
            decision=rt.admit_evidence(observation,event,receipt,expected_attempt_id=aid,context=self.context)
            self.eq('intact chain does not establish independent attester trust',decision['reason'],'UNTRUSTED_ATTESTATION')
            self.eq('untrusted assertion cannot count as pass',(decision['admitted'],decision['counts_as_pass']),(False,False))
            self.eq('untrusted assertion is not an admitted observation',rt.observations(),[])
            records=[record for record in rt.evidence_intakes() if record['intake_id']==decision['intake_id']]
            self.eq('untrusted exclusion is durably reviewable',len(records),1)
            self.eq('stored exclusion reason',records[0]['decision']['reason'],'UNTRUSTED_ATTESTATION')
            q=rt.qualify(context=self.context)
            self.eq('qualification counts no pass from untrusted assertion',q['passes'],0)
            self.eq('qualification excludes untrusted outcome reference',q['outcome_refs'],[])
            self.eq('untrusted assertion cannot qualify',q['disposition'],'HOLD')
            self.eq('untrusted assertion creates no authority',self.authority()['grants'],{})
            self.deny('no mutation authorized by intact but untrusted evidence',lambda:rt.commit(self.admit()),'REVOKED_AUTHORITY')
        else:
            raise NotImplementedError('unbound scenario')

    def close(self):
        self.rt.passport.close();self.rt.ledger.close();self.rt.close()


def source_hashes():
    paths=[Path(__file__),ROOT/'tools/validate_connected.py',ROOT/'features/bindings.json']
    paths+=sorted((ROOT/'earned_authority').glob('*.py'))+sorted((ROOT/'features').glob('*.feature'))
    return {str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def run(args):
    run_id=ident('service-bdd');requirements=feature_requirements();before=source_hashes()
    report={'run_id':run_id,'started_at':datetime.now(timezone.utc).isoformat(),'execution_state':'PREPARED' if args.prepare_only else 'RUNNING',
            'environment':'REAL_LOCAL_SERVICES_WITH_EXPLICIT_LOCAL_FAULT_CONTROLS','acceptance_color':'AMBER','cases':[],
            'scope':'Named BDD assertions on actual local canonical services and fenced SQLite registry; no cross-host, product-value or hardware claim.',
            'source_hashes_before':before,'EDD':'evaluation-driven development; no preregistered value result','CUT':'unconfirmed',
            'fixture_parameter_mapping':{'agent-a':'fresh canonical identity per case','skill-v1':'actual controller procedure_revision content digest',
                'demo-a':'fresh isolated context per case','registry-a/model-a':'model/champion',
                'qual-policy-v1':'demo3 canonical adapter profile; three fresh independent outcomes',
                'auth-policy-v1':'actual loaded Foundation/OPA policy revision',
                'BDD-009 requested window':'Explicit source-configured demo blackout 2100-01-01T00:00:00Z through 00:01:00Z; real OPA evaluation time, no business calendar claim',
                'BDD-015 cached grant':'Durable last-verified current-authority observation for diagnostics; never an executable authorization fallback',
                'BDD-016 qualification and authorization records':'Per-attempt consumption checks at mutation boundary; prior evaluation and grant creation records retain their original IDs and timestamps'},
            'exit_codes':{'0':'prepared inventory or all selected scenarios fully green','1':'observed failed assertion or runtime operation',
                          '2':'blocked, partial, unbound, or sources changed; acceptance incomplete'}}
    path=args.report or ROOT/'reports'/(run_id+'.json')
    args.report=path
    if path.exists():raise ValueError('preserve prior evidence: choose a new report filename')
    path.parent.mkdir(parents=True,exist_ok=True);args.state_dir.mkdir(parents=True,exist_ok=True)
    def save():path.write_text(json.dumps(report,indent=2)+'\n')
    selected=set(args.scenario or range(1,38));require_ids=set(range(1,38))
    if not selected<=require_ids:raise ValueError('only BDD-001 through BDD-037 are current scope')
    for number in sorted(selected):
        for label in CASES.get(number,['default']):
            row={'scenario_id':f'BDD-{number:03}','case':label,'requirements':requirements[number],
                 'execution_state':'NOT_RUN','acceptance_color':'AMBER','complete_scenario_candidate':number not in UNBOUND and number not in PARTIAL,
                 'limitation':UNBOUND.get(number,PARTIAL.get(number)),'assertions':[],'faults':[],'receipts':[],'artifacts':[]}
            report['cases'].append(row)
    save()
    for row in report['cases']:
        number=int(row['scenario_id'][4:]);label=row['case']
        if args.prepare_only or number in UNBOUND:continue
        case=None
        try:
            case=Case(args,number,label,run_id);row['state_before']=case.state()
            row['authority_before']=public(case.authority())
            report['canonical_source_revisions']=case.rt.qualifier.source_revisions
            case.run();case.assert_final_registry();case.verify_events();row.update(execution_state='PASSED',acceptance_color='AMBER' if number in PARTIAL else 'GREEN',
                state_after=case.state(),authority_after=public(case.authority()),authority_after_digest=canonical_digest(case.authority()),
                assertions=case.assertions,faults=case.faults,receipts=case.receipts,artifacts=case.artifacts)
        except Exception as exc:
            if case is None and not isinstance(exc,AssertionError):
                row.update(execution_state='BLOCKED',acceptance_color='AMBER',error=type(exc).__name__+': '+str(exc))
                report['blocked_reason']='Real service setup unavailable; no dependent scenario assertion executed.'
                save();break
            row.update(execution_state='FAILED',acceptance_color='RED',error=type(exc).__name__+': '+str(exc),traceback=traceback.format_exc())
            if case:row.update(assertions=case.assertions,faults=case.faults,receipts=case.receipts,artifacts=case.artifacts)
        finally:
            if case:case.close()
        save();print(json.dumps({'scenario_id':row['scenario_id'],'case':label,'state':row['execution_state'],'color':row['acceptance_color']}),flush=True)
    report['source_hashes']=source_hashes();report['source_unchanged_during_run']=before==report['source_hashes']
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    statuses={row['execution_state'] for row in report['cases']}
    report['execution_state']='PREPARED' if args.prepare_only else ('FAILED' if 'FAILED' in statuses else 'BLOCKED' if 'BLOCKED' in statuses else 'COMPLETED_WITH_GAPS')
    report['acceptance_color']='RED' if 'FAILED' in statuses else 'AMBER'
    if not report['source_unchanged_during_run']:report.update(execution_state='SOURCE_CHANGED',acceptance_color='AMBER')
    by_id={sid:[r for r in report['cases'] if r['scenario_id']==sid] for sid in sorted({r['scenario_id'] for r in report['cases']})}
    report['scenario_acceptance']={sid:('GREEN' if all(r['execution_state']=='PASSED' and r['complete_scenario_candidate'] for r in rows)
                                  and report['source_unchanged_during_run'] else 'RED' if any(r['execution_state']=='FAILED' for r in rows) else 'AMBER') for sid,rows in by_id.items()}
    report['counts']={'scenario_ids':len(by_id),'cases':len(report['cases']),'passed_cases':sum(r['execution_state']=='PASSED' for r in report['cases']),
                      'failed_cases':sum(r['execution_state']=='FAILED' for r in report['cases']),
                      'blocked_cases':sum(r['execution_state']=='BLOCKED' for r in report['cases']),
                      'unrun_cases':sum(r['execution_state']=='NOT_RUN' for r in report['cases']),
                      'complete_green_scenarios':sum(s=='GREEN' for s in report['scenario_acceptance'].values())}
    save();print(json.dumps({'report':str(path),'counts':report['counts'],'acceptance_color':report['acceptance_color']}))
    if 'FAILED' in statuses:return 1
    if args.prepare_only:return 0
    return 0 if all(color=='GREEN' for color in report['scenario_acceptance'].values()) else 2


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True,type=Path);parser.add_argument('--ledger-config',required=True,type=Path)
    parser.add_argument('--state-dir',required=True,type=Path);parser.add_argument('--report',type=Path)
    parser.add_argument('--scenario',type=int,action='append',help='One integer scenario ID; repeat to select several. Default all 37.')
    parser.add_argument('--prepare-only',action='store_true',help='Inventory bindings and gaps without calling services.')
    raise SystemExit(run(parser.parse_args()))
