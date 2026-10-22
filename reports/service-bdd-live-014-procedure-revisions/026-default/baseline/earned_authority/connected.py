"""Single-host real-service registry reference.

Canonical Passport owns authority, Foundation/OPA owns policy, Cascade owns its
qualification metrics and transitions, GCL checks the declared capacity proposal,
and canonical Ledger owns receipts. The registry and signed local outbox are
persistent SQLite. This is not a distributed transaction or a robotics controller.
"""
import copy
import fcntl
import hashlib
import json
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from .contracts import canonical_digest,load_unique_json
from .runtime import Runtime,Denied,ident,encoded
from .authority_journal import AuthorityJournal
from .authority_observations import AuthorityObservations
from .passport_client import issue_operation_request,revoke_operation_request
from .evidence_admission import EvidenceAdmission
from .grants import iter_grants, grants_for_skill, grant_by_id, select_grant, upsert_grant

ACTIONS={'release':'model.promote_to_production','read':'demo.read','read-health':'demo.read'}
BINDING='earned_authority_binding_v1'

def validate_requested_window(value):
    if (not isinstance(value,dict) or set(value)!={'not_before_ms','not_after_ms'}
        or any(type(v) is not int for v in value.values())
        or not 0<=value['not_before_ms']<value['not_after_ms']<=9007199254740991):
        raise Denied('INVALID_REQUESTED_WINDOW')
    return dict(value)

class SystemClock:
    @property
    def now_ms(self): return time.time_ns()//1000000

class FoundationPolicy:
    def __init__(self,base_url,token,opa_url,policy_digest,policy_id=None,authz_id=None,authz_digest=None):
        self.base_url=base_url.rstrip('/');self.token=token
        self.opa_url=opa_url.rstrip('/');self.policy_digest=policy_digest
        self.policy_id=policy_id
        self.expected_modules={policy_id:policy_digest} if policy_id else None
        if authz_id and self.expected_modules is not None:self.expected_modules[authz_id]=authz_digest
        for url in (base_url,opa_url):
            from urllib.parse import urlparse
            if urlparse(url).hostname not in ('localhost','127.0.0.1','::1'): raise ValueError('reference policy transport must be loopback')
    def request(self,path,body=None):
        raw=None if body is None else encoded(body)
        headers={'Authorization':'Bearer '+self.token,'X-Request-ID':ident('req'),
                 'X-ARE-Agent-ID':'earned-authority-coordinator','Content-Type':'application/json',
                 'Idempotency-Key':ident('idem')}
        req=urllib.request.Request(self.base_url+path,data=raw,headers=headers)
        with urllib.request.urlopen(req,timeout=5) as response: return json.load(response)
    def _inventory(self):
        with urllib.request.urlopen(self.opa_url+'/v1/policies',timeout=3) as response: modules=json.load(response)['result']
        hashes={p['id']:'sha256:'+hashlib.sha256(p['raw'].encode()).hexdigest() for p in modules}
        if self.expected_modules is not None:
            if hashes!=self.expected_modules: raise Denied('POLICY_REVISION_MISMATCH')
        elif len(hashes)!=1 or next(iter(hashes.values()))!=self.policy_digest:
            raise Denied('POLICY_REVISION_MISMATCH')
        return hashes

    def check(self,agent,action,resource,requested_window=None):
        window=validate_requested_window(requested_window) if requested_window is not None else None
        try:
            before=self._inventory()
            request={'decision_id':ident('decision'),'agent_id':agent,'action_class':ACTIONS[action],'resource':resource}
            if window is not None:request['requested_window']=window
            response=self.request('/v1/policy/evaluations',request)
            if self._inventory()!=before: raise Denied('POLICY_REVISION_MISMATCH')
            decision=response.get('decision',{})
            expected={**request,'policy_id':self.policy_id,'policy_digest':self.policy_digest}
            if any(decision.get(k)!=v for k,v in expected.items()): raise Denied('POLICY_DECISION_BINDING_MISMATCH')
            if window is None and 'requested_window' in decision:raise Denied('POLICY_DECISION_BINDING_MISMATCH')
            if window is not None:
                try:validate_requested_window(decision.get('requested_window'))
                except Denied as exc:raise Denied('POLICY_DECISION_BINDING_MISMATCH') from exc
            if window is not None or decision.get('reason')=='POLICY_WINDOW_DENIED':
                at=decision.get('evaluated_at_ms')
                if type(at) is not int or not 0<=at<=9007199254740991:raise Denied('POLICY_DECISION_BINDING_MISMATCH')
            if decision.get('effect')=='DENY':
                raise Denied('POLICY_WINDOW_DENIED' if decision.get('reason')=='POLICY_WINDOW_DENIED' else 'POLICY_DENIED')
            if decision.get('effect')!='ALLOW':raise Denied('POLICY_DECISION_BINDING_MISMATCH')
            return response
        except Denied: raise
        except Exception as exc: raise Denied('POLICY_UNCONFIRMED') from exc

class ConnectedRuntime(AuthorityObservations,AuthorityJournal,Runtime):
    mode='REAL_LOCAL_SERVICES'
    def __init__(self,path,*,passport,policy,ledger,qualification_client,fence_path):
        self.passport=passport;self.policy=policy;self.qualifier=qualification_client
        self.fence_path=str(fence_path)
        Path(self.fence_path).parent.mkdir(parents=True,exist_ok=True)
        super().__init__(path,clock=SystemClock(),ledger=ledger)
        self._init_authority_observations()
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS shadow_registry(attempt_id TEXT PRIMARY KEY,version TEXT NOT NULL,healthy INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS withdrawals(agent TEXT NOT NULL,skill TEXT NOT NULL,attempt_id TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(agent,skill))')
            db.execute('CREATE TABLE IF NOT EXISTS evidence_intakes(id TEXT PRIMARY KEY,body TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS evidence_quarantine(attempt_id TEXT NOT NULL,body_digest TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(attempt_id,body_digest))')
            columns={r[1] for r in db.execute('PRAGMA table_info(withdrawals)')}
            for column in ('target_grant_id','target_qualification_id'):
                if column not in columns:db.execute("ALTER TABLE withdrawals ADD COLUMN "+column+" TEXT NOT NULL DEFAULT ''")
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS withdrawal_causes(agent TEXT NOT NULL,skill TEXT NOT NULL,attempt_id TEXT NOT NULL,reason TEXT NOT NULL,target_grant_id TEXT NOT NULL,target_qualification_id TEXT NOT NULL,PRIMARY KEY(agent,skill,attempt_id,target_grant_id,target_qualification_id))')
            db.execute('INSERT OR IGNORE INTO withdrawal_causes SELECT agent,skill,attempt_id,reason,target_grant_id,target_qualification_id FROM withdrawals')
            db.execute('DELETE FROM withdrawals')
        self._init_authority_journal()
        self._trusted_outcome_producers={'checker':self.keys['checker'].public_key()}
        self.procedure_revision=canonical_digest({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__),Path(__file__).with_name('runtime.py'),Path(__file__).with_name('authority_journal.py'),Path(__file__).with_name('evidence_admission.py'),Path(__file__).with_name('grants.py'))})

    def _evidence_verifier(self):
        return EvidenceAdmission(self.ledger,trusted_producers=self._trusted_outcome_producers,
            trusted_evaluators={canonical_digest({'checker':'independent-registry-readback-v1'})},max_age_ms=self.evidence_window_ms)

    def evidence_intakes(self):
        with self._db() as db:
            records=[json.loads(row[0]) for row in db.execute('SELECT body FROM evidence_intakes ORDER BY rowid')]
        if any(not self._verified(record,{'writer'}) for record in records):raise Denied('LOCAL_INTENT_UNAUTHENTICATED')
        return records

    def _observation_admissible(self,observation):
        with self._db() as db:
            return not db.execute('SELECT 1 FROM evidence_quarantine WHERE attempt_id=? AND body_digest=?',
                (observation['attempt_id'],canonical_digest(observation))).fetchone()

    def _reference_issue(self,db,q,ref,verifier):
        row=db.execute('SELECT body FROM observations WHERE attempt_id=?',(ref['attempt_id'],)).fetchone()
        if row is None:return 'EVIDENCE_UNCONFIRMED',None
        try:
            observation=json.loads(row[0])
            quarantine=db.execute('SELECT reason FROM evidence_quarantine WHERE attempt_id=? AND body_digest=?',
                (ref['attempt_id'],canonical_digest(observation))).fetchone()
            if quarantine:return quarantine[0],observation
            checked=verifier.verify_observation(observation,expected_attempt_id=ref['attempt_id'],
                expected_skill_digest=q['skill_digest'],expected_context_digest=q['context_digest'],now_ms=self.clock.now_ms)
            if observation.get('evidence_digest')!=ref['evidence_digest'] or observation.get('observation_id')!=ref['observation_id']:
                return 'TAMPER_DETECTED',observation
            if not checked['admitted'] or checked['requires_hold']:
                return 'EVIDENCE_UNCONFIRMED' if checked['admitted'] else checked['reason'],observation
            return None,observation
        except (ValueError,TypeError,KeyError,AttributeError):return 'TAMPER_DETECTED',None

    def _qualification_evidence_issue(self,db,q):
        if not q.get('outcome_refs'):return 'EVIDENCE_UNCONFIRMED'
        verifier=self._evidence_verifier()
        return next((issue for ref in q['outcome_refs'] if (issue:=self._reference_issue(db,q,ref,verifier)[0])),None)

    def eligibility(self,qid,version,context):
        q=super().eligibility(qid,version,context)
        with self._db() as db:issue=self._qualification_evidence_issue(db,q)
        if issue:raise Denied(issue)
        return q

    def admit_evidence(self,observation,event,receipt,*,expected_attempt_id,skill='release-model',version=None,context):
        """Authenticate imported evidence; admission never grants or revokes permission."""
        version=version or self.procedure_revision
        if version!=self.procedure_revision:raise Denied('SKILL_REVISION_MISMATCH')
        expected={'expected_attempt_id':expected_attempt_id,
            'expected_skill_digest':canonical_digest({'skill':skill,'version':version}),
            'expected_context_digest':canonical_digest({'environment':context})}
        envelope=copy.deepcopy({'expected':expected,'observation':observation,'event':event,'receipt':receipt})
        iid='intake-'+canonical_digest(envelope).split(':')[1]
        decision=self._evidence_verifier().verify(envelope['observation'],envelope['event'],envelope['receipt'],**expected,now_ms=self.clock.now_ms)
        decision={**decision,'intake_id':iid}
        with self._tx() as db:
            prior_decisions=[]
            existing=db.execute('SELECT body FROM observations WHERE attempt_id=?',(expected_attempt_id,)).fetchone()
            if decision['admitted'] and existing and json.loads(existing[0])!=envelope['observation']:
                decision={**decision,'admitted':False,'counts_as_pass':False,'status':'REJECTED',
                          'reason':'IDEMPOTENCY_CONFLICT','outcome':'UNKNOWN','requires_hold':True}
            old=db.execute('SELECT body FROM evidence_intakes WHERE id=?',(iid,)).fetchone()
            if old:
                stored=json.loads(old[0])
                if not self._verified(stored,{'writer'}):raise Denied('LOCAL_INTENT_UNAUTHENTICATED')
                if stored['decision']==decision and (not decision['admitted'] or existing and json.loads(existing[0])==envelope['observation']):
                    return stored['decision']
                prior_decisions=stored.get('prior_decisions',[])+[{'decision':stored['decision'],'recorded_at_ms':stored['recorded_at_ms']}]
            if decision['admitted']:
                db.execute('INSERT OR IGNORE INTO observations VALUES (?,?)',(expected_attempt_id,json.dumps(envelope['observation'])))
            record=self._seal({**envelope,'intake_id':iid,'decision':decision,'prior_decisions':prior_decisions,'recorded_at_ms':self.clock.now_ms},'writer')
            db.execute('INSERT OR REPLACE INTO evidence_intakes VALUES (?,?)',(iid,json.dumps(record)))
            self._event(db,'EVIDENCE_ADMITTED' if decision['admitted'] else 'EVIDENCE_REJECTED',attempt_id=expected_attempt_id,
                intake_id=iid,reason=decision['reason'],subject_digest=expected['expected_skill_digest'])
        return decision

    def audit_qualification_evidence(self,agent='agent-a',skill='release-model'):
        with self._authority_serial():
            grants=grants_for_skill(self.authority(agent),skill)
            if not grants:
                return {'verified':False,'status':'NO_ACTIVE_GRANT','reason':'REVOKED_AUTHORITY','requires_hold':False}
            inspected=[];seen={};overall=None
            for grant in grants:
                key=(grant['qualification_id'],grant['qualification_digest'])
                if key not in seen:
                    seen[key]=self._audit_grant_evidence(grant,agent,skill)
                result=seen[key]
                inspected.append({'grant_id':grant['grant_id'],'qualification_id':key[0],'qualification_digest':key[1],**result})
                if overall is None or result.get('requires_hold') or (not result['verified'] and overall['verified']):
                    overall=result
            return {**overall,'inspected_grants':inspected}

    def _audit_grant_evidence(self,grant,agent='agent-a',skill='release-model'):
        """Audit this grant's bound evidence; bad unsolicited copies cannot hold it."""
        with self._authority_serial():
            authority=self.authority(agent)
            if not grant:return {'verified':False,'status':'NO_ACTIVE_GRANT','reason':'REVOKED_AUTHORITY','requires_hold':False}
            q=self.qualification(grant['qualification_id'])
            if q['disposition']!='ELIGIBLE':
                with self._tx() as db:
                    audit=self._event(db,'HELD',agent,skill=skill,reason=q['reason'],qualification_id=q['qualification_id'])
                    db.execute('INSERT OR IGNORE INTO withdrawal_causes VALUES (?,?,?,?,?,?)',
                        (agent,skill,audit['attempt_id'],q['reason'],grant['grant_id'],grant['qualification_id']))
                if not any(o['state'] in ('PREPARED','DISPATCHED') for o in self.authority_operations(agent)):
                    self.drain_withdrawals(only_agent=agent)
                return {'verified':False,'status':q['disposition'],'reason':q['reason'],'requires_hold':True,'qualification_id':q['qualification_id']}
            verifier=self._evidence_verifier()
            observations={o['attempt_id']:o for o in self.observations()}
            rows=self.events();intakes=self.evidence_intakes();deferred=None;bad=None
            refs=q.get('outcome_refs',[])
            if canonical_digest(q)!=grant['qualification_digest']:
                bad=(None,{'reason':'TAMPER_DETECTED','requires_hold':True})
            if not refs and bad is None:bad=(None,{'reason':'EVIDENCE_UNCONFIRMED','requires_hold':True})
            for ref in refs if bad is None else []:
                obs=observations.get(ref['attempt_id'])
                expected={'expected_attempt_id':ref['attempt_id'],'expected_skill_digest':q['skill_digest'],
                    'expected_context_digest':q['context_digest'],'now_ms':self.clock.now_ms}
                checked=verifier.verify_observation(obs,**expected)
                if obs is None:checked={**checked,'reason':'EVIDENCE_UNCONFIRMED'}
                elif obs.get('evidence_digest')!=ref['evidence_digest'] or obs.get('observation_id')!=ref['observation_id']:
                    checked={**checked,'admitted':False,'reason':'TAMPER_DETECTED','requires_hold':True}
                if checked['admitted'] and not checked['requires_hold']:
                    row=next((r for r in rows if r['event'].get('event_type')=='OUTCOME_OBSERVED' and r['event'].get('attempt_id')==ref['attempt_id']),None)
                    imported=next((i for i in intakes if i['decision']['admitted'] and i['observation']==obs),None)
                    if row and row['delivery']=='RECORDED':checked=verifier.verify(obs,row['event'],row['receipt'],**expected)
                    elif row and row['event'].get('outcome')!=obs:checked={**checked,'admitted':False,'reason':'TAMPER_DETECTED','requires_hold':True}
                    elif imported:checked=verifier.verify(obs,imported['event'],imported['receipt'],**expected)
                    elif not row:checked={**checked,'admitted':False,'reason':'EVIDENCE_UNCONFIRMED','requires_hold':True}
                if checked['requires_hold']:
                    bad=(obs,checked);break
                if not checked['admitted']:deferred=checked
            if bad is None:
                if deferred:
                    return {'verified':False,'status':'UNAVAILABLE','requires_hold':False,
                        'reason':(deferred.get('ledger_verification') or {}).get('reason',deferred['reason'])}
                return {'verified':True,'status':'VERIFIED','reason':'BOUND_LOCAL_EVIDENCE_VERIFIED','requires_hold':False}
            obs,checked=bad;reason=checked['reason']
            with self._tx() as db:
                if obs is not None and not checked.get('admitted',False):
                    db.execute('INSERT OR REPLACE INTO evidence_quarantine VALUES (?,?,?)',(obs['attempt_id'],canonical_digest(obs),reason))
                current=json.loads(db.execute('SELECT body FROM qualifications WHERE id=?',(q['qualification_id'],)).fetchone()[0])
                # An outcome may have arrived while receipt verification was in flight.
                # Keep its stronger decision and already queued target-bound withdrawal.
                if current['disposition']!='ELIGIBLE':
                    return {'verified':False,'status':current['disposition'],'reason':current['reason'],
                        'requires_hold':True,'qualification_id':current['qualification_id']}
                current['qualification_revision']+=1;current['disposition']='HOLD'
                current['reason']='STALE_EVIDENCE' if reason=='STALE_EVIDENCE' else 'EVIDENCE_UNCONFIRMED'
                self._save_qualification(db,current)
                audit=self._event(db,'HELD',agent,skill=skill,reason=current['reason'],evidence_reason=reason,qualification_id=q['qualification_id'])
                db.execute('INSERT OR IGNORE INTO withdrawal_causes VALUES (?,?,?,?,?,?)',(agent,skill,audit['attempt_id'],current['reason'],grant['grant_id'],grant['qualification_id']))
            self.drain_withdrawals(only_agent=agent)
            return {'verified':False,'status':'HOLD','reason':reason,'requires_hold':True,'qualification_id':q['qualification_id']}

    def _event(self,db,kind,agent='reference-qualification-checker',attempt_id='',**fields):
        return super()._event(db,kind,agent,attempt_id or ident('lifecycle'),**fields)

    def shadow(self,skill='release-model',version=None,context=None,attempt_id=None,expected=None,actual=None,
               healthy=True,observer_available=True,**claims):
        if claims: raise Denied('CALLER_CANNOT_ATTEST_OUTCOME')
        version=version or self.procedure_revision
        if version!=self.procedure_revision: raise Denied('SKILL_REVISION_MISMATCH')
        if not isinstance(context,dict) or not isinstance(context.get('model_version'),str): raise Denied('CONTEXT_INVALID')
        expected=context['model_version'] if expected is None else expected
        if expected!=context['model_version']: raise Denied('CONTEXT_TARGET_MISMATCH')
        actual=expected if actual is None else actual
        aid=attempt_id or ident('shadow')
        # Writer persists a disposable resource; the checker uses a separate reader.
        with self._tx() as db:
            existing=db.execute('SELECT version,healthy FROM shadow_registry WHERE attempt_id=?',(aid,)).fetchone()
            if existing and existing!=(actual,int(healthy)): raise Denied('IDEMPOTENCY_CONFLICT')
            db.execute('INSERT OR IGNORE INTO shadow_registry VALUES (?,?,?)',(aid,actual,int(healthy)))
        with self._db() as reader:
            observed=reader.execute('SELECT version,healthy FROM shadow_registry WHERE attempt_id=?',(aid,)).fetchone()
        return super().shadow(skill,version,context,aid,expected,observed[0],bool(observed[1]),observer_available,True,'checker')

    def qualify(self,skill='release-model',version=None,context=None):
        version=version or self.procedure_revision
        if version!=self.procedure_revision: raise Denied('SKILL_REVISION_MISMATCH')
        q=super().qualify(skill,version,context,_publish=False)
        proposal=self.qualifier.capacity_proposal(context) if hasattr(self.qualifier,'capacity_proposal') else None
        report=self.qualifier.evaluate(q,self.observations(),verify_observation=lambda o:self._verified(o,{'checker'}) and self._observation_admissible(o),now_ms=self.clock.now_ms,proposal=proposal)
        # Canonical scoring may further restrict, never relax authenticated evidence admission.
        if q['disposition']=='ELIGIBLE' and report['disposition']!='ELIGIBLE':
            q['disposition']=report['disposition'];q['reason']=report['reason']
        q['canonical_evaluation']=report
        with self._tx() as db:
            if q['disposition']=='ELIGIBLE':
                verifier=self._evidence_verifier();valid=[];issues=[];observations=[]
                for ref in q['outcome_refs']:
                    issue,observation=self._reference_issue(db,q,ref,verifier)
                    if issue:issues.append(issue)
                    else:valid.append(ref);observations.append(observation)
                if issues:
                    q['disposition']='HOLD';q['reason']=issues[0];q['outcome_refs']=valid
                    q['passes']=sum(o['outcome']=='PASS' for o in observations)
                    q['failures']=sum(o['outcome']=='FAIL' for o in observations)
                    q['canonical_evaluation']={**report,'publication_evidence_recheck':{'status':'REJECTED','reason':issues[0]}}
            self._save_qualification(db,q)
            self._event(db,'CANONICAL_QUALIFICATION_EVALUATED',qualification_id=q['qualification_id'],qualification_digest=canonical_digest(q),evaluation=report)
            self._event(db,'QUALIFIED' if q['disposition']=='ELIGIBLE' else 'HELD',qualification_id=q['qualification_id'],qualification_digest=canonical_digest(q))
        return q

    def _normalize(self,raw,agent):
        subject=raw['subject']
        if subject is None:
            return {'agent_id':agent,'revision':raw['revision'],'passport_id':None,'grants':[],'expires_at_ms':0,'status':'REVOKED','canonical':raw}
        grants=[]
        try:
            for scope in subject['scope_set']:
                if set(scope['context_constraints'])!={BINDING}: raise ValueError('unknown binding format')
                g=load_unique_json(scope['context_constraints'][BINDING])
                if ACTIONS[g['action']]!=scope['action_class'] or g['resource']!=scope['resource_pattern']: raise ValueError('scope binding mismatch')
                if type(g['expires_at_ms']) is not int:raise ValueError('invalid inner expiry')
                g['expires_at_ms']=min(g['expires_at_ms'],scope['expires_ts'],subject['expires_ts'])
                g['canonical_scope_id']=scope['scope_id'];grants.append(g)
            iter_grants({'grants':grants})
        except Exception as exc: raise Denied('BINDING_MISMATCH') from exc
        return {'agent_id':agent,'revision':raw['revision'],'passport_id':subject['passport_id'],'grants':grants,
                'expires_at_ms':subject['expires_ts'],'issued_at_ms':subject['issued_ts'],'status':raw['status'],'canonical':raw}

    def _authority(self,db,agent):
        return self.authority(agent)

    def authority(self,agent='agent-a'):
        if not self.authority_available: raise Denied('AUTHORITY_UNCONFIRMED')
        try:
            return self._normalize(self.passport.current(agent),agent)
        except Denied as exc:
            if exc.reason=='INVALID_CANONICAL_AUTHORITY':raise Denied('INVALID_AUTHORITY') from exc
            raise

    def _requests(self,grants):
        now=self.clock.now_ms;scopes=[]
        for g in iter_grants({'grants':grants}):
            # The signed inner absolute bound remains the execution deadline.
            # Rounding its containing TTL down would shorten unaffected grants
            # on every aggregate replacement. Round up, never extend the inner bound.
            remaining=(g['expires_at_ms']-now+999)//1000
            if remaining<=0: continue
            body={k:v for k,v in g.items() if k!='canonical_scope_id'}
            scopes.append({'action_class':ACTIONS[g['action']],'resource_pattern':g['resource'],
                'context_constraints':{BINDING:encoded(body).decode()},'scope_ttl_seconds':remaining})
        return scopes

    def _check_requested_policy_window(self,agent,action,resource,window=None):
        if window is None:return self.policy.check(agent,action,resource)
        window=validate_requested_window(window)
        result=self.policy.check(agent,action,resource,requested_window=window)
        # A policy interval evaluation is not a scheduling service. Only a
        # currently active interval may back immediately usable authority.
        if not window['not_before_ms']<=self.clock.now_ms<window['not_after_ms']:
            raise Denied('WINDOW_NOT_ACTIVE')
        return result

    def grant(self,qid,agent='agent-a',action='release',resource='model/champion',ttl_ms=300000,
              scope_ttl_ms=None,policy_allow=None,expected_revision=None,operation_id=None,requested_window=None):
        if policy_allow is not None: raise Denied('CALLER_CANNOT_AUTHORIZE')
        if type(ttl_ms) is not int or ttl_ms<=0 or (scope_ttl_ms is not None and (type(scope_ttl_ms) is not int or scope_ttl_ms<=0)): raise Denied('INVALID_AUTHORITY')
        invocation={'kind':'GRANT','qid':qid,'agent':agent,'action':action,'resource':resource,'ttl_ms':ttl_ms,'scope_ttl_ms':scope_ttl_ms,'expected_revision':expected_revision}
        window=validate_requested_window(requested_window) if requested_window is not None else None
        if window is not None:
            if action!='release':raise Denied('INVALID_REQUESTED_WINDOW')
            invocation['requested_window']=window
        with self._authority_serial():
            self._authority_durability()
            resumed=self._resume_authority_operation(operation_id,invocation)
            if resumed is not None:return resumed
            self.recover_authority_intents(agent)
            self.drain_withdrawals(agent)
            q=self.qualification(qid)
            self.eligibility(qid,q['version'],q['context'])
            if q['version']!=self.procedure_revision: raise Denied('SKILL_REVISION_MISMATCH')
            self._check_requested_policy_window(agent,action,resource,window)
            raw=self.passport.current(agent,require_valid=False)
            current=self._normalize(raw,agent)
            if expected_revision is not None and current['revision']!=expected_revision: raise Denied('REVISION_CONFLICT')
            expiry=min(self.clock.now_ms+ttl_ms,q['expires_at_ms'])
            g={'grant_id':ident('grant'),'skill':q['skill'],'version':q['version'],'context':q['context'],
               'skill_digest':q['skill_digest'],'context_digest':q['context_digest'],'qualification_id':qid,
               'qualification_digest':canonical_digest(q),'policy_digest':self.policy.policy_digest,
               'action':action,'resource':resource,'expires_at_ms':min(expiry,self.clock.now_ms+(scope_ttl_ms or ttl_ms))}
            if window is not None:
                g['requested_window']=window
                g['expires_at_ms']=min(g['expires_at_ms'],window['not_after_ms'])
            if g['expires_at_ms']-self.clock.now_ms<1000:raise Denied('EXPIRED_SCOPE')
            grants=upsert_grant(current,g);scopes=self._requests(grants)
            oid=operation_id or ident('authority-op')
            request=issue_operation_request(agent,scopes,max(300,max(s['scope_ttl_seconds'] for s in scopes)),raw,'qualification '+qid,oid)
            operation=self._new_authority_operation(operation_id=oid,agent=agent,kind='GRANT',request=request,prior_authority=raw,invocation=invocation,
                skill=q['skill'],qualification_id=qid,qualification_digest=canonical_digest(q),policy_digest=self.policy.policy_digest,grant_expires_at_ms=g['expires_at_ms'])
            result=self._recover_authority_operation(operation)
            if result['state']=='CANCELLED':raise Denied(result['last_error'])
            return self.authority(agent)

    def _held_reason(self,db,intent,authority):
        """Diagnose only the exact acknowledged hold at the current revision.

        The authenticated journal already contains its target and canonical
        receipt; no second hold database or inferred historical permission.
        """
        for operation in reversed(self._read_authority_operations(db,intent['agent'])):
            if operation['state']!='APPLIED' or operation['kind']!='REVOKE' or operation['skill']!=intent['skill']:
                continue
            receipt=operation['receipt']
            if receipt['agent_revision']!=authority['revision'] or (receipt['active_passport_id'] or None)!=authority['passport_id']:
                return None
            if operation['reason'] not in ('EVIDENCE_UNCONFIRMED','STALE_EVIDENCE'):return None
            prior_authority=self._normalize(operation['prior_authority'],intent['agent'])
            targets=operation.get('removed_targets')
            if targets is None:
                prior=grant_by_id(prior_authority,operation['target_grant_id'])
                targets=[prior] if prior and prior['qualification_id']==operation['target_qualification_id'] else []
            for prior in targets:
                if any(prior[k]!=intent[k] for k in ('skill','version','action','resource')):continue
                if prior['context_digest']!=canonical_digest({'environment':intent['context']}):continue
                anchor=self.qualification(operation['target_qualification_id'])
                if anchor['disposition']=='HOLD' and anchor['reason']==operation['reason']:
                    return anchor['reason']
            return None
        return None

    def _check(self,db,intent,expected_revision=None):
        self._assert_authority_ready(db,intent['agent'])
        a=self.authority(intent['agent'])
        if not grants_for_skill(a,intent['skill']) or a['status']!='ACTIVE':
            reason=self._held_reason(db,intent,a) if expected_revision is None else None
            raise Denied(reason or 'REVOKED_AUTHORITY')
        if expected_revision is not None and a['revision']!=expected_revision: raise Denied('REVOKED_AUTHORITY')
        if intent['version']!=self.procedure_revision: raise Denied('SKILL_REVISION_MISMATCH')
        g=select_grant(a,skill=intent['skill'],version=intent['version'],context=intent['context'],
                       action=intent['action'],resource=intent['resource'],grant_id=intent.get('grant_id'))
        if a['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_PASSPORT')
        if g['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_SCOPE')
        window=validate_requested_window(g['requested_window']) if 'requested_window' in g else None
        if window is not None and not window['not_before_ms']<=self.clock.now_ms<window['not_after_ms']:
            raise Denied('WINDOW_NOT_ACTIVE')
        for name in ('version','context','action','resource'):
            if g[name]!=intent[name]: raise Denied('SCOPE_MISMATCH')
        q=self.eligibility(g['qualification_id'],intent['version'],intent['context'])
        if canonical_digest(q)!=g['qualification_digest']: raise Denied('BINDING_MISMATCH')
        for field in ('skill','version','context','skill_digest','context_digest','qualification_id'):
            if g[field]!=q[field]: raise Denied('BINDING_MISMATCH')
        if self.policy.policy_digest!=g['policy_digest']: raise Denied('POLICY_REVISION_MISMATCH')
        if intent['action']=='release' and intent['target']!=intent['context'].get('model_version'): raise Denied('CONTEXT_TARGET_MISMATCH')
        decision=self._check_requested_policy_window(intent['agent'],intent['action'],intent['resource'],window)
        g['_policy_decision_id']=decision['decision']['decision_id']
        # Policy evaluation is synchronous but may have crossed an absolute deadline.
        if a['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_PASSPORT')
        if g['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_SCOPE')
        if q['expires_at_ms']<=self.clock.now_ms: raise Denied('STALE_EVIDENCE')
        return a,g

    @contextmanager
    def _commit_fence(self):
        with super()._commit_fence():
            with open(self.fence_path,'a+b') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX)
                try: yield
                finally: fcntl.flock(handle,fcntl.LOCK_UN)

    def _after_commit(self):
        self.drain_withdrawals()

    def apply_outcome(self,attempt_id):
        with self._tx() as db:
            row=db.execute('SELECT result FROM attempts WHERE id=?',(attempt_id,)).fetchone()
            if not row or not row[0]: raise Denied('OUTCOME_UNKNOWN')
            result=json.loads(row[0]);obs=result['outcome']
            if result['lifecycle_applied'] or obs is None: return result
            if not self._verified(obs,{'checker'}): raise Denied('OUTCOME_UNAUTHENTICATED')
            if obs['outcome']!='PASS':
                cmd=result['command'];q=self.qualification(cmd['qualification_id']);q['qualification_revision']+=1
                q['disposition']='INELIGIBLE' if obs['outcome']=='FAIL' else 'HOLD'
                q['reason']='KNOWN_FAILURE' if obs['outcome']=='FAIL' else 'EVIDENCE_UNCONFIRMED'
                self._include_withdrawal_observation(q,obs)
                q['canonical_evaluation']=self.qualifier.evaluate(q,self.observations(),verify_observation=lambda o:self._verified(o,{'checker'}) and self._observation_admissible(o),now_ms=self.clock.now_ms,proposal=None,require_gcl=False)
                if obs['outcome']=='FAIL':q['canonical_demotion']=q['canonical_evaluation']['cascade']
                self._save_qualification(db,q)
                db.execute('INSERT OR IGNORE INTO withdrawal_causes VALUES (?,?,?,?,?,?)',(cmd['agent'],cmd['skill'],attempt_id,q['reason'],cmd['grant_id'],cmd['qualification_id']))
                self._event(db,'DEMOTED' if obs['outcome']=='FAIL' else 'HELD',cmd['agent'],attempt_id,skill=cmd['skill'],reason=q['reason'])
            result['lifecycle_applied']=True
            db.execute('UPDATE attempts SET result=? WHERE id=?',(json.dumps(result),attempt_id))
            return result

    def drain_withdrawals(self,only_agent=None):
        with self._db() as db: pending=db.execute('SELECT agent,skill,attempt_id,reason,target_grant_id,target_qualification_id FROM withdrawal_causes').fetchall()
        for agent,skill,aid,reason,gid,qid in pending:
            if only_agent is not None and agent!=only_agent:continue
            if not gid or not qid:raise Denied('WITHDRAWAL_BINDING_MISSING')
            oid='withdrawal-'+canonical_digest({'agent':agent,'skill':skill,'attempt_id':aid,'grant_id':gid,'qualification_id':qid}).split(':')[1]
            self.revoke(agent,skill,reason,attempt_id=aid,target_grant_id=gid,target_qualification_id=qid,operation_id=oid)
            operation=next((o for o in self.authority_operations(agent) if o['operation_id']==oid),{'operation_id':oid,'agent_id':agent,'state':'NO_CHANGE'})
            self._authority_checkpoint('withdrawal_completed',operation)
            with self._tx() as db: db.execute('DELETE FROM withdrawal_causes WHERE agent=? AND skill=? AND attempt_id=? AND target_grant_id=? AND target_qualification_id=?',(agent,skill,aid,gid,qid))

    def revoke(self,agent='agent-a',skill='release-model',reason='KNOWN_FAILURE',expected_revision=None,attempt_id='',target_grant_id=None,target_qualification_id=None,operation_id=None):
        if (target_grant_id is not None or target_qualification_id is not None) and not all(
                isinstance(value,str) and value.strip() for value in (target_grant_id,target_qualification_id)):
            raise Denied('WITHDRAWAL_BINDING_MISSING')
        invocation={'kind':'REVOKE','agent':agent,'skill':skill,'reason':reason,'expected_revision':expected_revision,'attempt_id':attempt_id,'target_grant_id':target_grant_id,'target_qualification_id':target_qualification_id}
        with self._authority_serial():
            self._authority_durability()
            resumed=self._resume_authority_operation(operation_id,invocation)
            if resumed is not None:return resumed
            self.recover_authority_intents(agent)
            raw=self.passport.current(agent,require_valid=False);a=self._normalize(raw,agent)
            if expected_revision is not None and a['revision']!=expected_revision: raise Denied('REVISION_CONFLICT')
            targets=grants_for_skill(a,skill)
            grant=grant_by_id(a,target_grant_id) if target_grant_id is not None else (targets[0] if targets else None)
            if target_grant_id is not None and (not grant or grant['skill']!=skill or grant['qualification_id']!=target_qualification_id):
                event_id='reconciled-'+canonical_digest(invocation).split(':')[1]
                with self._tx() as db:
                    if not db.execute('SELECT 1 FROM events WHERE id=?',(event_id,)).fetchone():
                        self._event(db,'WITHDRAWAL_RECONCILED',agent,attempt_id,event_id=event_id,skill=skill,target_grant_id=target_grant_id,
                                    target_qualification_id=target_qualification_id,status='TARGET_NOT_CURRENT',authority_revision=a['revision'])
                return a
            if not grant:return a
            scopes=self._requests([g for g in iter_grants(a) if g['skill']!=skill]);oid=operation_id or ident('authority-op')
            if scopes:request=issue_operation_request(agent,scopes,max(300,max(s['scope_ttl_seconds'] for s in scopes)),raw,'selective withdrawal '+reason,oid)
            else:request=revoke_operation_request(raw,reason,oid)
            operation=self._new_authority_operation(operation_id=oid,agent=agent,kind='REVOKE',request=request,prior_authority=raw,invocation=invocation,
                skill=skill,reason=reason,target_grant_id=grant['grant_id'],target_qualification_id=grant['qualification_id'],removed_targets=list(targets))
            result=self._recover_authority_operation(operation)
            if result['state']=='CANCELLED':raise Denied(result['last_error'])
            return self.authority(agent)

    def reevaluate(self,agent='agent-a',skill='release-model',state='UNKNOWN'):
        if state not in ('UNKNOWN','STALE'): raise ValueError('unknown hold state')
        grants=grants_for_skill(self.authority(agent),skill)
        if not grants:return self.authority(agent)
        reason='STALE_EVIDENCE' if state=='STALE' else 'EVIDENCE_UNCONFIRMED'
        with self._tx() as db:
            seen={}
            for g in grants:
                qid=g['qualification_id']
                if qid not in seen:
                    q=self.qualification(qid)
                    if q['disposition']!='INELIGIBLE':
                        q['qualification_revision']+=1;q['disposition']='HOLD';q['reason']=reason
                        self._save_qualification(db,q)
                    seen[qid]=q
                q=seen[qid]
                event=self._event(db,'DEMOTED' if q['disposition']=='INELIGIBLE' else 'HELD',agent,skill=skill,reason=q['reason'],qualification_id=qid)
                db.execute('INSERT OR IGNORE INTO withdrawal_causes VALUES (?,?,?,?,?,?)',(agent,skill,event['attempt_id'],q['reason'],g['grant_id'],qid))
        self.drain_withdrawals()
        return self.authority(agent)
