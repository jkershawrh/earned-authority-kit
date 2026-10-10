"""Signed local authority intents reconciled against canonical operation receipts.

The journal serializes cooperating coordinators that share one registry database.
It does not hold Passport's mutation fence during an RPC. Pending authority changes
block new registry actions; signed historical receipts establish past transitions,
never current permission. Host/database administrators remain trusted.
"""
import copy
import fcntl
import json
from contextlib import contextmanager
from .contracts import canonical_digest
from .runtime import Denied, ident

PENDING={'PREPARED','DISPATCHED'}
STATES=PENDING|{'APPLIED','CANCELLED'}


class AuthorityJournal:
    def _init_authority_journal(self):
        self.authority_checkpoint=None
        self._authority_depth=0
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS authority_operations(operation_id TEXT PRIMARY KEY,agent TEXT NOT NULL,state TEXT NOT NULL,record TEXT NOT NULL)')

    @contextmanager
    def _authority_serial(self):
        # Reentrant for grant -> drain -> revoke on this runtime; cross-process
        # writers serialize through a different lock than Passport's fence.
        with self.lock:
            if self._authority_depth:
                self._authority_depth+=1
                try:yield
                finally:self._authority_depth-=1
                return
            with open(self.path+'.authority.lock','a+b') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX)
                self._authority_depth=1
                try:yield
                finally:
                    self._authority_depth=0
                    fcntl.flock(handle,fcntl.LOCK_UN)

    def _authority_checkpoint(self,stage,operation):
        if self.authority_checkpoint:self.authority_checkpoint(stage,copy.deepcopy(operation))

    def _authority_durability(self):
        if not self.local_durability_available:raise Denied('LOCAL_DURABILITY_UNAVAILABLE')
        if not self.local_writer_authenticated:raise Denied('LOCAL_INTENT_UNAUTHENTICATED')
        if not self.authority_available:raise Denied('AUTHORITY_UNCONFIRMED')

    def _read_authority_operations(self,db,agent=None):
        rows=[]
        for oid,owner,state,raw in db.execute('SELECT operation_id,agent,state,record FROM authority_operations ORDER BY rowid'):
            try:
                body=json.loads(raw)
                if not self._verified(body,{'writer'}) or body['operation_id']!=oid or body['agent_id']!=owner or body['state']!=state or state not in STATES:
                    raise ValueError('journal authentication or index mismatch')
            except Exception as exc:raise Denied('AUTHORITY_INTENT_UNAUTHENTICATED') from exc
            if agent is None or owner==agent:rows.append(body)
        return rows

    def authority_operations(self,agent=None):
        with self._db() as db:return self._read_authority_operations(db,agent)

    def _store_authority_operation(self,db,operation):
        if not self.local_durability_available:raise Denied('LOCAL_DURABILITY_UNAVAILABLE')
        if not self.local_writer_authenticated:raise Denied('LOCAL_INTENT_UNAUTHENTICATED')
        oid=operation['operation_id']
        prior=next((o for o in self._read_authority_operations(db) if o['operation_id']==oid),None)
        mutable={'state','receipt','last_error','recorded_at_ms','signature','signer'}
        if prior:
            if {k:v for k,v in prior.items() if k not in mutable}!={k:v for k,v in operation.items() if k not in mutable}:
                raise Denied('AUTHORITY_INTENT_BINDING_MISMATCH')
            allowed={'PREPARED':{'PREPARED','DISPATCHED','CANCELLED'},'DISPATCHED':{'DISPATCHED','APPLIED','CANCELLED'},'APPLIED':{'APPLIED'},'CANCELLED':{'CANCELLED'}}
            if operation['state'] not in allowed[prior['state']]:raise Denied('AUTHORITY_INTENT_STATE_CONFLICT')
            if prior['state']=='APPLIED' and prior.get('receipt')!=operation.get('receipt'):raise Denied('AUTHORITY_INTENT_BINDING_MISMATCH')
        elif operation['state']!='PREPARED':raise Denied('AUTHORITY_INTENT_STATE_CONFLICT')
        signed=self._seal(operation,'writer')
        db.execute('INSERT OR REPLACE INTO authority_operations VALUES (?,?,?,?)',(oid,signed['agent_id'],signed['state'],json.dumps(signed)))
        return signed

    def _assert_authority_ready(self,db,agent):
        records=self.authority_operations(agent) if db is None else self._read_authority_operations(db,agent)
        if any(o['state'] in PENDING for o in records):
            raise Denied('AUTHORITY_OPERATION_PENDING')

    def _new_authority_operation(self,*,operation_id,agent,kind,request,prior_authority,invocation,skill,qualification_id=None,qualification_digest=None,policy_digest=None,grant_expires_at_ms=None,reason=None,target_grant_id=None,target_qualification_id=None):
        self._authority_durability()
        oid=operation_id or ident('authority-op')
        if not isinstance(oid,str) or not oid or len(oid)>128:raise Denied('INVALID_OPERATION_ID')
        if request['operation_id']!=oid or request['agent_id']!=agent:raise Denied('AUTHORITY_INTENT_BINDING_MISMATCH')
        operation={'journal_version':1,'operation_id':oid,'agent_id':agent,'kind':kind,'request':request,
                   'prior_authority':prior_authority,'invocation':invocation,'skill':skill,
                   'qualification_id':qualification_id,'qualification_digest':qualification_digest,
                   'policy_digest':policy_digest,'grant_expires_at_ms':grant_expires_at_ms,'reason':reason,
                   'target_grant_id':target_grant_id,'target_qualification_id':target_qualification_id,
                   'created_at_ms':self.clock.now_ms,'event_id':ident('event'),'state':'PREPARED',
                   'prior_withdrawal_event_id':None,'requalification_event_id':None}
        with self._tx() as db:
            self._assert_authority_ready(db,agent)
            if any(o['operation_id']==oid for o in self._read_authority_operations(db)):raise Denied('IDEMPOTENCY_CONFLICT')
            if kind=='GRANT':
                prior=[json.loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY rowid DESC')]
                withdrawal=next((e for e in prior if e['event_type']=='REVOKED' and e['agent_id']==agent and e.get('skill')==skill),None)
                if withdrawal:
                    operation['prior_withdrawal_event_id']=withdrawal['event_id']
                    operation['requalification_event_id']=ident('event')
            operation=self._store_authority_operation(db,operation)
        self._authority_checkpoint('intent_committed',operation)
        return operation

    def _preflight_authority_operation(self,operation):
        if operation['kind']=='GRANT':
            q=self.qualification(operation['qualification_id'])
            self.eligibility(q['qualification_id'],q['version'],q['context'])
            if canonical_digest(q)!=operation['qualification_digest']:raise Denied('QUALIFICATION_CHANGED')
            if q['version']!=self.procedure_revision:raise Denied('SKILL_REVISION_MISMATCH')
            if operation['grant_expires_at_ms']<=self.clock.now_ms:raise Denied('EXPIRED_SCOPE')
            if operation['policy_digest']!=self.policy.policy_digest:raise Denied('POLICY_REVISION_MISMATCH')
            invocation=operation['invocation']
            self._check_requested_policy_window(operation['agent_id'],invocation['action'],invocation['resource'],invocation.get('requested_window'))
            # A synchronous policy response may cross a qualification/grant bound.
            if operation['grant_expires_at_ms']<=self.clock.now_ms or q['expires_at_ms']<=self.clock.now_ms:
                raise Denied('EXPIRED_SCOPE')

    def _finish_authority_operation(self,operation,receipt):
        request=operation['request']
        # The client authenticates the canonical receipt. Bind that verified result
        # again to the exact local intent before writing any lifecycle assertion.
        if receipt['request']!=request or receipt['operation_id']!=operation['operation_id'] or receipt['agent_id']!=operation['agent_id']:
            raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        if receipt['agent_revision']!=request['expected_agent_revision']+1 or receipt['previous_active_passport_id']!=request['expected_active_passport_id']:
            raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        authority=receipt['authority']
        if authority['revision']!=receipt['agent_revision'] or receipt['result']['action']!=request['action']:
            raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        active=authority['subject']['passport_id'] if authority['subject'] else ''
        if receipt['active_passport_id']!=active:raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        with self._tx() as db:
            fresh=next(o for o in self._read_authority_operations(db) if o['operation_id']==operation['operation_id'])
            if fresh['state']=='APPLIED':return fresh
            if fresh['state'] not in PENDING:raise Denied('AUTHORITY_INTENT_STATE_CONFLICT')
            fields={'event_id':fresh['event_id'],'authority_operation_id':fresh['operation_id'],
                    'correlation_id':fresh['operation_id'],'operation_receipt':receipt,
                    'operation_request_digest':canonical_digest(request),'authority_intent':fresh,
                    'occurred_at_ms':receipt['result']['completed_ts'],'recorded_at_ms':self.clock.now_ms,
                    'skill':fresh['skill'],'authority_revision':receipt['agent_revision']}
            if fresh['kind']=='GRANT':
                if fresh['prior_withdrawal_event_id']:
                    self._event(db,'REQUALIFIED',fresh['agent_id'],fresh['operation_id'],event_id=fresh['requalification_event_id'],
                                authority_operation_id=fresh['operation_id'],qualification_id=fresh['qualification_id'],
                                prior_withdrawal_event_id=fresh['prior_withdrawal_event_id'])
                self._event(db,'GRANTED',fresh['agent_id'],fresh['operation_id'],qualification_id=fresh['qualification_id'],authority=authority,**fields)
            else:
                self._event(db,'REVOKED',fresh['agent_id'],fresh['invocation']['attempt_id'] or fresh['operation_id'],
                            reason=fresh['reason'],target_grant_id=fresh['target_grant_id'],target_qualification_id=fresh['target_qualification_id'],**fields)
            applied=self._store_authority_operation(db,{**fresh,'state':'APPLIED','receipt':receipt,'recorded_at_ms':self.clock.now_ms,'last_error':None})
        self._authority_checkpoint('event_committed',applied)
        return applied

    def _authority_operation_error(self,operation,reason,*,cancel=False):
        with self._tx() as db:
            fresh=next(o for o in self._read_authority_operations(db) if o['operation_id']==operation['operation_id'])
            return self._store_authority_operation(db,{**fresh,'state':'CANCELLED' if cancel else fresh['state'],'last_error':reason})

    def _recover_authority_operation(self,operation):
        if operation['state'] not in PENDING:return operation
        self._authority_durability()
        if not self.reconciliation_available:raise Denied('RECONCILIATION_UNAVAILABLE')
        receipt=self.passport.operation(operation['agent_id'],operation['operation_id'],expected_request=operation['request'])
        if receipt is not None:
            self._authority_checkpoint('remote_committed',operation)
            return self._finish_authority_operation(operation,receipt)
        try:self._preflight_authority_operation(operation)
        except Denied as exc:
            # PREPARED has never crossed the durable dispatch marker. DISPATCHED
            # may still have an in-flight RPC; absence cannot establish cancellation.
            cancelled=operation['state']=='PREPARED'
            result=self._authority_operation_error(operation,exc.reason,cancel=cancelled)
            if cancelled:return result
            raise Denied('AUTHORITY_OPERATION_PENDING') from exc
        with self._tx() as db:operation=self._store_authority_operation(db,{**operation,'state':'DISPATCHED'})
        self._authority_checkpoint('dispatch_committed',operation)
        request=operation['request']
        try:
            if request['action']=='ISSUE':
                args=request['issue']
                self.passport.issue(operation['agent_id'],args['requested_scopes'],args['ttl_seconds'],operation['prior_authority'],args['reason'],operation_id=operation['operation_id'])
            else:
                self.passport.revoke(operation['prior_authority'],request['revoke']['reason'],operation_id=operation['operation_id'])
        except Denied as exc:
            if exc.reason=='REVISION_CONFLICT':
                # FAILED_PRECONDITION can also mean an inactive identity. Do not
                # mistake that for a terminal CAS loss while another dispatch
                # might still be in flight. An advanced monotonic tuple makes
                # this exact expected tuple permanently unable to commit.
                receipt=self.passport.operation(operation['agent_id'],operation['operation_id'],expected_request=request)
                if receipt is not None:return self._finish_authority_operation(operation,receipt)
                current=self.passport.current(operation['agent_id'],require_valid=False)
                if current['revision']>request['expected_agent_revision']:
                    # Resolve a commit that raced the first lookup before
                    # concluding that a different operation advanced authority.
                    receipt=self.passport.operation(operation['agent_id'],operation['operation_id'],expected_request=request)
                    if receipt is not None:return self._finish_authority_operation(operation,receipt)
                    return self._authority_operation_error(operation,exc.reason,cancel=True)
                # Equal revision with another pointer is inconsistent evidence;
                # revision rollback is also outside the local trust guarantee.
                self._authority_operation_error(operation,'AUTHORITY_OPERATION_PENDING')
                raise Denied('AUTHORITY_OPERATION_PENDING') from exc
            self._authority_operation_error(operation,exc.reason)
            raise
        receipt=self.passport.operation(operation['agent_id'],operation['operation_id'],expected_request=request)
        if receipt is None:raise Denied('AUTHORITY_OPERATION_UNCONFIRMED')
        self._authority_checkpoint('remote_committed',operation)
        return self._finish_authority_operation(operation,receipt)

    def recover_authority_intents(self,agent=None):
        with self._authority_serial():
            for operation in self.authority_operations(agent):
                if operation['state'] in PENDING:self._recover_authority_operation(operation)
            return self.authority_operations(agent)

    def _resume_authority_operation(self,operation_id,invocation):
        if operation_id is None:return None
        found=next((o for o in self.authority_operations() if o['operation_id']==operation_id),None)
        if found is None:return None
        if found['invocation']!=invocation:raise Denied('IDEMPOTENCY_CONFLICT')
        result=self._recover_authority_operation(found)
        if result['state']=='CANCELLED':raise Denied(result['last_error'])
        if result['state']!='APPLIED':raise Denied('AUTHORITY_OPERATION_PENDING')
        # Never return the historical receipt as current execution permission.
        return self._normalize(self.passport.current(found['agent_id'],require_valid=False),found['agent_id'])
