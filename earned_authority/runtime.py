"""Durable local fixture for qualification, authority and fenced registry actions.

M1 deliberately labels its authority and ledger as fixture implementations.
The mutation, independent readback, signatures, SQLite transactions and failure
injections execute real code. M2 must replace the service adapters and rerun.
"""
import base64
import copy
import fcntl
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .contracts import canonical_digest
from .ledger_client import LedgerError


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def ident(prefix):
    return prefix + '-' + uuid.uuid4().hex


class Denied(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class ControlledClock:
    def __init__(self, now_ms=1000000):
        self.now_ms = now_ms

    def advance(self, ms):
        self.now_ms += ms


class FixtureLedger:
    """Persistent signed hash-chain fixture; not the canonical ARE Ledger."""
    mode = 'FIXTURE'

    def __init__(self, path, clock, writer_key):
        self.path, self.clock, self.writer_key = str(path), clock, writer_key
        self.available = True
        self.fail_after = None
        self.lock = threading.RLock()
        self.trusted_writers = {'local-writer': writer_key.public_key()}
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS entries (position INTEGER PRIMARY KEY, idem TEXT UNIQUE NOT NULL, body TEXT NOT NULL)')

    def _connect(self):
        return sqlite3.connect(self.path, timeout=20)

    @property
    def entries(self):
        with self._connect() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT body FROM entries ORDER BY position')]

    def append(self, event, idempotency_key):
        with self.lock, self._connect() as db:
            if not self.available:
                raise ConnectionError('fixture ledger offline')
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT body FROM entries WHERE idem=?', (idempotency_key,)).fetchone()
            if existing:
                receipt = json.loads(existing[0])
                if receipt['event'] != event:
                    raise Denied('IDEMPOTENCY_CONFLICT')
                return receipt
            count = db.execute('SELECT COUNT(*) FROM entries').fetchone()[0]
            if self.fail_after is not None and count >= self.fail_after:
                raise ConnectionError('injected ledger failure')
            last = db.execute('SELECT body FROM entries ORDER BY position DESC LIMIT 1').fetchone()
            previous = json.loads(last[0])['entry_hash'] if last else 'GENESIS'
            body = {'position':count+1, 'idempotency_key':idempotency_key, 'event':copy.deepcopy(event),
                    'previous_hash':previous, 'writer':'local-writer', 'written_at_ms':self.clock.now_ms}
            body['signature'] = base64.b64encode(self.writer_key.sign(encoded(body))).decode()
            body['entry_hash'] = canonical_digest(body)
            db.execute('INSERT INTO entries VALUES (?,?,?)', (count+1,idempotency_key,json.dumps(body)))
            return body

    def verify(self, receipt, event, max_age_ms=600000):
        try:
            if not self.available or receipt['event'] != event:
                return False
            if not 0 <= self.clock.now_ms - receipt['written_at_ms'] <= max_age_ms:
                return False
            current = self.entries
            position = receipt['position']
            if type(position) is not int or position < 1 or position > len(current):
                return False
            if current[position-1] != receipt:
                return False
            previous = 'GENESIS'
            for entry in current[:position]:
                body = dict(entry); digest = body.pop('entry_hash')
                if canonical_digest(body) != digest or body['previous_hash'] != previous:
                    return False
                signature = base64.b64decode(body.pop('signature'), validate=True)
                self.trusted_writers[body['writer']].verify(signature, encoded(body))
                previous = digest
            return True
        except Exception:
            # Cryptography's InvalidSignature is intentionally treated as denial.
            return False

    def tamper(self, index):
        with self._connect() as db:
            row = db.execute('SELECT body FROM entries WHERE position=?', (index+1,)).fetchone()
            body = json.loads(row[0]); body['event']['tampered'] = True
            db.execute('UPDATE entries SET body=? WHERE position=?', (json.dumps(body),index+1))


class Runtime:
    mode = 'LOCAL_FIXTURE'
    evidence_window_ms = 600000

    def __init__(self, path, clock=None, ledger=None):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock or ControlledClock()
        self.lock = threading.RLock()
        self.authority_available = True
        self.local_durability_available = True
        self.local_writer_authenticated = True
        self.observer_available = True
        self.reconciliation_available = True
        with self._db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS keys(name TEXT PRIMARY KEY, material BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(attempt_id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS qualifications(id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS qualification_history(id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(id,revision));
            CREATE TABLE IF NOT EXISTS authorities(agent TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS registry(resource TEXT PRIMARY KEY, version TEXT NOT NULL, healthy INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY, intent_digest TEXT NOT NULL, command TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, body TEXT NOT NULL, signature TEXT NOT NULL, delivery TEXT NOT NULL, receipt TEXT);
            CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            INSERT OR IGNORE INTO meta VALUES ('mutation_count',0);
            ''')
            if 'attempt_id' not in {r[1] for r in db.execute('PRAGMA table_info(registry)')}:
                db.execute("ALTER TABLE registry ADD COLUMN attempt_id TEXT NOT NULL DEFAULT ''")
            for name in ('authority', 'checker', 'untrusted', 'writer'):
                if not db.execute('SELECT material FROM keys WHERE name=?', (name,)).fetchone():
                    key=Ed25519PrivateKey.generate()
                    raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
                    db.execute('INSERT INTO keys VALUES (?,?)', (name,raw))
            self.keys={name:Ed25519PrivateKey.from_private_bytes(raw) for name,raw in db.execute('SELECT name,material FROM keys')}
        self.ledger = ledger or FixtureLedger(self.path+'.ledger',self.clock,self.keys['writer'])

    def _db(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.execute('PRAGMA busy_timeout=20000')
        return db

    @contextmanager
    def _tx(self):
        with self.lock, self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            yield db

    def close(self):
        pass  # Connections are operation-scoped for restart and thread tests.

    def _seal(self, value, signer):
        body=copy.deepcopy(value)
        body.pop('signature',None); body['signer']=signer
        body['signature']=base64.b64encode(self.keys[signer].sign(encoded(body))).decode()
        return body

    def _verified(self, value, trusted):
        try:
            body=dict(value)
            evidence_digest=body.pop('evidence_digest',None)
            if evidence_digest is not None and evidence_digest!=canonical_digest(body): return False
            sig=base64.b64decode(body.pop('signature'),validate=True)
            signer=body['signer']
            if signer not in trusted: return False
            self.keys[signer].public_key().verify(sig,encoded(body))
            return True
        except Exception:
            return False

    def _event(self, db, kind, agent='agent-a', attempt_id='', **fields):
        event={'event_id':ident('event'),'event_type':kind,'agent_id':agent,
               'attempt_id':attempt_id,'correlation_id':fields.pop('correlation_id',attempt_id or ident('flow')),
               'occurred_at_ms':self.clock.now_ms,**fields}
        signature=base64.b64encode(self.keys['writer'].sign(encoded(event))).decode()
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,NULL)',(event['event_id'],attempt_id,json.dumps(event),signature,'PENDING'))
        return event

    def shadow(self, skill='release-model', version='skill-v1', context='demo-a', attempt_id=None,
               expected='model-v2', actual='model-v2', healthy=True, observer_available=True,
               independent=True, signer='checker', observed_at_ms=None):
        # Shadow execution uses a separate disposable state, never the live registry.
        shadow_state={'version':actual,'healthy':healthy}
        readback=dict(shadow_state) if observer_available else None
        outcome='UNKNOWN' if readback is None else ('PASS' if readback['version']==expected and readback['healthy'] else 'FAIL')
        reason='OBSERVATION_UNAVAILABLE' if outcome=='UNKNOWN' else ('POSTCONDITION_MET' if outcome=='PASS' else 'POSTCONDITION_NOT_MET')
        body={'observation_id':ident('observation'),'attempt_id':attempt_id or ident('shadow'),
              'skill':skill,'version':version,'context':context,'skill_digest':canonical_digest({'skill':skill,'version':version}),
              'context_digest':canonical_digest({'environment':context}), 'expected':expected,'readback':readback,
              'outcome':outcome,'reason':reason,'independent':independent,'shadow':True,
              'observed_at_ms':self.clock.now_ms if observed_at_ms is None else observed_at_ms,
              'evaluator_digest':canonical_digest({'checker':'independent-registry-readback-v1'})}
        if signer not in self.keys: signer='untrusted'
        body=self._seal(body,signer)
        body['evidence_digest']=canonical_digest(body)
        with self._tx() as db:
            prev=db.execute('SELECT body FROM observations WHERE attempt_id=?',(body['attempt_id'],)).fetchone()
            if prev:
                old=json.loads(prev[0])
                compare=('skill','version','context','expected','readback','outcome','independent','signer')
                if observed_at_ms is not None and old['observed_at_ms']!=observed_at_ms: raise Denied('IDEMPOTENCY_CONFLICT')
                if any(old[k]!=body[k] for k in compare): raise Denied('IDEMPOTENCY_CONFLICT')
                return old
            db.execute('INSERT INTO observations VALUES (?,?)',(body['attempt_id'],json.dumps(body)))
            self._event(db,'OUTCOME_OBSERVED',attempt_id=body['attempt_id'],outcome=body)
        return body

    def observations(self):
        with self._db() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT body FROM observations ORDER BY rowid')]

    def qualify(self, skill='release-model',version='skill-v1',context='demo-a',_publish=True):
        with self._tx() as db:
            all_obs=[json.loads(r[0]) for r in db.execute('SELECT body FROM observations')]
            selected=[o for o in all_obs if o['skill']==skill and o['version']==version and o['context']==context]
            trusted=[o for o in selected if o['independent'] and self._verified(o,{'checker'})]
            fresh=[o for o in trusted if 0 <= self.clock.now_ms-o['observed_at_ms'] < self.evidence_window_ms]
            passes=sum(o['outcome']=='PASS' for o in fresh); failures=sum(o['outcome']=='FAIL' for o in fresh)
            if failures: disposition,reason='INELIGIBLE','KNOWN_FAILURE'
            elif any(o['outcome']=='UNKNOWN' for o in fresh): disposition,reason='HOLD','EVIDENCE_UNCONFIRMED'
            elif trusted and not fresh: disposition,reason='HOLD','STALE_EVIDENCE'
            elif passes>=3: disposition,reason='ELIGIBLE','SUFFICIENT_INDEPENDENT_EVIDENCE'
            elif selected and any(o['independent'] and not self._verified(o,{'checker'}) for o in selected): disposition,reason='HOLD','UNTRUSTED_ATTESTATION'
            else: disposition,reason='HOLD','INSUFFICIENT_EVIDENCE'
            q={'qualification_id':ident('qualification'),'qualification_revision':1,'skill':skill,'version':version,'context':context,
               'skill_digest':canonical_digest({'skill':skill,'version':version}),
               'context_digest':canonical_digest({'environment':context}),
               'evaluator_digest':canonical_digest({'checker':'independent-registry-readback-v1'}),
               'policy_digest':canonical_digest({'required_passes':3,'window_ms':self.evidence_window_ms,'version':1}),
               'disposition':disposition,'reason':reason,'passes':passes,'failures':failures,
               'outcome_refs':[{'attempt_id':o['attempt_id'],'observation_id':o['observation_id'],
                                'evidence_digest':o['evidence_digest']} for o in fresh],
               'expires_at_ms':min((o['observed_at_ms']+self.evidence_window_ms for o in fresh),default=self.clock.now_ms),
               'evaluated_at_ms':self.clock.now_ms}
            stored=q if _publish else {**q,'disposition':'HOLD','reason':'CANONICAL_CHECK_PENDING'}
            db.execute('INSERT INTO qualifications VALUES (?,?)',(q['qualification_id'],json.dumps(stored)))
            if _publish:
                self._save_qualification(db,q)
                self._event(db,'QUALIFIED' if disposition=='ELIGIBLE' else 'HELD',subject=q['qualification_id'],qualification=canonical_digest(q))
            return q

    def _save_qualification(self,db,q):
        prior=db.execute('SELECT body FROM qualification_history WHERE id=? AND revision=?',
                         (q['qualification_id'],q['qualification_revision'])).fetchone()
        if prior and json.loads(prior[0])!=q: raise Denied('QUALIFICATION_REVISION_CONFLICT')
        db.execute('INSERT OR IGNORE INTO qualification_history VALUES (?,?,?)',
                   (q['qualification_id'],q['qualification_revision'],json.dumps(q)))
        db.execute('INSERT OR REPLACE INTO qualifications VALUES (?,?)',(q['qualification_id'],json.dumps(q)))

    def qualification_history(self):
        with self._db() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT body FROM qualification_history ORDER BY rowid')]

    def qualification_at(self,qid,revision=None,digest=None):
        for q in self.qualification_history():
            if q['qualification_id']==qid and (revision is None or q['qualification_revision']==revision) and (digest is None or canonical_digest(q)==digest):
                return q
        raise Denied('QUALIFICATION_REVISION_MISSING')

    def _include_withdrawal_observation(self,q,observation):
        if not self._verified(observation,{'checker'}): raise Denied('OUTCOME_UNAUTHENTICATED')
        ref={k:observation[k] for k in ('attempt_id','observation_id','evidence_digest')}
        if not any(r['attempt_id']==ref['attempt_id'] for r in q['outcome_refs']):
            q['outcome_refs'].append(ref)
            q['passes']+=int(observation['outcome']=='PASS')
            q['failures']+=int(observation['outcome']=='FAIL')
        q['evaluated_at_ms']=self.clock.now_ms

    def qualification(self,qid):
        with self._db() as db:
            row=db.execute('SELECT body FROM qualifications WHERE id=?',(qid,)).fetchone()
            if not row: raise Denied('QUALIFICATION_MISSING')
            return json.loads(row[0])

    def eligibility(self,qid,version,context):
        q=self.qualification(qid)
        if q['version']!=version: raise Denied('SKILL_REVISION_MISMATCH')
        if q['context']!=context: raise Denied('QUALIFICATION_CONTEXT_MISMATCH')
        if q['disposition']!='ELIGIBLE': raise Denied(q['reason'])
        if q['expires_at_ms']<=self.clock.now_ms: raise Denied('STALE_EVIDENCE')
        return q

    def _authority(self,db,agent):
        row=db.execute('SELECT body FROM authorities WHERE agent=?',(agent,)).fetchone()
        return json.loads(row[0]) if row else {'agent_id':agent,'revision':0,'passport_id':None,'grants':{},'expires_at_ms':0,'status':'REVOKED'}

    def authority(self,agent='agent-a'):
        if not self.authority_available: raise Denied('AUTHORITY_UNCONFIRMED')
        with self._db() as db: return self._authority(db,agent)

    def validate_authority(self,snapshot):
        try:
            if type(snapshot['expires_at_ms']) is not int or snapshot['expires_at_ms']<=self.clock.now_ms:
                raise Denied('INVALID_AUTHORITY')
            if not self._verified(snapshot,{'authority'}): raise Denied('INVALID_AUTHORITY')
            return snapshot
        except (KeyError,TypeError,ValueError):
            raise Denied('INVALID_AUTHORITY')

    def grant(self,qid,agent='agent-a',action='release',resource='registry-a/model-a',ttl_ms=300000,
              scope_ttl_ms=None,policy_allow=True,expected_revision=None):
        if not self.authority_available: raise Denied('AUTHORITY_UNCONFIRMED')
        if not policy_allow: raise Denied('POLICY_DENIED')
        if type(ttl_ms) is not int or ttl_ms<=0: raise Denied('INVALID_AUTHORITY')
        if scope_ttl_ms is not None and (type(scope_ttl_ms) is not int or scope_ttl_ms<=0): raise Denied('INVALID_AUTHORITY')
        with self._tx() as db:
            row=db.execute('SELECT body FROM qualifications WHERE id=?',(qid,)).fetchone()
            if not row: raise Denied('QUALIFICATION_MISSING')
            q=json.loads(row[0]); current=self._authority(db,agent)
            if expected_revision is not None and expected_revision!=current['revision']: raise Denied('REVISION_CONFLICT')
            if q['disposition']!='ELIGIBLE' or q['expires_at_ms']<=self.clock.now_ms: raise Denied('QUALIFICATION_NOT_ELIGIBLE')
            expiry=min(self.clock.now_ms+ttl_ms,q['expires_at_ms'])
            scope_expiry=min(expiry,self.clock.now_ms+(scope_ttl_ms or ttl_ms))
            policy=canonical_digest({'action':action,'resource':resource,'version':'auth-policy-v1'})
            grant={'grant_id':ident('grant'),'skill':q['skill'],'version':q['version'],'context':q['context'],
                   'skill_digest':q['skill_digest'],'context_digest':q['context_digest'],
                   'qualification_id':qid,'qualification_digest':canonical_digest(q),'policy_digest':policy,
                   'action':action,'resource':resource,'expires_at_ms':scope_expiry}
            grants=current['grants']; grants[q['skill']]=grant
            body={'agent_id':agent,'revision':current['revision']+1,'passport_id':ident('passport'),'issued_at_ms':self.clock.now_ms,
                  'grants':grants,'expires_at_ms':max([expiry]+[g['expires_at_ms'] for g in grants.values()]),'status':'ACTIVE'}
            body=self._seal(body,'authority')
            db.execute('INSERT OR REPLACE INTO authorities VALUES (?,?)',(agent,json.dumps(body)))
            prior=[json.loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY rowid DESC')]
            withdrawal=next((e for e in prior if e['event_type']=='REVOKED' and e['agent_id']==agent and e.get('skill')==q['skill']),None)
            if withdrawal:
                self._event(db,'REQUALIFIED',agent,skill=q['skill'],qualification_id=qid,
                            prior_withdrawal_event_id=withdrawal['event_id'])
            self._event(db,'GRANTED',agent,subject=grant['grant_id'],authority_revision=body['revision'],qualification_id=qid)
            return body

    def _revoke(self,db,agent,skill,reason,expected_revision=None,attempt_id=''):
        a=self._authority(db,agent)
        if expected_revision is not None and expected_revision!=a['revision']: raise Denied('REVISION_CONFLICT')
        if skill not in a['grants']: return a
        old=a['grants'].pop(skill);a['revision']+=1;a['passport_id']=ident('passport');a['issued_at_ms']=self.clock.now_ms
        a['status']='ACTIVE' if a['grants'] else 'REVOKED'
        a=self._seal(a,'authority')
        db.execute('INSERT OR REPLACE INTO authorities VALUES (?,?)',(agent,json.dumps(a)))
        self._event(db,'REVOKED',agent,attempt_id,subject=old['grant_id'],skill=skill,reason=reason,authority_revision=a['revision'])
        return a

    def revoke(self,agent='agent-a',skill='release-model',reason='KNOWN_FAILURE',expected_revision=None):
        if not self.authority_available: raise Denied('AUTHORITY_UNCONFIRMED')
        with self._tx() as db: return self._revoke(db,agent,skill,reason,expected_revision)

    def reactivate(self,agent,skill):
        raise Denied('QUALIFICATION_AND_POLICY_REQUIRED')

    def _check(self,db,intent,expected_revision=None):
        if not self.authority_available: raise Denied('AUTHORITY_UNCONFIRMED')
        a=self._authority(db,intent['agent']);skill=intent['skill']
        if a['status']!='ACTIVE' or skill not in a['grants']: raise Denied('REVOKED_AUTHORITY')
        if not self._verified(a,{'authority'}): raise Denied('INVALID_AUTHORITY')
        if expected_revision is not None and a['revision']!=expected_revision: raise Denied('REVOKED_AUTHORITY')
        if a['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_PASSPORT')
        g=a['grants'][skill]
        if g['expires_at_ms']<=self.clock.now_ms: raise Denied('EXPIRED_SCOPE')
        for name in ('version','context','action','resource'):
            if g[name]!=intent[name]: raise Denied('SCOPE_MISMATCH')
        qrow=db.execute('SELECT body FROM qualifications WHERE id=?',(g['qualification_id'],)).fetchone()
        q=json.loads(qrow[0]) if qrow else {}
        if q.get('disposition')!='ELIGIBLE' or q.get('expires_at_ms',0)<=self.clock.now_ms: raise Denied('EVIDENCE_UNCONFIRMED')
        if canonical_digest(q)!=g['qualification_digest']: raise Denied('BINDING_MISMATCH')
        g['_policy_decision_id']=ident('fixture-policy-check')
        return a,g

    def admit(self,agent='agent-a',skill='release-model',version='skill-v1',context='demo-a',action='release',
              resource='registry-a/model-a',target='model-v2',attempt_id=None,expected_revision=None):
        intent={'agent':agent,'skill':skill,'version':version,'context':context,'action':action,'resource':resource,
                'target':target,'attempt_id':attempt_id or ident('attempt')}
        request_digest=canonical_digest(intent)
        with self._tx() as db:
            old=db.execute('SELECT intent_digest,command FROM attempts WHERE id=?',(intent['attempt_id'],)).fetchone()
            if old:
                if old[0]!=request_digest: raise Denied('IDEMPOTENCY_CONFLICT')
                return json.loads(old[1])
            a,g=self._check(db,intent,expected_revision)
            cmd={**intent,'request_digest':request_digest,'requested_at_ms':self.clock.now_ms,'policy_decision_id':g['_policy_decision_id'],'authority_revision':a['revision'],'passport_id':a['passport_id'],
                 'grant_id':g['grant_id'],'skill_digest':g['skill_digest'],'context_digest':g['context_digest'],
                 'qualification_id':g['qualification_id'],'qualification_digest':g['qualification_digest'],
                 'policy_digest':g['policy_digest']}
            cmd=self._seal(cmd,'authority')
            db.execute('INSERT INTO attempts VALUES (?,?,?,NULL)',(intent['attempt_id'],request_digest,json.dumps(cmd)))
            return cmd

    def execute(self,**kwargs):
        return self.commit(self.admit(**kwargs))

    def read(self,resource='registry-a/model-a'):
        # Independent observer connection reads committed database state.
        with self._db() as db:
            row=db.execute('SELECT version,healthy FROM registry WHERE resource=?',(resource,)).fetchone()
            return {'version':row[0],'healthy':bool(row[1])} if row else {'version':'model-v1','healthy':True}

    @property
    def mutation_count(self):
        with self._db() as db: return db.execute("SELECT value FROM meta WHERE name='mutation_count'").fetchone()[0]

    def attempts(self,attempt_id):
        with self._db() as db:
            row=db.execute('SELECT command,result FROM attempts WHERE id=?',(attempt_id,)).fetchone()
            if not row: return None
            return json.loads(row[1]) if row[1] else {'state':'REQUESTED','command':json.loads(row[0]),'attempt_id':attempt_id}

    @contextmanager
    def _commit_fence(self):
        # Single-host fixture guarantee; all fixture registry writers use this lock.
        # Outbox network delivery is deliberately outside the mutation fence.
        with self.lock, open(self.path+'.commit.lock','a+b') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(handle,fcntl.LOCK_UN)

    def commit(self,command,actual=None,healthy=True,observer_available=True,lose_response=False,before_delivery=None):
        if not self.local_durability_available: raise Denied('LOCAL_DURABILITY_UNAVAILABLE')
        if not self.local_writer_authenticated: raise Denied('LOCAL_INTENT_UNAUTHENTICATED')
        with self._commit_fence():
            self._commit_local(command,actual,healthy,observer_available)
        if before_delivery: before_delivery()
        self.flush_outbox()
        result=self.attempts(command['attempt_id'])
        if lose_response: raise TimeoutError('response lost after durable commit')
        return result

    def _commit_local(self,command,actual,healthy,observer_available):
        with self._tx() as db:
            row=db.execute('SELECT command,result FROM attempts WHERE id=?',(command['attempt_id'],)).fetchone()
            if not row or json.loads(row[0])!=command or not self._verified(command,{'authority'}): raise Denied('BINDING_MISMATCH')
            if row[1]:
                if not self.reconciliation_available: raise Denied('RECONCILIATION_UNAVAILABLE')
                result=json.loads(row[1])
            else:
                a,g=self._check(db,command,command['authority_revision'])
                self._event(db,'INTENT',command['agent'],command['attempt_id'],command=command)
                if command['action']=='release':
                    db.execute('INSERT OR REPLACE INTO registry(resource,version,healthy,attempt_id) VALUES (?,?,?,?)',
                               (command['resource'],actual if actual is not None else command['target'],int(healthy),command['attempt_id']))
                    db.execute("UPDATE meta SET value=value+1 WHERE name='mutation_count'")
                elif command['action'] not in ('read','read-health'):
                    raise Denied('ACTION_UNSUPPORTED')
                result={'state':'COMMITTED','attempt_id':command['attempt_id'],'authority_revision':a['revision'],
                        'command':command,'policy_decision_id':g['_policy_decision_id'],'outcome':None,'delivery':'PENDING','receipt':None,'lifecycle_applied':False}
                db.execute('UPDATE attempts SET result=? WHERE id=?',(json.dumps(result),command['attempt_id']))
                self._event(db,'COMMITTED',command['agent'],command['attempt_id'],authority_revision=a['revision'],policy_decision_id=g['_policy_decision_id'])
        if result['outcome'] is not None:
            return self.apply_outcome(command['attempt_id'])
        # A crash here leaves a committed attempt requiring observation, never replay.
        readback=self.read(command['resource']) if observer_available and self.observer_available else None
        with self._db() as db:
            owner=db.execute('SELECT attempt_id FROM registry WHERE resource=?',(command['resource'],)).fetchone()
        attributable=command['action']!='release' or (owner and owner[0]==command['attempt_id'])
        match=readback and (command['action'] in ('read','read-health') or readback['version']==command['target']) and readback['healthy']
        outcome='UNKNOWN' if readback is None or not attributable else ('PASS' if match else 'FAIL')
        reason={'PASS':'POSTCONDITION_MET','FAIL':'POSTCONDITION_NOT_MET','UNKNOWN':'OBSERVATION_UNAVAILABLE'}[outcome]
        if not attributable: reason='OUTCOME_UNATTRIBUTABLE'
        obs={'observation_id':ident('observation'),'attempt_id':command['attempt_id'],'skill':command['skill'],
             'version':command['version'],'context':command['context'],'skill_digest':command['skill_digest'],
             'context_digest':command['context_digest'],'outcome':outcome,'reason':reason,
             'readback':readback,'independent':True,'shadow':False,'observed_at_ms':self.clock.now_ms,
             'evaluator_digest':canonical_digest({'checker':'independent-registry-readback-v1'})}
        obs=self._seal(obs,'checker'); obs['evidence_digest']=canonical_digest(obs)
        with self._tx() as db:
            db.execute('INSERT OR IGNORE INTO observations VALUES (?,?)',(obs['attempt_id'],json.dumps(obs)))
            result['outcome']=obs
            db.execute('UPDATE attempts SET result=? WHERE id=?',(json.dumps(result),command['attempt_id']))
            self._event(db,'OUTCOME_OBSERVED',command['agent'],command['attempt_id'],outcome=obs)
        return self.apply_outcome(command['attempt_id'])

    def apply_outcome(self,attempt_id):
        with self._tx() as db:
            row=db.execute('SELECT result FROM attempts WHERE id=?',(attempt_id,)).fetchone()
            if not row or not row[0]: raise Denied('OUTCOME_UNKNOWN')
            result=json.loads(row[0])
            if result['lifecycle_applied'] or result['outcome'] is None: return result
            cmd=result['command'];outcome=result['outcome']['outcome']
            if outcome!='PASS':
                qrow=db.execute('SELECT body FROM qualifications WHERE id=?',(cmd['qualification_id'],)).fetchone()
                q=json.loads(qrow[0]);q['qualification_revision']+=1;q['disposition']='INELIGIBLE' if outcome=='FAIL' else 'HOLD'
                q['reason']='KNOWN_FAILURE' if outcome=='FAIL' else 'EVIDENCE_UNCONFIRMED'
                self._include_withdrawal_observation(q,result['outcome'])
                self._save_qualification(db,q)
                self._revoke(db,cmd['agent'],cmd['skill'],q['reason'],attempt_id=attempt_id)
                self._event(db,'DEMOTED' if outcome=='FAIL' else 'HELD',cmd['agent'],attempt_id,skill=cmd['skill'],reason=q['reason'])
            result['lifecycle_applied']=True
            db.execute('UPDATE attempts SET result=? WHERE id=?',(json.dumps(result),attempt_id))
            return result

    def reevaluate(self,agent='agent-a',skill='release-model',state='UNKNOWN'):
        if state not in ('UNKNOWN','STALE'): raise ValueError('unknown hold state')
        with self._tx() as db:
            a=self._authority(db,agent);grant=a['grants'].get(skill)
            if not grant: return a
            row=db.execute('SELECT body FROM qualifications WHERE id=?',(grant['qualification_id'],)).fetchone()
            q=json.loads(row[0]);q['qualification_revision']+=1;q['disposition']='HOLD';q['reason']='STALE_EVIDENCE' if state=='STALE' else 'EVIDENCE_UNCONFIRMED'
            self._save_qualification(db,q)
            self._event(db,'HELD',agent,skill=skill,reason=q['reason'])
            return self._revoke(db,agent,skill,q['reason'])

    def events(self):
        with self._db() as db:
            return [{'event_id':i,'event':json.loads(body),'delivery':delivery,'receipt':json.loads(receipt) if receipt else None}
                    for i,body,delivery,receipt in db.execute('SELECT id,body,delivery,receipt FROM events ORDER BY rowid')]

    def _verify_local_events(self):
        with self._db() as db:
            for raw,signature in db.execute('SELECT body,signature FROM events'):
                try:
                    self.keys['writer'].public_key().verify(base64.b64decode(signature,validate=True),encoded(json.loads(raw)))
                except Exception:
                    raise Denied('LOCAL_INTENT_UNAUTHENTICATED')

    def audit_evidence(self,attempt_id):
        # Remote unavailability or receipt age does not turn a known PASS into FAIL.
        self._verify_local_events()
        rows=[r for r in self.events() if r['event']['attempt_id']==attempt_id and r['delivery']=='RECORDED']
        if not rows or not getattr(self.ledger,'available',True):
            return {'verified':False,'status':'UNAVAILABLE','integrity':'UNKNOWN'}
        for row in rows:
            receipt=row['receipt']
            if 'written_at_ms' in receipt and not 0<=self.clock.now_ms-receipt['written_at_ms']<=600000:
                raise Denied('STALE_LEDGER_RECEIPT')
            if hasattr(self.ledger,'verify_detailed'):
                checked=self.ledger.verify_detailed(receipt,row['event'],max_age_ms=600000,now_ms=self.clock.now_ms)
                if not checked['verified'] and checked['integrity']!='MISMATCH': return checked
                verified=checked['verified']
            else:
                verified=self.ledger.verify(receipt,row['event'])
            if not verified:
                result=self.attempts(attempt_id)
                if result and result.get('command'):
                    cmd=result['command']
                    self.reevaluate(cmd['agent'],cmd['skill'],state='UNKNOWN')
                raise Denied('TAMPER_DETECTED')
        return True

    def flush_outbox(self):
        self._verify_local_events()
        for row in self.events():
            if row['delivery']=='RECORDED': continue
            try:
                receipt=self.ledger.append(row['event'],row['event_id'])
                if not self.ledger.verify(receipt,row['event']): continue
            except (ConnectionError,TimeoutError,Denied,LedgerError):
                continue
            with self._tx() as db:
                db.execute("UPDATE events SET delivery='RECORDED',receipt=? WHERE id=?",(json.dumps(receipt),row['event_id']))
        with self._tx() as db:
            for aid,raw in db.execute('SELECT id,result FROM attempts WHERE result IS NOT NULL').fetchall():
                result=json.loads(raw)
                event_rows=db.execute('SELECT delivery,receipt FROM events WHERE attempt_id=? ORDER BY rowid',(aid,)).fetchall()
                result['delivery']='RECORDED' if event_rows and all(x[0]=='RECORDED' for x in event_rows) else 'PENDING'
                result['receipt']=json.loads(event_rows[-1][1]) if event_rows and event_rows[-1][1] else None
                db.execute('UPDATE attempts SET result=? WHERE id=?',(json.dumps(result),aid))
        return self.events()

    def record_check_only(self,attempt_id,response):
        if response.get('executed') is not False: raise Denied('INVALID_CHECK_ONLY_PROOF')
        return {'state':'AUTHORIZATION_CHECKED','attempt_id':attempt_id,'executed':False,
                'receipt_created':False,'outcome':None,'delivery':'NONE'}
