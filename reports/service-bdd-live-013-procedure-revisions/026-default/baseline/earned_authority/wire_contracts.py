"""Draft producer/consumer mapping for actual runtime records, never permission.

Proofs are private content-addressed source snapshots. Normalizing a qualification
does not replace its source digest signed into a grant. RuntimeTrust uses fresh
durable records, checker keys, current Passport and actual Ledger verification.
It is a local trust adapter, not a portable substitute for those services.
"""
import copy
from dataclasses import dataclass, field

from .contracts import canonical_digest, validate
from .grants import iter_grants

VERSION = '0.1.0-draft.1'
KINDS = {'qualification', 'authority', 'attempt', 'outcome', 'lifecycle-event'}
ACTIONS = {'release': 'model.promote_to_production', 'read': 'demo.read', 'read-health': 'demo.read'}


class WireContractError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise WireContractError(reason)


@dataclass
class WireBundle:
    records: list = field(default_factory=list)
    # Do not write proof_store to public reports: it contains raw signatures.
    proof_store: dict = field(default_factory=dict)

    def proof(self, kind, body):
        source = {'kind': kind, 'body': copy.deepcopy(body)}
        ref = 'source:' + canonical_digest(source)
        self.proof_store[ref] = source
        return ref

    def add(self, kind, primary, **inputs):
        values = {key: [self.proof_store[r]['body'] for r in refs] if isinstance(refs, list)
                  else self.proof_store[refs]['body'] for key, refs in inputs.items()}
        value = _map(kind, values)
        validate(kind, value)
        self.records.append({'kind': kind, 'source_digest': canonical_digest(values[primary]),
                             'primary': primary, 'inputs': inputs, 'value': value})


def _skill_binding(source):
    require(source['skill_digest'] == canonical_digest({'skill': source['skill'], 'version': source['version']}),
            'skill source digest mismatch')
    require(source['context_digest'] == canonical_digest({'environment': source['context']}),
            'context source digest mismatch')


def _observation_binding(observation, command=None):
    _skill_binding(observation)
    require(observation['evidence_digest'] == canonical_digest({
        k: v for k, v in observation.items() if k != 'evidence_digest'}), 'observation digest mismatch')
    if observation['shadow']:
        condition = {'version': observation['expected'], 'healthy': True}
    else:
        require(command is not None, 'live observation requires its original command')
        for key in ('attempt_id', 'skill', 'version', 'context', 'skill_digest', 'context_digest'):
            require(observation[key] == command[key], 'observation/command mismatch: ' + key)
        condition = {'healthy': True}
        if command['action'] == 'release':
            condition['version'] = command['target']
        else:
            require(command['action'] in ('read', 'read-health'), 'unsupported observation action')
    readback = observation['readback']
    if observation['outcome'] == 'UNKNOWN':
        require(readback is None or observation['reason'] == 'OUTCOME_UNATTRIBUTABLE',
                'unknown outcome requires unavailable or unattributable readback')
    else:
        require(isinstance(readback, dict) and type(readback.get('healthy')) is bool,
                'known outcome requires actual independent readback')
        matches = all(readback.get(key) == value for key, value in condition.items())
        require(observation['outcome'] == ('PASS' if matches else 'FAIL'),
                'outcome label disagrees with observed postcondition')
    return condition


def _map(kind, inputs):
    value = {'schema_version': VERSION}
    if kind == 'qualification':
        q, observations = inputs['qualification'], inputs['observations']
        _skill_binding(q)
        by_id = {o['observation_id']: o for o in observations}
        require(len(by_id) == len(observations), 'duplicate observation proof')
        refs = q['outcome_refs']
        require(len({r['attempt_id'] for r in refs}) == len(refs), 'duplicate qualification attempt')
        require(set(by_id) == {r['observation_id'] for r in refs}, 'qualification proof references differ')
        for ref in refs:
            o = by_id[ref['observation_id']]
            require(o['attempt_id'] == ref['attempt_id'] and o['evidence_digest'] == ref['evidence_digest'],
                    'qualification evidence reference mismatch')
            for key in ('skill_digest', 'context_digest', 'evaluator_digest'):
                require(o[key] == q[key], 'qualification evidence binding mismatch: ' + key)
            require(o['independent'] and o['signer'] == 'checker', 'qualification requires independent checker')
        if q['disposition'] == 'ELIGIBLE':
            require(len(observations) >= 3 and all(o['outcome'] == 'PASS' for o in observations),
                    'demo-three-pass eligibility requires three independent PASS observations')
        times = [o['observed_at_ms'] for o in observations]
        value.update(qualification_id=q['qualification_id'], skill_id=q['skill'],
                     qualification_revision=q['qualification_revision'],
                     outcome_refs=['observation:' + r['observation_id'] for r in refs],
                     observed_from_ms=min(times) if times else None, observed_until_ms=max(times) if times else None,
                     evidence_digest=canonical_digest(refs))
        for key in ('skill_digest', 'context_digest', 'evaluator_digest', 'policy_digest', 'expires_at_ms', 'disposition'):
            value[key] = q[key]
    elif kind == 'authority':
        a = inputs['authority']
        require(a['status'] == 'ACTIVE' and a['passport_id'] and a['grants'],
                'only an actual active credential can be exported; revoked tombstones have none')
        grants = []
        for g in sorted(iter_grants(a),key=lambda g:g['grant_id']):
            _skill_binding(g)
            item = {k: g[k] for k in ('grant_id', 'skill_digest', 'context_digest', 'qualification_id',
                                      'qualification_digest', 'policy_digest', 'resource', 'expires_at_ms')}
            item.update(skill_id=g['skill'], action_class=ACTIONS[g['action']]); grants.append(item)
        policies = [{'grant_id': g['grant_id'], 'policy_digest': g['policy_digest']}
                    for g in sorted(grants, key=lambda g: g['grant_id'])]
        canonical = a.get('canonical')
        signature = canonical['signature'] if canonical else a['signature']
        issuer = canonical['subject']['issued_by'] if canonical else a['signer']
        value.update(passport_id=a['passport_id'], agent_id=a['agent_id'], authority_revision=a['revision'],
                     issued_at_ms=a['issued_at_ms'], expires_at_ms=a['expires_at_ms'], status=a['status'],
                     grants=grants, policy_digest=canonical_digest(policies), issuer_ref=issuer,
                     signature_ref='signature:' + canonical_digest({'signature': signature}))
    elif kind == 'attempt':
        a = inputs['attempt']; command = a['command']; _skill_binding(command)
        q = inputs['qualification']
        require(canonical_digest(q) == command['qualification_digest']
                and q['qualification_id'] == command['qualification_id']
                and q['disposition'] == 'ELIGIBLE', 'attempt original qualification is not the exact eligible revision')
        for key in ('skill_digest', 'context_digest'):
            require(q[key] == command[key], 'attempt original qualification scope mismatch')
        require(q['evaluated_at_ms'] <= command['requested_at_ms'] < q['expires_at_ms'],
                'attempt was not requested within qualification validity')
        intent_keys = ('agent', 'skill', 'version', 'context', 'action', 'resource', 'target', 'attempt_id')
        require(command['request_digest'] == canonical_digest({k: command[k] for k in intent_keys}),
                'attempt original request digest mismatch')
        require(a['attempt_id'] == command['attempt_id'], 'attempt identifier mismatch')
        require(a['state'] in ('REQUESTED', 'COMMITTED'), 'unsupported runtime attempt state')
        value.update(attempt_id=command['attempt_id'], correlation_id=command['attempt_id'],
                     idempotency_key=command['attempt_id'], agent_id=command['agent'], skill_id=command['skill'],
                     action_class=ACTIONS[command['action']], arguments_digest=canonical_digest({'target': command['target']}),
                     state=a['state'], policy_decision_id=a.get('policy_decision_id', command['policy_decision_id']))
        for key in ('skill_digest', 'context_digest', 'passport_id', 'authority_revision', 'grant_id',
                    'policy_digest', 'resource', 'requested_at_ms'):
            value[key] = command[key]
        commits = inputs['commits']; checks = inputs.get('checks',[])
        require(type(command.get('execution_checks_version',1)) is int and command.get('execution_checks_version',1)==1,
                'unsupported execution checks version')
        if a['state'] == 'COMMITTED':
            require(len(commits) == 1, 'committed attempt requires exactly one durable commit event')
            e = commits[0]['event']
            require(e['event_type'] == 'COMMITTED' and e['attempt_id'] == command['attempt_id']
                    and e['agent_id'] == command['agent'] and e['authority_revision'] == command['authority_revision']
                    and e['policy_decision_id'] == value['policy_decision_id'], 'commit receipt binding mismatch')
            value['mutation_receipt_ref'] = 'local-event:' + e['event_id'] + ':' + canonical_digest(e)
            if command.get('execution_checks_version')==1 or checks:
                expected_types={'QUALIFICATION_CHECKED':'ELIGIBLE','AUTHORIZATION_CHECKED':'ALLOW'}
                require(len(checks)==2 and {r['event']['event_type'] for r in checks}==set(expected_types),
                        'attempt requires exactly one qualification and authorization check')
                expected={k:command[k] for k in ('skill_digest','context_digest','qualification_id','qualification_digest',
                          'passport_id','grant_id','authority_revision','policy_digest','action','resource')}
                expected.update(command_digest=canonical_digest(command),qualification_revision=q['qualification_revision'],
                                policy_decision_id=value['policy_decision_id'],check_stage='MUTATION_BOUNDARY',
                                authorizes_execution=False,agent_id=command['agent'],attempt_id=command['attempt_id'],
                                correlation_id=command['attempt_id'])
                for row in checks:
                    check=row['event']
                    require(all(type(check.get(k)) is type(v) and check.get(k)==v for k,v in expected.items()),
                            'attempt check binding mismatch')
                    require(check['result']==expected_types[check['event_type']], 'attempt check result mismatch')
                    require(command['requested_at_ms']<=check['occurred_at_ms']<=e['occurred_at_ms']
                            and q['evaluated_at_ms']<=check['occurred_at_ms']<q['expires_at_ms'],
                            'attempt check outside qualified execution time')
        else:
            require(not commits, 'requested attempt cannot have a commit receipt')
            require(not checks, 'requested attempt cannot claim completed boundary checks')
    elif kind == 'outcome':
        o = inputs['observation']; command = inputs.get('attempt', {}).get('command')
        condition = _observation_binding(o, command)
        independence = 'INDEPENDENT' if o['independent'] and o['signer'] == 'checker' else 'SELF_REPORTED'
        value.update(observation_id=o['observation_id'], attempt_id=o['attempt_id'], correlation_id=o['attempt_id'],
                     skill_id=o['skill'], skill_digest=o['skill_digest'], context_digest=o['context_digest'],
                     verifier_id=o['signer'], verifier_digest=o['evaluator_digest'],
                     verifier_attestation_ref='attestation:' + o['evidence_digest'], independence=independence,
                     observed_at_ms=o['observed_at_ms'], outcome=o['outcome'],
                     postcondition_digest=canonical_digest(condition), evidence_digest=o['evidence_digest'])
    elif kind == 'lifecycle-event':
        row = inputs['event']; e = row['event']
        require(row['event_id'] == e['event_id'], 'event identifier mismatch')
        value.update(event_id=e['event_id'], correlation_id=e['correlation_id'], agent_id=e['agent_id'],
                     subject_id=e['event_id'], subject_revision=1, event_type=e['event_type'],
                     occurred_at_ms=e['occurred_at_ms'], payload_digest=canonical_digest(e),
                     actor_ref='local-runtime-writer', reason_code=e.get('reason', 'NOT_SPECIFIED'),
                     delivery_state=row['delivery'])
        if row['delivery'] == 'RECORDED':
            require(row['receipt'] is not None, 'recorded event requires actual receipt')
            value['ledger_receipt_ref'] = 'ledger-receipt:' + canonical_digest(row['receipt'])
        else:
            require(row['receipt'] is None, 'pending event must not carry a recorded receipt')
    else:
        raise WireContractError('unknown wire kind')
    return value


def export_runtime(runtime, *, qualification_ids=(), agent='agent-a', attempt_ids=(), include_authority=True):
    """Snapshot actual records without execution, qualification, or grants.

    include_authority=False exports historical execution/evidence after withdrawal.
    An active bundle binds all included attempts to its current authority revision.
    Concurrent source changes invalidate consumption; retry from a fresh export.
    """
    try:
        bundle = WireBundle()
        observations = {o['observation_id']: o for o in runtime.observations()}
        events = runtime.events(); qids = set(qualification_ids)
        authority = runtime.authority(agent) if include_authority else None
        if authority:
            require(authority['status'] == 'ACTIVE' and authority['grants'] and authority['passport_id'],
                    'no active credential to export')
            qids.update(g['qualification_id'] for g in iter_grants(authority))
        outcomes = set()
        for qid in sorted(qids):
            q = runtime.qualification(qid)
            refs = [bundle.proof('observation', observations[r['observation_id']]) for r in q['outcome_refs']]
            outcomes.update(r['observation_id'] for r in q['outcome_refs'])
            bundle.add('qualification', 'qualification', qualification=bundle.proof('qualification', q), observations=refs)
        if authority:
            bundle.add('authority', 'authority', authority=bundle.proof('authority', authority))
        for aid in attempt_ids:
            attempt = runtime.attempts(aid); require(attempt is not None, 'attempt missing')
            commits = [bundle.proof('event', row) for row in events
                       if row['event']['attempt_id'] == aid and row['event']['event_type'] == 'COMMITTED']
            checks = [bundle.proof('event', row) for row in events if row['event']['attempt_id']==aid
                      and row['event']['event_type'] in ('QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED')]
            command = attempt['command']
            historical = runtime.qualification_at(command['qualification_id'], digest=command['qualification_digest'])
            bundle.add('attempt', 'attempt', attempt=bundle.proof('attempt', attempt), commits=commits, checks=checks,
                       qualification=bundle.proof('qualification-history', historical))
            if attempt.get('outcome'):
                outcomes.add(attempt['outcome']['observation_id'])
        for oid in sorted(outcomes):
            o = observations[oid]; inputs = {'observation': bundle.proof('observation', o)}
            if not o['shadow']:
                attempt = runtime.attempts(o['attempt_id']); require(attempt is not None, 'live outcome original attempt missing')
                inputs['attempt'] = bundle.proof('attempt', attempt)
            bundle.add('outcome', 'observation', **inputs)
        for row in events:
            bundle.add('lifecycle-event', 'event', event=bundle.proof('event', row))
        return bundle
    except WireContractError:
        raise
    except Exception as exc:
        raise WireContractError('runtime export incomplete or invalid: ' + str(exc)) from exc


class RuntimeTrust:
    """Trusted coordinator store plus provisioned checker/service trust anchors.

    Unsigned qualification and result metadata are trusted through this coordinator
    store. Observation, command and local-event signatures are additionally checked.
    Canonical Passport and Ledger check their respective provisioned trust anchors.
    """
    def __init__(self, runtime):
        self.runtime = runtime

    def authenticate(self, kind, body):
        rt = self.runtime
        if kind == 'qualification':
            return rt.qualification(body['qualification_id']) == body
        if kind == 'qualification-history':
            return rt.qualification_at(body['qualification_id'], digest=canonical_digest(body)) == body
        if kind == 'authority':
            if rt.authority(body['agent_id']) != body:
                return False
            if 'canonical' not in body:
                rt.validate_authority(body)
            return True  # canonical current() verified signature and current revision
        if kind == 'observation':
            return rt._verified(body, {'checker'}) and any(o == body for o in rt.observations())
        if kind == 'attempt':
            return rt.attempts(body['attempt_id']) == body and rt._verified(body['command'], {'authority'})
        if kind == 'event':
            rt._verify_local_events()
            return any(row == body for row in rt.events())
        return False

    def verify_receipt(self, receipt, event):
        return self.runtime.ledger.verify(receipt, event)


def consume_bundle(bundle, *, trust, now_ms):
    """Verify schemas, trusted originals, semantic links, and claimed receipts.

    This validates descriptive provenance only. Execution still needs a fresh policy
    decision, current authority and mutation fence in the actual runtime.
    """
    try:
        require(type(now_ms) is int and now_ms >= 0, 'consumer time must be integer milliseconds')
        require(bool(bundle.records), 'empty bundle provides no verified records')
        require(callable(getattr(trust, 'authenticate', None)) and callable(getattr(trust, 'verify_receipt', None)),
                'consumer requires external source and receipt trust adapters')
        verified = {}
        def resolve(ref):
            require(isinstance(ref, str) and ref in bundle.proof_store, 'missing source proof')
            proof = bundle.proof_store[ref]
            require(set(proof) == {'kind', 'body'} and ref == 'source:' + canonical_digest(proof),
                    'source content address mismatch')
            if ref not in verified:
                require(trust.authenticate(proof['kind'], proof['body']), 'source authentication rejected')
                verified[ref] = proof
            return proof['body']
        indexed = {}; seen = set(); attempt_event_ids = {}
        for record in bundle.records:
            require(set(record) == {'kind', 'source_digest', 'primary', 'inputs', 'value'}, 'unknown record envelope fields')
            kind = record['kind']; require(kind in KINDS, 'unknown record kind')
            expected_inputs = {
                'qualification': {'qualification': 'qualification', 'observations': 'observation'},
                'authority': {'authority': 'authority'},
                'attempt': {'attempt': 'attempt', 'commits': 'event', 'checks': 'event', 'qualification': 'qualification-history'},
                'outcome': {'observation': 'observation', **({'attempt': 'attempt'} if 'attempt' in record['inputs'] else {})},
                'lifecycle-event': {'event': 'event'},
            }[kind]
            if kind=='attempt' and 'checks' not in record['inputs']:
                source=resolve(record['inputs']['attempt'])
                require('execution_checks_version' not in source['command'], 'new attempt cannot omit check proofs')
                expected_inputs.pop('checks')
            expected_primary = {'qualification': 'qualification', 'authority': 'authority', 'attempt': 'attempt',
                                'outcome': 'observation', 'lifecycle-event': 'event'}[kind]
            require(record['primary'] == expected_primary and set(record['inputs']) == set(expected_inputs),
                    'record input contract mismatch')
            for name, refs in record['inputs'].items():
                for ref in refs if isinstance(refs, list) else [refs]:
                    resolve(ref)
                    require(bundle.proof_store[ref]['kind'] == expected_inputs[name], 'source proof kind mismatch')
            inputs = {key: [resolve(r) for r in refs] if isinstance(refs, list) else resolve(refs)
                      for key, refs in record['inputs'].items()}
            primary = inputs[record['primary']]
            require(canonical_digest(primary) == record['source_digest'], 'primary source digest mismatch')
            value = record['value']; validate(kind, value)
            require(value == _map(kind, inputs), 'normalized record differs from its authenticated producer')
            identity_field = {'qualification': 'qualification_id', 'authority': 'passport_id',
                              'outcome': 'observation_id', 'lifecycle-event': 'event_id',
                              'attempt': 'attempt_id'}[kind]
            identity = (kind, value[identity_field])
            require(identity not in seen, 'duplicate wire record')
            seen.add(identity); indexed.setdefault(kind, []).append((value, primary))
            if kind=='attempt':
                attempt_event_ids[value['attempt_id']]=[r['event']['event_id'] for r in inputs.get('checks',[])+inputs['commits']]
            if kind == 'qualification' and value['disposition'] == 'ELIGIBLE':
                require(value['observed_until_ms'] <= now_ms < value['expires_at_ms'], 'eligible qualification stale or future')
            if kind == 'outcome':
                require(value['observed_at_ms'] <= now_ms, 'future outcome observation')
            if kind == 'authority':
                require(value['issued_at_ms'] <= now_ms < value['expires_at_ms'], 'active authority expired or future')
                require(all(now_ms < g['expires_at_ms'] for g in value['grants']), 'active scope expired')
            if kind == 'lifecycle-event' and value['delivery_state'] == 'RECORDED':
                require(trust.verify_receipt(primary['receipt'], primary['event']), 'ledger receipt authentication rejected')
        quals = {q['qualification_id']: (q, raw) for q, raw in indexed.get('qualification', [])}
        outcomes = {o['observation_id']: o for o, _ in indexed.get('outcome', [])}
        events = {e['event_id']: e for e, _ in indexed.get('lifecycle-event', [])}
        for _, raw in quals.values():
            for ref in raw['outcome_refs']:
                require(ref['observation_id'] in outcomes, 'qualification outcome record missing')
                require(outcomes[ref['observation_id']]['evidence_digest'] == ref['evidence_digest'],
                        'qualification outcome record digest mismatch')
        for attempt, raw in indexed.get('attempt', []):
            if raw.get('outcome'):
                oid = raw['outcome']['observation_id']
                require(oid in outcomes and outcomes[oid]['attempt_id'] == attempt['attempt_id'],
                        'attempt outcome record missing or mismatched')
            if attempt['state'] == 'COMMITTED':
                require(all(event_id in events for event_id in attempt_event_ids[attempt['attempt_id']]),
                        'exact attempt check or commit lifecycle record missing')
                require(any(e['event_type'] == 'COMMITTED' and e['correlation_id'] == attempt['attempt_id']
                            for e in events.values()), 'durable commit lifecycle record missing')
                if raw['command'].get('execution_checks_version')==1:
                    for kind in ('QUALIFICATION_CHECKED','AUTHORIZATION_CHECKED'):
                        require(sum(e['event_type']==kind and e['correlation_id']==attempt['attempt_id']
                                    for e in events.values())==1, 'attempt check lifecycle record missing or duplicated')
        require(len(indexed.get('authority', [])) <= 1, 'bundle contains multiple current credentials')
        for authority, _ in indexed.get('authority', []):
            for grant in authority['grants']:
                require(grant['qualification_id'] in quals, 'authority qualification absent from bundle')
                q, raw = quals[grant['qualification_id']]
                require(q['disposition'] == 'ELIGIBLE' and canonical_digest(raw) == grant['qualification_digest'],
                        'authority does not bind this eligible qualification source')
                for name in ('skill_id', 'skill_digest', 'context_digest'):
                    require(grant[name] == q[name], 'grant/qualification scope mismatch')
                require(grant['expires_at_ms'] <= q['expires_at_ms'], 'grant outlives qualification')
            for attempt, source in indexed.get('attempt', []):
                require(attempt['passport_id'] == authority['passport_id']
                        and attempt['authority_revision'] == authority['authority_revision']
                        and attempt['agent_id'] == authority['agent_id'], 'attempt not bound to active credential')
                grants = [g for g in authority['grants'] if g['grant_id'] == attempt['grant_id']]
                require(len(grants) == 1, 'attempt grant absent'); grant = grants[0]
                for name in ('skill_id', 'skill_digest', 'context_digest', 'policy_digest', 'action_class', 'resource'):
                    require(attempt[name] == grant[name], 'attempt/grant binding mismatch: ' + name)
                cmd = source['command']
                require(cmd['qualification_id'] == grant['qualification_id'] and
                        cmd['qualification_digest'] == grant['qualification_digest'], 'command qualification binding mismatch')
        return {'verified': True, 'records_verified': len(bundle.records), 'source_proofs_verified': len(verified),
                'authorizes_execution': False, 'schema_version': VERSION}
    except WireContractError:
        raise
    except Exception as exc:
        raise WireContractError('consumer rejected incomplete or invalid producer data: ' + str(exc)) from exc
