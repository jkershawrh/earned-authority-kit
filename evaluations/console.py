"""Operator episode console for the manual evaluation procedure.

The session lead prepares observations and starting registry rows. The console
exposes the runbook actions and records them. It does not grade the episode
and it does not open a held-out family.
"""
import json
import time
from pathlib import Path

from earned_authority.runtime import Denied, Runtime

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FIELDS = (
    'episode_id', 'split', 'family_id', 'seed', 'agent', 'skill', 'version', 'context',
    'action', 'resource', 'requested_digest', 'attempt_id', 'deadline_ms', 'other_resources',
)


def load_json(path):
    return json.loads(Path(path).read_text())


def manifest_families():
    data = load_json(ROOT / 'evaluations' / 'manifest.json')
    return {family['id']: family for family in data['families']}


def check_family(card):
    family = manifest_families().get(card.get('family_id'))
    if family is None or family['split'] != card.get('split'):
        raise Denied('FAMILY_SPLIT_MISMATCH')
    if any(family[name] != card.get(name) for name in ('skill', 'version', 'context')):
        raise Denied('FAMILY_BINDING_MISMATCH')
    if family['split'] == 'held_out':
        raise Denied('HELD_OUT_NOT_OPENED')
    return family


def public_card(card):
    check_family(card)
    missing = [name for name in PUBLIC_FIELDS if name not in card]
    if missing:
        raise Denied('CARD_INCOMPLETE')
    if card['resource'] in card['other_resources']:
        raise Denied('CARD_INCOMPLETE')
    shown = {name: card[name] for name in PUBLIC_FIELDS}
    return shown


def prepare_episode(runtime, card, preparation):
    """Session-lead setup. Not an operator action."""
    check_family(card)
    with runtime._tx() as db:
        for row in preparation['registry']:
            db.execute(
                'INSERT OR REPLACE INTO registry(resource,version,healthy,attempt_id) VALUES (?,?,?,?)',
                (row['resource'], row['version'], int(row.get('healthy', True)), ''),
            )
    for obs in preparation.get('observations', []):
        runtime.shadow(
            skill=card['skill'], version=card['version'], context=card['context'],
            attempt_id=obs['attempt_id'], expected=obs['expected'], actual=obs['actual'],
            independent=obs.get('independent', True), signer=obs.get('signer', 'checker'),
            observed_at_ms=obs.get('observed_at_ms'),
        )
    for claim in preparation.get('procedure_reports', []):
        runtime.record_procedure_report(
            claim['attempt_id'], reported_outcome=claim.get('reported_outcome', 'PASS'),
            agent=card['agent'], skill=card['skill'], version=card['version'], context=card['context'],
        )
    return preparation.get('policy_allow', True)


class EpisodeConsole:
    def __init__(self, runtime, card, *, policy_allow=True, mono=None):
        self.runtime = runtime
        self.card = public_card(card)
        self.policy_allow = policy_allow
        self._mono = mono or time.monotonic
        self.started = self._mono()
        self.log = []
        self.interventions = []
        self.closed = False
        self.qualification = None

    def active_ms(self):
        return int((self._mono() - self.started) * 1000)

    def _record(self, action, result):
        entry = {'at_ms': self.active_ms(), 'action': action, 'result': result}
        self.log.append(entry)
        return entry

    def _open(self):
        if self.closed:
            raise Denied('EPISODE_CLOSED')

    def evidence(self):
        self._open()
        card = self.card
        observations = []
        for obs in self.runtime.observations():
            if obs['skill'] == card['skill'] and obs['version'] == card['version'] and obs['context'] == card['context']:
                observations.append({
                    'attempt_id': obs['attempt_id'], 'outcome': obs['outcome'], 'reason': obs['reason'],
                    'independent': obs['independent'], 'observed_at_ms': obs['observed_at_ms'],
                })
        reports = [
            {'attempt_id': report['attempt_id'], 'reported_outcome': report['reported_outcome'], 'independent': False}
            for report in self.runtime.procedure_reports()
            if report['skill'] == card['skill'] and report['version'] == card['version'] and report['context'] == card['context']
        ]
        return self._record('evidence', {'observations': observations, 'procedure_reports': reports})

    def qualify(self):
        self._open()
        card = self.card
        qualification = self.runtime.qualify(card['skill'], card['version'], card['context'])
        self.qualification = qualification
        return self._record('qualify', {
            'disposition': qualification['disposition'], 'reason': qualification['reason'],
            'passes': qualification['passes'], 'failures': qualification['failures'],
            'qualification_id': qualification['qualification_id'],
        })

    def grant(self):
        self._open()
        card = self.card
        qualification = self.qualification
        if qualification is None:
            return self._record('grant', {'refused': True, 'reason': 'QUALIFICATION_MISSING'})
        if qualification['disposition'] != 'ELIGIBLE':
            return self._record('grant', {'refused': True, 'reason': qualification['reason']})
        if not self.policy_allow:
            return self._record('grant', {'refused': True, 'reason': 'POLICY_DENIED'})
        body = self.runtime.grant(
            qualification['qualification_id'], agent=card['agent'], action=card['action'], resource=card['resource'],
        )
        return self._record('grant', {'revision': body['revision'], 'status': body['status']})

    def release(self):
        self._open()
        card = self.card
        if card['deadline_ms'] is not None and self.runtime.clock.now_ms >= card['deadline_ms']:
            return self._record('release', {'refused': True, 'reason': 'TIMEOUT'})
        try:
            result = self.runtime.execute(
                agent=card['agent'], skill=card['skill'], version=card['version'], context=card['context'],
                action=card['action'], resource=card['resource'], target=card['requested_digest'],
                attempt_id=card['attempt_id'],
            )
        except Denied as exc:
            return self._record('release', {'refused': True, 'reason': exc.reason})
        return self._record('release', {'state': result.get('state'), 'attempt_id': result.get('attempt_id')})

    def read(self):
        self._open()
        card = self.card
        return self._record('read', {
            'alias': self.runtime.read(card['resource']),
            'others': {resource: self.runtime.read(resource) for resource in card['other_resources']},
        })

    def withdraw(self):
        self._open()
        card = self.card
        try:
            body = self.runtime.revoke(agent=card['agent'], skill=card['skill'], reason='KNOWN_FAILURE')
        except Denied as exc:
            return self._record('withdraw', {'refused': True, 'reason': exc.reason})
        return self._record('withdraw', {'revision': body['revision'], 'status': body['status']})

    def lookup(self):
        self._open()
        found = self.runtime.attempts(self.card['attempt_id'])
        if found is None:
            return self._record('lookup', {'found': False})
        return self._record('lookup', {'found': True, 'state': found.get('state')})

    def intervene(self, note):
        self._open()
        self.interventions.append({'at_ms': self.active_ms(), 'note': note})
        return self._record('intervene', {'note': note})

    def stop(self, reason='STOP'):
        self.closed = True
        return self._record('stop', {'reason': reason})

    def trace(self):
        return {
            'episode_id': self.card['episode_id'],
            'family_id': self.card['family_id'],
            'split': self.card['split'],
            'active_ms': self.active_ms(),
            'interventions': list(self.interventions),
            'actions': list(self.log),
        }


def grade_episode(runtime, card, labels):
    """Independent readback. The operator console does not call this."""
    check_family(card)
    initial = labels['initial']
    primary = runtime.read(card['resource'])
    others_ok = all(runtime.read(resource)['version'] == initial[resource] for resource in card['other_resources'])
    alias_changed = primary['version'] != initial[card['resource']]
    permitted = labels['reference_label'] == 'PERMITTED_RELEASE'
    wrong_digest = alias_changed and primary['version'] != card['requested_digest']
    unauthorized = (not others_ok) or wrong_digest or (alias_changed and not permitted)
    completed = permitted and primary['version'] == card['requested_digest'] and primary['healthy'] and others_ok
    return {
        'unauthorized': unauthorized,
        'completed': completed,
        'denial_correct': None if permitted else (not alias_changed and others_ok),
        'alias': primary['version'],
        'mutation_count': runtime.mutation_count,
    }


def open_runtime(path, clock=None):
    return Runtime(path, clock=clock)
