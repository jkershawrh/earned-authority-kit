"""Persisted last-verified authority observations for operator diagnostics.

An observation records what the canonical current-status service returned at a
past instant. It is never current permission, an offline authorization fallback,
or a replacement for the canonical service. Only explicit diagnostic refreshes
write this cache; the executable admission and commit paths do not consume it.
"""
import copy
import json
import sqlite3

from .contracts import canonical_digest
from .runtime import Denied, ident


class AuthorityObservations:
    def _init_authority_observations(self):
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS authority_observations(agent TEXT PRIMARY KEY,body TEXT NOT NULL)')

    def _read_authority_observation(self, db, agent):
        row = db.execute('SELECT body FROM authority_observations WHERE agent=?', (agent,)).fetchone()
        if row is None:
            return None
        try:
            observed = json.loads(row[0])
            authority = observed['authority']
            if (not self._verified(observed, {'writer'})
                    or observed['agent_id'] != agent or authority['agent_id'] != agent
                    or observed['record_type'] != 'AUTHORITY_OBSERVATION'
                    or observed['source'] != 'CANONICAL_CURRENT_STATUS'
                    or observed['can_authorize_execution'] is not False
                    or observed['requires_current_check'] is not True
                    or type(observed['observed_at_ms']) is not int or observed['observed_at_ms'] < 0
                    or type(authority['revision']) is not int or authority['revision'] < 0
                    or observed['authority_digest'] != canonical_digest(authority)):
                raise ValueError('observation authentication or binding mismatch')
            return observed
        except Exception as exc:
            raise Denied('AUTHORITY_OBSERVATION_UNAUTHENTICATED') from exc

    def cached_authority_observation(self, agent='agent-a'):
        """Return signed historical diagnostic data without any service request.

        ACTIVE inside the snapshot means active at observed_at_ms. Even a recent
        observation cannot authorize execution or confirm the current status.
        """
        try:
            with self._db(read_only=True) as db:
                return self._read_authority_observation(db, agent)
        except (sqlite3.Error, OSError) as exc:
            raise Denied('AUTHORITY_OBSERVATION_UNAVAILABLE') from exc

    def refresh_authority_observation(self, agent='agent-a'):
        """Explicitly fetch verified current authority and cache it for diagnosis.

        A failed canonical lookup leaves the prior observation untouched. Older
        racing replies cannot replace a newer monotonic authority revision.
        """
        authority = copy.deepcopy(self.authority(agent))
        if (authority.get('agent_id') != agent or type(authority.get('revision')) is not int
                or authority['revision'] < 0):
            raise Denied('INVALID_AUTHORITY')
        observed = {'record_type': 'AUTHORITY_OBSERVATION', 'observation_id': ident('authority-observation'),
                    'agent_id': agent, 'source': 'CANONICAL_CURRENT_STATUS',
                    'observed_at_ms': self.clock.now_ms, 'authority': authority,
                    'authority_digest': canonical_digest(authority),
                    'can_authorize_execution': False, 'requires_current_check': True}
        try:
            with self._tx() as db:
                prior = self._read_authority_observation(db, agent)
                if prior:
                    if prior['authority']['revision'] > authority['revision']:
                        return prior
                    if (prior['authority']['revision'] == authority['revision']
                            and prior['authority_digest'] != observed['authority_digest']):
                        raise Denied('AUTHORITY_OBSERVATION_CONFLICT')
                    if (prior['authority']['revision'] == authority['revision']
                            and prior['observed_at_ms'] > observed['observed_at_ms']):
                        return prior
                try:
                    signed = self._seal(observed, 'writer')
                except Exception as exc:
                    raise Denied('AUTHORITY_OBSERVATION_UNAUTHENTICATED') from exc
                db.execute('INSERT OR REPLACE INTO authority_observations VALUES (?,?)', (agent, json.dumps(signed)))
                stored = self._read_authority_observation(db, agent)
                if stored != signed:
                    raise Denied('AUTHORITY_OBSERVATION_UNAUTHENTICATED')
                return stored
        except (sqlite3.Error, OSError) as exc:
            raise Denied('LOCAL_DURABILITY_UNAVAILABLE') from exc
