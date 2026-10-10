"""Diagnostic authority cache tests with explicit UNIT service seams.

These test local persistence and refusal to authorize from cached observations.
Only the separate connected BDD runner can establish real-service acceptance.
"""
import copy
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from earned_authority.connected import ConnectedRuntime
from earned_authority.contracts import canonical_digest
from earned_authority.runtime import Denied
from test_connected_evidence import CONTEXT, ready, rt


def admit(runtime, attempt='cache-attempt'):
    return runtime.admit(version=runtime.procedure_revision, context=CONTEXT,
                         resource='model/champion', target='model-v2', attempt_id=attempt)


def test_explicit_refresh_records_verified_snapshot_without_execution_authority(rt):
    ready(rt)
    assert rt.cached_authority_observation() is None
    current = rt.authority()
    observed = rt.refresh_authority_observation()
    assert observed['authority'] == current
    assert observed['authority_digest'] == canonical_digest(current)
    assert observed['source'] == 'CANONICAL_CURRENT_STATUS'
    assert observed['observed_at_ms'] == rt.clock.now_ms
    assert observed['can_authorize_execution'] is False
    assert observed['requires_current_check'] is True
    assert rt._verified(observed, {'writer'})
    assert rt.cached_authority_observation() == observed
    assert rt.mutation_count == 0


def test_cached_observation_survives_restart_without_calling_canonical_service(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    reopened = ConnectedRuntime(rt.path, passport=rt.passport, policy=rt.policy,
        ledger=rt.ledger, qualification_client=rt.qualifier, fence_path=rt.fence_path)
    reopened.passport.current = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('offline diagnostic read made an RPC'))
    assert reopened.cached_authority_observation() == observed
    assert reopened.mutation_count == 0


def test_cached_active_grant_cannot_admit_or_commit_during_current_status_outage(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    command = admit(rt)
    events = rt.events()
    def unavailable(*args, **kwargs):
        raise Denied('AUTHORITY_UNCONFIRMED')
    rt.passport.current = unavailable
    for action in (lambda: rt.refresh_authority_observation(), lambda: admit(rt, 'new-attempt'), lambda: rt.commit(command)):
        with pytest.raises(Denied) as failure: action()
        assert failure.value.reason == 'AUTHORITY_UNCONFIRMED'
    assert rt.cached_authority_observation() == observed
    assert observed['authority']['status'] == 'ACTIVE'
    assert 'release-model' in observed['authority']['grants']
    assert rt.attempts('new-attempt') is None
    assert rt.attempts('cache-attempt')['state'] == 'REQUESTED'
    assert rt.events() == events
    assert rt.read('model/champion') == {'version': 'model-v1', 'healthy': True}
    assert rt.mutation_count == 0


def test_canonical_revocation_overrides_cached_active_observation(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    rt.revoke(skill='release-model')
    assert rt.cached_authority_observation() == observed
    with pytest.raises(Denied) as failure: admit(rt)
    assert failure.value.reason == 'REVOKED_AUTHORITY'
    newer = rt.refresh_authority_observation()
    assert newer['authority']['revision'] > observed['authority']['revision']
    assert 'release-model' not in newer['authority']['grants']
    assert rt.mutation_count == 0


@pytest.mark.parametrize('has_cache', [False, True])
def test_malformed_canonical_response_cannot_refresh_cache(rt, has_cache):
    ready(rt)
    previous = rt.refresh_authority_observation() if has_cache else None
    def invalid(*args, **kwargs):
        raise Denied('INVALID_CANONICAL_AUTHORITY')
    rt.passport.current = invalid
    with pytest.raises(Denied) as failure: rt.refresh_authority_observation()
    assert failure.value.reason == 'INVALID_AUTHORITY'
    assert rt.cached_authority_observation() == previous


def test_tampered_diagnostic_record_is_rejected_without_network_fallback(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    changed = copy.deepcopy(observed)
    changed['observed_at_ms'] += 1
    with rt._tx() as db:
        db.execute('UPDATE authority_observations SET body=? WHERE agent=?', (json.dumps(changed), 'agent-a'))
    with pytest.raises(Denied) as failure: rt.cached_authority_observation()
    assert failure.value.reason == 'AUTHORITY_OBSERVATION_UNAUTHENTICATED'


def test_bad_diagnostic_cache_is_not_an_input_to_live_authorization(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    observed['authority']['status'] = 'FABRICATED'
    with rt._tx() as db:
        db.execute('UPDATE authority_observations SET body=? WHERE agent=?', (json.dumps(observed), 'agent-a'))
    with pytest.raises(Denied): rt.cached_authority_observation()
    result = rt.commit(admit(rt))
    assert result['outcome']['outcome'] == 'PASS'
    assert rt.read('model/champion') == {'version': 'model-v2', 'healthy': True}
    assert rt.mutation_count == 1


def test_signed_observation_cannot_be_reindexed_to_another_agent(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    with rt._tx() as db:
        db.execute('INSERT INTO authority_observations VALUES (?,?)', ('agent-b', json.dumps(observed)))
    with pytest.raises(Denied) as failure: rt.cached_authority_observation('agent-b')
    assert failure.value.reason == 'AUTHORITY_OBSERVATION_UNAUTHENTICATED'


def test_actual_wrong_local_signing_key_cannot_replace_cached_observation(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    original = rt.keys['writer']
    rt.keys['writer'] = Ed25519PrivateKey.generate()
    try:
        with pytest.raises(Denied) as failure: rt.refresh_authority_observation()
        assert failure.value.reason == 'AUTHORITY_OBSERVATION_UNAUTHENTICATED'
    finally: rt.keys['writer'] = original
    assert rt.cached_authority_observation() == observed


def test_delayed_older_observation_cannot_overwrite_later_revision(rt):
    ready(rt)
    old_snapshot = rt.authority()
    rt.refresh_authority_observation()
    rt.revoke(skill='release-model')
    newer = rt.refresh_authority_observation()
    # UNIT interleaving: a lookup captured before revocation completes later.
    rt.authority = lambda agent='agent-a': copy.deepcopy(old_snapshot)
    assert rt.refresh_authority_observation() == newer
    assert rt.cached_authority_observation() == newer


def test_same_revision_conflicting_observation_does_not_replace_known_record(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    inconsistent = copy.deepcopy(observed['authority'])
    inconsistent['passport_id'] = 'conflicting-same-revision-passport'
    rt.authority = lambda agent='agent-a': inconsistent
    with pytest.raises(Denied) as failure: rt.refresh_authority_observation()
    assert failure.value.reason == 'AUTHORITY_OBSERVATION_CONFLICT'
    assert rt.cached_authority_observation() == observed


def test_delayed_same_revision_observation_cannot_regress_observed_time(rt):
    ready(rt)
    rt.clock.advance(100)
    newer = rt.refresh_authority_observation()
    # UNIT ordering: the same verified snapshot's earlier read persists later.
    rt.clock.advance(-50)
    assert rt.refresh_authority_observation() == newer
    assert rt.cached_authority_observation() == newer


def test_actual_readonly_sqlite_write_preserves_prior_diagnostic_snapshot(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    original = rt._db
    # Actual SQLite read-only connection, not an invented exception/boolean.
    rt._db = lambda *args, **kwargs: original(read_only=True)
    try:
        with pytest.raises(Denied) as failure: rt.refresh_authority_observation()
        assert failure.value.reason == 'LOCAL_DURABILITY_UNAVAILABLE'
        assert failure.value.__cause__.sqlite_errorname == 'SQLITE_READONLY'
    finally: rt._db = original
    assert rt.cached_authority_observation() == observed
    assert rt.mutation_count == 0


def test_trigger_replay_of_valid_signed_record_cannot_replace_exact_observation(rt):
    ready(rt)
    observed = rt.refresh_authority_observation()
    rt.clock.advance(1)
    with rt._tx() as db:
        quoted = db.execute('SELECT quote(?)', (json.dumps(observed),)).fetchone()[0]
        db.execute('CREATE TRIGGER replay_cached_observation AFTER INSERT ON authority_observations '
                   'BEGIN UPDATE authority_observations SET body='+quoted+' WHERE agent=NEW.agent; END')
    with pytest.raises(Denied) as failure: rt.refresh_authority_observation()
    assert failure.value.reason == 'AUTHORITY_OBSERVATION_UNAUTHENTICATED'
    assert rt.cached_authority_observation() == observed
