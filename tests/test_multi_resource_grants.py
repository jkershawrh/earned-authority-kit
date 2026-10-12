"""Exact multi-resource grants and skill-wide withdrawal.

Unit seams exercise the adapter. They are not a live BDD-031 service run.
"""
import copy
import json

import pytest

from earned_authority.contracts import canonical_digest
from earned_authority.grants import (
    grants_for_skill, has_skill, iter_grants, select_grant, unique_grant, upsert_grant,
)
from earned_authority.runtime import Denied
from earned_authority.wire_contracts import WireBundle
from test_connected_evidence import CONTEXT, qualify, ready, rt


def grant_record(skill='read-health', resource='urn:dataset/health', **changes):
    context = changes.pop('context', {'model_version': 'model-v2'})
    version = changes.pop('version', 'skill-v1')
    body = {
        'grant_id': 'grant-' + resource.rsplit('/', 1)[-1],
        'skill': skill, 'version': version, 'context': context,
        'skill_digest': canonical_digest({'skill': skill, 'version': version}),
        'context_digest': canonical_digest({'environment': context}),
        'qualification_id': 'qualification-1', 'qualification_digest': 'sha256:' + 'b' * 64,
        'policy_digest': 'sha256:' + 'c' * 64, 'action': 'read', 'resource': resource,
        'expires_at_ms': 2000000,
    }
    body.update(changes)
    return body


def read_pair(rt):
    read = qualify(rt, 'read-health')
    first = rt.grant(read['qualification_id'], action='read', resource='urn:dataset/health', ttl_ms=10000)
    original = unique_grant(first, 'read-health')
    rt.clock.advance(50)
    second = rt.grant(read['qualification_id'], action='read', resource='urn:dataset/health-extra',
                      ttl_ms=10000, expected_revision=first['revision'])
    return read, original, second


def admit_read(rt, resource, **changes):
    return rt.admit(version=rt.procedure_revision, context=CONTEXT, skill='read-health',
                    action='read', resource=resource, **changes)


def test_second_resource_keeps_the_first_binding_and_rejects_a_stale_revision(rt):
    read, original, second = read_pair(rt)
    reads = grants_for_skill(second, 'read-health')
    kept = next(g for g in reads if g['resource'] == original['resource'])
    added = next(g for g in reads if g['resource'] == 'urn:dataset/health-extra')
    assert second['revision'] == 2
    assert kept['grant_id'] == original['grant_id']
    assert kept['expires_at_ms'] == original['expires_at_ms']
    assert kept['qualification_id'] == added['qualification_id'] == read['qualification_id']
    assert added['grant_id'] != kept['grant_id']
    before = rt.passport.issues
    with pytest.raises(Denied, match='^REVISION_CONFLICT$'):
        rt.grant(read['qualification_id'], action='read', resource='urn:dataset/other', expected_revision=1)
    assert rt.passport.issues == before
    assert rt.authority()['revision'] == second['revision']


def test_old_procedure_revision_is_rejected_before_scope_selection(rt):
    read_pair(rt)
    with pytest.raises(Denied, match='^SKILL_REVISION_MISMATCH$'):
        rt.admit(version='old-procedure', context=CONTEXT, skill='read-health', action='read', resource='urn:dataset/health')


def test_exact_execution_cannot_borrow_a_sibling_binding(rt):
    _, original, second = read_pair(rt)
    added = next(g for g in grants_for_skill(second, 'read-health') if g['resource'] == 'urn:dataset/health-extra')
    for resource in (original['resource'], added['resource']):
        assert rt.commit(admit_read(rt, resource))['outcome']['outcome'] == 'PASS'
    borrowed = {
        'agent': 'agent-a', 'skill': 'read-health', 'version': rt.procedure_revision,
        'context': CONTEXT, 'action': 'read', 'resource': original['resource'],
        'grant_id': added['grant_id'], 'qualification_id': added['qualification_id'],
        'qualification_digest': added['qualification_digest'], 'target': 'model-v2',
    }
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        rt._check(None, borrowed)
    with pytest.raises(Denied, match='^SCOPE_MISMATCH$'):
        admit_read(rt, 'urn:dataset/not-granted')
    assert rt.mutation_count == 0


def test_skill_wide_demotion_removes_both_resources_and_journals_every_target(rt):
    release = qualify(rt)
    rt.grant(release['qualification_id'])
    _, original, current = read_pair(rt)
    release_grant = unique_grant(current, 'release-model')
    rt.reevaluate(skill='read-health')
    authority = rt.authority()
    assert not has_skill(authority, 'read-health')
    kept = unique_grant(authority, 'release-model')
    assert (kept['grant_id'], kept['expires_at_ms']) == (release_grant['grant_id'], release_grant['expires_at_ms'])
    assert authority['revision'] == current['revision'] + 1
    revoked = [row['event'] for row in rt.events() if row['event']['event_type'] == 'REVOKED']
    assert {target['resource'] for target in revoked[-1]['targets']} == {original['resource'], 'urn:dataset/health-extra'}
    assert {target['grant_id'] for target in revoked[-1]['targets']} == {
        original['grant_id'], next(g['grant_id'] for g in grants_for_skill(current, 'read-health') if g['resource'] == 'urn:dataset/health-extra')}


def test_two_pending_anchors_are_both_retained_until_drain(rt):
    ready(rt)
    _, _, current = read_pair(rt)
    ids = {g['grant_id'] for g in grants_for_skill(current, 'read-health')}
    original = rt.drain_withdrawals
    rt.drain_withdrawals = lambda *args, **kwargs: None
    rt.reevaluate(skill='read-health')
    with rt._db() as db:
        pending = {row[0] for row in db.execute('SELECT target_grant_id FROM withdrawals')}
    assert pending == ids
    rt.drain_withdrawals = original
    revision = rt.authority()['revision']
    rt.drain_withdrawals()
    authority = rt.authority()
    assert not has_skill(authority, 'read-health') and has_skill(authority, 'release-model')
    assert authority['revision'] == revision + 1
    reconciled = [row['event'] for row in rt.events() if row['event']['event_type'] == 'WITHDRAWAL_RECONCILED']
    assert len(reconciled) == 1 and reconciled[0]['status'] == 'TARGET_NOT_CURRENT'
    with rt._db() as db:
        assert db.execute('SELECT COUNT(*) FROM withdrawals').fetchone()[0] == 0


def test_replaced_anchor_does_not_withdraw_the_current_sibling(rt):
    read, original, second = read_pair(rt)
    replacement = rt.grant(read['qualification_id'], action='read', resource=original['resource'],
                           ttl_ms=10000, expected_revision=second['revision'])
    current_ids = {g['resource']: g['grant_id'] for g in grants_for_skill(replacement, 'read-health')}
    assert current_ids[original['resource']] != original['grant_id']
    with rt._tx() as db:
        db.execute('INSERT INTO withdrawals VALUES (?,?,?,?,?,?)',
                   ('agent-a', 'read-health', 'stale-anchor', 'KNOWN_FAILURE', original['grant_id'], original['qualification_id']))
    rt.drain_withdrawals()
    authority = rt.authority()
    assert authority['revision'] == replacement['revision']
    assert {g['resource']: g['grant_id'] for g in grants_for_skill(authority, 'read-health')} == current_ids
    reconciled = [row['event'] for row in rt.events() if row['event']['event_type'] == 'WITHDRAWAL_RECONCILED']
    assert len(reconciled) == 1 and reconciled[0]['target_grant_id'] == original['grant_id']


def test_audit_of_one_qualification_withdraws_every_resource_of_that_skill(rt):
    release, read = ready(rt)
    rt.grant(read['qualification_id'], action='read', resource='urn:dataset/health-extra')
    release_grant = unique_grant(rt.authority(), 'release-model')
    with rt._tx() as db:
        db.execute('DELETE FROM observations WHERE attempt_id=?', (read['outcome_refs'][0]['attempt_id'],))
    result = rt.audit_qualification_evidence(skill='read-health')
    authority = rt.authority()
    assert result['requires_hold'] and result['reason'] == 'EVIDENCE_UNCONFIRMED'
    assert len(result['inspected_grants']) == 2
    assert not has_skill(authority, 'read-health')
    assert unique_grant(authority, 'release-model')['grant_id'] == release_grant['grant_id']


def test_normalize_rejects_duplicate_scope_identity_and_slot(rt):
    read_pair(rt)
    raw = rt.passport.current('agent-a')
    duplicated = copy.deepcopy(raw)
    extra = copy.deepcopy(duplicated['subject']['scope_set'][0])
    extra['scope_id'] = 'scope-duplicate'
    duplicated['subject']['scope_set'].append(extra)
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        rt._normalize(duplicated, 'agent-a')
    same_scope = copy.deepcopy(raw)
    cloned = copy.deepcopy(same_scope['subject']['scope_set'][0])
    binding = json.loads(cloned['context_constraints']['earned_authority_binding_v1'])
    binding['grant_id'] = 'grant-other-slot'
    binding['resource'] = 'urn:dataset/other'
    cloned['resource_pattern'] = binding['resource']
    cloned['context_constraints'] = {'earned_authority_binding_v1': json.dumps(binding, separators=(',', ':'))}
    same_scope['subject']['scope_set'].append(cloned)
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        rt._normalize(same_scope, 'agent-a')


def test_admin_revoke_without_a_target_removes_the_whole_skill(rt):
    ready(rt)
    _, _, current = read_pair(rt)
    revoked = rt.revoke(skill='read-health', reason='operator-request')
    assert not has_skill(revoked, 'read-health') and has_skill(revoked, 'release-model')
    assert revoked['revision'] == current['revision'] + 1


def test_wire_export_lists_every_resource_of_one_skill():
    first = grant_record()
    second = grant_record(resource='urn:dataset/health-extra', grant_id='grant-extra')
    authority = {
        'status': 'ACTIVE', 'passport_id': 'passport-1', 'agent_id': 'agent-a', 'revision': 2,
        'issued_at_ms': 1000000, 'expires_at_ms': 2000000, 'grants': [second, first],
        'signature': 'sig', 'signer': 'authority',
    }
    bundle = WireBundle()
    bundle.add('authority', 'authority', authority=bundle.proof('authority', authority))
    exported = bundle.records[0]['value']['grants']
    assert [grant['resource'] for grant in exported] == ['urn:dataset/health', 'urn:dataset/health-extra']
    assert [grant['grant_id'] for grant in exported] == ['grant-health', 'grant-extra']


def test_legacy_withdrawal_primary_key_keeps_distinct_anchors(rt):
    with rt._tx() as db:
        db.execute('DROP TABLE withdrawals')
        db.execute('CREATE TABLE withdrawals(agent TEXT NOT NULL, skill TEXT NOT NULL, attempt_id TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(agent, skill))')
        db.execute("INSERT INTO withdrawals VALUES ('agent-a','read-health','old-attempt','KNOWN_FAILURE')")
        rt._ensure_withdrawal_queue(db)
        row = db.execute('SELECT target_grant_id, target_qualification_id FROM withdrawals').fetchone()
        db.execute("INSERT INTO withdrawals VALUES ('agent-a','read-health','new-attempt','KNOWN_FAILURE','grant-a','qualification-a')")
        db.execute("INSERT INTO withdrawals VALUES ('agent-a','read-health','other-attempt','KNOWN_FAILURE','grant-b','qualification-a')")
        pending = db.execute('SELECT target_grant_id FROM withdrawals ORDER BY target_grant_id').fetchall()
    assert row == ('', '')
    assert [item[0] for item in pending] == ['', 'grant-a', 'grant-b']


def test_lookup_helpers_reject_ambiguity_and_preserve_replacement_order():
    first = grant_record(resource='urn:dataset/health')
    second = grant_record(resource='urn:dataset/health-extra', grant_id='grant-extra')
    third = grant_record(resource='urn:dataset/status', grant_id='grant-status')
    authority = {'grants': [first, second, third]}
    assert [g['resource'] for g in iter_grants(authority)] == [
        'urn:dataset/health', 'urn:dataset/health-extra', 'urn:dataset/status']
    with pytest.raises(Denied, match='^AMBIGUOUS_GRANT$'):
        unique_grant(authority, 'read-health')
    assert select_grant(authority, skill='read-health', version='skill-v1', context=first['context'],
                        action='read', resource='urn:dataset/health-extra')['grant_id'] == 'grant-extra'
    with pytest.raises(Denied, match='^SCOPE_MISMATCH$'):
        select_grant(authority, skill='read-health', version='skill-v1', context=first['context'],
                     action='read', resource='urn:dataset/missing')
    with pytest.raises(Denied, match='^REVOKED_AUTHORITY$'):
        select_grant({'grants': []}, skill='read-health', version='skill-v1', context=first['context'],
                     action='read', resource='urn:dataset/health')
    replacement = grant_record(resource='urn:dataset/health-extra', grant_id='grant-replaced', expires_at_ms=1800000)
    updated = upsert_grant(authority, replacement)
    assert [g['grant_id'] for g in updated] == ['grant-health', 'grant-status', 'grant-replaced']
    assert authority['grants'][1]['grant_id'] == 'grant-extra'
    duplicate = grant_record(resource='urn:dataset/health', grant_id='grant-copy')
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        select_grant({'grants': [first, duplicate]}, skill='read-health', version='skill-v1',
                     context=first['context'], action='read', resource='urn:dataset/health')
    mismatched = {'grants': {'other-skill': first}}
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        iter_grants(mismatched)
    bad_expiry = grant_record(expires_at_ms=True)
    with pytest.raises(Denied, match='^BINDING_MISMATCH$'):
        iter_grants({'grants': [bad_expiry]})
