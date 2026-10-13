"""Signed multi-target journal tests using real SQLite and local writer keys.

The stateful Passport adapter is an explicit UNIT transport seam. These tests
prove journal metadata/recovery, not canonical authorization or eligibility.
"""
import copy
import json

import pytest

from earned_authority.authority_journal import AuthorityJournal
from earned_authority.connected import ConnectedRuntime
from earned_authority.contracts import canonical_digest
from earned_authority.grants import grants_for_skill
from earned_authority.passport_client import issue_operation_request, revoke_operation_request
from earned_authority.runtime import Runtime, Denied, encoded
from test_authority_journal import OperationPassport


class JournalRuntime(AuthorityJournal, Runtime):
    _normalize = ConnectedRuntime._normalize

    def __init__(self, path, passport):
        super().__init__(path)
        self.passport = passport
        self._init_authority_journal()


def grant(identifier, skill, resource):
    context = {'model_version': 'model-v2'}
    return {'grant_id': identifier, 'skill': skill, 'version': 'unit-v1', 'context': context,
            'skill_digest': canonical_digest({'skill': skill, 'version': 'unit-v1'}),
            'context_digest': canonical_digest({'environment': context}),
            'qualification_id': 'qualification-' + identifier,
            'qualification_digest': canonical_digest({'unit_qualification': identifier}),
            'policy_digest': canonical_digest({'unit_policy': 1}),
            'action': 'release' if skill == 'release-model' else 'read',
            'resource': resource, 'expires_at_ms': 1300000}


def scopes(grants):
    return [{'action_class': 'model.promote_to_production' if g['action'] == 'release' else 'demo.read',
             'resource_pattern': g['resource'], 'scope_ttl_seconds': 300,
             'context_constraints': {'earned_authority_binding_v1': encoded(g).decode()}}
            for g in grants]


@pytest.fixture
def prepared(tmp_path):
    passport = OperationPassport()
    rt = JournalRuntime(tmp_path / 'journal.sqlite', passport)
    targets = [grant('release-a', 'release-model', 'model/a'),
               grant('release-b', 'release-model', 'model/b')]
    retained = grant('read-a', 'read-health', 'urn:dataset/health')
    passport.issue('agent-a', scopes(targets + [retained]), 300, passport.current('agent-a'), 'unit seed', operation_id='unit-seed')
    prior = passport.current('agent-a')
    targets = list(grants_for_skill(rt._normalize(prior, 'agent-a'), 'release-model'))
    request = issue_operation_request('agent-a', scopes([retained]), 300, prior, 'KNOWN_FAILURE', 'remove-multiple')
    arguments = dict(operation_id='remove-multiple', agent='agent-a', kind='REVOKE', request=request,
                     prior_authority=prior, invocation={'kind': 'REVOKE', 'attempt_id': 'failed-attempt'},
                     skill='release-model', reason='KNOWN_FAILURE',
                     target_grant_id=targets[0]['grant_id'], target_qualification_id=targets[0]['qualification_id'])
    return rt, passport, targets, retained, arguments


def removed_events(runtime):
    return [row['event'] for row in runtime.events() if row['event']['event_type'] == 'REVOKED']


def test_exact_full_targets_are_signed_and_isolated_from_caller_mutation(prepared):
    rt, _, targets, _, args = prepared
    expected = copy.deepcopy(targets)
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    targets[0]['context']['model_version'] = 'changed-after-persistence'
    targets.reverse()
    stored = rt.authority_operations()[0]
    assert operation['removed_targets'] == stored['removed_targets'] == expected
    assert rt._verified(stored, {'writer'})
    assert stored['journal_version'] == 1


def test_lost_reply_restart_preserves_complete_targets_and_one_event(prepared):
    rt, passport, targets, retained, args = prepared
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    passport.lose_response = True
    with pytest.raises(Denied):
        rt._recover_authority_operation(operation)
    assert removed_events(rt) == []
    revision = passport.state['revision']
    passport.lose_response = False
    restarted = JournalRuntime(rt.path, passport)
    restarted.recover_authority_intents()
    restarted.recover_authority_intents()
    event, = removed_events(restarted)
    assert event['removed_targets'] == targets
    assert event['authority_intent']['removed_targets'] == targets
    assert event['target_grant_id'] == targets[0]['grant_id']
    assert event['operation_receipt']['request'] == args['request']
    assert restarted.authority_operations()[0]['removed_targets'] == targets
    assert passport.state['revision'] == revision
    assert len(passport.state['subject']['scope_set']) == 1
    assert json.loads(passport.state['subject']['scope_set'][0]['context_constraints']['earned_authority_binding_v1']) == retained
    restarted._verify_local_events()


@pytest.mark.parametrize('edit', ['remove_field', 'remove_target', 'change_context', 'change_id', 'add_target', 'reorder'])
def test_persisted_target_metadata_cannot_be_rebound_even_by_state_transition(prepared, edit):
    rt, _, targets, _, args = prepared
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    changed = copy.deepcopy(operation)
    if edit == 'remove_field':
        del changed['removed_targets']
    elif edit == 'remove_target':
        changed['removed_targets'].pop()
    elif edit == 'change_context':
        changed['removed_targets'][0]['context']['model_version'] = 'different'
    elif edit == 'change_id':
        changed['removed_targets'][0]['grant_id'] = 'another-grant'
    elif edit == 'add_target':
        changed['removed_targets'].append(grant('invented', 'release-model', 'model/c'))
    else:
        changed['removed_targets'].reverse()
    changed['state'] = 'DISPATCHED'
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        with rt._tx() as db:
            rt._store_authority_operation(db, changed)
    assert rt.authority_operations()[0] == operation


def test_unsigned_stored_target_tamper_blocks_recovery(prepared):
    rt, passport, targets, _, args = prepared
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    with rt._tx() as db:
        altered = copy.deepcopy(operation)
        altered['removed_targets'][1]['resource'] = 'model/invented'
        db.execute('UPDATE authority_operations SET record=?', (json.dumps(altered),))
    with pytest.raises(Denied, match='AUTHORITY_INTENT_UNAUTHENTICATED'):
        rt.recover_authority_intents()
    assert passport.state['revision'] == args['prior_authority']['revision']
    assert removed_events(rt) == []


def test_historical_operation_without_targets_stays_without_targets(prepared):
    rt, passport, _, _, args = prepared
    old = rt._new_authority_operation(**args)
    assert 'removed_targets' not in old
    restarted = JournalRuntime(rt.path, passport)
    restarted.recover_authority_intents()
    event, = removed_events(restarted)
    assert 'removed_targets' not in restarted.authority_operations()[0]
    assert 'removed_targets' not in event
    assert 'removed_targets' not in event['authority_intent']
    restarted._verify_local_events()


def test_existing_legacy_record_cannot_be_enriched_with_invented_targets(prepared):
    rt, _, targets, _, args = prepared
    old = rt._new_authority_operation(**args)
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        with rt._tx() as db:
            rt._store_authority_operation(db, {**old, 'removed_targets': targets})


@pytest.mark.parametrize('case', ['not_list', 'empty', 'duplicate_id', 'missing_id', 'missing_full_field', 'wrong_skill', 'missing_anchor', 'wrong_anchor_qualification', 'grant_operation'])
def test_invalid_target_description_never_persists_an_intent(prepared, case):
    rt, _, targets, _, args = prepared
    targets = copy.deepcopy(targets)
    if case == 'not_list': targets = {'targets': targets}
    elif case == 'empty': targets = []
    elif case == 'duplicate_id': targets[1]['grant_id'] = targets[0]['grant_id']
    elif case == 'missing_id': del targets[0]['grant_id']
    elif case == 'missing_full_field': del targets[1]['resource']
    elif case == 'wrong_skill': targets[1]['skill'] = 'unrelated-skill'
    elif case == 'missing_anchor': args['target_grant_id'] = 'missing'
    elif case == 'wrong_anchor_qualification': args['target_qualification_id'] = 'other-qualification'
    else: args['kind'] = 'GRANT'
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        rt._new_authority_operation(**args, removed_targets=targets)
    assert rt.authority_operations() == []


@pytest.mark.parametrize('case', ['missing_sibling', 'invented_sibling', 'changed_resource',
                                'changed_scope_id', 'missing_scope_id', 'changed_expiry',
                                'changed_qualification', 'extra_field', 'wrong_prior_revision',
                                'wrong_prior_passport'])
def test_targets_must_exactly_describe_the_complete_prior_skill(prepared, case):
    rt, passport, targets, _, args = prepared
    targets = copy.deepcopy(targets)
    if case == 'missing_sibling': targets.pop()
    elif case == 'invented_sibling': targets.append(grant('invented', 'release-model', 'model/invented'))
    elif case == 'changed_resource': targets[1]['resource'] = 'model/invented'
    elif case == 'changed_scope_id': targets[1]['canonical_scope_id'] = 'scope-invented'
    elif case == 'missing_scope_id': del targets[1]['canonical_scope_id']
    elif case == 'changed_expiry': targets[1]['expires_at_ms'] += 1
    elif case == 'changed_qualification': targets[1]['qualification_id'] = 'other-qualification'
    elif case == 'extra_field': targets[1]['invented'] = 'signed-but-untrue'
    elif case == 'wrong_prior_revision': args['request']['expected_agent_revision'] += 1
    else: args['request']['expected_active_passport_id'] = 'other-passport'
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        rt._new_authority_operation(**args, removed_targets=targets)
    assert rt.authority_operations() == []
    assert passport.issues == 1


@pytest.mark.parametrize('case', ['retained_target', 'missing_live_survivor', 'invented_survivor',
                                'changed_survivor', 'extended_survivor', 'changed_outer_action',
                                'changed_outer_resource', 'extra_constraints', 'duplicate_survivor',
                                'revoke_with_live_survivor'])
def test_resulting_scope_set_must_remove_targets_and_preserve_other_live_grants(prepared, case):
    rt, passport, targets, retained, args = prepared
    request = args['request']
    requested = request['issue']['requested_scopes']
    if case == 'retained_target':
        requested += scopes([{k: v for k, v in targets[0].items() if k != 'canonical_scope_id'}])
    elif case == 'missing_live_survivor': requested.clear()
    elif case == 'invented_survivor': requested += scopes([grant('invented', 'read-health', 'urn:other')])
    elif case in ('changed_survivor', 'extended_survivor'):
        changed = copy.deepcopy(retained)
        if case == 'changed_survivor': changed['qualification_id'] = 'another-qualification'
        else: changed['expires_at_ms'] += 1
        requested[0] = scopes([changed])[0]
    elif case == 'changed_outer_action': requested[0]['action_class'] = 'model.promote_to_production'
    elif case == 'changed_outer_resource': requested[0]['resource_pattern'] = 'urn:other'
    elif case == 'extra_constraints': requested[0]['context_constraints']['ignored'] = 'not-ignored'
    elif case == 'duplicate_survivor': requested.append(copy.deepcopy(requested[0]))
    else: args['request'] = revoke_operation_request(args['prior_authority'], 'KNOWN_FAILURE', 'remove-multiple')
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        rt._new_authority_operation(**args, removed_targets=targets)
    assert rt.authority_operations() == []
    assert passport.issues == 1


def test_complete_target_set_may_start_in_any_order_but_signed_order_is_preserved(prepared):
    rt, _, targets, _, args = prepared
    targets.reverse()
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    assert operation['removed_targets'] == targets


def test_revoke_can_drop_expired_unrelated_grant(prepared):
    rt, passport, targets, _, args = prepared
    # The unrelated grant was valid in the prior aggregate but is already over;
    # a removal may drop it without asserting that it belonged to this skill.
    rt.clock.advance(300000)
    args['request'] = revoke_operation_request(args['prior_authority'], 'KNOWN_FAILURE', 'remove-multiple')
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    rt._recover_authority_operation(operation)
    assert passport.state['subject'] is None
    assert removed_events(rt)[0]['removed_targets'] == targets


def longer_survivor(prepared):
    """A 600-second prior survivor makes a valid 300-second ISSUE too short."""
    rt, passport, targets, retained, args = prepared
    retained['expires_at_ms'] = 1600000
    prior = args['prior_authority']
    prior['subject']['expires_ts'] = retained['expires_at_ms']
    survivor = prior['subject']['scope_set'][-1]
    survivor['expires_ts'] = retained['expires_at_ms']
    survivor['context_constraints']['earned_authority_binding_v1'] = encoded(retained).decode()
    passport.state = copy.deepcopy(prior)
    requested = scopes([retained])
    requested[0]['scope_ttl_seconds'] = 600
    args['request'] = issue_operation_request('agent-a', requested, 600, prior, 'KNOWN_FAILURE', 'remove-multiple')
    return rt, passport, targets, retained, args


@pytest.mark.parametrize('case', ['scope_ttl', 'passport_ttl', 'zero_scope_fallback'])
def test_containing_lifetimes_cannot_shorten_survivor_absolute_expiry(prepared, case):
    rt, passport, targets, _, args = longer_survivor(prepared)
    issue = args['request']['issue']
    if case == 'scope_ttl': issue['requested_scopes'][0]['scope_ttl_seconds'] = 1
    else:
        issue['ttl_seconds'] = 300  # Valid canonical minimum, but too short here.
        if case == 'zero_scope_fallback': issue['requested_scopes'][0]['scope_ttl_seconds'] = 0
    with pytest.raises(Denied, match='AUTHORITY_INTENT_BINDING_MISMATCH'):
        rt._new_authority_operation(**args, removed_targets=targets)
    assert rt.authority_operations() == []
    assert passport.issues == 1
    assert removed_events(rt) == []


@pytest.mark.parametrize('scope_ttl', [0, 600, 601])
def test_zero_fallback_and_scope_cap_accept_a_sufficient_passport_ttl(prepared, scope_ttl):
    rt, _, targets, _, args = longer_survivor(prepared)
    args['request']['issue']['requested_scopes'][0]['scope_ttl_seconds'] = scope_ttl
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    assert operation['state'] == 'PREPARED'
    assert operation['request']['issue']['requested_scopes'][0]['scope_ttl_seconds'] == scope_ttl


def test_ceil_safe_replacement_preserves_exact_expiry_at_fractional_second(prepared):
    rt, passport, targets, retained, args = longer_survivor(prepared)
    rt.clock.advance(875)
    passport.now = lambda: rt.clock.now_ms
    remaining = retained['expires_at_ms'] - rt.clock.now_ms
    assert remaining == 599125
    args['request']['issue']['requested_scopes'][0]['scope_ttl_seconds'] = (remaining + 999) // 1000
    operation = rt._new_authority_operation(**args, removed_targets=targets)
    rt._recover_authority_operation(operation)
    actual = rt._normalize(passport.current('agent-a'), 'agent-a')['grants']
    assert len(actual) == 1
    assert actual[0]['expires_at_ms'] == retained['expires_at_ms']
    assert {k: v for k, v in actual[0].items() if k != 'canonical_scope_id'} == retained
