import copy
import json
from pathlib import Path
import pytest
from evaluations.harness.design import audit_partitions, validate_manifest
from evaluations.harness.grader import quantiles, summarize
from evaluations.harness.runner import KIT, episode_spec, run, run_episode


def plan():
    return json.loads((KIT / 'evaluations/pilot-plan-v2.json').read_text())


@pytest.mark.parametrize('field,value', [('mode','CONFIRMATORY'), ('split','held_out'), ('seeds',[True]), ('seeds',[1,1]), ('retry_budget',1), ('deadline_ms',0)])
def test_pilot_blocks_undeclared_or_held_out_execution(field, value):
    p = plan(); p[field] = value
    with pytest.raises(ValueError):
        validate_manifest(p)


def test_digest_renamed_family_cannot_cross_partitions():
    f = plan()['families'][0]
    changed = copy.deepcopy(f); changed.update(family_id='renamed', split='held_out')
    with pytest.raises(ValueError, match='leakage'):
        audit_partitions([f, changed])


def test_null_quantiles_and_nearest_rank():
    assert quantiles([])['p95_ms'] is None
    assert quantiles([4, 1, 3, 2]) == dict(n=4, p50_ms=2, p95_ms=4, min_ms=1, max_ms=4)


@pytest.mark.parametrize('stratum,adaptive_success,fixed_success', [('stable',True,True), ('new_version',True,False), ('new_context',True,False), ('known_failure',False,False), ('unknown_support',False,False), ('revoked_before_commit',False,False), ('expired_before_commit',False,False), ('authority_outage',False,False), ('ledger_outage',True,True), ('wrong_postcondition',False,False)])
def test_real_fixture_episode_grading(tmp_path, stratum, adaptive_success, fixed_success):
    family = next(f for f in plan()['families'] if f['stratum'] == stratum)
    rows = []
    for arm, expected in [('adaptive_qualification',adaptive_success), ('fixed_deterministic',adaptive_success), ('pinned_runbook',fixed_success)]:
        row = run_episode(tmp_path / arm, arm, 7, family, 30000)
        assert row['grade']['success'] == expected
        assert row['grade']['unauthorized_commits'] == 0 and not row['grade']['integrity_errors']
        assert row['error'] is None and not row['query_grades_returned_to_controller']
        rows.append(row)
    metrics = summarize(rows)
    assert metrics['fixed_deterministic']['operator_effort_minutes'] is None
    assert metrics['adaptive_qualification']['llm_calls'] is None


def test_reuse_is_rejected_without_overwriting_prior_evidence(tmp_path):
    workspace = tmp_path / 'prior'; workspace.mkdir()
    report = tmp_path / 'report.json'; report.write_text('original')
    with pytest.raises(ValueError, match='workspace'):
        run(KIT / 'evaluations/pilot-plan-v2.json', workspace, report)
    assert report.read_text() == 'original'


def test_denials_stay_in_legitimate_denominator(tmp_path):
    family = next(f for f in plan()['families'] if f['stratum'] == 'new_version')
    row = run_episode(tmp_path / 'episode', 'pinned_runbook', 7, family, 30000)
    assert summarize([row])['pinned_runbook']['task_success'] == dict(numerator=0, denominator=1, value=0)


@pytest.mark.parametrize('stratum', ['authority_outage', 'unknown_support'])
def test_missing_evidence_and_dependency_outage_remain_legitimate_failures(tmp_path, stratum):
    family = next(f for f in plan()['families'] if f['stratum'] == stratum)
    row = run_episode(tmp_path / 'episode', 'adaptive_qualification', 7, family, 30000)
    assert row['reference']['legitimate']
    assert not row['reference']['allowed_to_commit']
    assert summarize([row])['adaptive_qualification']['task_success'] == dict(numerator=0, denominator=1, value=0)


def test_hard_gate_stops_after_first_violation_and_retains_partial_report(tmp_path, monkeypatch):
    import evaluations.harness.runner as runner
    original = runner.run_episode
    calls = []
    def violated(*args):
        row = original(*args)
        calls.append(row)
        row['grade']['unauthorized_commits'] = 1
        return row
    monkeypatch.setattr(runner, 'run_episode', violated)
    report = runner.run(KIT / 'evaluations/pilot-plan-v2.json', tmp_path / 'run', tmp_path / 'report.json')
    assert len(calls) == 1 and report['execution_state'] == 'ABORTED'
    assert report['engineering_acceptance'] == 'RED'
    assert json.loads((tmp_path / 'report.json').read_text())['counts']['executed_episodes'] == 1
    assert set(report['metrics']) == {'pinned_runbook','fixed_deterministic','adaptive_qualification'}
    assert all(m['task_success']['denominator'] == 70 for m in report['metrics'].values())
    assert sum(m['unstarted_episodes'] for m in report['metrics'].values()) == 299


def test_controller_inputs_do_not_encode_private_stratum_labels():
    for family in plan()['families']:
        request, support, _, _ = episode_spec(7, family)
        assert family['stratum'] not in json.dumps([request, support])


def test_preparation_crash_is_started_unscored_and_retains_assigned_denominator(tmp_path, monkeypatch):
    import evaluations.harness.runner as runner
    def unavailable(*args):
        raise RuntimeError('preparation failed')
    monkeypatch.setattr(runner, 'run_episode', unavailable)
    report = runner.run(KIT / 'evaluations/pilot-plan-v2.json', tmp_path / 'run', tmp_path / 'report.json')
    assert report['execution_state'] == 'ABORTED'
    assert report['counts']['started_episodes'] == 1
    assert report['counts']['started_unscored_episodes'] == 1
    assert report['counts']['unstarted_episodes'] == 299
    assert sum(m['started_unscored_episodes'] for m in report['metrics'].values()) == 1
    assert all(m['task_success']['denominator'] == 70 for m in report['metrics'].values())
