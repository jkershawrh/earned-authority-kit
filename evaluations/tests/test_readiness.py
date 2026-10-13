import copy
import json
import pytest
from evaluations.harness.readiness import readiness
from evaluations.harness.runner import KIT


def proposal():
    return json.loads((KIT / 'evaluations/confirmatory-design.json').read_text())


def test_draft_names_each_open_prerequisite_without_authorizing_execution():
    result = readiness(proposal())
    assert result['status'] == 'AMBER' and result['authorizes_execution'] is False
    assert len(result['blockers']) == 9


@pytest.mark.parametrize('value', [True, float('nan'), float('inf'), -.1, 1.1, None])
def test_invalid_threshold_cannot_pass(value):
    p = proposal(); p['thresholds'] = dict(status='SELECTED', minimum_completion_improvement=value,
                                          maximum_false_acceptance=.1, maximum_false_demotion=.1)
    result = readiness(p)
    assert 'explicit_value_and_quality_thresholds' in result['blockers']


def test_declared_readiness_cannot_enable_missing_execution_adapter():
    p = proposal()
    p.update(primary_outcome=dict(status='SELECTED', metric='task_success'),
             thresholds=dict(status='SELECTED', minimum_completion_improvement=.1, maximum_false_acceptance=.1, maximum_false_demotion=.1),
             families=[dict(family_id=s, split=s, procedure_ancestors=[s], context_ancestors=[s]) for s in ['development','calibration','held_out']],
             dataset_review=dict(status='REVIEWED',artifact_digest='declared-only'),
             sample_plan=dict(status='REVIEWED',independent_family_count=10,risk_budget='declared-only',uncertainty_method='declared-only'),
             manual_baseline=dict(status='PLANNED_WITH_OPERATOR',operator_id='test-operator',counterbalancing_plan='declared-only'),
             sequential_schedule=dict(status='REVIEWED',phases=['support','query'],query_grade_leakage_rule='SEAL_BEFORE_NEXT_SUPPORT'),
             preregistration=dict(status='FROZEN',manifest_digest='declared-only'))
    result = readiness(p)
    assert result['blockers'] == ['confirmatory_execution_adapter_available']
    assert result['status'] == 'AMBER' and result['authorizes_execution'] is False


def test_copied_pilot_ancestry_prevents_declared_holdout_readiness():
    p = proposal()
    p['families'] = [dict(family_id=s, split=s, procedure_ancestors=['copied'], context_ancestors=[s]) for s in ['development','calibration','held_out']]
    assert 'declared_family_partitions_disjoint' in readiness(p)['blockers']
