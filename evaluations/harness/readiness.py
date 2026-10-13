"""Expose confirmatory prerequisites; this checker never authorizes execution."""
import math
from .design import audit_partitions


def readiness(design):
    checks = []
    def check(name, passed, detail):
        checks.append(dict(check=name, passed=bool(passed), detail=detail))
    if not isinstance(design, dict) or design.get('version') != 'confirmatory-proposal-1':
        raise ValueError('Recognized confirmatory proposal required')
    primary = design.get('primary_outcome', {})
    check('primary_outcome_selected', primary.get('status') == 'SELECTED' and primary.get('metric') in ('task_success', 'operator_effort', 'latency_cost'),
          'Primary outcome is proposed until selected; pilot success is not value acceptance.')
    thresholds = design.get('thresholds', {})
    numeric = lambda value: type(value) in (int, float) and math.isfinite(value)
    required = ('minimum_completion_improvement', 'maximum_false_acceptance', 'maximum_false_demotion')
    check('explicit_value_and_quality_thresholds', all(numeric(thresholds.get(k)) and 0 <= thresholds[k] <= 1 for k in required)
          and thresholds.get('status') == 'SELECTED', 'Finite fractions and explicitly selected thresholds required; no invented default benefit threshold.')
    families = design.get('families')
    leakage_free = False
    if isinstance(families, list) and families:
        try:
            leakage_free = audit_partitions(families) and {f['split'] for f in families} == {'development', 'calibration', 'held_out'}
        except (ValueError, KeyError, TypeError):
            pass
    check('declared_family_partitions_disjoint', leakage_free,
          'All three partitions and declared ancestry required. Renamed pilot fixtures are not unseen families.')
    check('dataset_content_and_leakage_review', design.get('dataset_review', {}).get('status') == 'REVIEWED'
          and bool(design.get('dataset_review', {}).get('artifact_digest')), 'Declared ancestry alone does not prove independent populations or absence of near duplicates.')
    sample = design.get('sample_plan', {})
    check('sample_size_and_uncertainty_review', type(sample.get('independent_family_count')) is int and sample['independent_family_count'] > 0
          and sample.get('status') == 'REVIEWED' and bool(sample.get('risk_budget')) and bool(sample.get('uncertainty_method')),
          'An explicit reviewed independent-unit design is required; seed count is not sample adequacy.')
    manual = design.get('manual_baseline', {})
    check('actual_human_baseline_plan', manual.get('status') == 'PLANNED_WITH_OPERATOR' and bool(manual.get('operator_id'))
          and bool(manual.get('counterbalancing_plan')), 'Name a real operator and paired task/order plan; no simulated human baseline.')
    schedule = design.get('sequential_schedule', {})
    check('sequential_support_query_design', schedule.get('status') == 'REVIEWED' and bool(schedule.get('phases'))
          and schedule.get('query_grade_leakage_rule') == 'SEAL_BEFORE_NEXT_SUPPORT',
          'One fresh-support query gives general fixed/adaptive identical behavior; learning requires a separately reviewed schedule.')
    check('preregistration_frozen', design.get('preregistration', {}).get('status') == 'FROZEN'
          and bool(design.get('preregistration', {}).get('manifest_digest')),
          'Freeze executable sources, data, policies, budgets and stopping rules before held-out inspection.')
    check('confirmatory_execution_adapter_available', False,
          'The current CLI deliberately rejects held-out/confirmatory execution. A reviewed adapter is not implemented.')
    return dict(status='AMBER', authorizes_execution=False, scope='DECLARED_PREREQUISITE_DIAGNOSTIC_ONLY',
                checks=checks, blockers=[c['check'] for c in checks if not c['passed']],
                limits=['Local declarations are not signed reviewer attestations.', 'This diagnostic does not certify sample adequacy, dataset independence or permission to score.'])
