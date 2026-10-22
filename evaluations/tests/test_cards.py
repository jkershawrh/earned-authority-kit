"""G-07 evaluation-card/v1 emitter checks for the EDD harness output path."""
import json
from pathlib import Path

import pytest

from evaluations.harness.cards import (
    card_digest_check, digest_hex, emit_report_card, load_construct, wilson_95,
)
from evaluations.harness.runner import KIT, run


def small_plan(tmp_path):
    plan = json.loads((KIT / 'evaluations/pilot-plan-v2.json').read_text())
    plan['seeds'] = [7]  # all ten strata families are required by validate_manifest
    path = tmp_path / 'plan.json'
    path.write_text(json.dumps(plan, indent=2) + '\n')
    return path


def test_wilson_interval_matches_reference_values():
    # Verified against the standard Wilson score interval (z=1.96).
    assert wilson_95(0, 10) == [0.0, 0.27754]
    assert wilson_95(3, 4) == [0.300636, 0.954414]
    assert wilson_95(5, 5)[1] == 1.0 and wilson_95(0, 1)[0] == 0.0
    with pytest.raises(ValueError):
        wilson_95(0, 0)


def test_construct_sidecar_must_be_substantive(tmp_path):
    good = json.loads((KIT / 'evaluations/constructs/episode-qualification-construct-v1.json').read_text())
    assert load_construct(KIT / 'evaluations/constructs/episode-qualification-construct-v1.json') == good
    for field in ('statement', 'metric', 'gaming_analysis'):
        bad = json.loads(json.dumps(good)); bad[field] = 'too short'
        path = tmp_path / 'bad.json'; path.write_text(json.dumps(bad))
        with pytest.raises(ValueError, match='substantive'):
            load_construct(path)
    wrong = json.loads(json.dumps(good)); wrong['schema_version'] = 'other/v9'
    path = tmp_path / 'wrong.json'; path.write_text(json.dumps(wrong))
    with pytest.raises(ValueError, match='construct-statement'):
        load_construct(path)


def test_completed_run_emits_a_valid_non_authorizing_card(tmp_path):
    plan_path = small_plan(tmp_path)
    report_path = tmp_path / 'report.json'
    report = run(plan_path, tmp_path / 'work', report_path)
    assert report['execution_state'] == 'COMPLETED'
    card_path = tmp_path / 'report.card.json'
    card = json.loads(card_path.read_text())
    assert card['schema_version'] == 'fabric.evaluation-card/v1'
    assert card['mode'] == 'portable-pilot'
    assert card['verdict']['authorizes_execution'] is False
    assert card_digest_check(card)
    assert card['evaluation']['source_id'] == report['plan_digest']
    assert card['evaluation']['split'] == 'development'
    construct = load_construct(KIT / 'evaluations/constructs/episode-qualification-construct-v1.json')
    assert card['construct'] == dict(
        statement=construct['statement'], metric=construct['metric'],
        gaming_analysis=construct['gaming_analysis'],
        construct_sha256=digest_hex({k: construct[k] for k in ('statement', 'metric', 'gaming_analysis')}))
    assert {s['system_id'] for s in card['systems']} == set(report['metrics'])
    for system in card['systems']:
        assert system['evidence_label'] == 'OFFLINE'
        assert system['reliability_claimable'] is False
        assert system['repetition']['trials_per_case'] == 1
        assert system['model_binding']['candidate_kind'] == 'deterministic-controller'
        assert system['performance']['model_calls'] == 0
        assert system['gates']['unauthorized_mutations'] == 'GREEN'
        metrics = report['metrics'][system['system_id']]
        assert system['single_attempt_rate']['passed'] == metrics['task_success']['numerator']
        assert system['single_attempt_rate']['total'] == metrics['task_success']['denominator']
        assert 0.0 <= system['single_attempt_rate']['wilson_95'][0]
        assert system['single_attempt_rate']['wilson_95'][1] <= 1.0
    assert card['holdout_policy']['split'] == 'held_out'
    assert 'authorizes no execution' in card['limits']


def test_edited_card_fails_the_digest_check(tmp_path):
    plan_path = small_plan(tmp_path)
    report_path = tmp_path / 'report.json'
    run(plan_path, tmp_path / 'work', report_path)
    card_path = tmp_path / 'report.card.json'
    card = json.loads(card_path.read_text())
    card['systems'][0]['single_attempt_rate']['value'] = 1.0
    assert card_digest_check(card) is False


def test_aborted_run_emits_no_card(tmp_path, monkeypatch):
    import evaluations.harness.runner as runner
    original = runner.run_episode

    def violated(*args):
        row = original(*args)
        row['grade']['unauthorized_commits'] = 1
        return row

    monkeypatch.setattr(runner, 'run_episode', violated)
    plan_path = small_plan(tmp_path)
    report_path = tmp_path / 'report.json'
    report = run(plan_path, tmp_path / 'work', report_path)
    assert report['execution_state'] == 'ABORTED'
    assert not (tmp_path / 'report.card.json').exists()
    assert emit_report_card(report, report_path, plan_path) is None
