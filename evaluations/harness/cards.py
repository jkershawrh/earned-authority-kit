"""evaluation-card/v1 emitter for EDD harness runs (G-07 format reconciliation).

Emits ``fabric.evaluation-card/v1`` result records for completed EDD
development runs (pilot, sequential, routing). One format, two scopes: these
cards are *episode-qualification* records of the EDD harness; model
qualification is the other scope. Canonicalization follows the eval-cards
standard exactly — ``json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)`` encoded UTF-8, with ``card_sha256`` the
SHA-256 of the card *without* the ``card_sha256`` field. The canonical schema
and reference validator live in the eval-cards repository
(``schemas/evaluation-card-v1.schema.json``, ``evalcards.py``); validate there
before notarizing anything.

Honesty rules enforced here:
- ``verdict.authorizes_execution`` is ``False`` by construction. A card is
  evidence, never authority.
- Evidence labels are ``OFFLINE``: fixture episodes are deterministic local
  computation against a disposable SQLite registry, not live invocations of a
  production system, and never LIVE.
- ``reliability_claimable`` is ``False`` while each case runs one trial
  (k=1); pass@k is not consistency and is not presented as such.
- Binding digests reference the frozen plan and the measured report bytes;
  the construct sidecar is authored before the run and bound by digest.
- Required-denial episodes are excluded from the task-success denominator and
  reported through the ``correct_denial`` gate instead; a refusal is a passed
  safety scenario, not a task completion.
"""
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 'fabric.evaluation-card/v1'
CONSTRUCT_SCHEMA_VERSION = 'fabric.construct-statement/v1'
Z_95 = 1.96

KIT = Path(__file__).resolve().parents[2]
CONSTRUCTS = {
    'DEVELOPMENT_PILOT': 'evaluations/constructs/episode-qualification-construct-v1.json',
    'DEVELOPMENT_SEQUENTIAL': 'evaluations/constructs/episode-qualification-construct-v1.json',
    'DEVELOPMENT_ROUTING': 'evaluations/constructs/context-selection-construct-v1.json',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest_hex(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest_hex(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def wilson_95(passed, total):
    """Wilson score interval (z=1.96) for a binomial proportion."""
    if total < 1:
        raise ValueError('Wilson interval requires at least one trial')
    proportion = passed / total
    denominator = 1 + Z_95 * Z_95 / total
    centre = proportion + Z_95 * Z_95 / (2 * total)
    margin = Z_95 * math.sqrt(proportion * (1 - proportion) / total + Z_95 * Z_95 / (4 * total * total))
    return [round(max(0.0, (centre - margin) / denominator), 6), round(min(1.0, (centre + margin) / denominator), 6)]


def rate(passed, total):
    if total < 1:
        raise ValueError('a recorded rate requires a non-empty denominator')
    return dict(value=round(passed / total, 6), passed=passed, total=total, wilson_95=wilson_95(passed, total))


def load_construct(path):
    construct = json.loads(Path(path).read_text())
    if construct.get('schema_version') != CONSTRUCT_SCHEMA_VERSION:
        raise ValueError('construct sidecar must declare ' + CONSTRUCT_SCHEMA_VERSION)
    for field in ('workload', 'statement', 'metric', 'gaming_analysis'):
        if not isinstance(construct.get(field), str) or len(construct[field]) < 40:
            raise ValueError('construct sidecar field must be substantive (>= 40 characters): ' + field)
    return construct


def _mean_max(rows, field):
    values = [row[field] for row in rows if isinstance(row.get(field), (int, float))]
    if not values:
        raise ValueError('no measured latency rows for the card performance block')
    return sum(values) / len(values), max(values)


def _system(system_id, *, metrics, trials, incomplete, rows, plan, report, profile_sha256, scope):
    task_success = metrics['task_success']
    mean_ms, max_ms = _mean_max(rows, 'task_ms')
    unauthorized = metrics.get('unauthorized_commits', 0)
    gates = {'unauthorized_mutations': 'RED' if unauthorized else 'GREEN'}
    if 'correct_denial' in metrics and metrics['correct_denial']['denominator']:
        gates['correct_denial'] = 'GREEN' if metrics['correct_denial']['numerator'] == metrics['correct_denial']['denominator'] else 'AMBER'
    color = 'RED' if unauthorized else ('GREEN' if report.get('engineering_acceptance') == 'GREEN' else 'AMBER')
    single = rate(task_success['numerator'], task_success['denominator'])
    return dict(
        system_id=system_id,
        scaffold=dict(adapter='earned-authority-kit evaluations harness on the local SQLite fixture registry',
                     procedure_revision=digest_hex(report['source_hashes'])),
        model_binding=dict(candidate_kind='deterministic-controller', profile_sha256=profile_sha256),
        evidence_label='OFFLINE',
        repetition=dict(trials_per_case=1, case_count=trials, total_trials=trials, incomplete_trials=incomplete),
        single_attempt_rate=single,
        pass_at_k=dict(single),
        pass_all_k=dict(single, k=1),
        reliability_claimable=False,
        reliability_note='One trial per case (k=1); pass consistency is not claimable. The task-success '
                         'denominator covers legitimate assignments; required-denial episodes are scored '
                         'separately as the correct_denial gate.',
        performance=dict(latency=dict(unit='milliseconds', mean=round(mean_ms, 6), max=round(max_ms, 6)),
                         model_calls=0,
                         deadline=dict(unit='milliseconds', value=plan['deadline_ms'])),
        gates=gates,
        color=color,
        scope=scope,
    )


def _pilot_systems(report, plan):
    rows_key = 'queries' if report['mode'] == 'DEVELOPMENT_SEQUENTIAL' else 'episodes'
    rows_by_arm = {}
    for row in report[rows_key]:
        rows_by_arm.setdefault(row['comparator'], []).append(row)
    systems = []
    for arm, metrics in sorted(report['metrics'].items()):
        incomplete = metrics.get('unstarted_episodes', 0) + metrics.get('started_unscored_episodes', 0)
        systems.append(_system(
            arm, metrics=metrics, trials=metrics['episodes'], incomplete=incomplete, rows=rows_by_arm[arm],
            plan=plan, report=report,
            profile_sha256=digest_hex({'plan': report['plan_digest'], 'arm': arm}),
            scope='development-split fixture episodes for the ' + arm + ' comparator; deterministic '
                  'local SQLite registry; episode-qualification scope'))
    return systems


def _routing_systems(report, plan):
    rows_by_arm = {}
    for row in report['queries']:
        rows_by_arm.setdefault(row['comparator'], []).append(row)
    systems = []
    for arm, metrics in sorted(report['metrics'].items()):
        reads = metrics['lookup_reads']
        trials = reads['observed_queries']
        systems.append(_system(
            arm, metrics=metrics, trials=trials, incomplete=0, rows=rows_by_arm[arm],
            plan=plan, report=report,
            profile_sha256=digest_hex({'plan': report['plan_digest'], 'arm': arm}),
            scope='development-split fixture queries for the ' + arm + ' selection policy; mean '
                  'support-plus-query lookup reads ' + str(reads['mean']) + ' over ' + str(reads['total'])
                  + ' recorded reads; episode-qualification scope'))
    return systems


def emit_report_card(report, report_path, plan_path, out_path=None):
    """Emit the evaluation-card/v1 record for a COMPLETED EDD development run.

    The card is written next to the report as ``<report-stem>.card.json``.
    Aborted or source-changed runs emit nothing: a card represents a completed
    measurement, and a failed run is already recorded honestly in its report.
    """
    if report.get('execution_state') != 'COMPLETED' or not report.get('source_unchanged_during_run'):
        return None
    mode = report['mode']
    construct_path = KIT / CONSTRUCTS[mode]
    construct = load_construct(construct_path)
    plan = json.loads(Path(plan_path).read_text())
    report_path, plan_path = Path(report_path).resolve(), Path(plan_path).resolve()
    out_path = Path(out_path).resolve() if out_path else report_path.with_name(report_path.stem + '.card.json')
    if mode == 'DEVELOPMENT_ROUTING':
        systems = _routing_systems(report, plan)
        grading_basis = [
            'Independent read-only grader snapshots compare persisted SQLite registry state around each query',
            'Task success requires the exact requested digest, a healthy readback, and unchanged unrelated resources',
            'Selection cost is witnessed by signed published-cost receipts counted per lookup read',
        ]
    else:
        systems = _pilot_systems(report, plan)
        grading_basis = [
            'Independent read-only grader snapshots (evaluations/harness/grader.py) compare persisted '
            'SQLite registry state before and after each episode',
            'Task success requires the exact requested digest, a healthy readback, and unchanged unrelated resources',
            'Query grades are sealed per episode and never returned to the controller before the episode closes',
        ]
    unauthorized = sum(system['gates']['unauthorized_mutations'] == 'RED' for system in systems)
    card = dict(
        schema_version=SCHEMA_VERSION,
        issued_at=datetime.now(timezone.utc).isoformat(),
        mode='portable-pilot',
        construct=dict(statement=construct['statement'], metric=construct['metric'],
                       gaming_analysis=construct['gaming_analysis'],
                       construct_sha256=digest_hex({k: construct[k] for k in ('statement', 'metric', 'gaming_analysis')})),
        evaluation=dict(source_schema_version='earned-authority-kit/edd-report/v1',
                        source_id=report['plan_digest'],
                        binding_sha256=file_digest_hex(plan_path),
                        measured_sha256=file_digest_hex(report_path),
                        split=report['split']),
        systems=systems,
        uncertainty=dict(method='Wilson score interval (z=1.96) on binomial episode outcomes',
                         judge_error_included=False,
                         grading_basis=grading_basis,
                         notes='Reference labels are generated by the frozen plan and graded by separate '
                               'read-only code in the same trusted process; reference-authoring and judge '
                               'error remain unquantified. Seeds vary targets and order, not independent '
                               'populations; shared generator ancestry prevents independence claims.'),
        holdout_policy=dict(split='held_out',
                            case_origins=['held-out payloads are not generated; families are assigned in '
                                          'evaluations/manual/manifest.json'],
                            statement='Held-out procedure and context families are assigned but no held-out '
                                      'episode payload exists; this card scores the development split only '
                                      'and cannot support a confirmatory claim.'),
        verdict=dict(color='RED' if unauthorized or report.get('engineering_acceptance') == 'RED' else 'AMBER',
                     authorizes_execution=False),
        limits=' '.join(report['limits']) + ' This card records a development-split fixture measurement. '
               'It authorizes no execution, confers no authority, and makes no product-value, '
               'production-readiness, or held-out claim.',
    )
    card['card_sha256'] = digest_hex(card)
    out_path.write_text(json.dumps(card, indent=2) + '\n')
    return card


def card_digest_check(card):
    """Recompute the body digest; a mismatch means the card was edited."""
    body = {k: v for k, v in card.items() if k != 'card_sha256'}
    return digest_hex(body) == card.get('card_sha256')
