"""Reproducible development-only pilot on the existing real SQLite fixture."""
import hashlib
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from earned_authority.runtime import ControlledClock, Denied, Runtime
from .controller import prepare
from .design import validate_manifest
from .grader import grade, snapshot, summarize, registry_unchanged
from .cards import emit_report_card

KIT = Path(__file__).resolve().parents[2]


def digest(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    patterns = ('earned_authority/*.py', 'evaluations/harness/*.py',
                'evaluations/tests/*.py', 'evaluations/protocol.json',
                'evaluations/pilot-plan-v2.json', 'tools/run_edd_pilot.py',
                'evaluations/confirmatory-design.json', 'tools/check_edd_readiness.py',
                'evaluations/sequential-plan.json', 'tools/run_edd_sequential.py',
                'evaluations/constructs/*.json')
    return {str(p.relative_to(KIT)): digest(p) for pattern in patterns for p in sorted(KIT.glob(pattern))}


def episode_spec(seed, family):
    stratum, fid = family['stratum'], family['family_id']
    prefix = hashlib.sha256((fid + '-' + str(seed)).encode()).hexdigest()[:24]
    base_context = hashlib.sha256((fid + '-base').encode()).hexdigest()[:24]
    request = dict(agent='pilot-agent', skill='release-model', version='skill-v1', context=base_context,
                   action='release', resource='registry/' + prefix, target='model-' + str(seed), attempt_id=prefix + '-query')
    if stratum == 'new_version':
        request['version'] = 'skill-v2'
    if stratum == 'new_context':
        request['context'] = hashlib.sha256((fid + '-drifted').encode()).hexdigest()[:24]
    support = []
    bindings = [('skill-v1', base_context)]
    if (request['version'], request['context']) not in bindings:
        bindings.append((request['version'], request['context']))
    for version, context in bindings:
        for i in range(3):
            support.append(dict(skill=request['skill'], version=version, context=context,
                                attempt_id=f'{prefix}-support-{version}-{context}-{i}',
                                expected=request['target'], actual='wrong' if stratum == 'known_failure' else request['target'],
                                observer_available=stratum != 'unknown_support'))
    reference = dict(legitimate=stratum not in ('known_failure', 'revoked_before_commit', 'expired_before_commit'),
                     allowed_to_commit=stratum not in ('known_failure', 'unknown_support', 'revoked_before_commit', 'expired_before_commit', 'authority_outage'),
                     candidate_label='INELIGIBLE' if stratum == 'known_failure' else 'UNKNOWN' if stratum == 'unknown_support' else 'ELIGIBLE',
                     resource=request['resource'], target=request['target'], attempt_id=request['attempt_id'], request=dict(request))
    return request, support, reference, base_context


def run_episode(workspace, comparator, seed, family, deadline_ms):
    workspace.mkdir(parents=True, exist_ok=False)
    path = workspace / 'registry.sqlite'
    rt = Runtime(path, ControlledClock())
    request, support, reference, base_context = episode_spec(seed, family)
    # An unrelated durable sentinel makes side-effect grading concrete.
    with rt._tx() as db:
        db.execute("INSERT INTO registry VALUES ('unrelated/sentinel','keep-v1',1,'setup')")
    public_key = rt.keys['authority'].public_key()
    preparation_before = snapshot(path, request['agent'], public_key)
    preparation_start = time.perf_counter_ns()
    prepared = prepare(rt, comparator, request, support, 'skill-v1', base_context)
    preparation_ms = (time.perf_counter_ns() - preparation_start) / 1e6
    initial = snapshot(path, request['agent'], public_key)
    if not registry_unchanged(preparation_before,initial):
        raise RuntimeError('Unauthorized registry mutation during support preparation')
    stratum = family['stratum']
    if stratum == 'authority_outage':
        rt.authority_available = False
    if stratum == 'ledger_outage':
        rt.ledger.available = False
    command, returned, denial, error = None, {}, None, None
    decision_ms, revocation_ms = None, None
    before = initial
    started = time.perf_counter_ns()
    admission_start = time.perf_counter_ns()
    try:
        try:
            command = rt.admit(**request)
        finally:
            decision_ms = (time.perf_counter_ns() - admission_start) / 1e6
        if stratum == 'revoked_before_commit':
            revoke_start = time.perf_counter_ns()
            rt.revoke(agent=request['agent'], skill=request['skill'], reason='PILOT_ADMINISTRATIVE_WITHDRAWAL')
            revocation_ms = (time.perf_counter_ns() - revoke_start) / 1e6
        if stratum == 'expired_before_commit':
            rt.clock.advance(300000)
        admitted = snapshot(path, request['agent'], public_key)
        if not registry_unchanged(initial,admitted):
            raise RuntimeError('Unauthorized registry mutation during admission')
        before = admitted
        returned = rt.commit(command, actual='wrong-model' if stratum == 'wrong_postcondition' else None)
    except Denied as exc:
        denial = exc.reason
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    # Capture the grant state at commit, not post-outcome demotion state.
    after = snapshot(path, request['agent'], public_key)
    task_ms = (time.perf_counter_ns() - started) / 1e6
    scored = grade(reference, before, after, command, {**returned, 'denial_reason': denial, 'error': error}, rt.clock.now_ms)
    outcome = scored['controller_outcome']
    terminal = 'ERROR' if error else 'DENIED' if denial else outcome or 'UNCONFIRMED'
    timed_out = task_ms > deadline_ms
    return dict(comparator=comparator, seed=seed, family_id=family['family_id'], stratum=stratum,
                split='development', environment='LOCAL_FIXTURE_SQLITE', reference=reference,
                request=request, support=support, preparation_ms=preparation_ms,
                qualification_disposition=prepared['requested_disposition'], prepared_qualification=prepared['qualification'],
                terminal_state=terminal, denial_reason=denial, error=error, timed_out=timed_out,
                decision_ms=decision_ms, task_ms=task_ms, revocation_ack_ms=revocation_ms,
                logical_commit_time_ms=rt.clock.now_ms, grade=scored,
                withdrew_skill=bool(initial['authority'].get('grants')) and request['skill'] not in after['authority'].get('grants', {}),
                before_commit=before, after_query=after,
                preparation_before=preparation_before, preparation_after=initial,
                sealed_at_utc=datetime.now(timezone.utc).isoformat(), query_grades_returned_to_controller=False,
                ledger_available_at_query=rt.ledger.available)


def run(plan_path, workspace, report_path):
    plan_path, workspace, report_path = Path(plan_path).resolve(), Path(workspace).resolve(), Path(report_path).resolve()
    plan = validate_manifest(json.loads(plan_path.read_text()))
    if workspace.exists():
        raise ValueError('Fresh absent workspace required; prior episodes cannot be reused')
    if report_path.exists():
        raise ValueError('Fresh report path required; prior evidence cannot be overwritten')
    workspace.mkdir(parents=True)
    before = source_hashes()
    (workspace / 'frozen-input.json').write_text(json.dumps(dict(plan=plan, plan_digest=digest(plan_path), source_hashes=before), indent=2) + '\n')
    start = datetime.now(timezone.utc).isoformat()
    rows, order, assignments = [], [], []
    for seed in plan['seeds']:
        rng = random.Random(seed)
        for family in plan['families']:
            arms = list(plan['comparators']); rng.shuffle(arms)
            for arm in arms:
                assignments.append(dict(comparator=arm, seed=seed, family_id=family['family_id'], stratum=family['stratum'], started=False,
                                        reference=episode_spec(seed, family)[2]))
    expected = len(plan['seeds']) * len(plan['families']) * len(plan['comparators'])
    report = dict(mode='DEVELOPMENT_PILOT', split='development', environment='LOCAL_FIXTURE_SQLITE',
                  plan_digest=digest(plan_path), source_hashes_before=before, started_at_utc=start,
                  expected_episodes=expected, assignments=assignments, episodes=rows, execution_order=order,
                  manual_baseline=dict(status='NOT_EXECUTED', reason='Requires an actual human operator; no script is labelled manual'),
                  held_out=dict(status='NOT_EXECUTED', episodes=0),
                  overall_value_acceptance='AMBER', confirmatory_acceptance='AMBER',
                  limits=['Development cases only; no held-out or preregistered value claim.',
                          'General fixed and adaptive use identical exact qualification on fresh support; this one-query design cannot establish accumulated-learning value.',
                          'Pinned runbook is a legacy diagnostic third arm, not the primary fixed baseline.',
                          'Support preparation is reported separately and excluded from query latency; not end-to-end deployment latency.',
                          'Seeds vary nominal targets and order, not independent populations; shared generator/procedure ancestry prevents statistical independence claims.',
                          'Separate read-only grading code in the same trusted process; not a separate security principal or operator.',
                          'One query per episode, no query-grade feedback or sequential requalification comparison.',
                          'Logical expiry uses a controlled clock; measured latency uses the host monotonic clock.',
                          'Human effort, monetary cost and instrumented LLM accounting are absent, not zero.',
                          'No universal safety, canonical-service performance, OpenShift, or robotics acceptance.'])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        for seed in plan['seeds']:
            rng = random.Random(seed)
            for family in plan['families']:
                arms = list(plan['comparators'])
                rng.shuffle(arms)
                for arm in arms:
                    identifier = f"{seed}-{family['stratum']}-{arm}"
                    order.append(identifier)
                    assignment = next(a for a in assignments if a['comparator']==arm and a['seed']==seed and a['family_id']==family['family_id'])
                    assignment['started'] = True
                    row = run_episode(workspace / identifier, arm, seed, family, plan['deadline_ms'])
                    rows.append(row)
                    report_path.write_text(json.dumps(report, indent=2) + '\n')
                    if row['grade']['unauthorized_commits'] or row['grade']['integrity_errors']:
                        raise RuntimeError('Hard invariant failed; further mutation episodes stopped')
                    if row['error']:
                        raise RuntimeError('Critical episode error; pilot incomplete')
        report['execution_state'] = 'COMPLETED'
        report['engineering_acceptance'] = 'GREEN'
    except Exception as exc:
        report.update(execution_state='ABORTED', engineering_acceptance='RED', error=type(exc).__name__ + ': ' + str(exc))
    report['source_hashes'] = source_hashes()
    report['source_unchanged_during_run'] = before == report['source_hashes'] and digest(plan_path) == report['plan_digest']
    if not report['source_unchanged_during_run']:
        report.update(engineering_acceptance='RED', execution_state='ABORTED', error='Source or plan changed during run')
    report['counts'] = dict(executed_episodes=len(rows), scored_episodes=len(rows), started_episodes=len(order),
                          expected_episodes=expected, started_unscored_episodes=len(order)-len(rows), unstarted_episodes=expected-len(order),
                          shared_procedure_ancestries=len({a for f in plan['families'] for a in f['procedure_ancestors']}),
                          shared_context_ancestries=len({a for f in plan['families'] for a in f['context_ancestors']}))
    report['metrics'] = summarize(rows, assignments)
    report['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    # G-07: every completed run emits its evaluation-card/v1 record next to the
    # report (<report-stem>.card.json). The report file is final before the
    # card binds its bytes; the report itself stays free of card self-reference.
    emit_report_card(report, report_path, plan_path)
    return report
