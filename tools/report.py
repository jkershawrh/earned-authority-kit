#!/usr/bin/env python3
"""Render existing, scoped acceptance evidence; does not run tests or services."""
from datetime import datetime
import hashlib
import html
import json
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from earned_authority.rubric import assess, release_status


def digest(path):
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    try:
        return json.loads((ROOT / relative).read_text())
    except (OSError, ValueError):
        return {}


def current(data):
    hashes = data.get('source_hashes', {})
    if data.get('source_hashes_before', hashes) != hashes:
        return False
    if data.get('source_unchanged_during_run') is False:
        return False
    for relative, expected in hashes.items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or digest(path) != expected:
            return False
    for relative, expected in data.get('artifacts', {}).items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or digest(path) != expected:
            return False
    return True


def recorded_time(data, path):
    for key in ('finished_at_ms', 'generated_at_ms', 'executed_at_ms'):
        if type(data.get(key)) is int:
            return data[key]
    for key in ('finished_at', 'completed_at', 'executed_at_utc', 'generated_at'):
        if data.get(key):
            return int(datetime.fromisoformat(data[key]).timestamp() * 1000)
    return int(path.stat().st_mtime * 1000)


def main():
    now = time.time_ns() // 1000000
    inputs = sorted({p for pattern in ('earned_authority/*.py', 'tests/*.py', 'contracts/**/*.json', 'tools/*.py', 'deploy/**/*', 'patches/*.patch', 'requirements-dev.txt') for p in ROOT.glob(pattern) if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'})
    manifest = {str(p.relative_to(ROOT)): digest(p) for p in inputs}
    revision = 'sha256:' + hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    (ROOT / 'reports/source-manifest.json').write_text(json.dumps({'revision': revision, 'files': manifest}, indent=2) + '\n')
    component = read('reports/component-verification.json')
    pins = read('deploy/reference/sources.json')
    patches_current = all((ROOT / p['path']).is_file() and digest(ROOT / p['path']) == 'sha256:' + p['sha256'] for s in pins.get('sources', []) for p in s.get('patches', [])) and bool(pins.get('sources'))
    combined = read('reports/clean-reference-combined.json')
    pins_current = 'sha256:' + combined.get('source_manifest_sha256', '') == digest(ROOT / 'deploy/reference/sources.json') and patches_current
    rows, records = [], []

    def add(key, lane, name, method, environment, acceptance, artifact=None, outcome=None, valid=True, baseline='AMBER', milestone=None, release=True, detail=None):
        data = read(artifact) if artifact else {}
        target = revision
        req = dict(id=key, target_revision=target, environment=environment, required_methods=[method], max_age_ms=7*86400000)
        if artifact and (ROOT / artifact).is_file():
            # Missing/stale provenance becomes UNKNOWN, never a newly invented failure.
            value = outcome if valid and current(data) else 'UNKNOWN'
            records.append(dict(requirement_id=key, revision=target, environment=environment, method=method, outcome=value or 'UNKNOWN', timestamp_ms=recorded_time(data, ROOT / artifact), executed=True, artifact=artifact, artifact_digest=digest(ROOT / artifact)))
        result = assess(req, records, now, ROOT)
        rows.append(dict(req, **{k:v for k,v in result.items() if k!='requirement_id'}, lane=lane, component=name, acceptance=acceptance, baseline=baseline, release_required=release, milestone=milestone, implementation=detail or ('Recorded execution' if artifact else 'Acceptance outstanding'), artifact=artifact))

    def module(key, lane, name, method, modules, acceptance, milestone=None):
        found = [component.get('modules', {}).get(m, {}) for m in modules]
        count = sum(m.get('count', 0) for m in found)
        cases = [c for c in component.get('cases', []) if Path(c['test'].split('::')[0]).stem in modules]
        failures = any(c.get('outcome') in ('FAIL','ERROR') for c in cases)
        passed = all(m.get('status')=='PASS' and m.get('count', 0)>0 for m in found) and all(c.get('outcome')=='PASS' for c in cases)
        valid = bool(component.get('source_hashes')) and len(cases)==count and count>0
        add(key,lane,name,method,'LOCAL_COMPONENT',acceptance,'reports/component-verification.json', 'FAIL' if failures else ('PASS' if passed else 'UNKNOWN'),valid=valid,milestone=milestone,detail=f'{count} tests; exact named modules only')

    module('CON-01','WP0','Draft schemas and producer/consumer proofs','CDD',['test_contracts','test_wire_contracts'],'Actual fixture records, signed proof binding and historical qualification lookup. Draft contract; wider service adoption is separate.','M1')
    module('KIT-01','WP0','Evidence color evaluator','TDD',['test_rubric'],'Stale, missing, altered, unexecuted or wrong-environment evidence cannot satisfy a gate.','M1')
    module('BDD-LOCAL','WP5','Local earned-authority lifecycle','BDD',['test_lifecycle_bdd'],'BDD-001–037 have fixture bindings; counts include additional cases and the coverage check.','M1')
    module('EXEC-LOCAL','WP3','Durable registry and observation recovery','TDD',['test_runtime_security'],'Mutation intent, retry attribution, authenticated outbox and immutable qualification history in local SQLite.','M1')
    module('QUAL-01','WP2','Canonical Cascade and deterministic GCL','TDD',['test_qualification_client'],'Real canonical modules; demo-three-pass policy. GCL checks declared capacity and does not establish outcome truth.','M2')
    module('AUTH-CLIENT','WP1','Canonical authority and policy bindings','TDD',['test_passport_client','test_connected_binding','test_connected_security'],'Signed canonical bytes, cross-skill isolation, post-policy expiry, exact requested scopes and withdrawal reconciliation.','M2')
    module('LED-01','WP4','Canonical Ledger adapter','TDD',['test_ledger_client'],'Content/signature binding, idempotency, unavailable/stale/untrusted versus positively mismatched evidence.','M2')

    for key,lane,name,path,checknames,scope in [
        ('AUTH-01','WP1','Passport service and race regressions','evidence/canonical-passport-results.json',['green','race'],'49 normal and 49 race-detector leaf cases; overlapping cases, not 98 unique tests.'),
        ('POL-01','WP1','Foundation binding and real Rego engine','evidence/foundation-policy-binding-results.json',['green','race','rego'],'81 normal and 81 race leaf cases plus 3 actual OPA engine tests; overlapping cases.')]:
        data=read(path); checks=[data.get('checks',{}).get(n,{}) for n in checknames]
        passed=all(c.get('passed',0)>0 and c.get('failed',1)==0 for c in checks)
        add(key,lane,name,'TDD','CANONICAL_COMPONENT',scope,path,'PASS' if passed else 'UNKNOWN',valid=patches_current,baseline='RED',milestone='M2')

    live_specs=[
        ('POL-LIVE','WP1','Policy administration and binding','policy','CDD','8 live checks: expected policy digest and denied administrative mutations.','M2'),
        ('SVC-LIVE','WP1','Canonical service interfaces','services','CDD','7 live checks against Foundation, Passport, OPA and Ledger.','M2'),
        ('ARC-LIVE','WP5','Connected earned-authority arc','connected','BDD','23 live checks: qualify, grant, mutate, independent readback, selective withdrawal, refusal, requalification and exported proof consumption.','M2'),
        ('FAULT-LIVE','WP5','Connected fault and race checks','adversarial','BDD','17 live checks including process crash recovery, authority race, expiry, cross-skill binding, missing readback and ledger outage.','M2'),
        ('DEP-RESTORE','WP6','Persistent full-stack stop and restore','restore','BDD','6 checks preserve prior identity, authority revision/scopes, registry mutations and ledger receipts. Same host; no disk-loss claim.','M3')]
    for key,lane,name,part,method,scope,milestone in live_specs:
        path=f'reports/clean-reference-combined-{part}.json'; data=read(path); checks=data.get('checks',[])
        failed=any(c.get('passed') is False for c in checks)
        passed=checks and all(c.get('passed') is True for c in checks) and data.get('acceptance_color')=='GREEN' and data.get('execution_state')=='COMPLETED'
        add(key,lane,name,method,'REAL_LOCAL_SERVICES',scope,path,'FAIL' if failed else ('PASS' if passed else 'UNKNOWN'),valid=pins_current,milestone=milestone,detail=f'{len(checks)} executed checks')
    add('DEP-BUILD','WP6','Fresh source reconstruction and one-command validation','BDD','FRESH_SAME_HOST','Five pinned upstream repositories, explicit patches, distinct keys/state/volumes and 61 combined checks.','reports/clean-reference-combined.json','PASS' if combined.get('command_exit_code')==0 and combined.get('acceptance_color')=='GREEN' else 'UNKNOWN',valid=pins_current,milestone='M3')
    pending=[
        ('BDD-CORE','WP5','All 37 behaviors on real service adapters','BDD','SERVICE_ACCEPTANCE','Fixture coverage and the connected checks are separate; complete scenario-by-scenario real coverage is not asserted.'),
        ('AUDIT-ATOMIC','WP4','Authority change and lifecycle event crash recovery','BDD','CROSS_SERVICE_RECOVERY','Source review identifies a crash window after Passport change and before local GRANTED/REVOKED recording. Durable authority-operation intents and crash injection remain follow-on work.'),
        ('EDD-PLAN','WP5','Preregistered evaluation thresholds and risk budget','EDD','HELD_OUT_EVALUATION','Choose value target, sample adequacy, fixed versions, family-disjoint holdout and actual human baseline before scoring.'),
        ('EDD-RUN','WP5','Measured business value and uncertainty','EDD','HELD_OUT_EVALUATION','Protocol is unexecuted. Engineering acceptance does not establish reduced effort, cost or improved completion.'),
        ('DEP-EXTERNAL','WP6','Independent operator / another host','BDD','INDEPENDENT_REPRODUCTION','Clean same-host reconstruction passed; a second person or different host has not reproduced the run.'),
        ('DEP-RH','Later','Red Hat reference profile','BDD','OPENSHIFT','Select deployment target and validate identity, policy, persistence and mutation fencing; no compatibility/support claim.'),
        ('ROB-01','Later','Robotics simulation transfer','EDD','SIMULATION','Deferred BDD-038: separately governed simulator and safety/controller boundaries before any hardware consideration.')]
    for key,lane,name,method,environment,scope in pending:
        add(key,lane,name,method,environment,scope,release=key not in ('DEP-RH','ROB-01'))
    redpath='evidence/canonical-passport-results.json'; red=read(redpath).get('checks',{}).get('red',{})
    add('BASE-01','History','Original canonical authority defects','TDD','HISTORICAL_BASELINE','16 retained failing baseline leaf cases; patched target checked separately.',redpath,'FAIL' if red.get('failed',0)>0 else 'UNKNOWN',release=False,baseline='RED',detail='Historical red regression, not current target')
    required=[dict(requirement_id=r['id'],status=r['status']) for r in rows if r['release_required']]
    overall=release_status(required,[r['id'] for r in rows if r['release_required']])
    milestones=[]
    for key,title,scope in [('M1','Executable local fixture','Fixture behaviors, schemas and durable local evidence.'),('M2','Connected canonical services','Pinned local stack and specifically executed lifecycle/fault cases.'),('M3','Deployable local reference kit','Fresh same-host reconstruction and full persistent restart.')]:
        subset=[r for r in rows if r['milestone']==key]
        milestones.append(dict(id=key,title=title,status=release_status([dict(requirement_id=r['id'],status=r['status']) for r in subset],[r['id'] for r in subset]),scope=scope,requirements=[r['id'] for r in subset]))
    out={'generated_at_ms':now,'kit_revision':revision,'overall_integration_readiness':overall,'milestones':milestones,'kit_tests':{k:component.get(k) for k in ('tests_run','failures','errors','skipped','status')},'CUT':'Unconfirmed; component named explicitly','EDD':'evaluation-driven development','rows':rows,'evidence':records,'scope':'Local artifact-backed engineering acceptance; full G0–G4 and product readiness remain separate. Report inputs are local records, not an externally signed attestation.','record_time_rule':'Embedded completion time where available, otherwise artifact mtime. Re-rendering does not rerun acceptance.'}
    (ROOT/'reports/readiness.json').write_text(json.dumps(out,indent=2)+'\n')
    render(out)
    print(json.dumps({'component_tests':component.get('tests_run'),'milestones':{m['id']:m['status'] for m in milestones},'full_roadmap':overall,'report':'roadmap.html'}))
    return 0


def render(data):
    h=html.escape
    tr=[]
    for row in data['rows']:
        proof=f'<a href="{h(row["artifact"])}">Raw run</a>' if row['artifact'] else 'Not executed'
        tr.append(f'''<tr data-status="{row['status']}" data-lane="{h(row['lane'])}"><td><strong>{h(row['id'])}</strong><small>{h(row['lane'])}</small></td><td>{h(row['component'])}<small>{h(row['implementation'])}</small></td><td>{h(' / '.join(row['required_methods']))}</td><td><span class="badge {row['baseline'].lower()}">{row['baseline']}</span></td><td><span class="badge {row['status'].lower()}">{row['status']}</span><small>{h(row['environment'])}</small></td><td>{h(row['acceptance'])}</td><td>{proof}</td></tr>''')
    source='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Earned Authority | Parallel roadmap</title><style>
:root{color-scheme:light dark;--bg:#f7f8fa;--fg:#182333;--muted:#526174;--border:#d6dee8;--panel:#fff;--accent:#135bb0;--green:#126b45;--amber:#885300;--red:#a22424}*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}main{max-width:1320px;margin:auto;padding:38px 30px 60px}h1{font-size:30px;margin:8px 0 10px;line-height:1.2}h2{font-size:20px;margin-top:30px}p{max-width:900px}a{color:var(--accent)}.eyebrow{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}.lead{font-size:18px;max-width:850px}.top{display:flex;justify-content:space-between;align-items:start;gap:24px}.summary{padding:18px;background:var(--panel);border:1px solid var(--border);min-width:225px}.summary strong{display:block;font-size:23px}.summary span,small{display:block;color:var(--muted);font-size:12px}.badge{display:inline-block;font-weight:650;font-size:11px;letter-spacing:.03em;border:1px solid currentColor;padding:2px 7px;border-radius:3px}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}.phases{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.phase{border-top:3px solid var(--border);padding:12px 0}.phase b{display:block;margin-bottom:5px}.phase p{font-size:13px;color:var(--muted);margin:0}.controls{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}label{font-size:13px}select{font:inherit;margin-left:6px;padding:5px;border:1px solid var(--border);background:var(--panel);color:var(--fg)}.table-wrap{overflow:auto;border:1px solid var(--border);background:var(--panel)}table{border-collapse:collapse;width:100%;min-width:980px;text-align:left;font-size:13px}th{background:var(--bg);font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.025em}th,td{padding:13px 12px;vertical-align:top;border-bottom:1px solid var(--border)}td:nth-child(1){min-width:100px}td:nth-child(2){min-width:180px}td:nth-child(6){min-width:290px}tr[hidden]{display:none}.methods{display:grid;grid-template-columns:repeat(4,1fr);gap:22px}.methods p{font-size:13px;color:var(--muted)}.links{display:flex;gap:18px;flex-wrap:wrap;margin-top:22px}.note{font-size:13px;color:var(--muted)}footer{overflow-wrap:anywhere;margin-top:26px;padding-top:16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}@media(prefers-color-scheme:dark){:root{--bg:#14191f;--fg:#e0e6ee;--muted:#a4b0c0;--border:#354151;--panel:#1c232c;--accent:#8dbfff;--green:#83d1a6;--amber:#ebc071;--red:#ff9c9c}}@media(max-width:760px){main{padding:24px 16px}.top{display:block}.summary{margin-top:20px}.phases{grid-template-columns:1fr 1fr}.methods{grid-template-columns:1fr 1fr}h1{font-size:26px}}
</style></head><body><main><div class="eyebrow">Validated local reference · Contract draft 0.1.0-draft.1</div><div class="top"><div><h1>Earned authority, proven one gate at a time</h1><p class="lead">Qualify a deterministic procedure. Grant bounded permission. Enforce it at mutation. Verify the outcome. Withdraw and requalify.</p></div><aside class="summary"><span>Full roadmap acceptance</span><strong class="__OVERALL_CLASS__">__OVERALL__</strong><span>Local milestones are shown separately below</span></aside></div><p class="note">Green is scoped to the exact component, revision and environment. Historical red regressions remain visible. A fixture pass does not pass an integration, product evaluation or deployment gate.</p>
<div class="links"><a href="docs/ROADMAP.md">Full roadmap and handoffs</a><a href="evaluations/README.md">EDD protocol</a><a href="features/README.md">38 BDD specifications</a><a href="deploy/reference/README.md">Reproduce the deployment</a><a href="docs/BOUNDARIES.md">Scope and remaining gaps</a><a href="reports/readiness.json">Machine-readable matrix</a></div>
<h2>Three bounded engineering milestones</h2><div class="methods">__MILESTONES__</div><p class="note">Same host and a disposable model registry. A passing milestone covers its named checks. It does not pass every broader G0–G4 acceptance criterion.</p><h2>Broader dependency gates</h2><div class="phases"><div class="phase"><b>G0 · Shared contract</b><p>Agree producer/consumer fixtures, ownership, bindings and signed fields.</p></div><div class="phase"><b>G1 · Parallel components</b><p>Authority · Qualification · Fenced execution · Durable evidence</p></div><div class="phase"><b>G2 · Connected lifecycle</b><p>Execute the whole arc and preserve an unaffected second skill.</p></div><div class="phase"><b>G3 · Evaluation</b><p>Held-out comparisons, uncertainty, failure injection and stopping rules.</p></div><div class="phase"><b>G4 · Repeatable deployment</b><p>Fresh setup, recovery, then a tested Red Hat reference profile.</p></div></div>
<h2>Development methods</h2><div class="methods"><div><b>TDD · Test-driven</b><p>Capture a failing behavior, make the smallest correction, retain the regression.</p></div><div><b>EDD · Evaluation-driven</b><p>Freeze metrics, baselines and held-out cases before measuring benefit.</p></div><div><b>CDD · Contract-driven</b><p>Shared schemas and producer/consumer compatibility, including rejection cases.</p></div><div><b>BDD · Behavior-driven</b><p>Given/When/Then scenarios must execute against observable state changes.</p></div></div><p class="note">Evidence supports all four. CUT terminology remains unconfirmed. The business-value evaluation is still unrun: choose the target, human baseline and sample adequacy before scoring.</p>
<h2>Rubric matrix</h2><div class="controls"><label>Acceptance <select id="status"><option value="ALL">All statuses</option><option>RED</option><option>AMBER</option><option>GREEN</option></select></label><label>Work package <select id="lane"><option value="ALL">All packages</option><option>WP0</option><option>WP1</option><option>WP2</option><option>WP3</option><option>WP4</option><option>WP5</option><option>WP6</option><option>History</option><option>Later</option></select></label><span id="visible" aria-live="polite" class="note"></span></div><div class="table-wrap"><table><thead><tr><th>Requirement</th><th>Component under test</th><th>Methods</th><th>Baseline</th><th>Current scope</th><th>Acceptance gate</th><th>Evidence</th></tr></thead><tbody>__ROWS__</tbody></table></div><footer>__COUNT__ component tests in the recorded run, including pytest and unittest cases. Live pipeline: 61 checks (8 policy, 7 interfaces, 23 lifecycle, 17 fault/race, 6 restore); these are not 61 independent trials or 61 BDD scenarios. Full real-service coverage of all 37 BDD scenarios and held-out value EDD remain amber. Original tracked Foundation and Passport sources were preserved.<br>Kit revision: __REVISION__</footer></main><script>
const statusFilter=document.getElementById('status'),laneFilter=document.getElementById('lane');function filter(){let n=0;document.querySelectorAll('tbody tr').forEach(row=>{const show=(statusFilter.value==='ALL'||row.dataset.status===statusFilter.value)&&(laneFilter.value==='ALL'||row.dataset.lane===laneFilter.value);row.hidden=!show;if(show)n++;});document.getElementById('visible').textContent=n+' requirements shown';}statusFilter.addEventListener('change',filter);laneFilter.addEventListener('change',filter);filter();
</script></body></html>'''
    milestones=''.join(f'<div><b>{h(m["id"])} · {h(m["title"])}</b><p><span class="badge {m["status"].lower()}">{m["status"]}</span></p><p>{h(m["scope"])}</p></div>' for m in data['milestones'])
    source=source.replace('__MILESTONES__',milestones).replace('__OVERALL__',data['overall_integration_readiness']).replace('__OVERALL_CLASS__',data['overall_integration_readiness'].lower())
    source=source.replace('__ROWS__',''.join(tr)).replace('__COUNT__',str(data['kit_tests'].get('tests_run'))).replace('__REVISION__',h(data['kit_revision']))
    (ROOT/'roadmap.html').write_text(source)


if __name__=='__main__':
    raise SystemExit(main())
