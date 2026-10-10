"""Exercise report acceptance against isolated altered evidence, never originals."""
from pathlib import Path
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('kit_report', ROOT/'tools/report.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = []

def digest(path):
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()

def run_case(name, mutate, expected='AMBER', row='DEP-BUILD'):
    with tempfile.TemporaryDirectory(prefix='report-proof-') as directory:
        target = Path(directory).resolve()/'kit'
        shutil.copytree(ROOT,target,ignore=shutil.ignore_patterns('__pycache__','.pytest_cache'))
        aggregate_path = target/'reports/evidence-reference-combined.json'
        aggregate = json.loads(aggregate_path.read_text())
        child_path = target/aggregate['components']['connected']['report']
        child = json.loads(child_path.read_text())
        mutate(target,aggregate_path,aggregate,child_path,child)
        module.ROOT = target
        with contextlib.redirect_stdout(io.StringIO()):
            module.main()
        data = json.loads((target/'reports/readiness.json').read_text())
        actual = next(r['status'] for r in data['rows'] if r['id']==row)
        assert actual==expected,(name,expected,actual)
        checks.append({'check':name,'expected':expected,'actual':actual,'passed':True})

def save_child(aggregate_path,aggregate,path,data):
    path.write_text(json.dumps(data))
    aggregate['artifacts'][aggregate['components']['connected']['report']] = digest(path)
    aggregate_path.write_text(json.dumps(aggregate))

def change_and_rebind(change):
    def mutate(target,ap,a,cp,c):
        change(c)
        save_child(ap,a,cp,c)
    return mutate

run_case('current_complete_evidence_passes',lambda *args:None,'GREEN')
run_case('missing_child_does_not_pass',lambda t,ap,a,cp,c:cp.unlink())
run_case('changed_child_without_rebound_digest_does_not_pass',lambda t,ap,a,cp,c:cp.write_text(cp.read_text()+' '))
run_case('stale_child_source_does_not_pass',change_and_rebind(lambda c:c['source_hashes'].update({'earned_authority/connected.py':'sha256:'+'0'*64})))
def expire(c):
    c.pop('finished_at_ms',None)
    c['finished_at']='2020-01-01T00:00:00+00:00'
run_case('fresh_aggregate_cannot_refresh_expired_child',change_and_rebind(expire))
run_case('short_all_green_check_set_does_not_pass',change_and_rebind(lambda c:c.update(checks=c['checks'][:-1])))
run_case('duplicate_check_does_not_pass',change_and_rebind(lambda c:c['checks'].__setitem__(-1,copy.deepcopy(c['checks'][0]))))
run_case('wrong_named_check_does_not_pass',change_and_rebind(lambda c:c['checks'][0].update(check='unrelated_green_check')))
def arbitrary_bdd(t,*args):
    p=t/'reports/service-bdd-live-004.json';d=json.loads(p.read_text());d['scenario_acceptance']={f'UNRELATED-{i}':'GREEN' for i in range(37)};p.write_text(json.dumps(d))
run_case('37_arbitrary_green_ids_do_not_complete_BDD',arbitrary_bdd,row='BDD-CORE')
def changed_foundation_log(t,*args):
    report=json.loads((t/'evidence/foundation-policy-only-results.json').read_text())
    path=t/report['checks']['bff-green']['log']
    path.write_text(path.read_text()+' ')
run_case('changed_foundation_log_does_not_pass',changed_foundation_log,row='POL-01')
def missing_foundation_check(t,*args):
    path=t/'evidence/foundation-policy-only-results.json'
    report=json.loads(path.read_text());report['checks'].pop('gateway-race')
    path.write_text(json.dumps(report))
run_case('missing_foundation_race_check_does_not_pass',missing_foundation_check,row='POL-01')
module.ROOT = ROOT
report={'status':'PASS','scope':'READINESS_REPORT_PROVENANCE_NEGATIVE_CONTROLS','checks':checks,
        'finished_at_ms':time.time_ns()//1000000,
        'source_hashes':{name:digest(ROOT/name) for name in ('tools/report.py','tools/verify_report_provenance.py')},
        'artifacts':{name:digest(ROOT/name) for name in ('reports/evidence-reference-combined.json','reports/service-bdd-live-004.json')},
        'limitations':['Isolated altered evidence copies; original execution records unchanged','Does not execute the underlying services']}
(ROOT/'reports/report-provenance-checks.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'PASS','checks':len(checks)}))
