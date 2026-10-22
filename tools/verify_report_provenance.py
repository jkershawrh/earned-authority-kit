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
        aggregate_path = target/'reports/reconcile-reference-combined.json'
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
    p=t/'reports/service-bdd-live-014.json';d=json.loads(p.read_text());d['scenario_acceptance']={f'UNRELATED-{i}':'GREEN' for i in range(37)};p.write_text(json.dumps(d))
run_case('37_arbitrary_green_ids_do_not_complete_BDD',arbitrary_bdd,row='BDD-CORE')
def changed_foundation_log(t,*args):
    report=json.loads((t/'evidence/foundation-demo-window-results.json').read_text())
    path=t/report['checks']['bff-green']['log']
    path.write_text(path.read_text()+' ')
run_case('changed_foundation_log_does_not_pass',changed_foundation_log,row='POL-01')
def missing_foundation_check(t,*args):
    path=t/'evidence/foundation-demo-window-results.json'
    report=json.loads(path.read_text());report['checks'].pop('gateway-race')
    path.write_text(json.dumps(report))
run_case('missing_foundation_race_check_does_not_pass',missing_foundation_check,row='POL-01')
run_case('complete_development_pilot_passes',lambda *args:None,'GREEN',row='EDD-PILOT')
def incomplete_pilot(t,*args):
    p=t/'reports/edd-pilot-008.json';d=json.loads(p.read_text());d['episodes'].pop();p.write_text(json.dumps(d))
run_case('partial_pilot_does_not_pass',incomplete_pilot,row='EDD-PILOT')
def changed_grader(t,*args):
    p=t/'evaluations/harness/grader.py';p.write_text(p.read_text()+'\n')
run_case('changed_pilot_grader_does_not_pass',changed_grader,row='EDD-PILOT')
run_case('complete_sequential_development_passes',lambda *args:None,'GREEN',row='EDD-SEQUENTIAL')
def partial_sequence(t,*args):
    p=t/'reports/edd-sequential-004.json';d=json.loads(p.read_text());d['queries'].pop();p.write_text(json.dumps(d))
run_case('partial_sequence_does_not_pass',partial_sequence,row='EDD-SEQUENTIAL')
def changed_sequence(t,*args):
    p=t/'evaluations/harness/sequential.py';p.write_text(p.read_text()+'\n')
run_case('changed_sequence_source_does_not_pass',changed_sequence,row='EDD-SEQUENTIAL')
def false_recovery(t,*args):
    p=t/'reports/edd-sequential-004.json';d=json.loads(p.read_text())
    next(q for q in d['queries'] if q['phase_index']==4)['qualification_disposition']='ELIGIBLE'
    p.write_text(json.dumps(d))
run_case('false_recovery_does_not_pass',false_recovery,row='EDD-SEQUENTIAL')
def deleted_retained_failure(t,*args):
    p=t/'reports/edd-sequential-004.json';d=json.loads(p.read_text())
    q=next(q for q in d['queries'] if q['phase_index']==6)
    q['observations_after']=[o for o in q['observations_after'] if o['outcome']!='FAIL']
    p.write_text(json.dumps(d))
run_case('deleted_retained_failure_does_not_pass',deleted_retained_failure,row='EDD-SEQUENTIAL')
def preparation_write(t,*args):
    p=t/'reports/edd-sequential-004.json';d=json.loads(p.read_text())
    d['queries'][0]['preparation_after']['registry']['unrelated/sentinel']['version']='altered'
    p.write_text(json.dumps(d))
run_case('preparation_write_does_not_pass',preparation_write,row='EDD-SEQUENTIAL')
def typed_retained_alias(t,*args):
    p=t/'reports/edd-sequential-004.json';d=json.loads(p.read_text())
    q=next(q for q in d['queries'] if q['phase_index']==6)
    o=next(o for o in q['observations_after'] if o['outcome']=='FAIL');o['observed_at_ms']=float(o['observed_at_ms'])
    p.write_text(json.dumps(d))
run_case('typed_retained_alias_does_not_pass',typed_retained_alias,row='EDD-SEQUENTIAL')
def pilot_preparation_write(t,*args):
    p=t/'reports/edd-pilot-008.json';d=json.loads(p.read_text())
    d['episodes'][0]['preparation_after']['registry']['unrelated/sentinel']['version']='altered'
    p.write_text(json.dumps(d))
run_case('pilot_preparation_write_does_not_pass',pilot_preparation_write,row='EDD-PILOT')
run_case('complete_routing_development_passes',lambda *args:None,'GREEN',row='EDD-ROUTING')
def routing_change(change):
    def mutate(t,*args):
        p=t/'reports/edd-routing-003.json';d=json.loads(p.read_text());change(d);p.write_text(json.dumps(d))
    return mutate
run_case('partial_routing_does_not_pass',routing_change(lambda d:d['queries'].pop()),row='EDD-ROUTING')
run_case('false_routing_metrics_do_not_pass',routing_change(lambda d:d['metrics']['pooled_outcome']['lookup_reads'].update(total=0)),row='EDD-ROUTING')
run_case('altered_routing_choice_does_not_pass',routing_change(lambda d:d['queries'][0].update(choice='unregistered')),row='EDD-ROUTING')
run_case('altered_routing_receipt_does_not_pass',routing_change(lambda d:d['queries'][0]['published_cost'].update(signature='AAAA')),row='EDD-ROUTING')
def changed_lookup(t,*args):
    p=t/'evaluations/harness/lookup.py';p.write_text(p.read_text()+'\n')
run_case('changed_lookup_source_does_not_pass',changed_lookup,row='EDD-ROUTING')
module.ROOT = ROOT
report={'status':'PASS','scope':'READINESS_REPORT_PROVENANCE_NEGATIVE_CONTROLS','checks':checks,
        'finished_at_ms':time.time_ns()//1000000,
        'source_hashes':{name:digest(ROOT/name) for name in ('tools/report.py','tools/verify_report_provenance.py')},
        'artifacts':{name:digest(ROOT/name) for name in ('reports/reconcile-reference-combined.json','reports/service-bdd-live-014.json','reports/edd-routing-003.json')},
        'limitations':['Isolated altered evidence copies; original execution records unchanged','Does not execute the underlying services']}
(ROOT/'reports/report-provenance-checks.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'PASS','checks':len(checks)}))
