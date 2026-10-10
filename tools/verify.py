#!/usr/bin/env python3
"""One test run, per-module results and before/after source fingerprints."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import sys
import time
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def snapshot():
    return {str(p.relative_to(ROOT)):'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
        for pattern in ('earned_authority/*.py','tests/*.py','contracts/**/*.json','features/*.feature','requirements-dev.txt','deploy/reference/requirements.lock.txt','tools/verify.py')
        for p in sorted(ROOT.glob(pattern)) if p.is_file()}

class Recorded:
    def __init__(self):
        self.cases={};self.collection_errors=[]
    def pytest_collectreport(self,report):
        if report.failed:self.collection_errors.append(str(report.longrepr))
    def pytest_runtest_logreport(self,report):
        # Setup/teardown failures and skips must override a passing call.
        if report.when=='call' or report.failed or report.skipped:
            outcome='SKIP' if report.skipped else ('FAIL' if report.failed else 'PASS')
            previous=self.cases.get(report.nodeid)
            if previous is None or previous['outcome']=='PASS':
                self.cases[report.nodeid]={'test':report.nodeid,'outcome':outcome}

def main():
    before=snapshot();start=time.time_ns()//1000000
    stream=io.StringIO();recorded=Recorded()
    # pytest collects both unittest classes and pytest parametrized functions.
    with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
        exit_code=int(pytest.main([str(ROOT/'tests'),'-v','-p','no:cacheprovider'],plugins=[recorded]))
    after=snapshot();text=stream.getvalue();modules={}
    cases=list(recorded.cases.values())
    for case in cases:modules.setdefault(Path(case['test'].split('::')[0]).stem,[]).append(case)
    failures=sum(c['outcome']=='FAIL' for c in cases);skipped=sum(c['outcome']=='SKIP' for c in cases)
    report={'scope':'LOCAL_COMPONENT_TESTS_AND_CANONICAL_IN_PROCESS_ADAPTERS','started_at_ms':start,'finished_at_ms':time.time_ns()//1000000,
        'tests_run':len(cases),'failures':failures,'errors':len(recorded.collection_errors),'skipped':skipped,'exit_code':exit_code,
        'source_hashes_before':before,'source_hashes':after,'source_unchanged_during_run':before==after,'cases':cases,
        'modules':{k:{'count':len(v),'status':'PASS' if v and all(c['outcome']=='PASS' for c in v) else 'NOT_PASS'} for k,v in modules.items()},
        'status':'PASS' if exit_code==0 and not failures and not skipped and cases and before==after else 'NOT_PASS',
        'exclusions':['Live-service acceptance runs are separate','No held-out product-value comparison','No OpenShift or physical robot deployment']}
    (ROOT/'reports/kit-tests.log').write_text(text)
    (ROOT/'reports/component-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('tests_run','failures','errors','skipped','status')}))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
