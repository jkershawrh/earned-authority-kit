#!/usr/bin/env python3
"""Record the dedicated EDD harness tests independently of the 514-test baseline."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluations.harness.runner import source_hashes


class Recorder:
    def __init__(self):
        self.cases = {}; self.errors = []
    def pytest_collectreport(self, report):
        if report.failed:
            self.errors.append(str(report.longrepr))
    def pytest_runtest_logreport(self, report):
        if report.when == 'call' or report.failed or report.skipped:
            outcome = 'SKIP' if report.skipped else 'FAIL' if report.failed else 'PASS'
            prior = self.cases.get(report.nodeid)
            if prior is None or prior['outcome'] == 'PASS':
                self.cases[report.nodeid] = dict(test=report.nodeid, outcome=outcome)


def main():
    before = source_hashes(); start = time.time_ns() // 1000000
    stream, recorder = io.StringIO(), Recorder()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        code = int(pytest.main([str(ROOT / 'evaluations/tests'), '-v', '-p', 'no:cacheprovider'], plugins=[recorder]))
    after = source_hashes()
    log = ROOT / 'evidence/edd-harness-green.log'; log.write_text(stream.getvalue())
    cases = list(recorder.cases.values())
    sha = lambda p: 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()
    report = dict(status='PASS' if code == 0 and cases and all(c['outcome'] == 'PASS' for c in cases) and before == after and not recorder.errors else 'NOT_PASS',
                  scope='EDD_HARNESS_AND_LOCAL_SQLITE_FIXTURE_COMPONENTS', tests_run=len(cases), cases=cases,
                  exit_code=code, collection_errors=recorder.errors, started_at_ms=start, finished_at_ms=time.time_ns() // 1000000,
                  source_hashes_before=before, source_hashes=after, source_unchanged_during_run=before == after,
                  artifacts={str(p.relative_to(ROOT)): sha(p) for p in (log, ROOT/'evidence/edd-grader-red.log', Path(__file__))},
                  limits=['Dedicated harness tests, separate from the unchanged 514-test baseline.', 'Fixture-backed grading and controls; no held-out product-value acceptance.'])
    (ROOT / 'evidence/edd-harness-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], tests_run=len(cases))))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
