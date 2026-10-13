#!/usr/bin/env python3
"""Inspect confirmatory prerequisites without executing held-out cases."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluations.harness.readiness import readiness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--design', type=Path, default=ROOT / 'evaluations/confirmatory-design.json')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('Fresh report path required')
    raw = args.design.read_bytes()
    report = readiness(json.loads(raw))
    report['design_sha256'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
    report['source_hashes'] = {str(p.relative_to(ROOT)): 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in [ROOT/'evaluations/harness/readiness.py', ROOT/'evaluations/harness/design.py', Path(__file__)]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], blockers=report['blockers'], authorizes_execution=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
