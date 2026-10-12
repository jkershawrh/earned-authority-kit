#!/usr/bin/env python3
"""Record the local receipt-compaction proof. This is not a live service run."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from deploy.reference.evidence import bind_sources, source_hashes
from test_receipt_retention import run_proof


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    before = source_hashes()
    started = datetime.now(timezone.utc).isoformat()
    report = {'environment': 'LOCAL_COMPONENT', 'started_at': started, 'checks': [],
              'scope': 'Compaction removes disposable archive rows and refuses a receipt cited by an applied journal operation or a local event. Cited receipt growth stays unbounded. This is a unit proof, not Passport state compaction or disk recovery.',
              'limits': ['Cited receipts are retained without a size bound', 'Not a live Passport or Ledger compaction', 'Not protection against a hostile administrator']}
    try:
        proof = run_proof()
        checks = [
            ('cited_drop_refused', proof['refused'] and proof['refusal_kept_archive']),
            ('disposable_rows_compacted', proof['disposable_removed'] and len(proof['removed']) == 4),
            ('applied_journal_receipt_still_verifies', proof['journal_receipt_unchanged'] and proof['cited_retained']),
            ('local_event_receipt_still_verifies', proof['event_receipt_unchanged']),
        ]
        for name, passed in checks:
            report['checks'].append({'check': name, 'passed': bool(passed)})
            if not passed:
                raise AssertionError(name)
        report.update(execution_state='COMPLETED', acceptance_color='GREEN', receipt_digest=proof['receipt_digest'])
    except Exception as exc:
        report.update(execution_state='ABORTED', acceptance_color='RED', error=type(exc).__name__ + ': ' + str(exc))
    bind_sources(report, before)
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(args.report), 'status': report['acceptance_color'], 'checks': len(report['checks'])}))
    return 0 if report.get('execution_state') == 'COMPLETED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
