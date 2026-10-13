#!/usr/bin/env python3
"""Execute development EDD pilot; held-out execution is explicitly unavailable."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluations.harness.runner import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, default=ROOT / 'evaluations/pilot-plan.json')
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.plan, args.workspace, args.report)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps({k: result[k] for k in ('execution_state', 'engineering_acceptance', 'overall_value_acceptance', 'counts')}))
    return 0 if result['engineering_acceptance'] == 'GREEN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
