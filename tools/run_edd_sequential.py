#!/usr/bin/env python3
"""Execute only the frozen local development sequence."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from evaluations.harness.sequential import run
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--plan',type=Path,default=ROOT/'evaluations/sequential-plan.json')
p.add_argument('--workspace',type=Path,required=True)
p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
r=run(a.plan,a.workspace,a.report)
print(json.dumps(dict(status=r['engineering_acceptance'],counts=r['counts'])))
raise SystemExit(0 if r['engineering_acceptance']=='GREEN' else 1)
