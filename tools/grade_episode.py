#!/usr/bin/env python3
"""Grade one prepared episode from independent registry readback.

This reads the label file the operator console does not print. It does not
open a held-out family and it does not record a manual baseline.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from earned_authority.runtime import Denied
from evaluations.manual.console import grade_episode, load_json, open_runtime


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--card', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = grade_episode(open_runtime(args.state), load_json(args.card), load_json(args.labels))
    except Denied as exc:
        raise SystemExit(exc.reason)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
