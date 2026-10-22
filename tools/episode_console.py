#!/usr/bin/env python3
"""Interactive console for one manual evaluation episode.

Reads the public card only. Grade labels stay in a separate file and are not
printed here. Held-out families are rejected.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from earned_authority.runtime import ControlledClock, Denied
from evaluations.manual.console import EpisodeConsole, load_json, open_runtime, prepare_episode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--card', type=Path, required=True)
    parser.add_argument('--prepare', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if args.state.exists():
        raise SystemExit('state already exists')
    card = load_json(args.card)
    preparation = load_json(args.prepare)
    runtime = open_runtime(args.state, clock=ControlledClock(now_ms=1_000_000))
    try:
        policy_allow = prepare_episode(runtime, card, preparation)
        console = EpisodeConsole(runtime, card, policy_allow=policy_allow)
    except Denied as exc:
        raise SystemExit(exc.reason)
    print(json.dumps({'ready': True, 'episode_id': console.card['episode_id']}), flush=True)
    commands = {
        'evidence': console.evidence, 'qualify': console.qualify, 'grant': console.grant,
        'release': console.release, 'read': console.read, 'withdraw': console.withdraw,
        'lookup': console.lookup,
    }
    for line in sys.stdin:
        parts = line.strip().split(maxsplit=1)
        if not parts:
            continue
        name, note = parts[0], parts[1] if len(parts) > 1 else ''
        try:
            if name == 'stop':
                entry = console.stop(note or 'STOP')
            elif name == 'intervene':
                entry = console.intervene(note)
            elif name in commands:
                entry = commands[name]()
            else:
                entry = {'action': name, 'result': {'refused': True, 'reason': 'UNKNOWN_COMMAND'}}
        except Denied as exc:
            entry = {'action': name, 'result': {'refused': True, 'reason': exc.reason}}
        print(json.dumps(entry), flush=True)
        if name == 'stop':
            break
    trace_path = args.state.with_suffix('.trace.json')
    trace_path.write_text(json.dumps(console.trace(), indent=2) + '\n')
    print(json.dumps({'trace': str(trace_path), 'active_ms': console.active_ms()}), flush=True)


if __name__ == '__main__':
    main()
