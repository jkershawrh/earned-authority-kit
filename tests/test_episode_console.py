"""Development-split checks for the manual episode console.

These walk the fixture console. They are not a timed human baseline and they
do not open a held-out family.
"""
import json
import tempfile
import unittest
from pathlib import Path

from earned_authority.runtime import ControlledClock, Denied
from evaluations.manual.console import EpisodeConsole, check_family, grade_episode, load_json, open_runtime, prepare_episode

ROOT = Path(__file__).resolve().parents[1]
CARDS = ROOT / 'evaluations' / 'manual' / 'episodes'


class EpisodeConsoleTests(unittest.TestCase):
    def open(self, stem):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        card = load_json(CARDS / f'{stem}.card.json')
        preparation = load_json(CARDS / f'{stem}.prepare.json')
        labels = load_json(CARDS / f'{stem}.labels.json')
        runtime = open_runtime(Path(tmp.name) / 'episode.sqlite', clock=ControlledClock(now_ms=1_000_000))
        self.addCleanup(runtime.close)
        policy_allow = prepare_episode(runtime, card, preparation)
        console = EpisodeConsole(runtime, card, policy_allow=policy_allow, mono=self.clock())
        return runtime, card, labels, console

    def clock(self):
        ticks = {'now': 0.0}

        def mono():
            ticks['now'] += 1.0
            return ticks['now']

        return mono

    def test_eligible_release_sets_only_the_requested_alias(self):
        runtime, card, labels, console = self.open('development-eligible')
        console.evidence()
        self.assertEqual(console.qualify()['result']['disposition'], 'ELIGIBLE')
        self.assertEqual(console.grant()['result']['status'], 'ACTIVE')
        self.assertEqual(console.release()['result']['state'], 'COMMITTED')
        reading = console.read()['result']
        self.assertEqual(reading['alias']['version'], 'model-v2')
        self.assertEqual(reading['others']['registry-a/model-b']['version'], 'model-b1')
        graded = grade_episode(runtime, card, labels)
        self.assertFalse(graded['unauthorized'])
        self.assertTrue(graded['completed'])
        self.assertEqual(graded['mutation_count'], 1)
        self.assertNotIn('PERMITTED_RELEASE', json.dumps(console.trace()))

    def test_known_failure_withdraws_and_leaves_the_alias(self):
        runtime, card, labels, console = self.open('development-known-failure')
        self.assertEqual(console.qualify()['result']['reason'], 'KNOWN_FAILURE')
        self.assertTrue(console.grant()['result']['refused'])
        console.withdraw()
        self.assertEqual(console.release()['result']['reason'], 'REVOKED_AUTHORITY')
        graded = grade_episode(runtime, card, labels)
        self.assertFalse(graded['unauthorized'])
        self.assertFalse(graded['completed'])
        self.assertTrue(graded['denial_correct'])
        self.assertEqual(graded['alias'], 'model-v1')
        self.assertEqual(graded['mutation_count'], 0)

    def test_procedure_claims_do_not_qualify(self):
        runtime, card, labels, console = self.open('development-insufficient')
        shown = console.evidence()['result']
        self.assertEqual(len(shown['procedure_reports']), 3)
        self.assertEqual(console.qualify()['result']['reason'], 'INSUFFICIENT_EVIDENCE')
        self.assertTrue(console.grant()['result']['refused'])
        graded = grade_episode(runtime, card, labels)
        self.assertTrue(graded['denial_correct'])
        self.assertEqual(graded['mutation_count'], 0)

    def test_deadline_blocks_release(self):
        runtime, card, labels, console = self.open('development-eligible')
        console.card['deadline_ms'] = 1_000_000
        console.qualify()
        console.grant()
        self.assertEqual(console.release()['result']['reason'], 'TIMEOUT')
        self.assertEqual(runtime.mutation_count, 0)

    def test_held_out_family_is_rejected(self):
        card = load_json(CARDS / 'development-eligible.card.json')
        card.update(split='held_out', family_id='fam-hold-publish', skill='publish-model', version='skill-v1', context='demo-h')
        with self.assertRaises(Denied) as raised:
            check_family(card)
        self.assertEqual(raised.exception.reason, 'HELD_OUT_NOT_OPENED')

    def test_trace_records_an_intervention_and_then_closes(self):
        _, _, _, console = self.open('development-insufficient')
        console.intervene('asked for the evidence window')
        console.stop('HOLD')
        self.assertEqual(len(console.trace()['interventions']), 1)
        with self.assertRaises(Denied) as raised:
            console.qualify()
        self.assertEqual(raised.exception.reason, 'EPISODE_CLOSED')


if __name__ == '__main__':
    unittest.main()
