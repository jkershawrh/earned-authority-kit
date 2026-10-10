"""UNIT transport-seam negatives; these fixtures are not connected-service evidence."""
import base64
import copy
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from earned_authority.passport_client import PassportClient, PAYLOAD_HEADER, REVISION_HEADER
from earned_authority.runtime import Denied


class MetadataCall:
    def __init__(self, payload, revision=7):
        self.metadata = [(PAYLOAD_HEADER, payload), (REVISION_HEADER, str(revision))]
    def initial_metadata(self): return self.metadata


class RPCCall:
    def __init__(self, result=None, error=None): self.result, self.error = result, error
    def with_call(self, *args, **kwargs):
        if self.error: raise self.error
        return self.result


class MissingVerify(grpc.RpcError):
    def code(self): return grpc.StatusCode.NOT_FOUND
    def trailing_metadata(self): return [(REVISION_HEADER, '7')]


class PassportVerificationSnapshotBoundary(unittest.TestCase):
    def setUp(self):
        vector = json.loads((Path(__file__).resolve().parents[1] / 'contracts/fixtures/passport-canonical-v2.json').read_text())
        self.body = json.loads(base64.b64decode(vector['canonical_payload_base64']))
        key = Ed25519PrivateKey.generate()
        pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.body['public_key_pem'] = pem
        self.payload = json.dumps(self.body, separators=(',', ':'), ensure_ascii=False).encode()
        wire = copy.deepcopy(self.body)
        wire['scope_set'] = [SimpleNamespace(**s) for s in wire['scope_set']]
        wire.update(signature=key.sign(self.payload), status='ACTIVE')
        self.passport = SimpleNamespace(**wire)
        self.client = PassportClient.__new__(PassportClient)
        self.client.grpc = grpc
        self.client.public_key = pem
        self.client.timeout = 1
        self.client.pb = SimpleNamespace(GetAgentPassportRequest=SimpleNamespace, VerifyPassportRequest=SimpleNamespace)
        self.client.stub = SimpleNamespace(GetAgentPassport=RPCCall((SimpleNamespace(passport=self.passport), MetadataCall(self.payload))))
        self.checked = SimpleNamespace(valid=True, status='ACTIVE', passport_id=self.body['passport_id'], expires_ts=self.body['expires_ts'])

    def verify_call(self, checked=None, payload=None):
        self.client.stub.VerifyPassport = RPCCall((checked or self.checked, MetadataCall(payload or self.payload)))
        return self.client.current(self.body['agent_id'])

    def test_matching_verification_snapshot_is_accepted(self):
        self.assertEqual(self.body, self.verify_call()['subject'])

    def test_other_passport_at_same_agent_generation_is_rejected(self):
        self.checked.passport_id = 'different-passport'
        with self.assertRaises(Denied): self.verify_call()

    def test_verify_expiry_different_from_signed_snapshot_is_rejected(self):
        self.checked.expires_ts += 1000
        with self.assertRaises(Denied): self.verify_call()

    def test_verify_envelope_different_from_signed_snapshot_is_rejected(self):
        other = {**self.body, 'passport_id': 'different-passport'}
        with self.assertRaises(Denied): self.verify_call(payload=json.dumps(other).encode())

    def test_second_rpc_notfound_is_not_an_empty_aggregate(self):
        self.client.stub.VerifyPassport = RPCCall(error=MissingVerify())
        with self.assertRaises(Denied): self.client.current(self.body['agent_id'])


class UnitPolicy:
    policy_digest = 'sha256:' + 'a' * 64
    def __init__(self): self.after_check = lambda: None
    def check(self, *args):
        self.after_check()
        return {'decision': {'decision_id': 'unit-decision'}}


class UnitPassport:
    """Stateful UNIT seam; no canonical-service acceptance claims."""
    def __init__(self):
        self.state = {'subject': None, 'revision': 0, 'status': 'REVOKED'}
        self.issues = 0
        self.fail_mutations = False
        self.now = lambda: 0
        self.operations = {}
    def current(self, agent, require_valid=True): return copy.deepcopy(self.state)
    def operation(self, agent, operation_id, expected_request=None):
        value = self.operations.get(operation_id)
        if value and (value['agent_id'] != agent or expected_request is not None and value['request'] != expected_request):
            raise Denied('AUTHORITY_OPERATION_BINDING_MISMATCH')
        return copy.deepcopy(value)
    def _record_operation(self, request, current):
        if not request['operation_id']: return
        subject = self.state['subject']; old = current['subject']
        self.operations[request['operation_id']] = {
            'operation_id': request['operation_id'], 'agent_id': request['agent_id'], 'request': request,
            'agent_revision': self.state['revision'], 'previous_active_passport_id': old['passport_id'] if old else '',
            'active_passport_id': subject['passport_id'] if subject else '', 'authority': copy.deepcopy(self.state),
            'result': {'action': request['action'], 'completed_ts': self.now()}}
    def issue(self, agent, scopes, ttl, current, reason, operation_id=None):
        from earned_authority.passport_client import issue_operation_request
        request = issue_operation_request(agent, scopes, ttl, current, reason, operation_id)
        previous = self.operation(agent, operation_id, request) if operation_id else None
        if previous: return previous['authority']
        if self.fail_mutations: raise Denied('AUTHORITY_UNCONFIRMED')
        if current['revision'] != self.state['revision']: raise Denied('REVISION_CONFLICT')
        self.issues += 1
        revision = self.state['revision'] + 1
        self.state = {'revision': revision, 'status': 'ACTIVE', 'subject': {
            'passport_id': 'unit-passport-' + str(revision), 'agent_id': agent,
            'issued_ts': self.now(), 'expires_ts': self.now() + ttl * 1000,
            'scope_set': [{**s, 'scope_id': 'scope-' + str(i), 'granted_ts': self.now(),
                           'expires_ts': self.now() + s['scope_ttl_seconds'] * 1000}
                          for i, s in enumerate(scopes)]}}
        self._record_operation(request, current)
        return copy.deepcopy(self.state)
    def revoke(self, current, reason, operation_id=None):
        from earned_authority.passport_client import revoke_operation_request
        request = revoke_operation_request(current, reason, operation_id)
        previous = self.operation(request['agent_id'], operation_id, request) if operation_id else None
        if previous: return previous
        if self.fail_mutations: raise Denied('AUTHORITY_UNCONFIRMED')
        if current['revision'] != self.state['revision']: raise Denied('REVISION_CONFLICT')
        self.state = {'subject': None, 'revision': self.state['revision'] + 1, 'status': 'REVOKED'}
        self._record_operation(request, current)
        return self.state['revision']


class ConnectedDeadlineAndWithdrawalBoundary(unittest.TestCase):
    def setUp(self):
        import tempfile
        from earned_authority.connected import ConnectedRuntime
        from earned_authority.runtime import ControlledClock
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.passport, self.policy = UnitPassport(), UnitPolicy()
        self.rt = ConnectedRuntime(Path(self.tmp.name) / 'runtime.sqlite', passport=self.passport,
            policy=self.policy, ledger=None, qualification_client=None,
            fence_path=Path(self.tmp.name) / 'fence.lock')
        self.rt.clock = ControlledClock(1000000)
        self.passport.now = lambda: self.rt.clock.now_ms
        self.context = {'model_version': 'model-v2'}
        self.qcount = 0

    def qualification(self, skill='release-model', context=None):
        from earned_authority.contracts import canonical_digest
        self.qcount += 1
        context = self.context if context is None else context
        q = {'qualification_id': 'unit-q-' + str(self.qcount), 'qualification_revision': 1,
             'skill': skill, 'version': self.rt.procedure_revision, 'context': context,
             'skill_digest': canonical_digest({'skill': skill, 'version': self.rt.procedure_revision}),
             'context_digest': canonical_digest({'environment': context}),
             'expires_at_ms': self.rt.clock.now_ms + 10000, 'disposition': 'ELIGIBLE', 'reason': 'UNIT_ELIGIBLE'}
        with self.rt._tx() as db: self.rt._save_qualification(db, q)
        return q

    def test_scope_expiring_during_policy_call_cannot_commit(self):
        q = self.qualification()
        self.rt.grant(q['qualification_id'], ttl_ms=1200)
        self.policy.after_check = lambda: self.rt.clock.advance(1500)
        intent = {'agent': 'agent-a', 'skill': q['skill'], 'version': q['version'],
                  'context': q['context'], 'action': 'release', 'resource': 'model/champion', 'target': 'model-v2'}
        with self.assertRaises(Denied): self.rt._check(None, intent)
        self.assertEqual(0, self.rt.mutation_count)

    def test_short_requested_grant_cannot_disappear_behind_other_live_skill(self):
        read = self.qualification('read-health')
        self.rt.grant(read['qualification_id'], action='read', resource='urn:dataset/health', ttl_ms=10000)
        q = self.qualification()
        issued = self.passport.issues
        with self.assertRaises(Denied): self.rt.grant(q['qualification_id'], ttl_ms=999)
        self.assertEqual(issued, self.passport.issues)

    def test_unaffected_scope_keeps_exact_absolute_expiry_on_replacement(self):
        read = self.qualification('read-health')
        before = self.rt.grant(read['qualification_id'], action='read', resource='urn:dataset/health', ttl_ms=10000)
        expiry = before['grants']['read-health']['expires_at_ms']
        self.rt.clock.advance(125)
        release = self.qualification()
        after = self.rt.grant(release['qualification_id'], ttl_ms=10000)
        self.assertEqual(expiry, after['grants']['read-health']['expires_at_ms'])

    def test_delayed_old_withdrawal_does_not_revoke_requalified_grant(self):
        q = self.qualification()
        self.rt.grant(q['qualification_id'], ttl_ms=10000)
        self.passport.fail_mutations = True
        with self.assertRaises(Denied): self.rt.reevaluate(state='UNKNOWN')
        self.passport.fail_mutations = False
        revoke = self.rt.revoke
        new_grant = {}
        def delayed_drainer(*args, **kwargs):
            # This drainer already captured the old durable queue row. A peer
            # processes it, deletes it, and requalifies before it resumes.
            if not new_grant:
                revoke(*args, **kwargs)
                with self.rt._tx() as db: db.execute('DELETE FROM withdrawals')
                fresh = self.qualification(context={'model_version': 'model-v3'})
                new_grant['qualification_id'] = fresh['qualification_id']
                self.rt.grant(fresh['qualification_id'], ttl_ms=10000)
            return revoke(*args, **kwargs)
        self.rt.revoke = delayed_drainer
        self.rt.drain_withdrawals()
        current = self.rt.authority()
        self.assertIn('release-model', current['grants'])
        self.assertEqual(new_grant['qualification_id'], current['grants']['release-model']['qualification_id'])
