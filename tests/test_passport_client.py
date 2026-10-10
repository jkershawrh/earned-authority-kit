"""Independent consumer checks, including provider shape regression vectors."""
import json
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from earned_authority.passport_client import verify_envelope,check_endpoint
from earned_authority.runtime import Denied

class PassportConsumer(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.body={'canonical_version':'are.passport.v2','credential_id':'key1','public_key_pem':self.pem,
            'passport_id':'p1','agent_id':'agent1','issuance_revision':1,'passport_type':'STANDARD','scope_set':[],
            'issued_by':'issuer','reason':'qualified','issued_ts':100,'expires_ts':200,
            'policy_id_at_issuance':'policy1','policy_ver_at_issuance':'v1'}
    def verify(self,body=None,**kw):
        payload=json.dumps(body or self.body,separators=(',',':')).encode()
        return verify_envelope(payload,self.key.sign(payload),kw.get('pem',self.pem),kw.get('revision',1),kw.get('agent','agent1'))
    def test_valid_exact_envelope(self): self.assertEqual(self.body,self.verify())
    def test_unpinned_key_denied(self):
        other=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        with self.assertRaises(Denied): self.verify(pem=other)
    def test_active_read_revision_mismatch_denied(self):
        with self.assertRaises(Denied): self.verify(revision=2)
    def test_cross_agent_replay_denied(self):
        with self.assertRaises(Denied): self.verify(agent='agent2')
    def test_unknown_mandatory_field_denied(self):
        self.body['extra']='field'
        with self.assertRaises(Denied): self.verify()
    def test_boolean_expiry_is_not_a_timestamp(self):
        self.body['expires_ts']=True
        with self.assertRaises(Denied): self.verify()
    def test_scope_outliving_passport_denied(self):
        self.body['scope_set']=[{'scope_id':'s1','action_class':'release','resource_pattern':'model/a',
            'context_constraints':{},'granted_ts':100,'expires_ts':201,'is_escalation':False}]
        with self.assertRaises(Denied): self.verify()
    def test_remote_plaintext_denied(self):
        with self.assertRaises(ValueError):check_endpoint('192.0.2.1:50051')
    def test_loopback_allowed(self):check_endpoint('127.0.0.1:50051')
if __name__=='__main__':unittest.main()


class CanonicalProviderVector(unittest.TestCase):
    def test_go_v2_signature_verifies_in_python(self):
        import base64,hashlib
        d=json.loads((Path(__file__).resolve().parents[1]/'contracts/fixtures/passport-canonical-v2.json').read_text())
        payload=base64.b64decode(d['canonical_payload_base64'])
        self.assertEqual(d['canonical_payload_sha256'],hashlib.sha256(payload).hexdigest())
        body=verify_envelope(payload,base64.b64decode(d['signature_base64']),d['public_key_pem'],d['issuance_revision'],d['passport_proto_json']['agent_id'])
        self.assertEqual(d['passport_proto_json']['passport_id'],body['passport_id'])
