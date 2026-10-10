"""Signed operation consumer regressions. UNIT fixtures do not claim live recovery."""
import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from earned_authority.passport_client import issue_operation_request,revoke_operation_request,canonical_operation_request,verify_operation_receipt
from earned_authority.runtime import Denied

class OperationReceiptVerification(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.request=issue_operation_request('agent',[{'action_class':'WRITE','resource_pattern':'model/*','context_constraints':{'site':'<>& 世界\u2028'},'scope_ttl_seconds':60}],300,{'subject':None,'revision':0},'qualified','op1')
        self.passport={'canonical_version':'are.passport.v2','credential_id':'issuer','public_key_pem':self.pem,'passport_id':'p1','agent_id':'agent','issuance_revision':1,'passport_type':'STANDARD',
            'scope_set':[{'scope_id':'s1','action_class':'WRITE','resource_pattern':'model/*','context_constraints':{'site':'<>& 世界\u2028'},'granted_ts':1000000,'expires_ts':1060000,'is_escalation':False}],
            'issued_by':'earned-authority-coordinator','reason':'qualified','issued_ts':1000000,'expires_ts':1300000,'policy_id_at_issuance':'policy','policy_ver_at_issuance':'v1'}
        raw=json.dumps(self.passport).encode()
        self.body={'canonical_version':'are.passport.operation.v1','credential_id':'issuer','public_key_pem':self.pem,'operation_id':'op1','agent_id':'agent','request':self.request,
            'request_digest':'sha256:'+hashlib.sha256(canonical_operation_request(self.request)).hexdigest(),'agent_revision':1,'previous_active_passport_id':'','active_passport_id':'p1',
            'result':{'action':'ISSUE','passport_id':'p1','status':'ACTIVE','completed_ts':1000000,'passport_payload_base64':base64.b64encode(raw).decode(),'passport_signature_base64':base64.b64encode(self.key.sign(raw)).decode(),'previous_passport_payload_base64':'','previous_passport_signature_base64':''}}
    def receipt(self,body=None,key=None):
        raw=json.dumps(self.body if body is None else body).encode()
        return SimpleNamespace(canonical_payload=raw,signature=(key or self.key).sign(raw),credential_id='issuer',public_key_pem=self.pem)
    def verify(self,body=None,**kwargs):return verify_operation_receipt(self.receipt(body),self.pem,kwargs.get('agent','agent'),kwargs.get('operation_id','op1'),kwargs.get('expected_request',self.request))
    def test_valid_receipt_derives_historical_authority(self):
        got=self.verify();self.assertEqual(self.passport,got['authority']['subject']);self.assertEqual(1,got['authority']['revision'])
    def test_unpinned_receipt_signature_denied(self):
        with self.assertRaises(Denied):verify_operation_receipt(self.receipt(key=Ed25519PrivateKey.generate()),self.pem,'agent','op1')
    def test_other_agent_or_operation_denied(self):
        for kw in ({'agent':'other'},{'operation_id':'other'}):
            with self.subTest(kw=kw),self.assertRaises(Denied):self.verify(**kw)
    def test_request_reason_scope_and_cas_mismatch_denied(self):
        for field in ('reason','scope','cas'):
            expected=copy.deepcopy(self.request)
            if field=='reason':expected['issue']['reason']='other'
            if field=='scope':expected['issue']['requested_scopes'][0]['context_constraints']['site']='B'
            if field=='cas':expected['expected_agent_revision']=1
            with self.subTest(field=field),self.assertRaises(Denied):self.verify(expected_request=expected)
    def test_wrong_result_revision_or_target_denied(self):
        for key,value in (('agent_revision',2),('active_passport_id','other')):
            body=copy.deepcopy(self.body);body[key]=value
            with self.subTest(key=key),self.assertRaises(Denied):self.verify(body)
    def test_altered_nested_passport_signature_denied(self):
        self.body['result']['passport_signature_base64']=base64.b64encode(b'x'*64).decode()
        with self.assertRaises(Denied):self.verify()
    def test_receipt_cannot_claim_different_scope_than_request(self):
        p=copy.deepcopy(self.passport);p['scope_set'][0]['resource_pattern']='unbounded/*';raw=json.dumps(p).encode()
        self.body['result']['passport_payload_base64']=base64.b64encode(raw).decode();self.body['result']['passport_signature_base64']=base64.b64encode(self.key.sign(raw)).decode()
        with self.assertRaises(Denied):self.verify()
    def test_unknown_or_duplicate_receipt_fields_denied(self):
        self.body['unknown']=True
        with self.assertRaises(Denied):self.verify()
        del self.body['unknown'];raw=json.dumps(self.body).encode()[:-1]+b',"agent_id":"agent"}'
        receipt=SimpleNamespace(canonical_payload=raw,signature=self.key.sign(raw),credential_id='issuer',public_key_pem=self.pem)
        with self.assertRaises(Denied):verify_operation_receipt(receipt,self.pem,'agent','op1')
    def test_empty_state_cannot_make_revoke_request(self):
        with self.assertRaises(Denied):revoke_operation_request({'subject':None,'revision':2},'drift','op2')
    def test_falsey_non_map_context_is_not_silently_normalized(self):
        for invalid in ([],False,0,'',None):
            with self.subTest(context=invalid),self.assertRaises(Denied):
                issue_operation_request('agent',[{'action_class':'WRITE','resource_pattern':'model/*','context_constraints':invalid}],300,{'subject':None,'revision':0},'qualified','op1')

class OperationProviderVectors(unittest.TestCase):
    def test_go_operation_receipts_and_request_canonicalization(self):
        fixture=json.loads((Path(__file__).resolve().parents[1]/'contracts/fixtures/passport-operations-v1.json').read_text())
        for v in fixture['cases']:
            with self.subTest(operation=v['operation_id']):
                self.assertEqual(v['request_canonical_utf8'].encode(),canonical_operation_request(v['request']))
                receipt=SimpleNamespace(canonical_payload=base64.b64decode(v['canonical_payload_base64']),signature=base64.b64decode(v['signature_base64']),credential_id=v['credential_id'],public_key_pem=v['public_key_pem'])
                found=verify_operation_receipt(receipt,v['public_key_pem'],v['agent_id'],v['operation_id'],v['request'])
                self.assertEqual(v['request'],found['request'])
                if v['request']['action']=='REVOKE':self.assertIsNone(found['authority']['subject'])
                else:self.assertEqual(1,found['authority']['subject']['issuance_revision'])

class OperationClientTransport(unittest.TestCase):
    def setUp(self):
        import grpc
        from earned_authority.passport_client import PassportClient
        self.grpc=grpc
        self.client=PassportClient.__new__(PassportClient)
        self.client.grpc=grpc;self.client.timeout=1;self.client.token='unit-token'
        self.client.pb=SimpleNamespace(ApplyPassportOperationRequest=SimpleNamespace,GetPassportOperationRequest=SimpleNamespace,
            IssuePassportRequest=SimpleNamespace,RevokePassportRequest=SimpleNamespace,ScopeRequest=SimpleNamespace)
        fixture=json.loads((Path(__file__).resolve().parents[1]/'contracts/fixtures/passport-operations-v1.json').read_text())
        self.vector=fixture['cases'][0];v=self.vector;self.client.public_key=v['public_key_pem']
        receipt=SimpleNamespace(canonical_payload=base64.b64decode(v['canonical_payload_base64']),signature=base64.b64decode(v['signature_base64']),credential_id=v['credential_id'],public_key_pem=v['public_key_pem'])
        self.calls=[]
        def with_call(request,**kwargs):
            self.calls.append(request);self.assertEqual([('authorization','Bearer unit-token')],kwargs['metadata'])
            return SimpleNamespace(receipt=receipt),None
        self.client.stub=SimpleNamespace(ApplyPassportOperation=SimpleNamespace(with_call=with_call),GetPassportOperation=SimpleNamespace(with_call=with_call))
    def test_issue_and_lookup_use_explicit_signed_operation(self):
        r=self.vector['request'];i=r['issue']
        result=self.client.issue(r['agent_id'],i['requested_scopes'],i['ttl_seconds'],{'subject':None,'revision':0},i['reason'],operation_id=r['operation_id'])
        self.assertEqual(r,result['operation_receipt']['request']);self.assertEqual(1,result['revision'])
        receipt=self.client.operation(r['agent_id'],r['operation_id'],expected_request=r)
        self.assertEqual(result['operation_receipt'],receipt)
        self.assertEqual(r['operation_id'],self.calls[0].operation_id)
    def test_only_canonical_notfound_returns_no_operation(self):
        grpc=self.grpc
        class RPCFailure(grpc.RpcError):
            def __init__(self,code):self.status=code
            def code(self):return self.status
        for code in (grpc.StatusCode.NOT_FOUND,grpc.StatusCode.UNAVAILABLE,grpc.StatusCode.UNAUTHENTICATED):
            def failed(*args,**kwargs):raise RPCFailure(code)
            self.client.stub.GetPassportOperation=SimpleNamespace(with_call=failed)
            with self.subTest(code=code):
                if code==grpc.StatusCode.NOT_FOUND:self.assertIsNone(self.client.operation('agent','op1'))
                else:
                    with self.assertRaises(Denied):self.client.operation('agent','op1')
    def test_empty_current_state_cannot_claim_successful_operation_revoke(self):
        with self.assertRaises(Denied):self.client.revoke({'subject':None,'revision':5},'drift',operation_id='op-revoke')
        self.assertEqual([],self.calls)
