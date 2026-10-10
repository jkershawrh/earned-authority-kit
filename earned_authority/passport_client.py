"""Canonical Passport v2, with pinned signer and independently checked envelope."""
import base64
import importlib
import ipaddress
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from .runtime import Denied

PAYLOAD_HEADER='x-are-canonical-payload-bin'
REVISION_HEADER='x-are-agent-revision'


def check_endpoint(endpoint):
    host,_,port=endpoint.rpartition(':')
    if not port.isdigit() or not 0<int(port)<65536: raise ValueError('invalid endpoint')
    if host!='localhost' and not ipaddress.ip_address(host.strip('[]')).is_loopback:
        raise ValueError('plaintext reference transport requires loopback')


def verify_envelope(payload,signature,public_key_pem,revision,agent_id,passport=None):
    """The transport is not trusted to supply its own trust anchor."""
    try:
        key=serialization.load_pem_public_key(public_key_pem.encode())
        key.verify(signature,payload)
        def unique(pairs):
            value={}
            for k,v in pairs:
                if k in value: raise ValueError('duplicate key')
                value[k]=v
            return value
        body=json.loads(payload,object_pairs_hook=unique)
        fields={'canonical_version','credential_id','public_key_pem','passport_id','agent_id','issuance_revision',
                'passport_type','scope_set','issued_by','reason','issued_ts','expires_ts','policy_id_at_issuance','policy_ver_at_issuance'}
        if set(body)!=fields or body['canonical_version']!='are.passport.v2': raise ValueError('unknown envelope version/fields')
        if body['public_key_pem']!=public_key_pem or body['agent_id']!=agent_id: raise ValueError('subject mismatch')
        if type(body['issuance_revision']) is not int or body['issuance_revision']!=revision: raise ValueError('current revision mismatch')
        for name in ('issued_ts','expires_ts'):
            if type(body[name]) is not int or body[name]<=0: raise ValueError('invalid time bound')
        if body['expires_ts']<=body['issued_ts']: raise ValueError('empty authority interval')
        for scope in body['scope_set']:
            if type(scope['granted_ts']) is not int or type(scope['expires_ts']) is not int: raise ValueError('invalid scope time')
            if not body['issued_ts']-1000<=scope['granted_ts']<scope['expires_ts']<=body['expires_ts']: raise ValueError('scope outlives authority')
            if type(scope['is_escalation']) is not bool: raise ValueError('invalid escalation')
            if not isinstance(scope['context_constraints'],dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in scope['context_constraints'].items()):
                raise ValueError('invalid context')
        if passport is not None:
            for field in ('credential_id','public_key_pem','passport_id','agent_id','passport_type','issued_by',
                          'issued_ts','expires_ts','policy_id_at_issuance','policy_ver_at_issuance'):
                if body[field]!=getattr(passport,field): raise ValueError('wire field mismatch: '+field)
            if len(body['scope_set'])!=len(passport.scope_set): raise ValueError('scope count mismatch')
            for expected,scope in zip(body['scope_set'],passport.scope_set):
                keys={'scope_id','action_class','resource_pattern','context_constraints','granted_ts','expires_ts','is_escalation'}
                if set(expected)!=keys: raise ValueError('unknown scope fields')
                for name,value in expected.items():
                    actual=dict(scope.context_constraints) if name=='context_constraints' else getattr(scope,name)
                    if actual!=value: raise ValueError('scope mismatch: '+name)
        return body
    except Exception as exc:
        raise Denied('INVALID_CANONICAL_AUTHORITY') from exc


class PassportClient:
    def __init__(self,endpoint,mutation_token,public_key_pem,*,sdk_path,timeout_seconds=5):
        check_endpoint(endpoint)
        import grpc
        self.grpc=grpc;self.token=mutation_token;self.public_key=public_key_pem
        self.timeout=timeout_seconds
        sdk=str(Path(sdk_path).resolve())
        if sdk not in sys.path: sys.path.insert(0,sdk)
        self.pb=importlib.import_module('passport_issuance_pb2')
        stub=importlib.import_module('passport_issuance_pb2_grpc')
        self.channel=grpc.insecure_channel(endpoint)
        self.stub=stub.PassportIssuanceServiceStub(self.channel)

    def close(self): self.channel.close()

    def _revision(self,metadata):
        values=[v for k,v in metadata if k==REVISION_HEADER]
        if len(values)!=1 or not values[0].isdigit(): raise Denied('AUTHORITY_REVISION_UNCONFIRMED')
        return int(values[0])

    def _snapshot(self,response,call,agent):
        metadata=list(call.initial_metadata() or ())
        revision=self._revision(metadata)
        payloads=[v for k,v in metadata if k==PAYLOAD_HEADER]
        if len(payloads)!=1: raise Denied('AUTHORITY_ENVELOPE_MISSING')
        p=response.passport
        body=verify_envelope(payloads[0],p.signature,self.public_key,revision,agent,p)
        if p.status!='ACTIVE': raise Denied('REVOKED_AUTHORITY')
        return {'subject':body,'signature':base64.b64encode(p.signature).decode(),'status':p.status,'revision':revision}

    def current(self,agent,require_valid=True):
        try:
            response,call=self.stub.GetAgentPassport.with_call(self.pb.GetAgentPassportRequest(agent_id=agent),timeout=self.timeout)
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.NOT_FOUND:
                revision=self._revision(list(exc.trailing_metadata() or ()))
                return {'subject':None,'signature':None,'status':'REVOKED','revision':revision}
            raise Denied('AUTHORITY_UNCONFIRMED') from exc
        snapshot=self._snapshot(response,call,agent)
        if not require_valid:return snapshot
        # Verify is a separately returned authoritative snapshot, so bind it too.
        try:
            checked,vcall=self.stub.VerifyPassport.with_call(self.pb.VerifyPassportRequest(passport_id=response.passport.passport_id),timeout=self.timeout)
        except self.grpc.RpcError as exc:
            raise Denied('AUTHORITY_UNCONFIRMED') from exc
        metadata=list(vcall.initial_metadata() or ())
        if not checked.valid or checked.status!='ACTIVE' or self._revision(metadata)!=snapshot['revision']:
            raise Denied('AUTHORITY_UNCONFIRMED')
        if checked.passport_id!=snapshot['subject']['passport_id'] or checked.expires_ts!=snapshot['subject']['expires_ts']:
            raise Denied('AUTHORITY_UNCONFIRMED')
        payloads=[v for k,v in metadata if k==PAYLOAD_HEADER]
        if len(payloads)!=1:raise Denied('AUTHORITY_ENVELOPE_MISSING')
        verified=verify_envelope(payloads[0],response.passport.signature,self.public_key,snapshot['revision'],agent,response.passport)
        if verified!=snapshot['subject']:raise Denied('AUTHORITY_UNCONFIRMED')
        return snapshot

    def _metadata(self,current):
        subject=current['subject']
        return [('authorization','Bearer '+self.token),
                ('x-are-expected-active-passport-id',subject['passport_id'] if subject else 'none'),
                ('x-are-expected-agent-revision',str(current['revision']))]

    def issue(self,agent,scopes,ttl_seconds,current,reason):
        request=self.pb.IssuePassportRequest(agent_id=agent,passport_type='STANDARD',
            requested_scopes=[self.pb.ScopeRequest(**s) for s in scopes],ttl_seconds=ttl_seconds,
            issued_by='earned-authority-coordinator',force_reissue=bool(current['subject']),reason=reason)
        try:
            response,call=self.stub.IssuePassport.with_call(request,metadata=self._metadata(current),timeout=self.timeout)
            return self._snapshot(response,call,agent)
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.FAILED_PRECONDITION: raise Denied('REVISION_CONFLICT') from exc
            raise Denied('AUTHORITY_UNCONFIRMED') from exc

    def revoke(self,current,reason):
        if not current['subject']: return current['revision']
        request=self.pb.RevokePassportRequest(passport_id=current['subject']['passport_id'],reason=reason,revoked_by='earned-authority-coordinator')
        try:
            response,call=self.stub.RevokePassport.with_call(request,metadata=self._metadata(current),timeout=self.timeout)
            if response.status!='REVOKED': raise Denied('AUTHORITY_UNCONFIRMED')
            return self._revision(list(call.initial_metadata() or ()))
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.FAILED_PRECONDITION: raise Denied('REVISION_CONFLICT') from exc
            raise Denied('AUTHORITY_UNCONFIRMED') from exc
