"""Canonical Passport v2, with pinned signer and independently checked envelope."""
import base64
import copy
import hashlib
import re
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


def public_key_pems(text):
    """Split an explicit historical-issuer file into public PEM blocks."""
    pems=[];current=[]
    for line in text.splitlines(keepends=True):
        current.append(line)
        if '-----END PUBLIC KEY-----' in line:
            pems.append(''.join(current));current=[]
    if ''.join(current).strip():raise ValueError('historical issuer file has trailing data')
    if any('PRIVATE KEY' in pem for pem in pems):raise ValueError('historical issuer file must contain public keys only')
    return pems


def _signature_key(payload,signature,pems):
    for pem in pems:
        try:
            serialization.load_pem_public_key(pem.encode()).verify(signature,payload)
            return pem
        except Exception:
            continue
    return None


def verify_envelope(payload,signature,public_key_pem,revision,agent_id,passport=None,trusted_public_keys=()):
    """The transport is not trusted to supply its own trust anchor."""
    try:
        signer=_signature_key(payload,signature,(public_key_pem,*trusted_public_keys))
        if signer is None:raise ValueError('signature')
        public_key_pem=signer
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


def _operation_request(request):
    """Closed request normalization shared by journal storage and dispatch."""
    r=copy.deepcopy(request)
    fields={'operation_id','agent_id','action','expected_active_passport_id','expected_agent_revision','issue','revoke'}
    if set(r)!=fields or not isinstance(r['operation_id'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',r['operation_id']): raise Denied('INVALID_OPERATION_REQUEST')
    if not isinstance(r['agent_id'],str) or not r['agent_id'] or type(r['expected_agent_revision']) is not int or not 0<=r['expected_agent_revision']<2**64: raise Denied('INVALID_OPERATION_REQUEST')
    if not isinstance(r['expected_active_passport_id'],str) or r['expected_active_passport_id']=='none': raise Denied('INVALID_OPERATION_REQUEST')
    if r['action']=='ISSUE':
        i=r['issue']
        if not isinstance(i,dict) or r['revoke'] is not None or set(i)!={'agent_id','passport_type','requested_scopes','ttl_seconds','issued_by','force_reissue','reason'}: raise Denied('INVALID_OPERATION_REQUEST')
        if i['agent_id']!=r['agent_id'] or i['passport_type'] not in ('STANDARD','PROVISIONAL') or type(i['force_reissue']) is not bool: raise Denied('INVALID_OPERATION_REQUEST')
        if type(i['ttl_seconds']) is not int or not 300<=i['ttl_seconds']<=2592000 or (i['passport_type']=='PROVISIONAL' and i['ttl_seconds']>86400): raise Denied('INVALID_OPERATION_REQUEST')
        if any(not isinstance(i[k],str) or not i[k] for k in ('issued_by','reason')) or not isinstance(i['requested_scopes'],list) or not i['requested_scopes']: raise Denied('INVALID_OPERATION_REQUEST')
        for scope in i['requested_scopes']:
            if not isinstance(scope,dict) or set(scope)!={'action_class','resource_pattern','context_constraints','scope_ttl_seconds'}: raise Denied('INVALID_OPERATION_REQUEST')
            if any(not isinstance(scope[k],str) or not scope[k] for k in ('action_class','resource_pattern')): raise Denied('INVALID_OPERATION_REQUEST')
            if not isinstance(scope['context_constraints'],dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in scope['context_constraints'].items()): raise Denied('INVALID_OPERATION_REQUEST')
            if type(scope['scope_ttl_seconds']) is not int or not 0<=scope['scope_ttl_seconds']<2**63: raise Denied('INVALID_OPERATION_REQUEST')
    elif r['action']=='REVOKE':
        v=r['revoke']
        if r['issue'] is not None or not isinstance(v,dict) or set(v)!={'passport_id','reason','revoked_by'}: raise Denied('INVALID_OPERATION_REQUEST')
        if any(not isinstance(v[k],str) or not v[k] for k in v) or v['passport_id']!=r['expected_active_passport_id']: raise Denied('INVALID_OPERATION_REQUEST')
    else:raise Denied('INVALID_OPERATION_REQUEST')
    return r


def issue_operation_request(agent,scopes,ttl_seconds,current,reason,operation_id):
    subject=current['subject']
    if subject and subject['agent_id']!=agent: raise Denied('INVALID_OPERATION_REQUEST')
    normalized=[]
    for scope in scopes:
        if set(scope)-{'action_class','resource_pattern','context_constraints','scope_ttl_seconds'}: raise Denied('INVALID_OPERATION_REQUEST')
        normalized.append({'action_class':scope['action_class'],'resource_pattern':scope['resource_pattern'],
            'context_constraints':copy.deepcopy(scope.get('context_constraints',{})),'scope_ttl_seconds':scope.get('scope_ttl_seconds',0)})
    return _operation_request({'operation_id':operation_id,'agent_id':agent,'action':'ISSUE',
        'expected_active_passport_id':subject['passport_id'] if subject else '', 'expected_agent_revision':current['revision'],
        'issue':{'agent_id':agent,'passport_type':'STANDARD','requested_scopes':normalized,'ttl_seconds':ttl_seconds,
                 'issued_by':'earned-authority-coordinator','force_reissue':bool(subject),'reason':reason},'revoke':None})


def revoke_operation_request(current,reason,operation_id):
    subject=current['subject']
    if not subject:raise Denied('OPERATION_REVOKE_TARGET_REQUIRED')
    return _operation_request({'operation_id':operation_id,'agent_id':subject['agent_id'],'action':'REVOKE',
        'expected_active_passport_id':subject['passport_id'],'expected_agent_revision':current['revision'],
        'issue':None,'revoke':{'passport_id':subject['passport_id'],'reason':reason,'revoked_by':'earned-authority-coordinator'}})


def canonical_operation_request(request):
    # Match Go's sorted JSON keys and escaping; integer-only closed request schema.
    raw=json.dumps(_operation_request(request),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    for literal,escaped in (('<',r'\u003c'),('>',r'\u003e'),('&',r'\u0026'),('\u2028',r'\u2028'),('\u2029',r'\u2029')):
        raw=raw.replace(literal,escaped)
    return raw.encode('utf-8')


def verify_operation_receipt(receipt,public_key_pem,agent,operation_id,expected_request=None,*,historical_public_keys=(),require_current_signer=False):
    """Verify immutable transition evidence; never assert its authority is current.

    historical_public_keys trusts receipts and predecessor passports already stored.
    A new operation sets require_current_signer so its receipt must use the current key.
    """
    try:
        current_key=public_key_pem
        signer=_signature_key(receipt.canonical_payload,receipt.signature,(current_key,*historical_public_keys))
        if signer is None or (require_current_signer and signer!=current_key):raise ValueError('signature')
        public_key_pem=signer
        def unique(pairs):
            value={}
            for name,item in pairs:
                if name in value:raise ValueError('duplicate field')
                value[name]=item
            return value
        body=json.loads(receipt.canonical_payload,object_pairs_hook=unique)
        fields={'canonical_version','credential_id','public_key_pem','operation_id','agent_id','request','request_digest',
                'agent_revision','previous_active_passport_id','active_passport_id','result'}
        if not isinstance(body,dict) or set(body)!=fields or body['canonical_version']!='are.passport.operation.v1':raise ValueError('unknown receipt format')
        if body['public_key_pem']!=public_key_pem or receipt.public_key_pem!=public_key_pem or body['credential_id']!=receipt.credential_id:raise ValueError('issuer mismatch')
        if body['operation_id']!=operation_id or body['agent_id']!=agent:raise ValueError('receipt subject mismatch')
        request=_operation_request(body['request'])
        if request['operation_id']!=operation_id or request['agent_id']!=agent:raise ValueError('request subject mismatch')
        if expected_request is not None and request!=_operation_request(expected_request):raise ValueError('request body mismatch')
        if body['request_digest']!='sha256:'+hashlib.sha256(canonical_operation_request(request)).hexdigest():raise ValueError('request digest mismatch')
        revision=body['agent_revision']
        if type(revision) is not int or revision!=request['expected_agent_revision']+1 or not 0<revision<2**64:raise ValueError('result generation mismatch')
        if body['previous_active_passport_id']!=request['expected_active_passport_id']:raise ValueError('previous pointer mismatch')
        result=body['result']
        result_fields={'action','passport_id','status','completed_ts','passport_payload_base64','passport_signature_base64',
                       'previous_passport_payload_base64','previous_passport_signature_base64'}
        if not isinstance(result,dict) or set(result)!=result_fields or result['action']!=request['action']:raise ValueError('unknown result format')
        if type(result['completed_ts']) is not int or result['completed_ts']<=0:raise ValueError('invalid completion time')
        def artifact(payload_field,signature_field,issuance_revision):
            payload=base64.b64decode(result[payload_field],validate=True)
            signature=base64.b64decode(result[signature_field],validate=True)
            subject=verify_envelope(payload,signature,current_key,issuance_revision,agent,trusted_public_keys=historical_public_keys)
            # All operation artifacts use the current closed canonical passport scope schema.
            scope_fields={'scope_id','action_class','resource_pattern','context_constraints','granted_ts','expires_ts','is_escalation'}
            if not isinstance(subject['scope_set'],list) or not subject['scope_set']:raise ValueError('empty passport scopes')
            if any(set(scope)!=scope_fields for scope in subject['scope_set']):raise ValueError('unknown passport scope fields')
            return subject
        if body['previous_active_passport_id']:
            previous=artifact('previous_passport_payload_base64','previous_passport_signature_base64',request['expected_agent_revision'])
            if previous['passport_id']!=body['previous_active_passport_id']:raise ValueError('previous artifact mismatch')
        elif result['previous_passport_payload_base64']!='' or result['previous_passport_signature_base64']!='':raise ValueError('unexpected prior artifact')
        if request['action']=='ISSUE':
            subject=artifact('passport_payload_base64','passport_signature_base64',revision)
            if subject['public_key_pem']!=signer:raise ValueError('issued artifact issuer mismatch')
            issue=request['issue']
            if result['status']!='ACTIVE' or body['active_passport_id']!=subject['passport_id'] or result['passport_id']!=subject['passport_id']:raise ValueError('issue result mismatch')
            if subject['passport_id']==body['previous_active_passport_id'] or (body['previous_active_passport_id'] and not issue['force_reissue']):raise ValueError('invalid replacement')
            if subject['passport_type']!=issue['passport_type'] or subject['issued_by']!=issue['issued_by'] or subject['reason']!=issue['reason']:raise ValueError('issued subject mismatch')
            if subject['issued_ts']!=result['completed_ts'] or subject['expires_ts']-subject['issued_ts']!=issue['ttl_seconds']*1000:raise ValueError('issued lifetime mismatch')
            if len(subject['scope_set'])!=len(issue['requested_scopes']):raise ValueError('issued scope count mismatch')
            for scope,wanted in zip(subject['scope_set'],issue['requested_scopes']):
                if any(scope[k]!=wanted[k] for k in ('action_class','resource_pattern','context_constraints')):raise ValueError('issued scope request mismatch')
                ttl=min(wanted['scope_ttl_seconds'] or issue['ttl_seconds'],issue['ttl_seconds'])
                if scope['granted_ts']!=subject['issued_ts'] or scope['expires_ts']-scope['granted_ts']!=ttl*1000 or scope['is_escalation']:raise ValueError('issued scope lifetime mismatch')
            authority={'subject':subject,'signature':result['passport_signature_base64'],'status':'ACTIVE','revision':revision}
        else:
            subject=artifact('passport_payload_base64','passport_signature_base64',request['expected_agent_revision'])
            if result['status']!='REVOKED' or body['active_passport_id']!='' or result['passport_id']!=request['revoke']['passport_id'] or subject['passport_id']!=result['passport_id']:raise ValueError('revoke result mismatch')
            if result['passport_payload_base64']!=result['previous_passport_payload_base64'] or result['passport_signature_base64']!=result['previous_passport_signature_base64']:raise ValueError('revoke predecessor mismatch')
            if result['completed_ts']<subject['issued_ts']:raise ValueError('revocation precedes issue')
            authority={'subject':None,'signature':None,'status':'REVOKED','revision':revision}
        return {**body,'authority':authority,'canonical_payload_base64':base64.b64encode(receipt.canonical_payload).decode(),
                'signature':base64.b64encode(receipt.signature).decode()}
    except Exception as exc:
        raise Denied('INVALID_OPERATION_RECEIPT') from exc

class PassportClient:
    def __init__(self,endpoint,mutation_token,public_key_pem,*,sdk_path,timeout_seconds=5,historical_public_keys=()):
        check_endpoint(endpoint)
        import grpc
        self.grpc=grpc;self.token=mutation_token;self.public_key=public_key_pem
        self.historical_public_keys=tuple(historical_public_keys)
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
        body=verify_envelope(payloads[0],p.signature,self.public_key,revision,agent,p,self.historical_public_keys)
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
        verified=verify_envelope(payloads[0],response.passport.signature,self.public_key,snapshot['revision'],agent,response.passport,self.historical_public_keys)
        if verified!=snapshot['subject']:raise Denied('AUTHORITY_UNCONFIRMED')
        return snapshot

    def _metadata(self,current):
        subject=current['subject']
        return [('authorization','Bearer '+self.token),
                ('x-are-expected-active-passport-id',subject['passport_id'] if subject else 'none'),
                ('x-are-expected-agent-revision',str(current['revision']))]

    def issue(self,agent,scopes,ttl_seconds,current,reason,operation_id=None):
        if operation_id is not None:
            request=issue_operation_request(agent,scopes,ttl_seconds,current,reason,operation_id)
            receipt=self._apply_operation(request)
            return {**receipt['authority'],'operation_receipt':receipt}
        request=self.pb.IssuePassportRequest(agent_id=agent,passport_type='STANDARD',
            requested_scopes=[self.pb.ScopeRequest(**s) for s in scopes],ttl_seconds=ttl_seconds,
            issued_by='earned-authority-coordinator',force_reissue=bool(current['subject']),reason=reason)
        try:
            response,call=self.stub.IssuePassport.with_call(request,metadata=self._metadata(current),timeout=self.timeout)
            return self._snapshot(response,call,agent)
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.FAILED_PRECONDITION: raise Denied('REVISION_CONFLICT') from exc
            raise Denied('AUTHORITY_UNCONFIRMED') from exc

    def revoke(self,current,reason,operation_id=None):
        if operation_id is not None:
            return self._apply_operation(revoke_operation_request(current,reason,operation_id))
        if not current['subject']: return current['revision']
        request=self.pb.RevokePassportRequest(passport_id=current['subject']['passport_id'],reason=reason,revoked_by='earned-authority-coordinator')
        try:
            response,call=self.stub.RevokePassport.with_call(request,metadata=self._metadata(current),timeout=self.timeout)
            if response.status!='REVOKED': raise Denied('AUTHORITY_UNCONFIRMED')
            return self._revision(list(call.initial_metadata() or ()))
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.FAILED_PRECONDITION: raise Denied('REVISION_CONFLICT') from exc
            raise Denied('AUTHORITY_UNCONFIRMED') from exc


    def _apply_operation(self,request):
        request=_operation_request(request)
        body=dict(operation_id=request['operation_id'],agent_id=request['agent_id'],
            expected_active_passport_id=request['expected_active_passport_id'],expected_agent_revision=request['expected_agent_revision'])
        if request['action']=='ISSUE':
            issue={**request['issue'],'requested_scopes':[self.pb.ScopeRequest(**s) for s in request['issue']['requested_scopes']]}
            body['issue']=self.pb.IssuePassportRequest(**issue)
        else:body['revoke']=self.pb.RevokePassportRequest(**request['revoke'])
        try:
            response,call=self.stub.ApplyPassportOperation.with_call(self.pb.ApplyPassportOperationRequest(**body),
                metadata=[('authorization','Bearer '+self.token)],timeout=self.timeout)
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.ALREADY_EXISTS:raise Denied('OPERATION_CONFLICT') from exc
            if exc.code()==self.grpc.StatusCode.FAILED_PRECONDITION:raise Denied('REVISION_CONFLICT') from exc
            raise Denied('AUTHORITY_UNCONFIRMED') from exc
        return verify_operation_receipt(response.receipt,self.public_key,request['agent_id'],request['operation_id'],request,historical_public_keys=getattr(self,'historical_public_keys',()),require_current_signer=True)

    def operation(self,agent,operation_id,expected_request=None):
        try:
            response,call=self.stub.GetPassportOperation.with_call(self.pb.GetPassportOperationRequest(agent_id=agent,operation_id=operation_id),
                metadata=[('authorization','Bearer '+self.token)],timeout=self.timeout)
        except self.grpc.RpcError as exc:
            if exc.code()==self.grpc.StatusCode.NOT_FOUND:return None
            raise Denied('AUTHORITY_UNCONFIRMED') from exc
        return verify_operation_receipt(response.receipt,self.public_key,agent,operation_id,expected_request,historical_public_keys=getattr(self,'historical_public_keys',()))
