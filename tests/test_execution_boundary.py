"""Actual local storage and cryptographic faults at the mutation boundary."""
import copy
import json
import sqlite3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from earned_authority.runtime import Runtime, Denied
from earned_authority.contracts import canonical_digest


@pytest.fixture
def rt(tmp_path):
    runtime=Runtime(tmp_path/'registry.sqlite')
    for i in range(3):runtime.shadow(attempt_id='shadow-'+str(i))
    q=runtime.qualify();runtime.grant(q['qualification_id'])
    return runtime


def assert_unchanged(rt):
    assert rt.mutation_count==0 and rt.read()['version']=='model-v1'
    assert not [r for r in rt.events() if r['event']['event_type'] in ('INTENT','COMMITTED')]


def test_readonly_transaction_refuses_before_mutation(rt):
    command=rt.admit();original=rt._db
    rt._db=lambda **kwargs:sqlite3.connect('file:'+rt.path+'?mode=ro',uri=True)
    try:
        with pytest.raises(Denied,match='^LOCAL_DURABILITY_UNAVAILABLE$'):rt.commit(command)
    finally:rt._db=original
    assert_unchanged(rt)
    assert rt.attempts(command['attempt_id'])['state']=='REQUESTED'


def test_replacement_writer_private_key_cannot_replace_verification_trust(rt):
    command=rt.admit();key=rt.keys['writer'];rt.keys['writer']=Ed25519PrivateKey.generate()
    try:
        with pytest.raises(Denied,match='^LOCAL_INTENT_UNAUTHENTICATED$'):rt.commit(command)
    finally:rt.keys['writer']=key
    assert_unchanged(rt)


@pytest.mark.parametrize('fault',['invalid-signature','different-valid-event'])
def test_exact_persisted_intent_is_authenticated_before_registry_write(rt,fault):
    command=rt.admit()
    with rt._db() as db:
        if fault=='invalid-signature':body="UPDATE events SET signature='AAAA' WHERE id=NEW.id;"
        else:body="UPDATE events SET body=(SELECT body FROM events WHERE id!=NEW.id ORDER BY rowid LIMIT 1),signature=(SELECT signature FROM events WHERE id!=NEW.id ORDER BY rowid LIMIT 1) WHERE id=NEW.id;"
        db.executescript("CREATE TRIGGER corrupt_intent AFTER INSERT ON events WHEN json_extract(NEW.body,'$.event_type')='INTENT' BEGIN "+body+" END;")
    with pytest.raises(Denied,match='^LOCAL_INTENT_UNAUTHENTICATED$'):rt.commit(command)
    assert_unchanged(rt)


def assert_unknown(result,command,committed=None,reason='RECONCILIATION_UNAVAILABLE'):
    assert result['state']=='UNKNOWN' and result['reason']==reason
    assert result['attempt_id']==command['attempt_id'] and result['request_digest']==command['request_digest']
    assert result['command_digest']==canonical_digest(command)
    assert result['committed'] is committed and result['outcome'] is None and result['receipt'] is None
    assert result['delivery']=='UNKNOWN' and result['persisted'] is False and result['next_action']=='RECONCILE'
    assert result['reexecution_permitted'] is False


def test_unavailable_retry_lookup_preserves_actual_commit_and_never_reexecutes(rt,tmp_path):
    command=rt.admit();actual=rt.commit(command);events=rt.events();original=rt._db
    rt._db=lambda **kwargs:sqlite3.connect('file:'+str(tmp_path/'missing'/'registry.sqlite')+'?mode=rw',uri=True)
    try:unknown=rt.retry(command)
    finally:rt._db=original
    assert_unknown(unknown,command)
    assert rt.attempts(command['attempt_id'])==actual and rt.events()==events and rt.mutation_count==1
    assert rt.retry(command)==actual and rt.mutation_count==1


def test_missing_attempt_cannot_be_created_by_retry(rt):
    command=rt.admit()
    with rt._db() as db:db.execute('DELETE FROM attempts WHERE id=?',(command['attempt_id'],))
    assert_unknown(rt.retry(command),command,reason='ATTEMPT_UNCONFIRMED')
    assert rt.attempts(command['attempt_id']) is None
    assert_unchanged(rt)


def test_commit_acknowledgement_failure_returns_unknown_not_false_denial(rt):
    command=rt.admit();original=rt._db
    class LostCommitAck(sqlite3.Connection):
        def commit(self):
            super().commit()
            raise sqlite3.OperationalError('local commit acknowledgement unavailable')
    rt._db=lambda **kwargs:sqlite3.connect(rt.path,factory=LostCommitAck)
    try:unknown=rt.commit(command)
    finally:rt._db=original
    assert_unknown(unknown,command)
    assert rt.mutation_count==1 and rt.attempts(command['attempt_id'])['state']=='COMMITTED'
    result=rt.retry(command)
    assert result['outcome']['outcome']=='PASS' and rt.mutation_count==1


def test_observer_storage_failure_after_commit_retains_known_commit(rt,tmp_path):
    command=rt.admit();original=rt.read
    def inaccessible(resource):
        return sqlite3.connect('file:'+str(tmp_path/'absent.sqlite')+'?mode=ro',uri=True)
    rt.read=inaccessible
    try:unknown=rt.commit(command)
    finally:rt.read=original
    assert_unknown(unknown,command,committed=True)
    actual=rt.attempts(command['attempt_id'])
    assert actual['state']=='COMMITTED' and actual['outcome'] is None and rt.mutation_count==1
    assert rt.retry(command)['outcome']['outcome']=='PASS' and rt.mutation_count==1


def test_outbox_write_failure_cannot_report_a_committed_attempt_as_denied(rt):
    command=rt.admit();original=rt._db
    def readonly_delivery():rt._db=lambda **kwargs:sqlite3.connect('file:'+rt.path+'?mode=ro',uri=True)
    try:unknown=rt.commit(command,before_delivery=readonly_delivery)
    finally:rt._db=original
    assert_unknown(unknown,command,committed=True)
    assert rt.attempts(command['attempt_id'])['outcome']['outcome']=='PASS' and rt.mutation_count==1
    assert rt.retry(command)['delivery']=='RECORDED' and rt.mutation_count==1


def test_retry_with_different_authenticated_payload_remains_a_conflict(rt):
    command=rt.admit();rt.commit(command)
    other=copy.deepcopy(command);other['target']='another-version';other=rt._seal(other,'authority')
    with pytest.raises(Denied,match='^IDEMPOTENCY_CONFLICT$'):rt.retry(other)
    assert rt.mutation_count==1


def test_postcommit_outcome_signature_failure_is_uncertainty_not_execution_denial(rt):
    command=rt.admit()
    with rt._db() as db:
        db.executescript("CREATE TRIGGER corrupt_outcome AFTER INSERT ON events WHEN json_extract(NEW.body,'$.event_type')='OUTCOME_OBSERVED' BEGIN UPDATE events SET signature='AAAA' WHERE id=NEW.id; END;")
    result=rt.commit(command)
    assert_unknown(result,command,committed=True)
    assert rt.mutation_count==1 and rt.attempts(command['attempt_id'])['outcome'] is None
    with rt._db() as db:db.execute('DROP TRIGGER corrupt_outcome')
    assert rt.retry(command)['outcome']['outcome']=='PASS' and rt.mutation_count==1
