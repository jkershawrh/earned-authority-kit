"""Stateful adapter/contract regressions; UNIT seams are not live-service evidence."""
import copy
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from earned_authority.connected import BINDING
from earned_authority.contracts import canonical_digest
from earned_authority.grants import (iter_grants, grants_for_skill, grant_by_id,
                                     select_grant, unique_grant, upsert_grant)
from earned_authority.runtime import Denied
from earned_authority.wire_contracts import export_runtime, consume_bundle, RuntimeTrust, WireContractError
import test_authority_journal as journal
Crash=journal.Crash


class MultiResourceGrants(unittest.TestCase):
    setUp = journal.AuthorityJournalTests.setUp
    runtime = journal.AuthorityJournalTests.runtime
    qualify = journal.AuthorityJournalTests.qualify
    events = journal.AuthorityJournalTests.events

    def ready(self, distinct=False):
        self.read = self.qualify('read-health')
        self.rt.grant(self.read['qualification_id'],action='read',resource='urn:health/a')
        second=self.qualify('read-health',model='model-v3') if distinct else self.read
        self.second=second
        return self.rt.grant(second['qualification_id'],action='read',resource='urn:health/b')

    def read_command(self,resource='urn:health/a',qualification=None,**kwargs):
        q=qualification or self.read
        return self.rt.admit(skill='read-health',version=q['version'],context=q['context'],
                             action='read',resource=resource,**kwargs)

    def test_add_resource_preserves_full_original_binding_and_expiry(self):
        q=self.qualify('read-health')
        before=self.rt.grant(q['qualification_id'],action='read',resource='urn:health/a')
        original=copy.deepcopy(unique_grant(before,'read-health'));self.clock.advance(125)
        after=self.rt.grant(q['qualification_id'],action='read',resource='urn:health/b')
        preserved=grant_by_id(after,original['grant_id'])
        self.assertEqual({k:v for k,v in original.items() if k!='canonical_scope_id'},
                         {k:v for k,v in preserved.items() if k!='canonical_scope_id'})
        self.assertEqual(before['revision']+1,after['revision'])
        self.assertEqual(2,len(grants_for_skill(after,'read-health')))

    def test_both_resources_execute_with_their_exact_grant(self):
        self.ready();commands=[self.read_command(r) for r in ('urn:health/a','urn:health/b')]
        self.assertNotEqual(commands[0]['grant_id'],commands[1]['grant_id'])
        for command in commands:self.assertEqual('PASS',self.rt.commit(command)['outcome']['outcome'])
        self.assertEqual(0,self.rt.mutation_count)

    def test_command_cannot_borrow_other_resource_grant(self):
        a=self.ready();command=self.read_command()
        command['grant_id']=select_grant(a,skill='read-health',version=self.read['version'],
            context=self.read['context'],action='read',resource='urn:health/b')['grant_id']
        with self.assertRaises(Denied):self.rt._check(None,command,a['revision'])

    def test_exact_selection_rejects_wrong_dimensions(self):
        self.ready()
        for change in ({'action':'release'},{'resource':'urn:health/*'},
                       {'context':{'model_version':'elsewhere'}},{'version':'old'}):
            intent=self.read_command();intent.update(change)
            with self.subTest(change=change),self.assertRaises(Denied):self.rt._check(None,intent)

    def test_old_executable_retains_exact_revision_denial(self):
        self.ready();intent=self.read_command();intent['version']='old-executable'
        with self.assertRaisesRegex(Denied,'SKILL_REVISION_MISMATCH'):self.rt._check(None,intent)

    def test_typed_context_does_not_equate_boolean_and_integer(self):
        a=self.ready();g=iter_grants(a)[0]
        altered=copy.deepcopy(g);altered['context']={'enabled':True}
        altered['context_digest']=canonical_digest({'environment':altered['context']})
        with self.assertRaises(Denied):select_grant({'grants':[altered]},skill=g['skill'],version=g['version'],
            context={'enabled':1},action=g['action'],resource=g['resource'])

    def test_same_slot_replaces_only_that_resource(self):
        before=self.ready();first=select_grant(before,skill='read-health',version=self.read['version'],
            context=self.read['context'],action='read',resource='urn:health/a')
        sibling=select_grant(before,skill='read-health',version=self.read['version'],
            context=self.read['context'],action='read',resource='urn:health/b')
        fresh=self.qualify('read-health')
        after=self.rt.grant(fresh['qualification_id'],action='read',resource='urn:health/a')
        self.assertIsNone(grant_by_id(after,first['grant_id']))
        preserved=grant_by_id(after,sibling['grant_id'])
        self.assertEqual(sibling['expires_at_ms'],preserved['expires_at_ms'])
        self.assertEqual(2,len(iter_grants(after)))

    def test_version_change_cannot_coexist_in_one_logical_slot(self):
        a=self.ready();old=iter_grants(a)[0];new=copy.deepcopy(old)
        new.update(grant_id='replacement',version='next')
        new['skill_digest']=canonical_digest({'skill':new['skill'],'version':new['version']})
        result=upsert_grant(a,new)
        self.assertEqual(2,len(result));self.assertIsNone(grant_by_id({'grants':result},old['grant_id']))

    def test_duplicate_grant_scope_and_slot_denied(self):
        self.ready();raw=self.passport.current('agent-a')
        for variant in ('grant_id','scope_id','slot'):
            bad=copy.deepcopy(raw);scopes=bad['subject']['scope_set']
            if variant=='scope_id':scopes[1]['scope_id']=scopes[0]['scope_id']
            else:
                first=json.loads(scopes[0]['context_constraints'][BINDING]);second=json.loads(scopes[1]['context_constraints'][BINDING])
                if variant=='grant_id':second['grant_id']=first['grant_id']
                else:second['resource']=first['resource'];scopes[1]['resource_pattern']=first['resource']
                scopes[1]['context_constraints'][BINDING]=json.dumps(second)
            with self.subTest(variant=variant),self.assertRaises(Denied):self.rt._normalize(bad,'agent-a')

    def test_digest_and_outer_scope_mismatches_denied(self):
        self.ready();raw=self.passport.current('agent-a')
        for variant in ('context_digest','skill_digest','resource_pattern','action_class'):
            bad=copy.deepcopy(raw);scope=bad['subject']['scope_set'][0]
            if variant in ('resource_pattern','action_class'):scope[variant]='wrong'
            else:
                g=json.loads(scope['context_constraints'][BINDING]);g[variant]='wrong';scope['context_constraints'][BINDING]=json.dumps(g)
            with self.subTest(variant=variant),self.assertRaises(Denied):self.rt._normalize(bad,'agent-a')

    def test_skill_only_lookup_denies_ambiguity(self):
        with self.assertRaisesRegex(Denied,'AMBIGUOUS_GRANT'):unique_grant(self.ready(),'read-health')

    def test_stale_update_then_fresh_recompute_preserves_release_revocation(self):
        self.rt.grant(self.q['qualification_id']);self.ready()
        self.rt.grant(self.q['qualification_id']);self.assertEqual(4,self.rt.authority()['revision'])
        revoked=self.rt.revoke(skill='release-model');issues=self.passport.issues
        with self.assertRaisesRegex(Denied,'REVISION_CONFLICT'):
            self.rt.grant(self.read['qualification_id'],action='read',resource='urn:health/c',expected_revision=4,operation_id='stale')
        self.assertEqual(issues,self.passport.issues);self.assertEqual(5,revoked['revision'])
        after=self.rt.grant(self.read['qualification_id'],action='read',resource='urn:health/c',expected_revision=5,operation_id='fresh')
        self.assertEqual(6,after['revision']);self.assertFalse(grants_for_skill(after,'release-model'))
        self.assertEqual(3,len(grants_for_skill(after,'read-health')))

    def test_concurrent_expected_revision_has_one_winner(self):
        before=self.ready()
        def grant(resource):
            try:return self.rt.grant(self.read['qualification_id'],action='read',resource=resource,expected_revision=before['revision'])
            except Denied as exc:return exc.reason
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(grant,['urn:health/c','urn:health/d']))
        self.assertEqual(1,sum(isinstance(r,dict) for r in results));self.assertIn('REVISION_CONFLICT',results)
        self.assertEqual(3,len(iter_grants(self.rt.authority())))

    def test_skill_wide_revoke_preserves_other_skill(self):
        self.rt.grant(self.q['qualification_id']);a=self.ready()
        unrelated=unique_grant(a,'release-model');removed=list(grants_for_skill(a,'read-health'))
        after=self.rt.revoke(skill='read-health')
        self.assertFalse(grants_for_skill(after,'read-health'))
        self.assertEqual(unrelated['expires_at_ms'],unique_grant(after,'release-model')['expires_at_ms'])
        event=self.events('REVOKED')[-1];self.assertEqual(removed,event['removed_targets'])
        self.assertEqual(removed,event['authority_intent']['removed_targets'])

    def test_delayed_replaced_anchor_does_not_remove_sibling(self):
        before=self.ready();old=iter_grants(before)[0]
        self.rt.grant(self.read['qualification_id'],action='read',resource=old['resource'])
        current=self.rt.authority()
        result=self.rt.revoke(skill='read-health',target_grant_id=old['grant_id'],target_qualification_id=old['qualification_id'])
        self.assertEqual(current,result);self.assertEqual('TARGET_NOT_CURRENT',self.events('WITHDRAWAL_RECONCILED')[-1]['status'])

    def test_incomplete_or_invalid_withdrawal_anchor_cannot_revoke(self):
        current=self.ready();g=iter_grants(current)[0];events=copy.deepcopy(self.rt.events())
        for pair in ((None,g['qualification_id']),(g['grant_id'],None),('',g['qualification_id']),
                     (g['grant_id'],''),(7,g['qualification_id']),(g['grant_id'],True)):
            with self.subTest(pair=pair),self.assertRaisesRegex(Denied,'WITHDRAWAL_BINDING_MISSING'):
                self.rt.revoke(skill='read-health',target_grant_id=pair[0],target_qualification_id=pair[1])
            self.assertEqual(current,self.rt.authority());self.assertEqual(events,self.rt.events())

    def test_two_queued_causes_retained_when_one_anchor_replaced(self):
        before=self.ready();old,sibling=iter_grants(before)
        self.rt.grant(self.read['qualification_id'],action='read',resource=old['resource'])
        with self.rt._tx() as db:
            for g in (old,sibling):db.execute('INSERT INTO withdrawal_causes VALUES (?,?,?,?,?,?)',
                ('agent-a','read-health','cause-'+g['grant_id'],'KNOWN_FAILURE',g['grant_id'],g['qualification_id']))
        self.rt.drain_withdrawals()
        self.assertFalse(grants_for_skill(self.rt.authority(),'read-health'))
        self.assertEqual(1,len(self.events('WITHDRAWAL_RECONCILED')))
        with self.rt._db() as db:self.assertEqual(0,db.execute('SELECT COUNT(*) FROM withdrawal_causes').fetchone()[0])

    def test_legacy_queue_migrates_without_losing_binding(self):
        a=self.ready();g=iter_grants(a)[0]
        with self.rt._tx() as db:db.execute('INSERT INTO withdrawals VALUES (?,?,?,?,?,?)',
            ('agent-a','read-health','legacy','KNOWN_FAILURE',g['grant_id'],g['qualification_id']))
        self.rt=self.runtime()
        with self.rt._db() as db:
            self.assertEqual(1,db.execute('SELECT COUNT(*) FROM withdrawal_causes').fetchone()[0])
            self.assertEqual(0,db.execute('SELECT COUNT(*) FROM withdrawals').fetchone()[0])
        self.rt.drain_withdrawals();self.assertFalse(iter_grants(self.rt.authority()))

    def test_audit_bad_second_qualification_removes_all_siblings(self):
        self.ready(distinct=True)
        with self.rt._tx() as db:db.execute('DELETE FROM observations WHERE attempt_id=?',(self.second['outcome_refs'][0]['attempt_id'],))
        result=self.rt.audit_qualification_evidence(skill='read-health')
        self.assertTrue(result['requires_hold']);self.assertEqual(2,len(result['inspected_grants']))
        self.assertFalse(iter_grants(self.rt.authority()))

    def test_audit_all_good_distinct_qualifications(self):
        self.ready(distinct=True);result=self.rt.audit_qualification_evidence(skill='read-health')
        self.assertTrue(result['verified']);self.assertEqual(2,len(result['inspected_grants']))

    def test_reevaluate_holds_both_distinct_qualifications(self):
        self.ready(distinct=True);self.rt.reevaluate(skill='read-health')
        self.assertFalse(iter_grants(self.rt.authority()))
        for q in (self.read,self.second):self.assertEqual('HOLD',self.rt.qualification(q['qualification_id'])['disposition'])

    def test_hold_diagnostic_covers_each_removed_resource(self):
        self.ready();self.rt.reevaluate(skill='read-health')
        for resource in ('urn:health/a','urn:health/b'):
            with self.subTest(resource=resource),self.assertRaisesRegex(Denied,'EVIDENCE_UNCONFIRMED'):self.read_command(resource)

    def test_hold_diagnostic_requires_exact_typed_context(self):
        context={**self.q['context'],'enabled':True}
        from test_connected_security import bound_unit_qualification
        q=bound_unit_qualification(self.rt,'read-health',context,300000)
        self.rt.grant(q['qualification_id'],action='read',resource='urn:health/a')
        self.rt.reevaluate(skill='read-health')
        with self.assertRaisesRegex(Denied,'REVOKED_AUTHORITY'):
            self.rt.admit(skill='read-health',version=q['version'],context={**context,'enabled':1},
                          action='read',resource='urn:health/a')

    def test_noninteger_inner_expiry_cannot_hide_behind_outer_cap(self):
        self.ready();raw=self.passport.current('agent-a');scope=raw['subject']['scope_set'][0]
        g=json.loads(scope['context_constraints'][BINDING]);g['expires_at_ms']=float(raw['subject']['expires_ts']+1)
        scope['context_constraints'][BINDING]=json.dumps(g)
        with self.assertRaisesRegex(Denied,'BINDING_MISMATCH'):self.rt._normalize(raw,'agent-a')

    def test_reevaluation_cannot_weaken_confirmed_failure_during_outage(self):
        self.rt.grant(self.q['qualification_id'])
        self.rt.qualifier=SimpleNamespace(evaluate=lambda q,*args,**kwargs:{'cascade':{}})
        command=self.rt.admit(version=self.q['version'],context=self.q['context'],resource='model/champion')
        self.passport.lookup_available=False
        with self.assertRaises(Denied):self.rt.commit(command,actual='wrong-model')
        before=self.rt.qualification(self.q['qualification_id'])
        self.assertEqual(('INELIGIBLE','KNOWN_FAILURE'),(before['disposition'],before['reason']))
        with self.assertRaises(Denied):self.rt.reevaluate(state='STALE')
        self.assertEqual(before,self.rt.qualification(self.q['qualification_id']))

    def test_lost_response_restart_recovers_both_without_double_revision(self):
        q=self.qualify('read-health');self.rt.grant(q['qualification_id'],action='read',resource='urn:health/a')
        def crash(stage,operation):
            if stage=='remote_committed':raise Crash(stage)
        self.rt.authority_checkpoint=crash
        with self.assertRaises(Crash):self.rt.grant(q['qualification_id'],action='read',resource='urn:health/b',operation_id='lost')
        revision=self.passport.state['revision'];self.rt=self.runtime();self.rt.recover_authority_intents()
        self.assertEqual(revision,self.passport.state['revision']);self.assertEqual(2,len(iter_grants(self.rt.authority())))
        self.assertEqual(2,len(self.events('GRANTED')))

    def test_complete_wire_export_has_both_grants_qualifications_and_attempts(self):
        self.ready(distinct=True);commands=[self.read_command(),self.read_command('urn:health/b',self.second)]
        for command in commands:self.rt.commit(command)
        self.rt.flush_outbox()
        self.passport.state["subject"]["issued_by"]="unit-issuer"
        bundle=export_runtime(self.rt,attempt_ids=[c['attempt_id'] for c in commands])
        authority=next(r for r in bundle.records if r['kind']=='authority')
        self.assertEqual(2,len(authority['value']['grants']))
        self.assertEqual({self.read['qualification_id'],self.second['qualification_id']},
            {r['value']['qualification_id'] for r in bundle.records if r['kind']=='qualification'})
        self.assertTrue(consume_bundle(bundle,trust=RuntimeTrust(self.rt),now_ms=self.clock.now_ms)['verified'])
        missing=copy.deepcopy(bundle);missing.records=[r for r in missing.records if r['kind']!='qualification' or r['value']['qualification_id']!=self.second['qualification_id']]
        with self.assertRaises(WireContractError):consume_bundle(missing,trust=RuntimeTrust(self.rt),now_ms=self.clock.now_ms)

    def test_procedure_revision_includes_grant_selection_source(self):
        from pathlib import Path
        import hashlib
        import earned_authority.connected as module
        source=Path(module.__file__)
        expected=canonical_digest({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
            (source,source.with_name('runtime.py'),source.with_name('authority_journal.py'),source.with_name('evidence_admission.py'),source.with_name('grants.py'))})
        self.assertEqual(expected,self.rt.procedure_revision)
