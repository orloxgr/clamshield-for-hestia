"""Review pagination, native generation isolation and confirmed bulk log controls."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from clamshield.application import Application
from clamshield.errors import AccessDenied,ClamShieldError,Conflict
from clamshield.hestia import Hestia
from clamshield.review import Review,SPECS
from clamshield.settings import Settings
from clamshield.store import Store,encode
from clamshield.exceptions import Exceptions


class ReviewTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.base=Path(folder.name);self.settings=Settings(state=self.base/'state');self.settings.prepare()
        self.store=Store(self.settings.database);self.ids={name:name+'-generation' for name in ('admin','alice','bob')}
        self.hestia=Hestia();self.hestia.identity=lambda owner:self.ids[owner];self.hestia.call=Mock(side_effect=self.call)
        for owner in self.ids:(self.base/owner).mkdir()
        self.admin=self.hestia.authorize('admin');self.alice=self.hestia.authorize('alice');self.bob=self.hestia.authorize('bob')
        self.review=Review(self.settings,self.store,self.hestia);self.app=Application(self.settings,self.store,self.hestia)

    def call(self,command,*args):
        if command=='v-list-user':return {args[0]:dict(ROLE='admin' if args[0]=='admin' else 'user',SUSPENDED='no')}
        if command=='v-list-users':return {owner:dict(ROLE='admin' if owner=='admin' else 'user',SUSPENDED='no') for owner in self.ids}
        if command=='v-list-web-domains':return {args[0]+'.test':dict(DOCUMENT_ROOT=str(self.base/args[0]))}
        raise AssertionError(command)

    def page(self,kind,context=None,scope='account',filters=None,**values):
        return self.review.query(context or self.alice,kind,scope,filters or {},**values)

    def notice(self,context,event='scan.malware_found',subject='alice.test',created=None):
        self.store.notify(context['owner'],context['identity'],event,subject,{'message':'Fixture'},subject+':'+event)
        with self.store.connection() as db:
            row=db.execute('SELECT id FROM notifications WHERE owner=? AND identity=? AND event=? AND subject=?',(*self.store.scope(context),event,subject)).fetchone()
            if created is not None:db.execute('UPDATE notifications SET created=? WHERE id=?',(created,row[0]))
        return row[0]

    def findings(self,count=130,context=None):
        context=context or self.alice;site=dict(owner=context['owner'],identity=context['identity'],domain=context['owner']+'.test',root=str(self.base/context['owner']))
        job=self.store.enqueue(context,site);claimed=self.store.claim('fixture')
        for i in range(count):self.store.add_finding(claimed,'uploads/file-'+str(i)+'.php',{'sha256':'a'*64},dict(engine='clamav' if i%2 else 'yara',provider='official' if i%2 else 'local',signature='Fixture'+str(i)))
        return job

    def test_every_review_list_has_bounded_queries_and_options(self):
        for kind in SPECS:
            with self.subTest(kind=kind):
                value=self.page(kind,self.admin,'server')
                self.assertEqual(0,value['total']);self.assertEqual([],value['records']);self.assertIsNone(value['next_offset'])
                self.assertEqual(50,value['limit']);self.assertIn('type',value['options'])

    def test_pages_reach_beyond_old_preview_limits_without_duplicates(self):
        self.findings(560)
        ids=[]
        for offset in range(0,600,100):
            result=self.page('findings',offset=offset,limit=100);ids.extend(row['id'] for row in result['records'])
            self.assertEqual(560,result['total']);self.assertLessEqual(len(result['records']),100)
        self.assertEqual(560,len(ids));self.assertEqual(560,len(set(ids)))
        self.assertEqual(500,self.page('findings',offset=999999,limit=100)['offset'])

    def test_search_engine_provider_account_and_dates_filter_before_pagination(self):
        self.findings(56)
        value=self.page('findings',filters={'type':'yara','provider':'local','search':'uploads/file-2'})
        self.assertGreater(value['total'],0);self.assertTrue(all(row['engine']=='yara' and row['provider']=='local' and 'file-2' in row['path'] for row in value['records']))
        self.assertEqual(0,self.page('findings',filters={'from':'2099-01-01'})['total'])
        self.assertEqual(0,self.page('findings',filters={'to':'2000-01-01'})['total'])
        with self.assertRaises(AccessDenied):self.page('findings',filters={'account':'bob'})
        value=self.page('findings',self.admin,'server',{'account':'alice'})
        self.assertEqual(56,value['total']);self.assertIn('bob',value['accounts'])

    def test_removed_rule_source_is_labelled_in_paged_findings_without_rewriting_original_evidence(self):
        self.findings(1);finding=self.page('findings')['records'][0]
        with self.store.connection() as db:db.execute("UPDATE findings SET provider='php-hosting' WHERE id=?",(finding['id'],))
        self.assertTrue(self.page('findings')['records'][0]['detail']['source_removed'])
        self.assertNotIn('source_removed',self.store.finding(self.alice,finding['id'])['detail'])

    def test_global_and_recreated_account_scope_never_reveal_old_identity_records(self):
        self.notice(self.alice);self.notice(self.bob);self.notice(dict(owner='@admin',identity=''))
        self.assertEqual(1,self.page('notices')['total']);self.assertEqual(3,self.page('notices',self.admin,'server')['total'])
        with self.assertRaises(AccessDenied):self.page('notices',self.alice,'server')
        self.ids['alice']='recreated';fresh=self.hestia.authorize('alice')
        self.assertEqual(0,self.page('notices',fresh)['total']);self.assertEqual(2,self.page('notices',self.admin,'server')['total'])
        with self.assertRaises(AccessDenied):self.page('notices',self.alice)

    def test_notification_category_and_unread_filters_are_server_side(self):
        self.notice(self.alice,'health.problem','engine');target=self.notice(self.alice,'scan.malware_found','site')
        self.assertEqual(1,self.page('notices',filters={'categories':['detections'],'status':'unread'})['total'])
        self.store.read_notification(self.alice,target)
        self.assertEqual(0,self.page('notices',filters={'categories':['detections'],'status':'unread'})['total'])
        self.assertEqual(0,self.page('notices',filters={'categories':[]})['total'])

    def test_bulk_read_affects_only_current_scope_and_keeps_bell_receipts(self):
        self.notice(self.alice);self.notice(self.bob)
        self.assertEqual(1,self.review.bulk(self.alice,'notices','account','read')['changed'])
        self.assertEqual(0,self.page('notices',filters={'status':'unread'})['total'])
        self.assertEqual(1,self.page('notices',self.bob,filters={'status':'unread'})['total'])
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'notices','server','read')

    def test_confirmed_notification_clear_keeps_new_notices_and_deduplication(self):
        old=self.notice(self.alice,subject='old');proof=self.review.bulk(self.alice,'notices','account','preview')
        self.assertEqual(1,proof['count']);new=self.notice(self.alice,subject='new')
        self.assertEqual(1,self.review.bulk(self.alice,'notices','account','clear',proof['token'])['changed'])
        self.assertEqual([new],[r['id'] for r in self.page('notices')['records']]);self.assertEqual([new],[r['id'] for r in self.store.notifications(self.alice)])
        self.notice(self.alice,subject='old');self.assertEqual(1,self.page('notices')['total'])
        with self.store.connection() as db:self.assertIsNotNone(db.execute('SELECT read_at FROM notifications WHERE id=?',(old,)).fetchone()[0])
        with self.assertRaises(Conflict):self.review.bulk(self.alice,'notices','account','clear',proof['token'])

    def test_history_clear_hides_events_without_deleting_recovery_or_findings(self):
        job=self.findings(1);before=self.page('history')['total'];self.assertGreater(before,0)
        proof=self.review.bulk(self.alice,'history','account','preview')
        self.review.bulk(self.alice,'history','account','clear',proof['token'])
        self.assertEqual(0,self.page('history')['total']);self.assertEqual([],self.store.history(self.alice))
        self.assertEqual(1,len(self.store.list_findings(self.alice)));self.assertEqual(job,self.store.job(self.alice,job)['id'])
        with self.store.connection() as db:self.assertGreater(db.execute('SELECT count(*) FROM audit').fetchone()[0],0)

    def test_confirmation_is_bound_to_actor_kind_scope_native_identities_and_expiry(self):
        self.notice(self.alice);proof=self.review.bulk(self.admin,'notices','server','preview')
        with self.assertRaises(Conflict):self.review.bulk(self.bob,'notices','account','clear',proof['token'])
        with self.assertRaises(Conflict):self.review.bulk(self.admin,'history','server','clear',proof['token'])
        self.ids['bob']='replaced'
        with self.assertRaises(Conflict):self.review.bulk(self.admin,'notices','server','clear',proof['token'])
        proof=self.review.bulk(self.alice,'notices','account','preview')
        with patch('clamshield.review_bulk.time.time',return_value=99999999999):
            with self.assertRaises(Conflict):self.review.bulk(self.alice,'notices','account','clear',proof['token'])

    def test_history_delegation_denies_preview_and_clear_and_never_widens_tenant_scope(self):
        with self.store.connection() as db:db.execute('INSERT INTO history_permissions VALUES(?,?,?,?)',('alice',self.alice['identity'],0,'revision'))
        self.assertFalse(self.page('history')['can_clear'])
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'history','account','preview')
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'history','account','clear','forged')

    def test_invalid_identifiers_filters_dates_and_limits_are_rejected(self):
        for kind,fields in [('bad',{}),('history',{'limit':500}),('history',{'offset':True}),('history',{'filters':{'from':'invalid'}}),('history',{'filters':{'order':'id DESC; DELETE FROM jobs'}}),('notices',{'filters':{'categories':['made-up']}}),('history',{'filters':{'unknown':'x'}})]:
            with self.subTest(kind=kind,fields=fields),self.assertRaises(ClamShieldError):self.page(kind,**fields)
        with self.assertRaises(AccessDenied):self.page('activity',self.alice)

    def test_native_application_dispatch_does_not_trust_browser_role_or_identity(self):
        self.notice(self.alice);result=self.app.dispatch(dict(actor='alice',action='review-list',list='notices',filters={},scope='account'))
        self.assertEqual(1,result['total'])
        with self.assertRaises(AccessDenied):self.app.dispatch(dict(actor='alice',admin=True,identity='admin-generation',action='review-list',list='notices',filters={},scope='server'))

    def test_selected_findings_clear_exact_snapshot_without_deleting_detection_evidence(self):
        self.findings(3);admin=self.hestia.authorize('admin','alice')
        rows=self.page('findings')['records'];selected=[rows[0]['id']]
        proof=self.review.bulk(admin,'findings','account','preview',selected=selected)
        self.assertEqual(1,proof['count']);self.store.add_finding(self.store.job(self.alice,rows[0]['job_id']),'new.php',{'sha256':'b'*64},dict(engine='yara',provider='local',signature='NewFixture'))
        self.assertEqual(1,self.review.bulk(admin,'findings','account','clear',proof['token'])['changed'])
        self.assertEqual(3,self.page('findings')['total']);self.assertEqual(3,self.store.dashboard_counts(self.alice)['open_findings']);self.assertEqual('open',self.store.finding(self.alice,selected[0])['status'])
        data=dict(findings=rows);self.review.hide_deleted_previews(data);self.assertEqual(2,len(data['findings']))
        for values in ([],['missing'],[rows[1]['id']]*2):
            with self.assertRaises(ClamShieldError):self.review.bulk(admin,'findings','account','preview',selected=values)
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'findings','account','preview')

    def test_activity_clearing_keeps_running_work_and_rechecks_status_after_preview(self):
        ids=[self.store.enqueue_task(self.alice,'fixture',{'n':n}) for n in range(3)]
        with self.store.connection() as db:db.execute("UPDATE maintenance SET status='completed' WHERE id IN (?,?)",ids[:2])
        proof=self.review.bulk(self.admin,'activity','server','preview');self.assertEqual(2,proof['count']);self.assertEqual(1,proof['retained'])
        with self.store.connection() as db:db.execute("UPDATE maintenance SET status='running' WHERE id=?",(ids[0],))
        self.assertEqual(1,self.review.bulk(self.admin,'activity','server','clear',proof['token'])['changed'])
        rows=self.page('activity',self.admin,'server')['records'];self.assertEqual(set(ids[::2]),{row['id'] for row in rows})

    def test_removing_all_exceptions_disables_them_without_affecting_other_accounts(self):
        self.findings(1);finding=self.page('findings')['records'][0]['id'];exception=Exceptions(self.store).add(self.alice,finding)
        admin=self.hestia.authorize('admin','alice');proof=self.review.bulk(admin,'exceptions','account','preview')
        self.assertEqual(1,self.review.bulk(admin,'exceptions','account','clear',proof['token'])['changed']);self.assertEqual(0,self.page('exceptions')['total'])
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT enabled FROM exceptions WHERE id=?',(exception,)).fetchone()[0])

    def test_quarantine_batches_report_failures_keep_new_records_and_preserve_recovery(self):
        import uuid
        self.findings(1);finding=self.page('findings')['records'][0]['id'];ids=[uuid.uuid4().hex for _ in range(12)]
        with self.store.connection() as db:
            for index,ident in enumerate(ids):db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)',(ident,finding,*self.store.scope(self.alice),'alice','quarantine','restoring' if index==11 else 'quarantined',1,encode(dict(root=str(self.base/'alice'),path='fixture.php')),None))
        admin=self.hestia.authorize('admin','alice');proof=self.review.bulk(admin,'quarantine','account','preview')
        self.assertEqual(11,proof['count']);self.assertEqual(1,proof['retained'])
        def delete(context,ident):
            self.assertEqual('alice',context['owner']);self.assertEqual(self.alice['identity'],context['identity'])
            if ident==ids[0]:raise Conflict('Changed private content retained')
        with patch('clamshield.quarantine.Quarantine.delete',side_effect=delete) as action:
            first=self.review.bulk(admin,'quarantine','account','clear',proof['token']);self.assertTrue(first['pending']);self.assertEqual(5,action.call_count)
            result=first
            while result['pending']:result=self.review.bulk(admin,'quarantine','account','clear',proof['token'])
        self.assertEqual(10,result['changed']);self.assertEqual(1,result['failed']);self.assertEqual(2,self.page('quarantine')['total'])
        with self.store.connection() as db:self.assertEqual(0,db.execute('SELECT count(*) FROM review_confirmation_items').fetchone()[0])

    def test_selected_notifications_cannot_clear_another_account_and_keep_new_items(self):
        target=self.notice(self.alice);other=self.notice(self.bob)
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'notices','account','preview',selected=[other])
        proof=self.review.bulk(self.alice,'notices','account','preview',selected=[target]);new=self.notice(self.alice,subject='new')
        self.review.bulk(self.alice,'notices','account','clear',proof['token']);self.assertEqual([new],[row['id'] for row in self.page('notices')['records']])

    @unittest.skipUnless(shutil.which('php'),'PHP renderer')
    def test_shared_php_fragments_render_all_lists_and_escape_notifications(self):
        self.notice(self.alice,subject='<img src=x onerror=alert(1)>');job=self.findings(1)
        owner,identity=self.store.scope(self.alice);root=str(self.base/owner)
        with self.store.connection() as db:
            finding=db.execute('SELECT id FROM findings WHERE job_id=?',(job,)).fetchone()[0]
            def insert(table,**fields):
                db.execute('INSERT INTO '+table+' ('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',list(fields.values()))
            insert('repair_plans',id=job,finding_id=finding,owner=owner,identity=identity,actor=owner,status='ready',created=1,metadata='{}')
            insert('operations',id='operation',finding_id=finding,owner=owner,identity=identity,actor=owner,kind='quarantine',status='quarantined',created=1,metadata=encode(dict(root=root,path='uploads/fixture.php')))
            insert('exceptions',id='exception',owner=owner,identity=identity,actor=owner,domain='alice.test',root=root,path='fixture.php',kind='file',engine='yara',signature='Fixture',sha256='a'*64,note='Fixture',created=1)
            insert('remediation_actions',id='automatic',owner=owner,identity=identity,actor=owner,job_id=job,finding_id=finding,path='fixture.php',status='quarantined',created=1,updated=1,detail=encode(dict(policy=dict(mode='quarantine'),operation_id='operation')))
            insert('maintenance',id='task',owner=owner,identity=identity,actor=owner,action='signatures-update',payload='{}',created=1)
            insert('mail_transactions',id='transaction',exim_id='fixture-exim',created=1,updated=1,status='committed',sha256='a'*64,size=1,metadata=encode(dict(summary={'Subject':'<img src=subject>'},envelope={'sender':'sender@site.test'})))
            insert('mail_recipients',id='recipient',transaction_id='transaction',owner=owner,identity=identity,domain='alice.test',mailbox='inbox',recipient='inbox@alice.test',action='quarantine',status='quarantined',created=1,updated=1,detail='{}')
            insert('mail_decisions',id='decision',owner=owner,identity=identity,domain='alice.test',mailbox='inbox',recipient='inbox@alice.test',sender='sender@site.test',exim_id='fixture-exim',created=1,sha256='a'*64,action='tag',classification='clean',detail='{}')
        renderer=Path(__file__).resolve().parents[1]/'panel/review_render.php'
        code="set_error_handler(function($s,$m){throw new ErrorException($m,0,$s);});$data=json_decode(stream_get_contents(STDIN),true);$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];"
        for kind in SPECS:
            value=self.page(kind,self.admin,'server')
            self.assertGreater(value['total'],0,kind)
            result=subprocess.run(['php','-d','display_errors=stderr','-r',code,str(renderer)],input=encode(value),capture_output=True,text=True)
            self.assertEqual(0,result.returncode,result.stderr);self.assertEqual('',result.stderr,kind)
            if kind=='notices':self.assertIn('&lt;img',result.stdout);self.assertNotIn('<img',result.stdout)
            if kind in ('email-stored','email-messages'):self.assertIn('Deliver anyway',result.stdout);self.assertIn('&lt;img',result.stdout);self.assertNotIn('<img',result.stdout)

    def email(self,key='one',owner='alice',status='delivered',stored=True,**changes):
        with self.store.connection() as db:
            def insert(table,fields):
                db.execute('INSERT INTO '+table+' ('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',list(fields.values()))
            decision=dict(id='decision-'+key,owner=owner,identity=self.ids[owner],domain=owner+'.test',mailbox='inbox',recipient='inbox@'+owner+'.test',exim_id='exim-'+key,sender='sender@remote.test',created=2,sha256='a'*64,action='junk',classification='spam',detail='{}')
            decision.update(changes);insert('mail_decisions',decision)
            if stored:
                insert('mail_transactions',dict(id='transaction-'+key,exim_id='exim-'+key,created=1,updated=1,status='committed',sha256='a'*64,size=7,metadata=encode(dict(summary={'Subject':'Sample '+key},envelope={'sender':'sender@remote.test'}))))
                insert('mail_recipients',dict(id='recipient-'+key,transaction_id='transaction-'+key,owner=owner,identity=self.ids[owner],domain=owner+'.test',mailbox='inbox',recipient='inbox@'+owner+'.test',action='junk',status=status,created=1,updated=1,detail='{}'))
        return 'stored:recipient-'+key if stored else 'decision:decision-'+key

    def test_email_merges_repeated_evaluations_with_stored_recipient_before_paging(self):
        expected=self.email()
        with self.store.connection() as db:
            db.execute("INSERT INTO mail_decisions SELECT 'decision-retry',owner,identity,domain,mailbox,recipient,exim_id,sender,3,sha256,'tag','clean',detail FROM mail_decisions")
        value=self.page('email-messages',self.admin,'server')
        self.assertEqual(1,value['total']);row=value['records'][0]
        self.assertEqual(expected,row['id']);self.assertEqual('clean',row['classification']);self.assertEqual('tag',row['action']);self.assertEqual('delivered',row['status']);self.assertEqual('Sample one',row['subject'])
        self.assertFalse(row['can_deliver']);self.assertFalse(row['can_delete'])

    def test_email_requires_exact_content_envelope_and_native_generation_for_matching(self):
        for key,changes in [('hash',dict(sha256='b'*64)),('identity',dict(identity='old')),('recipient',dict(recipient='other@alice.test')),('mailbox',dict(mailbox='other')),('domain',dict(domain='other.test')),('exim',dict(exim_id='other-id'))]:
            self.email(key,**changes)
        value=self.page('email-messages',self.admin,'server')
        stored=[row for row in value['records'] if row['delivery_id']]
        self.assertEqual(6,len(stored));self.assertTrue(all(row['classification'] is None for row in stored))
        self.ids['alice']='recreated'
        self.assertEqual(0,self.page('email-messages',self.admin,'server')['total'])
        with self.assertRaises(AccessDenied):self.page('email-messages',self.alice,'server')

    def test_email_deduplicates_decision_only_rows_without_claiming_delivery(self):
        self.email(stored=False)
        with self.store.connection() as db:
            db.execute("INSERT INTO mail_decisions SELECT 'retry',owner,identity,domain,mailbox,recipient,exim_id,sender,3,sha256,'reject','spam',detail FROM mail_decisions")
        value=self.page('email-messages');self.assertEqual(1,value['total']);row=value['records'][0]
        self.assertEqual('rejected',row['status']);self.assertIsNone(row['subject']);self.assertIsNone(row['delivery_id'])
        with self.store.connection() as db:db.execute("UPDATE mail_decisions SET action='tag' WHERE id='retry'")
        self.assertEqual('not_retained',self.page('email-messages')['records'][0]['status'])

    def test_email_filters_and_pages_cover_all_rows_with_no_duplicate_message_records(self):
        for i in range(510):self.email(str(i),created=1700000000+i)
        self.email('bob',owner='bob')
        seen=[]
        for offset in range(0,600,100):
            value=self.page('email-messages',self.admin,'server',{'account':'alice'},offset=offset,limit=100)
            self.assertEqual(510,value['total']);seen.extend(row['id'] for row in value['records'])
        self.assertEqual(510,len(set(seen)));self.assertEqual(510,len(seen))
        value=self.page('email-messages',self.admin,'server',{'account':'alice','search':'Sample 50','type':'spam','provider':'junk','status':'delivered','from':'2023-11-14','to':'2023-11-14'})
        self.assertEqual(11,value['total']);self.assertEqual(['spam'],value['options']['type']);self.assertEqual(['junk'],value['options']['provider'])
        self.assertEqual(1,self.page('email-messages',self.admin,'server',{'account':'bob'})['total'])

    def test_email_clear_preserves_private_quarantine_uncertain_work_and_delivery_evidence(self):
        for status in ('delivered','quarantined','delivery_uncertain','release_queued','native_failed'):
            self.email(status,status=status)
        self.email('rejected',stored=False,action='reject');self.email('other',owner='bob')
        context=self.hestia.authorize('admin','alice')
        proof=self.review.bulk(context,'email-messages','account','preview')
        self.assertEqual(2,proof['count']);self.assertEqual(4,proof['retained'])
        self.assertEqual(2,self.review.bulk(context,'email-messages','account','clear',proof['token'])['changed'])
        self.assertEqual(4,self.page('email-messages')['total']);self.assertEqual(1,self.page('email-messages',self.bob)['total'])
        with self.store.connection() as db:
            self.assertEqual(7,db.execute('SELECT count(*) FROM mail_decisions').fetchone()[0])
            self.assertEqual(6,db.execute('SELECT count(*) FROM mail_recipients').fetchone()[0])
        with self.assertRaises(AccessDenied):self.review.bulk(self.alice,'email-messages','account','preview')

    def test_email_source_acceptance_and_successful_body_cleanup_do_not_mislabel_delivery(self):
        self.email('accepted',status='quarantined');self.email('pending',status='quarantined');self.email('cleaned')
        with self.store.connection() as db:
            db.execute("INSERT INTO mail_acceptance VALUES('transaction-pending','exim-pending',1,1,'uncertain','{}',NULL)")
            db.execute("UPDATE mail_transactions SET status='purged' WHERE id='transaction-cleaned'")
        rows={r['id']:r for r in self.page('email-messages')['records']}
        self.assertTrue(rows['stored:recipient-accepted']['can_deliver']);self.assertTrue(rows['stored:recipient-accepted']['can_delete'])
        pending=rows['stored:recipient-pending'];self.assertEqual('source_unconfirmed',pending['status']);self.assertFalse(pending['can_deliver']);self.assertFalse(pending['can_delete'])
        self.assertEqual('delivered',rows['stored:recipient-cleaned']['status'])
