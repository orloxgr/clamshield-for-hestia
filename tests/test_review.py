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
        with patch('clamshield.review.time.time',return_value=99999999999):
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

    @unittest.skipUnless(shutil.which('php'),'PHP renderer')
    def test_shared_php_fragments_render_all_lists_and_escape_notifications(self):
        self.notice(self.alice,subject='<img src=x onerror=alert(1)>');self.findings(1)
        renderer=Path(__file__).resolve().parents[1]/'panel/review_render.php'
        code="$data=json_decode(stream_get_contents(STDIN),true);$escape=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');require $argv[1];"
        for kind in SPECS:
            value=self.page(kind,self.admin,'server')
            result=subprocess.run(['php','-d','display_errors=stderr','-r',code,str(renderer)],input=encode(value),capture_output=True,text=True)
            self.assertEqual(0,result.returncode,result.stderr);self.assertEqual('',result.stderr,kind)
            if kind=='notices':self.assertIn('&lt;img',result.stdout);self.assertNotIn('<img',result.stdout)
