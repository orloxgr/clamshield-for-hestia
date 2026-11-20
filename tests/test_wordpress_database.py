import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import AccessDenied, Conflict
from clamshield.settings import Settings
from clamshield.wordpress_database import WordPressDatabase, unpacked, replacement


class NativeWordPressDatabase(unittest.TestCase):
    """A private Unix-socket server; never use a host/service database."""
    @classmethod
    def setUpClass(cls):
        if not shutil.which('mariadbd') or not shutil.which('mariadb-install-db'):
            raise unittest.SkipTest('MariaDB integration fixture requires its Ubuntu package')
        import pymysql
        cls.pymysql=pymysql;cls.temp=tempfile.TemporaryDirectory(prefix='cs-wp-db-');cls.base=Path(cls.temp.name)
        cls.socket=str(cls.base/'mysql.sock');cls.datadir=cls.base/'data'
        init=subprocess.run(['mariadb-install-db','--no-defaults','--datadir='+str(cls.datadir),'--auth-root-authentication-method=normal','--skip-test-db'],capture_output=True,timeout=60)
        if init.returncode:raise RuntimeError('Private MariaDB initialization failed')
        cls.process=subprocess.Popen(['mariadbd','--no-defaults','--user=root','--datadir='+str(cls.datadir),'--socket='+cls.socket,'--skip-networking','--pid-file='+str(cls.base/'pid'),'--log-error='+str(cls.base/'error.log')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+30
        while True:
            try:
                cls.admin=pymysql.connect(unix_socket=cls.socket,user='root',autocommit=True);break
            except pymysql.MySQLError:
                if time.monotonic()>deadline or cls.process.poll() is not None:
                    cls.process.terminate();cls.process.wait(timeout=10);raise RuntimeError('Private MariaDB did not start')
                time.sleep(.1)
        with cls.admin.cursor() as cursor:
            cursor.execute('CREATE DATABASE alice_wp CHARACTER SET utf8mb4')
            cursor.execute("CREATE USER 'alice_wp'@'localhost' IDENTIFIED BY 'fixture-password'")
            cursor.execute("GRANT ALL ON alice_wp.* TO 'alice_wp'@'localhost'")

    @classmethod
    def tearDownClass(cls):
        cls.admin.close();cls.process.terminate();cls.process.wait(timeout=15);cls.temp.cleanup()

    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);self.settings=Settings(state=self.root/'private');self.settings.prepare()
        self.context=dict(actor='alice',owner='alice',identity='generation',admin=False)
        self.native=Mock();self.native.authorize.return_value=self.context
        self.native.call.return_value={'alice_wp':{'USER':'alice_wp','HOST':'localhost'}}
        self.config="<?php\ndefine('DB_NAME','alice_wp');\ndefine('DB_USER','alice_wp');\ndefine('DB_PASSWORD','fixture-password');\ndefine('DB_HOST','localhost:"+self.socket+"');\n$table_prefix='wp_';\n"
        (self.root/'wp-config.php').write_text(self.config)
        self.database=WordPressDatabase(self.settings,self.native,self.context,str(self.root),'')
        with self.admin.cursor() as cursor:
            cursor.execute('DROP TABLE IF EXISTS alice_wp.wp_options')
            cursor.execute('DROP TABLE IF EXISTS alice_wp.other_options')
            cursor.execute('CREATE TABLE alice_wp.wp_options(option_id BIGINT PRIMARY KEY,option_name VARCHAR(191),option_value LONGTEXT) ENGINE=InnoDB')
            cursor.execute('CREATE TABLE alice_wp.other_options(id BIGINT PRIMARY KEY,value LONGTEXT) ENGINE=InnoDB')
            cursor.execute('INSERT INTO alice_wp.wp_options VALUES(1,%s,%s)',('custom_html','<script>bad()</script>θέμα'))
            cursor.execute('INSERT INTO alice_wp.other_options VALUES(1,%s)',('<script>outside selected prefix</script>',))

    def scan(self):
        items=[];result=self.database.inspect(items.append)
        return result,items

    def test_real_readonly_inspection_is_prefix_scoped_and_never_loads_php(self):
        (self.root/'wp-config.php').write_text(self.config+"file_put_contents('/root/SHOULD-NOT-RUN','bad');\n")
        result,items=self.scan();self.assertEqual(1,result['findings']);self.assertEqual('wp_options',items[0]['table'])
        self.assertEqual(['option_id'],items[0]['keys']);self.assertEqual(b'1',unpacked(items[0]['key_values'][0]))
        self.assertNotIn('fixture-password',str(items));self.assertEqual(1,len(items))

    def test_exact_change_retry_and_undo_preserve_unicode(self):
        _,items=self.scan();item=items[0];before=unpacked(item['before']);after=replacement(before,'<script>bad()</script>','')
        self.assertEqual('unchanged',self.database.change(item,before,after,inspect_only=True))
        self.assertEqual('applied',self.database.change(item,before,after))
        self.assertEqual('already-applied',self.database.change(item,before,after))
        with self.admin.cursor() as cursor:
            cursor.execute('SELECT option_value FROM alice_wp.wp_options WHERE option_id=1');self.assertEqual('θέμα',cursor.fetchone()[0])
        self.assertEqual('applied',self.database.change(item,after,before))

    def test_changed_content_or_configuration_is_never_overwritten(self):
        _,items=self.scan();item=items[0];before=unpacked(item['before'])
        with self.admin.cursor() as cursor:cursor.execute("UPDATE alice_wp.wp_options SET option_value='changed' WHERE option_id=1")
        with self.assertRaises(Conflict):self.database.change(item,before,b'clean')
        (self.root/'wp-config.php').write_text(self.config+'// configuration changed')
        with self.assertRaises(Conflict):self.database.change(item,before,b'clean')

    def test_native_database_user_and_generation_prevent_root_or_foreign_connections(self):
        (self.root/'wp-config.php').write_text(self.config.replace("'DB_USER','alice_wp'","'DB_USER','root'"))
        with self.assertRaises(AccessDenied):self.scan()
        (self.root/'wp-config.php').write_text(self.config);self.native.call.return_value={'bob_wp':{'USER':'bob_wp'}}
        with self.assertRaises(AccessDenied):self.scan()
        self.native.call.return_value={'alice_wp':{'USER':'alice_wp'}};self.native.authorize.return_value=self.context|{'identity':'replacement'}
        with self.assertRaises(AccessDenied):self.scan()

    def test_no_primary_key_and_nontransactional_tables_remain_review_only(self):
        with self.admin.cursor() as cursor:
            cursor.execute('ALTER TABLE alice_wp.wp_options DROP PRIMARY KEY')
        _,items=self.scan();self.assertFalse(items[0]['editable'])
        with self.assertRaises(AccessDenied):self.database.change(items[0],unpacked(items[0]['before']),b'clean')
        with self.admin.cursor() as cursor:
            cursor.execute('ALTER TABLE alice_wp.wp_options ADD PRIMARY KEY(option_id), ENGINE=MyISAM')
        _,items=self.scan()
        with self.assertRaises(Conflict):self.database.change(items[0],unpacked(items[0]['before']),b'clean')

    def test_schema_change_and_trigger_rewrite_are_rolled_back(self):
        _,items=self.scan();item=items[0];before=unpacked(item['before'])
        with self.admin.cursor() as cursor:cursor.execute('ALTER TABLE alice_wp.wp_options ADD extra_column INT')
        with self.assertRaises(Conflict):self.database.change(item,before,b'clean')
        _,items=self.scan();item=items[0]
        with self.admin.cursor() as cursor:cursor.execute("CREATE TRIGGER alice_wp.rewrite_value BEFORE UPDATE ON alice_wp.wp_options FOR EACH ROW SET NEW.option_value='triggered'")
        with self.assertRaises(Conflict):self.database.change(item,before,b'clean')
        with self.admin.cursor() as cursor:
            cursor.execute('SELECT option_value FROM alice_wp.wp_options WHERE option_id=1')
            self.assertEqual(before,cursor.fetchone()[0].encode())

    def test_complete_recovery_batch_previews_applies_and_undoes_a_real_database_change(self):
        from clamshield.store import Store
        from clamshield.wordpress_recovery import WordPressRecovery
        from clamshield.worker import Worker
        web=self.root/'web';web.mkdir();(web/'wp-config.php').write_text(self.config)
        (web/'wp-includes').mkdir();clean={'wp-includes/version.php':b"<?php\n$wp_version='6.8.3';\n",'wp-settings.php':b'clean core'}
        for path,content in clean.items():(web/path).write_bytes(content)
        site=dict(owner='alice',identity='generation',domain='database.test',root=str(web),suspended=False)
        self.native.sites.return_value=[site];store=Store(self.settings.database)
        refs=Mock();refs.receipts={};refs.manifest.return_value=dict(source='fixture',files={path:dict(algorithm='sha256',digest=hashlib.sha256(content).hexdigest()) for path,content in clean.items()})
        engines=[]
        for name in ('clamav','yara'):
            engine=Mock();engine.name=name;engine.scan.return_value=[];engines.append(engine)
        recovery=WordPressRecovery(self.settings,store,self.native);worker=Worker(self.settings,store,self.native,engines)
        with patch('clamshield.wordpress_recovery.RecoveryReferences',return_value=refs),patch('clamshield.wordpress.References',return_value=refs):
            key=recovery.analyze(self.context,'database.test','',{'database':True})['plan_id'];worker.once()
            status=recovery.status(self.context,key);self.assertEqual('ready',status['plan']['status'],status)
            item=next(item for item in status['items'] if item['kind']=='database')
            recovery.request(self.context,key,'preview',status['plan']['revision'],dict(items=[item['id']],edits={item['id']:dict(find='<script>bad()</script>',replace='')}));worker.once()
            status=recovery.status(self.context,key);self.assertEqual('reviewed',status['plan']['status'],status)
            old_revision=status['plan']['revision']
            with self.assertRaises(Conflict):
                recovery.request(self.context,key,'preview',old_revision,dict(items=[item['id']],edits={item['id']:dict(find='not-present',replace='')}))
            with self.assertRaises(Conflict):recovery.request(self.context,key,'apply',old_revision)
            status=recovery.status(self.context,key);self.assertEqual('preview-failed',status['plan']['status'])
            recovery.request(self.context,key,'preview',status['plan']['revision'],dict(items=[item['id']],edits={item['id']:dict(find='<script>bad()</script>',replace='')}));worker.once()
            status=recovery.status(self.context,key);self.assertEqual('reviewed',status['plan']['status'])
            recovery.request(self.context,key,'apply',status['plan']['revision']);worker.once()
            status=recovery.status(self.context,key);self.assertEqual('applied',status['plan']['status'],status)
            with self.admin.cursor() as cursor:
                cursor.execute('SELECT option_value FROM alice_wp.wp_options WHERE option_id=1');self.assertEqual('θέμα',cursor.fetchone()[0])
            recovery.request(self.context,key,'undo',status['plan']['revision'])
            for _ in range(10):
                if recovery.status(self.context,key)['plan']['status']=='undone':break
                worker.once()
            self.assertEqual('undone',recovery.status(self.context,key)['plan']['status'])
            with self.admin.cursor() as cursor:
                cursor.execute('SELECT option_value FROM alice_wp.wp_options WHERE option_id=1');self.assertEqual('<script>bad()</script>θέμα',cursor.fetchone()[0])
