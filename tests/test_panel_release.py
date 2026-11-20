"""Run the real PHP route across an external atomic release replacement."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PHP=shutil.which('php')


@unittest.skipUnless(os.name=='posix' and PHP,'Linux PHP symlink integration')
class PanelRelease(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.base=Path(folder.name)
        for name,value in [('old','OLD'),('new','NEW')]:
            panel=self.base/name/'panel';panel.mkdir(parents=True)
            (panel/'view.php').write_text('<?php echo "'+value+'";')
        (self.base/'current').symlink_to(self.base/'old')
        native=self.base/'hestia/web'
        (native/'inc').mkdir(parents=True);(native/'templates').mkdir()
        (native/'inc/main.php').write_text('<?php $_SESSION=["user"=>"admin"]; function top_panel($user,$tab){}')
        (native/'templates/header.php').write_text('<?php echo "HEADER";')
        (native/'templates/footer.php').write_text('<?php echo "FOOTER";')
        bridge=self.base/'bridge';bridge.write_text('#!/usr/bin/python3\nimport sys\nsys.stdin.read()\nprint(\'{"ok":true}\')\n');bridge.chmod(0o755)
        route=(ROOT/'panel/index.php').read_text(encoding='utf-8')
        route=route.replace('/usr/local/hestia',str(self.base/'hestia')).replace('/opt/clamshield',str(self.base/'current')).replace('/usr/bin/sudo',str(bridge))
        (self.base/'route.php').write_text(route,encoding='utf-8')
        runner='''<?php
$_SERVER['REQUEST_METHOD']='GET';
if(($argv[2]??'')==='warm'){
    fwrite(STDOUT,json_encode(realpath($argv[1].'/current/panel/view.php'))."\\n");
    fflush(STDOUT);fgets(STDIN);
}
require $argv[1].'/route.php';
'''
        (self.base/'runner.php').write_text(runner)

    def command(self):
        return [PHP,'-d','realpath_cache_ttl=3600','-d','realpath_cache_size=4096K','-d','opcache.enable_cli=0',str(self.base/'runner.php'),str(self.base)]

    def test_cached_deleted_release_loads_the_new_template_without_restarting_php(self):
        child=subprocess.Popen(self.command()+['warm'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def cleanup():
            if child.poll() is None:child.kill()
            child.communicate()
        self.addCleanup(cleanup)
        self.assertEqual(str(self.base/'old/panel/view.php'),json.loads(child.stdout.readline()))
        # Change the symlink outside PHP, as the root installer does.
        (self.base/'next').symlink_to(self.base/'new');(self.base/'next').replace(self.base/'current')
        (self.base/'old/panel/view.php').unlink()
        output,error=child.communicate('\n',timeout=20)
        self.assertEqual(0,child.returncode,error)
        self.assertEqual('HEADERNEWFOOTER',output);self.assertEqual('',error)

    def test_missing_panel_returns_an_explicit_error_before_native_header_output(self):
        (self.base/'old/panel/view.php').unlink()
        result=subprocess.run(self.command(),capture_output=True,text=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr)
        value=json.loads(result.stdout);self.assertFalse(value['ok']);self.assertIn('panel files are unavailable',value['error'])
        self.assertNotIn('HEADER',result.stdout);self.assertEqual('',result.stderr)

    def review_route(self,templates=True):
        if templates:shutil.copytree(ROOT/'panel',self.base/'old/panel',dirs_exist_ok=True)
        (self.base/'hestia/web/inc/main.php').write_text('<?php $_SESSION=["user"=>"admin","token"=>"fixture-token"];')
        value=dict(ok=True,list='notices',total=1,offset=0,limit=50,next_offset=None,options={},accounts=['alice'],can_clear=True,
                   records=[dict(id='notice',review_selectable=True,private_marker='ROOT_RECORD_ONLY')],view_data=dict(context=dict(owner='admin',view_scope='server'),notifications=[dict(owner='alice',id='notice',event='scan.malware_found',subject='<img src=x>',created=1,read_at=None,detail={})]))
        (self.base/'response.json').write_text(json.dumps(value),encoding='utf-8')
        (self.base/'bridge').write_text('#!/usr/bin/python3\nimport pathlib,sys\nsys.stdin.read()\nprint(pathlib.Path(__file__).with_name("response.json").read_text())\n')
        (self.base/'runner.php').write_text('''<?php
$_SERVER['REQUEST_METHOD']='POST';
$_POST=['action'=>'review-list','owner'=>'admin','scope'=>'server','token'=>'fixture-token','list'=>'notices','limit'=>'50','offset'=>'0','filters'=>'{}'];
require $argv[1].'/route.php';
''')
        result=subprocess.run(self.command(),capture_output=True,text=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr);self.assertEqual('',result.stderr)
        return json.loads(result.stdout)

    def test_review_post_renders_escaped_shared_rows_without_native_page_or_raw_data(self):
        value=self.review_route()
        self.assertTrue(value['ok']);self.assertEqual(1,value['total']);self.assertIn('&lt;img',value['html']);self.assertNotIn('<img',value['html'])
        self.assertNotIn('records',value);self.assertNotIn('view_data',value)
        self.assertNotIn('ROOT_RECORD_ONLY',json.dumps(value));self.assertNotIn('HEADER',value['html'])

    def test_missing_review_renderer_returns_explicit_json_error(self):
        value=self.review_route(templates=False)
        self.assertFalse(value['ok']);self.assertIn('Review templates are unavailable',value['error'])
