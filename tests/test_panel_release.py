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
