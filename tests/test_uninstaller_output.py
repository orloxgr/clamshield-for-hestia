"""Uninstall cleanup instructions never execute deletion commands."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('console_uninstaller',Path(__file__).resolve().parents[1]/'tools/uninstall.py')
uninstaller=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(uninstaller)


class UninstallerOutput(unittest.TestCase):
    def render(self,result,machine=False):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):uninstaller.display(result,machine)
        return out.getvalue()

    def test_cleanup_output_names_data_and_checkout_and_quotes_exact_paths_without_deleting(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);state=base/'state';state.mkdir()
            source=base/"checkout '$(do-not-run)'";source.mkdir()
            original=state/'quarantine-original';original.write_text('retained original')
            result=uninstaller.cleanup_report(dict(uninstalled=True,data_retained=True,
                retained_directories=[dict(path=str(state),purpose='Settings, history and quarantine')]),source)
            self.assertEqual([str(state),str(source)],[row['path'] for row in result['retained_directories']])
            for row in result['retained_directories']:
                self.assertEqual(['sudo','rm','-rf','--',row['path']],shlex.split(row['delete_command']))
            text=self.render(result)
            for item in ('Uninstall completed','NOT been deleted',str(state),str(source),'quarantine','Delete:'):
                self.assertIn(item,text)
            self.assertEqual('retained original',original.read_text());self.assertTrue(source.is_dir())

    def test_uninstaller_inside_retained_code_does_not_repeat_the_parent_cleanup_target(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);source=base/'release-one';source.mkdir()
            result=uninstaller.cleanup_report(dict(uninstalled=True,
                retained_directories=[dict(path=str(base),purpose='Code snapshots')]),source)
            self.assertEqual(1,len(result['retained_directories']))
            self.assertEqual(str(base),result['retained_directories'][0]['path'])

    def test_json_has_the_same_cleanup_paths_without_human_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            result=uninstaller.cleanup_report(dict(uninstalled=True,retained_directories=[]),folder)
            text=self.render(result,True)
            self.assertEqual(result,json.loads(text));self.assertNotIn('Uninstall completed',text)

    def test_failed_removal_never_prints_cleanup_commands(self):
        result=dict(uninstalled=False,error='Owned file changed',retained_directories=[dict(path='/unused',delete_command='sudo rm -rf -- /unused')])
        text=self.render(result)
        self.assertIn('Owned file changed',text);self.assertNotIn('sudo rm',text)
