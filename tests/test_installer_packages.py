"""The same installer command bootstraps new hosts and preserves existing APT engines."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('clamshield_installer', Path(__file__).resolve().parents[1]/'tools/install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerPackages(unittest.TestCase):
    def query(self, missing=(), code=0, partial=None):
        values={name:'installed' for name in installer.PACKAGES if name not in missing}
        if partial:values.update(partial)
        return subprocess.CompletedProcess([],code,stdout=''.join(name+':amd64\t'+status+'\n' for name,status in values.items()),stderr='')

    def test_existing_dependencies_do_not_run_apt_or_upgrade_engines(self):
        with patch.object(installer.subprocess,'run',return_value=self.query()) as query,patch.object(installer,'run') as apt:
            self.assertEqual([],installer.ensure_packages())
        apt.assert_not_called()
        self.assertEqual('/usr/bin/dpkg-query',query.call_args.args[0][0])

    def test_new_installation_bootstraps_missing_packages_without_a_flag(self):
        with patch.object(installer.subprocess,'run',return_value=self.query(missing=installer.PACKAGES,code=1)),patch.object(installer,'run') as apt:
            self.assertEqual(list(installer.PACKAGES),installer.ensure_packages())
        self.assertEqual([('/usr/bin/apt-get','update','-o','APT::Update::Error-Mode=any'),
            ('/usr/bin/apt-get','install','-y','--no-install-recommends','--no-remove',*installer.PACKAGES)],
            [v.args for v in apt.call_args_list])

    def test_partial_install_only_requests_missing_or_unconfigured_dependencies(self):
        with patch.object(installer.subprocess,'run',return_value=self.query(missing=('rsync',),code=1,partial={'gcc':'unpacked'})),patch.object(installer,'run') as apt:
            self.assertEqual(['rsync','gcc'],installer.ensure_packages())
        self.assertEqual(('/usr/bin/apt-get','install','-y','--no-install-recommends','--no-remove','rsync','gcc'),apt.call_args_list[1].args)

    def test_query_or_index_failure_stops_before_any_package_install(self):
        with patch.object(installer.subprocess,'run',return_value=self.query(code=2)),patch.object(installer,'run') as apt:
            with self.assertRaisesRegex(RuntimeError,'inspect'):installer.ensure_packages()
        apt.assert_not_called()
        with patch.object(installer.subprocess,'run',return_value=self.query(missing=('yara',),code=1)),patch.object(installer,'run',side_effect=subprocess.CalledProcessError(100,'apt-get')) as apt:
            with self.assertRaises(subprocess.CalledProcessError):installer.ensure_packages()
        self.assertEqual(1,apt.call_count)
