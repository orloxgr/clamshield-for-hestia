"""Public checkout and archive must carry the runtime validation helper."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DistributionTests(unittest.TestCase):
    def test_installer_rejects_incomplete_checkout_and_accepts_runtime_helper(self):
        installer = load('distribution_installer', 'tools/install.py')
        with tempfile.TemporaryDirectory() as temp, patch.object(installer, 'SOURCE', Path(temp)):
            with self.assertRaisesRegex(RuntimeError, 'spamassassin-config.pl is missing'):
                installer.validate_source()
            helper = Path(temp) / 'tools/spamassassin-config.pl'
            helper.parent.mkdir()
            shutil.copyfile(ROOT / 'tools/spamassassin-config.pl', helper)
            installer.validate_source()

    def test_source_archive_retains_exact_runtime_helper_bytes(self):
        package = load('distribution_package', 'tools/package.py')
        # Build a real archive in temporary storage without writing release outputs.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('README.md', 'LICENSE', 'pyproject.toml', 'entry.py', 'tools/install.py',
                         'tools/uninstall.py', 'tools/package.py', 'tools/spamassassin-config.pl',
                         'src/clamshield/__init__.py'):
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            output = io.StringIO()
            with patch.object(package, 'ROOT', root), contextlib.redirect_stdout(output):
                package.main()
            result = json.loads(output.getvalue())
            with tarfile.open(result['archive'], 'r:gz') as archive:
                prefix = 'clamshield-hestia-' + result['version']
                member = archive.getmember(prefix + '/tools/spamassassin-config.pl')
                self.assertTrue(member.isfile())
                self.assertEqual((ROOT / 'tools/spamassassin-config.pl').read_bytes(),
                                 archive.extractfile(member).read())
