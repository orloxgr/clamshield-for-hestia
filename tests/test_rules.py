import json
from pathlib import Path
import tempfile
import unittest

from clamshield.engines import Yara
from clamshield.errors import EngineError
from clamshield.rules import Rules
from clamshield.settings import Settings


@unittest.skipUnless(Path('/usr/bin/yarac').is_file(), 'Ubuntu yarac integration')
class RuleGenerations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(state=Path(self.temp.name) / 'state')
        self.rules = Rules(self.settings)

    def test_invalid_update_leaves_previous_rules_active(self):
        first = self.rules.publish(b'rule Good {condition: true}', {'provider': 'local'})
        with self.assertRaises(EngineError):
            self.rules.publish(b'this is invalid', {'provider': 'local'})
        self.assertEqual(first['generation'], self.rules.status()['generation'])
        self.assertEqual(1, len(list(self.rules.base.glob('generation-*'))))

    def test_compiled_generation_runs_with_ubuntu_engine_and_rollback_restores_previous(self):
        first = self.rules.publish(b'rule First {condition: true}', {'provider': 'local'})
        second = self.rules.publish(b'rule Second {condition: true}', {'provider': 'local'})
        sample = Path(self.temp.name) / 'sample'
        sample.write_text('fixture')
        active = self.rules.base / 'current/rules.yarac'
        self.assertEqual('Second', Yara('/usr/bin/yara', active).scan(sample)[0]['signature'])
        self.rules.rollback()
        self.assertEqual(first['generation'], self.rules.status()['generation'])
        self.assertEqual('First', Yara('/usr/bin/yara', active).scan(sample)[0]['signature'])
        self.assertNotEqual(first['generation'], second['generation'])

    def test_corrupt_previous_generation_does_not_replace_current_on_rollback(self):
        first = self.rules.publish(b'rule First {condition: true}', {'provider': 'local'})
        second = self.rules.publish(b'rule Second {condition: true}', {'provider': 'local'})
        previous = self.rules.base / 'previous'
        (previous / 'rules.yarac').write_bytes(b'corrupted compiled rules')
        with self.assertRaises(EngineError):
            self.rules.rollback()
        self.assertEqual(second['generation'], self.rules.status()['generation'])
