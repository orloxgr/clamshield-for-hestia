import hashlib
import subprocess
import unittest
from unittest.mock import patch

from clamshield.errors import EngineError
from clamshield.native_spam import rejection_threshold


class NativeSpamThresholdTests(unittest.TestCase):
    def test_queries_only_the_requested_native_macro_without_broad_config_export(self):
        raw=b'SPAM_REJECT_SCORE=100\n'
        with patch('clamshield.native_spam.bounded',return_value=subprocess.CompletedProcess([],0,raw,b'')) as run:
            result=rejection_threshold()
        self.assertEqual(10,result['required_score'])
        self.assertEqual(hashlib.sha256(raw.strip()).hexdigest(),result['revision'])
        self.assertEqual(['/usr/sbin/exim4','-bP','macro','SPAM_REJECT_SCORE'],run.call_args.args[0])
        self.assertEqual(3,run.call_args.kwargs['timeout'])

    def test_missing_changed_expressions_or_oversized_native_output_are_not_guessed(self):
        for code,raw in [(1,b''),(0,b''),(0,b'SPAM_REJECT_SCORE=${lookup secret}\n'),
                         (0,b'SPAM_REJECT_SCORE=nan'),(0,b'SPAM_REJECT_SCORE=100\nOTHER=secret'),
                         (0,b'SPAM_REJECT_SCORE=999999999999'),(0,b'x'*129)]:
            with self.subTest(code=code,raw=raw[:32]),patch('clamshield.native_spam.bounded',return_value=subprocess.CompletedProcess([],code,raw,b'')):
                with self.assertRaises(EngineError):rejection_threshold()
