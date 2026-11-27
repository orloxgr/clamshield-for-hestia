import fcntl
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock,patch

from clamshield.errors import EngineError
from clamshield.mail_bridge import SEALS
from clamshield.native_spam_client import NativeSpamAssassin,endpoint,native_group


def report(score='1000.813',threshold='5.0',text=b'Native rule report\n'):
    body=score.encode()+b'/'+threshold.encode()+b'\r\n'+text
    return b'SPAMD/1.1 0 EX_OK\r\nContent-length: '+str(len(body)).encode()+b'\r\n\r\n'+body


class NativeSpamClientTests(unittest.TestCase):
    def test_native_report_preserves_engine_value_and_exact_exim_metric(self):
        for score,metric in [('1000.813',1000.8),('10.0995',10.1),('-2.3',-2.2),('0',0)]:
            value=NativeSpamAssassin.parse(report(score))
            self.assertEqual(float(score),value['engine_score']);self.assertEqual(metric,value['score'])
            self.assertEqual('native-spamd-report',value['source']);self.assertEqual('Native rule report\n',value['report'])

    def test_truncated_nonfinite_duplicate_and_control_reports_are_not_native_success(self):
        for data in (report()[:-1],report('nan'),report('1e99'),report(text=b'bad\0report'),
                     report().replace(b'Content-length:',b'Content-length: 0\r\nContent-length:')):
            with self.subTest(data=data[:32]),self.assertRaises(EngineError):NativeSpamAssassin.parse(data)

    def test_actual_modern_native_report12_uses_spam_header_and_connection_close(self):
        data=b'SPAMD/1.1 0 EX_OK\r\nSpam: True ; 1000.8 / 5.0\r\n\r\nNative report\n'
        self.assertEqual(1000.8,NativeSpamAssassin.parse(data)['score'])
        with self.assertRaises(EngineError):NativeSpamAssassin.parse(data.replace(b'1000.8',b'nan'))

    def test_kernel_ipv4_and_mapped_ipv6_addresses_match_the_same_fixed_endpoint(self):
        self.assertEqual(('127.0.0.1',783),endpoint('0100007F:030F'))
        self.assertEqual(('127.0.0.1',783),endpoint('0000000000000000FFFF00000100007F:030F'))
        with self.assertRaises(ValueError):endpoint('00:030F')

    def test_an_unrelated_service_cannot_supply_native_spamd_identity(self):
        value=subprocess.CompletedProcess([],0,'MainPID=123\nControlGroup=/system.slice/foreign.service\n','')
        with patch('clamshield.native_spam_client.subprocess.run',return_value=value):
            with self.assertRaises(EngineError):native_group(time.monotonic()+5)

    @unittest.skipUnless(sys.platform=='linux','Native sealed mail descriptors')
    def test_unverified_tcp_peer_receives_no_message_bytes(self):
        fd=os.memfd_create('native-spam-test',os.MFD_ALLOW_SEALING);self.addCleanup(os.close,fd)
        os.write(fd,b'From: fixture@test\n\nPrivate inert body');fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
        connection=Mock();factory=Mock();factory.__enter__=Mock(return_value=connection);factory.__exit__=Mock(return_value=False)
        with patch('clamshield.native_spam_client.native_group',return_value=('/system.slice/spamd.service',123,456)), \
                patch('clamshield.native_spam.verify_endpoint'), \
                patch('clamshield.native_spam_client.socket.socket',return_value=factory), \
                patch('clamshield.native_spam_client.accepted_peer',side_effect=EngineError('Wrong service')):
            with self.assertRaises(EngineError):NativeSpamAssassin().scan(fd,deadline=time.monotonic()+5)
        connection.connect.assert_called_once_with(('127.0.0.1',783));connection.sendall.assert_not_called()
