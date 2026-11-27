from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

from clamshield.dns_health import DnsHealth,PROVIDERS,validate
from clamshield.errors import EngineError
from clamshield.settings import Settings
from clamshield.spam_report import parse
from clamshield.spamassassin import DEFAULTS


class LoopbackDns:
    """Answer an isolated SpamAssassin resolver; never alter host DNS."""
    def __init__(self,zone,answer):
        self.zone,self.answer=zone,answer;self.queries=0;self.errors=[];self.stop=threading.Event()
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.1)
        self.port=self.socket.getsockname()[1];self.thread=threading.Thread(target=self.run,daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:wire,peer=self.socket.recvfrom(4096)
            except socket.timeout:continue
            except OSError:
                if not self.stop.is_set():self.errors.append('DNS fixture socket failed')
                break
            try:
                cursor=12;labels=[]
                while wire[cursor]:
                    size=wire[cursor];cursor+=1;labels.append(wire[cursor:cursor+size].decode('ascii'));cursor+=size
                cursor+=1;kind,category=struct.unpack('!HH',wire[cursor:cursor+4]);cursor+=4
                query='.'.join(labels).lower();matches=query.endswith('.'+self.zone) or query==self.zone
                if matches:self.queries+=1
                error={'SERVFAIL':2,'REFUSED':5,'FORMERR':1,'NOTIMP':4}.get(self.answer) if matches else None
                positive=matches and self.answer is not None and error is None and kind==1 and category==1
                response=wire[:2]+struct.pack('!HHHHH',0x8180|error if error is not None else 0x8180 if positive else 0x8183,1,int(positive),0,0)+wire[12:cursor]
                if positive:response+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(self.answer)
                self.socket.sendto(response,peer)
            except (ValueError,IndexError,struct.error,OSError) as error:self.errors.append(type(error).__name__)

    def __enter__(self):self.thread.start();return self
    def __exit__(self,*_args):self.stop.set();self.socket.close();self.thread.join(1)


class DnsHealthTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.settings=Settings(state=self.root/'state');self.settings.prepare();self.health=DnsHealth(self.settings)

    def test_only_bounded_canonical_zone_states_can_be_retained(self):
        valid=[dict(zone='sa-trusted.bondedsender.org',state='blocked')]
        self.assertEqual(valid,validate(valid))
        for malformed in (valid*2,[dict(zone='private-key.sa-trusted.bondedsender.org',state='blocked')],
                          [dict(valid[0],query='private recipient')],[dict(valid[0],state='available')],
                          [dict(valid[0],state=[])],{},[dict(zone=[],state='blocked')]):
            with self.subTest(value=malformed),self.assertRaises(ValueError):validate(malformed)
        self.health.observe(dict(revision='a'*64,dns_observations=valid))
        contents=self.health.path.read_text();self.assertNotIn('recipient',contents)
        self.assertEqual('blocked',self.health.read()[valid[0]['zone']]['state'])
        with self.assertRaises(ValueError):self.health.observe(dict(revision='invalid',dns_observations=valid))

    def test_resolver_failures_are_retained_without_claiming_a_block_or_success(self):
        zone='multi.uribl.com'
        self.health.observe(dict(revision='b'*64,dns_observations=[dict(zone=zone,state='failed')]))
        current=next(row for row in self.health.status(DEFAULTS,False) if row['zone']==zone)
        self.assertEqual('failed',current['state']);self.assertEqual('b'*64,current['observation']['revision'])
        self.health.observe(dict(revision='c'*64,dns_observations=[dict(zone=zone,state='response-observed')]))
        self.assertEqual('response-observed',self.health.read()[zone]['state'])

    def test_absence_never_implies_availability_or_erases_an_observed_block(self):
        rows=self.health.status(DEFAULTS,None)
        self.assertEqual(set(PROVIDERS),{row['zone'] for row in rows});self.assertTrue(all(row['state']=='unknown' for row in rows))
        observation=dict(zone='sa-trusted.bondedsender.org',state='blocked')
        self.health.observe(dict(revision='a'*64,dns_observations=[observation]));before=self.health.path.read_bytes()
        self.health.observe(dict(revision='a'*64,dns_observations=[]));self.assertEqual(before,self.health.path.read_bytes())
        self.assertTrue(all(row['state']=='disabled' for row in self.health.status(DEFAULTS,True)))
        policy=DEFAULTS|dict(blocked_zones=['bondedsender.org'],rbl_enabled=False,uribl_enabled=False)
        rows={row['zone']:row for row in self.health.status(policy,False)}
        self.assertEqual('disabled',rows[observation['zone']]['state'])
        self.assertEqual('unknown',rows['lookup.dkimwl.org']['state']) # AskDNS is a separate native check.

    def test_failed_verification_cannot_poison_global_observations(self):
        from clamshield.spamassassin_binding import BoundSpamAssassin
        report=dict(revision='a'*64,dns_observations=[dict(zone='multi.uribl.com',state='blocked')])
        controls=Mock(settings=self.settings);controls.verify_report.side_effect=EngineError('Untrusted process')
        engine=Mock();engine.scan.return_value=report
        with self.assertRaises(EngineError):BoundSpamAssassin(engine,controls,DEFAULTS).scan(1)
        self.assertFalse(self.health.path.exists())
        controls.verify_report.side_effect=None;BoundSpamAssassin(engine,controls,DEFAULTS).scan(1)
        self.assertEqual('blocked',self.health.read()['multi.uribl.com']['state'])

    def test_aggregate_telemetry_failure_does_not_change_verified_message_score_or_erase_its_snapshot(self):
        from clamshield.spamassassin_binding import BoundSpamAssassin
        report=dict(score=2.395,revision='a'*64,dns_observations=[dict(zone='multi.uribl.com',state='blocked')])
        controls=Mock(settings=self.settings);engine=Mock();engine.scan.return_value=report
        with patch.object(DnsHealth,'observe',side_effect=EngineError('Corrupt metadata')),self.assertLogs('clamshield.spamassassin_binding',level='WARNING'):
            result=BoundSpamAssassin(engine,controls,DEFAULTS).scan(1)
        self.assertEqual(report,result);self.assertFalse(self.health.path.exists())

    @unittest.skipUnless(Path('/usr/bin/spamassassin').is_file(),'Real Ubuntu report plugin')
    def test_report_redacts_private_queries_and_ignores_txt_spoofed_suffixes_and_invalid_addresses(self):
        reporter=Path(__file__).resolve().parents[1]/'tools/spamassassin-report.pm'
        script=r'''
use strict;use warnings;use JSON::PP;
my $source=shift;require $source;
{ package Fixture;sub get_tag {return $_[0]->{raw};} }
local $/;my $raw=<STDIN>;my $pms=bless {raw=>$raw},'Fixture';
print JSON::PP->new->canonical->encode(ClamShield::Report::dns_observations($pms));
'''
        wire=('''<dns:private-key-and-recipient.multi.uribl.com> [127.0.0.2, 127.0.0.1]
<dns:private-key-and-recipient.multi.surbl.org> [127.0.0.3]
<dns:private-key-and-recipient.zen.spamhaus.org> [127.255.255.254]
<dns:private-key-and-recipient.multi.uribl.com.attacker.invalid> [127.0.0.1]
<dns:private-key-and-recipient.bl.score.senderscore.com?type=TXT> [127.255.255.255]
<dns:private-key-and-recipient.sa-accredit.habeas.com> [999.255.255.255]
<dns:private-key-and-recipient.sa-trusted.bondedsender.org> ["127.255.255.255"]
''').encode()
        result=subprocess.run(['/usr/bin/perl','-e',script,str(reporter)],input=wire,capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        observations=validate(json.loads(result.stdout))
        self.assertEqual({row['zone'] for row in observations},{'multi.uribl.com','multi.surbl.org','zen.spamhaus.org'})
        self.assertTrue(all(row['state']=='blocked' for row in observations))
        self.assertNotIn('private-key',result.stdout.decode());self.assertNotIn('127.',result.stdout.decode())

    @unittest.skipUnless(Path('/usr/bin/spamassassin').is_file(),'Real Ubuntu SpamAssassin and isolated DNS')
    def test_actual_askdns_internal_notice_is_observed_without_scoring_its_disabled_meta(self):
        reporter=Path(__file__).resolve().parents[1]/'tools/spamassassin-report.pm'
        empty=self.root/'empty';empty.mkdir()
        script=r'''
use strict;use warnings;use Mail::SpamAssassin;
my($rules,$site)=@ARGV;
my $sa=Mail::SpamAssassin->new({rules_filename=>$rules,site_rules_filename=>$site,
 userprefs_filename=>'/dev/null',dont_copy_prefs=>1,local_tests_only=>0});
die "Invalid AskDNS fixture" if $sa->lint_rules();
my $message=$sa->parse("From: fixture\@invalid.test\nTo: fixture\@invalid.test\nSubject: harmless\n\nHarmless content\n");
my $status=$sa->check($message);print $status->get_report();
$status->finish();$message->finish();$sa->finish();
'''
        zone='lookup.dkimwl.org'
        with LoopbackDns(zone,'127.255.255.255') as dns:
            config=self.root/'dns.cf'
            config.write_text('\n'.join([
                'loadplugin Mail::SpamAssassin::Plugin::Check','loadplugin Mail::SpamAssassin::Plugin::AskDNS',
                'loadplugin ClamShield::Report '+str(reporter),
                'util_rb_tld com net org test invalid','use_bayes 0','bayes_auto_learn 0',
                'clear_dns_servers','dns_server 127.0.0.1:'+str(dns.port),'dns_available yes',
                'askdns __DKIMWL_BLOCKED fixture.lookup.dkimwl.org A /^127\\.255\\.255\\.255$/',
                'meta DKIMWL_BLOCKED __DKIMWL_BLOCKED','score DKIMWL_BLOCKED 0',
                'askdns __DKIMWL_NORMAL fixture.lookup.dkimwl.org A /^127\\.0\\.0\\.2$/',
                'meta CS_NORMAL __DKIMWL_NORMAL','score CS_NORMAL 0.001',
                'clear_report_template','report CLAMSHIELD/1 '+'a'*64,'report _CLAMSHIELDREPORT_','']))
            result=subprocess.run(['/usr/bin/perl','-e',script,str(config),str(empty)],capture_output=True,timeout=12)
            self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'));detail=parse(result.stdout)
            self.assertGreater(dns.queries,0);self.assertEqual([],dns.errors)
            self.assertEqual([dict(zone=zone,state='blocked')],detail['dns_observations'])
            self.assertEqual(0,detail['score']);self.assertEqual([],detail['rules'])

    @unittest.skipUnless(Path('/usr/bin/spamassassin').is_file(),'Real Ubuntu SpamAssassin and isolated DNS')
    def test_actual_dns_blocked_and_failure_replies_survive_zero_score_while_nxdomain_is_unknown(self):
        reporter=Path(__file__).resolve().parents[1]/'tools/spamassassin-report.pm'
        empty=self.root/'empty';empty.mkdir()
        script=r'''
use strict;use warnings;use Mail::SpamAssassin;use JSON::PP;
my($rules,$site)=@ARGV;
my $sa=Mail::SpamAssassin->new({rules_filename=>$rules,site_rules_filename=>$site,
 userprefs_filename=>'/dev/null',dont_copy_prefs=>1,local_tests_only=>0});
die "Invalid DNS fixture" if $sa->lint_rules();
my $message=$sa->parse("Received: from remote.test (remote.test [8.8.8.8]) by mx.invalid.test with ESMTP; Fri, 27 Nov 2026 13:00:00 +0000\n".
 "From: fixture\@invalid.test\nTo: fixture\@invalid.test\nSubject: transactional fixture\n\nHarmless content\n");
my $status=$sa->check($message);print $status->get_report();
$status->finish();$message->finish();$sa->finish();
'''
        cases=[('sa-trusted.bondedsender.org',answer,wanted) for answer,wanted in
               (('127.255.255.255','blocked'),('127.0.0.2','response-observed'),(None,None),
                ('SERVFAIL','failed'),('REFUSED','failed'),('FORMERR','failed'),('NOTIMP','failed'))]
        for zone in ('zen.spamhaus.org','dbl.spamhaus.org'):
            cases.extend((zone,answer,wanted) for answer,wanted in
                         (('127.255.255.252','blocked'),('127.255.255.254','blocked'),('127.255.255.255','blocked'),
                          ('127.0.0.2','response-observed'),(None,None),('REFUSED','failed')))
        cases.append(('dbl.spamhaus.org','127.0.1.255','blocked'))
        for zone,answer,wanted in cases:
            with self.subTest(zone=zone,answer=answer),LoopbackDns(zone,answer) as dns:
                config=self.root/'dns.cf'
                config.write_text('\n'.join([
                    'loadplugin Mail::SpamAssassin::Plugin::Check',
                    'loadplugin Mail::SpamAssassin::Plugin::DNSEval',
                    'loadplugin ClamShield::Report '+str(reporter),
                    'util_rb_tld com net org test invalid','use_bayes 0','bayes_auto_learn 0',
                    'clear_dns_servers','dns_server 127.0.0.1:'+str(dns.port),'dns_available yes','rbl_timeout 2',
                    "header CS_QUERY eval:check_rbl('cs-probe', '"+zone+".', '^127\\.0\\.0\\.2$')",'tflags CS_QUERY net','score CS_QUERY 0.001',
                    "header RCVD_IN_VALIDITY_CERTIFIED_BLOCKED eval:check_rbl_sub('cs-probe', '^127\\.255\\.255\\.255$')",
                    'score RCVD_IN_VALIDITY_CERTIFIED_BLOCKED 0',
                    'header LAB_TRANSACTIONAL Subject =~ /transactional/','score LAB_TRANSACTIONAL 2.395',
                    'required_score 5','clear_report_template','report CLAMSHIELD/1 '+'a'*64,'report _CLAMSHIELDREPORT_','']))
                result=subprocess.run(['/usr/bin/perl','-e',script,str(config),str(empty)],capture_output=True,timeout=12)
                self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
                detail=parse(result.stdout)
                self.assertGreater(dns.queries,0);self.assertEqual([],dns.errors)
                self.assertEqual([] if wanted is None else [dict(zone=zone,state=wanted)],detail['dns_observations'])
                self.assertAlmostEqual(2.396 if wanted=='response-observed' else 2.395,detail['score'])
                self.assertNotIn('RCVD_IN_VALIDITY_CERTIFIED_BLOCKED',{row['name'] for row in detail['rules']})
                self.assertNotIn('8.8.8.8',result.stdout.decode())

    @unittest.skipUnless(Path('/usr/bin/spamassassin').is_file(),'Real Ubuntu DNS packet parser')
    def test_optional_lookup_cache_is_bounded_readonly_and_does_not_invent_timeouts(self):
        reporter=Path(__file__).resolve().parents[1]/'tools/spamassassin-report.pm'
        script=r'''
use strict;use warnings;use JSON::PP;use Net::DNS;
require shift;
{package Fixture;sub get_tag {return $_[0]->{raw}//'';}}
my $zone='multi.uribl.com';my $packet=Net::DNS::Packet->new('secret-key-and-recipient.'.$zone,'A');
$packet->header->rcode('SERVFAIL');
my $info={id=>'started',pkt=>$packet};my $key='A/secret-key-and-recipient.'.$zone;
my $cache={$key=>$info};my $async=bless {all_lookups=>$cache},'Mail::SpamAssassin::AsyncLoop';
my $pms=bless {async=>$async},'Fixture';my @results;
push @results,ClamShield::Report::dns_observations($pms);
die 'Observation mutated the cache' unless $cache->{$key}==$info && $info->{pkt}==$packet;
$pms->{raw}='<dns:secret-key-and-recipient.multi.uribl.com> [127.0.0.2]';
push @results,ClamShield::Report::dns_observations($pms);
$pms->{raw}='<dns:secret-key-and-recipient.multi.uribl.com> [127.0.0.1]';
push @results,ClamShield::Report::dns_observations($pms);
$pms->{raw}='';
for my $bad ({id=>'started'}, {id=>'started',pkt=>$packet,blocked=>'dns_query_restriction'},
 {pkt=>$packet}, {id=>'started',pkt=>{}}, []) {
 $cache->{$key}=$bad;push @results,ClamShield::Report::dns_observations($pms);
}
$async->{all_lookups}={map {('A/private'.$_=>{})} 1..10001};
push @results,ClamShield::Report::dns_observations($pms);
$pms->{async}={all_lookups=>{$key=>$info}};push @results,ClamShield::Report::dns_observations($pms);
$pms->{async}=bless {all_lookups=>[]},'Mail::SpamAssassin::AsyncLoop';
push @results,ClamShield::Report::dns_observations($pms);
print JSON::PP->new->canonical->encode(\@results);
'''
        result=subprocess.run(['/usr/bin/perl','-e',script,str(reporter)],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        rows=json.loads(result.stdout)
        self.assertEqual([[dict(zone='multi.uribl.com',state=state)] for state in ('failed','failed','blocked')],rows[:3])
        self.assertTrue(all(row==[] for row in rows[3:]));self.assertNotIn('secret',result.stdout.decode())
