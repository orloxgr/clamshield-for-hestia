# Managed by clamshield. Supported SpamAssassin hooks; never alter rule verdicts.
package ClamShield::Report;
use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use Scalar::Util qw(blessed reftype);
our @ISA = qw(Mail::SpamAssassin::Plugin);
my $reporter_sha256;
{
  open my $source, '<', __FILE__ or die "Cannot identify report plugin";
  local $/;
  $reporter_sha256 = sha256_hex(<$source>);
  close $source;
}

sub new {
  my ($class, $main) = @_;
  return bless $class->SUPER::new($main), $class;
}

sub check_start {
  my ($self, $options) = @_;
  my $pms = $options->{permsgstatus};
  $pms->{clamshield_rule_contributions} = [];
  $pms->{clamshield_dns_observed} = {};
  # A static callback receives the status object; no circular reference survives.
  $pms->set_tag('CLAMSHIELDREPORT', \&report);
}

sub hit_rule {
  my ($self, $options) = @_;
  my $pms = $options->{permsgstatus};
  my $name = $options->{rulename};
  my %notices = (__DKIMWL_BLOCKED=>'lookup.dkimwl.org', DKIMWL_BLOCKED=>'lookup.dkimwl.org',
    __FROM_FMBLA_NDBLOCKED=>'fresh.fmb.la', FROM_FMBLA_NDBLOCKED=>'fresh.fmb.la');
  $pms->{clamshield_dns_observed}{$notices{$name}} = 'blocked' if exists $notices{$name};
  return if index($name, '__') == 0; # internal meta inputs do not add points
  my $hits = $pms->{clamshield_rule_contributions} //= [];
  if (@$hits >= 1000) { $pms->{clamshield_report_overflow} = 1; return; }
  my $description = $pms->{conf}->get_description_for_rule($name) // '';
  $description =~ s/[\x00-\x1f\x7f]/ /g;
  push @$hits, {name=>$name, score=>0+$options->{score},
                description=>substr($description, 0, 512)};
}

sub dns_observations {
  my ($pms) = @_;
  # Never export query labels, TXT answers, addresses or provider credentials.
  # The supported RBL tag contains positive replies only; absence is unknown.
  my %zones = (
    'sa-trusted.bondedsender.org'=>qr/^127\.255\.255\.255$/,
    'sa-accredit.habeas.com'=>qr/^127\.255\.255\.255$/,
    'bl.score.senderscore.com'=>qr/^127\.255\.255\.255$/,
    'list.dnswl.org'=>qr/^127\.0\.\d+\.255$/,
    'lookup.dkimwl.org'=>qr/^127\.255\.255\.255$/,
    'fresh.fmb.la'=>qr/^127\.255\.255\.255$/,
    'multi.uribl.com'=>qr/^127\.0\.0\.(?:[13579]|[1-9]\d*[13579])$/,
    'multi.surbl.org'=>qr/^127\.0\.0\.(?:[13579]|[1-9]\d*[13579])$/,
    # Spamhaus administrative replies are not reputation/listing answers.
    # DBL additionally returns 127.0.1.255 for prohibited IP-address queries.
    'zen.spamhaus.org'=>qr/^127\.255\.255\.(?:252|254|255)$/,
    'dbl.spamhaus.org'=>qr/^(?:127\.255\.255\.(?:252|254|255)|127\.0\.1\.255)$/,
  );
  my %seen = %{$pms->{clamshield_dns_observed} // {}};
  # SA 4.x retains the actual resolver packets in its per-message AsyncLoop.
  # Inspect this optional cache read-only: no extra provider queries, DNS labels
  # in reports, or assumptions about missing replies/timeouts. An unfamiliar
  # cache layout remains unknown. NXDOMAIN is a normal negative answer.
  my $async = $pms->{async};
  my $lookups = blessed($async) && $async->isa('Mail::SpamAssassin::AsyncLoop')
    && (reftype($async) // '') eq 'HASH' ? $async->{all_lookups} : undef;
  if (ref($lookups) eq 'HASH' && keys(%$lookups) <= 10000) {
    for my $key (keys %$lookups) {
      next unless length($key) <= 512 && $key =~ /^A\/([A-Za-z0-9_.-]+)$/i;
      my $query = lc($1); $query =~ s/\.$//;
      my $info = $lookups->{$key};
      next unless ref($info) eq 'HASH' && !$info->{blocked} && defined $info->{id};
      my $packet = $info->{pkt};
      next unless blessed($packet) && $packet->isa('Net::DNS::Packet');
      my $rcode = eval { $packet->header->rcode } // '';
      next unless $rcode =~ /^(?:SERVFAIL|REFUSED|FORMERR|NOTIMP)$/;
      for my $zone (keys %zones) {
        next unless $query eq $zone || $query =~ /\.\Q$zone\E$/;
        $seen{$zone} = 'failed' unless ($seen{$zone} // '') eq 'blocked';
      }
    }
  }
  my $rbl = $pms->get_tag('RBL') // '';
  if (length($rbl) <= 262144) {
    for my $line (split /\n/, $rbl) {
      # Dns.pm omits parameters only for IN/A; TXT/class-specific data is not
      # an IPv4 return code, even if its text happens to look like an address.
      next unless $line =~ /^<dns:([A-Za-z0-9_.-]+)>\s+\[(.*)\]$/;
      my ($query, $answer) = (lc($1), $2); $query =~ s/\.$//;
      for my $zone (keys %zones) {
        next unless $query eq $zone || $query =~ /\.\Q$zone\E$/;
        for my $ip (split /,\s*/, $answer) {
          next unless $ip =~ /^(?:\d{1,3}\.){3}\d{1,3}$/;
          next if grep { $_ > 255 } split /\./, $ip;
          my $state = $ip =~ $zones{$zone} ? 'blocked' : 'response-observed';
          $seen{$zone} = $state if $state eq 'blocked' ||
            (($seen{$zone} // '') ne 'blocked' && ($seen{$zone} // '') ne 'failed');
        }
      }
    }
  }
  return [map { {zone=>$_, state=>$seen{$_}} } sort keys %seen];
}

sub report {
  my ($pms) = @_;
  my %rules;
  for my $hit (@{$pms->{clamshield_rule_contributions} // []}) {
    my $entry = $rules{$hit->{name}} //= {name=>$hit->{name}, score=>0,
                                        description=>$hit->{description}, hits=>0};
    $entry->{score} += $hit->{score};
    $entry->{hits}++;
  }
  return JSON::PP->new->canonical->ascii->encode({
    version=>1, reporter_sha256=>$reporter_sha256,
    complete=>($pms->{clamshield_report_overflow} ||
                          $pms->{rule_errors} || $pms->{deadline_exceeded}) ? 0 : 1,
    score=>0+$pms->get_score(), threshold=>0+$pms->get_required_score(),
    engine_version=>$pms->get_tag('VERSION') // '',
    rules_version=>$pms->get_tag('RULESVERSION') // '',
    rules=>[map { $rules{$_} } sort keys %rules],
    dns_observations=>dns_observations($pms),
  });
}
1;
