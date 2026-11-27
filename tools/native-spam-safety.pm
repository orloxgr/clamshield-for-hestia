# Managed by clamshield. Read-only live configuration proof, not rule mutation.
package ClamShield::NativeSafety;
use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Scalar::Util qw(looks_like_number);
our @ISA = qw(Mail::SpamAssassin::Plugin);
my %admin = map { $_ => 1 } qw(
  RCVD_IN_VALIDITY_CERTIFIED_BLOCKED RCVD_IN_VALIDITY_RPBL_BLOCKED
  RCVD_IN_VALIDITY_SAFE_BLOCKED URIBL_BLOCKED RCVD_IN_DNSWL_BLOCKED
  DKIMWL_BLOCKED FROM_FMBLA_NDBLOCKED SURBL_BLOCKED
  RCVD_IN_ZEN_BLOCKED RCVD_IN_ZEN_BLOCKED_OPENDNS
  URIBL_DBL_BLOCKED URIBL_DBL_BLOCKED_OPENDNS URIBL_ZEN_BLOCKED URIBL_ZEN_BLOCKED_OPENDNS
);
sub new {
  my ($class,$main)=@_;my $self=$class->SUPER::new($main);bless($self,$class);
  $self->register_eval_rule('check_native_scores');return $self;
}
sub check_native_scores {
  my ($self,$pms,$revision)=@_;
  return 0 unless defined($revision) && $revision =~ /^[a-f0-9]{64}$/;
  my $header=$pms->get('X-ClamShield-Native-Safety') // ''; $header =~ s/\s+$//;
  return 0 unless $header eq $revision;
  my $conf=$pms->{conf};return 0 unless ref($conf->{scores}) eq 'HASH' && ref($conf->{test_types}) eq 'HASH' && ref($conf->{scoreset}) eq 'ARRAY' && @{$conf->{scoreset}}==4;
  my $count=0;
  for my $name (keys %{$conf->{test_types}}) {
    my $description=$conf->{descriptions}{$name} // '';
    next unless $admin{$name} || $name =~ /^RCVD_IN_VALIDITY_[A-Z0-9_]+_BLOCKED$/ || $description =~ /^ADMINISTRATOR NOTICE:\s+The query\b/i;
    ++$count;
    for my $scores ($conf->{scores},@{$conf->{scoreset}}) {
      return 0 unless ref($scores) eq 'HASH' && exists($scores->{$name}) && defined($scores->{$name}) && looks_like_number($scores->{$name}) && $scores->{$name}==0;
    }
  }
  return $count ? 1 : 0;
}
1;
