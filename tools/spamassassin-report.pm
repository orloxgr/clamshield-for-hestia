# Managed by clamshield. Supported SpamAssassin hooks; never alter rule verdicts.
package ClamShield::Report;
use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
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
  # A static callback receives the status object; no circular reference survives.
  $pms->set_tag('CLAMSHIELDREPORT', \&report);
}

sub hit_rule {
  my ($self, $options) = @_;
  my $pms = $options->{permsgstatus};
  my $name = $options->{rulename};
  return if index($name, '__') == 0; # internal meta inputs do not add points
  my $hits = $pms->{clamshield_rule_contributions} //= [];
  if (@$hits >= 1000) { $pms->{clamshield_report_overflow} = 1; return; }
  my $description = $pms->{conf}->get_description_for_rule($name) // '';
  $description =~ s/[\x00-\x1f\x7f]/ /g;
  push @$hits, {name=>$name, score=>0+$options->{score},
                description=>substr($description, 0, 512)};
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
  });
}
1;
