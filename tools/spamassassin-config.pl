#!/usr/bin/perl
# Managed by clamshield. Run only as the isolated SpamAssassin account.
use strict;
use warnings;
use Mail::SpamAssassin;
use JSON::PP;
my $path = shift // die "Missing owned configuration\n";
die "Unexpected arguments\n" if @ARGV;
my $sa = Mail::SpamAssassin->new({
  userprefs_filename => '/dev/null', dont_copy_prefs => 1,
  local_tests_only => 0, post_config_text => "include $path\n",
});
die "Rule validation failed\n" if $sa->lint_rules();
my $conf = $sa->{conf};
die "Configuration errors\n" if $conf->{errors};
my @rules;
for my $name (sort keys %{$conf->{scores}}) {
  next unless exists $conf->{test_types}->{$name};
  push @rules, {name => $name, score => 0 + $conf->{scores}->{$name},
    score_local => 0 + ($conf->{scoreset}->[0]->{$name} // 0),
    score_network => 0 + ($conf->{scoreset}->[1]->{$name} // 0),
    scores => [map { 0 + ($conf->{scoreset}->[$_]->{$name} // 0) } (0..3)],
    description => $conf->{descriptions}->{$name} // ''};
}
die "Rule catalog limit\n" if @rules > 12000;
print JSON::PP->new->canonical->encode({required_score => 0 + $conf->{required_score},
  skip_rbl_checks => 0 + $conf->{skip_rbl_checks},
  skip_uribl_checks => 0 + $conf->{skip_uribl_checks},
  dns_query_blocked => $conf->{dns_query_blocked}, rules => \@rules,
  version => $Mail::SpamAssassin::VERSION});
