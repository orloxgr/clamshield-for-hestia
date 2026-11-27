#!/usr/bin/perl
# Managed by clamshield. Inspect standard native configuration as its mail user.
use strict;
use warnings;
use Mail::SpamAssassin;
use JSON::PP;
die "Unexpected arguments\n" if @ARGV;
my $text='';while (my $read=read(STDIN,my $block,8192)) { $text.=$block;die "Configuration limit\n" if length($text)>65536; }
my @user=getpwuid($<);die "Native user identity missing\n" unless @user && $user[0] eq 'debian-spamd';
$ENV{HOME}=$user[7];
my $sa=Mail::SpamAssassin->new({userprefs_filename=>$user[7].'/.spamassassin/user_prefs',dont_copy_prefs=>1,local_tests_only=>0,post_config_text=>$text});
die "Native configuration invalid\n" if $sa->lint_rules() || $sa->{conf}{errors};
my $conf=$sa->{conf};my @rules;
for my $name (sort keys %{$conf->{test_types}}) {
  push @rules,{name=>$name,description=>$conf->{descriptions}{$name}//'',
    scores=>[map {defined($conf->{scoreset}[$_]{$name}) ? 0+$conf->{scoreset}[$_]{$name} : undef} (0..3)]};
}
die "Rule limit\n" if @rules>12000;
print JSON::PP->new->canonical->encode({rules=>\@rules,version=>$Mail::SpamAssassin::VERSION,required_score=>0+$conf->{required_score}});
