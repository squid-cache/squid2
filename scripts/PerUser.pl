#!/usr/bin/perl -w


use strict;

# This is a simple script that will summarise per-user traffic
# statistics.
#
# Adrian Chadd <adrian@squid-cache.org>
# $Id$

use Squid::ParseLog;

my %u;

while (<>) {
	chomp;
	my $l = Squid::ParseLog::parse($_);
	if (! defined $u{$l->{"username"}}) {
		$u{$l->{"username"}}->{"traffic"} = 0;
	}
	$u{$l->{"username"}}->{"traffic"} += $l->{"size"};
}

foreach (keys %u) {
	printf "%s\t\t%lu\n", $_, $u{$_}->{"traffic"};
}
