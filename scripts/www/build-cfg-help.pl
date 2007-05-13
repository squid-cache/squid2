#!/usr/bin/perl -w

use strict;
use IO::File;


# This mess is designed to parse the squid config template file
# cf.data.pre and generate a set of HTML pages to use as documentation.
#
# Adrian Chadd <adrian@squid-cache.org>
#
# $Id$

#
# The template file is reasonably simple to parse. There's a number of
# directives which delineate sections but there's no section delineation.
# A section will "look" somewhat like this, most of the time:
# NAME: <name>
# IFDEF: <the ifdef bit>
# TYPE: <the config type>
# DEFAULT: <the default value>
# LOC: <location in the Config struct>
# DOC_START
#   documentation goes here
# NOCOMMENT_START
#   stuff which goes verbatim into the config file goes here
# NOCOMMENT_END
# DOC_END
#
# Now, we can't assume its going to be nicely nested, so I'll say that
# sections are delineated by NAME: lines, and then stuff is marked up
# appropriately.
#
# Then we have to fake paragraph markups as well for the documentation.
# We can at least use <PRE> type markups for the NOCOMMENT_START/_END stuff.

#
# Configuration sections are actually broken up by COMMENT_START/COMMENT_END
# bits, which we can use in the top-level index page. Nifty!
#

# XXX NAME: can actually have multiple entries on it; we should generate
# XXX a configuration index entry for each, linking back to the one entry.
# XXX I'll probably just choose the first entry in the list.

# 
# This code is ugly, but meh. We'll keep reading, line by line, and appending
# lines into 'state' variables until the next NAME comes up. We'll then
# shuffle everything off to a function to generate the page.

my ($state) = "";
my ($path) = "/tmp";
my ($name, $doc, $nin, @nocomment, $type, $default, $ifdef, $comment, $loc);
my ($default_if_none);
my (@names);

#
# Yes yes global variables suck. Rewrite it if you must.
#
sub generate_page()
{
	# XXX should make sure the config option is a valid unix filename!
	my ($fn) = $path . "/" . $name . ".html";

	my ($fh) = new IO::File;
	$fh->open($fn, "w") || die "Couldn't open $fn: $!\n";

	print $fh "name: $name\n";
	print $fh "default value: $default\n";
	print $fh "default if none: $default_if_none\n";

	close $fh;
	undef $fh;
}

while (<>) {
	chomp;
	next if (/^$/);
	if ($_ =~ /^NAME: (.*)$/) {
		# If we have a name already; shuffle the data off and blank
		if (defined $name && $name ne "") {
			generate_page();
		}
		$name = $1;
		$doc = "";
		$nin = "";
		undef @nocomment;
		$nin = 0;
		$type = "";
		$default = "";
		$ifdef = "";
		$loc = "";
		$comment = "";
		$default_if_none = "";
		unshift @names, $name;
		print "DEBUG: new section: $name\n";
	} elsif ($_ =~ /^COMMENT: (.*)$/) {
		$comment = $1;
	} elsif ($_ =~ /^TYPE: (.*)$/) {
		$type = $1;
	} elsif ($_ =~ /^DEFAULT: (.*)$/) {
		$default = $1;
	} elsif ($_ =~ /^LOC:(.*)$/) {
		$loc = $1;
		$loc =~ s/^[\s\t]*//;
	} elsif ($_ =~ /^DOC_START$/) {
		$state = "doc";
	} elsif ($_ =~ /^DOC_END$/) {
		$state = "";
	} elsif ($_ =~ /^DOC_NONE$/) {
		$state = "";
	} elsif ($_ =~ /^NOCOMMENT_START$/) {
		$state = "nocomment";
	} elsif ($_ =~ /^DEFAULT_IF_NONE: (.*)$/) {
		$default_if_none = $1;
	} elsif ($_ =~ /^NOCOMMENT_END$/) {
		$nin++;
		$state = "";
	} elsif ($_ =~ /^IFDEF: (.*)$/) {
		$ifdef = $1;
	} elsif ($state eq "doc") {
		$doc .= $_ . "\n";
	} elsif ($state eq "nocomment") {
		$nocomment[$nin] .= $_ . "\n";
	} else {
		print "DEBUG: unknown line '$_'\n";
	}
}

# print last section
if ($name ne "") {
	generate_page();
}

# and now, the index file!
