#!/usr/bin/perl -w

use strict;
use IO::File;
use Getopt::Long;


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
my ($name);
my (@names);
my (%data);

# XXX should implement this!
sub uriescape($)
{
	my ($line) = @_;
	return $line;
}

sub htmlescape($)
{
	my ($line) = @_;
	$line =~ s/([^\w\s])/sprintf ("&#%d;", ord ($1))/ge;
	return $line;
}
my $verbose = '';
my $path = "/tmp";

GetOptions('verbose' => \$verbose, 'v' => \$verbose, 'out=s' => \$path);

#
# Yes, we could just read the template file in once..!
#
sub generate_page($$)
{
	my ($template, $data) = @_;
	# XXX should make sure the config option is a valid unix filename!
	my ($fn) = $path . "/" . $name . ".html";

	my ($fh) = new IO::File;
	my ($th) = new IO::File;
	$fh->open($fn, "w") || die "Couldn't open $fn: $!\n";
	$th->open($template, "r") || die "Couldn't open $template: $!\n";

	# add in the local variables
	$data->{"title"} = $data->{"name"};
	$data->{"ldoc"} = $data->{"doc"};
	# XXX can't do this and then HTML escape..
	# $data->{"ldoc"} =~ s/\n\n/<\/p>\n<p>\n/;
	# XXX and the end-of-line formatting to turn single \n's into <BR>\n's.

	while (<$th>) {
		# Do variable substitution
		s/%(.*?)%/htmlescape($data->{$1})/ge;
		print $fh $_;
	}

	close $fh;
	undef $fh;
}

while (<>) {
	chomp;
#	next if (/^$/);
	if ($_ =~ /^NAME: (.*)$/) {
		# If we have a name already; shuffle the data off and blank
		if (defined $name && $name ne "") {
			generate_page("template.html", \%data);
		}

		undef %data;
		$data{"doc"} = "";
		my ($r) = {};
		@{$r->{"aliases"}} = split(/ /, $1);
		$name = $r->{"name"} = $data{"name"} = $r->{"aliases"}[0];
		# names should only have one entry!
		shift @{$r->{"aliases"}};
		unshift @names, $r;
		print "DEBUG: new section: $name\n";
	} elsif ($_ =~ /^COMMENT: (.*)$/) {
		$data{"comment"} = $1;
	} elsif ($_ =~ /^TYPE: (.*)$/) {
		$data{"type"} = $1;
	} elsif ($_ =~ /^DEFAULT: (.*)$/) {
		$data{"default"} = $1;
	} elsif ($_ =~ /^LOC:(.*)$/) {
		$data{"loc"} = $1;
		$data{"loc"} =~ s/^[\s\t]*//;
	} elsif ($_ =~ /^DOC_START$/) {
		$state = "doc";
	} elsif ($_ =~ /^DOC_END$/) {
		$state = "";
	} elsif ($_ =~ /^DOC_NONE$/) {
		$state = "";
	} elsif ($_ =~ /^NOCOMMENT_START$/) {
		$state = "nocomment";
	} elsif ($_ =~ /^DEFAULT_IF_NONE: (.*)$/) {
		$data{"default_if_none"} = $1;
	} elsif ($_ =~ /^NOCOMMENT_END$/) {
		$state = "";
	} elsif ($_ =~ /^IFDEF: (.*)$/) {
		$data{"ifdef"} = $1;
	} elsif ($state eq "doc") {
		$data{"doc"} .= $_ . "\n";
	} elsif ($state eq "nocomment") {
		$data{"nocomment"} .= $_;
	} elsif ($_ ne "") {
		print "DEBUG: unknown line '$_'\n";
	}
}

# print last section
if ($name ne "") {
	generate_page("template.html", \%data);
}

# and now, the index file!
my ($fh) = new IO::File;

$fh->open($path . "/index.html", "w") || die "Couldn't open $path/index.html for writing: $!\n";

print $fh <<EOF
<html>
  <head>
    <title>Squid configuration file</title>
  </head>

  <body>
    <ul>
EOF
;

foreach (@names) {
	my ($n) = $_->{"name"};
	print $fh '    <li><a href="' . uriescape($n) . '.html">' . htmlescape($n) . "</a></li>\n";
	if (defined $_->{"aliases"}) {
		foreach (@{$_->{"aliases"}}) {
			print $fh '    <li><a href="' . uriescape($n) . '.html">' . htmlescape($_) . "</a></li>\n";
		}
	}
}

print $fh <<EOF
    </ul>
  </body>
</html>
EOF
;
$fh->close;
undef $fh;
