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
my (%option);
my (%all_names);
my ($comment);

my $version = "2.HEAD";
my $verbose = '';
my $path = "/tmp";

GetOptions(
	'verbose' => \$verbose, 'v' => \$verbose,
	'out=s' => \$path,
	'version=s' => \$version
	);

# XXX should implement this!
sub uriescape($)
{
	my ($line) = @_;
	return $line;
}

sub filename($)
{
	my ($name) = @_;
	return $path . "/" . $name . ".html";
}

sub htmlescape($)
{
	my ($line) = @_;
	return "" if !defined $line;
	$line =~ s/([^\w\s])/sprintf ("&#%d;", ord ($1))/ge;
	return $line;
}

#
# Yes, we could just read the template file in once..!
#
sub generate_page($$)
{
	my ($template, $data) = @_;
	# XXX should make sure the config option is a valid unix filename!
	my ($fn) = filename($data->{'name'});

	my ($fh) = new IO::File;
	my ($th) = new IO::File;
	$fh->open($fn, "w") || die "Couldn't open $fn: $!\n";
	$th->open($template, "r") || die "Couldn't open $template: $!\n";

	# add in the local variables
	$data->{"title"} = $data->{"name"};
	$data->{"ldoc"} = $data->{"doc"};
	if (exists $data->{"aliases"}) {
		$data->{"aliaslist"} = join(", ", @{$data->{"aliases"}});
	}
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

my ($index) = new IO::File;

$index->open(filename("index"), "w") || die "Couldn't open ".filename("index").": $!\n";
print $index <<EOF
<html>
  <head>
    <title>Squid $version configuration file</title>
  </head>

  <body>
EOF
;


my ($name, $data);
my (@chained);

my $in_options = 0;
sub start_option($)
{
    my ($name) = @_;
    if (!$in_options) {
	print $index "<ul>\n";
	$in_options = 1;
    }
    print $index '    <li><a href="' . uriescape($name) . '.html" name="' . htmlescape($name) . '">' . htmlescape($name) . "</a></li>\n";
}
sub end_options()
{
    return if !$in_options;
    print $index "</ul>\n";
    $in_options = 0;
}
while (<>) {
	chomp;
	last if (/^EOF$/);
	if ($_ =~ /^NAME: (.*)$/) {
		my (@aliases) = split(/ /, $1);
		$data = {};
		foreach (@aliases) {
		    $all_names{$_} = $data;
		}

		$name = shift @aliases;

		$option{$name} = $data;
		$data->{'name'} = $name;
		$data->{'aliases'} = \@aliases;

		start_option($name);
		print "DEBUG: new option: $name\n" if $verbose;
	} elsif ($_ =~ /^COMMENT: (.*)$/) {
		$data->{"comment"} = $1;
	} elsif ($_ =~ /^TYPE: (.*)$/) {
		$data->{"type"} = $1;
	} elsif ($_ =~ /^DEFAULT: (.*)$/) {
		if ($1 eq "none") {
		    $data->{"default"} = "$1";
		} else {
		    $data->{"default"} = "$name $1";
		}
	} elsif ($_ =~ /^LOC:(.*)$/) {
		$data->{"loc"} = $1;
		$data->{"loc"} =~ s/^[\s\t]*//;
	} elsif ($_ =~ /^DOC_START$/) {
		$state = "doc";
	} elsif ($_ =~ /^DOC_END$/) {
		$state = "";
		my $othername;
		foreach $othername (@chained) {
		    $option{$othername}{'doc'} = $data->{'doc'};
		}
		undef @chained;
	} elsif ($_ =~ /^DOC_NONE$/) {
		push(@chained, $name);
	} elsif ($_ =~ /^NOCOMMENT_START$/) {
		$state = "nocomment";
	} elsif ($_ =~ /^DEFAULT_IF_NONE: (.*)$/) {
		$data->{"default_if_none"} = $1;
	} elsif ($_ =~ /^NOCOMMENT_END$/) {
		$state = "";
	} elsif ($_ =~ /^IFDEF: (.*)$/) {
		$data->{"ifdef"} = $1;
	} elsif ($_ =~ /^#/ && $state eq "doc") {
		$data->{"config"} .= $_ . "\n";
	} elsif ($state eq "nocomment") {
		$data->{"config"} .= $_ . "\n";
	} elsif ($state eq "doc") {
		$data->{"doc"} .= $_ . "\n";
	} elsif ($_ =~ /^COMMENT_START$/) {
		end_options;
		$state = "comment";
		$comment = "";
	} elsif ($_ =~ /^COMMENT_END$/) {
		print $index "<pre>\n";
		print $index $comment;
		print $index "</pre>\n";
	} elsif ($state eq "comment") {
		$comment .= $_ . "\n";
	} elsif (/^#/) {
		next;
	} elsif ($_ ne "") {
		print "NOTICE: unknown line '$_'\n";
	}
}
end_options;
print $index <<EOF
    </ul>
  <p><a href="index_all.html">Alphabetic index</a></p>
  </body>
</html>
EOF
;
$index->close;
undef $index;

# and now, build the option pages
my (@names) = keys %option;
foreach $name (@names) {
	generate_page("template.html", $option{$name});
}
# and now, the alpabetic index file!
my ($fh) = new IO::File;

my ($indexname) = filename("index_all");
$fh->open($indexname, "w") || die "Couldn't open $indexname for writing: $!\n";

print $fh <<EOF
<html>
  <head>
    <title>Squid $version configuration file index</title>
  </head>
  <p>| <a href="index.html">Back up to the index</a> |</p>

  <p>Alphabetic index of all options</p>

  <body>
    <ul>
EOF
;


foreach $name (sort keys %all_names) {
	my ($data) = $all_names{$name};
	print $fh '    <li><a href="' . uriescape($data->{'name'}) . '.html">' . htmlescape($name) . "</a></li>\n";
}

print $fh <<EOF
    </ul>
  <p>| <a href="index.html">Back up to the index</a> |</p>
  </body>
</html>
EOF
;
$fh->close;
undef $fh;
