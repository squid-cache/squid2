: # *-*-perl-*-*
    eval 'exec perl -S $0 "$@"'
    if $running_under_some_shell;  
#
#  $Id$
#

$middle = <<'EOF';
static ext_table_entry ext_mime_table [] = {
EOF

$end = <<'EOF';
};
EOF


$line = 0;
$count = 0;
$err = 0;
undef(%table);
while(<>) {
	$line++;
	next if /^#/;
	s/^\s+//;
	s/\s+$//;
	next if /^$/;
	#tr/A-Z/a-z/;
	($ext, $type, $enc, $ver, $icon) = split;
	if(!defined($enc) || $type !~ /\//) {
		print STDERR "Error on line $line\n";
		$err++;
		next;
	}
	$ext =~ s/^\.//;
	if(defined($table{$ext})) {
		print STDERR "Duplicate extension on line $line\n";
		$err++;
		next;
	}
	$table{$ext} = join("\t", $type, $enc, $icon);
	$count++;
}

if($err > 0) {
	printf STDERR ("%s: %s not created\n", "$err errors", $out);
	exit(1);
}

if ($count <= 0) {
	printf STDERR ("%s: %s not created\n", "No valid lines", $out);
}

print "#define EXT_TABLE_LEN $count\n";
print $middle;
$i=0;
foreach $ext (sort(keys %table)) {
	$i++;
	($type, $enc, $icon) = split("\t", $table{$ext});
	printf "\t{\"%s\", \"%s\", \"%s\", \"%s\"}%s\n",
		$ext, $type, $enc, $icon,
		$i == $count ? '' : ',';
}
print $end;
exit(0);
