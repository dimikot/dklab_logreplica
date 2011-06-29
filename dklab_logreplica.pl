#!/usr/bin/perl -w
use strict;
use Fcntl qw(:DEFAULT :flock);
use IO::Select;
use File::Path;
use File::Basename;
use Getopt::Long;
use Digest::MD5 qw(md5_hex);


my $pid_file;
GetOptions("p=s" => \$pid_file);


sub usage {
	die 
		"dklab_logreplica: gathers logs from multiple machines into one place in realtime.\n" .
		"Version: 1.10, 2011-06-27\n" .
		"Author: dkLab, http://en.dklab.ru/lib/dklab_logreplica/\n" .
		"License: GPL\n" .
		"Usage:\n" .
		"  $0 path-to-config-file\n";
}


sub INFO { 6 }
sub WARN { 4 }
sub ERR  { 3 }
sub message {
	my ($level, $msg, @args) = @_;
	my $pri = ($level == INFO and "INFO" or $level == WARN and "WARN" or $level == ERR and " ERR" or "    ");
	my $text = (@args? sprintf($msg, @args) : $msg);
	$text =~ s/\s+$//sg;
	$text =~ s/^/sprintf("[%-5d %s] ", $$, $pri)/mge;
	print $text . "\n";
}


sub read_config {
	my ($file) = @_;
	open(local *F, $file) or die "Cannot read $file: $!\n";
	my $section = undef;
	my %options = (
		HOSTS => [],
		FILES => [],
	);
	while (<F>) {
		s/[#;].*//sg;
		s/^\s+|\s+$//sg;
		next if !length;
		if (/^\[(.*)\]/s) {
			$section = $1;
			next;
		}
		if (!$section) {
			my ($k, $v) = split /\s*=\s*/s, $_, 2;
			$options{$k} = $v;
		} elsif ($section eq "hosts") {
			my %host = ();
			if (m{^([^=\s]+) \s*=\s* (.*)}sx) {
				$host{alias} = $1;
				$_ = $2;
			}
			$host{orig} = $_;
			if (m{^([^@]+)@(.*)}s) {
				$host{user} = $1;
				$_ = $2;
			}
			if (m{^([^:/]+):(\d+)}s) {
				$host{port} = $2;
				$_ = $1;
			}
			$host{host} = $_;
			push @{$options{HOSTS}}, \%host;
		} elsif ($section eq "files") {
			push @{$options{FILES}}, $_;
		}
	}
	
	# Check options and assign defaults.
	$options{user} or die "Option 'user' is not specified at $file\n";
	$options{destination} or die "Option 'destination' is not specified at $file\n";
	$options{scoreboard} or die "Option 'scoreboard' is not specified at $file\n";
	$options{delay} ||= 1.0;
	$options{skip_destination_prefixes} ||= undef;
	
	message(INFO, "Loaded %s: %d hosts, %d filename wildcards", $file, scalar @{$options{HOSTS}}, scalar @{$options{FILES}});
	return \%options;
}


sub escapeshellarg {
	my ($arg) = @_;
	my $q = qq{\x27};
	my $qq = qq{\x22};
	return $arg if $arg !~ m/[\s$q$qq\\]/s && length($arg);
	# aaa'bbb  =>  'aaa'\'bbb'
	$arg =~ s/$q/$q\\$q$q/sg;
	return $q . $arg . $q;
}


sub spawn_all {
	my ($config, $pids) = @_;
	my $ppid = $$;
	foreach my $host (@{$config->{HOSTS}}) {
		my $name = $host->{orig};
		if ($pids->{$name}) {
			if (!kill(0, $pids->{$name})) { # exists but dead
				message(WARN, "Child process $pids->{$name} for host $name is dead, respawning...");
			} else {
				next;
			}
		}
		my $pid = fork();
		if (!defined $pid) {
			message(ERR, "Cannot fork() for host $name: $!");
			next;
		}
		if ($pid) {
			# Parent.
			message(INFO, "Spawned watcher process $pid for host $name");
			$pids->{$name} = $pid;
			next;
		} else {
			# Child.
			if (!eval { child($config, {%$host}, $ppid); 1 }) {
				die $@ if $@;
			}
			exit();
		}
	}
}


sub child {
	my ($config, $host, $ppid) = @_;
	my $pid; # ssh pid

	# Prepare signals.
	$SIG{HUP} = 'IGNORE';
	$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{HUP} = sub { $pid && kill 9, $pid; exit(1); };
	$SIG{ALRM} = sub {
		if (!kill(0, $ppid)) {
			# Parent is dead.
			die "Child $$ terminated, because parent $ppid is not alive\n";
		}
		alarm(1);
	};
	$SIG{ALRM}->();
	$pid_file = undef;

	# Create command-line to run SSH.
	my $scoreboard = load_scoreboard($config);
	my @cmd = (
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "PasswordAuthentication=no",
		"-l", ($host->{user} || $config->{user}),
		($host->{port}? ("-p", $host->{port}) : ()),
		$host->{host},
		"perl -e " . join(" ", map { escapeshellarg($_) } (
			DATA() . "\n" . "DATA_main();\n",
			pack_wildcards($config->{FILES}),
			pack_scoreboard($scoreboard, $host->{host}),
			$config->{delay},
		)),
	);
	# We cannot get rid of escapeshellarg(), because config ssh_options
	# may be passed as a plain text with multiple space-delimited 
	# options and quotes.
	my $cmd = join " ", map { escapeshellarg($_) } @cmd;
	$cmd =~ s/^(\S+)/$1 $config->{ssh_options}/s if $config->{ssh_options};
	my ($cmd_to_show) = $cmd =~ /^(.*?\s+-e\s+)/;
	message(INFO, "\$ $cmd_to_show...");

	# Run SSH and monitor its output.
	$pid = open(local *P, "-|");
	defined $pid or die "Cannot fork(): $!\n";
	if (!$pid) {
		exec($cmd) or die "Cannot run SSH: $!\n";
	}
	my $err = eval { child_monitoring_process($config, $host, \*P); 1 }? undef : $@;
	kill 9, $pid;
	close(P);
	message(ERR, "Message from SSH watcher: $err") if $err;
}


sub child_monitoring_process {
	my ($config, $host, $pipe) = @_;
	my $host_prefix = $host->{alias} || $host->{orig};
	local *OUT;
	my $cur = undef;
	while (<$pipe>) {
		if (m/^==>\s*(.*?)\s*<==/s) {
			if ($1) {
				# Start of data block.
				my $packed = $1;
#				open(local *L, ">>/var/log/tmp/$$");
#				print L "[" . scalar(localtime) . "] [$host_prefix] [" . $packed . "]\n";
#				close(L);
				$cur = unpack_scoreboard_item($packed, $host->{orig});
				my $dest = get_dest_file($config, $cur->{file});
				if (!defined $dest) {
					$cur = undef;
				} elsif ($dest eq "-") {
					*OUT = *STDOUT;
				} elsif (!open(OUT, ">>", $dest)) {
					message(ERR, "Cannot write to $dest: $!");
					$cur = undef;
				}
			} elsif ($cur) {
				# End of data block.
				save_scoreboard_item($config, $cur);
				my $old = select(OUT); $| = 1; select($old);
				$cur = undef;
			}
		} elsif ($cur) {
			print OUT $host_prefix . ": " . $_;
			$cur->{pos} += length;
		}
	}
	close(OUT) if $cur;
}


sub get_dest_file {
	my ($config, $path) = @_;
	if ($path =~ m{(^|/)\.\.?(/|$)}s) {
		message(ERR, "Path must not contain relative components, given $path");
		return;
	}
	my $prefixes = $config->{skip_destination_prefixes};
	if ($prefixes) {
		foreach my $prefix (split /:/s, $prefixes) {
			$prefix .= "/" if substr($prefix, -1) ne "/";
			if (0 == index($path, $prefix)) {
				 $path = substr($path, length($prefix));
				 last;
			}
		}
	}
	$path =~ s{^/+}{}sg;
	$path = $config->{destination} . "/" . $path;
	mkpath(dirname($path), 0, 0755);
	return $path;
}


#
# Scoreboard persistence abstraction.
# We use a separated file for each log source to minitize IO traffic
# and locking concurrency (the previous version uses a single file,
# but it results to strange bugs with file corruption; unfortunately
# I cannod discover their cause, they seems as Perl bugs or unexpected
# signals correlation).
#

sub load_scoreboard {
	my ($config) = @_;
	my @lines;
	foreach my $file (glob("$config->{scoreboard}/*.txt")) {
	    open(my $f, $file) or next;
	    flock($f, LOCK_SH);
	    my $line = <$f>;
	    close($f);
	    chomp $line;
	    push(@lines, $line . "\n");
	}
	return unpack_scoreboard(join "", @lines);
}


sub save_scoreboard_item {
	my ($config, $item) = @_;
	my $dir = $config->{scoreboard};
	if (!-d $dir) {
		mkdir($dir) or die "Cannot mkdir('$dir'): $!\n";
	}
	my $fname = $dir . "/" . md5_hex("$item->{host}|$item->{file}") . ".txt";
	sysopen(my $f, $fname, O_RDWR|O_CREAT) or die "Cannot open $fname for writing: $!\n";
	flock($f, LOCK_EX) or die "Cannot LOCK_EX $fname: $!\n";
	truncate($f, 0) or die "Cannot truncate $fname: $!\n";;
	print $f (pack_scoreboard_item($item) . "\n");
	close($f);
}

#
# End of scoreboard persistence.
#


sub pack_wildcards {
	my ($wildcards) = @_;
	return join("\n", @$wildcards);
}


sub cleanup {
	if ($pid_file) {
		unlink($pid_file);
		$pid_file = undef;
	}
}


sub main {
	my $conf = $ARGV[0] or usage();

	message(INFO, "Started logreplica process $$");
	if ($pid_file) {
		open(local *F, ">", $pid_file); print F $$; close(F);
	}
	
	my $config = read_config($conf);
	die "No hosts specified in $conf!\n" if !$config->{HOSTS};
	die "No files to monitor specified in $conf!\n" if !$config->{FILES};
	
	my %pids = ();

	$SIG{CHLD} = 'IGNORE';
	$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = sub { cleanup(); exit(1); };
	$SIG{HUP} = sub {
		message(INFO, "SIGHUP received, reloading...");
		if (!eval { $config = read_config($conf); 1 }) {
			message(ERR, $@) if $@;
		}
		foreach (keys %pids) {
			kill 2, $pids{$_};
		}
	};

	while (1) {
		spawn_all($config, \%pids);
		sleep 1;
	}
	
}


sub END {
	cleanup();
}


# Execute the main code.
eval(DATA()); die $@ if $@;
main();


#######################################################################
#######################################################################
sub DATA {{{ return <<'EOT';

sub DATA_main {
	my ($p_wildcards, $p_scoreboard, $p_delay) = @ARGV;
	defined $p_wildcards or die "Filename wildcards expected!\n";
	defined $p_scoreboard or die "Scoreboard data expected!\n";
	defined $p_delay or die "Delay value expected!\n";
	my $wildcards = unpack_wildcards($p_wildcards);
	my $scoreboard_hash = { map { ($_->{file} => $_) } @{unpack_scoreboard($p_scoreboard)} };
	$| = 1;
	tail_follow($wildcards, $scoreboard_hash, $p_delay);
}

sub tail_follow {
	my ($wildcards, $scoreboard_hash, $delay) = @_;
	my $last_ping = 0;
	while (1) {
		my @files = wildcards_to_pathes($wildcards);
		my $printed = 0;
		foreach my $file (@files) {
			my @stat = stat($file);
			my $inode = $stat[1];
			my $sb = $scoreboard_hash->{$file} ||= { file => $file, inode => $inode, pos => $stat[7] };
			-f $file or next;
			if (!open(local *F, $file)) {
				warn "Cannot open $file: $!\n";
				next;
			}
			if ($inode == $sb->{inode}) {
				seek(F, $sb->{pos}, 0);
			} else {
				warn "File $file rotated (old_inode=$sb->{inode}, new_inode=$inode), reading from the beginning.\n";
				$sb->{pos} = 0;
				$sb->{inode} = $inode;
			}
			my $i = 0;
			for (; <F>; $i++, $printed++) {
				print "==> " . pack_scoreboard_item($sb) . " <==\n" if !$i;
				print;
				$sb->{pos} += length;
			}
			print "==>  <==\n" if $i; # end of data
		}
		if (!$printed) {
			if (time() - $last_ping > 5) {
				print "==>  <==\n"; # ping
				$last_ping = time();
			}
			select(undef, undef, undef, $delay);
		}
	}
}

sub wildcards_to_pathes {
	my ($wildcards) = @_;
	return map { glob $_ } @$wildcards;
}

sub unpack_scoreboard {
	my ($packed) = @_;
	my @scoreboard = ();
	foreach (split /\n/s, $packed) {
		chomp;
		next if !$_;
		push @scoreboard, unpack_scoreboard_item($_);
	}
	return \@scoreboard;
}

sub pack_scoreboard {
	my ($scoreboard, $only_host) = @_;
	return join(
		"\n",
		map { pack_scoreboard_item($_) }
		grep { !defined($only_host) || $_->{host} eq $only_host }
		@$scoreboard
	) . "\n";
}

sub unpack_scoreboard_item {
	my ($packed, $def_host) = @_;
	$packed =~ s/^\s+|\s+$//sg;
	my ($fn, $inode, $pos, $host) = split /\|/, $packed, 4;
	return {
		file => $fn,
		inode => $inode,
		pos => $pos,
		host => $host || $def_host,
	};
}

sub pack_scoreboard_item {
	my ($item) = @_;
	return "$item->{file}|$item->{inode}|$item->{pos}|" . ($item->{host}||""); #89
}

sub unpack_wildcards {
	my ($packed) = @_;
	return [ grep { chomp; $_ } split /\n/s, $packed ];
}

EOT
}}}
#######################################################################
#######################################################################
