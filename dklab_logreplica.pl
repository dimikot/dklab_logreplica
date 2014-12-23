#!/usr/bin/perl -w
use strict;
use Fcntl qw(:DEFAULT :flock);
use IO::Select;
use File::Path;
use File::Basename;
use Getopt::Long;
use Digest::MD5 qw(md5_hex);
use POSIX;

my ($pid_file, $log_priority, $log_tag, $daemonize);
GetOptions(
	"p=s" => \$pid_file,
	"log-priority=s" => \$log_priority,
	"log-tag=s" => \$log_tag,
	"daemonize" => \$daemonize,
);


sub usage {
	die
		"dklab_logreplica: gathers logs from multiple machines into one place in realtime.\n" .
		"Version: 1.12, 2013-04-13\n" .
		"Author: Dmitry Koterov, dkLab, http://en.dklab.ru/lib/dklab_logreplica/\n" .
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
		GROUP => {},
	);
	my %file_group = ();
	my $cur_group;
	while (<F>) {
                s/^\s*[#;].*//sg;
                s/^\s+//sg;
                s/\s*([;=])\s*/$1/sg;
                s/;+/;/sg;
                s/;*\s*$//sg;
		next if !length;
		if (/^\[(.*)\]/s) {
			$section = $1;
			next;
		}
		if (!$section) {
			my ($k, $v) = split /\s*=\s*/s, $_, 2;
			$v =~ s#[\s;]+##sg;
			$options{$k} = $v;
		} elsif ($section eq "hosts") {
			my %host = ();
			my @host_ = split /;/ , $_;
			$host{group} = $1  if $host_[1] && $host_[1] =~ s/group=(.*)//g ;
			$_ = $host_[0];
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
		} elsif ($section =~ m/group_files\w*/s) {
			push @{$file_group{$section}}, $_;
		}
	}
	$options{GROUP} = \%file_group if %file_group;

	# Check options and assign defaults.
	$options{user} or die "Option 'user' is not specified at $file\n";
	$options{destination} or die "Option 'destination' is not specified at $file\n";
	$options{scoreboard} or die "Option 'scoreboard' is not specified at $file\n";
	$options{repeat_command_timeout} ||= -1;
	$options{alarm_command} ||= "#";
	$options{filter} ||= '.*';
	$options{delay} ||= 1.0;
	$options{dest_separate} ||= '/';
	$options{skip_destination_prefixes} ||= undef;
	$options{server_id} ||= md5_hex(`hostname` . $file);
	if (!$options{speed_limit_filter} || ($options{speed_limit_filter} <= 0 )) {
		$options{sleep_send_line} = 0;
	} else {
		$options{sleep_send_line} = 1.0/$options{speed_limit_filter};
	}
	delete($options{speed_limit_filter});

	message(INFO, "Loaded %s: %d hosts, %d filename wildcards", $file, scalar @{$options{HOSTS}}, scalar @{$options{FILES}});
	return \%options;
}


sub escapeshellarg {
	my ($arg) = @_;
	my $q = qq{\x27};
	my $qq = qq{\x22};
	return $arg if $arg !~ m/[\s\|<>;\*\[\]\{\}\(\)\&\%\$\@\~\?$q$qq\\#]/s && length($arg);
	# aaa'bbb  =>  'aaa'\''bbb'
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
			if (!eval { child($config, {%$host}, $ppid, $host->{group} ||= undef); 1 }) {
				die $@ if $@;
			}
			exit();
		}
	}
}


sub child {
	my ($config, $host, $ppid, $group) = @_;
	my $pid; # ssh pid

	# Prepare signals.
	$SIG{HUP} = 'IGNORE';
	$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{HUP} = sub { $pid && kill 9, $pid; exit(1); };
	$pid_file = undef;

	# replace files to group_files 
	$config->{FILES}=$config->{GROUP}{$group} if $group && $config->{GROUP}{$group};
	
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
			$config->{server_id},
			($host->{alias} || $host->{host}),
			$config->{filter},
			$config->{repeat_command_timeout},
			$config->{alarm_command},
			$config->{sleep_send_line}
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
		# We use "exec" prefix to avoid creation of intermediate sh and
		# execute the ssh process as a direct child of the current one.
		exec("exec $cmd") or die "Cannot run SSH: $!\n";
	}
	my $err = eval { child_monitoring_process($config, $host, \*P, $ppid); 1 }? undef : $@;
	kill 9, $pid;
	close(P);
	message(ERR, "Message from SSH watcher: $err") if $err;
}

sub child_monitoring_process {
	my ($config, $host, $pipe, $ppid) = @_;
	my $host_prefix = $host->{alias} || $host->{orig};
	local *OUT;
	my $s = IO::Select->new();
	$s->add($pipe);
	my $cur = undef;
	my $ppid_check_at = 0;
	my $line_in_lump = 0;
	while (1) {
		# Check if the parent still lives (not frequently than once per 1000
		# lines within a solid block to save time() syscall penalty).
		# Unfortunately we cannot perform this check with SIGALRM, because
		# SIGALRM may break the same process'es read() syscall (or any other
		# syscall), so we have to do it using select().
		my $time = $line_in_lump < 1000? 0 : time();
		if ($time > $ppid_check_at + 1) {
			if (!kill(0, $ppid)) {
				die "Child $$ terminated, because parent $ppid is not alive\n";
			}
			$ppid_check_at = $time;
			$line_in_lump = 0; # new lump
		}
		# Wait for data no more than 1 second (if more, retry with parent check).
		if ($s->can_read(1)) {
			$_ = <$pipe>;
			last if !defined;
			$line_in_lump++;
		} else {
			$line_in_lump = 1e10;
			next;
		}
		# Process the line which was read.
		if (m/^==>\s*(.*?)\s*<==/s) {
			if ($1) {
				# Start of data block.
				my $packed = $1;
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
			if (m#<FiLe_CoMmAnD>alarm_command=([^;]+);file=([^<]+)</FiLe_CoMmAnD>#s) { # catch a certain sequence of characters and parameters parse
				my	$command = $1;
				my	$file = $2;
				s#<FiLe_CoMmAnD>[^<]*</FiLe_CoMmAnD>##gs; # Then to wipe
				system "$command " . escapeshellarg("$host_prefix: $file: $_")  or die "Cannot exec command: $command: $!\n";
			}
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
	$path =~ s#/#$config->{dest_separate}#g; # here the character replaces on another character
	my @p = split /;/s, $path;
	$path = $p[0];
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

	if ($log_priority || $log_tag || $daemonize) {
		if ($daemonize) {
			POSIX::setsid() or die "Cannot run setsid: $!\n";
			my $pid = fork();
			if (!defined $pid) {
				die "Cannot fork: $!\n";
			} elsif ($pid) {
				exit 0;
			}
		}
		$log_priority ||= "local3.info";
		$log_tag ||= "logreplica";
		foreach (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024)) {
			POSIX::close($_);
		}
		open(STDIN, "<", "/dev/null");
		open(STDOUT, "|-", "logger", "-p", $log_priority, "-t", $log_tag) or die "Cannot run logger process: $!\n";
		open(STDERR, ">&STDOUT");
		$0 = "dklab_logreplica";
	}

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
		sleep 10;
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
use Fcntl qw(:flock);
use Digest::MD5 qw(md5_hex);

my $my_host = "?";
sub my_die($) {
	my ($s) = @_;
	$s =~ s/^/$my_host says: /mg;
	die $s;
}
sub my_warn($) {
	my ($s) = @_;
	$s =~ s/^/$my_host says: /mg;
	warn $s;
}
sub DATA_main {
	my ($p_wildcards, $p_scoreboard, $p_delay, $p_server_id, $p_my_host, $filter, $repeat_command_timeout, $alarm_command, $sleep_send_line) = @ARGV;
	$my_host = $p_my_host;
	defined $p_wildcards or my_die "Filename wildcards expected!\n";
	defined $p_scoreboard or my_die "Scoreboard data expected!\n";
	defined $p_delay or my_die "Delay value expected!\n";
	my $wildcards = unpack_wildcards($p_wildcards);
	my $scoreboard_hash = { map { ($_->{file} => $_) } @{unpack_scoreboard($p_scoreboard)} };
	$| = 1;
	# Allow no more than 1 process from a particular server. This avoids
	# stalled scripts when connection is not closed properly.
	my $lock_file = "/tmp/logreplica.$p_server_id.lock"; # /tmp availables to all users
	open(LOCK, "+>>", $lock_file) or my_die "Cannot write to $lock_file: $!\n";
	if (!flock(LOCK, LOCK_EX | LOCK_NB)) {
		seek(LOCK, 0, 0);
		my $pid = int(<LOCK>);
		my_warn "Somebody else (PID=$pid) is already running for server_id=$p_server_id, killing him.\n";
		kill(15, $pid);
		sleep(2);
		if (!flock(LOCK, LOCK_EX | LOCK_NB)) {
			my_die "He is still alive after killing; cannot continue, aborting.\n";
		} else {
			my_warn "OK, I am the one now! Continue.\n";
		}
	}
	truncate(LOCK, 0);
	select((select(LOCK), $| = 1)[0]);
	print LOCK $$ . "\n";
	# Do not close LOCK!
	tail_follow($wildcards, $scoreboard_hash, $p_delay, $filter, $repeat_command_timeout, $alarm_command, $sleep_send_line);
}
sub tail_follow {
	my ($wildcards, $scoreboard_hash, $delay, $filter, $repeat_command_timeout, $alarm_command, $sleep_send_line) = @_;
	my $last_ping = 0;
	my %time_sb = ();
	my %time_cmd = ();
	while (1) {
		my @files = wildcards_to_pathes($wildcards);
		my $printed = 0;
		foreach my $file_ (@files) {
			my $fltr = $filter;
			my $command = $alarm_command;
			my $timeout = $repeat_command_timeout;
			my @fls = split /;/ ,$file_;
			my $file = $fls[0];
			foreach my $i (@fls) { # it overrides the global parametrs
				$fltr = $1 if $i =~ m/^filter=(.*)/ ;
				$command = $1 if $i =~ m/^alarm_command=(.*)/ ;
				$timeout= $1 if $i =~ m/^repeat_command_timeout=(.*)/ ;
			}
			$timeout *= 60;
			my @stat = stat($file);
			my $inode = $stat[1];
			my $sb_sent = 0;
			my $tail = $file . ";" . md5_hex("$fltr");
			my $sb = $scoreboard_hash->{$tail} ||= { file => $tail, inode => $inode, pos => $stat[7] };
			-f $file or next;
			if (!open(local *F, $file)) {
				my_warn "Cannot open $file: $!\n";
				next;
			}
			if ($inode == $sb->{inode}) {
				seek(F, $sb->{pos}, 0);
			} else {
				my_warn "File $sb->{host}:$file rotated, reading from the beginning (old_inode=$sb->{inode}, new_inode=$inode, old_pos=$sb->{pos}, new_pos=0).\n";
				$sb->{pos} = 0;
				$sb->{inode} = $inode;
				print_scoreboard_item($sb);
				$sb_sent = 1;
			}
			$time_sb{$tail} ||= 0;
			$time_cmd{$file} ||= 0;
			while (<F>) {
				next if  !m/^[^\n]*\n/s ;
				my $notice = "";
				if ($fltr ne '.*') {
					if ( m#$fltr# ) { 
						if ( $command ne "#" ) { #There is command in the config file
							if ($time_cmd{$tail} < ( time() - $timeout )){
								$time_cmd{$tail} = time();
								$notice = "<FiLe_CoMmAnD>alarm_command=".$command.";file=".$file."</FiLe_CoMmAnD>"; # pack parametrs into the message
							}
						}
					} else {
						$sb->{pos} += length;
						next if ($time_sb{$tail} > (time() - 2)) ;
						$time_sb{$tail} = time();
						$_ = "";
					}
				
					select(undef, undef, undef, $sleep_send_line) if $sleep_send_line != 0; # Speed limit transmission 
				}
				if (!$sb_sent) {
					print_scoreboard_item($sb);
					$sb_sent = 1;
				}
				print $notice . $_;
				$printed = 1;
				$sb->{pos} += length;
			}
			print_scoreboard_item(undef) if $sb_sent; # end of data
		}
		if (!$printed) {
			if (time() - $last_ping > 5) {
				print_scoreboard_item(undef); # ping
				$last_ping = time();
			}
			select(undef, undef, undef, $delay);
		}
	}
}
sub print_scoreboard_item {
	my ($item) = @_;
	print "==> " . ($item? pack_scoreboard_item($item) : "") . " <==\n";
}
sub wildcards_to_pathes {
	my ($wildcards) = @_;
	my @mapfile;
	foreach my $i (@$wildcards) {
		my @ii = split /;/,$i,2;
		foreach my $j (glob $ii[0]) {
			my $tail="";
			$tail=";".$ii[1] if $ii[1];
			push @mapfile,$j.$tail;
		}
	}
return @mapfile;
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
