#!/usr/bin/perl
use strict;
use feature 'say';
## Simple pattern discovery script by ewilded
# Script discovers how many unique patterns appear in the log file. Patterns are distinguished based on the amount of sections representing normal words.


my $cnt=0;
my %lines; #lines matching to particular pattern

my @filters=(); ## filters to apply (regular expressions)
my @files=();
my $logs='';
my @log_contents=(); ## contents of all log files
my $reverse='off';
my $filters_active='on';
my $outputfile='report.txt';
my $short='on';
my $pregrepping='off';

my @pregrep_filter=('user','admin','login','logon','logout','sql','file','open','command','exec','session','sql','ora-','script','http','auth', 'error', 'failed', 'invalid', 'denied', 'permission', 'grant', 'allowed', 'forbidden','memory','shared','pass','database', 'db', 'exception', 'config', 'delete', 'could not', 'audit', 'account', 'lock', 'block');

sub load_logfiles
{
	@log_contents=();
	if(scalar(@files) eq 0)
	{
		print "First set the input files list (set logs path_to_files, e.g. set logs /cygdrive/c/logs/myapp/*log).\n";
		print "No files loaded.\n";
		return;
	}
	my $skipped=0;
	foreach my $file(@files)
	{
		print "Reading $file...";
		open(F,"<$file");
		if($pregrepping eq 'on')
		{
			my $pregrep_filter_str=join('|',@pregrep_filter);
			while(my $row=<F>)
			{
				if($row=~/$pregrep_filter_str/i)
				{
					push(@log_contents,$row);
				}
				else
				{
					$skipped++;
				}
			}
		}
		else
		{
			while(my $row=<F>)
			{
				chomp($row);
				push(@log_contents,$row);
			}
		}
		print " ok\n";
	}
	print scalar(@log_contents)." lines read.\n";
	print "$skipped values skipped due pregrepping filter.\n" if($pregrepping eq 'on');
}

sub process_the_line
{
	my $row=shift;
	my $pattern=$row;
	print "\n\n$row\n";
	$pattern=quotemeta $pattern;
	print "$pattern\n";
	$pattern=~s/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_-]+/g;
	if($lines{$pattern} eq undef)
	{
		$lines{$pattern}=();
		print "$pattern\n";
	}
	push(@{$lines{$pattern}},$row); ## holding references to the main array would save a bit of memory
}
sub process
{	
	if(scalar(@log_contents) eq 0)
	{
		print "No lines to process, maybe you forgot to load the log files?\n";
		return;
	}
	# flush results
	%lines=undef;
	$cnt=0;
	# process out only lines of our interest
	my $pcnt=0;
	my $five_prcent=int(scalar(@log_contents)/20);
	my $prcent_complete=0;
	print "Starting pattern discovery\n";
	foreach my $row(@log_contents)
	{
		next if($row eq undef);
		if($filters_active eq 'on' && scalar(@filters)>0)
		{
			my $filter_preg=join('|',@filters);
			my $match=1 if($row=~/$filter_preg/i);
			if(($match ne 1 && $reverse eq 'off')||($match eq 1 && $reverse eq 'on'))
			{
				&process_the_line($row);
			}
			else
			{
				$row=undef; # mark as undef to filter it out
			}
		}
		else
		{
			&process_the_line($row);
		}
		$pcnt++;
		if($five_prcent ne 0 && $pcnt%$five_prcent eq 0) 
		{
			$prcent_complete+=5;
			print "complete: $prcent_complete %\n";
		}
	}
	print "... done.\n";
}
	
sub save_results
{
	my @counters=();
	open(F,">$outputfile");
	foreach my $k(keys %lines)
	{
		next if($k eq '');
		push(@counters,scalar(@{$lines{$k}}));
	}
	my @new_counters=sort {$b <=> $a} @counters; ## sort descending
	#my @new_counters=sort @counters; ## sort descending
	my $last_count=undef;
	foreach my $count_key(@new_counters)
	{
		next if($last_count ne undef &&$last_count eq $count_key); ## unique
		$last_count=$count_key;
		foreach my $k(keys %lines)
		{
			next if($k eq '');
			if(scalar(@{$lines{$k}}) eq $count_key)
			{
				$cnt++;
				print F "PATTERN ($count_key matches): $k\n";
				if($short eq 'on')
				{
					print F "EXAMPLE: ".@{$lines{$k}}[0]."\n"; #only the first line is presented
				}	
				else
				{
					foreach my $row(@{$lines{$k}})
					{	
						print F "$row\n";
					}
				}
				print F "\n\n";
			}
		}
	}
	close(F);
	print "$cnt patterns discovered.\n";
}

## The interface
sub usage
{
	print "Available commands: load, help, process, exit, set option value, filter list|add <PCRE>|del <PCRE>\n";
	print "load - reads contentes of the log files into the memory\n";
	print "help - you are looking at it\n";
	print "process - processes log files contents according to current settings and writes the results to the output file\n";
	print "exit|quit - exits without saving\n";
	print "filter on|off - enables/disables filters (current value: $filters_active)\n";
	print "filter list - list applied filters\n";
	print "filter add <PCRE> - adds <PCRE> regular expression as filter\n";
	print "filter del <PCRE> - removes <PCRE> regular expression from filters\n";
	print "set option value - sets a value to particular option\n";
	print "available options:\n";
	print "\tlogs - path to logfile, wildcard allowed to point multiple files, current value: $logs\n"; 
	print "\toutputfile - where to save the analysis report, current setting: $outputfile\n";
	print "\treverse - on|off (on - filters serve for ignoring content, off - filters serve for narrowing the content down), current value: $reverse\n";
	print "\tshort  - on|off - whether or not to present only one example of line matchinig to particular pattern in final report (recommended, especially when log files are heavy), current value: $short\n";
}
print "SIEM dedicated log file analysis framework by ewilded\n";
print "> put commands here (see help for list of available commands\n> ";
while(my $input=<STDIN>)
{
	chomp($input);
	if($input eq 'load')
	{
		&load_logfiles();
		goto end;
	}
	if($input eq 'process')
	{
		&process();
		&save_results();
		goto end;
	}
	if($input=~/filter (add|del|list|off|on)\s*(.*)/)
	{
		my $cmd=$1;
		my $param=$2;
		$filters_active=$cmd if($cmd=~/^on|off$/);
		if($cmd eq 'list')
		{
				print "Current list of filters: ".scalar(@filters)."\n";
				foreach my $f(@filters)
				{
					print "$f\n";
				}
		}
		if($cmd eq 'del')
		{
			my @n=();
			foreach my $f(@filters)
			{
				push(@n,$f) if($f ne $param);
			}
			@filters=@n;
		}
		if($cmd eq 'add')
		{
			push(@filters,$param);
		}
		goto end;
	}
	if($input=~/^set (\w+)\s+(.*)/)
	{
		my $option=$1;
		my $value=$2;
		if($option eq 'logs')
		{
			$logs=$value;
			$value=`ls $value` if($value=~/\*/); ## shell injection possible here, so what :D ?
			@files=split(/\s+/,$value);
			my @n=();
			foreach my $f(@files)
			{
				if(! -f $f)
				{
					print "File $f does not exist.\n";
				}
				else
				{
					push(@n,$f);
				}
			}
			@files=@n;
			print scalar(@files)." log files set.\n";
			goto end;
		}
		if($option eq 'outputfile')
		{
			$outputfile=$value;
			print "Output file set to $outputfile\n";
			goto end;
		}
		if($option eq 'pregrepping')
		{
			$pregrepping=$value if($value=~/^on|off$/);
			goto end;
		}
		if($option eq 'short')
		{
			$short=$value if($value=~/^on|off$/);
			goto end;
		}
		if($option eq 'reverse')
		{
			$reverse=$value if($value=~/^on|off$/);
			goto end;
		}
	}
	exit 0 if($input=~/^exit|quit$/);
	&usage() if(!($input=~/^\s*$/));
	end:
	print "> ";
}
