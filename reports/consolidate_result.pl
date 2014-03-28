use strict;
use warnings;

my $directory = $ARGV[0];

my $csv_files = `cd $directory && ls CWE*.csv`;
my @csv = split("\n", $csv_files);


my $total_files = 0;
my $total_files_not_reported = 0;
my $total_ok = 0;
my $total_fails = 0;

my @total_files_line;
my @total_files_not_reported_line;
my @total_ok_line;
my @total_fails_line;

foreach (@csv){
  print "[$_]";
  open FILE, "<", $_ or die $!;

  while (my $line = <FILE>){
    if ($line =~ m/Total files/){
      @total_files_line = split(", ", $line);
      chomp $total_files_line[1];
      $total_files += $total_files_line[1];
    }
    if ($line =~ m/Files not reported/){
      @total_files_not_reported_line = split(", ", $line);
      chomp $total_files_not_reported_line[1];
      $total_files_not_reported += $total_files_not_reported_line[1];
    }
    if ($line =~ m/Total OKs/){
      @total_ok_line = split(", ", $line);
      chomp $total_ok_line[1];
      $total_ok += $total_ok_line[1];
    }
    if ($line =~ m/Total Fails/){
      @total_fails_line = split(", ", $line);
      chomp $total_fails_line[1];
      $total_fails += $total_fails_line[1];
    }
  }

  close FILE;
}

print "TOTAL FILES: [$total_files]\n";
print "TOTAL OKs: [$total_ok]\n";
print "TOTAL FAILS: [$total_fails]\n";

my $percent_ok = ($total_ok/$total_files)*100;
my $percent_fails = ($total_fails/$total_files)*100;

open my $csv_handler, ">final_result.csv" or die $!;

print $csv_handler "Final result\n\n";

print $csv_handler "Total Files, $total_files\n";
print $csv_handler "Total Files not reported, $total_files_not_reported\n";
print $csv_handler "Total OKs, $total_ok, $percent_ok%\n";
print $csv_handler "Total Fails, $total_fails, $percent_fails%";

close $csv_handler;

