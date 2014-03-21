use warnings;
use strict;
use Tree;
use Data::Dumper;


sub process {
  my ($directory) = @_;
  my $title;
  my $bug_code;
  my $bug_name;

  #"Use_of_Uninitialized_Variable" =>"Assigned value is garbage or undefined"
  my %bugs_string = ( "Divide_by_Zero" => "Division by zero",
                      "Memory_Leak" => "Memory leak",
                      "Use_of_Uninitialized_Variable" => "Uninitialized argument value",
                      "NULL_Pointer_Dereference" => "Dereference of null pointer",
                      "Process_Control" => "",
                      "Stack_Based_Buffer_Overflow" => "Memory leak",
                      "Heap_Based_Buffer_Overflow" => "Memory leak",
                      "Write_What_Where_Condition" => "",
                      "Buffer_Underwrite" => "Memory leak",
                      "Buffer_Overread" => "Memory leak",
                      "Buffer_Underread" => "Memory leak",
                      "Uncontrolled_Format_String" => "",
                      "External_Control_of_System_or_Configuration_Setting" => "",
                      "Improper_Handling_of_Unicode_Encoding" => "",
                      "Reliance_on_Data_Memory_Layout" => "",
                      "Integer_Overflow" => "Memory leak",
                      "Integer_Underflow" => "Memory leak",
                      "Unexpected_Sign_Extension" => "",
                      "Signed_to_Unsigned_Conversion_Error" => "",
                      "Unsigned_to_Signed_Conversion_Error" => "",
                      "Numeric_Truncation_Error" => "",
                      "Truncation_of_Security_Relevant_Information" => "",
                      "Omission_of_Security_Relevant_Information" => "",
                      "Sensitive_Information_Uncleared_Before_Release" => "",
                      "Relative_Path_Traversal" => "",
                      "Use_of_Inherently_Dangerous_Function" => "",
                      "Heap_Inspection" => "",
                      "Reliance_on_DNS_Lookups_in_Security_Decision" => "",
                      "Unchecked_Return_Value" => "",
                      "Incorrect_Check_of_Function_Return_Value" => "",
                      "Plaintext_Storage_of_Password" => "",
                      "Hard_Coded_Password" => "",
                      "Least_Privilege_Violation" => "",
                      "Improper_Check_for_Dropped_Privileges" => "",
                      "Improper_Access_Control" => "",
                      "Cleartext_Tx_Sensitive_Info" => "",
                      "Hard_Coded_Cryptographic_Key" => "",
                      "Missing_Required_Cryptographic_Step" => "",
                      "Use_Broken_Crypto" => "",
                      "Reversible_One_Way_Hash" => "",
                      "Weak_PRNG" => "",
                      "Signal_Handler_Race_Condition" => "",
                      "Race_Condition_Within_Thread" => "",
                      "TOC_TOU" => "",
                      "Absolute_Path_Traversal" => "",
                      "Insecure_Temporary_File" => "",
                      "Error_Without_Action" => "",
                      "Unchecked_Error_Condition" => "",
                      "Catch_Generic_Exception" => "",
                      "Throw_Generic_Exception" => "",
                      "Poor_Code_Quality" => "",
                      "Resource_Exhaustion" => "",
                      "Improper_Resource_Shutdown" => "",
                      "Double_Free" => "",
                      "Use_After_Free" => "",
                      "Untrusted_Search_Path" => "",
                      "Uncontrolled_Search_Path_Element" => "",
                      "Expected_Behavior_Violation" => "",
                      "Incomplete_Cleanup" => "",
                      "Addition_of_Data_Structure_Sentinel" => "",
                      "Use_of_sizeof_on_Pointer_Type" => "",
                      "Incorrect_Pointer_Scaling" => "",
                      "Use_of_Pointer_Subtraction_to_Determine_Size" => "",
                      "Undefined_Behavior_for_Input_to_API" => "",
                      "Missing_Default_Case_in_Switch" => "",
                      "Signal_Handler_Use_of_Non_Reentrant_Function" => "",
                      "Use_of_Incorrect_Operator" => "",
                      "Assigning_Instead_of_Comparing" => "",
                      "Comparing_Instead_of_Assigning" => "",
                      "Incorrect_Block_Delimitation" => "",
                      "Omitted_Break_Statement_in_Switch" => "",
                      "Public_Static_Field_Not_Final" => "",
                      "Embedded_Malicious_Code" => "",
                      "Trapdoor" => "",
                      "Logic_Time_Bomb" => "",
                      "Info_Exposure_Environment_Variables" => "",
                      "Info_Exposure_Debug_Log" => "",
                      "Info_Exposure_Shell_Error" => "",
                      "Suspicious_Comment" => "",
                      "Dead_Code" => "",
                      "Return_of_Stack_Variable_Address" => "",
                      "Unused_Variable" => "",
                      "Expression_Always_False" => "",
                      "Expression_Always_True" => "",
                      "Assignment_of_Fixed_Address_to_Pointer" => "",
                      "Attempt_to_Access_Child_of_Non_Structure_Pointer" => "",
                      "Free_Memory_Not_on_Heap" => "",
                      "Sensitive_Data_Storage_in_Improperly_Locked_Memory" => "",
                      "Multiple_Binds_Same_Port" => "",
                      "Unchecked_Loop_Condition" => "",
                      "Info_Exposure_by_Comment" => "",
                      "Reachable_Assertion" => "",
                      "Unverified_Password_Change" => "",
                      "Improper_Initialization" => "",
                      "Operation_on_Resource_in_Wrong_Phase_of_Lifetime" => "",
                      "Improper_Locking" => "",
                      "Operation_on_Resource_After_Expiration_or_Release" => "",
                      "Uncontrolled_Recursion" => "",
                      "Duplicate_Operations_on_Resource" => "",
                      "Use_of_Potentially_Dangerous_Function" => "",
                      "Integer_Overflow_to_Buffer_Overflow" => "",
                      "Incorrect_Conversion_Between_Numeric_Types" => "",
                      "Function_Call_With_Incorrect_Number_of_Arguments" => "",
                      "Function_Call_With_Incorrect_Variable_or_Reference_as_Argument" => "",
                      "NULL_Deref_From_Return" => "",
                      "Undefined_Behavior" => "",
                      "Free_Pointer_Not_at_Start_of_Buffer" => "",
                      "Mismatched_Memory_Management_Routines" => "",
                      "Missing_Reference_to_Active_File_Descriptor_or_Handle" => "",
                      "Missing_Release_of_File_Descriptor_or_Handle" => "",
                      "Use_of_RSA_Algorithm_Without_OAEP" => "",
                      "Path_Manipulation_Function_Without_Max_Sized_Buffer" => "",
                      "Uncontrolled_Mem_Alloc" => "",
                      "OS_Command_Injection" => "",
                      "Unlock_of_Resource_That_is_Not_Locked" => "",
                      "Infinite_Loop" => "",
                      "Type_Confusion" => "",
                      "LDAP_Injection" => "",
                     );

  if ($directory =~ m/CWE([^<]+)/){
    $title = $1;
  }

  $title = "CWE".$title;

  $title =~ s/\//_/g;

  if ($directory =~ m/CWE([0-9]+)_([^\/]+)/){
    $bug_code = $1;
    $bug_name = $2;
  }

  my $real_bug_name = $bugs_string{$bug_name};

  my $path = "/tmp/$title";
  my $command_process = "cd $directory && rm -f *.o && scan-build -o $path make -j8 2>&1";
  my $return_clang = `$command_process`;

  if($return_clang =~ m/contains no reports\./){
    warn "No report in directory: [$directory]\n\n";
  } elsif ($return_clang =~ m/scan-view $path\/([^']+)/) {

    my $file;
    my $file_report = $path."/".$1."/index.html";

    open($file, '<', $file_report) or die $!;

    my $tree = new Tree;
    my $tree_analyzer;

    while(<$file>){
      $tree_analyzer = $tree->building_tree($_);
    }

    print Dumper $tree_analyzer;

    my $count_ok = 0;
    my $count_fail = 0;

    my @data_files;

    foreach my $file_name (keys $tree_analyzer) {
      my $is_equal;

      if(defined $tree_analyzer->{$file_name}->{$real_bug_name}){
        $is_equal = "OK";
        $count_ok++;
      } elsif(not defined $tree_analyzer->{$file_name}->{$real_bug_name}){
        $is_equal = "Fail";
        $count_fail++;
      }

      my @bugs_file;

      foreach (keys $tree_analyzer->{$file_name}){
        push(@bugs_file, $_);
      }

      my $total_bugs_file = join(";",@bugs_file);

      push (@data_files, "$file_name,".
        "$real_bug_name,".
        "$total_bugs_file,".
        "$is_equal\n");
    }

    my $command_total_files = "cd $directory && ls CWE*.c* | wc -l";
    my $return_total_files = `$command_total_files`;

    my $percent_ok = ($count_ok/$return_total_files)*100;
    my $percent_fail = ($count_fail/$return_total_files)*100;
    my $files_not_reported = $return_total_files - ($count_fail + $count_ok);


    print "OK: [$count_ok]\n";
    print "FAIL: [$count_fail]\n";


    open my $csv_handler, '>'.$title.".csv" or die $!;

    print $csv_handler $title."\n";

    print $csv_handler "\nTotal files, $return_total_files\n";
    print $csv_handler "Files not reported, $files_not_reported\n\n";
    print $csv_handler "Total OKs, $count_ok, $percent_ok%\n";
    print $csv_handler "Total Fails, $count_fail, $percent_fail%\n\n";

    print $csv_handler "File, Expected Bugs, Found Bugs, Bug was found?\n\n";

    print $csv_handler join("", @data_files);

    close $csv_handler;
  }

  print "The directory [$directory] was processed!\n";
}

my $base_dir = $ARGV[0];
my @directories = ($base_dir);
my $current_dir;

while (@directories) {
  $current_dir = shift @directories;
  my $project_dir = 0;

  opendir (DIR, $current_dir) or die $!;

  while (my $file = readdir(DIR)){
    next if ($file =~ m/^\./);

    if (-d "$current_dir/$file"){
      my $current_file = "$current_dir/$file";
      $current_file =~ s/\/\//\//;

      push (@directories, $current_file);
    }
    elsif ($file =~ m/\.c$/ or $file =~ m/\.cpp$/) {
      $project_dir = 1;
    }
  }

  if ($project_dir == 1){
    process($current_dir);
  }

}

