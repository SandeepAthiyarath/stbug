#!/usr/bin/perl
use DBI ;

my $dbh = undef ;


my @sql_commands = (
'SET foreign_key_checks=0',
'update bugs set bugs.reporter=1 where bugs.reporter=32',
'update longdescs set longdescs.who=1 where longdescs.who=0',
'update longdescs set longdescs.who=1 where longdescs.who=32',
'update longdescs set longdescs.who=1 where longdescs.who=1005',
) ;

#--- 
$dbh = DBI->connect('DBI:mysql:bugs;host=localhost', 'bugs', 'bugs',
                    { RaiseError => 1 }
                   );


foreach my $sql_cmd_string (@sql_commands) {
   print "\ndoing $sql_cmd_string\n" ;
   my $db_cmd = $dbh->prepare($sql_cmd_string) ;
   print $db_cmd->execute(), "\n" ;

} 

