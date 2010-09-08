#!/usr/bin/perl
use DBI ;

my $dbh = undef ;

#--- 

my @sql_commands = (
'SET foreign_key_checks=0',
'UPDATE bugs SET bugs.cf_buildid = bugs.buildid WHERE bugs.bug_id = bugs.bug_id',
'UPDATE bugs SET bugs.cf_rootcause = bugs.rootcause WHERE bugs.bug_id = bugs.bug_id',
'INSERT  INTO cf_relaffected (id,value,sortkey) SELECT id,value,sortkey from versions on duplicate key UPDATE cf_relaffected.id=cf_relaffected.id',
'INSERT  INTO cf_reltarget (id,value,sortkey) SELECT id,value,sortkey from versions on duplicate key UPDATE cf_reltarget.id=cf_reltarget.id',
'INSERT  INTO cf_relfixed (id,value,sortkey) SELECT id,value,sortkey from versions on duplicate key UPDATE cf_relfixed.id=cf_relfixed.id',
'INSERT  INTO cf_relnote (id,value,sortkey) SELECT id,value,sortkey from versions on duplicate key UPDATE cf_relnote.id=cf_relnote.id',
'INSERT INTO bugs.cf_testtype(id,value,sortkey,isactive ) SELECT id,value,sortkey,isactive from bugs.testtype on duplicate key UPDATE cf_testtype.id=cf_testtype.id',
'INSERT INTO bug_cf_relaffected (bug_id,value ) SELECT bug_id,relaffected from bugs  on duplicate key UPDATE bug_cf_relaffected.bug_id=bugs.bug_id',
'INSERT INTO bug_cf_relfixed (bug_id,value ) SELECT bug_id,relfixed from bugs  on duplicate key UPDATE bug_cf_relfixed.bug_id=bugs.bug_id',
'INSERT INTO bug_cf_reltarget (bug_id,value ) SELECT bug_id,reltarget from bugs  on duplicate key UPDATE bug_cf_reltarget.bug_id=bugs.bug_id',
'INSERT INTO bug_cf_relnote (bug_id,value ) SELECT bug_id,relnote from bugs  on duplicate key UPDATE bug_cf_relnote.bug_id=bugs.bug_id',
'DELETE FROM `bugs`.`cf_testtype` WHERE `cf_testtype`.`id` = 1',
'UPDATE bugs SET bugs.cf_testtype = bugs.testtype WHERE bugs.bug_id = bugs.bug_id',
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


