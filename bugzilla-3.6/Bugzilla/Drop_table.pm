 # Obtain db handle
  use Bugzilla::DB;
  my $dbh = Bugzilla->dbh;
$dbh->bz_drop_column($table, $column);
