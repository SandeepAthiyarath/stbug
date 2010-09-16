#!/bin/bash
#Created for automating bugzilla installation at Stoke
#Fist let us backup the existing bugs database
echo "Taking dump of existing Bugzilla database if any"
mysqldump -u root -pSys1adm bugs > ./oldbugs.dump
# Drop the database bugs
echo "Droping the existing bugs database"
mysql -u  root -pSys1adm -e 'drop database bugs';
#Then create a frush bugs database
echo "Creating new bugs database"
mysql -u root -pSys1adm -e 'create database bugs';
#Restore the dump
echo "Restore the bugs database from old production"
mysql -u root -pSys1adm bugs < bugs.dump;
# Grant privilages
echo "Giving the privilages "
mysql -u root -pSys1adm -e 'grant all privileges on bugs.* to 'bugs'@'localhost' identified by 'bugs'';
# Call the  Initial DBI script
echo "Starting First DBI Script"
perl beforechecksetup.pl
# Then Run checksetup.pl
echo "Starting Checksetup.pl"
/var/www/bugzilla/checksetup.pl
echo "##########################################################"
echo "Checksetup.pl is finished "
echo "Now create the custom fileds from the Graphical Interface "
echo "And after that run perl aftercustomfield.pl script"
echo "##########################################################"
