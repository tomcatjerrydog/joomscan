#!/usr/bin/perl
#
#            --------------------------------------------------
#                            OWASP JoomScan
#            --------------------------------------------------
#        Copyright (C) <2018>
#
#        This program is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        any later version.
#
#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#


$author="Mohammad Reza Espargham , Ali Razmjoo";$author.="big brother";
$version="1.0.1";$version.="";
$codename="";$codename.="";
$update="2018/10/08";$update.="";
$mmm=0;

system(($^O eq 'MSWin32') ? 'cls' : 'clear');
use if $^O eq "MSWin32", Win32::Console::ANSI;
use Term::ANSIColor;
use Getopt::Long;
use LWP;
use LWP::UserAgent;
use LWP::Simple;
use Cwd;                                                                       
$mepath = Cwd::realpath($0); $mepath =~ s#/[^/\\]*$##; 
$SIG{INT} = \&interrupt;
sub interrupt {
    fprint("\nShutting Down , Interrupt by user");
    do "$mepath/core/report.pl";
    print color("reset");
    exit 0;
}

%result = ('waf'=>'','cms_name'=>'','cms_ver'=>'','core_vul'=>'',
			'plugin'=>'','plugin_vul'=>'','register_page'=>'','admin_page'=>'',
			'interest_file'=>'','dir_list'=>'','wrong_config'=>'');
$split_str = "\n****************************************************************\n";

do "$mepath/core/header.pl";
do "$mepath/core/main.pl";
do "$mepath/modules/waf_detector.pl";
do "$mepath/exploit/jckeditor.pl";
do "$mepath/core/ver.pl";
do "$mepath/exploit/verexploit.pl";
do "$mepath/exploit/com_lfd.pl";
do "$mepath/modules/pathdisclure.pl";
do "$mepath/modules/debugmode.pl";
do "$mepath/modules/dirlisting.pl";
do "$mepath/modules/missconfig.pl";
do "$mepath/modules/cpfinder.pl";
do "$mepath/modules/robots.pl";
do "$mepath/modules/backupfinder.pl";
do "$mepath/modules/errfinder.pl";
do "$mepath/modules/reg.pl";
do "$mepath/modules/configfinder.pl";
do "$mepath/exploit/components.pl" if($components==1);

do "$mepath/core/report_json.pl";