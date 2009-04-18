#!perl
die "OS unsupported\n" if $^O !~ m{ \A MSWin }xmsi;
use 5.008;
use strict;
use vars qw(%PREREQ %RECOMMEND %BUILDREQ);
use ExtUtils::MakeMaker;

do 'PREREQ' or die "Error including PREREQ: $@";

WriteMakefile(
   NAME	        => 'Win32::ASP::CGI',
   VERSION_FROM => 'lib/Win32/ASP/CGI.pm',
   PREREQ_PM    => { %PREREQ, %BUILDREQ },
   ($] >= 5.005 ? (
   AUTHOR       => 'Burak Gursoy',
   ABSTRACT     => 'CGI.pm like interface to Classic ASP Programming',
   ) : ()),
   PL_FILES => {},
);
