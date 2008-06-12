#!/usr/bin/env perl -w
use strict;
use strict;
use lib qw(lib t/lib);
use Test::More qw(no_plan);
use MockASP;
use Win32::ASP::CGI qw(:all);

# TODO

my %param  = map {$_ => [ param $_  ]} param;
my %cookie = map {$_ => [ cookie $_ ]} cookie;

ok(1);

1;

__END__
