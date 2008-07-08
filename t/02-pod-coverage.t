#!/usr/bin/env perl -w
use strict;
use Test::More;# qw(no_plan);

eval "use Test::Pod::Coverage;1";
if ( $@ ) {
   plan skip_all => "Test::Pod::Coverage required for testing pod coverage";
} else {
   plan tests => 1;
   pod_coverage_ok(
      "Win32::ASP::CGI",
      {
         trustme => [qw/
            OPTION
            Print
            cache
            escapeHTML
            new
            protocol
            self_or_default
            unescapeHTML
         /]
      }
   );
}
