BEGIN { die "OS unsupported\n" if $^O !~ m{ \A MSWin }xmsi; }
use 5.008;
use strict;
use vars qw( %PREREQ );
use Module::Build;
use Cwd;

do 'PREREQ' or die "Error including PREREQ: $@";

my $mb = Module::Build->new(
    module_name    => 'Win32::ASP::CGI',
    license        => 'perl',
    requires       => \%PREREQ,
    recommends     => {},
    sign           => 0,
    dist_author    => 'Burak Gursoy <burak@cpan.org>',
);

$mb->create_build_script;
