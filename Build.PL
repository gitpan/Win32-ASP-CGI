die "OS unsupported\n" if $^O !~ m{ \A MSWin }xmsi;
use 5.008;
use strict;
use vars qw(%PREREQ %RECOMMEND %BUILDREQ);
use Module::Build;
use Cwd;
use File::Spec;
use IO::File;

do 'PREREQ' or die "Error including PREREQ: $@";

my $class = Module::Build->subclass(
                class => 'MBSubclass',
                code  => raw_subclass(),
            );

my $mb = $class->new(
    module_name    => 'Win32::ASP::CGI',
    license        => 'perl',
    requires       => \%PREREQ,
    recommends     => \%RECOMMEND,
    build_requires => \%BUILDREQ,
    sign           => 0,
    dist_author    => 'Burak Gursoy <burak@cpan.org>',
    create_license => 1,
    no_index       => {
        directory => [
            'tools',
            't',
        ]
    },
    meta_merge => {
        resources => {
            repository => 'http://bitbucket.org/burak/cpan-win32-asp-cgi/',
        },
    },
);

$mb->create_build_script;

sub raw_subclass {
    my $file = File::Spec->catfile( 'tools', 'Build.pm' );
    my $FH   = IO::File->new;
    $FH->open( $file, 'r' ) or die "Can not open($file): $!";
    my $rv = do { local $/; <$FH> };
    close $FH;
    return $rv;
}
