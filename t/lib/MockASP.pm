# TODO
package Base;
BEGIN {
   $INC{'Base.pm'} = 1;
}
use strict;
use vars qw($VERSION @ISA);

my %RV = (
   REQUEST_METHOD => 'GET',
   # QS
   foo  => 'bar',
   perl => 'rocks',
);

sub Item {
   my $self = shift;
   my $item = $self->{Item};
   return $RV{ $item };
}

sub new {
   my $class = shift;
   my $item  = shift;
   my $self  = {Item => $item};
   warn "$class\n";
   bless $self, $class;
   $self;
}

package Request;
use strict;
use base qw(Base);

sub ServerVariables { shift; Request::ServerVariables->new(@_) }
sub Cookies         { shift; Request::Cookies->new(@_)         }
sub QueryString     { shift; return 'perl' if not @_; Request::QueryStringX->new(@_)     }
sub Form            { shift; Request::QueryStringX->new(@_)     }

package Request::ServerVariables;use base qw(Base);
package Request::QueryStringX;
use strict;
use base qw(Base);

sub Count {1}

package Request::Cookies;        use base qw(Base);

package Server;
use strict;
use base qw(Base);

sub URLEncode  {  }
sub HTMLEncode {  }

package Response;
use strict;
use base qw(Base);

sub Write       { shift; print @_ }
sub End         { die "end" }
sub BinaryWrite {}
sub AddHeader   {}

package MockASP;
use strict;
use vars qw($VERSION $Application $ObjectContext
            $Request $Response    $Server
            $Session);
BEGIN {
   $Request         = Request->new;
   $Server          = Server->new;
   $Response        = Response->new;
   $::Request       = $::Request        = $Request;
   $::Response      = $::Response       = $Response;
   $::Server        = $::Server         = $Server;
   $::Application   = $::Application    = $Application;   # null
   $::ObjectContext = $::ObjectContext  = $ObjectContext; # null
   $::Session       = $::Session        = $Session;       # null
}

1;

__END__