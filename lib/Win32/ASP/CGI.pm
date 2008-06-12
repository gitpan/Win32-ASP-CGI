# This module includes modified code portions from CGI.pm distribution
#    CGI.pm Copyright 1995-1998 Lincoln D. Stein.  All rights reserved.
#    http://stein.cshl.org/WWW/software/CGI/
#
# This module includes modified code portions from Win32::ASP
#    Win32::ASP Copyright 1998 Matt Sergeant.  All rights reserved.
#    Win32::ASP Authors:
#       Matt Sergeant (through 2.12)
#       Bill Odom     (2.15 and later)
#
# Win32::ASP::CGI Copyright (c) 2008 Burak Gürsoy. All rights reserved.
#
package Win32::ASP::CGI::IO; # print overloading
use 5.008;
use strict;
use warnings;
use Win32::OLE::Variant;

sub new  { bless {}, shift }

sub print {
   my $self = shift;
   Win32::ASP::CGI::Print(@_);
   1;
}

sub TIEHANDLE { shift->new(@_)             }
sub PRINT     { shift->print(@_)           }
sub PRINTF    { shift->print(sprintf(shift, @_))  }

1;

package Win32::ASP::CGI;
use strict;
use warnings;
use vars qw(
   $Application   $ObjectContext $Request
   $Response      $Server        $Session
   @DeathHooks    $DIETMPL       $WARN
   $USE_PARAM_SEMICOLONS
);
# caller constants
use constant CPACKAGE    => 0;
use constant CFILENAME   => 1;
use constant CLINE       => 2;
use constant CSUBROUTINE => 3;
# modules
use Win32::OLE::Variant;
use Win32::OLE qw(in);
use Exporter ();
use Encode   ();
use CGI::Util qw( rearrange escape unescape );
use HTML::Entities;

BEGIN {
   # Set up the exportable ASP objects
   # while avoiding "only used once" warnings
   $Application   = $::Application    = $::Application;
   $ObjectContext = $::ObjectContext  = $::ObjectContext;
   $Request       = $::Request        = $::Request;
   $Response      = $::Response       = $::Response;
   $Server        = $::Server         = $::Server;
   $Session       = $::Session        = $::Session;
}

our $VERSION = '0.10';

our @ISA     = qw(Exporter);
our @EXPORT  = qw/
      Print        die            exit
      $Application $ObjectContext $Request
      $Response    $Server        $Session
   /;
our @EXPORT_OK   = qw( param cookie count );
our %EXPORT_TAGS = (all  => [ @EXPORT, @EXPORT_OK ] );

sub BinaryWrite(@); # silence the warning

# Create tied filehandle for print overloading.
tie   *RESPONSE_FH, 'Win32::ASP::CGI::IO';
select RESPONSE_FH;

$SIG{__WARN__} = sub {
   my $message = shift;
   chomp $message;
   if ( $WARN )  {
      if ( $WARN > 1 ) {
         my $stack = $WARN > 2 ? _caller_stack() : '';
         Print("<pre>[ WARNING ] ", $message, "$stack\n</pre>");
      }
      else {
         Print("<!-- ", $message, " -->\n");
      }
   }
   #CORE::warn($message);
};

my $DEFAULT; # default object

# yes, the template is from CGI::Carp
$DIETMPL = <<'FATAL_ERROR_TEMPLATE';
<div style="border: 1px dotted black; padding: 2px 10px 2px 10px">
   <p>
      <span style="font-size: 30; font-weight:bold">Software Error</span>
      <br />
      <pre style="border: 1px dotted #d7d7d7"><ERROR_MESSAGE></pre>
   </p>
   <p>
      For help, please send mail to this site's webmaster, giving this error
      message and the time and date of the error.
   </p>
</div>
FATAL_ERROR_TEMPLATE

sub OPTION {
   my $class = shift || die "Usage: Win32::ASP::CGI->OPTION( NAME => VALUE )";
   my $name  = shift || die "Usage: Win32::ASP::CGI->OPTION( NAME => VALUE )";
   my $value = shift;
   die "Usage: Win32::ASP::CGI->OPTION( NAME => VALUE )" if not defined $value;
   if ( uc($name) eq 'WARN' ) {
      $WARN = $value;
      return;
   }
   die "Unknown option: $name";
}

sub new {
   my $class = shift || __PACKAGE__;
   my $self  = {
      IS_DEFAULT   => 0,
      use_tempfile => 1, # always use a tempfile
   };
   bless $self, $class;
   $self;
}

sub self_or_default {
   my $this = __PACKAGE__;
   return @_ if defined($_[0]) && (!ref($_[0])) &&($_[0] eq $this);
   my $ok   = defined($_[0]) && 
             (
                 ref($_[0]) eq $this
                 ||
                 UNIVERSAL::isa( $_[0], $this )
              );
   if ( not $ok ) {
      if ( not defined $DEFAULT ) {
         $DEFAULT = $this->new;
         ++$DEFAULT->{IS_DEFAULT};
      }
      unshift @_, $DEFAULT;
   }
   return wantarray ? @_ : $DEFAULT;
}

sub Print {
   my($self, @out) = self_or_default(@_);
   foreach my $output ( @out ) {
      if ( length($output) > 128000 ) {
         Win32::ASP::CGI::Print(unpack('a128000a*', $output));
      }
      else {
         $Response->Write( $output );
      }
   }
}

sub BinaryWrite ( @ ) {
   my($self, @out) = self_or_default(@_);
   for my $output ( @out ) {
      if ( length($output) > 128000 ) {
         BinaryWrite( unpack('a128000a*', $output) );
      }
      else {
         my $variant = Win32::OLE::Variant->new( VT_UI1, $output );
         $::Response->BinaryWrite($variant);
      }
   }
}

sub bprint { &BinaryWrite }
sub print  { &Print       } # only for OO

sub die (@) {
   my($self, $message) = self_or_default(@_);
   my $error   = $DIETMPL;
      $error   =~ s{<ERROR_MESSAGE>}{$message}xms;
   Print $error, q{</body></html>};
   _END();
   $Response->End();
   CORE::die();
}

sub exit {
   _END();
   $Response->End();
   CORE::exit();
}

sub param (;$$) {
   my($self, @args) = self_or_default(@_);

   my $charset = $self->charset || '';
   my $utf8    = $charset =~ m{utf\-8}xmsi;

   RETURN_NAMES: if ( not @args ) {
      my     @keys;
      push   @keys, map { $_ } in $::Request->QueryString;
      push   @keys, map { $_ } in $::Request->Form;
      @keys = $self->_decoder( @keys ) if $utf8;
      return @keys;
   }

   my $name  = shift @args;
   my $index = shift @args;
      $index = 1 if not defined $index;

   my $handle = $self->_get_rhandle();
   # return a single value if context is scalar
   if ( not wantarray ) {
      my $single = $handle->($name)->Item($index);
      ($single)  = $self->_decoder( $single ) if $utf8;
      return $single;
   }
   # return a list
   my @ret;
   for my $i ( 1 .. $handle->($name)->Count ) {
      push @ret, $handle->($name)->Item($i);
   }
   @ret = $self->_decoder( @ret ) if $utf8;
   return @ret;
}

sub cookie {
   my($self, @args) = self_or_default(@_);
   my $many = @args > 1;
   my $list_context = wantarray;
   return        $self->_cookie_set(@args) if $many && $list_context;
   return scalar $self->_cookie_set(@args) if $many;
   return        $self->_cookie_get(@args) if $list_context;
   return scalar $self->_cookie_get(@args);
}

sub env {
   my($self,$id) = self_or_default(@_);
   if ( $id ) {
      return $Request->ServerVariables( $id )->{Item};
   }
   #return if not wantarray;
   my %env2;
   foreach my $var ( in $Request->ServerVariables ) {
      $env2{ $var } = $Request->ServerVariables( $var )->{Item};
   }
   return %env2;
}

sub unescapeHTML {
   my ($self,$string) = self_or_default(@_);
   return undef unless defined($string);
   my $charset = defined $self->{'.charset'} ? $self->{'.charset'} : undef;
   my $latin = $charset
             ? $self->{'.charset'} =~ /^(ISO-8859-1|WINDOWS-1252)$/i
             : 1;
   $string = decode_entities( $string );
   return $string;
}

sub escapeHTML {
   my ($self,$toencode,$newlinestoo) = self_or_default(@_);
   return undef unless defined($toencode);
   return $toencode if ref($self) && !$self->{'escape'};
   $toencode = encode_entities( $toencode );
   my $latin = uc $self->{'.charset'} eq 'ISO-8859-1' ||
               uc $self->{'.charset'} eq 'WINDOWS-1252';
   if ( $latin ) {
      if ( $newlinestoo ) {
         $toencode =~ s{\012}{&#10;}gso;
         $toencode =~ s{\015}{&#13;}gso;
      }
   }
   return $toencode;
}

sub redirect {
   my($self,$url) = self_or_default(@_);
   $Response->Redirect( $url );
   return;
}

sub header {
   my($self, @p) = self_or_default(@_);
   my(
      $type,  $status,     $cookie, $target, $expires,
       $nph, $charset, $attachment,    $p3p,   @other
   )
   = 
   rearrange([['TYPE','CONTENT_TYPE','CONTENT-TYPE'],
             'STATUS',['COOKIE','COOKIES'],'TARGET',
                            'EXPIRES','NPH','CHARSET',
                            'ATTACHMENT','P3P'],@p);
   $type    ||= 'text/html';
   $charset ||= '';

   my @headers;

   # rearrange() was designed for the HTML portion, so we
   # need to fix it up a little.
   foreach my $o ( @other ) {
      # Don't use \s because of perl bug 21951
      next unless my($header,$value) = $o =~ /([^ \r\n\t=]+)=\"?(.+?)\"?$/;
      ($o = $header) =~ s/^(\w)(.*)/"\u$1\L$2" . ': '.$self->unescapeHTML($value)/e;
   }

   $type .= "; charset=$charset"
      if     $type ne ''
         and $type !~ /\bcharset\b/
         and $charset ne '';

   # Maybe future compatibility.  Maybe not.
   my $protocol = env('SERVER_PROTOCOL') || 'HTTP/1.0';
   #push( @header, $protocol . ' ' . ($status || '200 OK')) if $nph;
   push( @headers, [ 'Server'       , &server_software ] ) if $nph;
   push( @headers, [ 'Status'       , $status          ] ) if $status;
   push( @headers, [ 'Window-Target', $target          ] ) if $target;

   if ( $p3p ) {
      $p3p = join ' ',@$p3p if ref($p3p) eq 'ARRAY';
      push @headers, [ 'P3P', qq(policyref="/w3c/p3p.xml", CP="$p3p") ];
   }

   # push all the cookies -- there may be several
   if ($cookie) {
      # Cookie stuff does not work from here. Call it separately.
      # A future version may implement an emulation
   }

   # if the user indicates an expiration time, then we need
   # both an Expires and a Date header (so that the browser is
   # uses OUR clock)
   push @headers, [ 'Expires', CGI::Util::expires($expires,'http') ] if $expires;
   push @headers, [ 'Date'   , CGI::Util::expires(0,'http')        ] if $expires || $cookie || $nph;
   #push(@header,"Pragma: no-cache") if $self->cache();
   push @headers, ['Content-Disposition', q{attachment; filename="$attachment"}] if $attachment;

   my %other = map {ucfirst $_} @other;

   foreach my $h ( sort keys %other ) {
      push @headers, [ $h => $other{ $h } ];
   }

   $Response->{Buffer} = 0; # disable buffering
   #my $cs    = $h{'-charset'} ? '; charset='.delete($h{'-charset'}) : '';
   #my $type  = $h{'-type'}    ? delete($h{'-type'})                 : 'text/html';
   #   $type .= $cs if $cs;
   $Response->{ContentType} = $type if $type;
   foreach my $type ( @headers ) {
      $Response->AddHeader( $type->[0], $type->[1] );
   }
   return 1;
}

sub charset {
   my ($self,$charset) = self_or_default(@_);
   $self->{'.charset'} = $charset if defined $charset;
   $self->{'.charset'};
}

sub cache {
   my($self,$new_value) = self_or_default(@_);
   $self->{'cache'}     = $new_value if defined $new_value;
   return $self->{'cache'};
}

sub query_string    { env('QUERY_STRING')                   }
sub server_port     { env('SERVER_PORT')     || 80          }
sub server_protocol { env('SERVER_PROTOCOL') || 'HTTP/1.0'  }
sub request_method  { env('REQUEST_METHOD')                 }
sub content_type    { env('CONTENT_TYPE')                   }
sub path_translated { env('PATH_TRANSLATED')                }
sub request_uri     { env('REQUEST_URI')                    }
sub remote_addr     { env('REMOTE_ADDR') || '127.0.0.1' }
sub remote_host     { env('REMOTE_HOST') || env('REMOTE_ADDR') || 'localhost' }
sub server_software { env('SERVER_SOFTWARE') || 'cmdline'   }
sub server_name     { env('SERVER_NAME')     || 'localhost' }
sub remote_ident    { env('REMOTE_IDENT')                   }
sub remote_user     { env('REMOTE_USER')                    }
sub auth_type       { env('AUTH_TYPE')                      }

sub user_name {
   my ($self) = self_or_default(@_);
   return $self->http('from') || env('REMOTE_IDENT') || env('REMOTE_USER');
}

sub virtual_port {
   my($self)    = self_or_default(@_);
   my $vh       = $self->http('x_forwarded_host') || $self->http('host');
   my $protocol = $self->protocol;
   if ( $vh ) {
      return ($vh =~ /:(\d+)$/)[0] || ($protocol eq 'https' ? 443 : 80);
   }
   else {
      return $self->server_port;
   }
}

sub virtual_host {
   my $vh = http('x_forwarded_host') || http('host') || server_name();
      $vh =~ s/:\d+$//; # get rid of port number
   return $vh;
}

sub referer {
   my($self) = self_or_default(@_);
   return $self->http('referer');
}

sub user_agent {
   my($self,$match) = self_or_default(@_);
   my $ua = $self->http('user_agent');
   return $ua if not $match;
   return $ua =~ /$match/i;
}

sub Accept {
   my($self,$search) = self_or_default(@_);
   my(%prefs,$type,$pref,$pat);

   my(@accept) = split(',',$self->http('accept'));

   foreach my $acc (@accept) {
      ($pref) = $acc =~ /q=(\d\.\d+|\d+)/;
      ($type) = $acc =~ m#(\S+/[^;]+)#;
      next unless $type;
      $prefs{$type}=$pref || 1;
   }

   return keys %prefs unless $search;

   # if a search type is provided, we may need to
   # perform a pattern matching operation.
   # The MIME types use a glob mechanism, which
   # is easily translated into a perl pattern match

   # First return the preference for directly supported
   # types:
   return $prefs{$search} if $prefs{$search};

   # Didn't get it, so try pattern matching.
   foreach my $pref (keys %prefs) {
      next unless $pref =~ /\*/;       # not a pattern match
      ($pat = $pref) =~ s/([^\w*])/\\$1/g; # escape meta characters
      $pat =~ s/\*/.*/g; # turn it into a pattern
      return $prefs{$pref} if $search=~/$pat/;
   }
}

sub protocol {
   local($^W)=0;
   my $self = shift;
   return 'https' if uc($self->https()) eq 'ON'; 
   return 'https' if $self->server_port == 443;
   my $prot = $self->server_protocol;
   my($protocol,$version) = split('/',$prot);
   return "\L$protocol\E";
}

sub http {
   my ($self,$parameter) = self_or_default(@_);
   return $self->env($parameter) if $parameter=~/^HTTP/;
   $parameter =~ tr/-/_/;
   return $self->env("HTTP_\U$parameter\E") if $parameter;
   my(@p);
   my %env = $self->env;
   foreach my $e (keys %env) {
      push(@p,$e) if $e =~ /^HTTP/;
   }
   return @p;
}

sub https {
   local($^W)=0;
   my ($self,$parameter) = self_or_default(@_);
   return env('HTTPS') unless $parameter;
   return  env($parameter) if $parameter=~/^HTTPS/;
   $parameter =~ tr/-/_/;
   return  env("HTTPS_\U$parameter\E") if $parameter;
   my(@p);
   my %env = $self->env;
   foreach my $e (keys %env) {
      push(@p,$e) if $e =~ /^HTTP/;
   }
   return @p;
}

#   my $path        =  $self->path_info;
#   my $script_name =  $self->script_name;
#   my $request_uri =  unescape($self->request_uri) || '';

sub path_info {
   my ($self,$info) = self_or_default(@_);
   if ( defined $info ) {
      $info = "/$info" if $info ne '' &&  substr($info,0,1) ne '/';
      $self->{'.path_info'} = $info;
   }
   elsif (! defined($self->{'.path_info'}) ) {
      my (undef,$path_info) = $self->_name_and_path_from_env;
      $self->{'.path_info'} = $path_info || '';
   }
   return $self->{'.path_info'};
}


sub url {
   my($self, @p) = self_or_default(@_);
   my($relative,$absolute,$full,$path_info,$query,$base,$rewrite) = 
   rearrange(
      [
       'RELATIVE','ABSOLUTE','FULL',
       ['PATH','PATH_INFO'],
       ['QUERY','QUERY_STRING'],
       'BASE','REWRITE'
      ],
      @p
   );
   my $url  = '';
   $full++      if $base || !($relative || $absolute);
   $rewrite++   unless defined $rewrite;

   my $path        =  $self->path_info;
   my $script_name =  $self->script_name;
   my $request_uri =  unescape($self->request_uri) || '';
   my $query_str   =  $self->query_string;

   my $rewrite_in_use = $request_uri && $request_uri !~ /^$script_name/;
   undef $path if $rewrite_in_use && $rewrite;  # path not valid when rewriting active

   my $uri         =  $rewrite && $request_uri ? $request_uri : $script_name;
   $uri            =~ s/\?.*$//;                                 # remove query string
   $uri            =~ s/\Q$path\E$//      if defined $path;      # remove path

   if ($full) {
      my $protocol = $self->protocol();
      $url = "$protocol://";
      my $vh = http('x_forwarded_host') || http('host');
      if ($vh) {
        $url .= $vh;
      } else {
        $url .= server_name();
         my $port = $self->server_port;
         unless (
            (lc($protocol) eq 'http'  && $port ==  80)
               ||
            (lc($protocol) eq 'https' && $port == 443)
         ) {
            $url .= ":" . $port
         }
      }
      return $url if $base;
      $url .= $uri;
   }
   elsif ($relative) {
      ($url) = $uri =~ m!([^/]+)$!;
   }
   elsif ($absolute) {
      $url = $uri;
   }

   $url .= $path         if $path_info and defined $path;
   $url .= "?$query_str" if $query     and $query_str ne '';
   $url =~ s/([^a-zA-Z0-9_.%;&?\/\\:+=~-])/sprintf("%%%02X",ord($1))/eg;
   return $url;
}

sub self_url {
   my($self,@p) = self_or_default(@_);
   return $self->url('-path_info'=>1,'-query'=>1,'-full'=>1,@p);
}

sub script_name {
   my ($self,@p) = self_or_default(@_);
   if (@p) {
      $self->{'.script_name'} = shift;
   } elsif (!exists $self->{'.script_name'}) {
      my ($script_name,$path_info) = $self->_name_and_path_from_env();
      $self->{'.script_name'} = $script_name;
   }
   return $self->{'.script_name'};
}

# Private Methods

sub _decoder {
   my $self = shift;
   my @data = @_;
   my @ok;
   foreach my $raw ( @data ) {
      push @ok, Encode::decode( utf8 => $raw );
   }
   return @ok;
}

sub _caller_stack {
   my $stack;
   my $id = 1;
   my @stack;
   my $space = q{ } x 4;
   while ( my @caller = caller $id++ ) {
      next if $caller[CLINE] < 1; # weird, but there may be a line zero
      $stack = join(" at ", $caller[CFILENAME], $caller[CLINE]);
      push @stack, $stack;
   }
   $stack = qq{\n${space}Caller Stack:\n};
   $id = 0;
   foreach my $buf ( reverse @stack) {
      $stack .= sprintf qq{${space}${space}[STEP % 2d] }, ++$id;
      $stack .= "$buf\n";
   }
   return $stack;
}

sub _name_and_path_from_env {
   my $self = shift;
   my $raw_script_name = env('SCRIPT_NAME') || '';
   my $raw_path_info   = env('PATH_INFO')   || '';
   my $uri             = unescape($self->request_uri) || '';

   my $protected    = quotemeta($raw_path_info);
   $raw_script_name =~ s/$protected$//;

   my @uri_double_slashes  = $uri =~ m^(/{2,}?)^g;
   my @path_double_slashes = "$raw_script_name $raw_path_info" =~ m^(/{2,}?)^g;

   my $apache_bug      = @uri_double_slashes != @path_double_slashes;
   return ($raw_script_name,$raw_path_info) unless $apache_bug;

   my $path_info_search = quotemeta($raw_path_info);
   $path_info_search    =~ s!/!/+!g;
   if ($uri =~ m/^(.+)($path_info_search)/) {
       return ($1,$2);
   } else {
       return ($raw_script_name,$raw_path_info);
   }
}

sub _get_rhandle { # get_request_handle
   return uc(env('REQUEST_METHOD')) eq 'GET'
          ? sub { $Request->QueryString($_[0]) }
          : sub { $Request->Form($_[0])        }   
}

sub _cookie_set ($$;%) {
   my ($self, @p) = self_or_default(@_);
   my($name,$value,$path,$domain,$secure,$expires,$httponly) =
   rearrange(['NAME',['VALUE','VALUES'], qw(PATH DOMAIN SECURE EXPIRES HTTPONLY) ],@p);
   if (ref($value) eq 'HASH') {
      $value = join( "\&" ,
         map { $::Server->URLEncode($_) . '=' . $::Server->URLEncode($$value{$_}) }
         keys %{ $value }
      )
   }

   $expires = CGI::Util::expires($expires, 'cookie') if $expires;

   my $extra  = '';
      $extra .= '; path='    . $path    if $path;
      $extra .= '; expires=' . $expires if $expires;
      $extra .= '; domain='  . $domain  if $domain;
      $extra .= '; secure'              if $secure;
      $extra .= '; HttpOnly'            if $httponly;

   $::Response->AddHeader( 'Set-Cookie', "$name=$value" . $extra );
}

sub _cookie_get (;$) {
   my($self, @args) = self_or_default(@_);
   if( not @args ) {
      my @names = map { $_ } in $::Request->Cookies;
      return @names or +();
   }
   my $name = shift @args;
   my $raw  = $::Request->Cookies($name)->Item;
   my %hash;
   my @values;
   foreach my $e (split /[&]/, $raw) {
      my($key, $value) = split /=/, $e;
      push @values, $value ? ($key => $value) : ($e);
   }
   return @values if wantarray;
   return $values[0];
}

sub DESTROY {
   my $self = shift;
   # if $self->{IS_DEFAULT};
}

# Legacy stuff

sub count ($) {
   my($self, $id) = self_or_default(@_);
   $self->_get_rhandle()->( $id )->Count;
}

sub _END {
   for my $func (@DeathHooks) {
      $func->();
   }
}

sub AddDeathHook(@) {
   push @DeathHooks, @_;
}

# Disabled in Win32::ASP and I did not test it yet. Might be buggy
# END { for my $func (@DeathHooks) { &$func() } }

__END__

=head1 NAME

Win32::ASP::CGI - A module for Classic ASP (PerlScript) Programming

=head1 SYNOPSIS

   <% @Language=PerlScript%>
   <%
   use Win32::ASP::CGI;

   my $r = Win32::ASP::CGI->new;

   $r->header(
      -type    => 'text/xml',
      -charset => 'utf8',
      '-Content-Length' => 1200,
   );
   my $test   = $r->param('test');
   my @select = $r->param('fruits');
   $r->print("Hello from Win32::ASP::CGI!");
   %>
   
   <% print "A bare print is also OK" %>

=head1 DESCRIPTION

This module is somewhat a re-write of L<Win32::ASP>. The main purpose of this
module is to provide an OO plug for abstract I<Request> classes which
are mostly implemented to support only C<CGI> and C<mod_perl> (and fastcgi).
C<Win32::ASP::CGI> supplies a L<CGI>.pm like interface for ASP programming.

This module may or may not be compatible with L<Win32::ASP>. Staying compatible
with L<Win32::ASP> is not intended.

=head1 METHODS

=head2 print

See L</Function Reference>

=head2 env

Wrapper around C<< $Request->ServerVariables >>:

    my $qs = $r->env('QUERY_STRING');

=head2 redirect URL

Redirects to the supplied URL.

=head2 charset

Set/Get the current charset.

=head2 url

=head2 self_url

See the I<"CREATING A SELF-REFERENCING URL THAT PRESERVES STATE INFORMATION">
section in L<CGI>.

=head2 FETCHING ENVIRONMENT VARIABLES 

Some of the more useful environment variables can be fetched through 
this interface. See L<CGI> for more information on these methods.
The methods are as follows:

=head3 query_string

=head3 server_port

=head3 server_protocol

=head3 request_method

=head3 content_type

=head3 path_translated

=head3 request_uri

=head3 remote_addr

=head3 remote_host

=head3 server_software

=head3 server_name

=head3 remote_ident

=head3 remote_user

=head3 auth_type

=head3 user_name

=head3 referer

=head3 virtual_port

=head3 virtual_host

=head3 user_agent

=head3 Accept

=head3 http

=head3 https

=head3 path_info

=head3 script_name

=head1 Function Reference

=head2 Overloaded built-ins

=head3 print LIST

Outputs a string or comma-separated list of strings to the browser. Use
as if you were using C<print> in a CGI application. C<print> handles the ASP
limitation of 128K per C<< $Response->Write >> call.

=head3 die LIST

Outputs the contents of LIST to the browser and then exits. C<die> automatically
calls C<< $Response->End >> and executes any cleanup code added with
C<AddDeathHook>.

=head3 exit

Exits the current script. C<exit> automatically
calls C<< $Response->End >> and executes any cleanup code added with
C<AddDeathHook>.

=head2 Web I/O Functions

=head3 param [NAME [, INDEX]]

Returns the value passed from a form (or non-form GET request). Use this
method if you want to be able to develop in GET mode (for ease of debugging)
and move to POST mode for release. The second (optional) parameter is for
getting multiple parameters, as in

    http://localhost/scripts/test.asp?Q=a&Q=b

In the above, S<C<param("Q", 1)>> returns "a" and S<C<param("Q", 2)>>
returns "b".

C<param> will work in an array context too, returning all the values
for a particular parameter. For example, with the above URL:

    my @AllQs = param('Q');

will result in the array C<@AllQs> containing C<('a', 'b')>.

If you call C<param> without any parameters, it will
return a list of form parameters in the same way that CGI.pm's C<param>
function does. This allows easy iteration over the form elements:

   foreach my $key (param()) {
      print "$key = ", param($key), "<br>\n";
   }

=head2 cookie [NAME [, VALUE [, HASH ] ] ]

This function tries to act like C<CGI::param>. It has two modes: read & write.

If called with no parameters, returns the names of the available
cookies.

If called with a single parameter, then, it will be recognized as
cookie C<NAME> and the value of the related cookie will be returned.

If called with two or more parameters, then it will write the cookie
named C<NAME> with value C<VALUE> to the client. The optional HASH
is used for write mode and can contain any of the following parameters:

=over 4

=item * -expires => A CGI.pm style expires value (see the CGI.pm header() documentation).

=item * -domain => a domain in the style ".matt.com" that the cookie is returned to.

=item * -path => a path that the cookie is returned to.

=item * -secure => cookie only gets returned under SSL if this is true.

=item * -httponly => cookie will have a HttpOnly flag if this is true.

=back

=head2 count EXPR

Returns the number of times EXPR appears in the request (Form or QueryString).
Use this value as C<$i> to iterate over S<C<param(EXPR, $i)>>.

For example, if the URL is:

    http://localhost/scripts/myscript.asp?Q=a&Q=b

And code is:

    my $numQs = count('Q');

Then C<$numQs> will equal 2.

=head2 bprint

Alias for L</BinaryWrite>.

=head2 Utility functions

The following are ported from L<Win32::ASP>.

=head3 AddDeathHook LIST

This frightening-sounding function allows you to have cleanup code
executed when you C<die> or C<exit>. For example, you may want to
disconnect from your database if there is a problem:

    <%
        my $Conn = $Server->CreateObject('ADODB.Connection');
        $Conn->Open( "DSN=BADEV1;UID=sa;DATABASE=ProjAlloc" );
        $Conn->BeginTrans();

        Win32::ASP::AddDeathHook( sub { $Conn->Close if $Conn; } );
    %>

Now when you C<die> because of an error, your database connection
will close gracefully, instead of you having loads of rogue connections
that you have to kill by hand, or restart your database once a day.

Death hooks are not executed upon the normal termination of the script,
so if you have processing that should occur upon a normal exit,
be sure to execute it directly.

=head3 BinaryWrite LIST

Performs the same function as C<< $Response->BinaryWrite >>, but handles
Perl's Unicode-related null padding. This function is not exported,
so call it as

  Win32::ASP::BinaryWrite($val);

Also available as C<bprint>

=head1 AUTHOR

Burak Gürsoy E<lt>F<burak@cpan.org>E<gt>.

=head1 COPYRIGHT

   This module includes modified code portions from CGI.pm distribution.
   CGI.pm Copyright 1995-1998 Lincoln D. Stein.  All rights reserved.
   http://stein.cshl.org/WWW/software/CGI/

   This module includes modified code portions from Win32::ASP
   Win32::ASP Copyright 1998 Matt Sergeant.  All rights reserved.
   Win32::ASP Authors:
      Matt Sergeant (through 2.12)
      Bill Odom     (2.15 and later)

Win32::ASP::CGI Copyright (c) 2008 Burak Gürsoy. All rights reserved.

=head1 LICENSE

This library is free software; you can redistribute it and/or modify 
it under the same terms as Perl itself, either Perl version 5.10.0 or, 
at your option, any later version of Perl 5 you may have available.

=cut
