#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use Data::Dump qw/dump/;
use Convert::ASN1 qw(asn_read);
use Net::LDAP::ASN qw(LDAPRequest LDAPResponse);
use Net::LDAP::Filter qw(Filter);
our $VERSION = '0.1';
use fields qw(socket target);
use Env qw(KEY_DIR SID BIND_DN BIND_PW LOG_FILE UPSTREAM_LDAP UPSTREAM_SSL LISTEN_SSL LISTEN_SSL_CERT LISTEN_SSL_KEY);

use SID qw(sid2config rid2sid sid2rid sid2string string2sid);
use Mangle qw(mangleFilter);
use SSHKey qw(keyExists keyContents);

defined $UPSTREAM_LDAP || die "Must set UPSTREAM_LDAP";
defined $BIND_DN       || die "Must set BIND_DN";
defined $BIND_PW       || die "Must set BIND_PW";
defined $SID           || die "Must set SID";
if ( $UPSTREAM_SSL ) {
    defined $LISTEN_SSL_CERT
      || die "If setting LISTEN_SSL you must set LISTEN_SSL_CERT";
    defined $LISTEN_SSL_KEY
      || die "If setting LISTEN_SSL you must set LISTEN_SSL_KEY";
}

my $config = {
    listen_addr     => shift @ARGV || '0.0.0.0',
    listen_port     => shift @ARGV || 389,
    listen_ssl      => $LISTEN_SSL || 0,
    listen_ssl_cert => $LISTEN_SSL_CERT,
    listen_ssl_key  => $LISTEN_SSL_KEY,
    upstream_ldap   => $UPSTREAM_LDAP,
    upstream_ssl    => $UPSTREAM_SSL || 0,
    bind_dn         => $BIND_DN,
    bind_pw         => $BIND_PW,
    sid             => sid2config($SID),
    key_dir         => $KEY_DIR
};

sub handle_client {
    my $client_socket = shift;
    my $server_socket = shift;
    asn_read( $client_socket, my $reqpdu );
    if ( !$reqpdu ) {
        return 0;    # client closed connection
    }
    my $request = handle_request($LDAPRequest->decode($reqpdu));
    $reqpdu = $LDAPRequest->encode($request);

    print $server_socket $reqpdu || return 0; # couldn't send to server..

    if (defined $request->{abandonRequest}) {
        return 0;
    }

    my $ready;
    my $sel = IO::Select->new($server_socket);
    for ( $ready = 1 ; $ready ; $ready = $sel->can_read(0) ) {
        asn_read( $server_socket, my $respdu );    # read from server
        if ( !$respdu ) {
            return 0;                             # server closed our connection
        }
        my $response = handle_response($LDAPResponse->decode($respdu));       # mangle response
        $respdu = $LDAPResponse->encode($response);
        print $client_socket $respdu || return 0;  # send res to client
    }

    return 1;
}

sub handle_request {
    my $request = shift;

    # rewrites anonymous bind requests to use service account
    if ( defined $request->{bindRequest} ) {
        my $old = $request->{bindRequest}->{name};
        if ( $old eq "" ) {
            $request->{bindRequest}->{name} = $config->{bind_dn};
            $request->{bindRequest}->{authentication} =
              { simple => $config->{bind_pw} };
        }
    }
    elsif ( defined $request->{searchRequest} ) {
        #warn dump($request->{searchRequest}->{filter});
        my $filter = $request->{searchRequest}->{filter};
        if ( defined $filter->{'and'} ) {
            my @new_filter;
            foreach my $f ( @{ $filter->{'and'} } ) {
                if (defined $f->{'or'}) {
                    my @or_filter;
                    foreach my $of ( @{ $f->{'or'} } ) {
                        $of = mangleFilter($of, $config->{sid});
                        if (defined $of) {
                            push @or_filter, $of
                        }
                    }
                    push @new_filter, {'or' => \@or_filter}
                } else {
                    $f = mangleFilter($f, $config->{sid});
                    if (defined $f) {
                        push @new_filter, $f
                    }
                }
            }
            $request->{searchRequest}->{filter}->{'and'} = \@new_filter;
        }

        my $f = bless($request->{searchRequest}->{filter}, 'Net::LDAP::Filter');
        $request->{searchRequest}->{filter} = $f;

        # TODO better respect this, currently we need to drop this in order
        # to ensure we are able to rewrite stuff correctly.
        $request->{searchRequest}->{attributes} = [];
        #warn dump($request->{searchRequest}->{filter});
    }
    #warn "Mangled request", dump($request);
    return $request;
}

sub handle_response {
    my $response = shift;
    if ( defined $response->{protocolOp}->{searchResEntry} ) {
        my $attrs = $response->{protocolOp}->{searchResEntry}->{attributes};
        my $objectClass;
        foreach my $attr ( @{$attrs} ) {
            if ( $attr->{type} eq 'objectClass' ) {
                $objectClass = $attr->{vals};
            }
        }
        my @attrs;
        if ( defined $objectClass ) {
            foreach my $attr ( @{$attrs} ) {
                my $values = $attr->{vals};
                if ( "user" ~~ $objectClass ) {
                    if ( $attr->{type} eq 'sAMAccountName' ) {
                        my $cn = $attr->{vals}[0];
                        push @attrs, { type => 'uid', vals => [$cn] };
                        push @attrs,
                          { type => 'homeDirectory', vals => ["/home/$cn"] };
                        push @attrs,
                          { type => 'loginShell', vals => ['/bin/bash'] };
                        # TODO read from file system, check if key exists etc
                        if (keyExists($cn, $config->{key_dir})) {
                            my $ssh_key = keyContents($cn, $config->{key_dir});
                            push @attrs, { type => 'sshPublicKey', vals => [$ssh_key] };
                        }
                    }
                    if ( $attr->{type} eq 'displayName' ) {
                        push @attrs, { type => 'gecos', vals => [ @$values ] };
                    }
                    if ( $attr->{type} eq 'objectSid' ) {
                        push @attrs,
                          {
                            type => 'uidNumber',
                            vals => [ sid2rid( @$values[0] ) ]
                          };
                    }
                    if ( $attr->{type} eq 'primaryGroupID' ) {
                        push @attrs,
                          { type => 'gidNumber', vals => [ @$values ]};
                    }
                }
                if ( "group" ~~ $objectClass ) {
                    if ( $attr->{type} eq 'objectSid' ) {
                        push @attrs,
                          {
                            type => 'gidNumber',
                            vals => [ sid2rid( @$values[0] ) ]
                          };
                    }
                    if ( $attr->{type} eq 'member' ) {
                        push @attrs,
                          { type => 'uniqueMember', vals => $values };
                    }
                }
            }
            push @{ $response->{protocolOp}->{searchResEntry}->{attributes} },
              $_
              foreach @attrs;
        }
    }
    #warn "Mangled response", dump($response);
    return $response
}


sub create_listener {
    my $sock;
    if ( $config->{listen_ssl} ) {
        $sock = IO::Socket::SSL->new(
            LocalAddr     => $config->{listen_addr},
            LocalPort     => $config->{listen_port},
            Listen        => 10,
            SSL_cert_file => $config->{listen_ssl_cert},
            SSL_key_file  => $config->{listen_ssl_key},
        ) || die "can't open listen socket: $!";
    }
    else {
        $sock = IO::Socket::INET->new(
            LocalAddr => $config->{listen_addr},
            LocalPort     => $config->{listen_port},
            Listen    => 10,
            Proto     => 'tcp',
            Reuse     => 1,
        ) || die "can't open listen socket: $!";
    }
    return $sock;
}

sub connect_to_server {
    my $sock;
    if ( $config->{upstream_ssl} ) {
        $sock = IO::Socket::SSL->new( $config->{upstream_ldap} . ':636' );
    }
    else {
        $sock = IO::Socket::INET->new(
            Proto    => 'tcp',
            PeerAddr => $config->{upstream_ldap},
            PeerPort => 389,
        );
    }
    die "can't open ", $config->{upstream_ldap}, " $!\n" unless $sock;
    return $sock;
}


sub run_proxy {
    print "Starting proxy\n";
    my $listener_sock = create_listener;
    my $server_sock; # connect lazily, TODO is this a bad idea?
    my $sel = IO::Select->new($listener_sock);
    while ( my @ready = $sel->can_read ) {
        foreach my $fh (@ready) {
            if ( $fh == $listener_sock ) {
                my $psock = $listener_sock->accept;
                my $paddr = $psock->peerhost;
                $sel->add($psock);
                print "Accepted connection from $paddr\n";
            }
            else {
                $server_sock->{$fh} ||= connect_to_server;
                if ( !handle_client( $fh, $server_sock->{$fh} ) ) {
                    $sel->remove( $server_sock->{$fh} );
                    $server_sock->{$fh}->close;
                    delete $server_sock->{$fh};
                    $sel->remove($fh);
                    $fh->close;
                }
            }
        }
    }
}

run_proxy;

exit 1;
