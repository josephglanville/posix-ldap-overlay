#!/usr/bin/perl

#use strict;
use warnings;

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use Data::Dump qw/dump/;
use Convert::ASN1 qw(asn_read);
use Net::LDAP::ASN qw(LDAPRequest LDAPResponse);
use Net::LDAP::Filter qw(Filter);
our $VERSION = '0.1';
use fields qw(socket target);
use Env
  qw(SID BIND_DN BIND_PW LOG_FILE UPSTREAM_LDAP UPSTREAM_SSL LISTEN_SSL LISTEN_SSL_CERT LISTEN_SSL_KEY);
use Carp;

my $config = {
    listen_addr => shift @ARGV || '0.0.0.0',
    listen_port => shift @ARGV || 389,
    listen_ssl  => $LISTEN_SSL || 0,
    listen_ssl_cert => $LISTEN_SSL_CERT,
    listen_ssl_key  => $LISTEN_SSL_KEY,
    upstream_ldap   => $UPSTREAM_LDAP,
    upstream_ssl    => $UPSTREAM_SSL || 0,
    bind_dn         => $BIND_DN,
    bind_pw         => $BIND_PW,
    sid             => sid2config("$SID"),
};

defined $UPSTREAM_LDAP || die "Must set UPSTREAM_LDAP";
defined $BIND_DN       || die "Must set BIND_DN";
defined $BIND_PW       || die "Must set BIND_PW";
defined $SID           || die "Must set SID";
if ( $config->{listen_ssl} ) {
    defined $LISTEN_SSL_CERT
      || die "If setting LISTEN_SSL you must set LISTEN_SSL_CERT";
    defined $LISTEN_SSL_KEY
      || die "If setting LISTEN_SSL you must set LISTEN_SSL_KEY";
}

sub handle_client {
    my $client_socket = shift;
    my $server_socket = shift;
    asn_read( $client_socket, my $reqpdu );
    if ( !$reqpdu ) {
        return 0;    # client closed connection
    }
    $request = handle_request($LDAPRequest->decode($reqpdu));
    $reqpdu = $LDAPRequest->encode($request);

    print $server_socket $reqpdu || return 0; # couldn't send to server..

    my $ready;
    my $sel = IO::Select->new($server_socket);
    for ( $ready = 1 ; $ready ; $ready = $sel->can_read(0) ) {
        asn_read( $server_socket, my $respdu );    # read from server
        if ( !$respdu ) {
            return 0;                             # server closed our connection
        }
        $response = handle_response($LDAPResponse->decode($respdu));       # mangle response
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
        my $filter = $request->{searchRequest}->{filter};
        my @new_filter;
        if ( defined $filter->{'and'} ) {
            foreach my $f ( @{ $filter->{'and'} } ) {
                if ( defined $f->{equalityMatch} ) {
                    my $ad = $f->{equalityMatch}->{attributeDesc};
                    my $v  = $f->{equalityMatch}->{assertionValue};
                    # Rewrite posixAccount to user
                    if ( $ad eq 'objectclass' && $v eq 'posixAccount' ) {
                        push @new_filter,
                          {
                            equalityMatch => {
                                assertionValue => 'user',
                                attributeDesc => $ad
                            }
                          };
                    }
                    # Rewrite uid queries to sAMAccountName
                    elsif ( $ad eq 'uid' ) {
                        push @new_filter,
                          {
                            equalityMatch => {
                                attributeDesc => 'sAMAccountName',
                                assertionValue => $v
                            }
                          };
                    }
                    # Rewrite gidNumber queries to objectSid
                    elsif ( $ad eq 'gidNumber') {
                        push @new_filter,
                        {
                            equalityMatch => {
                                attributeDesc => 'objectSid',
                                assertionValue => rid2sid($v)
                            }
                        }
                    }
                    # Rewrite uidNumber queries to objectSid
                    elsif ( $ad eq 'uidNumber') {
                        push @new_filter,
                        {
                            equalityMatch => {
                                attributeDesc => 'objectSid',
                                assertionValue => rid2sid($v)
                            }
                        }
                    }
                    elsif ( $ad eq 'objectclass' && $v eq 'ldapPublicKey' ) {
                        # Black hole, we don't want this to hit AD
                    }
                    else {
                        push @new_filter,
                          {
                            equalityMatch => {
                                assertionValue => $v,
                                attributeDesc => $ad
                            }
                          };
                    }
                } else {
                    push @new_filter, $f;
                }
            }
        $request->{searchRequest}->{filter}->{'and'} = \@new_filter;
        }
        my $f = bless( $request->{searchRequest}->{filter}, 'Net::LDAP::Filter' );
        $request->{searchRequest}->{filter} = $f;
        # TODO better respect this, currently we need to drop this in order
        # to ensure we are able to rewrite stuff correctly.
        $request->{searchRequest}->{attributes} = [];
    }
    return $request;
}

sub sid2config {
    my $string = shift;
    my ( undef, $revision_level, $authority, @sub_authorities ) = split /-/, $string;
    return {
        revision_level => $revision_level,
        authority => $authority,
        sub_authorities => \@sub_authorities
    };
}

sub string2sid {
    my $string = shift;
    my ( undef, $revision_level, $authority, @sub_authorities ) = split /-/,
        $string;
    my $sub_authority_count = scalar @sub_authorities;
    my $sid = pack 'C Vxx C V*', $revision_level, $authority,
        $sub_authority_count, @sub_authorities;
    return $sid;
}

sub sid2string {
    my $sid = @_;
    my ($revision_level, $authority, $sub_authority_count, @sub_authoritied) =
      unpack 'C Vxx C V*', $sid;
    die if $sub_authority_count != scalar @sub_authorities;
    my $string = join '-', 'S', $revision_level, $authority, @sub_authorities;
    return $string;
}

sub sid2rid {
    my ($sid) = @_;
    my ( $revision_level, $authority, $sub_authority_count, @sub_authorities ) =
      unpack 'C Vxx C V*', $sid;
    #die if $sub_authority_count != scalar @sub_authorities;

    return $sub_authorities[-1];
}

sub rid2sid {
    my $rid = shift;
    my $sub_authorities = $config->{sid}->{sub_authorities};
    my @sub_authorities = @$sub_authorities;
    push @sub_authorities, $rid;
    my $sub_authority_count = scalar @sub_authorities;
    my $revision_level = $config->{sid}->{revision_level};
    my $authority = $config->{sid}->{authority};
    my $sid = pack 'C Vxx C V*', $revision_level, $authority,
        $sub_authority_count, @sub_authorities;
    return $sid;
}

my $ssh_key =
"ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxNxII7j9H5cdEM5YYkjRtr9z4AcAD3360UCzRHZfyXm8DkkMmXOrxgkMJOe2CjoOLJKkd4PmEFdULQRbceLFEQwAdckuGKIVnzWz+1IwSZNfNi62jG8qw2UkS5k6HhzZKjHoO85ysFfwSzTbV5ASrTfcfThrilsPE3T0FXWPYqc3iMZ+zIni9A+OHI35LnPuH1912+TnPByONJmAzmWievVnOwvLBjctmQulk/UFESizB5XtE6pfjcoFuFuJDxusJzNq0w8+GykRo5xtEdt4b0whUTwjx5apaWLGr3WxER/EB+4ly7H+SVervpqBVByUYS7qcfq2+mX33EWVJbkysw== joseph\@cloudscaling.com";

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

                        # TODO inject sshPublicKey here
                        #if ($cn eq 'ldap-connect') {
                          push @attrs, { type => 'sshPublicKey', vals => [$ssh_key] };
                        #}
                    }
                    if ( $attr->{type} eq 'displayName' ) {
                        push @attrs, { type => 'gecos', vals => $values };
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
                          { type => 'gidNumber', vals => $values };
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
#                    if ( $attr->{type} eq 'member' ) {
#                        push @attrs,
#                          { type => 'uniqueMember', vals => $values };
#                    }
                }
            }
            push @{ $response->{protocolOp}->{searchResEntry}->{attributes} },
              $_
              foreach @attrs;
        }
    }
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
        $sock = IO::Socket::SSL->new(
            PeerAddr => $config->{upstream_ldap},
            PeerPort => 636
        );
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
    my $server_sock;
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
