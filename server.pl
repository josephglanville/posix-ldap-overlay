#!/usr/bin/perl

use strict;
use warnings;

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use Data::Dump qw/dump/;
use Convert::ASN1 qw(asn_read);
use Net::LDAP::ASN qw(LDAPRequest LDAPResponse);
our $VERSION = '0.1';
use fields qw(socket target);
use Env qw(BIND_DN BIND_PW LOG_FILE UPSTREAM_LDAP UPSTREAM_SSL);

defined $UPSTREAM_LDAP || die "Must set UPSTREAM_LDAP";
defined $BIND_DN || die "Must set BIND_DN";
defined $BIND_PW || die "Must set BIND_PW";

my $config = {
    listen         => shift @ARGV || '0.0.0.0:389',
    upstream_ldap  => $UPSTREAM_LDAP,
    upstream_ssl   => $UPSTREAM_SSL || 0,
    bind_dn        => $BIND_DN,
    bind_pw        => $BIND_PW,
};

sub handle {
    my $clientsocket = shift;
    my $serversocket = shift;
    asn_read( $clientsocket, my $reqpdu );
    if ( !$reqpdu ) {
        return 0; # client closed connection
    }
    $reqpdu = handle_request($reqpdu);

    print $serversocket $reqpdu or die "Could not send PDU to server\n ";

    my $ready;
    my $sel = IO::Select->new($serversocket);
    for ( $ready = 1 ; $ready ; $ready = $sel->can_read(0) ) {
        asn_read( $serversocket, my $respdu ); # read from server
        if ( !$respdu ) {
            return 0; # server closed our connection
        }
        $respdu = handle_response($respdu); # mangle response
        print $clientsocket $respdu || return 0; # send res to client
    }

    return 1;
}

sub handle_request {
    my $pdu = shift;

    die "empty pdu" unless $pdu;

    my $request = $LDAPRequest->decode($pdu);

    #TODO rewrite requests for uidNumber or gidNumber to objectSid

    # rewrites bind requests to use service account
    if ( defined $request->{bindRequest} ) {
        $request->{bindRequest}->{name} = $config->{bind_dn};
        $request->{bindRequest}->{authentication} = { simple => $config->{bind_pw} };
    $pdu = $LDAPRequest->encode($request);
    }

    return $pdu;
}

sub sid2rid {
  my ($sid) = @_;
  my ($revision_level, $authority, $sub_authority_count,
    @sub_authorities) = unpack 'C Vxx C V*', $sid;
  die if $sub_authority_count != scalar @sub_authorities;
  return $sub_authorities[4]
}

sub handle_response {
    my $pdu = shift;
    die "empty pdu" unless $pdu;
    my $response = $LDAPResponse->decode($pdu);
    if ( defined $response->{protocolOp}->{searchResEntry} ) {
        my $attrs = $response->{protocolOp}->{searchResEntry}->{attributes};
        my $objectClass;
        foreach my $attr ( @{ $attrs } ) {
          if ( $attr->{type} eq 'objectClass' ) {
            $objectClass = $attr->{vals};
          }
        }
        my @attrs;
        if ( defined $objectClass ) {
          foreach my $attr ( @{ $attrs } ) {
            if ( "user" ~~ $objectClass) {
              if ( $attr->{type} eq 'sAMAccountName' ) {
                my $cn = $attr->{vals}[0];
                push @attrs, { type => 'uid', vals => $attr->{vals} };
                push @attrs, { type => 'homeDirectory', vals => [ "/home/$cn" ] };
                push @attrs, { type => 'loginShell', vals => ['/bin/bash'] };
                # TODO inject sshPublicKey here
              }
              if ( $attr->{type} eq 'displayName' ) {
                push @attrs, { type => 'gecos', vals => $attr->{vals} };
              }
              if ( $attr->{type} eq 'objectSid' ) {
                push @attrs, { type => 'uidNumber', vals => [ sid2rid($attr->{vals}[0]) ] };
              }
              # TODO gidNumber from objectSid, could be painful as we will need to do a search
            }
            if ( "group" ~~ $objectClass) {
              if ( $attr->{type} eq 'objectSid' ) {
                push @attrs, { type => 'gidNumber', vals => [ sid2rid($attr->{vals}[0]) ] };
              }
            }
          }
          push @{ $response->{protocolOp}->{searchResEntry}->{attributes} }, $_ foreach @attrs;
        }
        $pdu = $LDAPResponse->encode($response);
    }
    return $pdu;
}

my $listenersock = IO::Socket::INET->new(
    Listen    => 5,
    Proto     => 'tcp',
    Reuse     => 1,
    LocalAddr => $config->{listen},
) || die "can't open listen socket: $!";

our $server_sock;

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

my $sel = IO::Select->new($listenersock);
while ( my @ready = $sel->can_read ) {
    foreach my $fh (@ready) {
        if ( $fh == $listenersock ) {
            my $psock = $listenersock->accept;
            $sel->add($psock);
        }
        else {
            $server_sock->{$fh} ||= connect_to_server;
            if ( !handle( $fh, $server_sock->{$fh} ) ) {
                $sel->remove( $server_sock->{$fh} );
                $server_sock->{$fh}->close;
                delete $server_sock->{$fh};
                $sel->remove($fh);
                $fh->close;
            }
        }
    }
}

exit 1;
