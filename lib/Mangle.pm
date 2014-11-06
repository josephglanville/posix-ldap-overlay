package Mangle;

use strict;
use warnings;
use Exporter 'import';
our $VERSION = '1.00';
our @EXPORT  = qw(mangleFilter);

use Net::LDAP::Filter;
use Data::Dump qw(dump);
use SID qw(rid2sid);

sub mangleFilter {
    my $f = shift;
    my $sid = shift;
    if ( defined $f->{equalityMatch} ) {
        my $a = $f->{equalityMatch}->{attributeDesc};
        my $v = $f->{equalityMatch}->{assertionValue};
        if ( $a eq 'objectclass' && $v eq 'posixAccount' ) {
            return {
                equalityMatch => {
                    assertionValue => 'user',
                    attributeDesc => $a
                }
            };
        }
        # Rewrite uid queries to sAMAccountName
        elsif ( $a eq 'uid' ) {
            return{
                equalityMatch => {
                    attributeDesc => 'sAMAccountName',
                    assertionValue => $v
                }
              };
        }
        # Rewrite gidNumber queries to objectSid
        elsif ( $a eq 'gidNumber') {
            return {
                equalityMatch => {
                    attributeDesc => 'objectSid',
                    assertionValue => rid2sid($v, $sid)
                }
            }
        }
        # Rewrite uidNumber queries to objectSid
        elsif ( $a eq 'uidNumber') {
            return {
                equalityMatch => {
                    attributeDesc => 'objectSid',
                    assertionValue => rid2sid($v, $sid)
                }
            }
        }
        # Rewrite uniqueMember queries to member
        elsif ( $a eq 'uniqueMember') {
            return {
                equalityMatch => {
                    attributeDesc => 'member',
                    assertionValue => $v
                }
            }
        }
        elsif ( $a eq 'objectclass' && $v eq 'ldapPublicKey' ) {
            return undef;
        }
        else {
            return $f;
        }
    } else {
        # Just return unmodified
        return $f;
    }
}
