package SID;

use strict;
use warnings;
use Exporter 'import';
our $VERSION = '1.00';
our @EXPORT  = qw(sid2config string2sid sid2string sid2rid rid2sid);

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
    my ($revision_level, $authority, $sub_authority_count, @sub_authorities) =
      unpack 'C Vxx C V*', $sid;
    my $string = join '-', 'S', $revision_level, $authority, @sub_authorities;
    return $string;
}

sub sid2rid {
    my ($sid) = @_;
    my ( $revision_level, $authority, $sub_authority_count, @sub_authorities ) =
      unpack 'C Vxx C V*', $sid;
    return $sub_authorities[-1];
}

sub rid2sid {
    my $rid = shift;
    my $base = shift;
    my $sub_authorities = $base->{sub_authorities};
    my @sub_authorities = @$sub_authorities;
    push @sub_authorities, $rid;
    my $sub_authority_count = scalar @sub_authorities;
    my $revision_level = $base->{revision_level};
    my $authority = $base->{authority};
    my $sid = pack 'C Vxx C V*', $revision_level, $authority,
        $sub_authority_count, @sub_authorities;
    return $sid;
}
