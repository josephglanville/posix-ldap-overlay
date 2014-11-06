package SSHKey;

use strict;
use warnings;
use Exporter 'import';
our $VERSION = '1.00';
our @EXPORT  = qw(keyExists keyContents);

use File::Spec::Functions;

sub keyExists {
    my $name = shift;
    my $dir = shift;
    my $fname = catfile($dir, $name);
    if (-e $fname) {
        return 1
    }
    return 0
}

sub keyContents {
    my $name = shift;
    my $dir = shift;
    my $file = catfile($dir, $name);
    my $contents = do {
        local $/ = undef;
        open my $fh, "<", $file
            or die "could not open $file: $!";
        <$fh>;
    };
    return $contents;
}
