# @file:    Unique.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Unique;

use strict;
our (@ISA);
use Deploy::Carp;

@ISA = qw(Deploy::Carp);

sub new{
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;

    my $self =
    bless {
        debug       => $debug,
        warn        => $warn,
        process_id  => $$
    }, $class;

    return bless $self;
}

# get only one in @a, @b
sub alone {
    my $self = shift if ref ($_[0]);
    my ($left, $right);

    if (ref($self) eq 'ARRAY') {
        $left = $self;
        $right = shift;
    } else {
        $left = shift;
        $right = shift;
    }

    my @alone = do {
        my %seen = ();
        $seen{$_}++ for (@$left, @$right);
        grep {/\S/} map { ($seen{$_} == 1) && $_ } keys %seen;
    };
    return @alone;
}

# get only unique in @array
sub unique {
    my $self = shift if ref ($_[0]);
    my $list = (ref($self) eq 'ARRAY') ? $self : shift;

    my %seen = ();
    my @uniqu = grep { ! $seen{$_} ++ } @$list;
    return @uniqu;
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
