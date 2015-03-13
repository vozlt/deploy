# @file:    Carp.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Carp;

use strict;
use Carp;

sub new{
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;

    my $self =
    bless {
        debug   => $debug,
        warn    => $warn
    }, $class;

    return bless $self;
}

sub __debug {
    my $self = shift if ref ($_[0]);
    my $res = shift;
    Carp::carp "# [DEBUG]: $res->{string}" if ($self->{debug});
    return $res->{return} || 1;
}

sub __return {
    my $self = shift if ref ($_[0]);
    my $res = shift;
    Carp::carp __PACKAGE__ . ": $res->{string}" if ($self->{debug} | $self->{warn});
    return $res->{return} || 0;
}

sub __exit {
    my $self = shift if ref ($_[0]);
    my $res = shift;
    Carp::carp __PACKAGE__ . ": $res->{string}" if ($self->{debug} | $self->{warn});
    exit($res->{return} || 0);
}

sub __debug_print {
    my $self = shift if ref ($_[0]);
    my $buf = shift;
    my $prefix = shift || '### ';
    if ($self->{debug}) {
        if (length($buf)) {
            print $prefix;
            if ($self->{debug} == 1) {
                my $len = length($buf) - 1;
                for(0 .. $len) {
                    my $c = substr($buf, $_, 1);
                    if (ord("$c") < 128) {
                        print $c;
                    } else {
                        print ".";
                    }
                }
            } else {
                print "$buf";
            }
        }
    }
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
