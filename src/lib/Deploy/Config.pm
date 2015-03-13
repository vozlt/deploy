# @file:     Config.pm
# @brief:
# @author:   YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Config;

use strict;
use Deploy::File;
our(@ISA);

@ISA = qw(Deploy::File);

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

sub parseIniFile {
    my $self = shift if ref ($_[0]);
    my $path = shift;
    my @arg = ();
    my %cnf = ();
    my $key = undef;

    for(my @lines = $self->fileReadLines($path)) {
        chomp;
        s/^\s+//;
        s/\s+$//;
        s/^[#;].*//;
        next unless length;

        # Only two args
        @arg = split(/\s*[=]\s*/, $_, 2);
        if ($#arg == 0) { 
            $key = $arg[0];
            $key =~ s/(^\[|\]$)//g;
        }   
        if ($#arg == 1) {
            if ($arg[0] =~ /\[\]$/) {
                my $two = $arg[0];
                $two =~ s/\[\]$//;
                push(@{$cnf{$key}{$two}}, $arg[1]);
            } else {
                $key = 'list' unless defined($key);
                if ($key) {
                    $cnf{$key}{$arg[0]} = $arg[1];
                } else {
                    $cnf{$arg[0]} = $arg[1];
                }
            }
        }
    }
    return %cnf;
}

sub DESTROY {
    my $self = shift if ref ($_[0]);

    # thread safe
    ($$ != $self->{process_id}) && return;

    for my $class (@ISA) {
        my $destroy = $class . "::DESTROY";
        $self->$destroy if $self->can($destroy);
    }
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
