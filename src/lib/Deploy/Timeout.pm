# @file:    Timeout.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Timeout;

use strict;
use POSIX;

sub new{
    my $class = shift;
    my $self = bless {}, $class;
    return bless $self;
}

sub timeoutAction {
    my $self = shift if ref ($_[0]);
    die "timeout";
}

sub timeoutInit {
    my $self = shift if ref ($_[0]);
    my $sigset = POSIX::SigSet->new(SIGALRM);
    my $sigact = POSIX::SigAction->new(sub { $self->timeoutAction() }, $sigset, 0);
    return $sigact;
}

sub timeoutFind {
    my $self = shift if ref ($_[0]);
    my $buf = shift;
    return ($buf =~ /timeout/) ? 1 : 0;
}

sub timeoutMain {
    my $self = shift if ref ($_[0]);
    my $fp = shift;
    my $timeout = shift || 0;
    my $res;

    eval {
        sigaction(SIGALRM, $self->timeoutInit());
        alarm($timeout);
        $res = $fp->();
        alarm(0);
    };
    $self->timeoutFind($@) && return;
    return $res || 1;
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
