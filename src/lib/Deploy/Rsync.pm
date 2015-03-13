# @file:    Rsync.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

# Package Start
package Deploy::Rsync;

use Carp;
use strict;
our(@ISA);
use Deploy::File;
use Deploy::Carp;

@ISA = qw(Deploy::File Deploy::Carp);

sub new {
    my($class, $cnf) = @_;
    $cnf = ref $cnf ? $cnf : {};
    $cnf->{path} = '/usr/bin/rsync' unless defined $cnf->{path};
    $cnf->{queue_path} = '/tmp' unless defined $cnf->{queue_path};

    my $debug = defined $cnf->{debug} ? $cnf->{debug} : 0;
    my $warn = defined $cnf->{warn} ? $cnf->{warn} : 0;
    my $self =
    bless {
        debug       => $debug,
        warn        => $warn,
        opts        => $cnf,
        returns     => {},
        process_id  => $$
    }, $class;

    return bless $self;
}   

# into memory: It'll probably be OK.
# 150000 list's size is about 10M(I'm not sure.)
sub __exec {
    my $self = shift if ref ($_[0]);
    # to prevent return code error(No child process) in fork()
    local ($SIG{CHLD}) = 'DEFAULT';
    my $output = qx(@_);
    my $status = $? >> 8; # = $? / 256

    if ($self->{opts}{background}) {
        sleep 1; # wait for qx's output file
        $output = $self->fileReadByte($self->{opts}{queue}, 512);
    }

    $self->{returns}{return} = $?;
    $self->{returns}{status} = $status ? 0 : 1;
    $self->{returns}{content} = $output;
    return $self;
}

sub exec {
    my $self = shift if ref ($_[0]);
    my $opts = shift;
    my $dest = $opts->{dest} || $self->{opts}{dest};
    my $src = $opts->{src} || $self->{opts}{src};
    my @cmd;

    if (grep{!defined($_)} ($dest, $src)) {
        return $self->__return({string => "error: empty value in options!"});
    }

    $self->{opts}{dest} = $dest;
    $self->{opts}{src} = $src;
    $self->{opts}{checksum} = $self->md5sum({string => $dest . $src});
    $self->{opts}{queue} = $self->{opts}{queue_path} . '/' . $self->{opts}{checksum};

    push @{$self->{opts}{array}{include}}, $self->{opts}{checksum} if ($self->{opts}{background});
    push @cmd, $self->getCommand();
    if ($self->{opts}{background}) {
        push @cmd, '&>', $self->{opts}{queue}, '&';
    } else {
        push @cmd, '2>&1';
    }

    $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ': ' . join ' ', @cmd});
    $self->__exec(@cmd);
    return $self;
}

sub checkSyncStatus {
    my $self = shift if ref ($_[0]);
    my $opts = shift;
    my $dest = $opts->{dest} || $self->{opts}{dest};
    my $src = $opts->{src} || $self->{opts}{src};

    $self->{opts}{checksum} = $self->md5sum({string => $dest . $src});
    my $pgrep = $self->getPgrep($self->{opts}{checksum});
    return $pgrep;
}

sub killProcess {
    my $self = shift if ref ($_[0]);
    my $opts = shift;
    my $dest = $opts->{dest} || $self->{opts}{dest};
    my $src = $opts->{src} || $self->{opts}{src};
    $self->{opts}{checksum} = $self->md5sum({string => $dest . $src});
    my $pgrep = $self->getPgrep($self->{opts}{checksum});
    $pgrep || return $self->__return({string => "warn: no such process: $self->{opts}{checksum}"});

    kill('KILL', keys %{$pgrep});
    my $queue = $self->{opts}{queue_path} . '/' . $self->{opts}{checksum};
    unlink($queue) if (-f $queue);
    return $pgrep;
}

sub getProcess {
    my $self = shift if ref ($_[0]);
    my $process = {};
    my $proc = '/proc';

    ($^O eq 'linux') || return $process;

    # only linux
    opendir my($DH), $proc || return $self->__return({string => "error: opendir(): $!"});
    my @pids = grep {/^[\d]+/} readdir $DH;
    closedir $DH;

    for my $pid (@pids) {
        my $cmdline = $self->fileRead("$proc/$pid/cmdline");
        $cmdline =~ s/[\x00]+$//g;
        $cmdline =~ s/\x00/\x20/g;
        $process->{$pid} = $cmdline if ($cmdline);
    }

    return $process;
}

sub getPgrep {
    my $self = shift if ref ($_[0]);
    my $pattern = shift || '.*';
    my $find = {};
    my $process = $self->getProcess();
    my $pc = 0;
    for my $pid (keys %{$process}) {
        if ($process->{$pid} =~ /$pattern/i) {
            $find->{$pid} = $process->{$pid};
            $pc++;
            $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ': ' . "$pid $process->{$pid}"});
        }
    }

    #return ($pc) ? $find : 0;
    return $pc && $find;
}

# options:
#       flags => @arr, scalars => {}, arrays => {}, dest, src
sub getCommand {
    my $self = shift if ref ($_[0]);
    my $opts = shift || $self->{opts};

    my $dest = $opts->{dest} if defined $opts->{dest};
    my $src = $opts->{src} if defined $opts->{src};
    my $strings = $opts->{strings} if defined $opts->{strings};

    if (grep{!defined($_)} ($dest, $src)) {
        return $self->__return({string => "error: empty value in options!"});
    }

    my @flags = keys %{$opts->{flag}};
    my @scalars = keys %{$opts->{scalar}};
    my @arrays = keys %{$opts->{array}};

    # flags
    my @ropts = grep {/\S/} ( (map{ "--$_" } @flags) );

    # scalars
    push @ropts, grep {/\S/} map{ '--' . $_ . '="' . $opts->{scalar}{$_} . '"' } @scalars;

    # arrays
    for my $key (@arrays) {
        push @ropts, grep {/\S/} map{ "--${key}=$_" } @{$opts->{array}{$key}};
    }

    return grep {/\S/} ($opts->{path}, @ropts, $strings && @{$strings}, $dest, $src);
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
