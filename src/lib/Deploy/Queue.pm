# @file:    Queue.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Queue;

use strict;
our (@ISA);
use Deploy::Boolean qw(:Boolean);
use Deploy::Carp;

use Storable;
use Data::Dumper;

@ISA = qw(Deploy::Carp);

sub new{
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $key = delete $cnf{key};
    my $ipc_path = delete $cnf{ipc_path};
    my $mode = delete $cnf{mode};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;
    $ipc_path = '/tmp/.deploy_ipc' unless defined $ipc_path;
    $mode = 0600 unless defined $mode;

    my $self =
    bless {
        debug           => $debug,
        warn            => $warn,
        worker_method   => ($ipc_path =~ /^(memory)$/i) ? 'memory' : 'file',
        key             => $key,
        ipc_path        => $ipc_path,
        mode            => $mode,
        process_id      => $$
    }, $class;

    my $init_handler = '__' . $self->{worker_method} . '_init';
    $self->$init_handler();

    return bless $self;
}

sub push {
    my $self = shift if ref ($_[0]);
    my $worker_handler = '__' . $self->{worker_method} . '_push' ;
    return $self->can($worker_handler) ? $self->$worker_handler(@_) : FALSE;
}

sub pop {
    my $self = shift if ref ($_[0]);
    my $worker_handler = '__' . $self->{worker_method} . '_pop' ;
    return $self->can($worker_handler) ? $self->$worker_handler(@_) : FALSE;
}

sub delete {
    my $self = shift if ref ($_[0]);
    my $worker_handler = '__' . $self->{worker_method} . '_delete' ;
    return $self->can($worker_handler) ? $self->$worker_handler(@_) : FALSE;
}

sub exists {
    my $self = shift if ref ($_[0]);
    my $worker_handler = '__' . $self->{worker_method} . '_exists' ;
    return $self->can($worker_handler) ? $self->$worker_handler(@_) : FALSE;
}

sub __memory_init {
    my $self = shift if ref ($_[0]);
    $self->__load_module();
}

sub __memory_push {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};
    my $mode = $cnf->{mode} || $self->{mode};
    my $store = $cnf->{store} || $self->{store};

    defined $key || return $self->__return({string => "error: store key is not defined: $!"});

    my $sharelite = IPC::ShareLite->new(
        -key     => $key,
        -create  => 'yes',
        -mode    => $mode,
        -destroy => 'no'
    ) || return $self->__return({string => "error: $!"});

    eval {
        $sharelite->lock(&IPC::ShareLite::LOCK_EX);
        $sharelite->store(Storable::freeze($store));
        $sharelite->unlock();
    };
    $@ && return $self->__return({string => "error: store failed: $!"});
    return TRUE;
}

sub __memory_pop {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};

    my $sharelite = IPC::ShareLite->new(
        -key     => $key,
        -create  => 'no',
        -destroy => 'no'
    ) || return $self->__return({string => "error: $!"});

    my $store;
    eval {
        $sharelite->lock(&IPC::ShareLite::LOCK_SH);
        $store = Storable::thaw($sharelite->fetch());
        $sharelite->unlock();
    };
    $@ && return $self->__return({string => "error: fetch failed: $!"});
    return $store || FALSE;
}

sub __memory_delete {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};

    my $sharelite = IPC::ShareLite->new(
        -key     => $key,
        -create  => 'no',
        -destroy => 'no'
    ) || return $self->__return({string => "error: $!"});

    return $sharelite->destroy(TRUE);
}

sub __memory_exists {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};

    my $sharelite = IPC::ShareLite->new(
        -key     => $key,
        -create  => 'no',
        -destroy => 'no'
    ) || return FALSE;

    return TRUE;
}

sub __file_init {
    my $self = shift if ref ($_[0]);
    defined $self->{ipc_path} || return $self->__return({string => "error: ipc_path is not defined: $!"});
    (-e $self->{ipc_path}) || mkdir($self->{ipc_path}, 0700) || return $self->__return({string => "error: mkdir(): $!"});
    (-d $self->{ipc_path}) || return $self->__return({string => "error: $self-{ipc_path} is not a directory: $!"});
}

sub __file_push {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};
    my $mode = $cnf->{mode} || $self->{mode};
    my $store = $cnf->{store} || $self->{store};
    my $queue = $self->{ipc_path} . '/' . $key;

    defined $key || return $self->__return({string => "error: store key is not defined: $!"});

    eval {
        Storable::lock_store($store, $queue);
    };
    $@ && return $self->__return({string => "error: store failed($queue): $!"});

    chmod(0600, $queue);
    return TRUE;
}

sub __file_pop {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};
    my $queue = $self->{ipc_path} . '/' . $key;
    (-f $queue) || return;
    my $store;
    eval {
        $store = Storable::lock_retrieve($queue);
    };
    $@ && return $self->__return({string => "error: retrieve failed($queue): $@"});;
    return $store || FALSE;
}

sub __file_delete {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};
    my $queue = $self->{ipc_path} . '/' . $key;
    return (-f $queue) ? unlink($queue) : TRUE;
}

sub __file_exists {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $key = $cnf->{key} || $self->{key};
    my $queue = $self->{ipc_path} . '/' . $key;
    return (-f $queue) ? TRUE : FALSE;
}

# IPC::ShareLite store() error: Identifier removed at 가 발생하면 
# semaphore 에서 삭제되지 않은 키가 존재하므로
# ipcs -a 로 확인후 ipcrm 으로 삭제
sub __load_module {
    my $self = shift if ref ($_[0]);
    my $suffix;
    if ($self->{worker_method} eq 'memory') {
        eval{
            use IPC::ShareLite;
        };
        if ( my $err = $@ ) {
            die "You need to install perl-IPC-ShareLite package.\n$@";
        }
    }
    return $self;
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
