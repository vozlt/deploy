# @file:    Socket.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Socket;

use strict;
our(@ISA);
use Deploy::Carp;
use Fcntl;
use IO::Select;
use IO::Handle;
use Socket qw(:all);

@ISA = qw(Deploy::Carp);

sub new{
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $addr = delete $cnf{addr};
    my $port = delete $cnf{port};
    my $backlog = delete $cnf{backlog};
    my $socket_timeout = delete $cnf{socket_timeout};
    my $max_read_buf_size = delete $cnf{max_read_buf_size};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;
    $addr = 0 unless defined $addr;
    $port = 80 unless defined $port;
    $backlog = SOMAXCONN unless defined $backlog;
    $socket_timeout = 5 unless defined $socket_timeout;
    $max_read_buf_size = 0xffff unless defined $max_read_buf_size;

    my $self =
    bless {
        debug                   => $debug,
        warn                    => $warn,
        addr                    => $addr,
        port                    => $port,
        backlog                 => $backlog,
        sock                    => undef,
        sock_listen             => undef,
        sock_accept             => undef,
        sock_client             => undef,
        socket_timeout          => $socket_timeout,
        max_read_buf_size       => $max_read_buf_size,
        process_id              => $$
    }, $class;

    return bless $self;
}

sub socketListenAvail {
    my $self = shift if ref ($_[0]);
    #my $addr = shift || inet_aton($self->{addr}) || INADDR_ANY;
    my $addr = shift || $self->{addr};
    my $port = shift || $self->{port};
    my $sock = shift || *ACCEPT_SERVER_CHECK;
    $addr = defined($addr) ? inet_aton($addr) : INADDR_ANY;

    # socket() -> bind() -> listen() -> accept() -> send() / recv()
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || return $self->__return({string => "error: socket(): $!"});
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1) || return $self->__return({string => "error: setsockopt(): $!"});
    my $paddr = sockaddr_in($port, $addr);
    my $rc = bind($sock, $paddr) || $self->__return({string => "error: listen port $port already in used!"});
    close($sock);
    return $rc;
}

sub socketAcceptFilter {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock_listen};
    my $name = shift || 'dataready';
    my $arg = shift;
    my $rc;

    if ($^O eq 'freebsd') {
        # name: httpready|dataready
        $arg = '' unless defined $arg;
        my $afa = pack('Z16 Z240', $name, $arg);
        $rc = setsockopt($sock, SOL_SOCKET, 0x1000, $afa) || return $self->__return({string => "error: setsockopt(): $!"});
    } elsif ($^O eq 'linux') {
        my $TCP_DEFER_ACCEPT = 9;
        my $timeout = $arg || $self->{socket_timeout};
        $rc = setsockopt($sock, IPPROTO_TCP, $TCP_DEFER_ACCEPT, 0xffff & $timeout) || return $self->__return({string => "error: setsockopt(): $!"});
    }

    return $rc;
}

sub socketListen {
    my $self = shift if ref ($_[0]);
    my $addr = shift || $self->{addr};
    my $port = shift || $self->{port};
    my $sock = shift || $self->{sock_listen} || *ACCEPT_SERVER;
    $addr = defined($addr) ? inet_aton($addr) : INADDR_ANY;

    # socket() -> bind() -> listen() -> accept() -> send() / recv()
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || return $self->__return({string => "error: socket(): $!"});
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1) || return $self->__return({string => "error: setsockopt(): $!"});
    my $paddr = sockaddr_in($port, $addr);
    my $rc = bind($sock, $paddr);
    if (!$rc) {
        close($sock);
        return $self->__return({string => "error: port $port already in used!"});
    }
    $rc = listen($sock, $self->{backlog}) || return $self->__return({string => "error: $!"});

    $sock->autoflush();
    return ($self->{sock_listen} = $sock);
}

sub socketAccept {
    my $self = shift if ref ($_[0]);
    my $client = shift;
    my $server = shift || $self->{sock_listen};
    my $accept = undef;
    if ($accept = accept($client, $server)) {
        $client->autoflush();
        $self->{sock_accept} = $accept;
        $self->{sock_client} = $client;
    }
    return $accept;
}

sub socketNonBlock {
    # 0 = Nonblocking
    # 1 = blocking
    my $self = shift if ref ($_[0]);
    my $block = shift || 0;
    my $sock = shift || $self->{sock};
    my $flag = undef;

    $flag = fcntl($sock, F_GETFL, 0) || return $self->__return({string => "error: Can't get flags for the socket: $!"});

    if (!$block) {
        $flag = fcntl($sock, F_SETFL, $flag | O_NONBLOCK) || return $self->__return({string => "error: Can't set flags for the socket: $!"}); 
    } else {
        $flag = fcntl($sock, F_SETFL, $flag & ~O_NONBLOCK) || return $self->__return({string => "error: Can't set flags for the socket: $!"});
    }

    return $self;
}

sub socketSend {
    my $self = shift if ref ($_[0]);
    my $sendbuf = shift;
    my $sock = shift || $self->{sock};
    my $c = undef;
    my $len = undef;
    my $rc = undef;

    $rc = send($sock, $sendbuf, 0);

    $self->__debug_print($sendbuf, ">>> ");
    
    return $rc;
}

sub __recv_byte {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock};
    my $buf_size = shift;
    my $max_read_buf_size = $self->{max_read_buf_size} || 0xffff;
    my $rc = undef;
    my $recv = undef;
    my $recvbuf = undef;

    my $read_buf_size = ($buf_size < $max_read_buf_size) ? $buf_size : $max_read_buf_size;
    my $rest_buf_size = 0;
    my $plus_rc = 0;
    while($rc = sysread($sock, $recv, $read_buf_size)) {
        $recvbuf .= $recv;
        $plus_rc += $rc;
        $rest_buf_size = $buf_size - $plus_rc;
        $read_buf_size = $rest_buf_size > $max_read_buf_size ? $max_read_buf_size : $rest_buf_size;
        $rest_buf_size || last;
    }

    return $recvbuf;
}

sub __recv_line {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock};
    my $rc = undef;
    my $recv = undef;
    my $recvbuf = undef;

    while(1) {
        $rc = sysread($sock, $recv, 1);
        if (!$rc) {
            $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ' connection colsed or sysread(): ' . $!});
            last;
        }
        $recvbuf .= $recv;
        last if ($recv eq "\n");
    }
    return $recvbuf;
}

sub socketRecv {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock};
    my $buf_size = shift;

    my $select = IO::Select->new();
    $select->add(\*{$sock});
    my @ready = $select->can_read($self->{socket_timeout});

    # sysread Return Value
    # undef on error
    # 0 at end of file
    # Integer, number of bytes read
    ($ready[0] == \*{$sock}) || return $self->__return({string => "error: timeout($self->{timeout}): $!"});

    my $recvbuf = ($buf_size) ? $self->__recv_byte($sock, $buf_size) : $self->__recv_line($sock);

    $select->remove(\*{$sock});

    $self->__debug_print($recvbuf, "<<< ");
    return $recvbuf;
} 

sub socketConnect {
    my $self = shift if ref ($_[0]);
    my $addr = shift || $self->{addr};
    my $port = shift || $self->{port};
    my $sock = shift || *SOCK;
    my $inet_addr = inet_aton($addr);
    my $paddr = sockaddr_in($port, $inet_addr);
    my $rc = undef;

    socket($sock, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || return $self->__return({string => "error: socket(): $!"});

    $rc = "error: connect(): $addr:$port $!" if !connect($sock, $paddr);

    defined $rc && return $self->__return({string => $rc});
    $@ && return $self->__return({string => "error: connect(): $@"});
    $sock->autoflush();
    return ($self->{sock} = $sock);
}

sub socketClose {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock};
    if ($sock) {
        shutdown($sock, 0);
        shutdown($sock, 1);
        shutdown($sock, 2);
    }
    return $self;
}

sub DESTROY {
    my $self = shift if ref ($_[0]);

    # Thread Safe
    ($$ != $self->{process_id}) && return;

    for my $class (@ISA) {
        my $destroy = $class . "::DESTROY";
        $self->$destroy if $self->can($destroy);
    }

    $self->socketClose();
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
