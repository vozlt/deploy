# @file:    Client.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Client;

use strict;
use warnings "all";

our(@ISA);
use Deploy::Boolean qw(:Boolean);
use Deploy::Onetime;
use Deploy::Socket;
use Deploy::Timeout;
use Deploy::File;
use Deploy::Unique;
use Deploy::Queue;
use Deploy::Carp;

use MIME::Base64;
use threads;
use Data::Dumper;

@ISA = qw(Deploy::Timeout Deploy::Carp Deploy::Unique);

sub new {
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $addr = delete $cnf{addr};
    my $port = delete $cnf{port};
    my $ipc_path = delete $cnf{ipc_path};
    my $worker_method = delete $cnf{worker_method};
    my $thread_timeout = delete $cnf{thread_timeout};
    my $socket_timeout = delete $cnf{socket_timeout};
    my $socket_accept_filter = delete $cnf{socket_accept_filter};
    my $key_cipher = delete $cnf{key_cipher};
    my $ssl = delete $cnf{ssl};
    my $ssl_public_key = delete $cnf{ssl_public_key};
    my $aes_key = delete $cnf{aes_key};
    my $orders = delete $cnf{orders};

    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;
    $ipc_path = '/tmp/.deploy_ipc' unless defined $ipc_path;
    $worker_method = 'fork' unless defined $worker_method;
    $thread_timeout = 5 unless defined $thread_timeout;
    $socket_timeout = 5 unless defined $socket_timeout;

    my $self =
    bless {
        debug                   => $debug,
        warn                    => $warn,

        addr                    => $addr,
        port                    => $port,

        ipc_path                => $ipc_path,
        worker_method           => $worker_method,
        thread_timeout          => $thread_timeout,
        socket_timeout          => $socket_timeout,
        socket_accept_filter    => $socket_accept_filter,
        threads                 => {},

        queue                   => undef,
        
        key_cipher              => $key_cipher,
        ssl                     => $ssl,
        ssl_public_key          => $ssl_public_key,
        aes_key                 => $aes_key,

        request                 => {},
        cnf                     => {},

        get_request             => undef,
        get_response            => undef,
        
        orders                  => $orders,
        allow_orders            => ['status', 'rlist', 'rsync', 'rkill', 'exec'],
        returns                 => {},

        process_id              => $$
    }, $class;

    $self->__load_module();

    return bless $self;
}

sub getAuthKey {
    my $self = shift if ref ($_[0]);
    my $key_cipher = shift || $self->{key_cipher};

    my $onetime = Deploy::Onetime->new(cipher=> $key_cipher);
    my $crypt_key = $onetime->generateKey();
    return $crypt_key;
}

sub getRequest {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $target = $cnf->{target} || $self->{orders}{target};
    my $order = $cnf->{order} || $self->{orders}{order};
    my $options = $cnf->{options} || $self->{orders}{options};
    my $args = $cnf->{args} || $self->{orders}{args};
    my $api_key = $cnf->{api_key} || $self->{orders}{api_key};
    my $auth_key = $self->getAuthKey();

    $target =~ s/^api$/agent/g;

    $target = '' unless defined $target;
    $order = '' unless defined $order;
    $auth_key = '' unless defined $auth_key;
    $options = '' unless defined $options;
    $args = '' unless defined $args;
    $api_key = '' unless defined $api_key;

    $target =~ s/^api$/agent/g;
    
    my $content = join("&", "auth_key=$auth_key", "options=$options", "args=$args", "api_key=$api_key");
    my $content_length = length $content;
    my $header = join("\r\n", "POST /$target/$order HTTP/1.1", "Connection: close", "Content-Length: $content_length", "\r\n");

    return $header . $content;
}

sub getRequestPlain {
    my $self = shift if ref ($_[0]);
    return $self->getRequest();
}

sub getRequestCrypt {
    my $self = shift if ref ($_[0]);
    my $ssl_public_key = shift || $self->{ssl_public_key};
    my $aes_key = Crypt::CBC->random_bytes(16);
    my $crypt = Deploy::Crypt->new(
        public_key => $ssl_public_key,
        aes_key => $aes_key
    );
    $self->{aes_key} = $aes_key;
    my $request_aes_key = $crypt->encrypt({key_type => 'public', string => $crypt->{aes_key}});
    my $request_string = $crypt->encrypt({key_type => 'aes', string => $self->getRequest()});
    $request_aes_key = 'aes:' . MIME::Base64::encode($request_aes_key, "");
    $request_string = $request_aes_key . "\r\n" . "ssl-length:" . length($request_string) . "\r\n\r\n" . $request_string;

    return $request_string;
}

sub getResponsePlain {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $request_string = $cnf->{request_string} || {};
    my $addr = $cnf->{addr}; 
    my $port = $cnf->{port} || $self->{port};
    my $socket_timeout = $cnf->{socket_timeout} || $self->{socket_timeout};
    my $response = {};

    defined $addr || return $self->__return({string => "error: addr not defined!: line " . __LINE__});
    defined $port || return $self->__return({string => "error: port not defined!: line " . __LINE__});

    my $request_handler = $self->{get_request};
    $request_string = $self->can($request_handler) ? $self->$request_handler() : undef;

    my $client = Deploy::Socket->new(
        addr => $addr,
        port => $port,
        socket_timeout => $socket_timeout,
        debug => $self->{debug},
        warn => $self->{warn}
    );

    my $sock = $client->socketConnect() || return $self->__return(
        {
            string => "error: connect(): line " . __LINE__,
            return => {
                host => $addr,
                server_status => FALSE,
                CONTENT => "can't connect to $addr:$port"
            }
        }
    );
    $client->socketSend($request_string, $sock);

    # Read Request
    local $/ = Socket::CRLF;
    while ($_ = $client->socketRecv($sock)) {
        chomp; # Main http response
        if (/\s*HTTP\/(\d.\d)\s*(\d+)\s*(.*)/) {
            $response->{HTTP_VERSION} = $1;
            $response->{HTTP_CODE} = $2;
            $response->{HTTP_STRING} = $3;
        } # Standard headers
        elsif (/:/) {
            my ($type, $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $response->{lc $type} = $val;
        } # POST data
        elsif (/^$/) {
            $response->{CONTENT} = $client->socketRecv($sock, $response->{'content-length'})
            if defined $response->{'content-length'};
            last;
        }
    }

    $response->{host} = $addr;
    $response->{port} = $port;
    $response->{server_status} = TRUE;
    return $response;
}

sub getResponseCrypt {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $request_string = $cnf->{request_string} || {};
    my $addr = $cnf->{addr}; 
    my $port = $cnf->{port} || $self->{port};
    my $socket_timeout = $cnf->{socket_timeout} || $self->{socket_timeout};
    my $response = {};

    defined $addr || return $self->__return({string => "error: addr not defined!: line " . __LINE__});
    defined $port || return $self->__return({string => "error: port not defined!: line " . __LINE__});

    my $request_handler = $self->{get_request};
    $request_string = $self->can($request_handler) ? $self->$request_handler() : undef;

    my $client = Deploy::Socket->new(
        addr => $addr,
        port => $port,
        socket_timeout => $socket_timeout,
        debug => $self->{debug},
        warn => $self->{warn}
    );
    my $sock = $client->socketConnect() || return $self->__return(
        {
            string => "error: connect(): line " . __LINE__,
            return => {
                host => $addr,
                server_status => FALSE,
                CONTENT => "can't connect to $addr:$port"
            }
        }
    );
    $client->socketSend($request_string, $sock);

    local $/ = Socket::CRLF;
    while ($_ = $client->socketRecv($sock)) {
        chomp;
        if (/:/) {
            my ($type, $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $response->{lc $type} = $val;
        } elsif (/^$/) {
            $response->{'CONTENT-SSL'} = $client->socketRecv($sock, $response->{'ssl-length'})
            if defined $response->{'ssl-length'};
            last;
        } elsif (/^WHO$/i) {
            # Send banner
            $client->socketSend("DEPLOY-SSL\r\n", $sock);
        }
    }

    if (!defined $response->{'ssl-length'}) {
        print "Protocol mismatch.\n";
    }

    my $crypt = Deploy::Crypt->new(aes_key => $self->{aes_key}, warn => 1);
    my $decrypt_content = $crypt->decrypt(
        {
            key_type => 'aes',
            string => $response->{'CONTENT-SSL'},
        }
    );

    my ($header, $content) = split(Socket::CRLF x 2, $decrypt_content, 2);
    my @lines = split(Socket::CRLF, $header);

    for (@lines) {
        chomp; # Main http response
        if (/\s*HTTP\/(\d.\d)\s*(\d+)\s*(.*)/) {
            $response->{HTTP_VERSION} = $1;
            $response->{HTTP_CODE} = $2;
            $response->{HTTP_STRING} = $3;
        } # Standard headers
        elsif (/:/) {
            my ($type, $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $response->{lc $type} = $val;
        } # POST data
        elsif (/^$/) {
            $response->{CONTENT} = $client->socketRecv($sock, $response->{'content-length'})
            if defined $response->{'content-length'};
            last;
        }
    }

    $response->{host} = $addr;
    $response->{port} = $port;
    $response->{server_status} = TRUE;
    $response->{CONTENT} = $content;

    return $response;
}

sub __exec_thread {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $thread_timeout = $cnf->{thread_timeout} || $self->{thread_timeout};
    my @hosts = defined $cnf->{hosts} ? @{$cnf->{hosts}} : @{$self->{orders}{hosts}};

    my $response_handler = $self->{get_response};
    $self->can($response_handler) || return $self->__return(
        {
            string => "error: $response_handler(): not found line " . __LINE__
        }
    );

    my @threads = ();
    my @results = ();
    for my $host (@hosts) {
        my $thr = threads->create( 
            {'stack_size' => 1024*1024*8, 'exit' => 'thread_only', 'scalar' => 1},
            sub {
                local $SIG{'KILL'} = sub {die};
                threads->yield(); # for socket thread safe;
                $self->$response_handler({addr => $host});
            }
        );
        push(@threads, $thr);
    }

    for (0..$thread_timeout) {
        push(@results, $_->join()) for (threads->list(threads::joinable));
        last if ($#threads == $#results);
        sleep 1;
    }
    $_->kill('KILL')->detach() for (threads->list(threads::running));

    my @get_hosts = map {$_->{host}} @results;
    
    my @out_hosts = do {
        my %seen = ();
        $seen{$_}++ for (@hosts, @get_hosts);
        grep {/\S/} map { ($seen{$_} == 1) && $_ } keys %seen;
    };

    my $i = $#results;
    for (@out_hosts) {
        $results[++$i]->{host} = $_;
        $results[$i]->{server_status} = 0;
        $results[$i]->{CONTENT} = "Process Timeout($thread_timeout)!";
    }

    return \@results;
}

sub __exec_fork {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $thread_timeout = $cnf->{thread_timeout} || $self->{thread_timeout};
    my @hosts = defined $cnf->{hosts} ? @{$cnf->{hosts}} : @{$self->{orders}{hosts}};

    my $response_handler = $self->{get_response};
    $self->can($response_handler) || return $self->__return(
        {
            string => "error: $response_handler(): not found line " . __LINE__
        }
    );

    my @threads = ();
    my @results = ();
    my $queue = Deploy::Queue->new(ipc_path => $self->{ipc_path}, warn => 1);
    my $ppid = $self->{process_id};
    $self->{queue} = $queue;
    for my $host (@hosts) {
        my $pid = fork();
        if ($pid > 0) {
            # parent process
            push(@threads, $pid);
            push(@{$self->{threads}{pids}}, $pid);
            next;
        } elsif ($pid == 0) {
            # child process
            $SIG{INT} = sub { $self->__exit({string => "info: child($$) SIGINT: line " . __LINE__, return => TRUE}); };
            $SIG{CHLD} = 'IGNORE'; # Avoiding zombie process

            $self->timeoutMain(
                sub {
                    my $res = $self->$response_handler({addr => $host});
                    my $key = $ppid . $$;
                    $queue->push(
                        {   
                            key => $key,
                            store => $res
                        }
                    );
                }, $thread_timeout
            ) || $self->__exit({string => "error: timeout($thread_timeout): line " . __LINE__, return => FALSE});

            $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ": ChildProcess End: pid[$$], ppid[$ppid]"});
            exit;
        } else {
            # fork fail
            next;
        }
    }
    # for memory destroy after timeoutMain: thread_timeout + 1
    my @rest = @threads;
    my @done;

    for (0..$thread_timeout) {
        for my $pid (@rest) {
            my $key = $ppid . $pid;
            if ($queue->exists({key => $key})) {
                $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ": key[$key] rest[@rest]"});
                if (my $value = $queue->pop({key => $key})) {
                    push(@results, $value);
                    push(@done, $pid);
                }
            }
        }

        @rest = Deploy::Unique::alone(\@rest, \@done);
        @done = ();

        $self->__debug(
            {
                string => (caller(0))[3] . '() line ' . __LINE__ . "threads_count[$#threads], results_count[$#results], rest[@rest], done[@done]"
            }
        );
        last if ($#threads <= $#results);
        sleep 1;
    }

    my @done_hosts = map {$_->{host}} @results;
    for my $host (@hosts) {
        my $find = FALSE;
        for my $done_host (@done_hosts) {
            if ($done_host eq $host) {
                $find = TRUE;
                last;
            }
        }
        if (!$find) {
            my $i = $#results;
            $results[++$i]->{host} = $host;
            $results[$i]->{server_status} = 0;
            $results[$i]->{CONTENT} = "Process Timeout($thread_timeout)!";
        }
    }

    return \@results;
}

sub exec {
    my $self = shift if ref ($_[0]);
    my $worker_handler = '__exec_' . $self->{worker_method};
    return $self->can($worker_handler) ? $self->$worker_handler(@_) : FALSE;
}

sub __thread_exit {
    my $self = shift if ref ($_[0]);
    threads->exit();
}

sub __load_module {
    my $self = shift if ref ($_[0]);
    my $suffix;
    if ($self->{ssl}) {
        eval('use Deploy::Crypt');
        if ( my $err = $@ ) {
            die "You need to install perl-Crypt-OpenSSL-RSA perl-Crypt-CBC perl-Crypt-OpenSSL-AES package.\n$@";
        }
        $suffix = 'Crypt';
    } else {
        $suffix = 'Plain';
    }
    $self->{get_request} = 'getRequest' . $suffix;
    $self->{get_response} = 'getResponse' . $suffix;
    return $self;
}

sub DESTROY {
    my $self = shift if ref ($_[0]);

    # Thread Safe
    ($$ != $self->{process_id}) && return;

    if ($self->{worker_method} eq 'fork') {
        if (defined $self->{threads}{pids}) {
            my @threads = @{$self->{threads}{pids}};
            # Destroy Childs
            kill('INT', @threads);

            # Destroy Memorys
            my $ppid = $self->{process_id};
            for my $pid (@threads) {
                my $key = $ppid . $pid;
                $self->{queue}->delete({key => $key});
            }
        }
    }

    # Destroy Modules
    for my $class (@ISA) {
        my $destroy = $class . "::DESTROY";
        $self->$destroy if $self->can($destroy);
    }
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
