# @file:    Server.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Server;

use strict;
our(@ISA, $VERSION);
use Deploy::Boolean qw(:Boolean);
use Deploy::Socket;
use Deploy::Syslog;
use Deploy::Timeout;
use Deploy::File;
use Deploy::Carp;
use IO::Handle;
use POSIX;
use Socket;

use MIME::Base64;
use Data::Dumper;

@ISA = qw(Deploy::Socket Deploy::Timeout Deploy::File Deploy::Syslog Deploy::Carp);
$VERSION = "1.0";

sub new {
    my($class, %cnf) = @_;

    my $worker_init = delete $cnf{worker_init};
    my $worker_handler = delete $cnf{worker_handler};

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $process_name = delete $cnf{process_name};
    my $user = delete $cnf{user};
    my $group = delete $cnf{group};
    my $addr = delete $cnf{addr};
    my $port = delete $cnf{port};
    my $backlog = delete $cnf{backlog};
    my $max_prefork = delete $cnf{max_prefork};
    my $max_requests_per_child = delete $cnf{max_requests_per_child};
    my $max_process_timeout = delete $cnf{max_process_timeout};
    my $socket_timeout = delete $cnf{socket_timeout};
    my $socket_accept_filter = delete $cnf{socket_accept_filter};
    my $log_write = delete $cnf{log_write};
    my $log_error_level = delete $cnf{log_error_level};
    my $log_error_path = delete $cnf{log_error_path};
    my $log_access_path = delete $cnf{log_access_path};
    my $ssl = delete $cnf{ssl};
    my $ssl_public_key = delete $cnf{ssl_public_key};
    my $ssl_private_key = delete $cnf{ssl_private_key};

    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;
    $process_name = 'deploy::server:' unless defined $process_name;
    $user = 0 unless defined $user;
    $group = 0 unless defined $group;
    $addr = 0 unless defined $addr;
    $port = 80 unless defined $port;
    $backlog = SOMAXCONN unless defined $backlog;
    $socket_timeout = 5 unless defined $socket_timeout;
    $socket_accept_filter = 0 unless defined $socket_accept_filter;
    $max_prefork = 0 unless defined $max_prefork;
    $max_requests_per_child = 0 unless defined $max_requests_per_child;
    $max_process_timeout = 300 unless defined $max_process_timeout;
    
    $log_write = 0 unless defined $log_write;
    $log_error_level = 'info' unless defined $log_error_level;
    $log_error_path = '/var/log/deploy/error.log' unless defined $log_error_path;
    $log_access_path = '/var/log/deploy/access.log' unless defined $log_access_path;
    $ssl = 'false' unless defined $ssl;

    my $self =
    bless {
        debug                   => $debug,
        warn                    => $warn,
        process_name            => $process_name,
        user                    => $user,
        group                   => $group,
        addr                    => $addr,
        port                    => $port,
        backlog                 => $backlog,

        max_prefork             => $max_prefork,
        max_requests_per_child  => $max_requests_per_child,
        max_process_timeout     => $max_process_timeout,

        log_write               => $log_write,
        log_error_level         => $log_error_level,
        log_error_path          => $log_error_path,
        log_access_path         => $log_access_path,
        ssl                     => $ssl,
        ssl_public_key          => $ssl_public_key,
        ssl_private_key         => $ssl_private_key,
        aes_key                 => undef,

        sock_orphan             => undef,
        sock                    => undef,
        sock_listen             => undef,
        sock_accept             => undef,
        sock_client             => undef,
        sent_byte               => undef,
        socket_timeout          => $socket_timeout,
        socket_accept_filter    => $socket_accept_filter,
        request                 => {},

        server_read_request     => undef,
        server_send_response    => undef,

        worker_init             => $worker_init,
        worker_handler          => $worker_handler,
        
        worker_children         => {},
        worker_children_c       => 0,
        
        process_id              => $$
    }, $class;

    return bless $self;
}

sub getDate {
    my $self = shift if ref ($_[0]);
    my ($day, $month, $year, $hour, $min, $sec) = (localtime)[3,4,5,2,1,0];
    return sprintf("%04d/%02d/%02d %02d:%02d:%02d", 1900 + $year, $month + 1, $day, $hour, $min, $sec);
}

sub daemonize {
    my $self = shift if ref ($_[0]);
    my $_PATH_DEVNULL = "/dev/null";
    my $pid = fork();

    if ($pid > 0) {
        exit(0);
    }
    umask(0);
    POSIX::setsid() || die "POSIX::setsid() : $!";
    chdir('/') || die "chdir() : $!";
    open(STDIN, $_PATH_DEVNULL) || die "STDIN : $!";
    open(STDOUT, '>>', $_PATH_DEVNULL) || die "STDOUT : $!";
    open(STDERR, '>>', $_PATH_DEVNULL) || die "STDERR : $!";

    return $self;
}

sub setRunUser {
    my $self = shift if ref ($_[0]);
    my $user = $self->{user} || shift;
    my $group = $self->{group} || shift;
    my $uid = ($user =~ /^[0-9]+$/g) ? $user : POSIX::getpwnam($user);
    my $gid = ($group =~ /^[0-9]+$/g) ? $group : POSIX::getgrnam($group);
    POSIX::setgid($gid);
    POSIX::setuid($uid);
    return $self;
}

sub serverException {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $isexit = defined($response->{exit}) ? $response->{exit} : TRUE;
    my $status = $response->{status} || 'error';
    my $return = $response->{return} || FAILURE;
    my $string = $response->{string};
    my $inline = $response->{line};
    my $date = $self->getDate();

    $self->serverLogWriteError("[$date] Exception: [$status:$return] [$string] [in $inline line]", $status);

    ($isexit) && exit($return);
}

sub serverMessage {
    my $self = shift if ref ($_[0]);
    my $string = shift;
    my $status = shift || 'info';
    my $date = $self->getDate();

    $self->serverLogWriteError("[$date] $status: [$string]", $status);

    return $self;
}

sub serverLogWrite {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $path = $response->{path};
    my $message = $response->{message};
    my $mode = $response->{mode} || 0600;
    my $status = $response->{status};
    ($self->{log_write}) || return;
    if($path =~ /(syslog)/i) {
        my $level = 'LOG_' . uc($status);
        $self->syslogWrite(__PACKAGE__ . " $message", $level, __PACKAGE__);
    } else {
        $path = strftime("$path", localtime);
        $self->fileWrite($path, $message, $mode);
    }
    return $self;
}

sub serverLogWriteAccess {
    my $self = shift if ref ($_[0]);
    my $request = shift;
    my $response = shift;
    my $status = shift || 'info';
    my $path = shift || $self->{log_access_path};
    my $mode = shift || 0600;
    my $lfmt = "%s %s [%s] \"%s %s %s\" %s %s";
    my @logs = (
        $request->{REMOTE_ADDR},
        $request->{REMOTE_HOST},
        $self->getDate(),
        $request->{METHOD},
        $request->{URL},
        "HTTP/$request->{HTTP_VERSION}",
        $response->{status} || 200,
        $response->{size}
    );
    my $buf = sprintf($lfmt, @logs);
    $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ': ' . $buf});
    $self->serverLogWrite({path => $path, message => "$buf\n", mode => $mode, status => $status});
    return $self;
}

sub serverLogWriteError {
    my $self = shift if ref ($_[0]);
    my $buf = shift;
    my $status = shift || 'error';
    my $path = shift || $self->{log_error_path};
    my $mode = shift || 0600;
    my $i = 0;
    my @levels = qw(emerg alert crit error warn notice info debug);
    my %levels = map{ ($_ => $i++) } @levels;
    my $config_level = $levels{$self->{log_error_level}} || -1;
    my $status_level = $levels{$status} || 0;
    $self->__debug({string => (caller(0))[3] . '() line ' . __LINE__ . ': ' . "log_error_level[$self->{log_error_level}:$config_level] status_level[$status:$status_level]"});
    ($config_level >= $status_level) || return;
    $self->serverLogWrite({path => $path, message => "$buf\n", mode => $mode, status => $status});
    return $self;
}

# GET/POST variables parse
sub httpQueryParse {
    my $self = shift if ref ($_[0]);
    my $data = shift;
    my $query = {};
    for (split /&/, $data) {
        # for base64
        my ($key, $val) = split(/=/, $_, 2);
        $val =~ s/\+/ /g;
        $val =~ s/%(..)/chr(hex($1))/eg;
        $query->{$key} = $val;
    }
    return $query;
}

sub serverReturnPack {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $data = {};
    my %status = (
        200 => {string => "OK", content => ""},
        400 => {string => "Bad Request", content => ""},
        401 => {string => "Unauthorized", content => ""},
        403 => {string => "Permission Denied", content => "You don't have permission to access."},
        404 => {string => "Not Found", content => ""},
        405 => {string => "Method Not Allowed", content => ""},
        408 => {string => "Request Timeout", content => ""},
        500 => {string => "Internal Server Error", content => ""},
    );
    my $code = $response->{status} || 200;
    my $string = $response->{string} || $status{$code}{string};
    my $content = $response->{content} || $status{$code}{content};
    my $content_type = $response->{content_type} || "text/plain";
    my $charset = $response->{charset} || "utf-8";
    my $content_length = defined($content) ? length($content) : 0;

    $data->{header} = "HTTP/1.1 $code $string\r\n";
    $data->{header} .= "Content-Type: $content_type; charset=$charset\r\n";
    $data->{header} .= "Content-Length: " . $content_length . "\r\n";
    $data->{header} .= "Connection: close\r\n\r\n";
    $data->{content} = ($content_length) ? $content : '';
    return $data;
}

sub serverReturnPlain {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $sock = shift || $self->{sock};
    my $data = $self->serverReturnPack($response);

    $self->{sent_byte} = $self->socketSend($data->{header} . $data->{content}, $sock);

    return $self;
}

sub serverReturnCrypt {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $sock = shift || $self->{sock};
    my $data = $self->serverReturnPack($response);

    my $crypt = Deploy::Crypt->new(aes_key => $self->{aes_key});
    my $encrypt_content = $crypt->encrypt(
        {
            key_type => 'aes',
            string => $data->{header} . $data->{content}
        }
    );

    my $content = "ssl-length:" . length($encrypt_content) . "\r\n\r\n" . $encrypt_content;

    $self->{sent_byte} = $self->socketSend($content, $sock);

    return $self;
}

sub serverReadRequestPlain {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock_client};
    my $request = {};

    # Read Request
    local $/ = Socket::CRLF;
    while ($_ = $self->socketRecv($sock)) {
        chomp; # Main http request
        if (/\s*(\w+)\s*([^\s]+)\s*HTTP\/(\d.\d)/) {
            $request->{METHOD} = uc $1;
            $request->{URL} = $2;
            $request->{HTTP_VERSION} = $3;
        } # Standard headers
        elsif (/:/) {
            my ($type, $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $request->{lc $type} = $val;
        } # POST data
        elsif (/^$/) {
            $request->{CONTENT} = $self->socketRecv($sock, $request->{'content-length'})
            if defined $request->{'content-length'};
            last;
        }
    }

    return $request;
}

sub serverReadRequestCrypt {
    my $self = shift if ref ($_[0]);
    my $sock = shift || $self->{sock_client};
    my $request = {};

    # Protocol
    #
    # Client
    # >> WHO
    #
    # Server
    # << DEPLOY-SSL
    #
    # Client
    # >> aes: {base64_encode_public_key_crypted_aes_key}\r\n
    # >> ssl-length: {size}}\r\n\r\n
    # >> {aes_crypted_data}
    #
    # Server
    # << {aes_crypted_data}

    local $/ = Socket::CRLF;
    while ($_ = $self->socketRecv($sock)) {
        chomp;
        if (/:/) {
            my ($type, $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $request->{lc $type} = $val;
        } elsif (/^$/) {
            $request->{'CONTENT-SSL'} = $self->socketRecv($sock, $request->{'ssl-length'})
            if defined $request->{'ssl-length'};
            last;
        } elsif (/^WHO$/i) {
            # Send banner
            $self->socketSend("DEPLOY-SSL\r\n", $sock);
        }
    }

    if (!defined $request->{'ssl-length'}) {
        print "Protocol mismatch.\n";
    }
    # Read Request
    my $crypt = Deploy::Crypt->new(private_key => $self->{ssl_private_key});
    $self->{aes_key} = $crypt->decrypt({key_type => 'private', string => MIME::Base64::decode($request->{aes})});

    my $decrypt_content = $crypt->decrypt(
        {
            key_type => 'aes',
            string => $request->{'CONTENT-SSL'},
            aes_key => $self->{aes_key}
        }
    );

    my ($header, $content) = split(Socket::CRLF x 2, $decrypt_content, 2);
    my @lines = split(Socket::CRLF, $header);

    for (@lines) {
        chomp; # Main http request
        if (/\s*(\w+)\s*([^\s]+)\s*HTTP\/(\d.\d)/) {
            $request->{METHOD} = uc $1;
            $request->{URL} = $2;
            $request->{HTTP_VERSION} = $3;
        } # Standard headers
        elsif (/:/) {
            (my $type, my $val) = split(/:/, $_, 2);
            $type =~ s/^\s+//;
            for ($type, $val) {
                s/^\s+//;
                s/\s+$//;
            }
            $request->{lc $type} = $val;
        }
    }
    $request->{CONTENT} = $content;

    return $request;
}

# standalone
sub serverWorker {
    my $self = shift if ref ($_[0]);
    my $c_addr = shift || $self->{sock_accept};
    my $sock = shift || $self->{sock_client};

    my $request = {};
    my $query = {};

    # For destructor
    $self->{sock_orphan} = $sock;
    $self->{sock} = $sock;

    my $read_handler = $self->{server_read_request};
    $request = $self->can($read_handler) ? $self->$read_handler() : {};
    
    # Variables
    if ($c_addr) {
        my ($c_addr_port, $c_addr_ip) = sockaddr_in($c_addr);
        $request->{REMOTE_ADDR} = inet_ntoa($c_addr_ip);
        $request->{REMOTE_HOST} = gethostbyaddr($c_addr_ip, AF_INET);
    }

    #  Parse Request
    if ($request->{METHOD} eq 'GET') {
        if ($request->{URL} =~ /(.*)\?(.*)/) {
            $request->{URL} = $1;
            $request->{CONTENT} = $2;
            $query = $self->httpQueryParse($request->{CONTENT});
        } else {
            $query = FALSE;
        }
        $query->{"_method"} = "GET";
    } elsif ($request->{METHOD} eq 'POST') {
        $query = $self->httpQueryParse($request->{CONTENT});
        $query->{"_method"} = "POST";
    } else {
        $query->{"_method"} = "ERROR";
    }

    $self->{request}{headers} = $request;
    $self->{request}{args} = $query;

    my $response = $self->{worker_handler}->() if (defined($self->{worker_handler}));

    my $send_handler = $self->{server_send_response};
    $self->$send_handler($response, $sock);

    $response->{size} = $self->{sent_byte};
    
    $self->serverLogWriteAccess($request, $response);

    $self->socketClose($sock);

    # Important
    exit(SUCCESS);
}

sub serverAccept {
    my $self = shift if ref ($_[0]);
    my $SERVER = shift || $self->{sock_listen};
    my $CLIENT = shift || *CLIENT;
    my $c_addr = undef;
    my $c_addr_ip = undef;
    my $c_addr_port = undef;
    my $c_ip = undef;
    my $c_host = undef;
    my $port = $self->{port};
    my $max_requests_per_child = $self->{max_requests_per_child} || 0;
    my $request_count = $max_requests_per_child;
    my $max_process_timeout = $self->{max_process_timeout} || 0;

    SOCKET_ACCEPT: while (1) {  
        if ($c_addr = $self->socketAccept($CLIENT)) {
            !defined(my $pid = fork()) && $self->serverException({string => "fork() failed!", line => __LINE__});
            # Parent
            if ($pid > 0) {
                # Parent process
                $self->__debug(
                    {  
                        string => (caller(0))[3] . '() line ' . __LINE__ . ": serverAccept(): max_requests_per_child[$max_requests_per_child], request_count[$request_count]"
                    }
                );

                $max_requests_per_child || redo SOCKET_ACCEPT;
                if (!$request_count--) {
                    $self->serverMessage("max_requests_per_child($max_requests_per_child) completed!");
                    exit;
                }
                redo SOCKET_ACCEPT;
            } elsif ($pid == 0) {
                # Child process

                # Worker child process name
                $0 = $self->{process_name} . ' worker:child process';

                $self->timeoutMain(
                    sub {$self->serverWorker()},
                    $max_process_timeout
                ) || $self->serverReturn(
                    {
                        status => 408
                    }
                )->serverException(
                    {
                        status => 408,
                        string => "max($max_process_timeout) process timeout!",
                        line => __LINE__
                    }
                );

                # Important
                exit;
            } else {
                # fork fail
                redo SOCKET_ACCEPT;
            }
        } else {
            $self->serverException({string => "accept failed!", line => __LINE__});
            exit;
        }
    }

    $self->socketClose($SERVER);

    return $self;
}

sub serverChildKiller {
    my $self = shift if ref ($_[0]);
    print "serverChildKiller\n";
    local ($SIG{CHLD}) = 'IGNORE';
    kill('INT', keys %{$self->{worker_children}});
    $self->serverMessage("Server Stop: process killed...");
    exit;
}

sub serverChildReaper {
    my $self = shift if ref ($_[0]);

    while ((my $pid = waitpid(-1, WNOHANG)) > 0) {
        $self->{worker_children_c}--;
        delete $self->{worker_children}{$pid};
    }

    $SIG{CHLD} = sub { $self->serverChildReaper() };
}

sub serverPrefork {
    my $self = shift if ref ($_[0]);
    my $max_prefork = defined($_[0]) ? $_[0] : $self->{max_prefork};
    my $SERVER = shift || $self->{sock_listen};
    my $pid;
    my $sigset;

    for (0..$max_prefork) {
        # block signal for fork
        $sigset = POSIX::SigSet->new(SIGINT);
        sigprocmask(SIG_BLOCK, $sigset) || $self->serverException({string => "Can't block SIGINT for fork(): $!", line => __LINE__});

        !defined(my $pid = fork()) && $self->serverException({string => "fork() failed!", line => __LINE__});;

        if ($pid > 0) {
            # Parent process
            sigprocmask(SIG_UNBLOCK, $sigset) || $self->serverException({string => "Can't unblock SIGINT for fork(): $!", line => __LINE__});
            $self->{worker_children_c}++;
            $self->{worker_children}{$pid} = 1;
            next;
        } elsif($pid == 0) {
            # Worker process name
            $0 = $self->{process_name} . ' worker process';
            # Child process
            $SIG{INT} = 'DEFAULT'; # make SIGINT kill us as it did before
            $SIG{CHLD} = 'IGNORE'; # Avoiding zombie process

            sigprocmask(SIG_UNBLOCK, $sigset) || $self->serverException({string => "Can't unblock SIGINT for fork(): $!", line => __LINE__});
            $self->serverAccept($SERVER);

            # Important
            $self->serverException({status => "info", string => "$pid is finished!", line => __LINE__});
            exit;
        } else {
            # fork fail
            next;
        }
    } 

    return $self;
}

sub serverListen {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $socket_accept_filter = $cnf->{socket_accept_filter} || $self->{socket_accept_filter};
    my $rc = $self->socketListen();
    $socket_accept_filter && $self->socketAcceptFilter();
    return $rc;
}

sub serverMain {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $daemonize = $cnf->{daemonize} || FALSE;

    # Initialize
    defined($self->{worker_init}) && $self->{worker_init}->($self)->serverMessage("Server Start: Initialize...");

    # Set uid & gid for running
    $self->setRunUser();

    # Master process name
    $0 = $self->{process_name} . ' master process';

    $self->__load_module();

    # In Parent: SIGINT signal does kill child processes including parent. 
    $SIG{INT} = sub { $self->serverChildKiller() };

    # In Parent: SIGCHLD sinal does reaper terminated child processess.
    $SIG{CHLD} = sub { $self->serverChildReaper() };

    $self->socketListenAvail() || $self->serverException({string => "accept port $self->{port} already in used!", line => __LINE__});

    $self->daemonize() if ($daemonize);

    my $max_prefork = $self->{max_prefork} || 0;
    while(TRUE) {
        if ($self->socketListenAvail()) {
            kill('INT', keys %{$self->{worker_children}});
            $self->serverListen() && $self->serverPrefork();
        }

        # prefork number keep
        if ($self->{worker_children_c} < ($max_prefork + 1)) {
            my $prefork_add_c = $max_prefork - $self->{worker_children_c};
            $self->__debug(
                {
                    string => (caller(0))[3] . '() line ' . __LINE__ . ": serverPrefork(): worker_children_c[$self->{worker_children_c}], max_prefork[$max_prefork], prefork_add_c[$prefork_add_c]"
                }
            );
            $self->socketListenAvail() && $self->servertListen();
            $self->serverPrefork($prefork_add_c);
            $self->serverMessage("Server Prefork Added: $prefork_add_c + 1");

        }
        sleep 1;
    }

    $self->__debug(
        {
            string => (caller(0))[3] . '() line ' . __LINE__ . ": exit(): main loop"
        }
    );

    return $self;
}   

sub __load_module {
    my $self = shift if ref ($_[0]);
    my $suffix;
    if ($self->{ssl}) {
        eval{use Deploy::Crypt};
        if ( my $err = $@ ) {
            die "You need to install perl-Crypt-OpenSSL-RSA perl-Crypt-CBC perl-Crypt-OpenSSL-AES package.\n$@";
        }
        $suffix = 'Crypt';
    } else {
        $suffix = 'Plain';
    }
    $self->{server_read_request} = 'serverReadRequest' . $suffix;
    $self->{server_send_response} = 'serverReturn' . $suffix;
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

    $self->socketClose($self->{sock_orphan});
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
