# @file:    Proxy.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Proxy;

use strict;
use warnings "all";

use Deploy::Boolean qw(:Boolean);
use Deploy::Onetime;
use Deploy::Server;
use Deploy::Ipcalc;
use Deploy::Config;
use Deploy::Rsync;
use Deploy::Carp;
use Deploy::Client;

use Socket;
use JSON;
use Data::Dumper;

our @ISA = qw(Deploy::Ipcalc Deploy::Config Deploy::Carp);

sub new {
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $path = delete $cnf{path};
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

    # Client (user -> proxy -> client -> agent)
    my $client_worker_method = delete $cnf{client_worker_method};
    my $client_ipc_path = delete $cnf{client_ipc_path};
    my $client_port = delete $cnf{port};
    my $client_thread_timeout = delete $cnf{client_thread_timeout};
    my $client_socket_timeout = delete $cnf{client_socket_timeout};
    my $client_key_cipher = delete $cnf{client_key_cipher};
    my $client_ssl = delete $cnf{client_ssl};
    my $client_ssl_public_key = delete $cnf{client_ssl_public_key};

    my $log_write = delete $cnf{log_write};
    my $log_error_level = delete $cnf{log_error_level};
    my $log_error_path = delete $cnf{log_error_path};
    my $log_access_path = delete $cnf{log_access_path};
    my $key_cipher = delete $cnf{key_cipher};
    my $ssl = delete $cnf{ssl};
    my $ssl_public_key = delete $cnf{ssl_public_key};
    my $ssl_private_key = delete $cnf{ssl_private_key};
    $path = '/etc/deploy/deploy_proxy.ini' unless defined $path;

    my $self =
    bless {
        debug                   => $debug,
        path                    => $path,

        user                    => $user,
        group                   => $group,
        addr                    => $addr,
        port                    => $port,
        backlog                 => $backlog,

        max_prefork             => $max_prefork,
        max_requests_per_child  => $max_requests_per_child,
        max_process_timeout     => $max_process_timeout,

        socket_timeout          => $socket_timeout,
        socket_accept_filter    => $socket_accept_filter,
        
        log_write               => $log_write,
        log_error_level         => $log_error_level,
        log_error_path          => $log_error_path,
        log_access_path         => $log_access_path,
        key_cipher              => $key_cipher,
        ssl                     => $ssl,
        ssl_public_key          => $ssl_public_key,
        ssl_private_key         => $ssl_private_key,

        client_worker_method    => $client_worker_method,
        client_ipc_path         => $client_ipc_path,
        client_port             => $client_port,
        client_thread_timeout   => $client_thread_timeout,
        client_socket_timeout   => $client_socket_timeout,
        client_key_cipher       => $client_key_cipher,
        client_ssl              => $client_ssl,
        client_ssl_public_key   => $client_ssl_public_key,
    
        server_self             => {},
        request                 => {},
        cnf                     => {},
        
        orders                  => {},
        allow_orders            => ['status', 'rlist', 'rsync', 'rkill', 'exec'],
        ps                      => 'ps',
        proxy                   => {},
        returns                 => {},

        process_name            => $process_name,
        process_id              => $$
    }, $class;

    return bless $self;
}

sub checkAllowInet {
    my $self = shift if ref ($_[0]);
    my @hosts = @{$self->{'cnf'}{'allow::hosts'}{'host'}};
    my $remote_addr = $self->{request}{headers}{REMOTE_ADDR};

    for (@hosts) {
        my $cidr = undef;
        if (/[a-z]+/i) {
            my $iaddr = Socket::inet_aton($_) || next;
            $cidr = Socket::inet_ntoa($iaddr) || next;
        } else {
            $cidr = $_;
        }
        $self->__debug(
            {
                string => (caller(0))[3] . '() line ' . __LINE__ . ': ' . 
                "checkAllowInet() => cidr:$cidr, remote_addr:$remote_addr"
            }
        );
        $self->ipCalcWithIn($cidr, $remote_addr) && return TRUE;
    }
    $self->{returns}{content} = "Your IP[$remote_addr] doesn't have permisson to access on this server.";
    return;
}

sub checkAllowMethod {
    my $self = shift if ref ($_[0]);
    my $method = $self->{request}{headers}{METHOD};
    my @methods = qw(GET POST);

    grep(/^${method}$/, @methods) || return;
}

sub checkAllowApi {
    my $self = shift if ref ($_[0]);
    my $api_key = $self->{orders}{api_key};
    my $args = $self->{orders}{args}; # (groups|hosts):(group or hosts)

    my $proxy = $self->{proxy} = $self->getHosts();

    if ($proxy->{type} eq 'hosts') {
        
        for my $host (@{$proxy->{hosts}}) {
            if (!grep(/^${host}$/, @{$self->{cnf}{api}{list}{access_hosts}{$api_key}})) {
                $self->{returns}{content} = "You don't have permisson to access on this[$host].";
                return;
            }
        }
    } elsif ($proxy->{type} eq 'groups') {
        for my $group (@{$proxy->{groups}}) {
            if (!grep(/^${group}$/, @{$self->{cnf}{api}{list}{access_groups}{$api_key}})) {
                $self->{returns}{content} = "You don't have permisson to access on this[$group].";
                return;
            }
        }
    } else {
        $self->{returns}{content} = "Syntax error, unrecognized expression: [$args]";
        return;
    }

    return TRUE;
}

sub checkAllowUrl {
    my $self = shift if ref ($_[0]);
    my $url = $self->{request}{headers}{URL};
    my @args =  grep {/\S/} split('/', $url);
    my $target = $self->{orders}{target} = $args[0];
    my $order = $self->{orders}{order} = $args[1];
    my $options = $self->{orders}{options} = ($args[2]) ? $args[2] : $self->{request}{args}{options};
    my $args = $self->{orders}{args} = ($args[3]) ? $args[3] : $self->{request}{args}{args};
    my $api_key = $self->{orders}{api_key} = ($args[4]) ? $args[4] : $self->{request}{args}{api_key};

    $self->trim($self->{orders}{target});
    $self->trim($self->{orders}{args});
    $self->trim($self->{orders}{options});
    $self->trim($self->{orders}{api_key});

    (grep(/^$order$/, @{$self->{allow_orders}}) && $target =~ /^(api|agent)$/) || return;
}

sub __client_exec {
    my $self = shift if ref ($_[0]);
    my $api_key = $self->{orders}{api_key};
    my @hosts = @{$self->{proxy}{hosts}};

    my $client = Deploy::Client->new(
        warn => $self->{warn},
        debug => $self->{debug},
        worker_method => $self->{client_worker_method},
        ipc_path => $self->{client_ipc_path},
        port => $self->{client_port},
        thread_timeout => $self->{client_thread_timeout},
        socket_timeout => $self->{client_socket_timeout},
        ssl => $self->{client_ssl},
        ssl_public_key => $self->{client_ssl_public_key},
        key_cipher => $self->{client_key_cipher},
        orders => {
            target => $self->{orders}{target},
            order => $self->{orders}{order},
            options => $self->{orders}{options},
            args => $self->{orders}{args},
            hosts => \@hosts
        }
    );

    my $results = $client->exec();
    $self->__debug(
        {
            string => (caller(0))[3] . '() line ' . __LINE__ . ": " . Dumper($results)
        }
    );
    my $json = JSON->new->utf8(1)->pretty(1);
    my $jref = {};
    for my $res (@{$results}) {
        my $host = $res->{host};
        my $server_status = $res->{server_status};
        my $content = $res->{CONTENT};
        my $order = $self->{orders}{order};
        my $return = ($res->{HTTP_CODE} == 200) ? 1 :0;

        my $json_content = ($return) ? $json->decode($content) : FALSE;

        $jref->{$host}{$order}{return} = $return;
        $jref->{$host}{$order}{serverStatus} = $server_status;
        $jref->{$host}{$order}{content} = ($json_content) ? $json_content : $content;
        $jref->{$host}{$order}{returnCode} = $res->{HTTP_CODE};
        $jref->{$host}{$order}{returnString} = $res->{HTTP_STRING};
    }

    my $json_string = $json->encode($jref);

    return $json_string;
}

sub __proxy_exec {
    my $self = shift if ref ($_[0]);
    my $content;
    my $status = 200;
    eval {
        $content = $self->__client_exec();
    };

    if ($@) {
        $self->__debug(
            {  
                string => (caller(0))[3] . '() line ' . __LINE__ . ": $@"
            }
        );
        if (!defined($content)) {
            $status = 500;
            $content = $@
        }
    }

    return(
        {
            status => $status,
            content => $content
        }
    );
}

sub getHosts {
    my $self = shift if ref ($_[0]);
    my $args = shift || $self->{orders}{args}; # (groups|hosts):(group or hosts)
    my @hosts = ();
    my @groups = ();

    my ($left, $right) = split(/:/, lc($args), 2);
    if ($left eq 'hosts') {
        @hosts = grep {/\S/} split(/,/, $right);
    } elsif ($left eq 'groups') {
        @groups = grep {/\S/} split(/,/, $right);
        for my $group (@groups) {
            push @hosts, $self->getGroupToHosts($group);
        }
    }

    return ({type => $left, hosts => \@hosts, groups => \@groups});
}

sub getAccessHosts {
    my $self = shift if ref ($_[0]);
    my $api_key = shift || $self->{orders}{api_key};
    defined $self->{cnf}{api}{list}{access_hosts}{$api_key} || return;
    return @{$self->{cnf}{api}{list}{access_hosts}{$api_key}};
}

sub getAccessGroups {
    my $self = shift if ref ($_[0]);
    my $api_key = shift || $self->{orders}{api_key};
    defined $self->{cnf}{api}{list}{access_groups}{$api_key} || return;
    return @{$self->{cnf}{api}{list}{access_groups}{$api_key}};
}

sub getGroupToHosts {
    my $self = shift if ref ($_[0]);
    my $group = shift;
    defined $self->{cnf}{api}{list}{servers}{$group} || return;
    return @{$self->{cnf}{api}{list}{servers}{$group}};
}

sub __init_api {
    my $self = shift if ref ($_[0]);
    my @keys = keys %{$self->{cnf}{api}{list}{keys}};
    my @groups = ();
    for my $key (@keys) {
        for my $group (@{$self->{cnf}{api}{list}{keys}{$key}}) {
            push @groups, grep {/\S/} split(/,/, $group);
        }
        for my $group (@groups) {
            push @{$self->{cnf}{api}{list}{access_hosts}{$key}}, @{$self->{cnf}{api}{list}{servers}{$group}}
            if defined $self->{cnf}{api}{list}{servers}{$group};
        }
        push @{$self->{cnf}{api}{list}{access_groups}{$key}}, @groups;
        @groups = ();
    }

    return $self;
}

# first reading in serverMain(config file...)
sub workerInit {
    my $self = shift if ref ($_[0]);
    my $server_self = shift if ref ($_[0]);
    $self->{server_self} = $server_self; 
    my %cnf = $self->parseIniFile($self->{path});
    $cnf{api}{list} = {$self->parseIniFile($cnf{api}{path})};
    my $process_name = $cnf{server}{process_name};
    my $user = $cnf{server}{user};
    my $group = $cnf{server}{group};
    my $addr = $cnf{server}{addr};
    my $port = $cnf{server}{port};
    my $backlog = $cnf{server}{backlog};
    my $socket_timeout = $cnf{server}{socket_timeout};
    my $socket_accept_filter = $cnf{server}{socket_accept_filter};
    my $max_prefork = $cnf{server}{max_prefork};
    my $max_requests_per_child = $cnf{server}{max_requests_per_child};
    my $max_process_timeout = $cnf{server}{max_process_timeout};
    
    my $log_write = $cnf{server}{log_write};
    my $log_error_level = $cnf{server}{log_error_level};
    my $log_error_path = $cnf{server}{log_error_path};
    my $log_access_path = $cnf{server}{log_access_path};
    my $key_cipher = $cnf{server}{key_cipher};
    my $ssl = $cnf{server}{ssl};
    my $ssl_public_key = $cnf{server}{ssl_public_key};
    my $ssl_private_key = $cnf{server}{ssl_private_key};
    
    my $client_worker_method = $cnf{client}{worker_method};
    my $client_ipc_path = $cnf{client}{ipc_path};
    my $client_port = $cnf{client}{port};
    my $client_thread_timeout = $cnf{client}{thread_timeout};
    my $client_socket_timeout = $cnf{client}{socket_timeout};
    my $client_key_cipher = $cnf{client}{key_cipher};
    my $client_ssl = $cnf{client}{ssl};
    my $client_ssl_public_key = $cnf{client}{ssl_public_key};

    $process_name = 'deploy::proxy:' unless defined $process_name;
    $user = 0 unless defined $user;
    $group = 0 unless defined $group;
    $addr = 0 unless defined $addr;
    $port = 3441 unless defined $port;
    $backlog = SOMAXCONN unless defined $backlog;
    $socket_timeout = 5 unless defined $socket_timeout;
    $socket_accept_filter = 'false' unless defined $socket_accept_filter;
    $max_prefork = 0 unless defined $max_prefork;
    $max_requests_per_child = 0 unless defined $max_requests_per_child;
    $max_process_timeout = 0 unless defined $max_process_timeout;
    
    $log_write = 'false' unless defined $log_write;
    $log_error_level = 'info' unless defined $log_error_level;
    $log_error_path = '/var/log/deploy/error.log' unless defined $log_error_path;
    $log_access_path = '/var/log/deploy/access.log' unless defined $log_access_path;
    $ssl = 'false' unless defined $ssl;

    $client_worker_method = 'fork' unless defined $client_worker_method;
    $client_ipc_path = '/tmp/.deploy_proxy_ipc' unless defined $client_ipc_path;
    $client_port = 3440 unless defined $client_port;
    $client_thread_timeout = 10 unless defined $client_thread_timeout;
    $client_socket_timeout = 5 unless defined $client_socket_timeout;
    $client_ssl = 'false' unless defined $client_ssl;

    # Server config
    $server_self->{debug} = $self->{debug} || $server_self->{debug};
    $server_self->{process_name} = defined($self->{process_name}) ? $self->{process_name} : $process_name;
    $server_self->{user} = defined($self->{user}) ? $self->{user} : $user;
    $server_self->{group} = defined($self->{group}) ? $self->{group} : $group;
    $server_self->{addr} = defined($self->{addr}) ? $self->{addr} : $addr;
    $server_self->{port} = defined($self->{port}) ? $self->{port} : $port;
    $server_self->{backlog} = defined($self->{backlog}) ? $self->{backlog} : $backlog;
    $server_self->{socket_timeout} = defined($self->{socket_timeout}) ? $self->{socket_timeout} : $socket_timeout;
    $server_self->{socket_accept_filter} =  defined($self->{socket_accept_filter}) ? $self->{socket_accept_filter} : $socket_accept_filter;
    $server_self->{max_prefork} = defined($self->{max_prefork}) ? $self->{max_prefork} : $max_prefork;
    $server_self->{max_requests_per_child} = defined($self->{max_requests_per_child}) ? $self->{max_requests_per_child} : $max_requests_per_child;
    $server_self->{max_process_timeout} = defined($self->{max_process_timeout}) ? $self->{max_process_timeout} : $max_process_timeout;
    
    $server_self->{log_write} = defined($self->{log_write}) ? $self->{log_write} : $log_write;
    $server_self->{log_error_level} = defined($self->{log_error_level}) ? $self->{log_error_level} : $log_error_level;
    $server_self->{log_error_path} = defined($self->{log_error_path}) ? $self->{log_error_path} : $log_error_path;
    $server_self->{log_access_path} = defined($self->{log_access_path}) ? $self->{log_access_path} : $log_access_path;
    $server_self->{ssl} = defined($self->{ssl}) ? $self->{ssl} : $ssl;
    $server_self->{ssl_public_key} = defined($self->{ssl_public_key}) ? $self->{ssl_public_key} : $ssl_public_key;
    $server_self->{ssl_private_key} = defined($self->{ssl_private_key}) ? $self->{ssl_private_key} : $ssl_private_key;

    $server_self->{ssl_public_key} = $self->fileRead($server_self->{ssl_public_key}) if defined $server_self->{ssl_public_key};
    $server_self->{ssl_private_key} = $self->fileRead($server_self->{ssl_private_key}) if defined $server_self->{ssl_private_key};
    
    # Agent config
    $self->{key_cipher} = defined($self->{key_cipher}) ? $self->{key_cipher} : $key_cipher;

    # Client config
    $self->{client_worker_method} = defined($self->{client_worker_method}) ? $self->{client_worker_method} : $client_worker_method;
    $self->{client_ipc_path} = defined($self->{client_ipc_path}) ? $self->{client_ipc_path} : $client_ipc_path;
    $self->{client_port} = defined($self->{client_port}) ? $self->{client_port} : $client_port;
    $self->{client_thread_timeout} = defined($self->{client_thread_timeout}) ? $self->{client_thread_timeout} : $client_thread_timeout;
    $self->{client_socket_timeout} = defined($self->{client_socket_timeout}) ? $self->{client_socket_timeout} : $client_socket_timeout;
    $self->{client_key_cipher} = defined($self->{client_key_cipher}) ? $self->{client_key_cipher} : $client_key_cipher;
    $self->{client_ssl} = defined($self->{client_ssl}) ? $self->{client_ssl} : $client_ssl;
    $self->{client_ssl_public_key} = defined($self->{client_ssl_public_key}) ? $self->{client_ssl_public_key} : $client_ssl_public_key;

    $self->{client_ssl_public_key} = $self->fileRead($self->{client_ssl_public_key}) if defined $self->{client_ssl_public_key};

    # String to flag
    $server_self->{socket_accept_filter} = ($server_self->{socket_accept_filter} =~ /^(true|on|1)$/i) ? 1 : 0;
    $server_self->{log_write} = ($server_self->{log_write} =~ /^(true|on|1)$/i) ? 1 : 0;
    $server_self->{ssl} = ($server_self->{ssl} =~ /^(true|on|1)$/i) ? 1 : 0;
    $self->{client_ssl} = ($self->{client_ssl} =~ /^(true|on|1)$/i) ? 1 : 0;

    $self->{cnf} = \%cnf;

    $self->__init_api();

    return $server_self;
}

sub workerHandlerInit {
    my $self = shift if ref ($_[0]);
    my $server_self = $self->{server_self};
    # same reference for memory
    $self->{request} = $server_self->{request};

    if ($self->{debug}) {
        my %headers = %{$self->{request}{headers}};
        my %args = %{$self->{request}{args}};
        for (keys(%headers)) {
            print("request{$_} = $headers{$_}\n");
        }
        for (keys(%args)) {
            print("args{$_} = $args{$_}\n");
        }
    }
}

sub workerHandler {
    my $self = shift if ref ($_[0]);
    my $server_self = $self->{server_self};

    $self->workerHandlerInit($server_self);

    $self->checkAllowInet() || return({status => 403, content => $self->{returns}{content}});
    $self->checkAllowMethod() || return({status => 405});
    $self->checkAllowUrl() || return({status => 404});
    $self->checkAllowApi() || return({status => 403, content => $self->{returns}{content}});

    my $order_handler = '__proxy_exec';

    return $self->can($order_handler) ? $self->$order_handler() : (status => 400, content => "${order_handler}() not found!");
}

sub main {
    my $self = shift if ref ($_[0]);
    my $daemonize = ($self->{debug}) ? FALSE : TRUE;
    my $server = Deploy::Server->new(
            worker_init => sub { $self->workerInit(@_) },
            worker_handler => sub { $self->workerHandler(@_) }
    );

    $server->serverMain({daemonize => $daemonize});
}

AUTOLOAD {
    my $self = shift if ref ($_[0]);
    my $attr = our ($AUTOLOAD);
    $attr =~ s/.*:://;
    return(status => 400, content => "$attr() not found!");
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
