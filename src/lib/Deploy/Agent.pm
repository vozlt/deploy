# @file:    Agent.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Agent;

use strict;
use warnings "all";

use Deploy::Boolean qw(:Boolean);
use Deploy::Onetime;
use Deploy::Server;
use Deploy::Ipcalc;
use Deploy::Config;
use Deploy::Syslog;
use Deploy::Rsync;
use Deploy::Carp;

use Socket;
use MIME::Base64;
use Data::Dumper;

our @ISA = qw(Deploy::Ipcalc Deploy::Config Deploy::Syslog Deploy::Carp);

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
    my $log_write = delete $cnf{log_write};
    my $log_error_level = delete $cnf{log_error_level};
    my $log_error_path = delete $cnf{log_error_path};
    my $log_access_path = delete $cnf{log_access_path};
    my $key_cipher = delete $cnf{key_cipher};
    my $ssl = delete $cnf{ssl};
    my $ssl_public_key = delete $cnf{ssl_public_key};
    my $ssl_private_key = delete $cnf{ssl_private_key};
    $path = '/etc/deploy/deploy_agent.ini' unless defined $path;

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

        server_self             => {},
        request                 => {},
        cnf                     => {},
        
        orders                  => {},
        allow_orders            => ['status', 'rlist', 'rsync', 'rkill', 'exec'],
        ps                      => 'ps',
        rsync                   => {},
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
        $self->ipCalcWithIn($cidr, $remote_addr) && return 1;
    }
    return;
}

sub checkAllowMethod {
    my $self = shift if ref ($_[0]);
    my $method = $self->{request}{headers}{METHOD};
    my @methods = qw(GET POST);

    grep(/^${method}$/, @methods) || return;
}

sub checkAllowAuth {
    my $self = shift if ref ($_[0]);
    my $auth_key = $self->{request}{args}{auth_key};

    my $onetime = Deploy::Onetime->new(cipher=> $self->{key_cipher});
    return $onetime->validKey($auth_key);
}

sub checkAllowUrl {
    my $self = shift if ref ($_[0]);
    my $url = $self->{request}{headers}{URL};
    my @args =  grep {/\S/} split('/', $url);
    my $target = $self->{orders}{target} = $args[0];
    my $order = $self->{orders}{order} = $args[1];
    (grep(/^$order$/, @{$self->{allow_orders}}) && $target eq 'agent') || return;
}

sub checkAllowPath {
    my $self = shift if ref ($_[0]);
    my $src = shift || $self->{returns}{src};
    my @paths = @{$self->{'cnf'}{'allow::paths'}{'path'}};
    map{s/\s//g; s/[\/]+/\//g; s/[\/]+$//g} @paths;
    
    if (!(grep { $src =~ /^$_([\/]|$)/ } @paths)) {
        $self->{returns}{status} = FALSE;
        $self->{returns}{status_code} = 403;
        $self->{returns}{content} = "$src is not allowed!";
        return $self->{returns}{status};
    }   
    
    return ($self->{returns}{status} = TRUE);
}

sub returnToServer {
    my $self = shift if ref ($_[0]);
    my $status = shift || $self->{returns}{status_code};
    return (
        {
            status => $status,
            content => $self->{returns}{content}
        }
    );
}

# options=service:httpd,restart
sub parseRSyncQuery {
    my $self = shift if ref ($_[0]);
    my $options = $self->{request}{args}{options};
    my $group = $self->{'cnf'}{"rsync::group::$options"};
    my ($dest_host, $dest_path, $src_path); 
    my ($dest, $src); 
    
    if ($group) {
        $dest = $group->{dest} if defined $group->{dest};
        $src = $group->{src} if defined $group->{src};
    }

    # host::DEST|/tmp/src
    if ($options =~ /[\|,]/) {
        my @args = split(/[\|,]/, $options);
        $dest = $args[0] if defined $args[0];
        $src = $args[1] if defined $args[1];
    }

    if (grep{!defined($_)} ($dest, $src)) {
        $self->{returns}{status} = FALSE;
        $self->{returns}{status_code} = 400;
        $self->{returns}{content} = "empty value in options!";
        return $self->{returns}{status};
    }

    $dest =~ s/[\/]+/\//g if defined $dest;
    $src =~ s/[\/]+/\//g if defined $src;

    $self->{returns}{status} = TRUE;
    $self->{returns}{dest} = $dest;
    $self->{returns}{src} = $src;

    return $self->{returns}{status};
}

sub __escape_string {
    my $self = shift if ref ($_[0]);
    my $string = shift;
    my $pattern = '([;<>\*\|`&\$!#\(\)\[\]\{\}\'\"])';

    if (ref($string) eq 'ARRAY') {
        for (0.. $#{$string}) {
            $string->[$_] =~ s/$pattern/\\$1/g;
        }
        return $string;
    } else {
        $$string =~ s/$pattern/\\$1/g;
    }
    return $string;

    $string =~ s/([;<>\*\|`&\$!#\(\)\[\]\{\}'"])/\\$1/g;
}

sub __exec {
    my $self = shift if ref ($_[0]);
    # to prevent return code error(No child process) in fork()
    local ($SIG{CHLD}) = 'DEFAULT';
    my $output = qx(@_);
    my $status = $? >> 8; # = $? / 256

    $self->{returns}{return} = $?;
    $self->{returns}{status} = $status ? 0 : 1;
    $self->{returns}{content} = $output;

    return $self->{returns}{status};
}

# options=service:httpd|restart
sub parseExecQuery {
    my $self = shift if ref ($_[0]);
    my $options = $self->{request}{args}{options};
    my ($command, $args);
    my %jobs = ();  

    my @args = split(/[\|,]/, $options);
    $command = shift @args if defined $args[0];
    my @groups = keys %{$self->{cnf}{jobs}{list}};
    for my $group (@groups) {
        $jobs{$_} = $self->{cnf}{jobs}{list}{$group}{$_} for (keys %{$self->{cnf}{jobs}{list}{$group}});
    }
    my @cmds = keys(%jobs);

    $self->__debug(
        {   
            string => (caller(0))[3] . '() line ' . __LINE__ . ": " . Dumper(%jobs)
        }
    );

    if (!defined($command) || !grep(/^${command}$/, @cmds)) {
        $command = '' if !defined($command);
        $self->{returns}{status} = FALSE;
        $self->{returns}{status_code} = 400;
        $self->{returns}{content} = "exec[$command] not found!";
        return $self->{returns}{status};
    }
    $self->__escape_string(\@args);
    $args = join(' ', @args);
    my $system_command = sprintf($jobs{$command}, $args);
    
    $self->{returns}{status} = TRUE;
    $self->{returns}{content} = $system_command;

    return $self->{returns}{status};
}

sub getRsyncObject {
    my $self = shift if ref ($_[0]);
    my $order = shift || $self->{orders}{order};
    my $options = $self->{request}{args}{options};
    my $group = $self->{'cnf'}{"rsync::group::$options"};
    my @force_flags = qw(stats verbose);
    my @default_flags = qw(archive delete force);
    my (@flags, @scalars, @arrays);
    my %response = ();
    my $sync_sure = ($order eq 'rsync') ? TRUE : FALSE;
    
    $self->parseRSyncQuery() || return FALSE;
    $self->checkAllowPath() || return FALSE;

    my $dest = $self->{returns}{dest} if defined $self->{returns}{dest};
    my $src = $self->{returns}{src} if defined $self->{returns}{src};

    $self->{rsync}{path} = defined($group->{rsync}) ? $group->{rsync} : '/usr/bin/rsync';
    $self->{rsync}{scalar}{rsh} = $group->{rsh} if defined $group->{rsh};

    $self->{rsync}{array}{exclude} = \@{$group->{exclude}} if defined($group->{exclude});
    $self->{rsync}{array}{include} = \@{$group->{include}} if defined($group->{include});

    my @user_options = @{$group->{option}} if defined($group->{option});

    $self->{rsync}{flag}{'dry-run'} = 1 if (!$sync_sure);
    @flags = @user_options ? (@force_flags) : (@force_flags, @default_flags);

    $self->{rsync}{flag}{$_} = 1 for(@flags);

    my $rsync = Deploy::Rsync->new(
        {
            debug => $self->{debug},
            path => $self->{rsync}{path},
            flag => $self->{rsync}{flag},
            scalar => $self->{rsync}{scalar},
            array => $self->{rsync}{array},
            dest => $dest,
            src => $src,
            strings => \@user_options,
            background => $sync_sure,
            queue_path => '/tmp',
        }
    );
    return $rsync;
}

sub __json_encode {
    my $self = shift if ref ($_[0]);
    my $response = shift;
    my $option = shift;
    my (@elements, $element);
    for my $key (keys %{$response}) {
        my $type = ref($response->{$key});
        if ($type eq 'ARRAY') {
            $element = "[\n" . join(",\n", map {'"' . $_ . '"'} @{$response->{$key}}) . "\n]";
        } else {
            $element = '"' . $response->{$key} . '"';
        }
        push @elements, "\"$key\": $element";
    }
    my $encode = join(",\n", @elements);
    return "{\n$encode\n}";
}

sub __return_rsync_false {
    my $self = shift if ref ($_[0]);
    my $rsync = shift;
    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $self->__json_encode(
                {
                    return => 'false',
                    content => MIME::Base64::encode($rsync->{returns}{content}, "")
                }
            )
        }
    );
}

sub __order_status {
    my $self = shift if ref ($_[0]);
    my $rsync = $self->getRsyncObject() || return $self->returnToServer();
    my $status = $rsync->checkSyncStatus();

    my @pids = ref $status ? keys %{$status} : ();
    if ($status) {
        return(
            {
                status => 200,
                content_type => 'application/json',
                content => $self->__json_encode(
                    {
                        return => 'true',
                        alreadyRsync => 'true',
                        process => \@pids
                    }
                )
            }
        );
    }
    $rsync->exec();

    $rsync->{returns}{status} || return $self->__return_rsync_false($rsync);

    $rsync->{returns}{content} =~ s/\r/\n/g;
    my @data = split(/\n\n/, $rsync->{returns}{content});

    my $transfer_files_count = 0;
    my $transfer_files_size = 0;
    $transfer_files_count = () = $data[0] =~ /\ndeleting[ ]/gi;
    $transfer_files_count += $1 if ($data[1] =~ /Number of files transferred: ([0-9]+)/gi);
    $transfer_files_size = $1 if ($data[1] =~ /Total transferred file size: ([0-9]+)/gi);

    my $content = $self->__json_encode(
        {
            return => 'true',
            alreadyRsync => 'false',
            transferFilesCount => $transfer_files_count,
            transferFilesSize => $transfer_files_size
        }
    );
    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $content
        }
    );
}

sub __order_rlist {
    my $self = shift if ref ($_[0]);
    my $rsync = $self->getRsyncObject() || return $self->returnToServer();
    $rsync->exec();
    $rsync->{returns}{status} || return $self->__return_rsync_false($rsync);
    $rsync->{returns}{content} =~ s/\r/\n/g;
    my @data = split(/\n\n/, $rsync->{returns}{content});
    my $transfer_files_count = 0;
    my $transfer_files_size = 0;
    $transfer_files_count = () = $data[0] =~ /\ndeleting[ ]/gi;
    $transfer_files_count += $1 if ($data[1] =~ /Number of files transferred: ([0-9]+)/gi);
    $transfer_files_size = $1 if ($data[1] =~ /Total transferred file size: ([0-9]+)/gi);
    my @files = grep {/[^\/]$/} split("\n", $data[0]);
    shift @files;
    my (@new_files, @delete_files);
    for my $file (@files) {
        if ($file =~ /^deleting[ ](.*)/i) {
            push @delete_files, $1;
        } else {
            push @new_files, $file;
        }
    }

    my $content = $self->__json_encode(
        {
            return => 'true',
            transferFilesCount => $transfer_files_count,
            transferFilesSize => $transfer_files_size,
            transferDeleteFiles => \@delete_files,
            transferNewFiles => \@new_files,
        }
    );

    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $content
        }
    );
}

sub __order_rsync {
    my $self = shift if ref ($_[0]);
    my $order = shift;
    my $rsync = $self->getRsyncObject() || return $self->returnToServer();
    my $status = $rsync->checkSyncStatus();
    my @pids = ref $status ? keys %{$status} : ();
    if ($status) {
        return(
            {
                status => 200,
                content_type => 'application/json',
                content => $self->__json_encode(
                    {
                        return => 'true',
                        alreadyRsync => 'true',
                        process => \@pids
                    }
                )
            }
        );
    }
    $rsync->exec();
    
    if ($rsync->{returns}{content} =~ /rsync error/i) {
        return $self->__return_rsync_false($rsync);
    } 
    
    my $content = $self->__json_encode(
        {
            return => 'true',
            checksum => $rsync->{opts}{checksum}
        }
    );

    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $content
        }
    );
}

sub __order_rkill {
    my $self = shift if ref ($_[0]);
    my $rsync = $self->getRsyncObject();
    my $pgrep = $rsync->killProcess();
    my @pids = $pgrep ? keys %{$pgrep} : ();
    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $self->__json_encode(
                {
                    return => 'true',
                    process => \@pids
                }
            )
        }
    );
}

sub __order_exec {
    my $self = shift if ref ($_[0]);

    $self->parseExecQuery() || return $self->returnToServer();
    my $command = $self->{returns}{content};
    $self->__exec($command . ' 2>&1');
    return(
        {
            status => 200,
            content_type => 'application/json',
            content => $self->__json_encode(
                {
                    return => $self->{returns}{status} ? 'true' : 'false',
                    content => MIME::Base64::encode($self->{returns}{content}, ""),
                    command => MIME::Base64::encode($command, "")
                }
            )
        }
    );
}

# first reading in serverMain(config file...)
sub workerInit {
    my $self = shift if ref ($_[0]);
    my $server_self = shift if ref ($_[0]);
    $self->{server_self} = $server_self; 

    my %cnf = $self->parseIniFile($self->{path});
    $cnf{jobs}{list} = {$self->parseIniFile($cnf{jobs}{path})};

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

    $process_name = 'deploy::agent:' unless defined $process_name;
    $user = 0 unless defined $user;
    $group = 0 unless defined $group;
    $addr = 0 unless defined $addr;
    $port = 3440 unless defined $port;
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

    # Server config
    $server_self->{debug} = $self->{debug} || $server_self->{debug};
    $server_self->{process_name} = defined($self->{process_name}) ? $self->{process_name} : $process_name;
    $server_self->{user} = defined($self->{user}) ? $self->{user} : $user;
    $server_self->{group} = defined($self->{group}) ? $self->{group} : $group;
    $server_self->{addr} = defined($self->{addr}) ? $self->{addr} : $addr;
    $server_self->{port} = defined($self->{port}) ? $self->{port} : $port;
    $server_self->{backlog} =  defined($self->{backlog}) ? $self->{backlog} : $backlog;
    $server_self->{socket_timeout} =  defined($self->{socket_timeout}) ? $self->{socket_timeout} : $socket_timeout;
    $server_self->{socket_accept_filter} =  defined($self->{socket_accept_filter}) ? $self->{socket_accept_filter} : $socket_accept_filter;
    $server_self->{max_prefork} =  defined($self->{max_prefork}) ? $self->{max_prefork} : $max_prefork;
    $server_self->{max_requests_per_child} =  defined($self->{max_requests_per_child}) ? $self->{max_requests_per_child} : $max_requests_per_child;
    $server_self->{max_process_timeout} =  defined($self->{max_process_timeout}) ? $self->{max_process_timeout} : $max_process_timeout;
    
    $server_self->{log_write} =  defined($self->{log_write}) ? $self->{log_write} : $log_write;
    $server_self->{log_error_level} =  defined($self->{log_error_level}) ? $self->{log_error_level} : $log_error_level;
    $server_self->{log_error_path} =  defined($self->{log_error_path}) ? $self->{log_error_path} : $log_error_path;
    $server_self->{log_access_path} =  defined($self->{log_access_path}) ? $self->{log_access_path} : $log_access_path;
    $server_self->{ssl} =  defined($self->{ssl}) ? $self->{ssl} : $ssl;
    $server_self->{ssl_public_key} =  defined($self->{ssl_public_key}) ? $self->{ssl_public_key} : $ssl_public_key;
    $server_self->{ssl_private_key} =  defined($self->{ssl_private_key}) ? $self->{ssl_private_key} : $ssl_private_key;

    $server_self->{ssl_public_key} = $self->fileRead($server_self->{ssl_public_key}) if defined $server_self->{ssl_public_key};
    $server_self->{ssl_private_key} = $self->fileRead($server_self->{ssl_private_key}) if defined $server_self->{ssl_private_key};
    
    # Agent config
    $self->{key_cipher} =  defined($self->{key_cipher}) ? $self->{key_cipher} : $key_cipher;

    # String to flag
    $server_self->{socket_accept_filter} = ($server_self->{socket_accept_filter} =~ /^(true|on|1)$/i) ? 1 : 0;
    $server_self->{log_write} = ($server_self->{log_write} =~ /^(true|on|1)$/i) ? 1 : 0;
    $server_self->{ssl} = ($server_self->{ssl} =~ /^(true|on|1)$/i) ? 1 : 0;

    $self->{cnf} = \%cnf;
    
    return $server_self;
}

sub workerHandlerInit {
    my $self = shift if ref ($_[0]);
    my $server_self = $self->{server_self};
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

    $self->checkAllowInet() || return({status => 403});
    $self->checkAllowMethod() || return({status => 405});
    $self->checkAllowAuth() || return({status => 401});
    $self->checkAllowUrl() || return({status => 404});

    my $order_handler = '__order_' . $self->{orders}{order};
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
