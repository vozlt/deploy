# @file:    Syslog.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Syslog;

use strict;
use Sys::Syslog;

sub new{
    my $class = shift;
    my $self = bless {}, $class;
    return bless $self;
}

sub syslogWrite {
    # http://perldoc.perl.org/Sys/Syslog.html
    # * Option
    # cons          if there is an error while sending data to the system logger, write directly to the system console
    # nodelay       open the connection to the logger immediately
    # nofatal       (default) delay opening the connection until the first message is logged
    # nowait        Don't wait for child processes that may have been created while logging the message.
    # perror        print log message also to standard error
    # pid           include PID with each message

    # * Facility
    # LOG_AUTH       security/authorization messages (use LOG_AUTHPRIV instead in systems where that constant is defined)
    # LOG_AUTHPRIV   security/authorization messages (private)
    # LOG_CRON       clock daemon (cron and at)
    # LOG_DAEMON     other system daemons
    # LOG_KERN       kernel messages
    # LOG_LOCAL0..7  reserved for local use, these are not available in Windows
    # LOG_LPR        line printer subsystem
    # LOG_MAIL       mail subsystem
    # LOG_NEWS       USENET news subsystem
    # LOG_SYSLOG     messages generated internally by syslogd
    # LOG_USER       generic user-level messages
    # LOG_UUCP       UUCP subsystem

    #* Priority
    # LOG_EMERG      system is unusable
    # LOG_ALERT      action must be taken immediately
    # LOG_CRIT       critical conditions
    # LOG_ERR        error conditions
    # LOG_WARNING    warning conditions
    # LOG_NOTICE     normal, but significant, condition
    # LOG_INFO       informational message
    # LOG_DEBUG      debug-level message

    my $self = shift if ref ($_[0]);
    my $message = shift;
    my $priority = shift || 'LOG_WARNING';
    my $program = shift || __PACKAGE__;
    my $host = shift;
    $host && setlogsock({ type => "udp", host => $host});
    openlog($program, 'ndelay,pid', "LOG_DAEMON");
    syslog($priority, $message);
    closelog;

    return $self;
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
