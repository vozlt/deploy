# @file:    File.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::File;

use strict;
our (@ISA);
use Deploy::Carp;
use Digest::MD5;
use Fcntl;
use IO::Handle;
use File::Copy;     # move()

@ISA = qw(Deploy::Carp);

sub new{
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $path = delete $cnf{path};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;

    my $self =
    bless {
        debug   => $debug,
        warn    => $warn,
        path    => $path
    }, $class;

    return bless $self;
}

sub fileReadByte {
    my $self = shift if ref ($_[0]);
    my $path = shift;
    my $byte = shift || 1;
    my $buf;
    $path = $self->{path} unless defined $path;
    (defined $path && -e $path) || $self->__return({string => "error: PATH[$path] is not defined or exists!"});
    open(my $FP, "<", $path) || return $self->__return({string => "error: open(): $!"});
    read($FP, $buf, $byte) || return $self->__return({string => "error: read(): $!"});
    close($FP);
    return $buf;
}

sub fileRead {
    my $self = shift if ref ($_[0]);
    my $path = shift;
    local $/ = undef;
    $path = $self->{path} unless defined $path;
    (defined $path && -e $path) || $self->__return({string => "error: PATH[$path] is not defined or exists!"});
    open(my $FP, "<", $path) || return $self->__return({string => "error: open(): $!"});
    my $buf = <$FP>;
    close($FP);
    return $buf;
}

sub fileReadLines {
    my $self = shift if ref ($_[0]);
    my $path = shift;
    $path = $self->{path} unless defined $path;
    (defined $path && -e $path) || $self->__return({string => "error: PATH[$path] is not defined or exists!"});
    my @lines = FH->getlines() if (sysopen(FH, $path, O_RDONLY));
    close(FH);
    return @lines;
}

sub fileWrite {
    my $self = shift if ref ($_[0]);
    my $path = shift;
    my $writebuf = shift;
    my $mode = shift;
    my $ret = undef;
    $path = $self->{path} unless defined $path;
    defined $path || return;
    $mode = 0644 unless defined $mode;
    ($ret = sysopen(FH, $path, O_WRONLY|O_APPEND|O_CREAT, $mode)) && FH->syswrite($writebuf);
    close(FH);
    return $ret;
}

sub fileRcopy {
    my $self = shift if ref ($_[0]);
    my $from_dir = shift;
    my $to_dir = shift;

    opendir(DH, $from_dir) || return $self->__return({string => "error: opendir(): $!"});

    (-e $to_dir) || mkdir($to_dir) || return $self->__return({string => "error: mkdir(): $!"});

    for my $entry (readdir DH) {
        next if $entry =~ /^(\.|\.\.)$/;
        my $source = $from_dir . '/' . $entry;
        my $destination = $to_dir . '/' . $entry;

        if (-d $source) {
            (-e $destination) || mkdir($destination) || return $self->__return({string => "error: mkdir(): $!"});
            $self->fileRcopy($source, $destination);
        } else {
            copy($source, $destination) || $self->__return({string => "error: copy($source, $destination): $!"}); 
        }
    }
    closedir(DH);
    return $self;
}

sub md5sum {
    my $self = shift if ref ($_[0]);
    my $request = shift;
    my $string = $request->{string};
    my $path = $request->{path};
    my $digest = undef;

    my $ctx = Digest::MD5->new();
    if ($string) {
        $ctx->add($string);
    } else {
        open(FILE, $path) || $self->__return({string => "error: open() : $!"});
        $ctx->addfile(*FILE);
        close(FILE);
    }
    return $ctx->hexdigest;
}

sub trim {
    my $self = shift if ref ($_[0]);
    my $string = \shift;
    $$string =~ s/[\s\n]*//g;
    return $self;
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
