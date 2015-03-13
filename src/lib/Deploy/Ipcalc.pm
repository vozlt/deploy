# @file:    Ipcalc.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Ipcalc;

use strict;
use POSIX;
use Socket;

sub new{
    my $class = shift;
    my $self = bless {}, $class;
    return bless $self;
}

sub hex2bin {
    my $self = shift if ref ($_[0]);
    my $hex = shift;
    my $pack = unpack("B32", pack("N", $hex));
    $pack = substr($pack, -8);
    return $pack;
}

sub bin2hex {
    my $self = shift if ref ($_[0]);
    my $bin = shift;
    return unpack("N", pack("B32", substr("0" x 32 . $bin, -32)))
}

sub bin2ip {
    my $self = shift if ref ($_[0]);
    my $bin = shift;
    my $type = shift;
    my $ip;
    (length($bin) < 32) && return;
    $ip .= $self->bin2hex(substr($bin,0,8)) ."\.";
    $ip .= $self->bin2hex(substr($bin,8,8)) ."\.";
    $ip .= $self->bin2hex(substr($bin,16,8)) ."\.";
    if ( $type eq 'first') {
        $ip .= $self->bin2hex(substr($bin,24,8)) + 1 ;
    } elsif ($type eq 'broad') {
        $ip .= $self->bin2hex(substr($bin,24,8)) - 1 ;
    } else {
        $ip .= $self->bin2hex(substr($bin,24,8));
    }
    return $ip;
}

sub normalization {
    my $self = shift if ref ($_[0]);
    my $line = shift;
    my ($ip, $mask) = split(/\//, $line);
    $mask = ($mask) ? $mask : 32;
    return($ip, $mask);
}

sub ipCalc {
    my $self = shift if ref ($_[0]);
    my $cidr = shift;
    my %iph = ();

    my ($ip,$net_mask) = $self->normalization($cidr);

    my $host_mask = 32-$net_mask;
    my $max_host = POSIX::pow(2,$host_mask)-2;
    my $bin_mask = "1" x $net_mask . "0" x $host_mask;

    my $bin_ip ;
    $bin_ip .= $self->hex2bin($_) for (split(/\./, $ip));

    my $min = $bin_ip & $bin_mask;
    my $max_mask = "0" x $net_mask . "1" x $host_mask;
    my $max = $bin_ip | $max_mask;

    my $min_ip = $self->bin2ip($min);
    my $min_host_ip = $self->bin2ip($min, 'first');
    my $max_ip = $self->bin2ip($max);
    my $max_host_ip = $self->bin2ip($max,'broad');

    $iph{ip} = $ip;
    $iph{bin_ip} = $bin_ip;
    $iph{net_mask} = $net_mask;
    $iph{bin_mask} = $bin_mask;
    $iph{host_mask} = $host_mask;
    $iph{max_mask} = $max_mask;
    $iph{min_ip} = $min_ip;
    $iph{max_ip} = $max_ip;
    $iph{min} = $min;
    $iph{max} = $max;
    $iph{min_host_ip} = $min_host_ip;
    $iph{max_host_ip} = $max_host_ip;
    $iph{max_host} = $max_host;

    $iph{start_inet} = unpack('N', inet_aton($iph{min_host_ip}));
    $iph{finish_inet} = unpack('N', inet_aton($iph{max_host_ip}));

    return %iph;
}

sub ipCalcWithIn {
    my $self = shift if ref ($_[0]);
    my $range = shift;
    my $ipaddr = shift;

    my ($ip, $net_mask) = $self->normalization($range);

    return 1 if ($net_mask == 32 && ($ip eq $ipaddr));

    my $host_mask = 32-$net_mask;
    my $bin_mask = "1" x $net_mask . "0" x $host_mask;

    my $bin_ip ;
    $bin_ip .= $self->hex2bin($_) for (split(/\./, $ip));

    my $min = $bin_ip & $bin_mask;
    my $max_mask = "0" x $net_mask . "1" x $host_mask;
    my $max = $bin_ip | $max_mask;

    my $min_host_ip = $self->bin2ip($min, 'first');
    my $max_host_ip = $self->bin2ip($max, 'broad');

    my $start_inet = unpack('N', inet_aton($min_host_ip));
    my $finish_inet = unpack('N', inet_aton($max_host_ip));
    my $target_inet = unpack('N', inet_aton($ipaddr));

    return ($start_inet <= $target_inet && $target_inet <= $finish_inet) ? 1 : 0;
}

sub ipCalcPrint {
    my $self = shift if ref ($_[0]);
    my $cidr = shift;
    my %iph = $self->ipCalc($cidr);

    my $buf = "IP ADDRESS: $iph{ip}\t $iph{bin_ip}\n";
    $buf .= "NETWORK MASK: \/$iph{net_mask}\t\t $iph{bin_mask}\n";
    $buf .= "WILDCARD: \/$iph{host_mask}\t\t $iph{max_mask}\n";
    $buf .= "NETWORK IP: $iph{min_ip}\/$iph{net_mask}\t $iph{min}\n";
    $buf .= "BROADCAST ADDR: $iph{max_ip}\t $iph{max}\n";
    $buf .= "FIRST ADDR: $iph{min_host_ip}\n";
    $buf .= "LAST ADDR: $iph{max_host_ip}\n";
    $buf .= "MAX HOSTS: $iph{max_host}\n";
    $buf .= "INET RANGE: $iph{start_inet} - $iph{finish_inet}\n";

    print $buf;
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
