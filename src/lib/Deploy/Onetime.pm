# @file:    Onetime.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Onetime;

use strict;
use Digest::MD5;

sub new {
    my($class, %cnf) = @_;

    my $cipher = delete $cnf{cipher};
    my $expire = delete $cnf{expire};
    $cipher = 0xffff unless defined $cipher;
    $expire = 60 unless defined $expire;
    my $self =
    bless {
        cipher      => $cipher,
        expire      => $expire
    }, $class;

    return bless $self;
}   

# Vernam cipher Algorithm
#   x ^ y ^ y = x
#
# Example: arg is a only numbers 
#   xorx('01234567') => 10325476
#   xorx('10325476') => 01234567
#
# Argument is a only numbers 
sub xorx {
    my $self = shift if ref ($_[0]);
    my $v = shift;
    my $x = 1;
    my $xor_plus = undef;
    my $len = length($v) - 1;
    for(0..$len) {
        my $c = int(substr($v, $_, 1));
        $xor_plus .= ($c ^ $x);
    }
    return $xor_plus;
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
        open(FILE, $path) || return;
        $ctx->addfile(*FILE);
        close(FILE);
    }
    return $ctx->hexdigest;
}

sub expireKey {
    my $self = shift if ref ($_[0]);
    my $old = shift;
    my $expire = shift || $self->{expire};
    my $now = time();
    my $diff = abs($now - $old);
    ($expire > $diff) && return 1;
    return;
}

# Simple & no security
sub generateKey {
    my $self = shift if ref ($_[0]);
    my $cipher = shift || $self->{cipher};
    my $now = time();
    my $crypt_key = $self->md5sum({string => $cipher}) . reverse($self->xorx($now));
    return $crypt_key;
}

sub validKey {
    my $self = shift if ref ($_[0]);
    my $crypt_key = shift;
    my $cipher = shift || $self->{cipher};
    my $now = time();

    (length($crypt_key) < 32) && return;
    my $my_crypt_key = $self->md5sum({string => $cipher});
    my $your_crypt_key = substr($crypt_key, 0, 32);
    my $your_time = reverse($self->xorx(substr($crypt_key, 32)));
    ($my_crypt_key eq $your_crypt_key) || return;
    return $self->expireKey($your_time);
}

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
