# @file:    Crypt.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

package Deploy::Crypt;

use strict;
our(@ISA);
use Deploy::Carp;
use Crypt::OpenSSL::RSA;
use Crypt::CBC;

@ISA = qw(Deploy::File Deploy::Carp);

sub new {
    my($class, %cnf) = @_;

    my $debug = delete $cnf{debug};
    my $warn = delete $cnf{warn};
    my $aes_key = delete $cnf{aes_key};
    my $ssl_key = delete $cnf{ssl_key};
    my $public_key = delete $cnf{public_key};
    my $private_key = delete $cnf{private_key};
    $debug = 0 unless defined $debug;
    $warn = 0 unless defined $warn;
    my $self =
    bless {
        aes_key         => $aes_key,
        ssl_key         => $ssl_key,
        public_key      => $public_key,
        private_key     => $private_key,
        debug           => $debug,
        warn            => $warn
    }, $class;

    return bless $self;
}   

# public_key: encrypt
# private_key: decrypt|encrypt
sub getPrivateKey {
    my $self = shift if ref ($_[0]);
    my $size = shift || 1024;
    my $rsa = Crypt::OpenSSL::RSA->generate_key($size);
    return $rsa->get_private_key_string();
}

# generate (private|public).pem
# $ openssl genrsa 2048 > private.pem
# $ openssl rsa -in private.pem -out public.pem -outform PEM -pubout
sub encrypt {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $public_key = $cnf->{public_key} || $self->{public_key};
    my $private_key = $cnf->{private_key} || $self->{private_key};
    my $aes_key = $cnf->{aes_key} || $self->{aes_key};
    my $string;
    if ($cnf->{key_type} eq 'public') {
        my $public = Crypt::OpenSSL::RSA->new_public_key($public_key);
        $string = $public->encrypt($cnf->{string});
    } elsif ($cnf->{key_type} eq 'private') {
        my $private = Crypt::OpenSSL::RSA->new_private_key($private_key);
        $string = $private->encrypt($cnf->{string});
    } elsif ($cnf->{key_type} eq 'aes') {
        my $aes_key = $aes_key ? $aes_key : Crypt::CBC->random_bytes(16);
        my $cipher = Crypt::CBC->new(
            -key        => $aes_key,
            -keylength  => 256,
            -cipher     => "Crypt::OpenSSL::AES"
        );
        $string = $cipher->encrypt($cnf->{string});
        $self->{aes_key} = $aes_key unless defined $self->{aes_key};
    }
    return $string;
}

sub decrypt {
    my $self = shift if ref ($_[0]);
    my $cnf = shift;
    my $string;
    if ($cnf->{key_type} eq 'private') {
        my $private_key = $cnf->{private_key} || $self->{private_key};
        my $private = Crypt::OpenSSL::RSA->new_private_key($private_key);
        $string = $private->decrypt($cnf->{string});
    } elsif ($cnf->{key_type} eq 'aes') {
        my $aes_key = $cnf->{aes_key} || $self->{aes_key};
        eval {
            my $cipher = Crypt::CBC->new(
                -key        => $aes_key,
                -keylength  => 256,
                -cipher     => "Crypt::OpenSSL::AES"
            );
            $string = $cipher->decrypt($cnf->{string});
        };
        $@ && return $self->__return(
            {
                string => "error: decrypt(): $@",
                return => "error: decrypt(): $@"
            }
        );
    }
    return $string;
}
1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
