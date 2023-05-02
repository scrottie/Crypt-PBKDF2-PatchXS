package Crypt::PBKDF2::PatchXS;

use strict;
use warnings;

use Crypt::PBKDF2;
# use Devel::Peek;
use IO::Handle;

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Crypt::PBKDF2::PatchXS', $VERSION);

=head1 NAME

Crypt::PBKDF2::PatchXS - Patch Crypt::PBKDF2 to do keyhashing in XS

=head1 SYNOPSIS

  use Crypt::CBC;
  use Crypt::PBKDF2;
  use Crypt::PBKDF2::PatchXS;

=head1 DESCRIPTION

Replaces C<Crypt::PBKDF2::PBKDF2> and C<Crypt::PBKDF2::_PBKDF2_F>
with monkey-patched versions to do key hash iteration in XS.
This is a bit over twice as fast, in my testing.

=cut

no warnings 'redefine';
*Crypt::PBKDF2::PBKDF2 = sub {
    my ($self, $salt, $password) = @_;
    my $iterations = $self->iterations // die;

    my $hasher = $self->hasher;  # not used; hmac_sha256 is assumed
  
    my $output;
  
    my $initial_hash = $salt . pack("N", 1); # pre-compute this for XS
    $output .= $self->_PBKDF2_F($hasher, $salt, $password, $iterations, 1, $initial_hash);  # 4 bytes
  
    $initial_hash = $salt . pack("N", 2); # pre-compute this for XS
    $output .= $self->_PBKDF2_F($hasher, $salt, $password, $iterations, 2, $initial_hash);   # 4 more bytes
  
    # warn "key = " . unpack('H32', $output) . "\n";
  
    return $output;
};

*Crypt::PBKDF2::_PBKDF2_F = *_PBKDF2_F;

1;

