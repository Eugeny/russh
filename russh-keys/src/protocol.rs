use std::borrow::Cow;

use crate::encoding::{Encoding, Position, SshRead, SshWrite};
use crate::key::zeroize_cow;

type Result<T> = std::result::Result<T, crate::Error>;

/// SSH RSA public key.
pub struct RsaPublicKey<'a> {
    /// `e`: RSA public exponent.
    pub public_exponent: Cow<'a, [u8]>,
    /// `n`: RSA modulus.
    pub modulus: Cow<'a, [u8]>,
}

impl<'a> SshRead<'a> for RsaPublicKey<'a> {
    fn read_ssh(pos: &mut Position<'a>) -> Result<Self> {
        Ok(Self {
            public_exponent: Cow::Borrowed(pos.read_mpint()?),
            modulus: Cow::Borrowed(pos.read_mpint()?),
        })
    }
}

impl SshWrite for RsaPublicKey<'_> {
    fn write_ssh<E: Encoding + ?Sized>(&self, encoder: &mut E) {
        encoder.extend_ssh_mpint(&self.public_exponent);
        encoder.extend_ssh_mpint(&self.modulus);
    }
}

/// SSH RSA private key.
pub struct RsaPrivateKey<'a> {
    /// RSA public key.
    pub public_key: RsaPublicKey<'a>,
    /// `d`: RSA private exponent.
    pub private_exponent: Cow<'a, [u8]>,
    /// CRT coefficient: `(inverse of q) mod p`.
    pub coefficient: Cow<'a, [u8]>,
    /// `p`: first prime factor of `n`.
    pub prime1: Cow<'a, [u8]>,
    /// `q`: Second prime factor of `n`.
    pub prime2: Cow<'a, [u8]>,
    /// Comment.
    pub comment: Cow<'a, [u8]>,
}

impl<'a> SshRead<'a> for RsaPrivateKey<'a> {
    fn read_ssh(pos: &mut Position<'a>) -> Result<Self> {
        Ok(Self {
            // Note the field order.
            public_key: RsaPublicKey {
                modulus: Cow::Borrowed(pos.read_mpint()?),
                public_exponent: Cow::Borrowed(pos.read_mpint()?),
            },
            private_exponent: Cow::Borrowed(pos.read_mpint()?),
            coefficient: Cow::Borrowed(pos.read_mpint()?),
            prime1: Cow::Borrowed(pos.read_mpint()?),
            prime2: Cow::Borrowed(pos.read_mpint()?),
            comment: Cow::Borrowed(pos.read_string()?),
        })
    }
}

impl SshWrite for RsaPrivateKey<'_> {
    fn write_ssh<E: Encoding + ?Sized>(&self, encoder: &mut E) {
        // Note the field order.
        encoder.extend_ssh_mpint(&self.public_key.modulus);
        encoder.extend_ssh_mpint(&self.public_key.public_exponent);
        encoder.extend_ssh_mpint(&self.private_exponent);
        encoder.extend_ssh_mpint(&self.coefficient);
        encoder.extend_ssh_mpint(&self.prime1);
        encoder.extend_ssh_mpint(&self.prime2);
        encoder.extend_ssh_string(&self.comment);
    }
}

impl Drop for RsaPrivateKey<'_> {
    fn drop(&mut self) {
        // Private parts only.
        zeroize_cow(&mut self.private_exponent);
        zeroize_cow(&mut self.coefficient);
        zeroize_cow(&mut self.prime1);
        zeroize_cow(&mut self.prime2);
        zeroize_cow(&mut self.comment);
    }
}
