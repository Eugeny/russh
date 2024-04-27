use std::convert::TryFrom;

use crate::key::{RsaCrtExtra, SignatureHash};
use crate::{protocol, Error};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint,
};

#[derive(Clone, PartialEq, Eq)]
pub struct RsaPublic {
    key: rsa::RsaPublicKey,
}

impl RsaPublic {
    pub fn verify_detached(&self, hash: &SignatureHash, msg: &[u8], sig: &[u8]) -> bool {
        self.key
            .verify(signature_scheme_for_hash(hash), &hash_msg(hash, msg), sig)
            .is_ok()
    }
}

impl TryFrom<&protocol::RsaPublicKey<'_>> for RsaPublic {
    type Error = Error;

    fn try_from(pk: &protocol::RsaPublicKey<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: rsa::RsaPublicKey::new(
                BigUint::from_bytes_be(&pk.modulus),
                BigUint::from_bytes_be(&pk.public_exponent),
            )?,
        })
    }
}

impl<'a> From<&RsaPublic> for protocol::RsaPublicKey<'a> {
    fn from(key: &RsaPublic) -> Self {
        Self {
            modulus: key.key.n().to_bytes_be().into(),
            public_exponent: key.key.e().to_bytes_be().into(),
        }
    }
}

impl std::fmt::Debug for RsaPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RsaPublic {{ (hidden) }}")
    }
}

#[derive(Clone)]
pub struct RsaPrivate {
    key: rsa::RsaPrivateKey,
}

impl RsaPrivate {
    pub fn new(
        sk: &protocol::RsaPrivateKey<'_>,
        extra: Option<&RsaCrtExtra<'_>>,
    ) -> Result<Self, Error> {
        let mut key = rsa::RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&sk.public_key.modulus),
            BigUint::from_bytes_be(&sk.public_key.public_exponent),
            BigUint::from_bytes_be(&sk.private_exponent),
            vec![
                BigUint::from_bytes_be(&sk.prime1),
                BigUint::from_bytes_be(&sk.prime2),
            ],
        )?;
        key.validate()?;
        key.precompute()?;

        if Some(BigUint::from_bytes_be(&sk.coefficient)) != key.crt_coefficient() {
            return Err(Error::KeyIsCorrupt);
        }
        if let Some(extra) = extra {
            if (
                Some(&BigUint::from_bytes_be(&extra.dp)),
                Some(&BigUint::from_bytes_be(&extra.dq)),
            ) != (key.dp(), key.dq())
            {
                return Err(Error::KeyIsCorrupt);
            }
        }

        Ok(Self { key })
    }

    pub fn new_from_der(der: &[u8]) -> Result<Self, Error> {
        use pkcs1::DecodeRsaPrivateKey;
        Ok(Self {
            key: rsa::RsaPrivateKey::from_pkcs1_der(der)?,
        })
    }

    pub fn generate(bits: usize) -> Result<Self, Error> {
        Ok(Self {
            key: rsa::RsaPrivateKey::new(&mut crate::key::safe_rng(), bits)?,
        })
    }

    pub fn sign(&self, hash: &SignatureHash, msg: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .key
            .sign(signature_scheme_for_hash(hash), &hash_msg(hash, msg))?)
    }
}

impl<'a> TryFrom<&RsaPrivate> for protocol::RsaPrivateKey<'a> {
    type Error = Error;

    fn try_from(key: &RsaPrivate) -> Result<protocol::RsaPrivateKey<'a>, Self::Error> {
        let key = &key.key;
        // We always precompute these.
        if let ([p, q], Some(iqmp)) = (key.primes(), key.crt_coefficient()) {
            Ok(protocol::RsaPrivateKey {
                public_key: protocol::RsaPublicKey {
                    modulus: key.n().to_bytes_be().into(),
                    public_exponent: key.e().to_bytes_be().into(),
                },
                private_exponent: key.d().to_bytes_be().into(),
                prime1: p.to_bytes_be().into(),
                prime2: q.to_bytes_be().into(),
                coefficient: iqmp.to_bytes_be().into(),
                comment: b"".as_slice().into(),
            })
        } else {
            Err(Error::KeyIsCorrupt)
        }
    }
}

impl<'a> TryFrom<&RsaPrivate> for RsaCrtExtra<'a> {
    type Error = Error;

    fn try_from(key: &RsaPrivate) -> Result<RsaCrtExtra<'a>, Self::Error> {
        let key = &key.key;
        // We always precompute these.
        if let (Some(dp), Some(dq)) = (key.dp(), key.dq()) {
            Ok(RsaCrtExtra {
                dp: dp.to_bytes_be().into(),
                dq: dq.to_bytes_be().into(),
            })
        } else {
            Err(Error::KeyIsCorrupt)
        }
    }
}

impl<'a> From<&RsaPrivate> for protocol::RsaPublicKey<'a> {
    fn from(key: &RsaPrivate) -> Self {
        Self {
            modulus: key.key.n().to_bytes_be().into(),
            public_exponent: key.key.e().to_bytes_be().into(),
        }
    }
}

impl TryFrom<&RsaPrivate> for RsaPublic {
    type Error = Error;

    fn try_from(key: &RsaPrivate) -> Result<Self, Self::Error> {
        Ok(Self {
            key: key.key.to_public_key(),
        })
    }
}

fn signature_scheme_for_hash(hash: &SignatureHash) -> rsa::pkcs1v15::Pkcs1v15Sign {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    match *hash {
        SignatureHash::SHA2_256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        SignatureHash::SHA2_512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        SignatureHash::SHA1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
    }
}

fn hash_msg(hash: &SignatureHash, msg: &[u8]) -> Vec<u8> {
    use digest::Digest;
    match *hash {
        SignatureHash::SHA2_256 => sha2::Sha256::digest(msg).to_vec(),
        SignatureHash::SHA2_512 => sha2::Sha512::digest(msg).to_vec(),
        SignatureHash::SHA1 => sha1::Sha1::digest(msg).to_vec(),
    }
}
