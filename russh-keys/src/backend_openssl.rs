use std::convert::TryFrom;

use crate::key::{RsaCrtExtra, SignatureHash};
use crate::{protocol, Error};
use openssl::{
    bn::{BigNum, BigNumContext, BigNumRef},
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
};

#[derive(Clone)]
pub struct RsaPublic {
    key: Rsa<Public>,
    pkey: PKey<Public>,
}

impl RsaPublic {
    pub fn verify_detached(&self, hash: &SignatureHash, msg: &[u8], sig: &[u8]) -> bool {
        openssl::sign::Verifier::new(message_digest_for(hash), &self.pkey)
            .and_then(|mut v| v.verify_oneshot(sig, msg))
            .unwrap_or(false)
    }
}

impl TryFrom<&protocol::RsaPublicKey<'_>> for RsaPublic {
    type Error = Error;

    fn try_from(pk: &protocol::RsaPublicKey<'_>) -> Result<Self, Self::Error> {
        let key = Rsa::from_public_components(
            BigNum::from_slice(&pk.modulus)?,
            BigNum::from_slice(&pk.public_exponent)?,
        )?;
        Ok(Self {
            pkey: PKey::from_rsa(key.clone())?,
            key,
        })
    }
}

impl<'a> From<&RsaPublic> for protocol::RsaPublicKey<'a> {
    fn from(key: &RsaPublic) -> Self {
        Self {
            modulus: key.key.n().to_vec().into(),
            public_exponent: key.key.e().to_vec().into(),
        }
    }
}

impl PartialEq for RsaPublic {
    fn eq(&self, b: &RsaPublic) -> bool {
        self.pkey.public_eq(&b.pkey)
    }
}

impl Eq for RsaPublic {}

impl std::fmt::Debug for RsaPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RsaPublic {{ (hidden) }}")
    }
}

#[derive(Clone)]
pub struct RsaPrivate {
    key: Rsa<Private>,
    pkey: PKey<Private>,
}

impl RsaPrivate {
    pub fn new(
        sk: &protocol::RsaPrivateKey<'_>,
        extra: Option<&RsaCrtExtra<'_>>,
    ) -> Result<Self, Error> {
        let (d, p, q) = (
            BigNum::from_slice(&sk.private_exponent)?,
            BigNum::from_slice(&sk.prime1)?,
            BigNum::from_slice(&sk.prime2)?,
        );
        let (dp, dq) = if let Some(extra) = extra {
            (
                BigNum::from_slice(&extra.dp)?,
                BigNum::from_slice(&extra.dq)?,
            )
        } else {
            calc_dp_dq(d.as_ref(), p.as_ref(), q.as_ref())?
        };
        let key = Rsa::from_private_components(
            BigNum::from_slice(&sk.public_key.modulus)?,
            BigNum::from_slice(&sk.public_key.public_exponent)?,
            d,
            p,
            q,
            dp,
            dq,
            BigNum::from_slice(&sk.coefficient)?,
        )?;
        key.check_key()?;
        Ok(Self {
            pkey: PKey::from_rsa(key.clone())?,
            key,
        })
    }

    pub fn new_from_der(der: &[u8]) -> Result<Self, Error> {
        let key = Rsa::private_key_from_der(der)?;
        key.check_key()?;
        Ok(Self {
            pkey: PKey::from_rsa(key.clone())?,
            key,
        })
    }

    pub fn generate(bits: usize) -> Result<Self, Error> {
        let key = Rsa::generate(bits as u32)?;
        Ok(Self {
            pkey: PKey::from_rsa(key.clone())?,
            key,
        })
    }

    pub fn sign(&self, hash: &SignatureHash, msg: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(
            openssl::sign::Signer::new(message_digest_for(hash), &self.pkey)?
                .sign_oneshot_to_vec(msg)?,
        )
    }
}

impl<'a> TryFrom<&RsaPrivate> for protocol::RsaPrivateKey<'a> {
    type Error = Error;

    fn try_from(key: &RsaPrivate) -> Result<protocol::RsaPrivateKey<'a>, Self::Error> {
        let key = &key.key;
        // We always set these.
        if let (Some(p), Some(q), Some(iqmp)) = (key.p(), key.q(), key.iqmp()) {
            Ok(protocol::RsaPrivateKey {
                public_key: protocol::RsaPublicKey {
                    modulus: key.n().to_vec().into(),
                    public_exponent: key.e().to_vec().into(),
                },
                private_exponent: key.d().to_vec().into(),
                prime1: p.to_vec().into(),
                prime2: q.to_vec().into(),
                coefficient: iqmp.to_vec().into(),
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
        // We always set these.
        if let (Some(dp), Some(dq)) = (key.dmp1(), key.dmq1()) {
            Ok(RsaCrtExtra {
                dp: dp.to_vec().into(),
                dq: dq.to_vec().into(),
            })
        } else {
            Err(Error::KeyIsCorrupt)
        }
    }
}

impl<'a> From<&RsaPrivate> for protocol::RsaPublicKey<'a> {
    fn from(key: &RsaPrivate) -> Self {
        Self {
            modulus: key.key.n().to_vec().into(),
            public_exponent: key.key.e().to_vec().into(),
        }
    }
}

impl TryFrom<&RsaPrivate> for RsaPublic {
    type Error = Error;

    fn try_from(key: &RsaPrivate) -> Result<Self, Self::Error> {
        let key = Rsa::from_public_components(key.key.n().to_owned()?, key.key.e().to_owned()?)?;
        Ok(Self {
            pkey: PKey::from_rsa(key.clone())?,
            key,
        })
    }
}

fn message_digest_for(hash: &SignatureHash) -> MessageDigest {
    match hash {
        SignatureHash::SHA2_256 => MessageDigest::sha256(),
        SignatureHash::SHA2_512 => MessageDigest::sha512(),
        SignatureHash::SHA1 => MessageDigest::sha1(),
    }
}

fn calc_dp_dq(d: &BigNumRef, p: &BigNumRef, q: &BigNumRef) -> Result<(BigNum, BigNum), Error> {
    let one = BigNum::from_u32(1)?;
    let p1 = p - one.as_ref();
    let q1 = q - one.as_ref();
    let mut context = BigNumContext::new()?;
    let mut dp = BigNum::new()?;
    let mut dq = BigNum::new()?;
    dp.checked_rem(d, &p1, &mut context)?;
    dq.checked_rem(d, &q1, &mut context)?;
    Ok((dp, dq))
}
