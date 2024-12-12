use ssh_encoding::Encode;

#[doc(hidden)]
pub trait EncodedExt {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>>;
}

impl<E: Encode> EncodedExt for E {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}

pub struct NameList(pub Vec<String>);

impl NameList {
    pub fn as_encoded_string(&self) -> String {
        self.0.join(",")
    }
}

impl Encode for NameList {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.as_encoded_string().encoded_len()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.as_encoded_string().encode(writer)
    }
}

#[macro_export]
#[doc(hidden)]
#[allow(clippy::crate_in_macro_def)]
macro_rules! map_err {
    ($result:expr) => {
        $result.map_err(|e| crate::Error::from(e))
    };
}

pub use map_err;

mod signature_workarounds {
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha512};
    use ssh_encoding::Encode;
    use ssh_key::{Algorithm, HashAlg};

    use crate::helpers::EncodedExt;
    use crate::key::PrivateKeyWithHashAlg;

    fn sign_rsa_with_hash_alg_encoded(
        key: &RsaPrivateKey,
        message: &[u8],
        hash_alg: Option<HashAlg>,
    ) -> ssh_key::Result<Vec<u8>> {
        let signature = key.sign(
            match hash_alg {
                Some(HashAlg::Sha256) => Pkcs1v15Sign::new::<sha2::Sha256>(),
                Some(HashAlg::Sha512) => Pkcs1v15Sign::new::<sha2::Sha512>(),
                None => Pkcs1v15Sign::new::<sha1::Sha1>(),
                _ => unreachable!(),
            },
            &match hash_alg {
                Some(HashAlg::Sha256) => Sha256::digest(message).to_vec(),
                Some(HashAlg::Sha512) => Sha512::digest(message).to_vec(),
                None => Sha1::digest(message).to_vec(),
                _ => unreachable!(),
            },
        )?;

        // due to internal stable ssh_key hijinks, it's impossible to construct a pure ssh-rsa signature in any way so we just encode it manually

        let mut buf = Vec::new();
        Algorithm::Rsa { hash: hash_alg }.encode(&mut buf)?;
        signature.to_vec().encode(&mut buf)?;
        dbg!(&buf);
        Ok(buf)
    }

    // TODO only needed until https://github.com/RustCrypto/SSH/pull/318 is released
    // and until RSA-SHA1 signatures are implemented
    pub fn sign_workaround_encoded(
        key: &PrivateKeyWithHashAlg,
        data: &[u8],
    ) -> ssh_key::Result<Vec<u8>> {
        dbg!(&key);
        Ok(match key.key_data() {
            ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
                let pk = rsa::RsaPrivateKey::from_components(
                    <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.public.n)?,
                    <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.public.e)?,
                    <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.private.d)?,
                    vec![
                        <rsa::BigUint as std::convert::TryFrom<_>>::try_from(
                            &rsa_keypair.private.p,
                        )?,
                        <rsa::BigUint as std::convert::TryFrom<_>>::try_from(
                            &rsa_keypair.private.q,
                        )?,
                    ],
                )?;
                let Algorithm::Rsa { hash } = key.algorithm() else {
                    unreachable!();
                };
                sign_rsa_with_hash_alg_encoded(&pk, data, hash)?
            }
            keypair => signature::Signer::try_sign(keypair, data)?.encoded()?,
        })
    }
}

mod algorithm {
    use ssh_key::{Algorithm, HashAlg};

    pub trait AlgorithmExt {
        fn hash_alg(&self) -> Option<HashAlg>;
        fn with_hash_alg(&self, hash_alg: Option<HashAlg>) -> Self;
        fn new_certificate_ext(algo: &str) -> Result<Self, ssh_key::Error>
        where
            Self: Sized;
    }

    impl AlgorithmExt for Algorithm {
        fn hash_alg(&self) -> Option<HashAlg> {
            match self {
                Algorithm::Rsa { hash } => *hash,
                _ => None,
            }
        }

        fn with_hash_alg(&self, hash_alg: Option<HashAlg>) -> Self {
            match self {
                Algorithm::Rsa { .. } => Algorithm::Rsa { hash: hash_alg },
                x => x.clone(),
            }
        }

        fn new_certificate_ext(algo: &str) -> Result<Self, ssh_key::Error> {
            match algo {
                "rsa-sha2-256-cert-v01@openssh.com" => Ok(Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                }),
                "rsa-sha2-512-cert-v01@openssh.com" => Ok(Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                }),
                x => Algorithm::new_certificate(x),
            }
        }
    }
}

#[doc(hidden)]
pub use {algorithm::AlgorithmExt, signature_workarounds::sign_workaround_encoded};
