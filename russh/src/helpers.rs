use std::fmt::Debug;

use ssh_encoding::{Decode, Encode};

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

impl Debug for NameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl NameList {
    pub fn as_encoded_string(&self) -> String {
        self.0.join(",")
    }

    pub fn from_encoded_string(value: &str) -> Self {
        Self(value.split(',').map(|x| x.to_string()).collect())
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

impl Decode for NameList {
    fn decode(reader: &mut impl ssh_encoding::Reader) -> Result<Self, ssh_encoding::Error> {
        let s = String::decode(reader)?;
        Ok(Self::from_encoded_string(&s))
    }

    type Error = ssh_encoding::Error;
}

pub(crate) mod macros {
    #[allow(clippy::crate_in_macro_def)]
    macro_rules! map_err {
        ($result:expr) => {
            $result.map_err(|e| crate::Error::from(e))
        };
    }

    pub(crate) use map_err;
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub(crate) use macros::map_err;

#[doc(hidden)]
pub fn sign_with_hash_alg(key: &PrivateKeyWithHashAlg, data: &[u8]) -> ssh_key::Result<Vec<u8>> {
    Ok(match key.key_data() {
        #[cfg(feature = "rsa")]
        ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
            let ssh_key::Algorithm::Rsa { hash } = key.algorithm() else {
                unreachable!();
            };
            signature::Signer::try_sign(&(rsa_keypair, hash), data)?.encoded()?
        }
        keypair => signature::Signer::try_sign(keypair, data)?.encoded()?,
    })
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
pub use algorithm::AlgorithmExt;

use crate::keys::key::PrivateKeyWithHashAlg;
