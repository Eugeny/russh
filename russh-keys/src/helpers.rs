use ssh_encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::Algorithm;

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

#[doc(hidden)]
pub fn sign_with_hash_alg(key: &PrivateKeyWithHashAlg, data: &[u8]) -> ssh_key::Result<Vec<u8>> {
    Ok(match key.key_data() {
        KeypairData::Rsa(rsa_keypair) => {
            let Algorithm::Rsa { hash } = key.algorithm() else {
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

use crate::key::PrivateKeyWithHashAlg;
