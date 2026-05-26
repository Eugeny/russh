use ssh_key::{Certificate, HashAlg, PublicKey};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::helpers::AlgorithmExt, ssh_encoding::Decode, ssh_key::Algorithm,
    ssh_key::public::KeyData,
};

use crate::keys::key::PrivateKeyWithHashAlg;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PublicKeyOrCertificate {
    PublicKey {
        key: PublicKey,
        hash_alg: Option<HashAlg>,
    },
    Certificate(Certificate),
}

impl From<&PrivateKeyWithHashAlg> for PublicKeyOrCertificate {
    fn from(key: &PrivateKeyWithHashAlg) -> Self {
        PublicKeyOrCertificate::PublicKey {
            key: key.public_key().clone(),
            hash_alg: key.hash_alg(),
        }
    }
}

impl PublicKeyOrCertificate {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decode(pubkey_algo: &str, buf: &[u8]) -> Result<Self, ssh_key::Error> {
        let mut reader = buf;
        match Algorithm::new_certificate_ext(pubkey_algo) {
            Ok(Algorithm::Other(_)) | Err(ssh_key::Error::Encoding(_)) => {
                // Did not match a known cert algorithm
                Ok(PublicKeyOrCertificate::PublicKey {
                    key: KeyData::decode(&mut reader)?.into(),
                    hash_alg: Algorithm::new(pubkey_algo)?.hash_alg(),
                })
            }
            _ => Ok(PublicKeyOrCertificate::Certificate(Certificate::decode(
                &mut reader,
            )?)),
        }
    }
}
