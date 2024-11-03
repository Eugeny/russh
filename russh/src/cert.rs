use core::str;

use ssh_encoding::Decode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Certificate, HashAlg, PublicKey};

#[derive(Debug)]
pub(crate) enum PublicKeyOrCertificate {
    PublicKey(PublicKey),
    Certificate(Certificate),
}

impl PublicKeyOrCertificate {
    pub fn decode(pubkey_algo: &[u8], buf: &[u8]) -> Result<Self, ssh_key::Error> {
        let mut reader = buf;
        match Algorithm::new_certificate_ext(str::from_utf8(pubkey_algo)?) {
            Ok(Algorithm::Other(_)) | Err(ssh_key::Error::Encoding(_)) => {
                // Did not match a known cert algorithm
                Ok(PublicKeyOrCertificate::PublicKey(
                    KeyData::decode(&mut reader)?.into(),
                ))
            }
            _ => Ok(PublicKeyOrCertificate::Certificate(Certificate::decode(
                &mut reader,
            )?)),
        }
    }
}

trait AlgorithmExt {
    fn new_certificate_ext(algo: &str) -> Result<Self, ssh_key::Error>
    where
        Self: Sized;
}

impl AlgorithmExt for Algorithm {
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
