use std::convert::TryFrom;

use crate::{
    ec,
    key::{KeyPair, PublicKey, SignatureHash},
    protocol, Error,
};

use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, PrivateKey, RsaKeypair, RsaPrivateKey},
    public::{Ed25519PublicKey, KeyData, RsaPublicKey},
    Algorithm, HashAlg,
};

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<KeyPair, Error> {
    let pk = PrivateKey::from_bytes(secret)?;
    KeyPair::try_from(&match password {
        Some(password) => pk.decrypt(password)?,
        None => pk,
    })
}

impl TryFrom<&PrivateKey> for KeyPair {
    type Error = Error;

    fn try_from(pk: &PrivateKey) -> Result<Self, Self::Error> {
        match pk.key_data() {
            KeypairData::Ed25519(Ed25519Keypair { public, private }) => {
                let key = ed25519_dalek::SigningKey::from(private.as_ref());
                let public_key = ed25519_dalek::VerifyingKey::from_bytes(public.as_ref())?;
                if public_key != key.verifying_key() {
                    return Err(Error::KeyIsCorrupt);
                }
                Ok(KeyPair::Ed25519(key))
            }
            KeypairData::Rsa(keypair) => {
                KeyPair::new_rsa_with_hash(&keypair.into(), None, SignatureHash::SHA2_512)
            }
            KeypairData::Ecdsa(keypair) => {
                let key_type = match keypair {
                    EcdsaKeypair::NistP256 { .. } => crate::KEYTYPE_ECDSA_SHA2_NISTP256,
                    EcdsaKeypair::NistP384 { .. } => crate::KEYTYPE_ECDSA_SHA2_NISTP384,
                    EcdsaKeypair::NistP521 { .. } => crate::KEYTYPE_ECDSA_SHA2_NISTP521,
                };
                let key =
                    ec::PrivateKey::new_from_secret_scalar(key_type, keypair.private_key_bytes())?;
                let public_key =
                    ec::PublicKey::from_sec1_bytes(key_type, keypair.public_key_bytes())?;
                if public_key != key.to_public_key() {
                    return Err(Error::KeyIsCorrupt);
                }
                Ok(KeyPair::EC { key })
            }
            KeypairData::Encrypted(_) => Err(Error::KeyIsEncrypted),
            _ => Err(Error::UnsupportedKeyType {
                key_type_string: pk.algorithm().as_str().into(),
                key_type_raw: pk.algorithm().as_str().as_bytes().into(),
            }),
        }
    }
}

impl<'a> From<&'a RsaKeypair> for protocol::RsaPrivateKey<'a> {
    fn from(key: &'a RsaKeypair) -> Self {
        let RsaPublicKey { e, n } = &key.public;
        let RsaPrivateKey { d, iqmp, p, q } = &key.private;
        Self {
            public_key: protocol::RsaPublicKey {
                public_exponent: e.as_bytes().into(),
                modulus: n.as_bytes().into(),
            },
            private_exponent: d.as_bytes().into(),
            prime1: p.as_bytes().into(),
            prime2: q.as_bytes().into(),
            coefficient: iqmp.as_bytes().into(),
            comment: b"".as_slice().into(),
        }
    }
}

impl TryFrom<&KeyData> for PublicKey {
    type Error = Error;

    fn try_from(key_data: &KeyData) -> Result<Self, Self::Error> {
        match key_data {
            KeyData::Ed25519(Ed25519PublicKey(public)) => Ok(PublicKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(public)?,
            )),
            KeyData::Rsa(ref public) => PublicKey::new_rsa_with_hash(
                &public.into(),
                match key_data.algorithm() {
                    Algorithm::Rsa { hash } => match hash {
                        Some(HashAlg::Sha256) => SignatureHash::SHA2_256,
                        Some(HashAlg::Sha512) => SignatureHash::SHA2_512,
                        _ => SignatureHash::SHA1,
                    },
                    _ => return Err(Error::KeyIsCorrupt),
                },
            ),
            KeyData::Ecdsa(public) => Ok(PublicKey::EC {
                key: ec::PublicKey::from_sec1_bytes(
                    key_data.algorithm().as_str().as_bytes(),
                    public.as_sec1_bytes(),
                )?,
            }),
            _ => Err(Error::UnsupportedKeyType {
                key_type_string: key_data.algorithm().as_str().into(),
                key_type_raw: key_data.algorithm().as_str().as_bytes().into(),
            }),
        }
    }
}

impl<'a> From<&'a RsaPublicKey> for protocol::RsaPublicKey<'a> {
    fn from(key: &'a RsaPublicKey) -> Self {
        let RsaPublicKey { e, n } = key;
        Self {
            public_exponent: e.as_bytes().into(),
            modulus: n.as_bytes().into(),
        }
    }
}
