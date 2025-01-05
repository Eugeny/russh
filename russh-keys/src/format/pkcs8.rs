use std::convert::{TryFrom, TryInto};

use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, EncodePrivateKey, PrivateKeyInfo, SecretDocument};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::PrivateKey;

use crate::Error;

/// Decode a PKCS#8-encoded private key.
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfo>()?
            .decrypt(password)?
    } else {
        doc
    };
    Ok(pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfo>()?)?.try_into()?)
}

fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfo<'_>) -> Result<KeypairData, Error> {
    match pki.algorithm.oid {
        ed25519_dalek::pkcs8::ALGORITHM_OID => {
            let kpb = ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?;
            let pk = Ed25519PrivateKey::from_bytes(&kpb.secret_key);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        pkcs1::ALGORITHM_OID => {
            let sk = &pkcs1::RsaPrivateKey::try_from(pki.private_key)?;
            let pk = rsa::RsaPrivateKey::from_components(
                rsa::BigUint::from_bytes_be(sk.modulus.as_bytes()),
                rsa::BigUint::from_bytes_be(sk.public_exponent.as_bytes()),
                rsa::BigUint::from_bytes_be(sk.private_exponent.as_bytes()),
                vec![
                    rsa::BigUint::from_bytes_be(sk.prime1.as_bytes()),
                    rsa::BigUint::from_bytes_be(sk.prime2.as_bytes()),
                ],
            )?;
            Ok(KeypairData::Rsa(pk.try_into()?))
        }
        sec1::ALGORITHM_OID => Ok(KeypairData::Ecdsa(
            match pki.algorithm.parameters_oid()? {
                NistP256::OID => {
                    let sk = p256::SecretKey::try_from(pki)?;
                    EcdsaKeypair::NistP256 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
                NistP384::OID => {
                    let sk = p384::SecretKey::try_from(pki)?;
                    EcdsaKeypair::NistP384 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
                NistP521::OID => {
                    let sk = p521::SecretKey::try_from(pki)?;
                    EcdsaKeypair::NistP521 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
                oid => return Err(Error::UnknownAlgorithm(oid)),
            },
        )),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

/// Encode into a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let pvi_bytes = encode_pkcs8(key)?;
    let pvi = PrivateKeyInfo::try_from(pvi_bytes.as_slice())?;

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = [0; 64];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let doc = pvi.encrypt_with_params(
        pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(rounds, &salt, &iv)
            .map_err(|_| Error::InvalidParameters)?,
        pass,
    )?;
    Ok(doc.as_bytes().to_vec())
}

/// Encode into a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &ssh_key::PrivateKey) -> Result<Vec<u8>, Error> {
    let v = match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(ref pair) => {
            let sk: ed25519_dalek::SigningKey = pair.try_into()?;
            sk.to_pkcs8_der()?
        }
        ssh_key::private::KeypairData::Rsa(ref pair) => {
            let sk: rsa::RsaPrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?
        }
        ssh_key::private::KeypairData::Ecdsa(ref pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let sk = p256::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?
            }
        },
        _ => {
            let algo = key.algorithm();
            let kt = algo.as_str();
            return Err(Error::UnsupportedKeyType {
                key_type_string: kt.into(),
                key_type_raw: kt.as_bytes().into(),
            });
        }
    }
    .as_bytes()
    .to_vec();
    Ok(v)
}
