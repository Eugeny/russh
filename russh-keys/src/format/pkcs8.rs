use std::convert::{TryFrom, TryInto};

use crate::{ec, key, key::SignatureHash, protocol, Error};
use pkcs8::{EncodePrivateKey, PrivateKeyInfo, SecretDocument};

/// Decode a PKCS#8-encoded private key.
pub fn decode_pkcs8(ciphertext: &[u8], password: Option<&[u8]>) -> Result<key::KeyPair, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfo>()?
            .decrypt(password)?
    } else {
        doc
    };
    key::KeyPair::try_from(doc.decode_msg::<PrivateKeyInfo>()?)
}

impl<'a> TryFrom<PrivateKeyInfo<'a>> for key::KeyPair {
    type Error = Error;

    fn try_from(pki: PrivateKeyInfo<'a>) -> Result<Self, Self::Error> {
        match pki.algorithm.oid {
            ed25519_dalek::pkcs8::ALGORITHM_OID => Ok(key::KeyPair::Ed25519(
                ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?
                    .secret_key
                    .into(),
            )),
            pkcs1::ALGORITHM_OID => {
                let sk = &pkcs1::RsaPrivateKey::try_from(pki.private_key)?;
                key::KeyPair::new_rsa_with_hash(
                    &sk.into(),
                    Some(&sk.into()),
                    SignatureHash::SHA2_256,
                )
            }
            sec1::ALGORITHM_OID => Ok(key::KeyPair::EC {
                key: pki.try_into()?,
            }),
            oid => Err(Error::UnknownAlgorithm(oid)),
        }
    }
}

impl<'a> From<&pkcs1::RsaPrivateKey<'a>> for protocol::RsaPrivateKey<'a> {
    fn from(sk: &pkcs1::RsaPrivateKey<'a>) -> Self {
        Self {
            public_key: protocol::RsaPublicKey {
                public_exponent: sk.public_exponent.as_bytes().into(),
                modulus: sk.modulus.as_bytes().into(),
            },
            private_exponent: sk.private_exponent.as_bytes().into(),
            prime1: sk.prime1.as_bytes().into(),
            prime2: sk.prime2.as_bytes().into(),
            coefficient: sk.coefficient.as_bytes().into(),
            comment: b"".as_slice().into(),
        }
    }
}

impl<'a> From<&pkcs1::RsaPrivateKey<'a>> for key::RsaCrtExtra<'a> {
    fn from(sk: &pkcs1::RsaPrivateKey<'a>) -> Self {
        Self {
            dp: sk.exponent1.as_bytes().into(),
            dq: sk.exponent2.as_bytes().into(),
        }
    }
}

// Note: It's infeasible to implement `EncodePrivateKey` because that is bound to `pkcs8::Result`.
impl TryFrom<&key::RsaPrivate> for SecretDocument {
    type Error = Error;

    fn try_from(key: &key::RsaPrivate) -> Result<Self, Self::Error> {
        use der::Encode;
        use pkcs1::UintRef;

        let sk = protocol::RsaPrivateKey::try_from(key)?;
        let extra = key::RsaCrtExtra::try_from(key)?;

        let rsa_private_key = pkcs1::RsaPrivateKey {
            modulus: UintRef::new(&sk.public_key.modulus)?,
            public_exponent: UintRef::new(&sk.public_key.public_exponent)?,
            private_exponent: UintRef::new(&sk.private_exponent)?,
            prime1: UintRef::new(&sk.prime1)?,
            prime2: UintRef::new(&sk.prime2)?,
            exponent1: UintRef::new(&extra.dp)?,
            exponent2: UintRef::new(&extra.dq)?,
            coefficient: UintRef::new(&sk.coefficient)?,
            other_prime_infos: None,
        };
        let pki = PrivateKeyInfo {
            algorithm: spki::AlgorithmIdentifier {
                oid: pkcs1::ALGORITHM_OID,
                parameters: Some(der::asn1::Null.into()),
            },
            private_key: &rsa_private_key.to_der()?,
            public_key: None,
        };
        Ok(Self::try_from(pki)?)
    }
}

impl TryFrom<PrivateKeyInfo<'_>> for ec::PrivateKey {
    type Error = Error;

    fn try_from(pki: PrivateKeyInfo<'_>) -> Result<Self, Self::Error> {
        use pkcs8::AssociatedOid;
        match pki.algorithm.parameters_oid()? {
            p256::NistP256::OID => Ok(ec::PrivateKey::P256(pki.try_into()?)),
            p384::NistP384::OID => Ok(ec::PrivateKey::P384(pki.try_into()?)),
            p521::NistP521::OID => Ok(ec::PrivateKey::P521(pki.try_into()?)),
            oid => Err(Error::UnknownAlgorithm(oid)),
        }
    }
}

impl EncodePrivateKey for ec::PrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        match self {
            ec::PrivateKey::P256(key) => key.to_pkcs8_der(),
            ec::PrivateKey::P384(key) => key.to_pkcs8_der(),
            ec::PrivateKey::P521(key) => key.to_pkcs8_der(),
        }
    }
}

#[test]
fn test_read_write_pkcs8() {
    let secret = ed25519_dalek::SigningKey::generate(&mut key::safe_rng());
    assert_eq!(
        secret.verifying_key().as_bytes(),
        ed25519_dalek::VerifyingKey::from(&secret).as_bytes()
    );
    let key = key::KeyPair::Ed25519(secret);
    let password = b"blabla";
    let ciphertext = encode_pkcs8_encrypted(password, 100, &key).unwrap();
    let key = decode_pkcs8(&ciphertext, Some(password)).unwrap();
    match key {
        key::KeyPair::Ed25519 { .. } => println!("Ed25519"),
        key::KeyPair::EC { .. } => println!("EC"),
        key::KeyPair::RSA { .. } => println!("RSA"),
    }
}

/// Encode a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &key::KeyPair,
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

/// Encode a Decode a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &key::KeyPair) -> Result<Vec<u8>, Error> {
    let v = match *key {
        key::KeyPair::Ed25519(ref pair) => pair.to_pkcs8_der()?,
        key::KeyPair::RSA { ref key, .. } => SecretDocument::try_from(key)?,
        key::KeyPair::EC { ref key, .. } => key.to_pkcs8_der()?,
    }
    .as_bytes()
    .to_vec();
    Ok(v)
}
