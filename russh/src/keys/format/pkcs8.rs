use std::convert::{TryFrom, TryInto};

use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, EncodePrivateKey, PrivateKeyInfo, SecretDocument};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData};

use crate::keys::Error;

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
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

    match doc.decode_msg::<sec1::EcPrivateKey>() {
        Ok(key) => {
            // X9.62 EC private key
            let Some(curve) = key.parameters.and_then(|x| x.named_curve()) else {
                return Err(Error::CouldNotReadKey);
            };
            let kp = ec_key_data_into_keypair(curve, key)?;
            Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?)
        }
        Err(_) => {
            // ASN.1 key
            Ok(pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfo>()?)?.try_into()?)
        }
    }
}

fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfo<'_>) -> Result<KeypairData, Error> {
    // Temporary if {} due to multiple const_oid crate versions
    #[cfg(feature = "rsa")]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        let sk = &pkcs1::RsaPrivateKey::try_from(pki.private_key)?;
        let pk = rsa::RsaPrivateKey::from_components(
            rsa::BoxedUint::from_be_slice_vartime(sk.modulus.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.public_exponent.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.private_exponent.as_bytes()),
            vec![
                rsa::BoxedUint::from_be_slice_vartime(sk.prime1.as_bytes()),
                rsa::BoxedUint::from_be_slice_vartime(sk.prime2.as_bytes()),
            ],
        )?;
        return Ok(KeypairData::Rsa(pk.try_into()?));
    }
    match pki.algorithm.oid {
        ed25519_dalek::pkcs8::ALGORITHM_OID => {
            let kpb = ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?;
            let pk = Ed25519PrivateKey::from_bytes(&kpb.secret_key);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        sec1::ALGORITHM_OID => Ok(KeypairData::Ecdsa(ec_key_data_into_keypair(
            pki.algorithm.parameters_oid()?,
            pki,
        )?)),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

fn ec_key_data_into_keypair<K, E>(
    curve_oid: ObjectIdentifier,
    private_key: K,
) -> Result<EcdsaKeypair, Error>
where
    p256::SecretKey: TryFrom<K, Error = E>,
    p384::SecretKey: TryFrom<K, Error = E>,
    p521::SecretKey: TryFrom<K, Error = E>,
    crate::keys::Error: From<E>,
{
    Ok(match curve_oid {
        NistP256::OID => {
            let sk = p256::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP384::OID => {
            let sk = p384::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP521::OID => {
            let sk = p521::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        oid => return Err(Error::UnknownAlgorithm(oid)),
    })
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
        ssh_key::private::KeypairData::Ed25519(pair) => {
            let sk: ed25519_dalek::SigningKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        #[cfg(feature = "rsa")]
        ssh_key::private::KeypairData::Rsa(pair) => {
            use rsa::pkcs8::EncodePrivateKey;
            let sk: rsa::RsaPrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        ssh_key::private::KeypairData::Ecdsa(pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let sk = p256::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_bytes(private.as_slice().into())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
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
    };
    Ok(v)
}
