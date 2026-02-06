use der::Encode;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, EncodePrivateKey, SecretDocument};
use rand::Rng;
use spki::ObjectIdentifier;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::PrivateKey;
use std::convert::{TryFrom, TryInto};

use crate::keys::key::safe_rng;
use crate::keys::Error;

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
pub fn decode_pkcs8(ciphertext: &[u8], password: Option<&[u8]>) -> Result<PrivateKey, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        // Decrypt password-protected PKCS#8 (PBES2).
        let enc = doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>()?;
        enc.decrypt(password)?
    } else {
        doc
    };

    match doc.decode_msg::<sec1::EcPrivateKey>() {
        Ok(key) => {
            // X9.62 EC private key
            let curve: ObjectIdentifier = key
                .parameters
                .and_then(|x| x.named_curve())
                .ok_or(Error::CouldNotReadKey)?;
            let kp = ec_key_data_into_keypair(curve, key)?;
            Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?)
        }
        Err(_) => {
            // PKCS#8 PrivateKeyInfo
            let pki = doc.decode_msg::<pkcs8::PrivateKeyInfoRef<'_>>()?;
            Ok(pkcs8_pki_into_keypair_data(pki)?.try_into()?)
        }
    }
}

fn pkcs8_pki_into_keypair_data(pki: pkcs8::PrivateKeyInfoRef<'_>) -> Result<KeypairData, Error> {
    // Temporary if {} due to multiple const_oid crate versions
    #[cfg(feature = "rsa")]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        // pkcs1 0.8 rc decodes the inner PKCS#1 key from the PKCS#8 octet string.
        let sk = pkcs1::RsaPrivateKey::try_from(pki.private_key.as_bytes())?;
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
            // RFC8410: PrivateKeyInfo.privateKey is OCTET STRING containing the DER encoding of
            // an *inner* OCTET STRING which holds the 32-byte seed.
            let outer = pki.private_key.as_bytes();

            let secret_bytes: Option<[u8; 32]> = (|| {
                let inner: &der::asn1::OctetStringRef = der::Decode::from_der(outer).ok()?;
                let inner_bytes: [u8; 32] = inner.as_bytes().try_into().ok()?;
                Some(inner_bytes)
            })();

            // Backward-compatible fallback: some encoders put the 32 bytes directly in the outer
            // octets (non-RFC). If inner decoding fails, try interpreting outer bytes directly.
            let secret = if let Some(secret) = secret_bytes {
                secret
            } else {
                let direct: [u8; 32] = outer.try_into().map_err(|_| Error::CouldNotReadKey)?;
                direct
            };

            let pk = Ed25519PrivateKey::from_bytes(&secret);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        sec1::ALGORITHM_OID => {
            let curve = pki.algorithm.parameters_oid()?;
            Ok(KeypairData::Ecdsa(ec_key_data_into_keypair(curve, pki)?))
        }
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
    let pvi = pkcs8::PrivateKeyInfoRef::try_from(pvi_bytes.as_slice())?;

    let mut rng = safe_rng();
    let mut salt = [0; 64];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let doc = pvi.encrypt_with_params(
        // Current pkcs5 API expects the IV by value.
        pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(rounds, &salt, iv)
            .map_err(|_| Error::InvalidParameters)?,
        pass,
    )?;
    Ok(doc.as_bytes().to_vec())
}

/// Encode into a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &PrivateKey) -> Result<Vec<u8>, Error> {
    let v = match key.key_data() {
        KeypairData::Ed25519(pair) => {
            // Manually build PKCS#8 PrivateKeyInfo for Ed25519 (RFC 8410).
            // Per RFC8410, PrivateKeyInfo.privateKey is an OCTET STRING which contains an
            // *inner* OCTET STRING holding the 32-byte seed.
            let seed: [u8; 32] = ed25519_dalek::SigningKey::try_from(&pair.private)
                .map_err(|_| Error::CouldNotReadKey)?
                .to_bytes();

            let inner =
                der::asn1::OctetStringRef::new(&seed).map_err(|_| Error::CouldNotReadKey)?;
            let inner_der = inner.to_der().map_err(|_| Error::CouldNotReadKey)?;

            let pki = pkcs8::PrivateKeyInfoRef {
                algorithm: pkcs8::AlgorithmIdentifierRef {
                    oid: ed25519_dalek::pkcs8::ALGORITHM_OID,
                    parameters: None,
                },
                private_key: der::asn1::OctetStringRef::new(&inner_der)
                    .map_err(|_| Error::CouldNotReadKey)?,
                // We always include the public key in OpenSSH encodings, but RFC8410 test vectors
                // include both variants. Leave public_key unset here.
                public_key: None,
            };

            let doc: SecretDocument = pki.try_into().map_err(|_| Error::CouldNotReadKey)?;

            doc.as_bytes().to_vec()
        }
        #[cfg(feature = "rsa")]
        KeypairData::Rsa(pair) => {
            use rsa::pkcs8::EncodePrivateKey;
            let sk: rsa::RsaPrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        KeypairData::Ecdsa(pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let bytes: [u8; 32] = private
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CouldNotReadKey)?;
                let sk = p256::SecretKey::from_bytes(&bytes.into())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let bytes: [u8; 48] = private
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CouldNotReadKey)?;
                let sk = p384::SecretKey::from_bytes(&bytes.into())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let bytes: [u8; 66] = private
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CouldNotReadKey)?;
                let sk = p521::SecretKey::from_bytes(&bytes.into())?;
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
