use std::convert::{TryFrom, TryInto};

use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AssociatedOid, EncodePrivateKey, PrivateKeyInfoRef, SecretDocument};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData};

use crate::keys::Error;
use crate::keys::key::safe_rng;

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    let doc = SecretDocument::try_from(ciphertext)?;
    let doc = if let Some(password) = password {
        doc.decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>()?
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
            // SEC1 key with full domain parameters (not a named curve OID)
            match decode_sec1_with_full_domain_params(ciphertext) {
                Ok(kp) => return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?),
                Err(_) => {},
            }
            // ASN.1 key (PKCS#8)
            Ok(
                pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfoRef<'_>>()?)?
                    .try_into()?,
            )
        }
    }
}

fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfoRef<'_>) -> Result<KeypairData, Error> {
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

/// Try to manually parse an SEC1 EC key with full domain parameters.
///
/// Some key generators (e.g. OpenSSL with certain options) produce SEC1 keys
/// where the `[0]` parameters field contains full EC domain parameters instead
/// of a named curve OID. The `sec1` crate does not support this format.
/// This function manually parses the DER to extract the curve and private key.
fn decode_sec1_with_full_domain_params(der: &[u8]) -> Result<EcdsaKeypair, Error> {
    if der.is_empty() || der[0] != 0x30 {
        return Err(Error::CouldNotReadKey);
    }
    let (header_size, _) = read_der_len(&der[1..], der.len() - 1)?;
    let mut pos = 1 + header_size;

    if pos >= der.len() || der[pos] != 0x02 {
        return Err(Error::CouldNotReadKey);
    }
    let (ver, new_pos) = read_der_value(der, pos)?;
    pos = new_pos;
    // SEC1 version must be 1 (ecPrivkeyVer1)
    if ver.len() != 1 || ver[0] < 1 {
        return Err(Error::CouldNotReadKey);
    }

    if pos >= der.len() || der[pos] != 0x04 {
        return Err(Error::CouldNotReadKey);
    }
    let (priv_key, new_pos) = read_der_value(der, pos)?;
    pos = new_pos;

    if pos >= der.len() || der[pos] != 0xa0 {
        return Err(Error::CouldNotReadKey);
    }
    let (params_content, _) = read_der_value(der, pos)?;

    if params_content.is_empty() || params_content[0] != 0x30 {
        return Err(Error::CouldNotReadKey);
    }

    let curve_oid = extract_curve_from_domain_params(params_content)?;
    build_ec_keypair_from_bytes(curve_oid, priv_key)
}

/// Read a DER TLV (tag-length-value) from `der` starting at `pos`.
/// Returns (value_bytes, next_position_after_this_tlv).
fn read_der_value(der: &[u8], pos: usize) -> Result<(&[u8], usize), Error> {
    if pos >= der.len() {
        return Err(Error::CouldNotReadKey);
    }
    // read_der_len reads from the LENGTH field (pos + 1, after the tag byte).
    // It returns (length_field_size, length_field_size + content_length).
    // So total_size = header_size + content_size (relative to length field start).
    let (length_field_size, total_from_len_field) = read_der_len(&der[pos + 1..], der.len() - pos - 1)?;
    let header_size = 1 + length_field_size; // tag byte + length field bytes
    let value_start = pos + header_size;
    let value_end = pos + 1 + total_from_len_field; // 1 for tag + total_from_len_field
    if value_end > der.len() || value_start > value_end {
        return Err(Error::CouldNotReadKey);
    }
    Ok((&der[value_start..value_end], value_end))
}

/// Read a DER length field from `buf` (which starts at the length byte, after the tag).
///
/// Returns `(length_field_size, length_field_size + content_length)`:
/// - `length_field_size`: number of bytes used to encode the length itself (1 for short form, 1+N for long form)
/// - `length_field_size + content_length`: total bytes consumed (length field + content)
///
/// `max` is the number of available bytes in `buf` (used for bounds checking).
fn read_der_len(buf: &[u8], max: usize) -> Result<(usize, usize), Error> {
    if buf.is_empty() {
        return Err(Error::CouldNotReadKey);
    }
    let first = buf[0];
    if first & 0x80 == 0 {
        let len = first as usize;
        if 1 + len > max {
            return Err(Error::CouldNotReadKey);
        }
        Ok((1, 1 + len))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || 1 + num_bytes > max {
            return Err(Error::CouldNotReadKey);
        }
        let mut len = 0usize;
        for &b in &buf[1..1 + num_bytes] {
            len = (len << 8) | b as usize;
        }
        if 1 + num_bytes + len > max {
            return Err(Error::CouldNotReadKey);
        }
        Ok((1 + num_bytes, 1 + num_bytes + len))
    }
}

/// Extract the named curve OID from full EC domain parameters.
/// Handles two formats:
/// 1. Standard ECParameters: SEQUENCE { FieldID, Curve, base, order, cofactor }
/// 2. Wrapped ECParameters: SEQUENCE { INTEGER version, SEQUENCE { FieldID, ... } }
fn extract_curve_from_domain_params(params_der: &[u8]) -> Result<ObjectIdentifier, Error> {
    if params_der.is_empty() || params_der[0] != 0x30 {
        return Err(Error::CouldNotReadKey);
    }
    let (header_size, _) = read_der_len(&params_der[1..], params_der.len() - 1)?;
    let mut pos = 1 + header_size; // skip SEQUENCE tag + length bytes

    if pos >= params_der.len() {
        return Err(Error::CouldNotReadKey);
    }

    // If the first element is an INTEGER (version), skip it to reach FieldID SEQUENCE
    if params_der[pos] == 0x02 {
        let (_, skip_pos) = read_der_value(params_der, pos)?;
        pos = skip_pos;
    }

    // Now pos should point to the FieldID SEQUENCE
    if pos >= params_der.len() || params_der[pos] != 0x30 {
        return Err(Error::CouldNotReadKey);
    }
    let (field_id_content, _new_pos) = read_der_value(params_der, pos)?;

    // Parse FieldID: first element is OID (prime-field = 1.2.840.10045.1.1)
    if field_id_content.is_empty() || field_id_content[0] != 0x06 {
        return Err(Error::CouldNotReadKey);
    }
    // OID 1.2.840.10045.1.1 (prime-field from ANSI X9.62):
    //   DER tag 0x06, length 0x07, then 7 bytes of OID content
    //   2a = 1.2, 86 48 = 840, ce 3d = 10045, 01 = 1, 01 = 1
    // This is a stable ASN.1 standard OID that will not change.
    let prime_field_der: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
    let oid_len = field_id_content[1] as usize;
    let oid_end = 2 + oid_len;
    if oid_end > field_id_content.len() || &field_id_content[..oid_end] != prime_field_der {
        return Err(Error::CouldNotReadKey);
    }
    let prime_pos = oid_end;

    if prime_pos >= field_id_content.len() || field_id_content[prime_pos] != 0x02 {
        return Err(Error::CouldNotReadKey);
    }
    let (prime_bytes, _) = read_der_value(field_id_content, prime_pos)?;

    // Determine curve from prime byte length.
    // DER INTEGERs are signed, so when the high bit of the first content byte is set,
    // a leading 0x00 pad byte is added to keep the value positive. For example, the
    // P-256 prime (a 256-bit value with high bit set) encodes as 33 bytes: 0x00 || 32-byte-prime.
    // We match both padded (33/49/67) and unpadded (32/48/66) lengths.
    let prime_len = prime_bytes.len();
    Ok(match prime_len {
        32 | 33 => NistP256::OID,  // P-256: secp256r1 prime is 32 bytes
        48 | 49 => NistP384::OID,  // P-384: secp384r1 prime is 48 bytes
        66 | 67 => NistP521::OID,  // P-521: secp521r1 prime is 66 bytes
        _ => return Err(Error::CouldNotReadKey),
    })
}

/// Build an EcdsaKeypair from raw private key bytes and a curve OID.
fn build_ec_keypair_from_bytes(
    curve_oid: ObjectIdentifier,
    private_key_bytes: &[u8],
) -> Result<EcdsaKeypair, Error> {
    if curve_oid == NistP256::OID {
        let sk = p256::SecretKey::from_slice(private_key_bytes)
            .map_err(|_| Error::CouldNotReadKey)?;
        Ok(EcdsaKeypair::NistP256 {
            public: sk.public_key().into(),
            private: sk.into(),
        })
    } else if curve_oid == NistP384::OID {
        let sk = p384::SecretKey::from_slice(private_key_bytes)
            .map_err(|_| Error::CouldNotReadKey)?;
        Ok(EcdsaKeypair::NistP384 {
            public: sk.public_key().into(),
            private: sk.into(),
        })
    } else if curve_oid == NistP521::OID {
        let sk = p521::SecretKey::from_slice(private_key_bytes)
            .map_err(|_| Error::CouldNotReadKey)?;
        Ok(EcdsaKeypair::NistP521 {
            public: sk.public_key().into(),
            private: sk.into(),
        })
    } else {
        Err(Error::UnknownAlgorithm(curve_oid))
    }
}

/// Encode into a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let pvi_bytes = encode_pkcs8(key)?;
    let pvi = PrivateKeyInfoRef::try_from(pvi_bytes.as_slice())?;

    use rand_core::Rng;
    let mut rng = safe_rng();
    let mut salt = [0; 32];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let doc = pvi.encrypt_with_params(
        pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(rounds, &salt, iv)
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
                let sk = p256::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_slice(private.as_slice())?;
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
