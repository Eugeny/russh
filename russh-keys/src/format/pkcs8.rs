use std::borrow::Cow;
use std::convert::TryFrom;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use bit_vec::BitVec;
use block_padding::{NoPadding, Pkcs7};
#[cfg(test)]
use rand_core::OsRng;
use yasna::BERReaderSeq;
use {std, yasna};

use super::Encryption;
use crate::key::SignatureHash;
use crate::{key, protocol, Error};

const PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const AES256CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const ED25519: &[u64] = &[1, 3, 101, 112];
const RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
const SECP521R1: &[u64] = &[1, 3, 132, 0, 35];

/// Decode a PKCS#8-encoded private key.
pub fn decode_pkcs8(ciphertext: &[u8], password: Option<&[u8]>) -> Result<key::KeyPair, Error> {
    let secret = if let Some(pass) = password {
        Cow::Owned(yasna::parse_der(ciphertext, |reader| {
            reader.read_sequence(|reader| {
                // Encryption parameters
                let parameters = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    if oid.components().as_slice() == PBES2 {
                        asn1_read_pbes2(reader)
                    } else {
                        Ok(Err(Error::UnknownAlgorithm(oid)))
                    }
                })?;
                // Ciphertext
                let ciphertext = reader.next().read_bytes()?;
                Ok(parameters.map(|p| p.decrypt(pass, &ciphertext)))
            })
        })???)
    } else {
        Cow::Borrowed(ciphertext)
    };
    yasna::parse_der(&secret, |reader| {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u64()?;
            if version == 0 {
                Ok(read_key_v0(reader))
            } else if version == 1 {
                Ok(read_key_v1(reader))
            } else {
                Ok(Err(Error::CouldNotReadKey))
            }
        })
    })?
}

fn asn1_read_pbes2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Algorithms, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        // PBES2 has two components.
        // 1. Key generation algorithm
        let keygen = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == PBKDF2 {
                asn1_read_pbkdf2(reader)
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        // 2. Encryption algorithm.
        let algorithm = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == AES256CBC {
                asn1_read_aes256cbc(reader)
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        Ok(keygen.and_then(|keygen| algorithm.map(|algo| Algorithms::Pbes2(keygen, algo))))
    })
}

fn asn1_read_pbkdf2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<KeyDerivation, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        let salt = reader.next().read_bytes()?;
        let rounds = reader.next().read_u64()?;
        let digest = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == HMAC_SHA256 {
                reader.next().read_null()?;
                Ok(Ok(()))
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        Ok(digest.map(|()| KeyDerivation::Pbkdf2 { salt, rounds }))
    })
}

fn asn1_read_aes256cbc(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Encryption, Error>, yasna::ASN1Error> {
    let iv = reader.next().read_bytes()?;
    let mut i = [0; 16];
    i.clone_from_slice(&iv);
    Ok(Ok(Encryption::Aes256Cbc(i)))
}

fn write_key_v1(writer: &mut yasna::DERWriterSeq, secret: &ed25519_dalek::SigningKey) {
    let public = ed25519_dalek::VerifyingKey::from(secret);
    writer.next().write_u32(1);
    // write OID
    writer.next().write_sequence(|writer| {
        writer
            .next()
            .write_oid(&ObjectIdentifier::from_slice(ED25519));
    });
    let seed = yasna::construct_der(|writer| writer.write_bytes(secret.to_bytes().as_slice()));
    writer.next().write_bytes(&seed);
    writer
        .next()
        .write_tagged_implicit(yasna::Tag::context(1), |writer| {
            writer.write_bitvec(&BitVec::from_bytes(public.as_bytes()))
        })
}

fn read_key_v1(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader
        .next()
        .read_sequence(|reader| reader.next().read_oid())?;
    if oid.components().as_slice() == ED25519 {
        let key = parse_ed25519_private_key(&reader.next().read_bytes()?)?;
        let _attributes = reader.read_optional(|reader| {
            reader.read_tagged_implicit(yasna::Tag::context(0), |reader| reader.read_der())
        })?;
        let _public_key = reader.read_optional(|reader| {
            reader.read_tagged_implicit(yasna::Tag::context(1), |reader| reader.read_bitvec())
        })?;
        Ok(key)
    } else {
        Err(Error::CouldNotReadKey)
    }
}

fn parse_ed25519_private_key(der: &[u8]) -> Result<key::KeyPair, Error> {
    use ed25519_dalek::SigningKey;
    let secret_bytes = yasna::parse_der(der, |reader| reader.read_bytes())?;
    let secret_key = SigningKey::from(
        <&[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::try_from(secret_bytes.as_slice())
            .map_err(|_| Error::CouldNotReadKey)?,
    );
    Ok(key::KeyPair::Ed25519(secret_key))
}

fn write_key_v0_rsa(writer: &mut yasna::DERWriterSeq, key: &key::RsaPrivate) {
    writer.next().write_u32(0);
    // write OID
    writer.next().write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(RSA));
        writer.next().write_null()
    });
    #[allow(clippy::unwrap_used)] // key is known to be private
    let (sk, extra) = (
        protocol::RsaPrivateKey::try_from(key).unwrap(),
        key::RsaCrtExtra::try_from(key).unwrap(),
    );
    let bytes = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(0);
            use num_bigint::BigUint;
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.public_key.modulus));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.public_key.public_exponent));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.private_exponent));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.prime1));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.prime2));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&extra.dp));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&extra.dq));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&sk.coefficient));
        })
    });
    writer.next().write_bytes(&bytes);
}

fn write_key_v0_ec(writer: &mut yasna::DERWriterSeq, key: &crate::ec::PrivateKey) {
    writer.next().write_u32(0);
    writer.next().write_sequence(|writer| {
        writer
            .next()
            .write_oid(&ObjectIdentifier::from_slice(EC_PUBLIC_KEY));
        writer
            .next()
            .write_oid(&ObjectIdentifier::from_slice(match key {
                crate::ec::PrivateKey::P256(_) => SECP256R1,
                crate::ec::PrivateKey::P384(_) => SECP384R1,
                crate::ec::PrivateKey::P521(_) => SECP521R1,
            }))
    });
    let bytes = yasna::construct_der(|writer| {
        #[allow(clippy::unwrap_used)] // key is known to be private
        writer.write_sequence(|writer| {
            writer.next().write_u32(1);
            writer.next().write_bytes(&key.to_secret_bytes());
            writer
                .next()
                .write_tagged(yasna::Tag::context(1), |writer| {
                    writer.write_bitvec(&BitVec::from_bytes(&key.to_public_key().to_sec1_bytes()))
                });
        })
    });
    writer.next().write_bytes(&bytes);
}

// Utility enum used for reading v0 key.
enum KeyType {
    Unknown(ObjectIdentifier),
    #[allow(clippy::upper_case_acronyms)]
    ED25519,
    #[allow(clippy::upper_case_acronyms)]
    RSA,
    EC(ObjectIdentifier),
}

fn read_key_v0(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let key_type = reader.next().read_sequence(|reader| {
        let oid = reader.next().read_oid()?;
        Ok(match oid.components().as_slice() {
            ED25519 => KeyType::ED25519,
            RSA => {
                reader.next().read_null()?;
                KeyType::RSA
            }
            EC_PUBLIC_KEY => KeyType::EC(reader.next().read_oid()?),
            _ => KeyType::Unknown(oid),
        })
    })?;
    match key_type {
        KeyType::Unknown(_) => Err(Error::CouldNotReadKey),
        KeyType::ED25519 => parse_ed25519_private_key(&reader.next().read_bytes()?),
        KeyType::RSA => {
            let seq = &reader.next().read_bytes()?;
            let (sk, extra) = yasna::parse_der(seq, |reader| {
                reader.read_sequence(|reader| {
                    let version = reader.next().read_u32()?;
                    if version != 0 {
                        return Ok(Err(Error::CouldNotReadKey));
                    }
                    let (n, e, d, p, q, dmp1, dmq1, iqmp) = (
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                        reader.next().read_biguint()?.to_bytes_be(),
                    );
                    Ok(Ok((
                        protocol::RsaPrivateKey {
                            public_key: protocol::RsaPublicKey {
                                modulus: n.into(),
                                public_exponent: e.into(),
                            },
                            private_exponent: d.into(),
                            prime1: p.into(),
                            prime2: q.into(),
                            coefficient: iqmp.into(),
                            comment: Cow::Borrowed(b""),
                        },
                        key::RsaCrtExtra {
                            dp: dmp1.into(),
                            dq: dmq1.into(),
                        },
                    )))
                })
            })??;
            Ok(key::KeyPair::new_rsa_with_hash(
                &sk,
                Some(&extra),
                SignatureHash::SHA2_256,
            )?)
        }
        KeyType::EC(oid) => {
            let private_key = reader.next().read_bytes()?;
            let (version, secret_key, public_key) = yasna::parse_der(&private_key, |reader| {
                reader.read_sequence(|reader| {
                    // Per RFC 5915, section 3:
                    // ECPrivateKey ::= SEQUENCE {
                    //   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                    //   privateKey     OCTET STRING,
                    //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                    //   publicKey  [1] BIT STRING OPTIONAL
                    // }
                    let version = reader.next().read_u64()?;
                    let secret_key = reader.next().read_bytes()?;
                    let _named_curve = reader.read_optional(|reader| {
                        reader.read_tagged(yasna::Tag::context(0), |reader| reader.read_oid())
                    })?;
                    let public_key = reader.read_optional(|reader| {
                        reader.read_tagged(yasna::Tag::context(1), |reader| reader.read_bitvec())
                    })?;
                    Ok((version, secret_key, public_key))
                })
            })?;
            if version != 1 {
                return Err(Error::CouldNotReadKey);
            }
            let key = crate::ec::PrivateKey::new_from_secret_scalar(
                match oid.components().as_slice() {
                    SECP256R1 => crate::KEYTYPE_ECDSA_SHA2_NISTP256,
                    SECP384R1 => crate::KEYTYPE_ECDSA_SHA2_NISTP384,
                    SECP521R1 => crate::KEYTYPE_ECDSA_SHA2_NISTP521,
                    _ => return Err(Error::CouldNotReadKey),
                },
                &secret_key,
            )?;
            if let Some(public_key) = public_key {
                if key.to_public_key().to_sec1_bytes() != public_key.to_bytes() {
                    return Err(Error::CouldNotReadKey);
                }
            }
            Ok(key::KeyPair::EC { key })
        }
    }
}

#[test]
fn test_read_write_pkcs8() {
    let secret = ed25519_dalek::SigningKey::generate(&mut OsRng {});
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

use aes::*;
use yasna::models::ObjectIdentifier;

/// Encode a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &key::KeyPair,
) -> Result<Vec<u8>, Error> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = [0; 64];
    rng.fill_bytes(&mut salt);
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);
    let mut dkey = [0; 32]; // AES256-CBC
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, &salt, rounds, &mut dkey);
    let mut plaintext = encode_pkcs8(key);

    let padding_len = 32 - (plaintext.len() % 32);
    plaintext.extend(std::iter::repeat(padding_len as u8).take(padding_len));

    #[allow(clippy::unwrap_used)] // parameters are static
    let c = cbc::Encryptor::<Aes256>::new_from_slices(&dkey, &iv).unwrap();
    let n = plaintext.len();
    let encrypted = c.encrypt_padded_mut::<NoPadding>(&mut plaintext, n)?;

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // Encryption parameters
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(PBES2));
                asn1_write_pbes2(writer.next(), rounds as u64, &salt, &iv)
            });
            // Ciphertext
            writer.next().write_bytes(encrypted)
        })
    }))
}

/// Encode a Decode a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &key::KeyPair) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| match *key {
            key::KeyPair::Ed25519(ref pair) => write_key_v1(writer, pair),
            key::KeyPair::RSA { ref key, .. } => write_key_v0_rsa(writer, key),
            key::KeyPair::EC { ref key, .. } => write_key_v0_ec(writer, key),
        })
    })
}

fn asn1_write_pbes2(writer: yasna::DERWriter, rounds: u64, salt: &[u8], iv: &[u8]) {
    writer.write_sequence(|writer| {
        // 1. Key generation algorithm
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(PBKDF2));
            asn1_write_pbkdf2(writer.next(), rounds, salt)
        });
        // 2. Encryption algorithm.
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(AES256CBC));
            writer.next().write_bytes(iv)
        });
    })
}

fn asn1_write_pbkdf2(writer: yasna::DERWriter, rounds: u64, salt: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_bytes(salt);
        writer.next().write_u64(rounds);
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(HMAC_SHA256));
            writer.next().write_null()
        })
    })
}

enum Algorithms {
    Pbes2(KeyDerivation, Encryption),
}

impl Algorithms {
    fn decrypt(&self, password: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithms::Pbes2(ref der, ref enc) => {
                let mut key = enc.key();
                der.derive(password, &mut key)?;
                let out = enc.decrypt(&key, cipher)?;
                Ok(out)
            }
        }
    }
}

impl KeyDerivation {
    fn derive(&self, password: &[u8], key: &mut [u8]) -> Result<(), Error> {
        match *self {
            KeyDerivation::Pbkdf2 { ref salt, rounds } => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, rounds as u32, key)
                // pbkdf2_hmac(password, salt, rounds as usize, digest, key)?
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
enum Key {
    K128([u8; 16]),
    K256([u8; 32]),
}

impl std::ops::Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            Key::K128(ref k) => k,
            Key::K256(ref k) => k,
        }
    }
}

impl std::ops::DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        match *self {
            Key::K128(ref mut k) => k,
            Key::K256(ref mut k) => k,
        }
    }
}

impl Encryption {
    fn key(&self) -> Key {
        match *self {
            Encryption::Aes128Cbc(_) => Key::K128([0; 16]),
            Encryption::Aes256Cbc(_) => Key::K256([0; 32]),
        }
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Encryption::Aes128Cbc(ref iv) => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let c = cbc::Decryptor::<Aes128>::new_from_slices(key, iv).unwrap();
                let mut dec = ciphertext.to_vec();
                Ok(c.decrypt_padded_mut::<Pkcs7>(&mut dec)?.into())
            }
            Encryption::Aes256Cbc(ref iv) => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let c = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).unwrap();
                let mut dec = ciphertext.to_vec();
                Ok(c.decrypt_padded_mut::<Pkcs7>(&mut dec)?.into())
            }
        }
    }
}

enum KeyDerivation {
    Pbkdf2 { salt: Vec<u8>, rounds: u64 },
}
