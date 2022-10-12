#[cfg(feature = "rs-crypto")]
use bit_vec::BitVec;
#[cfg(feature = "openssl")]
use openssl::pkey::Private;
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
use std::borrow::Cow;
use yasna::BERReaderSeq;
use {std, yasna};

use super::Encryption;
#[cfg(feature = "openssl")]
use crate::key::SignatureHash;
use crate::{key, Error};

const PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const AES256CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const ED25519: &[u64] = &[1, 3, 101, 112];
#[cfg(feature = "openssl")]
const RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

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

#[cfg(feature = "rs-crypto")]
fn write_key_v1(writer: &mut yasna::DERWriterSeq, secret: &ed25519_dalek::SecretKey) {
    let public = ed25519_dalek::PublicKey::from(secret);
    writer.next().write_u32(1);
    // write OID
    writer.next().write_sequence(|writer| {
        writer
            .next()
            .write_oid(&ObjectIdentifier::from_slice(ED25519));
    });
    let seed = yasna::construct_der(|writer| {
        writer.write_bytes(
            [secret.as_bytes().as_slice(), public.as_bytes().as_slice()]
                .concat()
                .as_slice(),
        )
    });
    writer.next().write_bytes(&seed);
    writer
        .next()
        .write_tagged(yasna::Tag::context(1), |writer| {
            writer.write_bitvec(&BitVec::from_bytes(public.as_bytes()))
        })
}

fn read_key_v1(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader
        .next()
        .read_sequence(|reader| reader.next().read_oid())?;
    if oid.components().as_slice() == ED25519 && cfg!(feature = "rs-crypto") {
        #[cfg(feature = "rs-crypto")]
        {
            use ed25519_dalek::{Keypair, PublicKey, SecretKey};
            let secret = {
                let s =
                    yasna::parse_der(&reader.next().read_bytes()?, |reader| reader.read_bytes())?;

                s.get(..ed25519_dalek::SECRET_KEY_LENGTH)
                    .ok_or(Error::KeyIsCorrupt)
                    .and_then(|s| SecretKey::from_bytes(s).map_err(|_| Error::CouldNotReadKey))?
            };
            let public = {
                let public = reader
                    .next()
                    .read_tagged(yasna::Tag::context(1), |reader| reader.read_bitvec())?
                    .to_bytes();
                PublicKey::from_bytes(&public).map_err(|_| Error::CouldNotReadKey)?
            };
            return Ok(key::KeyPair::Ed25519(Keypair { public, secret }));
        }
    }

    Err(Error::CouldNotReadKey)
}

#[cfg(feature = "openssl")]
fn write_key_v0(writer: &mut yasna::DERWriterSeq, key: &Rsa<Private>) {
    writer.next().write_u32(0);
    // write OID
    writer.next().write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(RSA));
        writer.next().write_null()
    });
    let bytes = yasna::construct_der(|writer| {
        #[allow(clippy::unwrap_used)] // key is known to be private
        writer.write_sequence(|writer| {
            writer.next().write_u32(0);
            use num_bigint::BigUint;
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.n().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.e().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.d().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.p().unwrap().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.q().unwrap().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.dmp1().unwrap().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.dmq1().unwrap().to_vec()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.iqmp().unwrap().to_vec()));
        })
    });
    writer.next().write_bytes(&bytes);
}

#[cfg(feature = "openssl")]
fn read_key_v0(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader.next().read_sequence(|reader| {
        let oid = reader.next().read_oid()?;
        reader.next().read_null()?;
        Ok(oid)
    })?;
    if oid.components().as_slice() == RSA {
        let seq = &reader.next().read_bytes()?;
        let rsa: Result<Rsa<Private>, Error> = yasna::parse_der(seq, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u32()?;
                if version != 0 {
                    return Ok(Err(Error::CouldNotReadKey));
                }
                use openssl::bn::BigNum;
                let mut read_key = || -> Result<Rsa<Private>, Error> {
                    Ok(Rsa::from_private_components(
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                        BigNum::from_slice(&reader.next().read_biguint()?.to_bytes_be())?,
                    )?)
                };
                Ok(read_key())
            })
        })?;
        Ok(key::KeyPair::RSA {
            key: rsa?,
            hash: SignatureHash::SHA2_256,
        })
    } else {
        Err(Error::CouldNotReadKey)
    }
}

#[cfg(not(feature = "openssl"))]
fn read_key_v0(_: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    Err(Error::CouldNotReadKey)
}

#[test]
#[allow(clippy::unwrap_used)]
#[cfg(feature = "rs-crypto")]
fn test_read_write_pkcs8() {
    use rand_core::OsRng;
    let ed25519_dalek::Keypair { public, secret } = ed25519_dalek::Keypair::generate(&mut OsRng {});
    assert_eq!(
        public.as_bytes(),
        ed25519_dalek::PublicKey::from(&secret).as_bytes()
    );
    let key = key::KeyPair::Ed25519(ed25519_dalek::Keypair { public, secret });
    let password = b"blabla";
    let ciphertext = encode_pkcs8_encrypted(password, 100, &key).unwrap();
    let key = decode_pkcs8(&ciphertext, Some(password)).unwrap();
    match key {
        key::KeyPair::Ed25519 { .. } => println!("Ed25519"),
        #[cfg(feature = "openssl")]
        key::KeyPair::RSA { .. } => println!("RSA"),
    }
}

use yasna::models::ObjectIdentifier;

#[cfg(feature = "rs-crypto")]
fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32, key: &mut [u8]) -> Result<(), Error> {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, rounds, key);
    Ok(())
}

#[cfg(all(feature = "openssl", not(feature = "rs-crypto")))]
fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32, key: &mut [u8]) -> Result<(), Error> {
    openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        rounds as usize,
        openssl::hash::MessageDigest::sha256(),
        key,
    )?;
    Ok(())
}

#[cfg(all(feature = "openssl", not(feature = "rs-crypto")))]
fn encrypt_key(key: &[u8], iv: &[u8], plaintext: &mut [u8]) -> Result<Vec<u8>, Error> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::*;

    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(Cipher::aes_256_cbc()), Some(key), Some(iv))?;
    ctx.set_padding(false);

    let mut output = vec![];
    ctx.cipher_update_vec(plaintext, &mut output)?;
    ctx.cipher_final_vec(&mut output)?;
    Ok(output)
}

#[cfg(feature = "rs-crypto")]
fn encrypt_key(key: &[u8], iv: &[u8], plaintext: &mut [u8]) -> Result<Vec<u8>, Error> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use aes::*;
    use block_padding::NoPadding;

    #[allow(clippy::unwrap_used)] // parameters are static
    let c = cbc::Encryptor::<Aes256>::new_from_slices(key, iv).unwrap();
    let n = plaintext.len();
    let enc = c.encrypt_padded_mut::<NoPadding>(plaintext, n)?;
    Ok(enc.to_vec())
}

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
    pbkdf2(pass, &salt, rounds, &mut dkey)?;
    let mut plaintext = encode_pkcs8(key);

    let padding_len = 32 - (plaintext.len() % 32);
    plaintext.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    let encrypted = encrypt_key(&dkey, &iv, &mut plaintext)?;

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
            writer.next().write_bytes(&encrypted)
        })
    }))
}

/// Encode a Decode a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &key::KeyPair) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| match *key {
            #[cfg(feature = "rs-crypto")]
            key::KeyPair::Ed25519(ref pair) => write_key_v1(writer, &pair.secret),
            #[cfg(feature = "openssl")]
            key::KeyPair::RSA { ref key, .. } => write_key_v0(writer, key),
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
                pbkdf2(password, salt, rounds as u32, key)?
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

    #[cfg(feature = "rs-crypto")]
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        use aes::cipher::{BlockDecryptMut, KeyIvInit};
        use aes::*;
        use block_padding::Pkcs7;
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

    #[cfg(all(feature = "openssl", not(feature = "rs-crypto")))]
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        use openssl::symm::{decrypt, Cipher};
        match *self {
            Encryption::Aes128Cbc(ref iv) => {
                Ok(decrypt(Cipher::aes_128_cbc(), key, Some(iv), ciphertext)?)
            }
            Encryption::Aes256Cbc(ref iv) => {
                Ok(decrypt(Cipher::aes_256_cbc(), key, Some(iv), ciphertext)?)
            }
        }
    }
}

enum KeyDerivation {
    Pbkdf2 { salt: Vec<u8>, rounds: u64 },
}
