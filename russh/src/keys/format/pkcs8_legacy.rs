use std::borrow::Cow;
use std::convert::TryFrom;

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::*;
use block_padding::Pkcs7;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::PrivateKey;
use yasna::BERReaderSeq;

use super::Encryption;
use crate::keys::Error;

const PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const ED25519: &[u64] = &[1, 3, 101, 112];
const PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const AES256CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];

pub fn decode_pkcs8(ciphertext: &[u8], password: Option<&[u8]>) -> Result<PrivateKey, Error> {
    let secret = if let Some(pass) = password {
        Cow::Owned(yasna::parse_der(ciphertext, |reader| {
            reader.read_sequence(|reader| {
                // Encryption parameters
                let parameters = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    if oid.components().as_slice() == PBES2 {
                        asn1_read_pbes2(reader)
                    } else {
                        Ok(Err(Error::InvalidParameters))
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
                Ok(Err(Error::CouldNotReadKey))
            } else if version == 1 {
                Ok(read_key_v1(reader))
            } else {
                Ok(Err(Error::CouldNotReadKey))
            }
        })
    })?
}

fn read_key_v1(reader: &mut BERReaderSeq) -> Result<PrivateKey, Error> {
    let oid = reader
        .next()
        .read_sequence(|reader| reader.next().read_oid())?;
    if oid.components().as_slice() == ED25519 {
        use ed25519_dalek::SigningKey;
        let secret = {
            let s = yasna::parse_der(&reader.next().read_bytes()?, |reader| reader.read_bytes())?;

            s.get(..ed25519_dalek::SECRET_KEY_LENGTH)
                .ok_or(Error::KeyIsCorrupt)
                .and_then(|s| SigningKey::try_from(s).map_err(|_| Error::CouldNotReadKey))?
        };
        // Consume the public key
        reader
            .next()
            .read_tagged(yasna::Tag::context(1), |reader| reader.read_bitvec())?;

        let pk = Ed25519PrivateKey::from(&secret);
        Ok(PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }),
            "",
        )?)
    } else {
        Err(Error::CouldNotReadKey)
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

impl KeyDerivation {
    fn derive(&self, password: &[u8], key: &mut [u8]) -> Result<(), Error> {
        match *self {
            KeyDerivation::Pbkdf2 { ref salt, rounds } => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, rounds as u32, key)
                    .map_err(|_| Error::InvalidParameters)
                // pbkdf2_hmac(password, salt, rounds as usize, digest, key)?
            }
        }
    }
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
                Ok(Err(Error::InvalidParameters))
            }
        })?;
        // 2. Encryption algorithm.
        let algorithm = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == AES256CBC {
                asn1_read_aes256cbc(reader)
            } else {
                Ok(Err(Error::InvalidParameters))
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
                Ok(Err(Error::InvalidParameters))
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
