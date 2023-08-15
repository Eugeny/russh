use std::convert::TryFrom;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
use bcrypt_pbkdf;
use ctr::Ctr64BE;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;

use crate::encoding::Reader;
use crate::{key, Error, KEYTYPE_ED25519, KEYTYPE_RSA};

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<key::KeyPair, Error> {
    if matches!(secret.get(0..15), Some(b"openssh-key-v1\0")) {
        let mut position = secret.reader(15);

        let ciphername = position.read_string()?;
        let kdfname = position.read_string()?;
        let kdfoptions = position.read_string()?;

        let nkeys = position.read_u32()?;

        // Read all public keys
        for _ in 0..nkeys {
            position.read_string()?;
        }

        // Read all secret keys
        let secret_ = position.read_string()?;
        let secret = decrypt_secret_key(ciphername, kdfname, kdfoptions, password, secret_)?;
        let mut position = secret.reader(0);
        let _check0 = position.read_u32()?;
        let _check1 = position.read_u32()?;
        #[allow(clippy::never_loop)]
        for _ in 0..nkeys {
            // TODO check: never really loops beyond the first key
            let key_type = position.read_string()?;
            if key_type == KEYTYPE_ED25519 {
                let pubkey = position.read_string()?;
                let seckey = position.read_string()?;
                let _comment = position.read_string()?;
                if Some(pubkey) != seckey.get(32..) {
                    return Err(Error::KeyIsCorrupt);
                }
                let secret = ed25519_dalek::SigningKey::try_from(
                    seckey.get(..32).ok_or(Error::KeyIsCorrupt)?,
                )?;
                return Ok(key::KeyPair::Ed25519(secret));
            } else if key_type == KEYTYPE_RSA && cfg!(feature = "openssl") {
                #[cfg(feature = "openssl")]
                {
                    let n = BigNum::from_slice(position.read_string()?)?;
                    let e = BigNum::from_slice(position.read_string()?)?;
                    let d = BigNum::from_slice(position.read_string()?)?;
                    let iqmp = BigNum::from_slice(position.read_string()?)?;
                    let p = BigNum::from_slice(position.read_string()?)?;
                    let q = BigNum::from_slice(position.read_string()?)?;

                    let mut ctx = openssl::bn::BigNumContext::new()?;
                    let un = openssl::bn::BigNum::from_u32(1)?;
                    let mut p1 = openssl::bn::BigNum::new()?;
                    let mut q1 = openssl::bn::BigNum::new()?;
                    p1.checked_sub(&p, &un)?;
                    q1.checked_sub(&q, &un)?;
                    let mut dmp1 = openssl::bn::BigNum::new()?; // d mod p-1
                    dmp1.checked_rem(&d, &p1, &mut ctx)?;
                    let mut dmq1 = openssl::bn::BigNum::new()?; // d mod q-1
                    dmq1.checked_rem(&d, &q1, &mut ctx)?;

                    let key = openssl::rsa::RsaPrivateKeyBuilder::new(n, e, d)?
                        .set_factors(p, q)?
                        .set_crt_params(dmp1, dmq1, iqmp)?
                        .build();
                    key.check_key()?;
                    return Ok(key::KeyPair::RSA {
                        key,
                        hash: key::SignatureHash::SHA2_512,
                    });
                }
            } else {
                return Err(Error::UnsupportedKeyType {
                    key_type_string: String::from_utf8(key_type.to_vec())
                        .unwrap_or_else(|_| format!("{key_type:?}")),
                    key_type_raw: key_type.to_vec(),
                });
            }
        }
        Err(Error::CouldNotReadKey)
    } else {
        Err(Error::CouldNotReadKey)
    }
}

use aes::*;

fn decrypt_secret_key(
    ciphername: &[u8],
    kdfname: &[u8],
    kdfoptions: &[u8],
    password: Option<&str>,
    secret_key: &[u8],
) -> Result<Vec<u8>, Error> {
    if kdfname == b"none" {
        if password.is_none() {
            Ok(secret_key.to_vec())
        } else {
            Err(Error::CouldNotReadKey)
        }
    } else if let Some(password) = password {
        let mut key = [0; 48];
        let n = match ciphername {
            b"aes128-cbc" | b"aes128-ctr" => 32,
            b"aes256-cbc" | b"aes256-ctr" => 48,
            _ => return Err(Error::CouldNotReadKey),
        };
        match kdfname {
            b"bcrypt" => {
                let mut kdfopts = kdfoptions.reader(0);
                let salt = kdfopts.read_string()?;
                let rounds = kdfopts.read_u32()?;
                #[allow(clippy::unwrap_used)] // parameters are static
                #[allow(clippy::indexing_slicing)] // output length is static
                match bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut key[..n]) {
                    Err(bcrypt_pbkdf::Error::InvalidParamLen) => return Err(Error::KeyIsEncrypted),
                    e => e.unwrap(),
                }
            }
            _kdfname => {
                return Err(Error::CouldNotReadKey);
            }
        };
        let (key, iv) = key.split_at(n - 16);

        let mut dec = secret_key.to_vec();
        dec.resize(dec.len() + 32, 0u8);
        match ciphername {
            b"aes128-cbc" => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let cipher = cbc::Decryptor::<Aes128>::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt_padded_mut::<NoPadding>(&mut dec)?.len();
                dec.truncate(n)
            }
            b"aes256-cbc" => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt_padded_mut::<NoPadding>(&mut dec)?.len();
                dec.truncate(n)
            }
            b"aes128-ctr" => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let mut cipher = Ctr64BE::<Aes128>::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut dec);
                dec.truncate(secret_key.len())
            }
            b"aes256-ctr" => {
                #[allow(clippy::unwrap_used)] // parameters are static
                let mut cipher = Ctr64BE::<Aes256>::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut dec);
                dec.truncate(secret_key.len())
            }
            _ => {}
        }
        Ok(dec)
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
