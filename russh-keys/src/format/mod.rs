use std::io::Write;

use data_encoding::{BASE64_MIME, HEXLOWER_PERMISSIVE};
#[cfg(not(feature = "openssl"))]
use rsa::{self, RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;

use super::is_base64_char;
use crate::{key, Error};

pub mod pkcs5;
pub mod openssh;
pub use self::openssh::*;
pub use self::pkcs5::*;

pub mod pkcs8;

const AES_128_CBC: &str = "DEK-Info: AES-128-CBC,";

#[derive(Clone, Copy, Debug)]
/// AES encryption key.
pub enum Encryption {
    /// Key for AES128
    Aes128Cbc([u8; 16]),
    /// Key for AES256
    Aes256Cbc([u8; 16]),
}

#[derive(Clone, Debug)]
enum Format {
    Rsa,
    Openssh,
    Pkcs5Encrypted(Encryption),
    Pkcs8Encrypted,
    Pkcs8,
}

/// Parse the header line to determine the format of the secret key.
fn parse_header(line: &str) -> Option<Format> {
    match line {
        "-----BEGIN OPENSSH PRIVATE KEY-----" => Some(Format::Openssh),
        "-----BEGIN RSA PRIVATE KEY-----" => Some(Format::Rsa),
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" => Some(Format::Pkcs8Encrypted),
        "-----BEGIN PRIVATE KEY-----" => Some(Format::Pkcs8),
        _ => None,
    }
}

/// Decode a secret key, possibly deciphering it with the supplied
/// password.
pub fn decode_secret_key(secret: &str, password: Option<&str>) -> Result<key::KeyPair, Error> {
    let mut format = None;
    let secret: String = {
        let mut started = false;
        let mut sec = String::new();
        for l in secret.lines() {
            if started {
                if l.starts_with("-----END ") {
                    break;
                }
                if l.chars().all(is_base64_char) {
                    sec.push_str(l)
                } else if l.starts_with(AES_128_CBC) {
                    let iv_: Vec<u8> = HEXLOWER_PERMISSIVE
                        .decode(l.split_at(AES_128_CBC.len()).1.as_bytes())?;
                    if iv_.len() != 16 {
                        return Err(Error::CouldNotReadKey);
                    }
                    let mut iv = [0; 16];
                    iv.clone_from_slice(&iv_);
                    format = Some(Format::Pkcs5Encrypted(Encryption::Aes128Cbc(iv)))
                }
            } else {
                format = parse_header(l);
                started = true;
            }
        }
        sec
    };

    let secret = BASE64_MIME.decode(secret.as_bytes())?;
    match format {
        Some(Format::Openssh) => decode_openssh(&secret, password),
        Some(Format::Rsa) => decode_rsa(&secret),
        Some(Format::Pkcs5Encrypted(enc)) => decode_pkcs5(&secret, password, enc),
        Some(Format::Pkcs8Encrypted) | Some(Format::Pkcs8) => {
            self::pkcs8::decode_pkcs8(&secret, password.map(|x| x.as_bytes()))
        }
        None => Err(Error::CouldNotReadKey),
    }
}

pub fn encode_pkcs8_pem<W: Write>(key: &key::KeyPair, mut w: W) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8(key);
    w.write_all(b"-----BEGIN PRIVATE KEY-----\n")?;
    w.write_all(BASE64_MIME.encode(&x).as_bytes())?;
    w.write_all(b"\n-----END PRIVATE KEY-----\n")?;
    Ok(())
}

pub fn encode_pkcs8_pem_encrypted<W: Write>(
    key: &key::KeyPair,
    pass: &[u8],
    rounds: u32,
    mut w: W,
) -> Result<(), Error> {
    let x = self::pkcs8::encode_pkcs8_encrypted(pass, rounds, key)?;
    w.write_all(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")?;
    w.write_all(BASE64_MIME.encode(&x).as_bytes())?;
    w.write_all(b"\n-----END ENCRYPTED PRIVATE KEY-----\n")?;
    Ok(())
}

fn decode_rsa(secret: &[u8]) -> Result<key::KeyPair, Error> {
    Ok(key::KeyPair::RSA {
        #[cfg(feature = "openssl")]
        key: Rsa::private_key_from_der(secret)?,
        #[cfg(not(feature = "openssl"))]
        key: RsaPrivateKey::from_pkcs1_der(secret).map_err(rsa::Error::from)?,
        hash: key::SignatureHash::SHA2_256,
    })
}
