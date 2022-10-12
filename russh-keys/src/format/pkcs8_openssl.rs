use openssl::{pkey::*, symm::Cipher};

use crate::{key::{self, KeyPair, SignatureHash}, Error};

pub fn decode_pkcs8(key: &str, _dec: &[u8], password: Option<&[u8]>) -> Result<key::KeyPair, Error> {
  let pkey = match password {
    Some(p) => PKey::private_key_from_pem_passphrase(key.as_bytes(), p)?,
    None => PKey::private_key_from_pem(key.as_bytes())?
  };

  Ok(KeyPair::RSA { key: pkey.rsa()? , hash: SignatureHash::SHA2_256 })
}

pub fn encode_pkcs8(key: &key::KeyPair) -> Result<Vec<u8>, Error> {
  let pkey = match key {
    KeyPair::Ed25519 { .. } => return Err(Error::UnsupportedKeyType(vec![]).into()),
    KeyPair::RSA { key, hash } => PKey::from_rsa(key.clone())?
  };

  Ok(pkey.private_key_to_pem_pkcs8()?)
}

pub fn encode_pkcs8_encrypted(pass: &[u8], rounds: u32, key: &key::KeyPair) -> Result<Vec<u8>, Error> {
  let pkey = match key {
    KeyPair::Ed25519 { .. } => return Err(Error::UnsupportedKeyType(vec![]).into()),
    KeyPair::RSA { key, hash } => PKey::from_rsa(key.clone())?
  };

  Ok(pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pass)?)
}
