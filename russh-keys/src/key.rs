// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use std::convert::TryFrom;

use ed25519_dalek::{Signer, Verifier};
#[cfg(feature = "openssl")]
use openssl::pkey::{Private, Public};
use p256::elliptic_curve::generic_array::typenum::Unsigned;
use p521::elliptic_curve::generic_array::GenericArray;
use rand_core::OsRng;
use russh_cryptovec::CryptoVec;
use serde::{Deserialize, Serialize};

use crate::encoding::{Encoding, Reader};
pub use crate::signature::*;
use crate::Error;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Name of a public key algorithm.
pub struct Name(pub &'static str);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The name of the ecdsa-sha2-nistp256 algorithm for SSH.
pub const ECDSA_SHA2_NISTP256: Name = Name("ecdsa-sha2-nistp256");
/// The name of the ecdsa-sha2-nistp521 algorithm for SSH.
pub const ECDSA_SHA2_NISTP521: Name = Name("ecdsa-sha2-nistp521");
/// The name of the Ed25519 algorithm for SSH.
pub const ED25519: Name = Name("ssh-ed25519");
/// The name of the ssh-sha2-512 algorithm for SSH.
pub const RSA_SHA2_512: Name = Name("rsa-sha2-512");
/// The name of the ssh-sha2-256 algorithm for SSH.
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");

pub const NONE: Name = Name("none");

pub const SSH_RSA: Name = Name("ssh-rsa");

impl Name {
    /// Base name of the private key file for a key name.
    pub fn identity_file(&self) -> &'static str {
        match *self {
            ECDSA_SHA2_NISTP256 | ECDSA_SHA2_NISTP521 => "id_ecdsa",
            ED25519 => "id_ed25519",
            RSA_SHA2_512 => "id_rsa",
            RSA_SHA2_256 => "id_rsa",
            _ => unreachable!(),
        }
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// The hash function used for signing with RSA keys.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// SHA2, 256 bits.
    SHA2_256,
    /// SHA2, 512 bits.
    SHA2_512,
    /// SHA1
    SHA1,
}

impl SignatureHash {
    pub fn name(&self) -> Name {
        match *self {
            SignatureHash::SHA2_256 => RSA_SHA2_256,
            SignatureHash::SHA2_512 => RSA_SHA2_512,
            SignatureHash::SHA1 => SSH_RSA,
        }
    }

    #[cfg(feature = "openssl")]
    fn message_digest(&self) -> openssl::hash::MessageDigest {
        use openssl::hash::MessageDigest;
        match *self {
            SignatureHash::SHA2_256 => MessageDigest::sha256(),
            SignatureHash::SHA2_512 => MessageDigest::sha512(),
            SignatureHash::SHA1 => MessageDigest::sha1(),
        }
    }

    pub fn from_rsa_hostkey_algo(algo: &[u8]) -> Option<Self> {
        if algo == b"rsa-sha2-256" {
            Some(Self::SHA2_256)
        } else if algo == b"rsa-sha2-512" {
            Some(Self::SHA2_512)
        } else {
            Some(Self::SHA1)
        }
    }
}

/// Public key
#[derive(Eq, Debug, Clone)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(ed25519_dalek::VerifyingKey),
    #[doc(hidden)]
    #[cfg(feature = "openssl")]
    RSA {
        key: OpenSSLPKey,
        hash: SignatureHash,
    },
    #[doc(hidden)]
    P256(p256::PublicKey),
    #[doc(hidden)]
    P521(p521::PublicKey),
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(feature = "openssl")]
            (Self::RSA { key: a, .. }, Self::RSA { key: b, .. }) => a == b,
            (Self::Ed25519(a), Self::Ed25519(b)) => a == b,
            (Self::P256(a), Self::P256(b)) => a == b,
            (Self::P521(a), Self::P521(b)) => a == b,
            _ => false,
        }
    }
}

/// A public key from OpenSSL.
#[cfg(feature = "openssl")]
#[derive(Clone)]
pub struct OpenSSLPKey(pub openssl::pkey::PKey<Public>);

#[cfg(feature = "openssl")]
use std::cmp::{Eq, PartialEq};

#[cfg(feature = "openssl")]
impl PartialEq for OpenSSLPKey {
    fn eq(&self, b: &OpenSSLPKey) -> bool {
        self.0.public_eq(&b.0)
    }
}
#[cfg(feature = "openssl")]
impl Eq for OpenSSLPKey {}
#[cfg(feature = "openssl")]
impl std::fmt::Debug for OpenSSLPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSLPKey {{ (hidden) }}")
    }
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let key_bytes = p.read_string()?;
                if key_algo != b"ssh-ed25519" {
                    return Err(Error::CouldNotReadKey);
                }
                let Ok(key_bytes) = <&[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::try_from(key_bytes)
                else {
                    return Err(Error::CouldNotReadKey);
                };
                ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
                    .map(PublicKey::Ed25519)
                    .map_err(Error::from)
            }
            b"ssh-rsa" | b"rsa-sha2-256" | b"rsa-sha2-512" if cfg!(feature = "openssl") => {
                #[cfg(feature = "openssl")]
                {
                    use log::debug;
                    let mut p = pubkey.reader(0);
                    let key_algo = p.read_string()?;
                    debug!("{:?}", std::str::from_utf8(key_algo));
                    if key_algo != b"ssh-rsa"
                        && key_algo != b"rsa-sha2-256"
                        && key_algo != b"rsa-sha2-512"
                    {
                        return Err(Error::CouldNotReadKey);
                    }
                    let key_e = p.read_string()?;
                    let key_n = p.read_string()?;
                    use openssl::bn::BigNum;
                    use openssl::pkey::PKey;
                    use openssl::rsa::Rsa;
                    Ok(PublicKey::RSA {
                        key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                            BigNum::from_slice(key_n)?,
                            BigNum::from_slice(key_e)?,
                        )?)?),
                        hash: SignatureHash::from_rsa_hostkey_algo(algo)
                            .unwrap_or(SignatureHash::SHA1),
                    })
                }
                #[cfg(not(feature = "openssl"))]
                {
                    unreachable!()
                }
            }
            b"ecdsa-sha2-nistp256" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let curve = p.read_string()?;
                if key_algo != b"ecdsa-sha2-nistp256" || curve != b"nistp256" {
                    return Err(Error::CouldNotReadKey);
                }
                let sec1_bytes = p.read_string()?;
                let key = p256::PublicKey::from_sec1_bytes(sec1_bytes)
                    .map_err(|_| Error::CouldNotReadKey)?;
                Ok(PublicKey::P256(key))
            }
            b"ecdsa-sha2-nistp521" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let curve = p.read_string()?;
                if key_algo != b"ecdsa-sha2-nistp521" || curve != b"nistp521" {
                    return Err(Error::CouldNotReadKey);
                }
                let sec1_bytes = p.read_string()?;
                let key = p521::PublicKey::from_sec1_bytes(sec1_bytes)
                    .map_err(|_| Error::CouldNotReadKey)?;
                Ok(PublicKey::P521(key))
            }
            _ => Err(Error::CouldNotReadKey),
        }
    }

    /// Algorithm name for that key.
    pub fn name(&self) -> &'static str {
        match *self {
            PublicKey::Ed25519(_) => ED25519.0,
            #[cfg(feature = "openssl")]
            PublicKey::RSA { ref hash, .. } => hash.name().0,
            PublicKey::P256(_) => ECDSA_SHA2_NISTP256.0,
            PublicKey::P521(_) => ECDSA_SHA2_NISTP521.0,
        }
    }

    /// Verify a signature.
    pub fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519(ref public) => {
                let Ok(sig) = ed25519_dalek::ed25519::SignatureBytes::try_from(sig) else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig);
                public.verify(buffer, &sig).is_ok()
            }

            #[cfg(feature = "openssl")]
            PublicKey::RSA { ref key, ref hash } => {
                use openssl::sign::*;
                let verify = || {
                    let mut verifier = Verifier::new(hash.message_digest(), &key.0)?;
                    verifier.update(buffer)?;
                    verifier.verify(sig)
                };
                verify().unwrap_or(false)
            }
            PublicKey::P256(ref public) => {
                const FIELD_LEN: usize =
                    <p256::NistP256 as p256::elliptic_curve::Curve>::FieldBytesSize::USIZE;
                let mut reader = sig.reader(0);
                let mut read_field = || -> Option<p256::FieldBytes> {
                    let f = reader.read_mpint().ok()?;
                    let f = f.strip_prefix(&[0]).unwrap_or(f);
                    let mut result = [0; FIELD_LEN];
                    if f.len() > FIELD_LEN {
                        return None;
                    }
                    #[allow(clippy::indexing_slicing)] // length is known
                    result[FIELD_LEN - f.len()..].copy_from_slice(f);
                    Some(result.into())
                };
                let Some(r) = read_field() else { return false };
                let Some(s) = read_field() else { return false };
                let Ok(signature) = p256::ecdsa::Signature::from_scalars(r, s) else {
                    return false;
                };
                p256::ecdsa::VerifyingKey::from(public)
                    .verify(buffer, &signature)
                    .is_ok()
            }
            PublicKey::P521(ref public) => {
                const FIELD_LEN: usize =
                    <p521::NistP521 as p256::elliptic_curve::Curve>::FieldBytesSize::USIZE;
                let mut reader = sig.reader(0);
                let mut read_field = || -> Option<p521::FieldBytes> {
                    let f = reader.read_mpint().ok()?;
                    let f = f.strip_prefix(&[0]).unwrap_or(f);
                    let mut result = [0; FIELD_LEN];
                    if f.len() > FIELD_LEN {
                        return None;
                    }
                    #[allow(clippy::indexing_slicing)] // length is known
                    result[FIELD_LEN - f.len()..].copy_from_slice(f);
                    Some(GenericArray::clone_from_slice(&result))
                };
                let Some(r) = read_field() else { return false };
                let Some(s) = read_field() else { return false };
                let Ok(signature) = p521::ecdsa::Signature::from_scalars(r, s) else {
                    return false;
                };

                // Length known
                #[allow(clippy::unwrap_used)]
                p521::ecdsa::VerifyingKey::from_sec1_bytes(&public.to_sec1_bytes())
                    .unwrap()
                    .verify(buffer, &signature)
                    .is_ok()
            }
        }
    }

    /// Compute the key fingerprint, hashed with sha2-256.
    pub fn fingerprint(&self) -> String {
        use super::PublicKeyBase64;
        let key = self.public_key_bytes();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key[..]);
        data_encoding::BASE64_NOPAD.encode(&hasher.finalize())
    }

    #[cfg(feature = "openssl")]
    pub fn set_algorithm(&mut self, algorithm: &[u8]) {
        if let PublicKey::RSA { ref mut hash, .. } = self {
            if algorithm == b"rsa-sha2-512" {
                *hash = SignatureHash::SHA2_512
            } else if algorithm == b"rsa-sha2-256" {
                *hash = SignatureHash::SHA2_256
            } else if algorithm == b"ssh-rsa" {
                *hash = SignatureHash::SHA1
            }
        }
    }

    #[cfg(not(feature = "openssl"))]
    pub fn set_algorithm(&mut self, _: &[u8]) {}
}

impl Verify for PublicKey {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
}

/// Public key exchange algorithms.
#[allow(clippy::large_enum_variant)]
pub enum KeyPair {
    Ed25519(ed25519_dalek::SigningKey),
    #[cfg(feature = "openssl")]
    RSA {
        key: openssl::rsa::Rsa<Private>,
        hash: SignatureHash,
    },
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        match self {
            #[allow(clippy::expect_used)]
            Self::Ed25519(kp) => {
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&kp.to_bytes()))
            }
            #[cfg(feature = "openssl")]
            Self::RSA { key, hash } => Self::RSA {
                key: key.clone(),
                hash: *hash,
            },
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyPair::Ed25519(ref key) => write!(
                f,
                "Ed25519 {{ public: {:?}, secret: (hidden) }}",
                key.verifying_key().as_bytes()
            ),
            #[cfg(feature = "openssl")]
            KeyPair::RSA { .. } => write!(f, "RSA {{ (hidden) }}"),
        }
    }
}

impl<'b> crate::encoding::Bytes for &'b KeyPair {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

impl KeyPair {
    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> Result<PublicKey, Error> {
        Ok(match self {
            KeyPair::Ed25519(ref key) => PublicKey::Ed25519(key.verifying_key()),
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, ref hash } => {
                use openssl::pkey::PKey;
                use openssl::rsa::Rsa;
                let key = Rsa::from_public_components(key.n().to_owned()?, key.e().to_owned()?)?;
                PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(key)?),
                    hash: *hash,
                }
            }
        })
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref hash, .. } => hash.name().0,
        }
    }

    /// Generate a key pair.
    pub fn generate_ed25519() -> Option<Self> {
        let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng {});
        assert_eq!(
            keypair.verifying_key().as_bytes(),
            ed25519_dalek::VerifyingKey::from(&keypair).as_bytes()
        );
        Some(KeyPair::Ed25519(keypair))
    }

    #[cfg(feature = "openssl")]
    pub fn generate_rsa(bits: usize, hash: SignatureHash) -> Option<Self> {
        let key = openssl::rsa::Rsa::generate(bits as u32).ok()?;
        Some(KeyPair::RSA { key, hash })
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            #[allow(clippy::unwrap_used)]
            KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(
                secret.sign(to_sign).to_bytes(),
            ))),
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA {
                bytes: rsa_signature(hash, key, to_sign)?,
                hash: *hash,
            }),
        }
    }

    #[doc(hidden)]
    /// This is used by the server to sign the initial DH kex
    /// message. Note: we are not signing the same kind of thing as in
    /// the function below, `add_self_signature`.
    pub fn add_signature<H: AsRef<[u8]>>(
        &self,
        buffer: &mut CryptoVec,
        to_sign: H,
    ) -> Result<(), Error> {
        match self {
            KeyPair::Ed25519(ref secret) => {
                let signature = secret.sign(to_sign.as_ref());

                buffer.push_u32_be((ED25519.0.len() + signature.to_bytes().len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(signature.to_bytes().as_slice());
            }
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, to_sign.as_ref())?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    /// This is used by the client for authentication. Note: we are
    /// not signing the same kind of thing as in the above function,
    /// `add_signature`.
    pub fn add_self_signature(&self, buffer: &mut CryptoVec) -> Result<(), Error> {
        match self {
            KeyPair::Ed25519(ref secret) => {
                let signature = secret.sign(buffer);
                buffer.push_u32_be((ED25519.0.len() + signature.to_bytes().len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(signature.to_bytes().as_slice());
            }
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, buffer)?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }

    /// Create a copy of an RSA key with a specified hash algorithm.
    #[cfg(feature = "openssl")]
    pub fn with_signature_hash(&self, hash: SignatureHash) -> Option<Self> {
        match self {
            KeyPair::Ed25519(_) => None,
            #[cfg(feature = "openssl")]
            KeyPair::RSA { key, .. } => Some(KeyPair::RSA {
                key: key.clone(),
                hash,
            }),
        }
    }
}

#[cfg(feature = "openssl")]
fn rsa_signature(
    hash: &SignatureHash,
    key: &openssl::rsa::Rsa<Private>,
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    use openssl::pkey::*;
    use openssl::rsa::*;
    use openssl::sign::Signer;
    let pkey = PKey::from_rsa(Rsa::from_private_components(
        key.n().to_owned()?,
        key.e().to_owned()?,
        key.d().to_owned()?,
        key.p().ok_or(Error::KeyIsCorrupt)?.to_owned()?,
        key.q().ok_or(Error::KeyIsCorrupt)?.to_owned()?,
        key.dmp1().ok_or(Error::KeyIsCorrupt)?.to_owned()?,
        key.dmq1().ok_or(Error::KeyIsCorrupt)?.to_owned()?,
        key.iqmp().ok_or(Error::KeyIsCorrupt)?.to_owned()?,
    )?)?;
    let mut signer = Signer::new(hash.message_digest(), &pkey)?;
    signer.update(b)?;
    Ok(signer.sign_to_vec()?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(
    p: &[u8],
    #[cfg(feature = "openssl")] prefer_hash: Option<SignatureHash>,
) -> Result<PublicKey, Error> {
    let mut pos = p.reader(0);
    let t = pos.read_string()?;
    if t == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            let Ok(pubkey) = <&[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::try_from(pubkey) else {
                return Err(Error::CouldNotReadKey);
            };
            let p = ed25519_dalek::VerifyingKey::from_bytes(pubkey).map_err(Error::from)?;
            return Ok(PublicKey::Ed25519(p));
        }
    }
    if t == b"ssh-rsa" {
        #[cfg(feature = "openssl")]
        {
            let e = pos.read_string()?;
            let n = pos.read_string()?;
            use openssl::bn::*;
            use openssl::pkey::*;
            use openssl::rsa::*;
            return Ok(PublicKey::RSA {
                key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                    BigNum::from_slice(n)?,
                    BigNum::from_slice(e)?,
                )?)?),
                hash: prefer_hash.unwrap_or(SignatureHash::SHA2_256),
            });
        }
    }
    if t == b"ecdsa-sha2-nistp256" {
        if pos.read_string()? != b"nistp256" {
            return Err(Error::CouldNotReadKey);
        }
        let sec1_bytes = pos.read_string()?;
        let key = p256::PublicKey::from_sec1_bytes(sec1_bytes)?;
        return Ok(PublicKey::P256(key));
    }
    if t == b"ecdsa-sha2-nistp521" {
        if pos.read_string()? != b"nistp521" {
            return Err(Error::CouldNotReadKey);
        }
        let sec1_bytes = pos.read_string()?;
        let key = p521::PublicKey::from_sec1_bytes(sec1_bytes)?;
        return Ok(PublicKey::P521(key));
    }
    Err(Error::CouldNotReadKey)
}
