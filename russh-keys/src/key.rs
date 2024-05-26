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
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};

use ed25519_dalek::{Signer, Verifier};
use rand_core::OsRng;
use russh_cryptovec::CryptoVec;
use serde::{Deserialize, Serialize};

use crate::backend;
use crate::ec;
use crate::encoding::{Encoding, Reader};
use crate::protocol;
pub use crate::signature::*;
use crate::Error;

pub use backend::{RsaPrivate, RsaPublic};

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
/// The name of the ecdsa-sha2-nistp384 algorithm for SSH.
pub const ECDSA_SHA2_NISTP384: Name = Name("ecdsa-sha2-nistp384");
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
            ECDSA_SHA2_NISTP256 | ECDSA_SHA2_NISTP384 | ECDSA_SHA2_NISTP521 => "id_ecdsa",
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

    pub fn from_rsa_hostkey_algo(algo: &[u8]) -> Option<Self> {
        match algo {
            b"rsa-sha2-256" => Some(Self::SHA2_256),
            b"rsa-sha2-512" => Some(Self::SHA2_512),
            b"ssh-rsa" => Some(Self::SHA1),
            _ => None,
        }
    }
}

/// Public key
#[derive(Eq, Debug, Clone)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(ed25519_dalek::VerifyingKey),
    #[doc(hidden)]
    RSA {
        key: backend::RsaPublic,
        hash: SignatureHash,
    },
    #[doc(hidden)]
    EC { key: ec::PublicKey },
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RSA { key: a, .. }, Self::RSA { key: b, .. }) => a == b,
            (Self::Ed25519(a), Self::Ed25519(b)) => a == b,
            (Self::EC { key: a }, Self::EC { key: b }) => a == b,
            _ => false,
        }
    }
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        use ssh_encoding::Decode;
        let key_data = &ssh_key::public::KeyData::decode(&mut pubkey.reader(0))?;
        let key_algo = key_data.algorithm();
        let key_algo = key_algo.as_str().as_bytes();
        if key_algo == b"ssh-rsa" {
            if algo != SSH_RSA.as_ref().as_bytes()
                && algo != RSA_SHA2_256.as_ref().as_bytes()
                && algo != RSA_SHA2_512.as_ref().as_bytes()
            {
                return Err(Error::KeyIsCorrupt);
            }
        } else if key_algo != algo {
            return Err(Error::KeyIsCorrupt);
        }
        Self::try_from(key_data)
    }

    pub fn new_rsa_with_hash(
        pk: &protocol::RsaPublicKey<'_>,
        hash: SignatureHash,
    ) -> Result<Self, Error> {
        Ok(PublicKey::RSA {
            key: RsaPublic::try_from(pk)?,
            hash,
        })
    }

    /// Algorithm name for that key.
    pub fn name(&self) -> &'static str {
        match *self {
            PublicKey::Ed25519(_) => ED25519.0,
            PublicKey::RSA { ref hash, .. } => hash.name().0,
            PublicKey::EC { ref key } => key.algorithm(),
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
            PublicKey::RSA { ref key, ref hash } => key.verify_detached(hash, buffer, sig),
            PublicKey::EC { ref key, .. } => ec_verify(key, buffer, sig).is_ok(),
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

    pub fn set_algorithm(&mut self, algorithm: SignatureHash) {
        if let PublicKey::RSA { ref mut hash, .. } = self {
            *hash = algorithm;
        }
    }
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
    RSA {
        key: backend::RsaPrivate,
        hash: SignatureHash,
    },
    EC {
        key: ec::PrivateKey,
    },
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        match self {
            #[allow(clippy::expect_used)]
            Self::Ed25519(kp) => {
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&kp.to_bytes()))
            }
            Self::RSA { key, hash } => Self::RSA {
                key: key.clone(),
                hash: *hash,
            },
            Self::EC { key } => Self::EC { key: key.clone() },
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
            KeyPair::RSA { .. } => write!(f, "RSA {{ (hidden) }}"),
            KeyPair::EC { .. } => write!(f, "EC {{ (hidden) }}"),
        }
    }
}

impl<'b> crate::encoding::Bytes for &'b KeyPair {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

impl KeyPair {
    pub fn new_rsa_with_hash(
        sk: &protocol::RsaPrivateKey<'_>,
        extra: Option<&RsaCrtExtra<'_>>,
        hash: SignatureHash,
    ) -> Result<KeyPair, Error> {
        Ok(KeyPair::RSA {
            key: RsaPrivate::new(sk, extra)?,
            hash,
        })
    }

    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> Result<PublicKey, Error> {
        Ok(match self {
            KeyPair::Ed25519(ref key) => PublicKey::Ed25519(key.verifying_key()),
            KeyPair::RSA { ref key, ref hash } => PublicKey::RSA {
                key: key.try_into()?,
                hash: *hash,
            },
            KeyPair::EC { ref key } => PublicKey::EC {
                key: key.to_public_key(),
            },
        })
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            KeyPair::RSA { ref hash, .. } => hash.name().0,
            KeyPair::EC { ref key } => key.algorithm(),
        }
    }

    /// Generate a ED25519 key pair.
    pub fn generate_ed25519() -> Option<Self> {
        let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng {});
        assert_eq!(
            keypair.verifying_key().as_bytes(),
            ed25519_dalek::VerifyingKey::from(&keypair).as_bytes()
        );
        Some(KeyPair::Ed25519(keypair))
    }

    /// Generate a RSA key pair.
    pub fn generate_rsa(bits: usize, hash: SignatureHash) -> Option<Self> {
        let key = RsaPrivate::generate(bits).ok()?;
        Some(KeyPair::RSA { key, hash })
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            #[allow(clippy::unwrap_used)]
            KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(
                secret.sign(to_sign).to_bytes(),
            ))),
            KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA {
                bytes: key.sign(hash, to_sign)?,
                hash: *hash,
            }),
            KeyPair::EC { ref key } => Ok(Signature::ECDSA {
                algorithm: key.algorithm(),
                signature: ec_signature(key, to_sign)?,
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
            KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = key.sign(hash, to_sign.as_ref())?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            KeyPair::EC { ref key } => {
                let algorithm = key.algorithm().as_bytes();
                let signature = ec_signature(key, to_sign.as_ref())?;
                buffer.push_u32_be((algorithm.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(algorithm);
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
            KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = key.sign(hash, buffer)?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            KeyPair::EC { ref key } => {
                let signature = ec_signature(key, buffer)?;
                let algorithm = key.algorithm().as_bytes();
                buffer.push_u32_be((algorithm.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(algorithm);
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }

    /// Create a copy of an RSA key with a specified hash algorithm.
    pub fn with_signature_hash(&self, hash: SignatureHash) -> Option<Self> {
        match self {
            KeyPair::Ed25519(_) => None,
            KeyPair::RSA { key, .. } => Some(KeyPair::RSA {
                key: key.clone(),
                hash,
            }),
            KeyPair::EC { .. } => None,
        }
    }
}

/// Extra CRT parameters for RSA private key.
pub struct RsaCrtExtra<'a> {
    /// `d mod (p-1)`.
    pub dp: Cow<'a, [u8]>,
    /// `d mod (q-1)`.
    pub dq: Cow<'a, [u8]>,
}

impl Drop for RsaCrtExtra<'_> {
    fn drop(&mut self) {
        zeroize_cow(&mut self.dp);
        zeroize_cow(&mut self.dq);
    }
}

fn ec_signature(key: &ec::PrivateKey, b: &[u8]) -> Result<Vec<u8>, Error> {
    let (r, s) = key.try_sign(b)?;
    let mut buf = Vec::new();
    buf.extend_ssh_mpint(&r);
    buf.extend_ssh_mpint(&s);
    Ok(buf)
}

fn ec_verify(key: &ec::PublicKey, b: &[u8], sig: &[u8]) -> Result<(), Error> {
    let mut reader = sig.reader(0);
    key.verify(b, reader.read_mpint()?, reader.read_mpint()?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8], prefer_hash: Option<SignatureHash>) -> Result<PublicKey, Error> {
    use ssh_encoding::Decode;
    let mut key = PublicKey::try_from(&ssh_key::public::KeyData::decode(&mut p.reader(0))?)?;
    key.set_algorithm(prefer_hash.unwrap_or(SignatureHash::SHA2_256));
    Ok(key)
}

/// Obtain a cryptographic-safe random number generator.
pub fn safe_rng() -> impl rand::CryptoRng + rand::RngCore {
    rand::thread_rng()
}

/// Zeroize `Cow` if value is owned.
pub(crate) fn zeroize_cow<T>(v: &mut Cow<T>)
where
    T: ToOwned + ?Sized,
    <T as ToOwned>::Owned: zeroize::Zeroize,
{
    use zeroize::Zeroize;
    match v {
        Cow::Owned(v) => v.zeroize(),
        Cow::Borrowed(_) => (),
    }
}
