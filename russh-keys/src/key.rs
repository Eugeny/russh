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
use ssh_encoding::Decode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey};

use crate::Error;

pub trait PublicKeyExt {
    fn decode(bytes: &[u8]) -> Result<PublicKey, Error>;
}

impl PublicKeyExt for PublicKey {
    fn decode(mut bytes: &[u8]) -> Result<PublicKey, Error> {
        let key = KeyData::decode(&mut bytes)?;
        Ok(PublicKey::new(key, ""))
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(mut p: &[u8]) -> Result<PublicKey, Error> {
    Ok(ssh_key::public::KeyData::decode(&mut p)?.into())
}

/// Obtain a cryptographic-safe random number generator.
pub fn safe_rng() -> impl rand::CryptoRng + rand::RngCore {
    rand::thread_rng()
}

mod private_key_with_hash_alg {
    use std::ops::Deref;
    use std::sync::Arc;

    use ssh_key::Algorithm;

    use crate::helpers::AlgorithmExt;

    /// Helper structure to correlate a key and (in case of RSA) a hash algorithm.
    /// Only used for authentication, not key storage as RSA keys do not inherently
    /// have a hash algorithm associated with them.
    #[derive(Clone, Debug)]
    pub struct PrivateKeyWithHashAlg {
        key: Arc<crate::PrivateKey>,
        hash_alg: Option<crate::HashAlg>,
    }

    impl PrivateKeyWithHashAlg {
        pub fn new(
            key: Arc<crate::PrivateKey>,
            hash_alg: Option<crate::HashAlg>,
        ) -> Result<Self, crate::Error> {
            if hash_alg.is_some() && !key.algorithm().is_rsa() {
                return Err(crate::Error::InvalidParameters);
            }
            Ok(Self { key, hash_alg })
        }

        pub fn algorithm(&self) -> Algorithm {
            self.key.algorithm().with_hash_alg(self.hash_alg)
        }

        pub fn hash_alg(&self) -> Option<crate::HashAlg> {
            self.hash_alg
        }
    }

    impl Deref for PrivateKeyWithHashAlg {
        type Target = crate::PrivateKey;

        fn deref(&self) -> &Self::Target {
            &self.key
        }
    }
}

pub use private_key_with_hash_alg::PrivateKeyWithHashAlg;

pub const ALL_KEY_TYPES: &[Algorithm] = &[
    Algorithm::Dsa,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Ed25519,
    Algorithm::Rsa { hash: None },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::SkEcdsaSha2NistP256,
    Algorithm::SkEd25519,
];
