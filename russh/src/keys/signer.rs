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

//! Traits and types for SSH host key signing.
//!
//! This module provides abstractions for signing operations, allowing both
//! local private keys and external signers (like AWS KMS, HSMs, etc.) to be
//! used as SSH host keys.
//!
//! # Example: Using a local key
//!
//! ```no_run
//! use russh::keys::{PrivateKey, KeyPair};
//!
//! let key = PrivateKey::random(
//!     &mut rand_core::OsRng,
//!     russh::keys::Algorithm::Ed25519
//! ).unwrap();
//!
//! // Convert to KeyPair - works seamlessly with existing code
//! let keypair: KeyPair = key.into();
//! ```
//!
//! # Example: Implementing a custom signer
//!
//! ```ignore
//! use russh::keys::{PrivateKeySigner, KeyPair};
//! use ssh_key::{Algorithm, Signature};
//! use std::future::Future;
//! use std::pin::Pin;
//!
//! struct RemoteSigner {
//!     public_key: ssh_key::PublicKey,
//!     // ... client for remote signing service
//! }
//!
//! impl PrivateKeySigner for RemoteSigner {
//!     fn public_key(&self) -> &ssh_key::PublicKey {
//!         &self.public_key
//!     }
//!
//!     fn sign<'a>(
//!         &'a self,
//!         data: &'a [u8],
//!     ) -> Pin<Box<dyn Future<Output = Result<Signature, ssh_key::Error>> + Send + 'a>> {
//!         Box::pin(async move {
//!             // Call remote service to sign the data
//!             let raw_signature: Vec<u8> = todo!("call remote signing service");
//!             // Wrap in SSH Signature with the appropriate algorithm
//!             Signature::new(Algorithm::Ed25519, raw_signature)
//!         })
//!     }
//! }
//!
//! let keypair = KeyPair::new(RemoteSigner { /* ... */ });
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
use tokio::sync::Mutex;

use crate::CryptoVec;

use crate::helpers::{AlgorithmExt, EncodedExt};

/// A trait for SSH private key signing operations.
///
/// This trait allows custom signing implementations (like AWS KMS, HSMs, etc.)
/// to be used for SSH host key operations. All signing operations are async
/// to support remote signing services.
///
/// The trait is object-safe and implementations must be `Send + Sync + 'static`
/// as they may be shared across threads, connections, and stored in long-lived
/// structures.
///
/// This is similar to [`crate::Signer`] but designed for host keys rather than
/// client authentication. The key differences are:
/// - Object-safe (can be used as `dyn PrivateKeySigner`)
/// - Takes `&self` rather than `&mut self` (shareable across connections)
/// - Encapsulates the public key (no external key lookup needed)
///
/// # Implementing this trait
///
/// If the `async-trait` feature is enabled, you can use `#[async_trait::async_trait]`
/// for a cleaner implementation. Otherwise, you'll need to return a pinned boxed future.
pub trait PrivateKeySigner: Send + Sync + 'static {
    /// Returns the public key for this signer.
    fn public_key(&self) -> &PublicKey;

    /// Signs the given data and returns an SSH [`Signature`].
    ///
    /// # Arguments
    /// * `data` - The data to sign (typically the exchange hash during key exchange)
    ///
    /// # Returns
    /// An SSH signature that can be encoded for the wire protocol.
    fn sign<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, ssh_key::Error>> + Send + 'a>>;
}

/// A host key that wraps a private key signer.
///
/// This type provides a uniform interface for host keys, whether they are
/// local private keys or external signers like AWS KMS.
///
/// # Converting from PrivateKey
///
/// For backward compatibility, `PrivateKey` can be converted directly:
///
/// ```no_run
/// use russh::keys::{PrivateKey, KeyPair, Algorithm};
///
/// let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
/// let keypair: KeyPair = key.into();
/// ```
#[derive(Clone)]
pub struct KeyPair {
    signer: Arc<dyn PrivateKeySigner>,
    /// Optional hash algorithm override for RSA keys.
    hash_alg: Option<HashAlg>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.signer.public_key().algorithm())
            .field("hash_alg", &self.hash_alg)
            .finish()
    }
}

impl From<PrivateKey> for KeyPair {
    fn from(key: PrivateKey) -> Self {
        KeyPair {
            signer: Arc::new(LocalSigner::new(key)),
            hash_alg: None,
        }
    }
}

impl From<Arc<dyn PrivateKeySigner>> for KeyPair {
    fn from(signer: Arc<dyn PrivateKeySigner>) -> Self {
        KeyPair {
            signer,
            hash_alg: None,
        }
    }
}

impl KeyPair {
    /// Creates a new key pair from a signer implementation.
    pub fn new<S: PrivateKeySigner + 'static>(signer: S) -> Self {
        KeyPair {
            signer: Arc::new(signer),
            hash_alg: None,
        }
    }

    /// Creates a new key pair from an Arc-wrapped signer.
    pub fn from_arc(signer: Arc<dyn PrivateKeySigner>) -> Self {
        KeyPair {
            signer,
            hash_alg: None,
        }
    }

    /// Returns the public key for this key pair.
    pub fn public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    /// Returns the SSH algorithm for this key.
    pub fn algorithm(&self) -> Algorithm {
        self.signer.public_key().algorithm().with_hash_alg(self.hash_alg)
    }

    /// Returns the base algorithm without hash algorithm override.
    /// This is useful for key compatibility checking.
    pub fn base_algorithm(&self) -> Algorithm {
        self.signer.public_key().algorithm()
    }

    /// Returns whether this is an RSA key.
    pub fn is_rsa(&self) -> bool {
        self.base_algorithm().is_rsa()
    }

    /// Returns the public key bytes in SSH wire format.
    pub fn public_key_bytes(&self) -> ssh_key::Result<Vec<u8>> {
        self.signer.public_key().to_bytes()
    }

    /// Signs the given data and returns the encoded signature bytes.
    ///
    /// The returned bytes are in SSH wire format, ready to be sent as a
    /// length-prefixed string in the protocol.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `_signature_hash_alg` - Reserved for future RSA hash algorithm selection
    pub async fn sign(
        &self,
        data: &[u8],
        _signature_hash_alg: Option<HashAlg>,
    ) -> Result<Vec<u8>, ssh_key::Error> {
        let signature = self.signer.sign(data).await?;
        signature.encoded()
    }

    /// Creates a clone of this key pair with a specific hash algorithm for RSA.
    ///
    /// For non-RSA keys, this returns a clone without modifications.
    pub fn with_hash_alg(&self, hash_alg: Option<HashAlg>) -> Self {
        KeyPair {
            signer: self.signer.clone(),
            hash_alg,
        }
    }
}

/// A wrapper that implements `PrivateKeySigner` for a local `PrivateKey`.
#[derive(Clone)]
pub struct LocalSigner {
    key: PrivateKey,
    public_key: PublicKey,
    hash_alg: Option<HashAlg>,
}

impl LocalSigner {
    /// Creates a new local signer from a private key.
    pub fn new(key: PrivateKey) -> Self {
        let public_key = key.public_key().clone();
        Self {
            key,
            public_key,
            hash_alg: None,
        }
    }

    /// Creates a new local signer with a specific hash algorithm for RSA.
    pub fn with_hash_alg(key: PrivateKey, hash_alg: Option<HashAlg>) -> Self {
        let public_key = key.public_key().clone();
        Self {
            key,
            public_key,
            hash_alg,
        }
    }
}

impl PrivateKeySigner for LocalSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, ssh_key::Error>> + Send + 'a>> {
        // Local signing is synchronous, wrap in a ready future
        let result = sign_local_key(&self.key, data, self.hash_alg);
        Box::pin(std::future::ready(result))
    }
}

/// Signs data using a local private key.
fn sign_local_key(
    key: &PrivateKey,
    data: &[u8],
    hash_alg: Option<HashAlg>,
) -> Result<Signature, ssh_key::Error> {
    match key.key_data() {
        #[cfg(feature = "rsa")]
        ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
            Ok(signature::Signer::try_sign(&(rsa_keypair, hash_alg), data)?)
        }
        keypair => Ok(signature::Signer::try_sign(keypair, data)?),
    }
}

/// A wrapper that adapts an [`crate::auth::Signer`] into a [`PrivateKeySigner`].
///
/// This allows using SSH agent clients or other `Signer` implementations as host keys.
/// The wrapper uses a `Mutex` internally since `Signer::auth_publickey_sign` takes `&mut self`.
///
/// # Example
///
/// ```ignore
/// use russh::keys::{KeyPair, SignerWrapper};
/// use russh::keys::agent::client::AgentClient;
///
/// // Connect to SSH agent and get keys
/// let mut agent = AgentClient::connect_env().await?;
/// let identities = agent.request_identities().await?;
/// let public_key = identities[0].clone();
///
/// // Wrap the agent as a PrivateKeySigner
/// let signer = SignerWrapper::new(agent, public_key, None);
/// let keypair = KeyPair::new(signer);
/// ```
pub struct SignerWrapper<S> {
    signer: Mutex<S>,
    public_key: PublicKey,
    hash_alg: Option<HashAlg>,
}

impl<S> SignerWrapper<S> {
    /// Creates a new wrapper around a `Signer`.
    ///
    /// # Arguments
    /// * `signer` - The signer to wrap (e.g., an SSH agent client)
    /// * `public_key` - The public key corresponding to this signer
    /// * `hash_alg` - Optional hash algorithm for RSA signatures
    pub fn new(signer: S, public_key: PublicKey, hash_alg: Option<HashAlg>) -> Self {
        Self {
            signer: Mutex::new(signer),
            public_key,
            hash_alg,
        }
    }
}

impl<S> PrivateKeySigner for SignerWrapper<S>
where
    S: crate::auth::Signer + Send + Sync + 'static,
    S::Error: std::fmt::Debug,
{
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, ssh_key::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut signer = self.signer.lock().await;
            let to_sign = CryptoVec::from_slice(data);

            let signature_bytes = signer
                .auth_publickey_sign(&self.public_key, self.hash_alg, to_sign)
                .await
                .map_err(|_| ssh_key::Error::Crypto)?;

            // The signature from auth_publickey_sign is already in SSH wire format
            // (algorithm name + signature blob), so we need to decode it
            decode_signature_from_wire(&signature_bytes)
        })
    }
}

/// Decodes an SSH signature from wire format (algorithm name string + signature blob).
fn decode_signature_from_wire(data: &[u8]) -> Result<Signature, ssh_key::Error> {
    use ssh_encoding::Decode;
    let mut reader = data;
    Signature::decode(&mut reader)
}
