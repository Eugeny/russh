use openssl::pkey::HasPublic;
use openssl::rsa::Rsa;
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
use russh_cryptovec::CryptoVec;
use russh_keys::deps::ecdsa::elliptic_curve;
use russh_keys::deps::ed25519_dalek;
use russh_keys::deps::p256::NistP256;
use russh_keys::encoding::*;
use russh_keys::key::*;
use russh_keys::PublicKeyBase64;

#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoVec);
}

impl PubKey for ed25519_dalek::VerifyingKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        buffer.push_u32_be((ED25519.0.len() + self.as_bytes().len() + 8) as u32);
        buffer.extend_ssh_string(ED25519.0.as_bytes());
        buffer.extend_ssh_string(self.as_bytes());
    }
}

impl PubKey for elliptic_curve::PublicKey<NistP256> {
    fn push_to(&self, buffer: &mut CryptoVec) {
        let public = self.to_sec1_bytes();
        buffer.push_u32_be((ECDSA_SHA2_NISTP256.0.len() + public.len() + 20) as u32);
        buffer.extend_ssh_string(ECDSA_SHA2_NISTP256.0.as_bytes());
        buffer.extend_ssh_string(b"nistp256");
        buffer.extend_ssh_string(&public);
    }
}

#[cfg(feature = "openssl")]
impl<T> PubKey for Rsa<T>
where
    T: HasPublic,
{
    fn push_to(&self, buffer: &mut CryptoVec) {
        let e = self.e().to_vec();
        let n = self.n().to_vec();
        buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
        buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
        buffer.extend_ssh_mpint(&e);
        buffer.extend_ssh_mpint(&n);
    }
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            PublicKey::Ed25519(ref key) => key.push_to(buffer),
            PublicKey::P256(ref key) => key.push_to(buffer),
            #[cfg(feature = "openssl")]
            #[allow(clippy::unwrap_used)] // type known
            PublicKey::RSA { ref key, .. } => key.0.rsa().unwrap().push_to(buffer),
        }
    }
}

impl PubKey for KeyPair {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            KeyPair::Ed25519(ref key) => key.verifying_key().push_to(buffer),
            KeyPair::EcdsaSha2NistP256(ref key) => key.public_key().push_to(buffer),
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, .. } => key.push_to(buffer),
        }
    }
}
