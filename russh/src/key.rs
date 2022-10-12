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
use russh_keys::encoding::*;
use russh_keys::key::*;

#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoVec);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            #[cfg(feature = "rs-crypto")]
            PublicKey::Ed25519(ref public) => {
                buffer.push_u32_be((ED25519.0.len() + public.as_bytes().len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
            #[cfg(feature = "openssl")]
            PublicKey::RSA { ref key, .. } => {
                #[allow(clippy::unwrap_used)] // type known
                let rsa = key.0.rsa().unwrap();
                let e = rsa.e().to_vec();
                let n = rsa.n().to_vec();
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
        }
    }
}

impl PubKey for KeyPair {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            #[cfg(feature = "rs-crypto")]
            KeyPair::Ed25519(ref key) => {
                let public = key.public.as_bytes();
                buffer.push_u32_be((ED25519.0.len() + public.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public);
            }
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref key, .. } => {
                let e = key.e().to_vec();
                let n = key.n().to_vec();
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
        }
    }
}
