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
use russh_keys::ec;
use russh_keys::encoding::*;
use russh_keys::key::*;

#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoVec);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            PublicKey::Ed25519(ref public) => {
                buffer.push_u32_be((ED25519.0.len() + public.as_bytes().len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
            #[allow(unused_assignments)]
            PublicKey::RSA { ref key, .. } => {
                let mut e = Vec::new();
                let mut n = Vec::new();

                #[cfg(feature = "openssl")]
                #[allow(clippy::unwrap_used)] // type known
                {
                    let rsa = key.0.rsa().unwrap();
                    e = rsa.e().to_vec();
                    n = rsa.n().to_vec();
                }
                #[cfg(not(feature = "openssl"))]
                {
                    use russh_keys::PublicKeyParts;
                    let rsa = key.clone();
                    e = rsa.e().to_bytes_be();
                    n = rsa.n().to_bytes_be();
                }
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
            PublicKey::EC { ref key } => {
                write_ec_public_key(buffer, key);
            }
        }
    }
}

impl PubKey for KeyPair {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            KeyPair::Ed25519(ref key) => {
                let public = key.verifying_key().to_bytes();
                buffer.push_u32_be((ED25519.0.len() + public.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public.as_slice());
            }
            #[allow(unused_assignments)]
            KeyPair::RSA { ref key, .. } => {
                let mut e = Vec::new();
                let mut n = Vec::new();
                #[cfg(feature = "openssl")]
                {
                    e = key.e().to_vec();
                    n = key.n().to_vec();
                }

                #[cfg(not(feature = "openssl"))]
                {
                    use russh_keys::PublicKeyParts;
                    e = key.e().to_bytes_be();
                    n = key.n().to_bytes_be();
                }
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
            KeyPair::EC { ref key } => {
                write_ec_public_key(buffer, &key.to_public_key());
            }
        }
    }
}

pub(crate) fn write_ec_public_key(buf: &mut CryptoVec, key: &ec::PublicKey) {
    let algorithm = key.algorithm().as_bytes();
    let ident = key.ident().as_bytes();
    let q = key.to_sec1_bytes();

    buf.push_u32_be((algorithm.len() + ident.len() + q.len() + 12) as u32);
    buf.extend_ssh_string(algorithm);
    buf.extend_ssh_string(ident);
    buf.extend_ssh_string(&q);
}
