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
use russh_keys::protocol;

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
            PublicKey::RSA { ref key, .. } => {
                buffer.extend_wrapped(|buffer| {
                    buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                    buffer.extend_ssh(&protocol::RsaPublicKey::from(key));
                });
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
            KeyPair::RSA { ref key, .. } => {
                buffer.extend_wrapped(|buffer| {
                    buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                    buffer.extend_ssh(&protocol::RsaPublicKey::from(key));
                });
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
