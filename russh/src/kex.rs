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
use std::cell::RefCell;

use byteorder::{BigEndian, ByteOrder};
use rand::RngCore;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;

use crate::cipher::CIPHERS;
use crate::mac::{self, MACS};
use crate::session::Exchange;
use crate::{cipher, key, msg};

pub trait KexAlgorithm {
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error>;

    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error>;

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error>;

    fn compute_exchange_hash<K: key::PubKey>(
        &self,
        key: &K,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<crate::Sha256Hash, crate::Error>;

    fn compute_keys(
        &self,
        session_id: &crate::Sha256Hash,
        exchange_hash: &crate::Sha256Hash,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error>;
}

#[doc(hidden)]
pub struct Curve25519Kex {
    local_secret: Option<sodium::scalarmult::Scalar>,
    shared_secret: Option<sodium::scalarmult::GroupElement>,
}

impl std::fmt::Debug for Curve25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");

thread_local! {
    static KEY_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static NONCE_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static MAC_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html

impl Curve25519Kex {
    pub fn new() -> Self {
        Self {
            local_secret: None,
            shared_secret: None,
        }
    }
}
impl KexAlgorithm for Curve25519Kex {
    #[doc(hidden)]
    fn server_dh(
        &mut self,
        exchange: &mut Exchange,
        payload: &[u8],
    ) -> Result<(), crate::Error> {
        debug!("server_dh");

        let mut client_pubkey = GroupElement([0; 32]);
        {
            if payload.get(0) != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            client_pubkey
                .0
                .clone_from_slice(&payload[5..(5 + pubkey_len)])
        };
        debug!("client_pubkey: {:?}", client_pubkey);
        use sodium::scalarmult::*;
        let mut server_secret = Scalar([0; 32]);
        rand::thread_rng().fill_bytes(&mut server_secret.0);
        let server_pubkey = scalarmult_base(&server_secret);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        let shared = scalarmult(&server_secret, &client_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        use sodium::scalarmult::*;
        let mut client_secret = Scalar([0; 32]);
        rand::thread_rng().fill_bytes(&mut client_secret.0);
        let client_pubkey = scalarmult_base(&client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);

        self.local_secret =  Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret =
            std::mem::replace(&mut self.local_secret, None).ok_or(crate::Error::KexInit)?;

        use sodium::scalarmult::*;
        let mut remote_pubkey = GroupElement([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let shared = scalarmult(&local_secret, &remote_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    fn compute_exchange_hash<K: key::PubKey>(
        &self,
        key: &K,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<crate::Sha256Hash, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        key.push_to(buffer);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared.0);
        }

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&buffer);
        Ok(hasher.finalize())
    }

    fn compute_keys(
        &self,
        session_id: &crate::Sha256Hash,
        exchange_hash: &crate::Sha256Hash,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        compute_keys(
            self.shared_secret.as_ref().map(|x| x.0.as_slice()),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

pub fn compute_keys(
    shared_secret: Option<&[u8]>,
    session_id: &crate::Sha256Hash,
    exchange_hash: &crate::Sha256Hash,
    cipher: cipher::Name,
    remote_to_local_mac: mac::Name,
    local_to_remote_mac: mac::Name,
    is_server: bool,
) -> Result<super::cipher::CipherPair, crate::Error> {
    let cipher = CIPHERS.get(&cipher).ok_or(crate::Error::UnknownAlgo)?;
    let remote_to_local_mac = MACS
        .get(&remote_to_local_mac)
        .ok_or(crate::Error::UnknownAlgo)?;
    let local_to_remote_mac = MACS
        .get(&local_to_remote_mac)
        .ok_or(crate::Error::UnknownAlgo)?;

    // https://tools.ietf.org/html/rfc4253#section-7.2
    BUFFER.with(|buffer| {
        KEY_BUF.with(|key| {
            NONCE_BUF.with(|nonce| {
                MAC_BUF.with(|mac| {
                    let compute_key = |c, key: &mut CryptoVec, len| -> Result<(), crate::Error> {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        key.clear();

                        if let Some(ref shared) = shared_secret {
                            buffer.extend_ssh_mpint(&shared);
                        }

                        buffer.extend(exchange_hash.as_ref());
                        buffer.push(c);
                        buffer.extend(session_id.as_ref());
                        let hash = {
                            use sha2::Digest;
                            let mut hasher = sha2::Sha256::new();
                            hasher.update(&buffer[..]);
                            hasher.finalize()
                        };
                        key.extend(hash.as_ref());

                        while key.len() < len {
                            // extend.
                            buffer.clear();
                            if let Some(ref shared) = shared_secret {
                                buffer.extend_ssh_mpint(&shared);
                            }
                            buffer.extend(exchange_hash.as_ref());
                            buffer.extend(key);
                            let hash = {
                                use sha2::Digest;
                                let mut hasher = sha2::Sha256::new();
                                hasher.update(&buffer[..]);
                                hasher.finalize()
                            };
                            key.extend(hash.as_ref());
                        }

                        key.resize(len);
                        Ok(())
                    };

                    let (local_to_remote, remote_to_local) = if is_server {
                        (b'D', b'C')
                    } else {
                        (b'C', b'D')
                    };

                    let (local_to_remote_nonce, remote_to_local_nonce) = if is_server {
                        (b'B', b'A')
                    } else {
                        (b'A', b'B')
                    };

                    let (local_to_remote_mac_key, remote_to_local_mac_key) = if is_server {
                        (b'F', b'E')
                    } else {
                        (b'E', b'F')
                    };

                    let mut key = key.borrow_mut();
                    let mut nonce = nonce.borrow_mut();
                    let mut mac = mac.borrow_mut();

                    compute_key(local_to_remote, &mut key, cipher.key_len())?;
                    compute_key(local_to_remote_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        local_to_remote_mac_key,
                        &mut mac,
                        local_to_remote_mac.key_len(),
                    )?;

                    let local_to_remote =
                        cipher.make_sealing_key(&key, &nonce, &mac, *local_to_remote_mac);

                    compute_key(remote_to_local, &mut key, cipher.key_len())?;
                    compute_key(remote_to_local_nonce, &mut nonce, cipher.nonce_len())?;
                    compute_key(
                        remote_to_local_mac_key,
                        &mut mac,
                        remote_to_local_mac.key_len(),
                    )?;
                    let remote_to_local =
                        cipher.make_opening_key(&key, &nonce, &mac, *remote_to_local_mac);

                    Ok(super::cipher::CipherPair {
                        local_to_remote,
                        remote_to_local,
                    })
                })
            })
        })
    })
}
