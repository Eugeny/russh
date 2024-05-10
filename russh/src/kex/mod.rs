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

//!
//! This module exports kex algorithm names for use with [Preferred].
mod curve25519;
mod dh;
mod ecdh_nistp;
mod none;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;

use curve25519::Curve25519KexType;
use dh::{
    DhGroup14Sha1KexType, DhGroup14Sha256KexType, DhGroup16Sha512KexType, DhGroup1Sha1KexType,
};
use digest::Digest;
use ecdh_nistp::{EcdhNistP256KexType, EcdhNistP384KexType, EcdhNistP521KexType};
use once_cell::sync::Lazy;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;

use crate::cipher;
use crate::cipher::CIPHERS;
use crate::mac::{self, MACS};
use crate::session::Exchange;

pub(crate) trait KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send>;
}

impl Debug for dyn KexAlgorithm + Send {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KexAlgorithm")
    }
}

pub(crate) trait KexAlgorithm {
    fn skip_exchange(&self) -> bool;

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error>;

    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error>;

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error>;

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error>;

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error>;
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// `curve25519-sha256`
pub const CURVE25519: Name = Name("curve25519-sha256");
/// `curve25519-sha256@libssh.org`
pub const CURVE25519_PRE_RFC_8731: Name = Name("curve25519-sha256@libssh.org");
/// `diffie-hellman-group1-sha1`
pub const DH_G1_SHA1: Name = Name("diffie-hellman-group1-sha1");
/// `diffie-hellman-group14-sha1`
pub const DH_G14_SHA1: Name = Name("diffie-hellman-group14-sha1");
/// `diffie-hellman-group14-sha256`
pub const DH_G14_SHA256: Name = Name("diffie-hellman-group14-sha256");
/// `diffie-hellman-group16-sha512`
pub const DH_G16_SHA512: Name = Name("diffie-hellman-group16-sha512");
/// `ecdh-sha2-nistp256`
pub const ECDH_SHA2_NISTP256: Name = Name("ecdh-sha2-nistp256");
/// `ecdh-sha2-nistp384`
pub const ECDH_SHA2_NISTP384: Name = Name("ecdh-sha2-nistp384");
/// `ecdh-sha2-nistp521`
pub const ECDH_SHA2_NISTP521: Name = Name("ecdh-sha2-nistp521");
/// `none`
pub const NONE: Name = Name("none");
/// `ext-info-c`
pub const EXTENSION_SUPPORT_AS_CLIENT: Name = Name("ext-info-c");
/// `ext-info-s`
pub const EXTENSION_SUPPORT_AS_SERVER: Name = Name("ext-info-s");
/// `kex-strict-c-v00@openssh.com`
pub const EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT: Name = Name("kex-strict-c-v00@openssh.com");
/// `kex-strict-s-v00@openssh.com`
pub const EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER: Name = Name("kex-strict-s-v00@openssh.com");

const _CURVE25519: Curve25519KexType = Curve25519KexType {};
const _DH_G1_SHA1: DhGroup1Sha1KexType = DhGroup1Sha1KexType {};
const _DH_G14_SHA1: DhGroup14Sha1KexType = DhGroup14Sha1KexType {};
const _DH_G14_SHA256: DhGroup14Sha256KexType = DhGroup14Sha256KexType {};
const _DH_G16_SHA512: DhGroup16Sha512KexType = DhGroup16Sha512KexType {};
const _ECDH_SHA2_NISTP256: EcdhNistP256KexType = EcdhNistP256KexType {};
const _ECDH_SHA2_NISTP384: EcdhNistP384KexType = EcdhNistP384KexType {};
const _ECDH_SHA2_NISTP521: EcdhNistP521KexType = EcdhNistP521KexType {};
const _NONE: none::NoneKexType = none::NoneKexType {};

pub(crate) static KEXES: Lazy<HashMap<&'static Name, &(dyn KexType + Send + Sync)>> =
    Lazy::new(|| {
        let mut h: HashMap<&'static Name, &(dyn KexType + Send + Sync)> = HashMap::new();
        h.insert(&CURVE25519, &_CURVE25519);
        h.insert(&CURVE25519_PRE_RFC_8731, &_CURVE25519);
        h.insert(&DH_G16_SHA512, &_DH_G16_SHA512);
        h.insert(&DH_G14_SHA256, &_DH_G14_SHA256);
        h.insert(&DH_G14_SHA1, &_DH_G14_SHA1);
        h.insert(&DH_G1_SHA1, &_DH_G1_SHA1);
        h.insert(&ECDH_SHA2_NISTP256, &_ECDH_SHA2_NISTP256);
        h.insert(&ECDH_SHA2_NISTP384, &_ECDH_SHA2_NISTP384);
        h.insert(&ECDH_SHA2_NISTP521, &_ECDH_SHA2_NISTP521);
        h.insert(&NONE, &_NONE);
        h
    });

thread_local! {
    static KEY_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static NONCE_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static MAC_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

pub(crate) fn compute_keys<D: Digest>(
    shared_secret: Option<&[u8]>,
    session_id: &CryptoVec,
    exchange_hash: &CryptoVec,
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

                        if let Some(shared) = shared_secret {
                            buffer.extend_ssh_mpint(shared);
                        }

                        buffer.extend(exchange_hash.as_ref());
                        buffer.push(c);
                        buffer.extend(session_id.as_ref());
                        let hash = {
                            let mut hasher = D::new();
                            hasher.update(&buffer[..]);
                            hasher.finalize()
                        };
                        key.extend(hash.as_ref());

                        while key.len() < len {
                            // extend.
                            buffer.clear();
                            if let Some(shared) = shared_secret {
                                buffer.extend_ssh_mpint(shared);
                            }
                            buffer.extend(exchange_hash.as_ref());
                            buffer.extend(key);
                            let hash = {
                                let mut hasher = D::new();
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
