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
use std::str::from_utf8;

use log::debug;
use rand::RngCore;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::{Encoding, Reader};
use russh_keys::key;
use russh_keys::key::{KeyPair, PublicKey};

use crate::cipher::CIPHERS;
use crate::compression::*;
use crate::kex::{EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT, EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER};
use crate::server::Config;
use crate::{cipher, kex, mac, msg, Error};

#[derive(Debug, Clone)]
pub struct Names {
    pub kex: kex::Name,
    pub key: key::Name,
    pub cipher: cipher::Name,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub server_compression: Compression,
    pub client_compression: Compression,
    pub ignore_guessed: bool,
    pub strict_kex: bool,
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug, Clone)]
pub struct Preferred {
    /// Preferred key exchange algorithms.
    pub kex: &'static [kex::Name],
    /// Preferred host & public key algorithms.
    pub key: &'static [key::Name],
    /// Preferred symmetric ciphers.
    pub cipher: &'static [cipher::Name],
    /// Preferred MAC algorithms.
    pub mac: &'static [mac::Name],
    /// Preferred compression algorithms.
    pub compression: &'static [&'static str],
}

impl Preferred {
    pub(crate) fn possible_host_key_algos_for_keys(
        &self,
        available_host_keys: &[KeyPair],
    ) -> Vec<&'static key::Name> {
        self.key
            .iter()
            .filter(|n| available_host_keys.iter().any(|k| k.name() == n.0))
            .collect::<Vec<_>>()
    }
}

const SAFE_KEX_ORDER: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_G16_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const CIPHER_ORDER: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];

const HMAC_ORDER: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA1,
];

impl Preferred {
    pub const DEFAULT: Preferred = Preferred {
        kex: SAFE_KEX_ORDER,
        key: &[
            key::ED25519,
            key::ECDSA_SHA2_NISTP256,
            key::ECDSA_SHA2_NISTP521,
            key::RSA_SHA2_256,
            key::RSA_SHA2_512,
        ],
        cipher: CIPHER_ORDER,
        mac: HMAC_ORDER,
        compression: &["none", "zlib", "zlib@openssh.com"],
    };

    pub const COMPRESSED: Preferred = Preferred {
        kex: SAFE_KEX_ORDER,
        key: Preferred::DEFAULT.key,
        cipher: CIPHER_ORDER,
        mac: HMAC_ORDER,
        compression: &["zlib", "zlib@openssh.com", "none"],
    };
}

impl Default for Preferred {
    fn default() -> Preferred {
        Preferred::DEFAULT
    }
}

/// Named algorithms.
pub trait Named {
    /// The name of this algorithm.
    fn name(&self) -> &'static str;
}

impl Named for () {
    fn name(&self) -> &'static str {
        ""
    }
}

use russh_keys::key::ED25519;

impl Named for PublicKey {
    fn name(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => ED25519.0,
            PublicKey::RSA { ref hash, .. } => hash.name().0,
            PublicKey::EC { ref key } => key.algorithm(),
        }
    }
}

impl Named for KeyPair {
    fn name(&self) -> &'static str {
        match self {
            KeyPair::Ed25519 { .. } => ED25519.0,
            KeyPair::RSA { ref hash, .. } => hash.name().0,
            KeyPair::EC { ref key } => key.algorithm(),
        }
    }
}

pub(crate) trait Select {
    fn is_server() -> bool;

    fn select<S: AsRef<str> + Copy>(a: &[S], b: &[u8]) -> Option<(bool, S)>;

    /// `available_host_keys`, if present, is used to limit the host key algorithms to the ones we have keys for.
    fn read_kex(
        buffer: &[u8],
        pref: &Preferred,
        available_host_keys: Option<&[KeyPair]>,
    ) -> Result<Names, Error> {
        let mut r = buffer.reader(17);

        // Key exchange

        let kex_string = r.read_string()?;
        let (kex_both_first, kex_algorithm) = Self::select(pref.kex, kex_string).ok_or_else(||
        {
            debug!(
                "Could not find common kex algorithm, other side only supports {:?}, we only support {:?}",
                from_utf8(kex_string),
                pref.kex
            );
            Error::NoCommonKexAlgo
        })?;

        // Strict kex detection

        let strict_kex_requested = pref.kex.contains(if Self::is_server() {
            &EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER
        } else {
            &EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT
        });
        let strict_kex_provided = Self::select(
            &[if Self::is_server() {
                EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT
            } else {
                EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER
            }],
            kex_string,
        )
        .is_some();
        if strict_kex_requested && strict_kex_provided {
            debug!("strict kex enabled")
        }

        // Host key

        let key_string: &[u8] = r.read_string()?;
        let possible_host_key_algos = match available_host_keys {
            Some(available_host_keys) => pref.possible_host_key_algos_for_keys(available_host_keys),
            None => pref.key.iter().collect::<Vec<_>>(),
        };

        let (key_both_first, key_algorithm) =
            Self::select(&possible_host_key_algos[..], key_string).ok_or_else(|| {
                debug!(
                    "Could not find common key algorithm, other side only supports {:?}, we only support {:?}",
                    from_utf8(key_string),
                    pref.key
                );
                Error::NoCommonKeyAlgo
            })?;

        // Cipher

        let cipher_string = r.read_string()?;
        let (_cipher_both_first, cipher) =
            Self::select(pref.cipher, cipher_string).ok_or_else(|| {
                debug!(
                "Could not find common cipher, other side only supports {:?}, we only support {:?}",
                from_utf8(cipher_string),
                pref.cipher
            );
                Error::NoCommonCipher
            })?;
        r.read_string()?; // cipher server-to-client.
        debug!("kex {}", line!());

        // MAC

        let need_mac = CIPHERS.get(&cipher).map(|x| x.needs_mac()).unwrap_or(false);

        let client_mac = if let Some((_, m)) = Self::select(pref.mac, r.read_string()?) {
            m
        } else if need_mac {
            return Err(Error::NoCommonMac);
        } else {
            mac::NONE
        };
        let server_mac = if let Some((_, m)) = Self::select(pref.mac, r.read_string()?) {
            m
        } else if need_mac {
            return Err(Error::NoCommonMac);
        } else {
            mac::NONE
        };

        // Compression

        debug!("kex {}", line!());
        // client-to-server compression.
        let client_compression =
            if let Some((_, c)) = Self::select(pref.compression, r.read_string()?) {
                Compression::from_string(c)
            } else {
                return Err(Error::NoCommonCompression);
            };
        debug!("kex {}", line!());
        // server-to-client compression.
        let server_compression =
            if let Some((_, c)) = Self::select(pref.compression, r.read_string()?) {
                Compression::from_string(c)
            } else {
                return Err(Error::NoCommonCompression);
            };
        debug!("client_compression = {:?}", client_compression);
        r.read_string()?; // languages client-to-server
        r.read_string()?; // languages server-to-client

        let follows = r.read_byte()? != 0;
        Ok(Names {
            kex: kex_algorithm,
            key: *key_algorithm,
            cipher,
            client_mac,
            server_mac,
            client_compression,
            server_compression,
            // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
            ignore_guessed: follows && !(kex_both_first && key_both_first),
            strict_kex: strict_kex_requested && strict_kex_provided,
        })
    }
}

pub struct Server;
pub struct Client;

impl Select for Server {
    fn is_server() -> bool {
        true
    }

    fn select<S: AsRef<str> + Copy>(server_list: &[S], client_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for c in client_list.split(|&x| x == b',') {
            for &s in server_list {
                if c == s.as_ref().as_bytes() {
                    return Some((both_first_choice, s));
                }
                both_first_choice = false
            }
        }
        None
    }
}

impl Select for Client {
    fn is_server() -> bool {
        false
    }

    fn select<S: AsRef<str> + Copy>(client_list: &[S], server_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for &c in client_list {
            for s in server_list.split(|&x| x == b',') {
                if s == c.as_ref().as_bytes() {
                    return Some((both_first_choice, c));
                }
                both_first_choice = false
            }
        }
        None
    }
}

pub fn write_kex(
    prefs: &Preferred,
    buf: &mut CryptoVec,
    server_config: Option<&Config>,
) -> Result<(), Error> {
    // buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0; 16];
    rand::thread_rng().fill_bytes(&mut cookie);

    buf.extend(&cookie); // cookie
    buf.extend_list(prefs.kex.iter().filter(|k| {
        !(if server_config.is_some() {
            [
                crate::kex::EXTENSION_SUPPORT_AS_CLIENT,
                crate::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ]
        } else {
            [
                crate::kex::EXTENSION_SUPPORT_AS_SERVER,
                crate::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
            ]
        })
        .contains(*k)
    })); // kex algo

    if let Some(server_config) = server_config {
        // Only advertise host key algorithms that we have keys for.
        buf.extend_list(
            prefs
                .key
                .iter()
                .filter(|name| server_config.keys.iter().any(|k| k.name() == name.0)),
        );
    } else {
        buf.extend_list(prefs.key.iter());
    }

    buf.extend_list(prefs.cipher.iter()); // cipher client to server
    buf.extend_list(prefs.cipher.iter()); // cipher server to client

    buf.extend_list(prefs.mac.iter()); // mac client to server
    buf.extend_list(prefs.mac.iter()); // mac server to client
    buf.extend_list(prefs.compression.iter()); // compress client to server
    buf.extend_list(prefs.compression.iter()); // compress server to client

    buf.write_empty_list(); // languages client to server
    buf.write_empty_list(); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0, 0, 0, 0]); // reserved
    Ok(())
}
