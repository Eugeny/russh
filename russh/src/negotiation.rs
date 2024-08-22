use std::borrow::Cow;
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

use crate::cipher::CIPHERS;
use crate::kex::{EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT, EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER};
use crate::keys::encoding::{Encoding, Reader};
use crate::keys::key;
use crate::keys::key::{KeyPair, PublicKey};
use crate::server::Config;
use crate::{cipher, compression, kex, mac, msg, AlgorithmKind, CryptoVec, Error};

#[derive(Debug, Clone)]
pub struct Names {
    pub kex: kex::Name,
    pub key: key::Name,
    pub cipher: cipher::Name,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub server_compression: compression::Compression,
    pub client_compression: compression::Compression,
    pub ignore_guessed: bool,
    pub strict_kex: bool,
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug, Clone)]
pub struct Preferred {
    /// Preferred key exchange algorithms.
    pub kex: Cow<'static, [kex::Name]>,
    /// Preferred host & public key algorithms.
    pub key: Cow<'static, [key::Name]>,
    /// Preferred symmetric ciphers.
    pub cipher: Cow<'static, [cipher::Name]>,
    /// Preferred MAC algorithms.
    pub mac: Cow<'static, [mac::Name]>,
    /// Preferred compression algorithms.
    pub compression: Cow<'static, [compression::Name]>,
}

impl Preferred {
    pub(crate) fn possible_host_key_algos_for_keys(
        &self,
        available_host_keys: &[KeyPair],
    ) -> Vec<key::Name> {
        self.key
            .iter()
            .filter(|n| available_host_keys.iter().any(|k| k.name() == n.0))
            .copied()
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

const COMPRESSION_ORDER: &[compression::Name] = &[
    compression::NONE,
    #[cfg(feature = "flate2")]
    compression::ZLIB,
    #[cfg(feature = "flate2")]
    compression::ZLIB_LEGACY,
];

impl Preferred {
    pub const DEFAULT: Preferred = Preferred {
        kex: Cow::Borrowed(SAFE_KEX_ORDER),
        key: Cow::Borrowed(&[
            key::ED25519,
            key::ECDSA_SHA2_NISTP256,
            key::ECDSA_SHA2_NISTP521,
            key::RSA_SHA2_256,
            key::RSA_SHA2_512,
        ]),
        cipher: Cow::Borrowed(CIPHER_ORDER),
        mac: Cow::Borrowed(HMAC_ORDER),
        compression: Cow::Borrowed(COMPRESSION_ORDER),
    };

    pub const COMPRESSED: Preferred = Preferred {
        kex: Cow::Borrowed(SAFE_KEX_ORDER),
        key: Preferred::DEFAULT.key,
        cipher: Cow::Borrowed(CIPHER_ORDER),
        mac: Cow::Borrowed(HMAC_ORDER),
        compression: Cow::Borrowed(COMPRESSION_ORDER),
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

use crate::keys::key::ED25519;

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

pub(crate) fn parse_kex_algo_list(list: &[u8]) -> Vec<&str> {
    list.split(|&x| x == b',')
        .map(|x| from_utf8(x).unwrap_or_default())
        .collect()
}

pub(crate) trait Select {
    fn is_server() -> bool;

    fn select<S: AsRef<str> + Clone>(
        a: &[S],
        b: &[&str],
        kind: AlgorithmKind,
    ) -> Result<(bool, S), Error>;

    /// `available_host_keys`, if present, is used to limit the host key algorithms to the ones we have keys for.
    fn read_kex(
        buffer: &[u8],
        pref: &Preferred,
        available_host_keys: Option<&[KeyPair]>,
    ) -> Result<Names, Error> {
        let mut r = buffer.reader(17);

        // Key exchange

        let kex_string = r.read_string()?;
        let (kex_both_first, kex_algorithm) = Self::select(
            &pref.kex,
            &parse_kex_algo_list(kex_string),
            AlgorithmKind::Kex,
        )?;

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
            &parse_kex_algo_list(kex_string),
            AlgorithmKind::Kex,
        )
        .is_ok();
        if strict_kex_requested && strict_kex_provided {
            debug!("strict kex enabled")
        }

        // Host key

        let key_string: &[u8] = r.read_string()?;
        let possible_host_key_algos = match available_host_keys {
            Some(available_host_keys) => pref.possible_host_key_algos_for_keys(available_host_keys),
            None => pref.key.iter().map(ToOwned::to_owned).collect::<Vec<_>>(),
        };

        let (key_both_first, key_algorithm) = Self::select(
            &possible_host_key_algos[..],
            &parse_kex_algo_list(key_string),
            AlgorithmKind::Key,
        )?;

        // Cipher

        let cipher_string = r.read_string()?;
        let (_cipher_both_first, cipher) = Self::select(
            &pref.cipher,
            &parse_kex_algo_list(cipher_string),
            AlgorithmKind::Cipher,
        )?;
        r.read_string()?; // cipher server-to-client.
        debug!("kex {}", line!());

        // MAC

        let need_mac = CIPHERS.get(&cipher).map(|x| x.needs_mac()).unwrap_or(false);

        let client_mac = match Self::select(
            &pref.mac,
            &parse_kex_algo_list(r.read_string()?),
            AlgorithmKind::Mac,
        ) {
            Ok((_, m)) => m,
            Err(e) => {
                if need_mac {
                    return Err(e);
                } else {
                    mac::NONE
                }
            }
        };
        let server_mac = match Self::select(
            &pref.mac,
            &parse_kex_algo_list(r.read_string()?),
            AlgorithmKind::Mac,
        ) {
            Ok((_, m)) => m,
            Err(e) => {
                if need_mac {
                    return Err(e);
                } else {
                    mac::NONE
                }
            }
        };

        // Compression

        debug!("kex {}", line!());
        // client-to-server compression.
        let client_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &parse_kex_algo_list(r.read_string()?),
                AlgorithmKind::Compression,
            )?
            .1,
        );

        debug!("kex {}", line!());
        // server-to-client compression.
        let server_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &parse_kex_algo_list(r.read_string()?),
                AlgorithmKind::Compression,
            )?
            .1,
        );
        debug!("client_compression = {:?}", client_compression);
        r.read_string()?; // languages client-to-server
        r.read_string()?; // languages server-to-client

        let follows = r.read_byte()? != 0;
        Ok(Names {
            kex: kex_algorithm,
            key: key_algorithm,
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

    fn select<S: AsRef<str> + Clone>(
        server_list: &[S],
        client_list: &[&str],
        kind: AlgorithmKind,
    ) -> Result<(bool, S), Error> {
        let mut both_first_choice = true;
        for c in client_list {
            for s in server_list {
                if c == &s.as_ref() {
                    return Ok((both_first_choice, s.clone()));
                }
                both_first_choice = false
            }
        }
        Err(Error::NoCommonAlgo {
            kind,
            ours: server_list.iter().map(|x| x.as_ref().to_owned()).collect(),
            theirs: client_list.iter().map(|x| (*x).to_owned()).collect(),
        })
    }
}

impl Select for Client {
    fn is_server() -> bool {
        false
    }

    fn select<S: AsRef<str> + Clone>(
        client_list: &[S],
        server_list: &[&str],
        kind: AlgorithmKind,
    ) -> Result<(bool, S), Error> {
        let mut both_first_choice = true;
        for c in client_list {
            for s in server_list {
                if s == &c.as_ref() {
                    return Ok((both_first_choice, c.clone()));
                }
                both_first_choice = false
            }
        }
        Err(Error::NoCommonAlgo {
            kind,
            ours: client_list.iter().map(|x| x.as_ref().to_owned()).collect(),
            theirs: server_list.iter().map(|x| (*x).to_owned()).collect(),
        })
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
