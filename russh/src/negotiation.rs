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
use std::borrow::Cow;

use log::debug;
use rand::RngCore;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};

use crate::cipher::CIPHERS;
use crate::helpers::NameList;
use crate::kex::{
    EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT, EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER, KexCause,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::server::Config;
use crate::sshbuffer::PacketWriter;
use crate::{AlgorithmKind, CryptoVec, Error, cipher, compression, kex, mac, msg};

#[cfg(target_arch = "wasm32")]
/// WASM-only stub
pub struct Config {
    keys: Vec<PrivateKey>,
}

#[derive(Debug, Clone)]
pub struct Names {
    pub kex: kex::Name,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub key: Algorithm,
    pub cipher: cipher::Name,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub server_compression: compression::Compression,
    pub client_compression: compression::Compression,
    pub ignore_guessed: bool,
    // Prevent accidentally contructing [Names] without a [KeyCause]
    // as strict kext algo is not sent during a rekey and hence the state
    // of [strict_kex] cannot be known without a [KexCause].
    strict_kex: bool,
}

impl Names {
    pub fn strict_kex(&self) -> bool {
        self.strict_kex
    }
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug, Clone)]
pub struct Preferred {
    /// Preferred key exchange algorithms.
    pub kex: Cow<'static, [kex::Name]>,
    /// Preferred host & public key algorithms.
    pub key: Cow<'static, [Algorithm]>,
    /// Preferred symmetric ciphers.
    pub cipher: Cow<'static, [cipher::Name]>,
    /// Preferred MAC algorithms.
    pub mac: Cow<'static, [mac::Name]>,
    /// Preferred compression algorithms.
    pub compression: Cow<'static, [compression::Name]>,
}

pub(crate) fn is_key_compatible_with_algo(key: &PrivateKey, algo: &Algorithm) -> bool {
    match algo {
        // All RSA keys are compatible with all RSA based algos.
        Algorithm::Rsa { .. } => key.algorithm().is_rsa(),
        // Other keys have to match exactly
        a => key.algorithm() == *a,
    }
}

impl Preferred {
    pub(crate) fn possible_host_key_algos_for_keys(
        &self,
        available_host_keys: &[PrivateKey],
    ) -> Vec<Algorithm> {
        self.key
            .iter()
            .filter(|n| {
                available_host_keys
                    .iter()
                    .any(|k| is_key_compatible_with_algo(k, n))
            })
            .cloned()
            .collect::<Vec<_>>()
    }
}

const SAFE_KEX_ORDER: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const KEX_EXTENSION_NAMES: &[kex::Name] = &[
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
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa { hash: None },
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

pub(crate) fn parse_kex_algo_list(list: &str) -> Vec<&str> {
    list.split(',').collect()
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
        available_host_keys: Option<&[PrivateKey]>,
        cause: &KexCause,
    ) -> Result<Names, Error> {
        let &Some(mut r) = &buffer.get(17..) else {
            return Err(Error::Inconsistent);
        };

        // Key exchange

        let kex_string = String::decode(&mut r)?;
        // Filter out extension kex names from both lists before selecting
        let _local_kexes_no_ext = pref
            .kex
            .iter()
            .filter(|k| !KEX_EXTENSION_NAMES.contains(k))
            .cloned()
            .collect::<Vec<_>>();
        let _remote_kexes_no_ext = parse_kex_algo_list(&kex_string)
            .into_iter()
            .filter(|k| {
                kex::Name::try_from(*k)
                    .ok()
                    .map(|k| !KEX_EXTENSION_NAMES.contains(&k))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        let (kex_both_first, kex_algorithm) = Self::select(
            &_local_kexes_no_ext,
            &_remote_kexes_no_ext,
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
            &parse_kex_algo_list(&kex_string),
            AlgorithmKind::Kex,
        )
        .is_ok();

        if strict_kex_requested && strict_kex_provided {
            debug!("strict kex enabled")
        }

        // Host key

        let key_string = String::decode(&mut r)?;
        let possible_host_key_algos = match available_host_keys {
            Some(available_host_keys) => pref.possible_host_key_algos_for_keys(available_host_keys),
            None => pref.key.iter().map(ToOwned::to_owned).collect::<Vec<_>>(),
        };

        let (key_both_first, key_algorithm) = Self::select(
            &possible_host_key_algos[..],
            &parse_kex_algo_list(&key_string),
            AlgorithmKind::Key,
        )?;

        // Cipher

        let cipher_string = String::decode(&mut r)?;
        let (_cipher_both_first, cipher) = Self::select(
            &pref.cipher,
            &parse_kex_algo_list(&cipher_string),
            AlgorithmKind::Cipher,
        )?;
        String::decode(&mut r)?; // cipher server-to-client.

        // MAC

        let need_mac = CIPHERS.get(&cipher).map(|x| x.needs_mac()).unwrap_or(false);

        let client_mac = match Self::select(
            &pref.mac,
            &parse_kex_algo_list(&String::decode(&mut r)?),
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
            &parse_kex_algo_list(&String::decode(&mut r)?),
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

        // client-to-server compression.
        let client_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &parse_kex_algo_list(&String::decode(&mut r)?),
                AlgorithmKind::Compression,
            )?
            .1,
        );

        // server-to-client compression.
        let server_compression = compression::Compression::new(
            &Self::select(
                &pref.compression,
                &parse_kex_algo_list(&String::decode(&mut r)?),
                AlgorithmKind::Compression,
            )?
            .1,
        );
        String::decode(&mut r)?; // languages client-to-server
        String::decode(&mut r)?; // languages server-to-client

        let follows = u8::decode(&mut r)? != 0;
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
            strict_kex: (strict_kex_requested && strict_kex_provided) || cause.is_strict_rekey(),
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

pub(crate) fn write_kex(
    prefs: &Preferred,
    writer: &mut PacketWriter,
    server_config: Option<&Config>,
) -> Result<CryptoVec, Error> {
    writer.packet(|w| {
        // buf.clear();
        msg::KEXINIT.encode(w)?;

        let mut cookie = [0; 16];
        rand::thread_rng().fill_bytes(&mut cookie);
        for b in cookie {
            b.encode(w)?;
        }

        NameList(
            prefs
                .kex
                .iter()
                .filter(|k| {
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
                })
                .map(|x| x.as_ref().to_owned())
                .collect(),
        )
        .encode(w)?; // kex algo

        if let Some(server_config) = server_config {
            // Only advertise host key algorithms that we have keys for.
            NameList(
                prefs
                    .key
                    .iter()
                    .filter(|algo| {
                        server_config
                            .keys
                            .iter()
                            .any(|k| is_key_compatible_with_algo(k, algo))
                    })
                    .map(|x| x.to_string())
                    .collect(),
            )
            .encode(w)?;
        } else {
            NameList(prefs.key.iter().map(ToString::to_string).collect()).encode(w)?;
        }

        // cipher client to server
        NameList(
            prefs
                .cipher
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // cipher server to client
        NameList(
            prefs
                .cipher
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // mac client to server
        NameList(prefs.mac.iter().map(|x| x.as_ref().to_string()).collect()).encode(w)?;

        // mac server to client
        NameList(prefs.mac.iter().map(|x| x.as_ref().to_string()).collect()).encode(w)?;

        // compress client to server
        NameList(
            prefs
                .compression
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        // compress server to client
        NameList(
            prefs
                .compression
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
        )
        .encode(w)?;

        Vec::<String>::new().encode(w)?; // languages client to server
        Vec::<String>::new().encode(w)?; // languages server to client

        0u8.encode(w)?; // doesn't follow
        0u32.encode(w)?; // reserved
        Ok(())
    })
}
