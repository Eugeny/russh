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
//! This module exports cipher names for use with [Preferred].
use std::collections::HashMap;
use std::marker::PhantomData;

use digest::typenum::{U20, U32, U64};
use hmac::Hmac;
use once_cell::sync::Lazy;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use self::crypto::CryptoMacAlgorithm;
use self::crypto_etm::CryptoEtmMacAlgorithm;
use self::none::NoMacAlgorithm;

mod crypto;
mod crypto_etm;
mod none;

pub(crate) trait MacAlgorithm {
    fn key_len(&self) -> usize;
    fn make_mac(&self, key: &[u8]) -> Box<dyn Mac + Send>;
}

pub(crate) trait Mac {
    fn mac_len(&self) -> usize;
    fn is_etm(&self) -> bool {
        false
    }
    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]);
    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool;
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// `none`
pub const NONE: Name = Name("none");
/// `hmac-sha1`
pub const HMAC_SHA1: Name = Name("hmac-sha1");
/// `hmac-sha2-256`
pub const HMAC_SHA256: Name = Name("hmac-sha2-256");
/// `hmac-sha2-512`
pub const HMAC_SHA512: Name = Name("hmac-sha2-512");
/// `hmac-sha1-etm@openssh.com`
pub const HMAC_SHA1_ETM: Name = Name("hmac-sha1-etm@openssh.com");
/// `hmac-sha2-256-etm@openssh.com`
pub const HMAC_SHA256_ETM: Name = Name("hmac-sha2-256-etm@openssh.com");
/// `hmac-sha2-512-etm@openssh.com`
pub const HMAC_SHA512_ETM: Name = Name("hmac-sha2-512-etm@openssh.com");

static _NONE: NoMacAlgorithm = NoMacAlgorithm {};
static _HMAC_SHA1: CryptoMacAlgorithm<Hmac<Sha1>, U20> =
    CryptoMacAlgorithm(PhantomData, PhantomData);
static _HMAC_SHA256: CryptoMacAlgorithm<Hmac<Sha256>, U32> =
    CryptoMacAlgorithm(PhantomData, PhantomData);
static _HMAC_SHA512: CryptoMacAlgorithm<Hmac<Sha512>, U64> =
    CryptoMacAlgorithm(PhantomData, PhantomData);
static _HMAC_SHA1_ETM: CryptoEtmMacAlgorithm<Hmac<Sha1>, U20> =
    CryptoEtmMacAlgorithm(PhantomData, PhantomData);
static _HMAC_SHA256_ETM: CryptoEtmMacAlgorithm<Hmac<Sha256>, U32> =
    CryptoEtmMacAlgorithm(PhantomData, PhantomData);
static _HMAC_SHA512_ETM: CryptoEtmMacAlgorithm<Hmac<Sha512>, U64> =
    CryptoEtmMacAlgorithm(PhantomData, PhantomData);

pub(crate) static MACS: Lazy<HashMap<&'static Name, &(dyn MacAlgorithm + Send + Sync)>> =
    Lazy::new(|| {
        let mut h: HashMap<&'static Name, &(dyn MacAlgorithm + Send + Sync)> = HashMap::new();
        h.insert(&NONE, &_NONE);
        h.insert(&HMAC_SHA1, &_HMAC_SHA1);
        h.insert(&HMAC_SHA256, &_HMAC_SHA256);
        h.insert(&HMAC_SHA512, &_HMAC_SHA512);
        h.insert(&HMAC_SHA1_ETM, &_HMAC_SHA1_ETM);
        h.insert(&HMAC_SHA256_ETM, &_HMAC_SHA256_ETM);
        h.insert(&HMAC_SHA512_ETM, &_HMAC_SHA512_ETM);
        h
    });
