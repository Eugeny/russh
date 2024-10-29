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
pub use signature::Verifier;
use ssh_encoding::Decode;
pub use ssh_key::public::KeyData;
pub use ssh_key::public::PublicKey;
pub use ssh_key::Signature;
pub use ssh_key::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey as KeyPair};

use crate::encoding::Reader;
use crate::Error;

pub trait PublicKeyExt {
    fn decode(bytes: &[u8]) -> Result<PublicKey, Error>;
}

impl PublicKeyExt for PublicKey {
    fn decode(bytes: &[u8]) -> Result<PublicKey, Error> {
        let key = KeyData::decode(&mut bytes.reader(0))?;
        Ok(PublicKey::new(key, ""))
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8]) -> Result<PublicKey, Error> {
    use ssh_encoding::Decode;
    Ok(ssh_key::public::KeyData::decode(&mut p.reader(0))?.into())
}

/// Obtain a cryptographic-safe random number generator.
pub fn safe_rng() -> impl rand::CryptoRng + rand::RngCore {
    rand::thread_rng()
}
