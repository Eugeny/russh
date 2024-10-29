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
use crate::keys::encoding::*;
use crate::keys::key::*;
use crate::CryptoVec;
use ssh_key::Certificate;

#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoVec);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        buffer.extend_ssh_string(&self.to_bytes().unwrap()); // only error source is usize->u32 conversion
    }
}

impl PubKey for KeyPair {
    fn push_to(&self, buffer: &mut CryptoVec) {
        self.public_key().push_to(buffer);
    }
}

impl PubKey for Certificate {
    fn push_to(&self, buffer: &mut CryptoVec) {
        buffer.extend_ssh_string(&self.to_bytes().unwrap()); // only error source is usize->u32 conversion
    }
}
