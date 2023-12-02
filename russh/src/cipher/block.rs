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

use std::marker::PhantomData;

use aes::cipher::{IvSizeUser, KeyIvInit, KeySizeUser, StreamCipher};
use generic_array::GenericArray;
use rand::RngCore;

use super::super::Error;
use super::PACKET_LENGTH_LEN;
use crate::mac::{Mac, MacAlgorithm};

pub struct SshBlockCipher<C: StreamCipher + KeySizeUser + IvSizeUser>(pub PhantomData<C>);

impl<C: StreamCipher + KeySizeUser + IvSizeUser + KeyIvInit + Send + 'static> super::Cipher
    for SshBlockCipher<C>
{
    fn key_len(&self) -> usize {
        C::key_size()
    }

    fn nonce_len(&self) -> usize {
        C::iv_size()
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut nonce = GenericArray::<u8, C::IvSize>::default();
        key.clone_from_slice(k);
        nonce.clone_from_slice(n);
        Box::new(OpeningKey {
            cipher: C::new(&key, &nonce),
            mac: mac.make_mac(m),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut nonce = GenericArray::<u8, C::IvSize>::default();
        key.clone_from_slice(k);
        nonce.clone_from_slice(n);
        Box::new(SealingKey {
            cipher: C::new(&key, &nonce),
            mac: mac.make_mac(m),
        })
    }
}

pub struct OpeningKey<C: StreamCipher + KeySizeUser + IvSizeUser> {
    cipher: C,
    mac: Box<dyn Mac + Send>,
}

pub struct SealingKey<C: StreamCipher + KeySizeUser + IvSizeUser> {
    cipher: C,
    mac: Box<dyn Mac + Send>,
}

impl<C: StreamCipher + KeySizeUser + IvSizeUser> super::OpeningKey for OpeningKey<C> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        if self.mac.is_etm() {
            encrypted_packet_length
        } else {
            // Work around uncloneable Aes<>
            let mut cipher: C = unsafe { std::ptr::read(&self.cipher as *const C) };
            cipher.apply_keystream(&mut encrypted_packet_length);
            encrypted_packet_length
        }
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        if self.mac.is_etm() {
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .apply_keystream(&mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..]);
        } else {
            self.cipher.apply_keystream(ciphertext_in_plaintext_out);

            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..])
    }
}

impl<C: StreamCipher + KeySizeUser + IvSizeUser> super::SealingKey for SealingKey<C> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;

        let pll = if self.mac.is_etm() {
            0
        } else {
            PACKET_LENGTH_LEN
        };

        let extra_len = PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + self.mac.mac_len();

        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN - pll
        } else {
            block_size - ((pll + super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        rand::thread_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        if self.mac.is_etm() {
            #[allow(clippy::indexing_slicing)]
            self.cipher
                .apply_keystream(&mut plaintext_in_ciphertext_out[PACKET_LENGTH_LEN..]);
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
            self.cipher.apply_keystream(plaintext_in_ciphertext_out);
        }
    }
}
