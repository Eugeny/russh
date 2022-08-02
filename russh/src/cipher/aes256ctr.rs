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

use super::super::Error;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use byteorder::{BigEndian, ByteOrder};
use ctr::Ctr128BE;
use digest::typenum::U20;
use digest::CtOutput;
use generic_array::typenum::{U16, U32};
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use russh_libsodium::random::randombytes;
use sha1::Sha1;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 16;
const MAC_KEY_BYTES: usize = 20;
type Key = GenericArray<u8, U32>;
type Nonce = GenericArray<u8, U16>;
type MacKey = GenericArray<u8, U20>;

pub struct OpeningKey {
    mac_key: MacKey,
    cipher: Ctr128BE<Aes256>,
}

pub struct SealingKey {
    mac_key: MacKey,
    cipher: Ctr128BE<Aes256>,
}

const TAG_LEN: usize = 20;
const SEQ_OFFSET: u32 = 3;

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: KEY_BYTES,
    nonce_len: NONCE_BYTES,
    mac_key_len: MAC_KEY_BYTES,
    make_sealing_cipher,
    make_opening_cipher,
};
pub const NAME: super::Name = super::Name("aes256-ctr");

fn make_nonce(nonce: &Nonce, sequence_number: u32) -> Nonce {
    let mut new_nonce = Nonce::from([0; NONCE_BYTES]);
    new_nonce.clone_from_slice(&nonce);

    #[allow(clippy::indexing_slicing)] // length checked
    let ctr = BigEndian::read_u128(&new_nonce[..]);

    #[allow(clippy::indexing_slicing)] // length checked
    BigEndian::write_u128(
        &mut new_nonce[..],
        ctr + sequence_number as u128 - SEQ_OFFSET as u128,
    );

    new_nonce
}

fn make_sealing_cipher(k: &[u8], n: &[u8], m: &[u8]) -> super::SealingCipher {
    let mut key = GenericArray::from([0u8; KEY_BYTES]);
    let mut nonce = GenericArray::from([0u8; NONCE_BYTES]);
    let mut mac_key = GenericArray::from([0u8; MAC_KEY_BYTES]);
    key.clone_from_slice(k);
    nonce.clone_from_slice(n);
    mac_key.clone_from_slice(m);
    super::SealingCipher::AES256CTR(SealingKey {
        cipher: Ctr128BE::<Aes256>::new(&key, &nonce),
        mac_key,
    })
}

fn make_opening_cipher(k: &[u8], n: &[u8], m: &[u8]) -> super::OpeningCipher {
    let mut key = GenericArray::from([0u8; KEY_BYTES]);
    let mut nonce = GenericArray::from([0u8; NONCE_BYTES]);
    let mut mac_key = GenericArray::from([0u8; MAC_KEY_BYTES]);
    key.clone_from_slice(k);
    nonce.clone_from_slice(n);
    mac_key.clone_from_slice(m);
    super::OpeningCipher::AES256CTR(OpeningKey {
        cipher: Ctr128BE::<Aes256>::new(&key, &nonce),
        mac_key,
    })
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        // Work around uncloneable Aes<>
        let mut cipher: Ctr128BE<Aes256> =
            unsafe { std::ptr::read(&self.cipher as *const Ctr128BE<Aes256>) };
        cipher.apply_keystream(&mut encrypted_packet_length);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        self.cipher.apply_keystream(ciphertext_in_plaintext_out);

        let mac = hmac(sequence_number, ciphertext_in_plaintext_out, &self.mac_key);

        let mut rcvd_mac = GenericArray::from([0u8; TAG_LEN]);
        rcvd_mac.copy_from_slice(tag);
        let rcvd_mac = CtOutput::<Hmac<Sha1>>::new(rcvd_mac);

        if mac != rcvd_mac {
            return Err(Error::PacketAuth);
        }

        Ok(ciphertext_in_plaintext_out)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + TAG_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN
                - payload.len()
                - super::PADDING_LENGTH_LEN
                - super::PACKET_LENGTH_LEN
        } else {
            block_size
                - ((super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + payload.len())
                    % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        randombytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        tag_out.copy_from_slice(
            &hmac(sequence_number, plaintext_in_ciphertext_out, &self.mac_key).into_bytes(),
        );
        self.cipher.apply_keystream(plaintext_in_ciphertext_out);
    }
}

fn hmac(seq: u32, packet: &[u8], key: &MacKey) -> CtOutput<Hmac<Sha1>> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key).unwrap();
    let mut buf = vec![0; 4];
    BigEndian::write_u32(&mut buf, seq);
    hmac.update(&buf);
    hmac.update(packet);
    hmac.finalize()
}
