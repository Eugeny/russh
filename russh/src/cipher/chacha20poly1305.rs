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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use aes::cipher::{BlockSizeUser, StreamCipherSeek};
use byteorder::{BigEndian, ByteOrder};
use chacha20::cipher::{KeyInit, KeyIvInit, StreamCipher};
use chacha20::{ChaCha20Legacy, ChaCha20LegacyCore};
use generic_array::typenum::{Unsigned, U16, U32, U8};
use generic_array::GenericArray;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

use super::super::Error;
use crate::cipher::PACKET_LENGTH_LEN;
use crate::mac::MacAlgorithm;

pub struct SshChacha20Poly1305Cipher {}

type KeyLength = U32;
type NonceLength = U8;
type TagLength = U16;
type Key = GenericArray<u8, KeyLength>;
type Nonce = GenericArray<u8, NonceLength>;

impl super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        KeyLength::to_usize() * 2
    }

    #[allow(clippy::indexing_slicing)] // length checked
    fn make_opening_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Result<Box<dyn super::OpeningKey + Send>, Error> {
        let mut k1 = Key::default();
        let mut k2 = Key::default();
        k1.clone_from_slice(&k[KeyLength::to_usize()..]);
        k2.clone_from_slice(&k[..KeyLength::to_usize()]);
        Ok(Box::new(OpeningKey { k1, k2 }))
    }

    #[allow(clippy::indexing_slicing)] // length checked
    fn make_sealing_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Result<Box<dyn super::SealingKey + Send>, Error> {
        let mut k1 = Key::default();
        let mut k2 = Key::default();
        k1.clone_from_slice(&k[KeyLength::to_usize()..]);
        k2.clone_from_slice(&k[..KeyLength::to_usize()]);
        Ok(Box::new(SealingKey { k1, k2 }))
    }
}

pub struct OpeningKey {
    k1: Key,
    k2: Key,
}

pub struct SealingKey {
    k1: Key,
    k2: Key,
}

#[allow(clippy::indexing_slicing)] // length checked
fn make_counter(sequence_number: u32) -> Nonce {
    let mut nonce = Nonce::default();
    let i0 = NonceLength::to_usize() - 4;
    BigEndian::write_u32(&mut nonce[i0..], sequence_number);
    nonce
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> Result<[u8; 4], Error> {
        let nonce = make_counter(sequence_number);
        let mut cipher = ChaCha20Legacy::new(&self.k1, &nonce);
        cipher.apply_keystream(&mut encrypted_packet_length);
        Ok(encrypted_packet_length)
    }

    fn tag_len(&self) -> usize {
        TagLength::to_usize()
    }

    #[allow(clippy::indexing_slicing)] // lengths checked
    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = make_counter(sequence_number);
        let expected_tag = compute_poly1305(&nonce, &self.k2, ciphertext_in_plaintext_out);

        if !bool::from(expected_tag.ct_eq(tag)) {
            return Err(Error::DecryptionError);
        }

        let mut cipher = ChaCha20Legacy::new(&self.k2, &nonce);

        cipher.seek(<ChaCha20LegacyCore as BlockSizeUser>::BlockSize::to_usize());
        cipher.apply_keystream(&mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..]);

        Ok(&ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..])
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TagLength::to_usize()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        let nonce = make_counter(sequence_number);

        let mut cipher = ChaCha20Legacy::new(&self.k1, &nonce);
        #[allow(clippy::indexing_slicing)] // length checked
        cipher.apply_keystream(&mut plaintext_in_ciphertext_out[..PACKET_LENGTH_LEN]);

        // --
        let mut cipher = ChaCha20Legacy::new(&self.k2, &nonce);

        cipher.seek(<ChaCha20LegacyCore as BlockSizeUser>::BlockSize::to_usize());
        #[allow(clippy::indexing_slicing, clippy::unwrap_used)]
        cipher.apply_keystream(&mut plaintext_in_ciphertext_out[PACKET_LENGTH_LEN..]);

        // --

        tag.copy_from_slice(
            compute_poly1305(&nonce, &self.k2, plaintext_in_ciphertext_out).as_slice(),
        );
    }
}

fn compute_poly1305(nonce: &Nonce, key: &Key, data: &[u8]) -> poly1305::Tag {
    let mut cipher = ChaCha20Legacy::new(key, nonce);
    let mut poly_key = GenericArray::<u8, U32>::default();
    cipher.apply_keystream(&mut poly_key);

    Poly1305::new(&poly_key).compute_unpadded(data)
}
