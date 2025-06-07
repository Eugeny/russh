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

use std::convert::TryInto;

use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit},
    ChaCha20Poly1305, KeySizeUser,
};
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::super::Error;
use crate::mac::MacAlgorithm;

pub struct SshChacha20Poly1305Cipher {}

type KeySize = <ChaCha20Poly1305 as KeySizeUser>::KeySize;
type Key = GenericArray<u8, KeySize>;
type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
type TagSize = <ChaCha20Poly1305 as AeadCore>::TagSize;

impl super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        ChaCha20Poly1305::key_size()
    }

    fn nonce_len(&self) -> usize {
        GenericArray::<u8, NonceSize>::default().len()
    }

    #[allow(clippy::indexing_slicing)] // length checked
    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        let mut key = Key::default();
        key.clone_from_slice(k);
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        nonce.clone_from_slice(n);
        Box::new(OpeningKey {
            nonce,
            cipher: ChaCha20Poly1305::new(&key),
        })
    }

    #[allow(clippy::indexing_slicing)] // length checked
    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        let mut key = Key::default();
        key.clone_from_slice(k);
        let mut nonce = GenericArray::<u8, NonceSize>::default();
        nonce.clone_from_slice(n);
        Box::new(SealingKey {
            nonce,
            cipher: ChaCha20Poly1305::new(&key),
        })
    }
}

pub struct OpeningKey {
    nonce: GenericArray<u8, NonceSize>,
    cipher: ChaCha20Poly1305,
}

pub struct SealingKey {
    nonce: GenericArray<u8, NonceSize>,
    cipher: ChaCha20Poly1305,
}

fn inc_nonce(nonce: &mut GenericArray<u8, NonceSize>) {
    let mut carry = 1;
    #[allow(clippy::indexing_slicing)] // length checked
    for i in (0..nonce.len()).rev() {
        let n = nonce[i] as u16 + carry;
        nonce[i] = n as u8;
        carry = n >> 8;
    }
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        TagSize::to_usize()
    }

    #[allow(clippy::indexing_slicing)] // lengths checked
    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        // Packet length is sent unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];

        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&ciphertext_in_plaintext_out[..super::PACKET_LENGTH_LEN]);

        let mut tag_buf = GenericArray::<u8, TagSize>::default();
        tag_buf.clone_from_slice(tag);

        #[allow(clippy::indexing_slicing)]
        self.cipher
            .decrypt_in_place_detached(
                &self.nonce,
                &packet_length,
                &mut ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..],
                &tag_buf,
            )
            .map_err(|_| Error::DecryptionError)?;

        inc_nonce(&mut self.nonce);

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..])
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
        TagSize::to_usize()
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        // Packet length is received unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        #[allow(clippy::indexing_slicing, clippy::unwrap_used)]
        let tag_out = self
            .cipher
            .encrypt_in_place_detached(
                &self.nonce,
                &packet_length,
                &mut plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
            )
            .unwrap();

        inc_nonce(&mut self.nonce);
        tag.clone_from_slice(&tag_out)
    }
}
