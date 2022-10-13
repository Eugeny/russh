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

use openssl::{cipher::CipherRef, cipher_ctx::CipherCtx};

use rand::RngCore;

use super::super::Error;
use super::PACKET_LENGTH_LEN;
use crate::mac::{Mac, MacAlgorithm};

pub struct AesSshCipher(pub fn() -> &'static CipherRef);

#[allow(clippy::expect_used)]
impl super::Cipher for AesSshCipher {
    fn key_len(&self) -> usize {
        self.0().key_length()
    }

    fn nonce_len(&self) -> usize {
        self.0().iv_length()
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Result<Box<dyn super::OpeningKey + Send>, Error> {
        let mut ctx = CipherCtx::new().expect("expected to make openssl cipher");
        ctx.decrypt_init(Some(self.0()), Some(key), Some(iv))?;

        Ok(Box::new(OpeningKey {
            ctx,
            key: key.to_vec(),
            iv: iv.to_vec(),
            cipher: self.0(),
            mac: mac.make_mac(mac_key),
        }))
    }

    fn make_sealing_key(
        &self,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Result<Box<dyn super::SealingKey + Send>, Error> {
        let mut ctx = CipherCtx::new().expect("expected to make openssl cipher");
        ctx.encrypt_init(Some(self.0()), Some(key), Some(iv))?;

        Ok(Box::new(SealingKey {
            ctx,
            mac: mac.make_mac(mac_key),
        }))
    }
}

pub struct OpeningKey {
    ctx: CipherCtx,
    key: Vec<u8>,
    iv: Vec<u8>,
    cipher: &'static CipherRef,
    mac: Box<dyn Mac + Send>,
}

pub struct SealingKey {
    ctx: CipherCtx,
    mac: Box<dyn Mac + Send>,
}

#[allow(clippy::expect_used)]
impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> Result<[u8; 4], Error> {
        if self.mac.is_etm() {
            Ok(encrypted_packet_length)
        } else {
            let mut ctx = CipherCtx::new().expect("expected to make openssl cipher");
            ctx.decrypt_init(Some(self.cipher), Some(&self.key), Some(&self.iv))?;

            let input = encrypted_packet_length;
            let n = ctx.cipher_update(&input, Some(&mut encrypted_packet_length))?;
            #[allow(clippy::indexing_slicing)]
            ctx.cipher_final(&mut encrypted_packet_length[n..])?;
            Ok(encrypted_packet_length)
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
        let input = ciphertext_in_plaintext_out.to_vec();
        if self.mac.is_etm() {
            if !self.mac.verify(sequence_number, &input, tag) {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            self.ctx.cipher_update(
                &input[PACKET_LENGTH_LEN..],
                Some(&mut ciphertext_in_plaintext_out[PACKET_LENGTH_LEN..]),
            )?;
        } else {
            self.ctx
                .cipher_update(&input, Some(ciphertext_in_plaintext_out))?;

            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        Ok(ciphertext_in_plaintext_out)
    }
}

#[allow(clippy::expect_used)]
impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        // note: the .blocksize() method reports 1 for CTR, which is not what we need...
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
        let plaintext = plaintext_in_ciphertext_out.to_vec();
        #[allow(clippy::indexing_slicing)]
        if self.mac.is_etm() {
            self.ctx
                .cipher_update(
                    &plaintext[PACKET_LENGTH_LEN..],
                    Some(&mut plaintext_in_ciphertext_out[PACKET_LENGTH_LEN..]),
                )
                .expect("cipher update should not fail");
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac.compute(sequence_number, &plaintext, tag_out);
            self.ctx
                .cipher_update(&plaintext, Some(plaintext_in_ciphertext_out))
                .expect("cipher update should not fail");
        }
    }
}
