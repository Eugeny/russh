//! `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com` on the RustCrypto `aes-gcm` crate.
//!
//! RFC 5647 as amended by OpenSSH's PROTOCOL: the packet length is sent in the
//! clear and authenticated as AAD, and the 12-byte nonce is the key exchange's
//! IV, incremented as a big-endian counter after every packet.

use std::marker::PhantomData;

use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::aead::array::typenum::Unsigned;
use rand_core::Rng;

use crate::Error;
use crate::cipher::{MINIMUM_PACKET_LEN, PACKET_LENGTH_LEN, PADDING_LENGTH_LEN};
use crate::keys::key::safe_rng;
use crate::mac::MacAlgorithm;

pub struct GcmCipher<C>(pub PhantomData<C>);

impl<C: AeadInOut + KeyInit + Send + 'static> super::super::Cipher for GcmCipher<C> {
    fn key_len(&self) -> usize {
        C::KeySize::USIZE
    }

    fn nonce_len(&self) -> usize {
        C::NonceSize::USIZE
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::super::OpeningKey + Send> {
        let (cipher, nonce) = new_cipher::<C>(k, n);
        Box::new(OpeningKey { cipher, nonce })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::super::SealingKey + Send> {
        let (cipher, nonce) = new_cipher::<C>(k, n);
        Box::new(SealingKey { cipher, nonce })
    }
}

fn new_cipher<C: AeadCore + KeyInit>(k: &[u8], n: &[u8]) -> (C, Nonce<C>) {
    // The key schedule derives exactly `key_len()` and `nonce_len()` bytes.
    #[allow(clippy::unwrap_used)]
    let cipher = C::new_from_slice(k).unwrap();
    #[allow(clippy::unwrap_used)]
    let nonce = Nonce::<C>::try_from(n).unwrap();
    (cipher, nonce)
}

/// Returns the nonce for this packet and advances `nonce` for the next one.
fn next_nonce<C: AeadCore>(nonce: &mut Nonce<C>) -> Nonce<C> {
    let current = nonce.clone();
    let mut carry = 1;
    for byte in nonce.iter_mut().rev() {
        let n = *byte as u16 + carry;
        *byte = n as u8;
        carry = n >> 8;
    }
    current
}

pub struct OpeningKey<C: AeadCore> {
    cipher: C,
    nonce: Nonce<C>,
}

pub struct SealingKey<C: AeadCore> {
    cipher: C,
    nonce: Nonce<C>,
}

impl<C: AeadInOut> super::super::OpeningKey for OpeningKey<C> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        C::TagSize::USIZE
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(self.tag_len())
            .ok_or(Error::DecryptionError)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        #[allow(clippy::unwrap_used)] // split at tag_len() from the end
        let tag = Tag::<C>::try_from(&*tag).unwrap();
        // Packet length is sent unencrypted and authenticated as AAD.
        #[allow(clippy::indexing_slicing)] // the caller always passes the length prefix
        let (packet_length, payload) = ciphertext.split_at_mut(PACKET_LENGTH_LEN);

        let nonce = next_nonce::<C>(&mut self.nonce);
        self.cipher
            .decrypt_inout_detached(&nonce, packet_length, payload.into(), &tag)
            .map_err(|_| Error::DecryptionError)?;
        Ok(payload)
    }
}

impl<C: AeadInOut> super::super::SealingKey for SealingKey<C> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = PACKET_LENGTH_LEN + PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= MINIMUM_PACKET_LEN {
            MINIMUM_PACKET_LEN - payload.len() - PADDING_LENGTH_LEN
        } else {
            block_size - ((PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        C::TagSize::USIZE
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        // Packet length is sent unencrypted and authenticated as AAD.
        #[allow(clippy::indexing_slicing)] // the caller always passes the length prefix
        let (packet_length, payload) =
            plaintext_in_ciphertext_out.split_at_mut(PACKET_LENGTH_LEN);

        let nonce = next_nonce::<C>(&mut self.nonce);
        // Only fails for inputs over 2^36 bytes, far beyond MAXIMUM_PACKET_LEN.
        #[allow(clippy::unwrap_used)]
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, packet_length, payload.into())
            .unwrap();
        tag_out.copy_from_slice(&tag);
    }
}
