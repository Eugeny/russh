//! `chacha20-poly1305@openssh.com` on the RustCrypto `chacha20` and `poly1305` crates.
//!
//! https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305
//!
//! The 64-byte key is K_2 (payload and MAC key) followed by K_1 (packet length).
//! Both are used with the original 64-bit-nonce ChaCha20, whose nonce is the
//! sequence number as a big-endian u64. Block 0 of the K_2 stream is the
//! Poly1305 key; the payload is encrypted from block 1.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use subtle::ConstantTimeEq;

use crate::Error;
use crate::cipher::{MINIMUM_PACKET_LEN, PACKET_LENGTH_LEN, PADDING_LENGTH_LEN};
use crate::mac::MacAlgorithm;

const HALF_KEY_LEN: usize = 32;
const KEY_LEN: usize = 2 * HALF_KEY_LEN;
const TAG_LEN: usize = 16;
const CHACHA_BLOCK_LEN: u64 = 64;

type HalfKey = [u8; HALF_KEY_LEN];

pub struct SshChacha20Poly1305Cipher {}

impl super::super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::super::OpeningKey + Send> {
        let (k2, k1) = split_key(k);
        Box::new(OpeningKey { k1, k2 })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::super::SealingKey + Send> {
        let (k2, k1) = split_key(k);
        Box::new(SealingKey { k1, k2 })
    }
}

/// Returns `(K_2, K_1)`.
fn split_key(k: &[u8]) -> (HalfKey, HalfKey) {
    #[allow(clippy::unwrap_used)] // the key schedule derives exactly `key_len()` bytes
    let k: &[u8; KEY_LEN] = k.try_into().unwrap();
    let (k2, k1) = k.split_at(HALF_KEY_LEN);
    #[allow(clippy::unwrap_used)] // both halves are HALF_KEY_LEN long
    (k2.try_into().unwrap(), k1.try_into().unwrap())
}

fn chacha(key: &HalfKey, sequence_number: u32) -> ChaCha20Legacy {
    let nonce = u64::from(sequence_number).to_be_bytes();
    ChaCha20Legacy::new(key.into(), &nonce.into())
}

fn poly1305_tag(k2: &HalfKey, sequence_number: u32, data: &[u8]) -> poly1305::Tag {
    let mut poly_key = poly1305::Key::default();
    chacha(k2, sequence_number).apply_keystream(&mut poly_key);
    Poly1305::new(&poly_key).compute_unpadded(data)
}

fn apply_payload_keystream(k2: &HalfKey, sequence_number: u32, payload: &mut [u8]) {
    let mut cipher = chacha(k2, sequence_number);
    cipher.seek(CHACHA_BLOCK_LEN);
    cipher.apply_keystream(payload);
}

pub struct OpeningKey {
    k1: HalfKey,
    k2: HalfKey,
}

pub struct SealingKey {
    k1: HalfKey,
    k2: HalfKey,
}

impl super::super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used)]
        let mut packet_length: [u8; PACKET_LENGTH_LEN] =
            encrypted_packet_length.try_into().unwrap();
        chacha(&self.k1, sequence_number).apply_keystream(&mut packet_length);
        packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptionError)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);

        // The MAC covers the encrypted packet length as well as the payload.
        let expected_tag = poly1305_tag(&self.k2, sequence_number, ciphertext);
        if !bool::from(expected_tag.as_slice().ct_eq(tag)) {
            return Err(Error::DecryptionError);
        }

        #[allow(clippy::indexing_slicing)] // the caller always passes the length prefix
        let payload = &mut ciphertext[PACKET_LENGTH_LEN..];
        apply_payload_keystream(&self.k2, sequence_number, payload);
        Ok(payload)
    }
}

impl super::super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
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

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        padding_out.fill(0);
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
        #[allow(clippy::indexing_slicing)] // the caller always passes the length prefix
        let (packet_length, payload) =
            plaintext_in_ciphertext_out.split_at_mut(PACKET_LENGTH_LEN);
        chacha(&self.k1, sequence_number).apply_keystream(packet_length);
        apply_payload_keystream(&self.k2, sequence_number, payload);

        let tag = poly1305_tag(&self.k2, sequence_number, plaintext_in_ciphertext_out);
        tag_out.copy_from_slice(tag.as_slice());
    }
}
