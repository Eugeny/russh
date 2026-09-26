//! Pure-Rust AEAD ciphers for the `rustcrypto` feature, used when neither
//! `aws-lc-rs` nor `ring` is enabled.

pub(crate) mod chacha20poly1305;
pub(crate) mod gcm;

/// Known-answer tests against the `aws-lc-rs`/`ring` implementations: for the
/// same key, nonce and plaintext both backends must produce the same bytes,
/// and each must open what the other sealed.
#[cfg(all(test, any(feature = "ring", feature = "aws-lc-rs")))]
mod tests {
    use std::marker::PhantomData;

    use rand_core::Rng;

    use crate::cipher::{Cipher, OpeningKey, PACKET_LENGTH_LEN, SealingKey};
    use crate::keys::key::safe_rng;
    use crate::mac::_NONE;

    const SEQUENCE_NUMBERS: [u32; 4] = [0, 1, 0x0102_0304, u32::MAX];
    const PAYLOAD_LENS: [usize; 5] = [0, 1, 12, 64, 1000];

    fn random(len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        safe_rng().fill_bytes(&mut bytes);
        bytes
    }

    fn seal(key: &mut dyn SealingKey, seqn: u32, plaintext: &[u8]) -> Vec<u8> {
        let mut packet = plaintext.to_vec();
        packet.resize(plaintext.len() + key.tag_len(), 0);
        let (text, tag) = packet.split_at_mut(plaintext.len());
        key.seal(seqn, text, tag);
        packet
    }

    fn open(key: &mut dyn OpeningKey, seqn: u32, packet: &[u8]) -> Option<Vec<u8>> {
        let mut packet = packet.to_vec();
        key.open(seqn, &mut packet).ok().map(<[u8]>::to_vec)
    }

    /// Seals the same packets with `reference` and `candidate`, which must
    /// agree byte for byte and open each other's output.
    fn check(reference: &dyn Cipher, candidate: &dyn Cipher, nonce: &[u8]) {
        assert_eq!(reference.key_len(), candidate.key_len());
        assert_eq!(reference.nonce_len(), candidate.nonce_len());
        let key = random(reference.key_len());
        let make_keys = |c: &dyn Cipher| {
            (
                c.make_sealing_key(&key, nonce, &[], &_NONE),
                c.make_opening_key(&key, nonce, &[], &_NONE),
            )
        };
        let (mut ref_seal, mut ref_open) = make_keys(reference);
        let (mut cand_seal, mut cand_open) = make_keys(candidate);

        for seqn in SEQUENCE_NUMBERS {
            for payload_len in PAYLOAD_LENS {
                let plaintext = random(PACKET_LENGTH_LEN + payload_len);
                let sealed = seal(&mut *ref_seal, seqn, &plaintext);
                assert_eq!(sealed, seal(&mut *cand_seal, seqn, &plaintext));

                #[allow(clippy::indexing_slicing)]
                let length = &sealed[..PACKET_LENGTH_LEN];
                assert_eq!(
                    cand_open.decrypt_packet_length(seqn, length),
                    ref_open.decrypt_packet_length(seqn, length),
                );

                #[allow(clippy::indexing_slicing)]
                let payload = Some(plaintext[PACKET_LENGTH_LEN..].to_vec());
                assert_eq!(open(&mut *cand_open, seqn, &sealed), payload);
                assert_eq!(open(&mut *ref_open, seqn, &sealed), payload);
            }
        }

        check_rejects_tampering(reference, &key, nonce);
        check_rejects_tampering(candidate, &key, nonce);
    }

    /// Flips one bit of the packet length, the payload and the tag in turn.
    /// Every key pair is fresh, so a rejection cannot come from a nonce out of step.
    fn check_rejects_tampering(cipher: &dyn Cipher, key: &[u8], nonce: &[u8]) {
        let seqn = 5;
        let plaintext = random(PACKET_LENGTH_LEN + 32);
        let packet_len = plaintext.len() + cipher.make_sealing_key(key, nonce, &[], &_NONE).tag_len();
        for index in [1, PACKET_LENGTH_LEN, packet_len - 1] {
            let sealed = seal(&mut *cipher.make_sealing_key(key, nonce, &[], &_NONE), seqn, &plaintext);
            let mut tampered = sealed.clone();
            #[allow(clippy::indexing_slicing)]
            {
                tampered[index] ^= 1;
            }
            let opening_key = || cipher.make_opening_key(key, nonce, &[], &_NONE);
            assert_eq!(open(&mut *opening_key(), seqn, &tampered), None, "bit flipped at {index}");
            #[allow(clippy::indexing_slicing)]
            let payload = Some(plaintext[PACKET_LENGTH_LEN..].to_vec());
            assert_eq!(open(&mut *opening_key(), seqn, &sealed), payload);
        }
    }

    #[test]
    fn chacha20_poly1305_matches_reference_backend() {
        check(
            &super::super::chacha20poly1305::SshChacha20Poly1305Cipher {},
            &super::chacha20poly1305::SshChacha20Poly1305Cipher {},
            &[],
        );
    }

    #[test]
    fn aes_gcm_matches_reference_backend() {
        // The nonce ends in 0xfffe so the per-packet increment carries across bytes.
        let mut nonce = random(12);
        #[allow(clippy::indexing_slicing)]
        nonce[10..].copy_from_slice(&[0xff, 0xfe]);
        check(
            &super::super::gcm::GcmCipher(&super::super::ALGORITHM_AES_128_GCM),
            &super::gcm::GcmCipher::<aes_gcm::Aes128Gcm>(PhantomData),
            &nonce,
        );
        check(
            &super::super::gcm::GcmCipher(&super::super::ALGORITHM_AES_256_GCM),
            &super::gcm::GcmCipher::<aes_gcm::Aes256Gcm>(PhantomData),
            &nonce,
        );
    }
}
