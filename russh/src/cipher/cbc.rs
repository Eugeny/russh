use cbc::Encryptor;
use cbc::cipher::{InnerIvInit, Iv, IvSizeUser};
use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeEncrypt};
use cipher::common::InnerUser;

use super::block::{BlockStreamCipher, PacketLengthProbe};

/// CBC wrapper that stores the decryption cipher and IV separately rather than
/// a `cbc::Decryptor`, because `Decryptor` is no longer `Clone` in cbc 0.2.
/// This allows stateless peeking at the packet length block without cloning.
pub struct CbcWrapper<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt,
{
    encryptor: Encryptor<C>,
    /// Raw cipher used for decryption. `BlockCipherDecrypt::decrypt_block` takes
    /// `&self`, so this can be used without mutation for packet-length probing.
    dec_cipher: C,
    /// Current CBC decryption IV (i.e. the last ciphertext block consumed).
    dec_iv: Block<C>,
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> InnerUser for CbcWrapper<C> {
    type Inner = C;
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> IvSizeUser for CbcWrapper<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> BlockStreamCipher for CbcWrapper<C> {
    fn encrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            #[allow(clippy::expect_used)]
            let block = <&mut Block<C>>::try_from(chunk).expect("chunk length matches block size");
            self.encryptor.encrypt_block(block);
        }
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            #[allow(clippy::expect_used)]
            let ciphertext =
                Block::<C>::try_from(chunk.as_ref()).expect("chunk length matches block size");
            #[allow(clippy::expect_used)]
            let block =
                <&mut Block<C>>::try_from(chunk).expect("chunk length matches block size");
            self.dec_cipher.decrypt_block(block);
            for (b, k) in block.iter_mut().zip(self.dec_iv.iter()) {
                *b ^= k;
            }
            self.dec_iv = ciphertext;
        }
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> PacketLengthProbe for CbcWrapper<C> {
    fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]) {
        // Use a local copy of the IV so self.dec_iv is never modified (peek, no consume).
        // BlockCipherDecrypt::decrypt_block takes &self — no mutation of dec_cipher.
        let mut iv = self.dec_iv.clone();
        for chunk in first_block.chunks_exact_mut(C::block_size()) {
            #[allow(clippy::expect_used)]
            let ciphertext = Block::<C>::try_from(chunk.as_ref()).expect("chunk length matches block size");
            #[allow(clippy::expect_used)]
            let block = <&mut Block<C>>::try_from(chunk).expect("chunk length matches block size");
            self.dec_cipher.decrypt_block(block);
            for (b, k) in block.iter_mut().zip(iv.iter()) {
                *b ^= k;
            }
            iv = ciphertext;
        }
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone> InnerIvInit for CbcWrapper<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: Encryptor::inner_iv_init(cipher.clone(), iv),
            dec_cipher: cipher,
            dec_iv: iv.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::Aes128;
    use cbc::cipher::KeyIvInit;
    #[cfg(feature = "des")]
    use des::TdesEde3;

    use super::{BlockStreamCipher, CbcWrapper, PacketLengthProbe};

    #[test]
    fn packet_length_probe_does_not_advance_cbc_decryptor_state() {
        let plaintext = *b"0123456789ABCDEF";
        let key = fixture_bytes::<16>(11);
        let iv = fixture_bytes::<16>(5);

        let mut encryptor = CbcWrapper::<Aes128>::new(&key.into(), &iv.into());
        let mut ciphertext = plaintext;
        encryptor.encrypt_data(&mut ciphertext);

        let cipher = CbcWrapper::<Aes128>::new(&key.into(), &iv.into());
        let mut probed_block = ciphertext;
        cipher.decrypt_packet_length_block(&mut probed_block);
        assert_eq!(probed_block, plaintext);

        let mut decrypted = ciphertext;
        let mut cipher_after_probe = cipher;
        cipher_after_probe.decrypt_data(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "des")]
    #[test]
    fn packet_length_probe_respects_3des_block_size() {
        let plaintext = *b"0123456789ABCDEF";
        let key = fixture_bytes::<24>(11);
        let iv = fixture_bytes::<8>(5);

        let mut encryptor = CbcWrapper::<TdesEde3>::new(&key.into(), &iv.into());
        let mut ciphertext = plaintext;
        encryptor.encrypt_data(&mut ciphertext);

        let cipher = CbcWrapper::<TdesEde3>::new(&key.into(), &iv.into());
        let mut probed_block = ciphertext;
        cipher.decrypt_packet_length_block(&mut probed_block);
        assert_eq!(probed_block, plaintext);
    }

    fn fixture_bytes<const N: usize>(seed: u8) -> [u8; N] {
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        bytes
    }
}
