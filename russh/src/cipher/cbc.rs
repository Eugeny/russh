use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, InnerIvInit, Iv,
    IvSizeUser,
};
use cbc::{Decryptor, Encryptor};
use digest::crypto_common::InnerUser;
#[allow(deprecated)]
use digest::generic_array::GenericArray;

use super::block::{BlockStreamCipher, PacketLengthProbe};

// Allow deprecated generic-array 0.14 usage until RustCrypto crates (cipher, cbc, etc.)
// upgrade to generic-array 1.x. Remove this when dependencies no longer use 0.14.
#[allow(deprecated)]
fn generic_array_from_slice<N>(chunk: &[u8]) -> GenericArray<u8, N>
where
    N: digest::generic_array::ArrayLength<u8>,
{
    GenericArray::from_slice(chunk).clone()
}

pub struct CbcWrapper<C: BlockEncrypt + BlockCipher + BlockDecrypt> {
    encryptor: Encryptor<C>,
    decryptor: Decryptor<C>,
}

impl<C: BlockEncrypt + BlockCipher + BlockDecrypt> InnerUser for CbcWrapper<C> {
    type Inner = C;
}

impl<C: BlockEncrypt + BlockCipher + BlockDecrypt> IvSizeUser for CbcWrapper<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncrypt + BlockCipher + BlockDecrypt> BlockStreamCipher for CbcWrapper<C> {
    fn encrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            let mut block = generic_array_from_slice(chunk);
            self.encryptor.encrypt_block_mut(&mut block);
            chunk.copy_from_slice(&block);
        }
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            let mut block = generic_array_from_slice(chunk);
            self.decryptor.decrypt_block_mut(&mut block);
            chunk.copy_from_slice(&block);
        }
    }
}

impl<C: BlockEncrypt + BlockCipher + BlockDecrypt + Clone> PacketLengthProbe for CbcWrapper<C>
where
    C: BlockDecryptMut,
{
    fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]) {
        let mut decryptor = self.decryptor.clone();
        for chunk in first_block.chunks_exact_mut(C::block_size()) {
            let mut block = generic_array_from_slice(chunk);
            decryptor.decrypt_block_mut(&mut block);
            chunk.copy_from_slice(&block);
        }
    }
}

impl<C: BlockEncrypt + BlockCipher + BlockDecrypt + Clone> InnerIvInit for CbcWrapper<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: Encryptor::inner_iv_init(cipher.clone(), iv),
            decryptor: Decryptor::inner_iv_init(cipher, iv),
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::cipher::KeyIvInit;
    use aes::Aes128;
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
