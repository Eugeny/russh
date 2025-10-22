use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, InnerIvInit, Iv,
    IvSizeUser,
};
use cbc::{Decryptor, Encryptor};
use digest::crypto_common::InnerUser;
#[allow(deprecated)]
use digest::generic_array::GenericArray;

use super::block::BlockStreamCipher;

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
