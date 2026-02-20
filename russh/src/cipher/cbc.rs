use aes::cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, InnerIvInit,
    Iv, IvSizeUser,
};
use cbc::{Decryptor, Encryptor};
use digest::common::InnerUser;

use super::block::BlockStreamCipher;

pub struct CbcWrapper<C: BlockCipherEncrypt + BlockCipherDecrypt> {
    encryptor: Encryptor<C>,
    decryptor: Decryptor<C>,
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
            let mut block: Array<_, _> = (&*chunk)
                .try_into()
                .expect("chunk length matches block size");
            self.encryptor.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            let mut block: Array<_, _> = (&*chunk)
                .try_into()
                .expect("chunk length matches block size");
            self.decryptor.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone> InnerIvInit for CbcWrapper<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: Encryptor::inner_iv_init(cipher.clone(), iv),
            decryptor: Decryptor::inner_iv_init(cipher, iv),
        }
    }
}
