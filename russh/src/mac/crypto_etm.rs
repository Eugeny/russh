use std::marker::PhantomData;

use digest::{KeyInit, Mac as DigestMac, OutputSizeUser};
use hybrid_array::{Array, ArraySize};

use super::crypto::{CryptoMac, CryptoMacAlgorithm};
use super::{Mac, MacAlgorithm};

pub struct CryptoEtmMacAlgorithm<
    M: DigestMac + KeyInit + Send + 'static,
    KL: ArraySize + 'static,
>(pub PhantomData<M>, pub PhantomData<KL>);

impl<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static> MacAlgorithm
    for CryptoEtmMacAlgorithm<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArraySize,
{
    fn key_len(&self) -> usize {
        CryptoMacAlgorithm::<M, KL>(self.0, self.1).key_len()
    }

    fn make_mac(&self, mac_key: &[u8]) -> Result<Box<dyn Mac + Send>, crate::Error> {
        let mut key = Array::<u8, KL>::default();
        key.copy_from_slice(mac_key);
        Ok(Box::new(CryptoEtmMac::<M, KL>(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        })) as Box<dyn Mac + Send>)
    }
}

pub struct CryptoEtmMac<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static>(
    CryptoMac<M, KL>,
);

impl<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static> Mac
    for CryptoEtmMac<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArraySize,
{
    fn is_etm(&self) -> bool {
        true
    }

    fn mac_len(&self) -> usize {
        self.0.mac_len()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        self.0.compute(sequence_number, payload, output)
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        self.0.verify(sequence_number, payload, mac)
    }
}
