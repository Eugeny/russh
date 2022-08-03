use std::marker::PhantomData;

use digest::KeyInit;
use generic_array::{ArrayLength, GenericArray};

use super::crypto::{CryptoMac, CryptoMacAlgorithm};
use super::{Mac, MacAlgorithm};

pub struct CryptoEtmMacAlgorithm<
    M: digest::Mac + KeyInit + Send + 'static,
    KL: ArrayLength<u8> + 'static,
>(pub PhantomData<M>, pub PhantomData<KL>);

impl<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength<u8> + 'static> MacAlgorithm
    for CryptoEtmMacAlgorithm<M, KL>
{
    fn key_len(&self) -> usize {
        CryptoMacAlgorithm::<M, KL>(self.0, self.1).key_len()
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        let mut key = GenericArray::<u8, KL>::default();
        key.clone_from_slice(mac_key);
        Box::new(CryptoEtmMac::<M, KL>(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        })) as Box<dyn Mac + Send>
    }
}

pub struct CryptoEtmMac<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength<u8> + 'static>(
    CryptoMac<M, KL>,
);

impl<M: digest::Mac + KeyInit + Send + 'static, KL: ArrayLength<u8> + 'static> Mac
    for CryptoEtmMac<M, KL>
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
