use std::marker::PhantomData;

use digest::KeyInit;

use super::crypto::{CryptoMac};
use super::{Mac, MacAlgorithm};

pub struct CryptoEtmMacAlgorithm<M: digest::Mac + KeyInit + Send + 'static, const KL: usize>(
    pub PhantomData<M>,
);

impl<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> MacAlgorithm
    for CryptoEtmMacAlgorithm<M, KL>
{
    fn key_len(&self) -> usize {
        KL
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        let mut key = [0u8; KL];
        key.copy_from_slice(mac_key);
        Box::new(CryptoEtmMac::<M, KL>(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        })) as Box<dyn Mac + Send>
    }
}

pub struct CryptoEtmMac<M: digest::Mac + KeyInit + Send + 'static, const KL: usize>(
    CryptoMac<M, KL>,
);

impl<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> Mac for CryptoEtmMac<M, KL> {
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
