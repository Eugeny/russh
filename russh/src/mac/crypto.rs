use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use digest::typenum::Unsigned;
use digest::KeyInit;

use super::{Mac, MacAlgorithm};

pub struct CryptoMacAlgorithm<M: digest::Mac + KeyInit + Send + 'static, const KL: usize>(
    pub PhantomData<M>,
);

pub struct CryptoMac<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> {
    pub(crate) key: [u8; KL],
    pub(crate) p: PhantomData<M>,
}

impl<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> CryptoMac<M, KL> {
    fn hmac(&self, sequence_number: u32, payload: &[u8]) -> M {
        #[allow(clippy::unwrap_used)]
        let mut hmac = <M as KeyInit>::new_from_slice(&self.key).unwrap();
        let mut seqno_buf = [0; 4];
        BigEndian::write_u32(&mut seqno_buf, sequence_number);
        hmac.update(&seqno_buf);
        hmac.update(payload);
        hmac
    }
}

impl<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> MacAlgorithm
    for CryptoMacAlgorithm<M, KL>
{
    fn key_len(&self) -> usize {
        KL
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        let mut key = [0u8; KL];
        key.copy_from_slice(mac_key);
        Box::new(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        }) as Box<dyn Mac + Send>
    }
}

impl<M: digest::Mac + KeyInit + Send + 'static, const KL: usize> Mac for CryptoMac<M, KL> {
    fn mac_len(&self) -> usize {
        M::OutputSize::to_usize()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        output.copy_from_slice(&self.hmac(sequence_number, payload).finalize().into_bytes());
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        self.hmac(sequence_number, payload).verify_slice(mac).is_ok()
    }
}
