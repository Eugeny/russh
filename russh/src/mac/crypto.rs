use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use digest::typenum::Unsigned;
use digest::{KeyInit, Mac as DigestMac, OutputSizeUser};
use hybrid_array::{Array, ArraySize};
use subtle::ConstantTimeEq;

use super::{Mac, MacAlgorithm};

pub struct CryptoMacAlgorithm<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static>(
    pub PhantomData<M>,
    pub PhantomData<KL>,
);

pub struct CryptoMac<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static> {
    pub(crate) key: Array<u8, KL>,
    pub(crate) p: PhantomData<M>,
}

impl<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static> MacAlgorithm
    for CryptoMacAlgorithm<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArraySize,
{
    fn key_len(&self) -> usize {
        KL::to_usize()
    }

    fn make_mac(&self, mac_key: &[u8]) -> Result<Box<dyn Mac + Send>, crate::Error> {
        let mut key = Array::<u8, KL>::default();
        key.copy_from_slice(mac_key);
        Ok(Box::new(CryptoMac::<M, KL> {
            key,
            p: PhantomData,
        }) as Box<dyn Mac + Send>)
    }
}

impl<M: DigestMac + KeyInit + Send + 'static, KL: ArraySize + 'static> Mac for CryptoMac<M, KL>
where
    <M as OutputSizeUser>::OutputSize: ArraySize,
{
    fn mac_len(&self) -> usize {
        M::OutputSize::to_usize()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        #[allow(clippy::unwrap_used)]
        let mut hmac = M::new_from_slice(&self.key).unwrap();
        let mut seqno_buf = [0; 4];
        BigEndian::write_u32(&mut seqno_buf, sequence_number);
        DigestMac::update(&mut hmac, &seqno_buf);
        DigestMac::update(&mut hmac, payload);
        let result = hmac.finalize();
        output.copy_from_slice(result.as_bytes());
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        let mut buf = Array::<u8, M::OutputSize>::default();
        self.compute(sequence_number, payload, &mut buf);
        buf.as_slice().ct_eq(mac).into()
    }
}
