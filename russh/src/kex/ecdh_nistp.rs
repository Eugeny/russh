use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize};
use log::debug;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::kex::{compute_keys, KexAlgorithm, KexType};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg};

pub struct EcdhNistP256KexType {}

impl KexType for EcdhNistP256KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(EcdhNistPKex::<NistP256, Sha256> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

pub struct EcdhNistP384KexType {}

impl KexType for EcdhNistP384KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(EcdhNistPKex::<NistP384, Sha384> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

pub struct EcdhNistP521KexType {}

impl KexType for EcdhNistP521KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(EcdhNistPKex::<NistP521, Sha512> {
            local_secret: None,
            shared_secret: None,
            _digest: PhantomData,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

#[doc(hidden)]
pub struct EcdhNistPKex<C: Curve + CurveArithmetic, D: Digest> {
    local_secret: Option<EphemeralSecret<C>>,
    shared_secret: Option<SharedSecret<C>>,
    _digest: PhantomData<D>,
}

impl<C: Curve + CurveArithmetic, D: Digest> std::fmt::Debug for EcdhNistPKex<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

impl<C: Curve + CurveArithmetic, D: Digest> KexAlgorithm for EcdhNistPKex<C, D>
where
    C: PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh");

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            elliptic_curve::PublicKey::<C>::from_sec1_bytes(&payload[5..(5 + pubkey_len)])
                .map_err(|_| crate::Error::Inconsistent)?
        };

        let server_secret =
            elliptic_curve::ecdh::EphemeralSecret::<C>::random(&mut rand_core::OsRng);
        let server_pubkey = server_secret.public_key();

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange
            .server_ephemeral
            .extend(&server_pubkey.to_sec1_bytes());
        let shared = server_secret.diffie_hellman(&client_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        let client_secret =
            elliptic_curve::ecdh::EphemeralSecret::<C>::random(&mut rand_core::OsRng);
        let client_pubkey = client_secret.public_key();

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.to_sec1_bytes());

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.to_sec1_bytes());

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        let pubkey = elliptic_curve::PublicKey::<C>::from_sec1_bytes(remote_pubkey_)
            .map_err(|_| crate::Error::KexInit)?;
        self.shared_secret = Some(local_secret.diffie_hellman(&pubkey));
        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        buffer.extend(key);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(shared.raw_secret_bytes());
        }

        let mut hasher = D::new();
        hasher.update(&buffer);

        let mut res = CryptoVec::new();
        res.extend(hasher.finalize().as_slice());
        Ok(res)
    }

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<crate::kex::cipher::CipherPair, crate::Error> {
        compute_keys::<D>(
            self.shared_secret
                .as_ref()
                .map(|x| x.raw_secret_bytes() as &[u8]),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret() {
        let mut party1 = EcdhNistPKex::<NistP256, Sha256> {
            local_secret: Some(EphemeralSecret::<NistP256>::random(&mut rand_core::OsRng)),
            shared_secret: None,
            _digest: PhantomData,
        };
        let p1_pubkey = party1.local_secret.as_ref().unwrap().public_key();

        let mut party2 = EcdhNistPKex::<NistP256, Sha256> {
            local_secret: Some(EphemeralSecret::<NistP256>::random(&mut rand_core::OsRng)),
            shared_secret: None,
            _digest: PhantomData,
        };
        let p2_pubkey = party2.local_secret.as_ref().unwrap().public_key();

        party1
            .compute_shared_secret(&p2_pubkey.to_sec1_bytes())
            .unwrap();

        party2
            .compute_shared_secret(&p1_pubkey.to_sec1_bytes())
            .unwrap();

        let p1_shared_secret = party1.shared_secret.unwrap();
        let p2_shared_secret = party2.shared_secret.unwrap();

        assert_eq!(
            p1_shared_secret.raw_secret_bytes(),
            p2_shared_secret.raw_secret_bytes()
        )
    }
}
