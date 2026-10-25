use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::montgomery::MontgomeryPoint;
use log::debug;
use sha2::Digest;
use sha2::Sha512;
use sntrup::sntrup761::{
    Ciphertext as SntrupCiphertext, DecapsulationKey as SntrupDecapsulationKey,
    EncapsulationKey as SntrupEncapsulationKey, SharedSecret as SntrupSharedSecret,
};
use ssh_encoding::{Encode, Writer};
use zeroize::Zeroizing;

use super::{compute_keys, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};
use crate::mac;
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec, Error};

const SNTRUP761_PUBLIC_KEY_SIZE: usize = sntrup::sntrup761::PUBLIC_KEY_SIZE;
const SNTRUP761_CIPHERTEXT_SIZE: usize = sntrup::sntrup761::CIPHERTEXT_SIZE;
const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub struct Sntrup761X25519KexType {}

impl KexType for Sntrup761X25519KexType {
    fn make(&self) -> KexAlgorithm {
        Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
            combined: None,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct Sntrup761X25519Kex {
    sntrup_secret: Option<SntrupDecapsulationKey>,
    x25519_secret: Option<Zeroizing<[u8; 32]>>,
    k_pq: Option<SntrupSharedSecret>,
    k_cl: Option<Zeroizing<[u8; 32]>>,
    combined: Option<Zeroizing<[u8; 64]>>,
}

impl std::fmt::Debug for Sntrup761X25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Sntrup761X25519Kex {{ sntrup_secret: [hidden], x25519_secret: [hidden], k_pq: [hidden], k_cl: [hidden] }}",
        )
    }
}

impl Sntrup761X25519Kex {
    #[allow(clippy::indexing_slicing)]
    fn cache_combined_secret(&mut self) -> Result<(), Error> {
        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;

        let mut hasher = Sha512::new();
        hasher.update(k_pq.as_ref());
        hasher.update(&k_cl[..]);

        let digest = hasher.finalize();
        let mut combined = [0u8; 64];
        combined.copy_from_slice(&digest);
        self.combined = Some(Zeroizing::new(combined));
        Ok(())
    }

    fn combined_secret(&self) -> Result<&[u8], Error> {
        self.combined.as_ref().map(|k| k.as_ref()).ok_or(Error::KexInit)
    }
}

impl KexAlgorithmImplementor for Sntrup761X25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    #[allow(clippy::indexing_slicing)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        debug!("server_dh (hybrid SNTRUP)");

        if payload.first() != Some(&msg::KEX_HYBRID_INIT) || payload.len() < 5 {
            return Err(Error::Inconsistent);
        }

        let c_init_len = BigEndian::read_u32(&payload[1..5]) as usize;
        let expected_len = SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE;
        if c_init_len != expected_len || payload.len() != 5 + c_init_len {
            return Err(Error::Kex);
        }

        let c_init = &payload[5..];
        let c_pk2_bytes = &c_init[..SNTRUP761_PUBLIC_KEY_SIZE];
        let c_pk1_bytes = &c_init[SNTRUP761_PUBLIC_KEY_SIZE..];
        let c_pk2 = SntrupEncapsulationKey::try_from(c_pk2_bytes).map_err(|_| Error::Kex)?;

        let mut rng = rand::rng();
        let (s_ct2, k_pq) = c_pk2.encapsulate(&mut rng);

        let s_secret = Zeroizing::new(rand::random::<[u8; 32]>());
        let s_pk1 = MontgomeryPoint::mul_base_clamped(*s_secret);

        let mut c_pk1 = MontgomeryPoint([0; 32]);
        c_pk1.0.copy_from_slice(c_pk1_bytes);
        let k_cl = Zeroizing::new(c_pk1.mul_clamped(*s_secret).0);
        if k_cl[..] == [0u8; 32] {
            debug!("client sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        exchange.server_ephemeral.clear();
        exchange
            .server_ephemeral
            .extend_from_slice(s_ct2.as_ref());
        exchange.server_ephemeral.extend_from_slice(&s_pk1.0);

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        self.cache_combined_secret()?;

        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let mut rng = rand::rng();
        let (sntrup_pk, sntrup_secret) = sntrup::sntrup761::generate_key(&mut rng);

        let x25519_secret = Zeroizing::new(rand::random::<[u8; 32]>());
        let x25519_pk = MontgomeryPoint::mul_base_clamped(*x25519_secret);

        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(sntrup_pk.as_ref());
        client_ephemeral.extend_from_slice(&x25519_pk.0);

        msg::KEX_HYBRID_INIT.encode(writer)?;
        let mut c_init =
            Vec::with_capacity(SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);
        c_init.extend_from_slice(sntrup_pk.as_ref());
        c_init.extend_from_slice(&x25519_pk.0);
        c_init.as_slice().encode(writer)?;

        self.sntrup_secret = Some(sntrup_secret);
        self.x25519_secret = Some(x25519_secret);

        Ok(())
    }

    #[allow(clippy::indexing_slicing)]
    fn compute_shared_secret(&mut self, remote_pubkey: &[u8]) -> Result<(), Error> {
        if remote_pubkey.len() != SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }

        let s_ct2_bytes = &remote_pubkey[..SNTRUP761_CIPHERTEXT_SIZE];
        let s_pk1_bytes = &remote_pubkey[SNTRUP761_CIPHERTEXT_SIZE..];
        let s_ct2 = SntrupCiphertext::try_from(s_ct2_bytes).map_err(|_| Error::KexInit)?;

        let sntrup_secret = self.sntrup_secret.take().ok_or(Error::KexInit)?;
        let k_pq = sntrup_secret.decapsulate(&s_ct2);

        let mut s_pk1 = MontgomeryPoint([0; 32]);
        s_pk1.0.copy_from_slice(s_pk1_bytes);

        let x25519_secret = self.x25519_secret.take().ok_or(Error::KexInit)?;
        let k_cl = Zeroizing::new(s_pk1.mul_clamped(*x25519_secret).0);
        if k_cl[..] == [0u8; 32] {
            debug!("server sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        self.cache_combined_secret()?;

        Ok(())
    }

    #[allow(clippy::indexing_slicing)]
    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.combined.as_ref().map(|k| &k[..])
    }

    #[allow(clippy::indexing_slicing)]
    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        let combined = self.combined_secret()?;
        combined.encode(buffer)?;

        let mut hasher = Sha512::new();
        hasher.update(&buffer[..]);
        Ok(hasher.finalize().to_vec())
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let combined = self.combined_secret()?;
        let shared_secret = SharedSecret::from_string(combined)?;

        compute_keys::<Sha512>(
            Some(&shared_secret),
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
    use crate::session::Exchange;

    fn test_kex() -> Sntrup761X25519Kex {
        Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
            combined: None,
        }
    }

    #[test]
    fn client_and_server_exchange() {
        let mut client_kex = test_kex();
        let mut server_kex = test_kex();
        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();

        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        assert_eq!(
            client_ephemeral.len(),
            SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE
        );

        let mut exchange = Exchange::new(b"client", b"server");
        server_kex
            .server_dh(&mut exchange, &client_init_msg)
            .unwrap();

        assert_eq!(
            exchange.server_ephemeral.len(),
            SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE
        );

        client_kex
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        let key = b"test_host_key";
        let mut buffer = CryptoVec::new();
        let client_hash = client_kex
            .compute_exchange_hash(key, &exchange, &mut buffer)
            .unwrap();
        let server_hash = server_kex
            .compute_exchange_hash(key, &exchange, &mut buffer)
            .unwrap();

        assert_eq!(client_hash, server_hash);
        assert_eq!(client_hash.len(), 64);
        assert_eq!(client_kex.combined_secret().unwrap(), server_kex.combined_secret().unwrap());
        assert_eq!(client_kex.shared_secret_bytes().unwrap().len(), 64);
        assert_eq!(
            client_kex.shared_secret_bytes(),
            server_kex.shared_secret_bytes()
        );
    }

    #[test]
    fn rejects_invalid_lengths() {
        let mut client_kex = test_kex();
        let mut client_ephemeral = Vec::new();
        let mut client_init_msg = Vec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_msg)
            .unwrap();

        let mut server_kex = test_kex();
        let mut exchange = Exchange::default();
        client_init_msg.truncate(4);
        assert!(server_kex
            .server_dh(&mut exchange, &client_init_msg)
            .is_err());

        assert!(client_kex.compute_shared_secret(&[0u8; 100]).is_err());
    }

    #[test]
    fn rejects_low_order_curve25519_points() {
        let low_order = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut server_kex = test_kex();
        let mut payload = vec![msg::KEX_HYBRID_INIT];
        let mut init = vec![0u8; SNTRUP761_PUBLIC_KEY_SIZE];
        init.extend_from_slice(&low_order);
        payload.extend_from_slice(&(init.len() as u32).to_be_bytes());
        payload.extend_from_slice(&init);

        let mut exchange = Exchange::default();
        assert!(server_kex.server_dh(&mut exchange, &payload).is_err());
    }
}
