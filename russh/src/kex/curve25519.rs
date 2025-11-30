use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use log::debug;
use ssh_encoding::{Encode, Writer};

use super::{
    compute_keys, encode_mpint, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret,
};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec};

pub struct Curve25519KexType {}

impl KexType for Curve25519KexType {
    fn make(&self) -> KexAlgorithm {
        Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        }
        .into()
    }
}

#[doc(hidden)]
pub struct Curve25519Kex {
    local_secret: Option<Scalar>,
    shared_secret: Option<MontgomeryPoint>,
}

impl std::fmt::Debug for Curve25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html
impl KexAlgorithmImplementor for Curve25519Kex {
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

            if pubkey_len != 32 {
                return Err(crate::Error::Kex);
            }

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            let mut pubkey = MontgomeryPoint([0; 32]);
            #[allow(clippy::indexing_slicing)] // length checked
            pubkey.0.clone_from_slice(&payload[5..5 + 32]);
            pubkey
        };

        let server_secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let server_pubkey = (ED25519_BASEPOINT_TABLE * &server_secret).to_montgomery();

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        let shared = server_secret * client_pubkey;
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        writer: &mut impl Writer,
    ) -> Result<(), crate::Error> {
        let client_secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let client_pubkey = (ED25519_BASEPOINT_TABLE * &client_secret).to_montgomery();

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        msg::KEX_ECDH_INIT.encode(writer)?;
        client_pubkey.0.encode(writer)?;

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        let mut remote_pubkey = MontgomeryPoint([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let shared = local_secret * remote_pubkey;
        self.shared_secret = Some(shared);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        self.shared_secret.as_ref().map(|s| s.0.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;

        buffer.extend(key);
        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;

        if let Some(ref shared) = self.shared_secret {
            encode_mpint(&shared.0, buffer)?;
        }

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&buffer);

        let mut res = CryptoVec::new();
        res.extend(&hasher.finalize());
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
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        let shared_secret = self
            .shared_secret
            .as_ref()
            .map(|x| SharedSecret::from_mpint(&x.0))
            .transpose()?;

        compute_keys::<sha2::Sha256>(
            shared_secret.as_ref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}
