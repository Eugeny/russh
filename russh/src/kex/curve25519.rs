use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use log::debug;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;

use super::{compute_keys, KexAlgorithm, KexType};
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg};

pub struct Curve25519KexType {}

impl KexType for Curve25519KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        }) as Box<dyn KexAlgorithm + Send>
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
impl KexAlgorithm for Curve25519Kex {
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
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        let client_secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let client_pubkey = (ED25519_BASEPOINT_TABLE * &client_secret).to_montgomery();

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);

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
            buffer.extend_ssh_mpint(&shared.0);
        }

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
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
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        compute_keys::<sha2::Sha256>(
            self.shared_secret.as_ref().map(|x| x.0.as_slice()),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}
