mod groups;
use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};
use log::debug;
use digest::Digest;
use groups::DH;
use num_bigint::BigUint;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;
use sha1::Sha1;
use sha2::Sha256;

use self::groups::{DhGroup, DH_GROUP1, DH_GROUP14};
use super::{compute_keys, KexAlgorithm, KexType};
use crate::session::Exchange;
use crate::{cipher, mac, msg};

pub struct DhGroup1Sha1KexType {}

impl KexType for DhGroup1Sha1KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(DhGroupKex::<Sha1>::new(&DH_GROUP1)) as Box<dyn KexAlgorithm + Send>
    }
}
pub struct DhGroup14Sha1KexType {}

impl KexType for DhGroup14Sha1KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(DhGroupKex::<Sha1>::new(&DH_GROUP14)) as Box<dyn KexAlgorithm + Send>
    }
}
pub struct DhGroup14Sha256KexType {}

impl KexType for DhGroup14Sha256KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(DhGroupKex::<Sha256>::new(&DH_GROUP14)) as Box<dyn KexAlgorithm + Send>
    }
}

#[doc(hidden)]
pub struct DhGroupKex<D: Digest> {
    dh: DH,
    shared_secret: Option<Vec<u8>>,
    _digest: PhantomData<D>,
}

impl<D: Digest> DhGroupKex<D> {
    pub fn new(group: &DhGroup) -> DhGroupKex<D> {
        let dh = DH::new(group);
        DhGroupKex {
            dh,
            shared_secret: None,
            _digest: PhantomData,
        }
    }
}

impl<D: Digest> std::fmt::Debug for DhGroupKex<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

fn biguint_to_mpint(biguint: &BigUint) -> Vec<u8> {
    let mut mpint = Vec::new();
    let bytes = biguint.to_bytes_be();
    if let Some(b) = bytes.first() {
        if b > &0x7f {
            mpint.push(0);
        }
    }
    mpint.extend(&bytes);
    mpint
}

impl<D: Digest> KexAlgorithm for DhGroupKex<D> {
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

            &payload
                .get(5..(5 + pubkey_len))
                .ok_or(crate::Error::Inconsistent)?
        };

        debug!("client_pubkey: {:?}", client_pubkey);

        self.dh.generate_private_key();
        let server_pubkey = biguint_to_mpint(&self.dh.generate_public_key());

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey);

        let shared = self
            .dh
            .compute_shared_secret(DH::decode_public_key(client_pubkey));
        self.shared_secret = Some(biguint_to_mpint(&shared));
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        self.dh.generate_private_key();
        let client_pubkey = biguint_to_mpint(&self.dh.generate_public_key());

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey);

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let remote_pubkey = DH::decode_public_key(remote_pubkey_);
        let shared = self.dh.compute_shared_secret(remote_pubkey);
        self.shared_secret = Some(biguint_to_mpint(&shared));
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
            buffer.extend_ssh_mpint(shared);
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
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        compute_keys::<D>(
            self.shared_secret.as_deref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}
