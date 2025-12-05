use ssh_encoding::Writer;

use super::{KexAlgorithm, KexAlgorithmImplementor, KexType};
use crate::CryptoVec;

pub struct NoneKexType {}

impl KexType for NoneKexType {
    fn make(&self) -> KexAlgorithm {
        NoneKexAlgorithm {}.into()
    }
}

#[doc(hidden)]
pub struct NoneKexAlgorithm {}

impl KexAlgorithmImplementor for NoneKexAlgorithm {
    fn skip_exchange(&self) -> bool {
        true
    }

    fn server_dh(
        &mut self,
        _exchange: &mut crate::session::Exchange,
        _payload: &[u8],
    ) -> Result<(), crate::Error> {
        Ok(())
    }

    fn client_dh(
        &mut self,
        _client_ephemeral: &mut russh_cryptovec::CryptoVec,
        _buf: &mut impl Writer,
    ) -> Result<(), crate::Error> {
        Ok(())
    }

    fn compute_shared_secret(&mut self, _remote_pubkey: &[u8]) -> Result<(), crate::Error> {
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        None
    }

    fn compute_exchange_hash(
        &self,
        _key: &russh_cryptovec::CryptoVec,
        _exchange: &crate::session::Exchange,
        _buffer: &mut russh_cryptovec::CryptoVec,
    ) -> Result<russh_cryptovec::CryptoVec, crate::Error> {
        Ok(CryptoVec::new())
    }

    fn compute_keys(
        &self,
        session_id: &russh_cryptovec::CryptoVec,
        exchange_hash: &russh_cryptovec::CryptoVec,
        cipher: crate::cipher::Name,
        remote_to_local_mac: crate::mac::Name,
        local_to_remote_mac: crate::mac::Name,
        is_server: bool,
    ) -> Result<crate::cipher::CipherPair, crate::Error> {
        super::compute_keys::<sha2::Sha256>(
            None,
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}
