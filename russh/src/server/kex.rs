use std::cell::RefCell;
use std::ops::DerefMut;

use log::debug;
use russh_keys::helpers::sign_with_hash_alg;
use russh_keys::key::PrivateKeyWithHashAlg;
use ssh_encoding::Encode;
use ssh_key::Algorithm;

use super::*;
use crate::cipher::SealingKey;
use crate::kex::{KexAlgorithmImplementor, KEXES};
use crate::negotiation::{is_key_compatible_with_algo, Select};
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl KexInit {
    pub fn server_parse(
        mut self,
        config: &Config,
        cipher: &mut dyn SealingKey,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if buf.first() == Some(&msg::KEXINIT) {
            let algo = {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                super::negotiation::Server::read_kex(buf, &config.preferred, Some(&config.keys))?
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)?
            }

            let Some(matching_key_index) = config
                .keys
                .iter()
                .position(|key| is_key_compatible_with_algo(key, &algo.key))
            else {
                debug!("unknown key {:?}", algo.key);
                return Err(Error::UnknownKey);
            };

            let next_kex = Kex::Dh(KexDh {
                exchange: self.exchange,
                key: matching_key_index,
                names: algo,
                session_id: self.session_id,
            });

            Ok(next_kex)
        } else {
            Ok(Kex::Init(self))
        }
    }

    pub fn server_write(
        &mut self,
        config: &Config,
        cipher: &mut dyn SealingKey,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.server_kex_init.clear();
        negotiation::write_kex(
            &config.preferred,
            &mut self.exchange.server_kex_init,
            Some(config),
        )?;
        debug!("server kex init: {:?}", &self.exchange.server_kex_init[..]);
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer);
        Ok(())
    }
}

impl KexDh {
    pub fn parse(
        mut self,
        config: &Config,
        cipher: &mut dyn SealingKey,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::Dh(self))
        } else {
            // Else, process it.
            let Some((&msg::KEX_ECDH_INIT, mut r)) = buf.split_first() else {
                return Err(Error::Inconsistent);
            };

            self.exchange
                .client_ephemeral
                .extend(&Bytes::decode(&mut r)?);

            let mut kex = KEXES.get(&self.names.kex).ok_or(Error::UnknownAlgo)?.make();

            kex.server_dh(&mut self.exchange, buf)?;

            // Look up the key we'll be using to sign the exchange hash
            #[allow(clippy::indexing_slicing)] // key index checked
            let key = &config.keys[self.key];
            let signature_hash_alg = match &self.names.key {
                Algorithm::Rsa { hash } => *hash,
                _ => None,
            };

            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: self.exchange,
                kex,
                key: self.key,
                names: self.names,
                session_id: self.session_id,
            };

            let hash: Result<_, Error> = HASH_BUF.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                debug!("server kexdhdone.exchange = {:?}", kexdhdone.exchange);

                let mut pubkey_vec = CryptoVec::new();
                key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;

                let hash = kexdhdone.kex.compute_exchange_hash(
                    &pubkey_vec,
                    &kexdhdone.exchange,
                    &mut buffer,
                )?;
                debug!("exchange hash: {:?}", hash);
                buffer.clear();
                buffer.push(msg::KEX_ECDH_REPLY);
                key.public_key().to_bytes()?.encode(buffer.deref_mut())?;

                // Server ephemeral
                kexdhdone
                    .exchange
                    .server_ephemeral
                    .encode(buffer.deref_mut())?;

                // Hash signature
                debug!("signing with key {:?}", kexdhdone.key);
                debug!("hash: {:?}", hash);
                debug!("key: {:?}", key);

                sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg)?,
                    &hash,
                )?
                .encode(&mut *buffer)?;

                cipher.write(&buffer, write_buffer);
                cipher.write(&[msg::NEWKEYS], write_buffer);
                Ok(hash)
            });

            Ok(Kex::Keys(kexdhdone.compute_keys(hash?, true)?))
        }
    }
}
