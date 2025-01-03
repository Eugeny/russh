use std::str::FromStr;
use std::sync::Arc;

use crate::client::{Config, NewKeys};
use crate::kex::{Kex, KexAlgorithm, KexProgress};
use crate::kex::{KexAlgorithmImplementor, KEXES};
use crate::negotiation::{Names, Select};
use crate::session::Exchange;
use crate::sshbuffer::PacketWriter;
use crate::{msg, negotiation, strict_kex_violation, Error, SshId};
use bytes::Bytes;
use log::{debug, trace};
use russh_cryptovec::CryptoVec;
use russh_keys::key::parse_public_key;
use signature::Verifier;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, PublicKey, Signature};
use std::cell::RefCell;

use super::IncomingSshPacket;

thread_local! {
    static HASH_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
enum ClientKexState {
    Created,
    WaitingForKexReply {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        server_host_key: PublicKey,
        newkeys: NewKeys,
    },
}

#[derive(Debug)]
pub(crate) struct ClientKex {
    exchange: Exchange,
    session_id: Option<CryptoVec>,
    state: ClientKexState,
    config: Arc<Config>,
}

impl ClientKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &SshId,
        server_sshid: &[u8],
        session_id: Option<CryptoVec>,
    ) -> Self {
        let exchange = Exchange::new(client_sshid.as_kex_hash_bytes(), server_sshid);
        Self {
            config,
            exchange,
            session_id,
            state: ClientKexState::Created,
        }
    }
}

impl Kex for ClientKex {
    fn kexinit(&mut self) -> Result<CryptoVec, Error> {
        self.exchange.client_kex_init.clear();
        negotiation::write_kex(
            &self.config.preferred,
            &mut self.exchange.client_kex_init,
            None,
        )?;

        Ok(self.exchange.client_kex_init.clone())
    }

    fn step(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        match self.state {
            ClientKexState::Created => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    return Err(Error::KexInit);
                }

                trace!("client parse {:?} {:?}", input.buffer.len(), input.buffer);
                let algo = {
                    // read algorithms from packet.
                    debug!("extending {:?}", &self.exchange.server_kex_init[..]);
                    self.exchange.server_kex_init.extend(&input.buffer);
                    negotiation::Client::read_kex(&input.buffer, &self.config.preferred, None)?
                };
                debug!("algo = {:?}", algo);
                // debug!("write = {:?}", &write_buffer.buffer[..]);

                // seqno has already been incremented after read()
                if algo.strict_kex && input.seqn.0 != 1 {
                    return Err(
                        strict_kex_violation(msg::KEXINIT, input.seqn.0 as usize - 1).into(),
                    );
                }

                let mut kex = KEXES.get(&algo.kex).ok_or(Error::UnknownAlgo)?.make();

                output.packet(|w| {
                    kex.client_dh(&mut self.exchange.client_ephemeral, w)?;
                    Ok(())
                })?;

                if kex.skip_exchange() {
                    let newkeys = compute_keys(
                        CryptoVec::new(),
                        kex,
                        algo.clone(),
                        self.exchange.clone(),
                        self.session_id.as_ref(),
                    )?;

                    return Ok(KexProgress::Done {
                        newkeys,
                        server_host_key: None,
                    });
                }

                self.state = ClientKexState::WaitingForKexReply { names: algo, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ClientKexState::WaitingForKexReply { mut names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ClientKexState::WaitingForKexReply { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                if input.buffer.first() != Some(&msg::KEX_ECDH_REPLY) {
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let r = &mut &input.buffer[1..];

                let server_host_key = Bytes::decode(r)?; // server public key.
                let server_host_key = parse_public_key(&server_host_key)?;
                debug!("server_public_Key: {:?}", server_host_key);

                let server_ephemeral = Bytes::decode(r)?;
                self.exchange.server_ephemeral.extend(&server_ephemeral);
                let signature = Bytes::decode(r)?;

                kex.compute_shared_secret(&self.exchange.server_ephemeral)?;
                debug!("kexdhdone.exchange = {:?}", self.exchange);

                let mut pubkey_vec = CryptoVec::new();
                server_host_key.to_bytes()?.encode(&mut pubkey_vec)?;

                let exchange = &self.exchange;
                let hash = HASH_BUFFER.with({
                    |buffer| {
                        let mut buffer = buffer.borrow_mut();
                        buffer.clear();
                        kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)
                    }
                })?;

                debug!("exchange hash: {:?}", &hash[..]);
                let (sig_type, signature) = {
                    let mut r = &signature[..];
                    let sig_type = String::decode(&mut r)?;
                    debug!("sig_type: {:?}", sig_type);
                    (
                        Algorithm::from_str(&sig_type).map_err(ssh_encoding::Error::from)?,
                        Bytes::decode(&mut r)?,
                    )
                };

                debug!("signature: {:?}", signature);
                let signature = Signature::new(sig_type, signature.to_vec()).map_err(|e| {
                    debug!("signature ctor failed: {e:?}");
                    Error::WrongServerSig
                })?;
                if let Err(e) = Verifier::verify(&server_host_key, hash.as_ref(), &signature) {
                    debug!("wrong server sig: {e:?}");
                    return Err(Error::WrongServerSig);
                }

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.session_id.as_ref(),
                )?;

                output.packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let reset_seqn = newkeys.names.strict_kex;

                self.state = ClientKexState::WaitingForNewKeys {
                    server_host_key,
                    newkeys,
                };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ClientKexState::WaitingForNewKeys {
                server_host_key,
                newkeys,
            } => {
                debug!("newkeys received");
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    return Err(Error::Kex);
                }

                Ok(KexProgress::Done {
                    newkeys,
                    server_host_key: Some(server_host_key),
                })
            }
        }
    }
}

fn compute_keys(
    hash: CryptoVec,
    kex: KexAlgorithm,
    names: Names,
    exchange: Exchange,
    session_id: Option<&CryptoVec>,
) -> Result<NewKeys, Error> {
    let session_id = if let Some(session_id) = session_id {
        session_id
    } else {
        &hash
    };
    // Now computing keys.
    let c = kex.compute_keys(
        &session_id,
        &hash,
        names.cipher,
        names.server_mac,
        names.client_mac,
        false,
    )?;
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id.clone(),
        sent: true,
    })
}
