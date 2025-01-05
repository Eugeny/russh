use core::fmt;
use std::cell::RefCell;

use log::debug;
use russh_keys::helpers::sign_with_hash_alg;
use russh_keys::key::PrivateKeyWithHashAlg;
use ssh_encoding::Encode;
use ssh_key::Algorithm;

use super::*;
use crate::kex::{Kex, KexAlgorithm, KexAlgorithmImplementor, KexCause, KEXES};
use crate::negotiation::{is_key_compatible_with_algo, Names, Select};
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerKexState {
    Created,
    WaitingForKexReply {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        newkeys: NewKeys,
    },
}

pub(crate) struct ServerKex {
    exchange: Exchange,
    cause: KexCause,
    state: ServerKexState,
    config: Arc<Config>,
}

impl Debug for ServerKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ServerKexState::Created => {
                s.field("state", &"created");
            }
            ServerKexState::WaitingForKexReply { .. } => {
                s.field("state", &"waiting for a reply");
            }
            ServerKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

impl ServerKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &[u8],
        server_sshid: &SshId,
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid, server_sshid.as_kex_hash_bytes());
        Self {
            config,
            exchange,
            cause,
            state: ServerKexState::Created,
        }
    }
}

impl Kex for ServerKex {
    fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        self.exchange.server_kex_init =
            negotiation::write_kex(&self.config.preferred, output, Some(self.config.as_ref()))?;

        Ok(())
    }

    fn step(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
    ) -> Result<KexProgress<Self>, Error> {
        match self.state {
            ServerKexState::Created => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                let names = {
                    self.exchange.client_kex_init.extend(&input.buffer);
                    negotiation::Server::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        Some(&self.config.keys),
                    )?
                };
                debug!("negotiated: {names:?}");

                // seqno has already been incremented after read()
                if !self.cause.is_rekey() && self.cause.is_strict_kex(&names) && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ));
                }

                let kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    let newkeys = compute_keys(
                        CryptoVec::new(),
                        kex,
                        names.clone(),
                        self.exchange.clone(),
                        self.cause.session_id(),
                    )?;

                    output.packet(|w| {
                        msg::NEWKEYS.encode(w)?;
                        Ok(())
                    })?;

                    return Ok(KexProgress::Done {
                        newkeys,
                        server_host_key: None,
                    });
                }

                self.state = ServerKexState::WaitingForKexReply { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForKexReply { mut names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ServerKexState::WaitingForKexReply { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                // We've received ECDH_REPLY
                if input.buffer.first() != Some(&msg::KEX_ECDH_INIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit);
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                self.exchange
                    .client_ephemeral
                    .extend(&Bytes::decode(&mut r)?);

                let exchange = &mut self.exchange;
                kex.server_dh(exchange, &input.buffer)?;

                let Some(matching_key_index) = self
                    .config
                    .keys
                    .iter()
                    .position(|key| is_key_compatible_with_algo(key, &names.key))
                else {
                    debug!("we don't have a host key of type {:?}", names.key);
                    return Err(Error::UnknownKey);
                };

                // Look up the key we'll be using to sign the exchange hash
                #[allow(clippy::indexing_slicing)] // key index checked
                let key = &self.config.keys[matching_key_index];
                let signature_hash_alg = match &names.key {
                    Algorithm::Rsa { hash } => *hash,
                    _ => None,
                };

                let hash = HASH_BUF.with(|buffer| {
                    let mut buffer = buffer.borrow_mut();
                    buffer.clear();

                    let mut pubkey_vec = CryptoVec::new();
                    key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;

                    let hash = kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)?;

                    Ok::<_, Error>(hash)
                })?;

                // Hash signature
                debug!("signing with key {:?}", key);
                let signature = sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg)?,
                    &hash,
                )?;

                output.packet(|w| {
                    msg::KEX_ECDH_REPLY.encode(w)?;
                    key.public_key().to_bytes()?.encode(w)?;
                    exchange.server_ephemeral.encode(w)?;
                    signature.encode(w)?;
                    Ok(())
                })?;

                output.packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                let reset_seqn = self.cause.is_strict_kex(&newkeys.names);

                self.state = ServerKexState::WaitingForNewKeys { newkeys };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ServerKexState::WaitingForNewKeys { newkeys } => {
                let Some(input) = input else {
                    return Err(Error::KexInit);
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex);
                }

                debug!("new keys received");
                Ok(KexProgress::Done {
                    newkeys,
                    server_host_key: None,
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
        session_id,
        &hash,
        names.cipher,
        names.client_mac,
        names.server_mac,
        true,
    )?;
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id.clone(),
    })
}
