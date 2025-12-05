use core::fmt;
use std::cell::RefCell;

use client::GexParams;
use log::debug;
use num_bigint::BigUint;
use ssh_encoding::Encode;
use ssh_key::Algorithm;

use super::*;
use crate::helpers::sign_with_hash_alg;
use crate::kex::dh::biguint_to_mpint;
use crate::kex::{KexAlgorithm, KexAlgorithmImplementor, KexCause, KEXES};
use crate::keys::key::PrivateKeyWithHashAlg;
use crate::negotiation::{is_key_compatible_with_algo, Names, Select};
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerKexState {
    Created,
    WaitingForGexRequest {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhInit {
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
            ServerKexState::WaitingForGexRequest { .. } => {
                s.field("state", &"waiting for GEX request");
            }
            ServerKexState::WaitingForDhInit { .. } => {
                s.field("state", &"waiting for DH reply");
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

    pub fn kexinit(&mut self, output: &mut PacketWriter) -> Result<(), Error> {
        self.exchange.server_kex_init =
            negotiation::write_kex(&self.config.preferred, output, Some(self.config.as_ref()))?;

        Ok(())
    }

    pub async fn step<H: Handler + Send>(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut PacketWriter,
        handler: &mut H,
    ) -> Result<KexProgress<Self>, H::Error> {
        match self.state {
            ServerKexState::Created => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                let names = {
                    self.exchange.client_kex_init.extend(&input.buffer);
                    negotiation::Server::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        Some(&self.config.keys),
                        &self.cause,
                    )?
                };
                debug!("negotiated: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ))?;
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

                if kex.is_dh_gex() {
                    self.state = ServerKexState::WaitingForGexRequest { names, kex };
                } else {
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForGexRequest { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEX_DH_GEX_REQUEST) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let gex_params = GexParams::decode(&mut &input.buffer[1..])?;
                debug!("client requests a gex group: {gex_params:?}");

                let Some(dh_group) = handler.lookup_dh_gex_group(&gex_params).await? else {
                    debug!("server::Handler impl did not find a matching DH group (is lookup_dh_gex_group implemented?)");
                    return Err(Error::Kex)?;
                };

                let prime = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.prime));
                let generator = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.generator));

                self.exchange.gex = Some((gex_params, dh_group.clone()));
                kex.dh_gex_set_group(dh_group)?;

                output.packet(|w| {
                    msg::KEX_DH_GEX_GROUP.encode(w)?;
                    prime.encode(w)?;
                    generator.encode(w)?;
                    Ok(())
                })?;

                self.state = ServerKexState::WaitingForDhInit { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForDhInit { mut names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_INIT,
                        false => &msg::KEX_ECDH_INIT,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                self.exchange
                    .client_ephemeral
                    .extend(&Bytes::decode(&mut r).map_err(Into::into)?);

                let exchange = &mut self.exchange;
                kex.server_dh(exchange, &input.buffer)?;

                let Some(matching_key_index) = self
                    .config
                    .keys
                    .iter()
                    .position(|key| is_key_compatible_with_algo(key, &names.key))
                else {
                    debug!("we don't have a host key of type {:?}", names.key);
                    return Err(Error::UnknownKey.into());
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
                debug!("signing with key {key:?}");
                let signature = sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg),
                    &hash,
                )
                .map_err(Into::into)?;

                output.packet(|w| {
                    match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    }
                    .encode(w)?;
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

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ServerKexState::WaitingForNewKeys { newkeys };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ServerKexState::WaitingForNewKeys { newkeys } => {
                let Some(input) = input else {
                    return Err(Error::KexInit.into());
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex.into());
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
