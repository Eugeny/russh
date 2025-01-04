use std::cell::RefCell;
use std::ops::DerefMut;

use log::{debug, trace, warn};
use russh_keys::helpers::sign_with_hash_alg;
use russh_keys::key::PrivateKeyWithHashAlg;
use ssh_encoding::Encode;
use ssh_key::{Algorithm, PublicKey};

use super::*;
use crate::cipher::SealingKey;
use crate::kex::{Kex, KexAlgorithm, KexAlgorithmImplementor, KEXES};
use crate::negotiation::{is_key_compatible_with_algo, Names, Select};
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
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

#[derive(Debug)]
pub(crate) struct ServerKex {
    exchange: Exchange,
    session_id: Option<CryptoVec>,
    state: ServerKexState,
    config: Arc<Config>,
}

impl ServerKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &[u8],
        server_sshid: &SshId,
        session_id: Option<CryptoVec>,
    ) -> Self {
        let exchange = Exchange::new(client_sshid, server_sshid.as_kex_hash_bytes());
        Self {
            config,
            exchange,
            session_id,
            state: ServerKexState::Created,
        }
    }

    fn is_rekey(&self) -> bool {
        self.session_id.is_some()
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

                trace!("server parse {:?} {:?}", input.buffer.len(), input.buffer);
                let algo = {
                    // read algorithms from packet.
                    debug!("extending {:?}", &self.exchange.client_kex_init[..]);
                    self.exchange.client_kex_init.extend(&input.buffer);
                    negotiation::Server::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        Some(&self.config.keys),
                    )?
                };
                debug!("algo = {:?}", algo);
                // debug!("write = {:?}", &write_buffer.buffer[..]);

                // seqno has already been incremented after read()
                if algo.strict_kex && input.seqn.0 != 1 && !self.is_rekey() {
                    return Err(
                        strict_kex_violation(msg::KEXINIT, input.seqn.0 as usize - 1).into(),
                    );
                }

                let kex = KEXES.get(&algo.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    let newkeys = compute_keys(
                        CryptoVec::new(),
                        kex,
                        algo.clone(),
                        self.exchange.clone(),
                        self.session_id.as_ref(),
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

                self.state = ServerKexState::WaitingForKexReply { names: algo, kex };

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
                    debug!("unknown key {:?}", names.key);
                    return Err(Error::UnknownKey);
                };

                // Look up the key we'll be using to sign the exchange hash
                #[allow(clippy::indexing_slicing)] // key index checked
                let key = &self.config.keys[matching_key_index];
                let signature_hash_alg = match &names.key {
                    Algorithm::Rsa { hash } => *hash,
                    _ => None,
                };
                //---

                let hash = HASH_BUF.with(|buffer| {
                    let mut buffer = buffer.borrow_mut();
                    buffer.clear();
                    debug!("server kexdhdone.exchange = {:?}", exchange);

                    let mut pubkey_vec = CryptoVec::new();
                    key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;

                    let hash = kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)?;
                    debug!("exchange hash: {:?}", hash);

                    Ok::<_, Error>(hash)
                })?;

                // Hash signature
                debug!("signing with key {:?}", key);
                debug!("hash: {:?}", hash);
                debug!("key: {:?}", key);
                let signature = sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg)?,
                    &hash,
                )?;

                output.packet(|w| {
                    warn!("sending ecdh reply");
                    msg::KEX_ECDH_REPLY.encode(w)?;
                    key.public_key().to_bytes()?.encode(w)?;
                    // Server ephemeral
                    exchange.server_ephemeral.encode(w)?;
                    signature.encode(w)?;
                    Ok(())
                })?;

                output.packet(|w| {
                    warn!("sending newkeys");
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.session_id.as_ref(),
                )?;

                let reset_seqn = newkeys.names.strict_kex;

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

                debug!("newkeys received");
                Ok(KexProgress::Done {
                    newkeys,
                    server_host_key: None,
                })
            }
        }
    }
}

// impl KexInit {
    //     pub fn server_parse(
    //         mut self,
    //         config: &Config,
    //         cipher: &mut (dyn SealingKey + Send),
    //         buf: &[u8],
    //         write_buffer: &mut SSHBuffer,
    //     ) -> Result<OldKex, Error> {
    //         if buf.first() == Some(&msg::KEXINIT) {
    //             let algo = {
    //                 // read algorithms from packet.
    //                 self.exchange.client_kex_init.extend(buf);
    //                 super::negotiation::Server::read_kex(buf, &config.preferred, Some(&config.keys))?
    //             };
    //             if !self.sent {
    //                 self.server_write(config, cipher, write_buffer)?
    //             }

    //             let Some(matching_key_index) = config
    //                 .keys
    //                 .iter()
    //                 .position(|key| is_key_compatible_with_algo(key, &algo.key))
    //             else {
    //                 debug!("unknown key {:?}", algo.key);
    //                 return Err(Error::UnknownKey);
    //             };

    //             let next_kex = OldKex::Dh(KexDh {
    //                 exchange: self.exchange,
    //                 key: matching_key_index,
    //                 names: algo,
    //                 session_id: self.session_id,
    //             });

    //             Ok(next_kex)
    //         } else {
    //             Ok(OldKex::Init(self))
    //         }
    //     }

//     pub fn server_write(
//         &mut self,
//         config: &Config,
//         cipher: &mut (dyn SealingKey + Send),
//         write_buffer: &mut SSHBuffer,
//     ) -> Result<(), Error> {
//         self.exchange.server_kex_init.clear();
//         let mut writer = PacketWriter::new(cipher, write_buffer);
//         self.exchange.server_kex_init =
//             negotiation::write_kex(&config.preferred, &mut writer, Some(config))?;
//         debug!("server kex init: {:?}", &self.exchange.server_kex_init[..]);
//         self.sent = true;
//         Ok(())
//     }
// }

// impl KexDh {
//     pub fn parse(
//         mut self,
//         config: &Config,
//         cipher: &mut dyn SealingKey,
//         buf: &[u8],
//         write_buffer: &mut SSHBuffer,
//     ) -> Result<OldKex, Error> {
//         if self.names.ignore_guessed {
//             // If we need to ignore this packet.
//             self.names.ignore_guessed = false;
//             Ok(OldKex::Dh(self))
//         } else {
//             // Else, process it.
//             let Some((&msg::KEX_ECDH_INIT, mut r)) = buf.split_first() else {
//                 return Err(Error::Inconsistent);
//             };

//             self.exchange
//                 .client_ephemeral
//                 .extend(&Bytes::decode(&mut r)?);

//             let mut kex = KEXES.get(&self.names.kex).ok_or(Error::UnknownAlgo)?.make();

//             kex.server_dh(&mut self.exchange, buf)?;

//             // Look up the key we'll be using to sign the exchange hash
//             #[allow(clippy::indexing_slicing)] // key index checked
//             let key = &config.keys[self.key];
//             let signature_hash_alg = match &self.names.key {
//                 Algorithm::Rsa { hash } => *hash,
//                 _ => None,
//             };

//             // Then, we fill the write buffer right away, so that we
//             // can output it immediately when the time comes.
//             let kexdhdone = KexDhDone {
//                 exchange: self.exchange,
//                 kex,
//                 key: self.key,
//                 names: self.names,
//                 session_id: self.session_id,
//             };

//             let hash: Result<_, Error> = HASH_BUF.with(|buffer| {
//                 let mut buffer = buffer.borrow_mut();
//                 buffer.clear();
//                 debug!("server kexdhdone.exchange = {:?}", kexdhdone.exchange);

//                 let mut pubkey_vec = CryptoVec::new();
//                 key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;

//                 let hash = kexdhdone.kex.compute_exchange_hash(
//                     &pubkey_vec,
//                     &kexdhdone.exchange,
//                     &mut buffer,
//                 )?;
//                 debug!("exchange hash: {:?}", hash);
//                 buffer.clear();
//                 buffer.push(msg::KEX_ECDH_REPLY);
//                 key.public_key().to_bytes()?.encode(buffer.deref_mut())?;

//                 // Server ephemeral
//                 kexdhdone
//                     .exchange
//                     .server_ephemeral
//                     .encode(buffer.deref_mut())?;

//                 // Hash signature
//                 debug!("signing with key {:?}", kexdhdone.key);
//                 debug!("hash: {:?}", hash);
//                 debug!("key: {:?}", key);

//                 sign_with_hash_alg(
//                     &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg)?,
//                     &hash,
//                 )?
//                 .encode(&mut *buffer)?;

//                 cipher.write(&buffer, write_buffer);
//                 cipher.write(&[msg::NEWKEYS], write_buffer);
//                 Ok(hash)
//             });

//             Ok(OldKex::Keys(kexdhdone.compute_keys(hash?, true)?))
//         }
//     }
// }

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
