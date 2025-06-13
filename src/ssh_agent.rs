use std::collections::HashMap;
use std::marker::Sync;
use std::result::Result;
use std::sync::{Arc, RwLock};

use anyhow::Error;
use byteorder::{BigEndian, ByteOrder};
use futures::stream::{Stream, StreamExt};
use russh_cryptovec::CryptoVec;
use ssh_key::{HashAlg, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio_util::sync::CancellationToken;

use super::msg::{REQUEST_IDENTITIES, SIGN_REQUEST};
use crate::encoding::{Encoding, Position, Reader};
use crate::msg::{self, EXTENSION};
use crate::session_bind::SessionBindResult;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct KeyStore<Key>(pub Arc<RwLock<HashMap<Vec<u8>, Key>>>);

pub trait SshKey {
    fn name(&self) -> &str;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn private_key(&self) -> Option<Box<dyn SigningKey>>;
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub trait Agent<I: Clone, K>: Clone + Send + 'static {
    fn confirm(
        &self,
        _pk: K,
        _data: &[u8],
        _connection_info: &I,
    ) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }

    fn can_list(&self, _connection_info: &I) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }

    fn set_sessionbind_info(
        &self,
        _session_bind_info: &SessionBindResult,
        _connection_info: &I,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

pub async fn serve<S, L, A, I, K>(
    mut listener: L,
    agent: A,
    keys: KeyStore<K>,
    cancellation_token: CancellationToken,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<(S, I)>> + Unpin,
    A: Agent<I, K> + Send + Sync + 'static,
    I: Clone + Send + Sync + 'static,
    K: SshKey + Send + Sync + Clone + 'static,
{
    loop {
        select! {
            _ = cancellation_token.cancelled() => {
                break;
            }
            Some(Ok((stream, info))) = listener.next() => {
                let mut buf = CryptoVec::new();
                buf.resize(4);
                let keys = keys.clone();
                let agent = agent.clone();

                tokio::spawn(async move {
                    let _ = Connection {
                        keys,
                        agent: Some(agent),
                        s: stream,
                        buf: CryptoVec::new(),
                        connection_info: info.clone(),
                    }
                    .run()
                    .await;
                });
            }
        }
    }

    Ok(())
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent<I, K>, I: Clone, K> {
    keys: KeyStore<K>,
    agent: Option<A>,
    s: S,
    buf: CryptoVec,
    connection_info: I,
}

impl<
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        A: Agent<I, K> + Send + Sync + 'static,
        I: Clone,
        K: SshKey + Send + Sync + Clone + 'static,
    > Connection<S, A, I, K>
{
    async fn run(mut self) -> Result<(), Error> {
        let mut writebuf = CryptoVec::new();
        loop {
            // Reading the length
            self.buf.clear();
            self.buf.resize(4);
            self.s.read_exact(&mut self.buf).await?;

            // Reading the rest of the buffer
            let len = BigEndian::read_u32(&self.buf) as usize;
            self.buf.clear();
            self.buf.resize(len);
            self.s.read_exact(&mut self.buf).await?;

            // respond
            writebuf.clear();
            self.respond(&mut writebuf).await?;
            self.s.write_all(&writebuf).await?;
            self.s.flush().await?
        }
    }

    async fn respond(&mut self, writebuf: &mut CryptoVec) -> Result<(), Error> {
        writebuf.extend(&[0, 0, 0, 0]);
        let mut r = self.buf.reader(0);
        match r.read_byte() {
            Ok(REQUEST_IDENTITIES) => {
                let agent = self.agent.take().ok_or(SSHAgentError::AgentFailure)?;
                self.agent = Some(agent.clone());
                if !agent.can_list(&self.connection_info).await {
                    writebuf.push(msg::FAILURE);
                } else if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (public_key_bytes, key) in keys.iter() {
                        writebuf.extend_ssh_string(public_key_bytes);
                        writebuf.extend_ssh_string(key.name().as_bytes());
                    }
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(SIGN_REQUEST) => {
                let agent = self.agent.take().ok_or(SSHAgentError::AgentFailure)?;
                let (agent, signed) = self.try_sign(agent, r, writebuf).await?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4);
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(EXTENSION) => {
                let extension_name = r.read_string()?;
                let extension_name = String::from_utf8(extension_name.to_vec())
                    .map_err(|_| SSHAgentError::AgentFailure)?;

                // https://raw.githubusercontent.com/openssh/openssh-portable/refs/heads/master/PROTOCOL.agent
                if extension_name == "session-bind@openssh.com" {
                    if let Some(agent) = self.agent.as_mut() {
                        if crate::session_bind::respond_extension_session_bind(
                            agent,
                            &mut r,
                            self.connection_info.clone(),
                        )
                        .await
                        .is_ok()
                        {
                            writebuf.push(msg::SUCCESS);
                        } else {
                            writebuf.push(msg::FAILURE);
                        }
                    } else {
                        writebuf.push(msg::SUCCESS);
                    }
                } else {
                    writebuf.push(msg::FAILURE);
                }
            }
            _ => writebuf.push(msg::FAILURE),
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[..], len as u32);
        Ok(())
    }

    async fn try_sign(
        &self,
        agent: A,
        mut r: Position<'_>,
        writebuf: &mut CryptoVec,
    ) -> Result<(A, bool), Error> {
        let blob = r.read_string()?;
        let key = {
            let k = self.keys.0.read().or(Err(SSHAgentError::AgentFailure))?;
            if let Some(key) = k.get(blob) {
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };

        let data = r.read_string()?;

        let ok = agent.confirm(key, data, &self.connection_info).await;
        if !ok {
            return Ok((agent, false));
        }

        let key = {
            let k = self.keys.0.read().or(Err(SSHAgentError::AgentFailure))?;
            if let Some(key) = k.get(blob) {
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };

        match key.private_key() {
            Some(private_key) => {
                writebuf.push(msg::SIGN_RESPONSE);
                let signature = private_key
                    .try_sign(data)
                    .or(Err(SSHAgentError::AgentFailure));
                let Ok(signature) = signature else {
                    writebuf.push(msg::FAILURE);
                    return Ok((agent, false));
                };

                let signature_name = match signature.algorithm() {
                    ssh_key::Algorithm::Ed25519 => "ssh-ed25519",
                    ssh_key::Algorithm::Rsa { hash: None } => "ssh-rsa",
                    ssh_key::Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    } => "rsa-sha2-256",
                    ssh_key::Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    } => "rsa-sha2-512",
                    _ => {
                        println!("Unsupported signing algorithm");
                        writebuf.push(msg::FAILURE);
                        return Ok((agent, false));
                    }
                };

                writebuf.push_u32_be(
                    signature_name.len() as u32 + signature.as_bytes().len() as u32 + 8,
                );
                writebuf.extend_ssh_string(signature_name.as_bytes());
                writebuf.extend_ssh_string(signature.as_bytes());

                let len = writebuf.len();
                BigEndian::write_u32(writebuf, (len - 4) as u32);

                Ok((agent, true))
            }
            None => {
                writebuf.push(msg::FAILURE);
                Ok((agent, false))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SSHAgentError {
    #[error("Agent failure")]
    AgentFailure,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}
