use std::collections::HashMap;
use std::marker::Sync;
use std::sync::{Arc, RwLock};

use crate::encoding::{Encoding, Position, Reader};
use byteorder::{BigEndian, ByteOrder};
use futures::stream::{Stream, StreamExt};
use russh_cryptovec::CryptoVec;
use ssh_key::{HashAlg, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::msg;
use anyhow::Error;

use super::msg::{REQUEST_IDENTITIES, SIGN_REQUEST};
use std::result::Result;

#[derive(Clone)]
pub struct Key {
    pub private_key: Option<ssh_key::private::PrivateKey>,
    pub name: String,
    pub cipher_uuid: String,
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct KeyStore(pub Arc<RwLock<HashMap<Vec<u8>, Key>>>);

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub trait Agent: Clone + Send + 'static {
    fn confirm(&self, _pk: Key) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }
    
    fn can_list(&self) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }
}

pub async fn serve<S, L, A>(
    mut listener: L,
    agent: A,
    keys: KeyStore,
    cancellation_token: CancellationToken,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<S>> + Unpin,
    A: Agent + Send + Sync + 'static,
{
    loop {
        select! {
            _ = cancellation_token.cancelled() => {
                break;
            }
            Some(Ok(stream)) = listener.next() => {
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
                    }
                    .run()
                    .await;
                });
            }
        }
    }

    Ok(())
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent> {
    keys: KeyStore,
    agent: Option<A>,
    s: S,
    buf: CryptoVec,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static, A: Agent + Send + Sync + 'static>
    Connection<S, A>
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
                if !agent.can_list().await {
                    writebuf.push(msg::FAILURE);
                    return Ok(());
                }

                if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (public_key_bytes, key) in keys.iter() {
                        writebuf.extend_ssh_string(public_key_bytes);
                        writebuf.extend_ssh_string(key.name.as_bytes());
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

        let ok = agent.confirm(key.clone()).await;
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

        match key.private_key {
            Some(private_key) => {
                writebuf.push(msg::SIGN_RESPONSE);
                let signer: &dyn SigningKey = &private_key;
                let sig = signer.try_sign(data).or(Err(SSHAgentError::AgentFailure));
                let sig = match sig {
                    Ok(sig) => sig,
                    Err(err) => {
                        println!("Error signing: {:?}", err);
                        writebuf.push(msg::FAILURE);
                        return Ok((agent, false));
                    }
                };

                let sig_name = match sig.algorithm() {
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

                writebuf.push_u32_be(sig_name.len() as u32 + sig.as_bytes().len() as u32 + 8);
                writebuf.extend_ssh_string(sig_name.as_bytes());
                writebuf.extend_ssh_string(sig.as_bytes());

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
}
