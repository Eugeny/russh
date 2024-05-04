use std::collections::HashMap;
use std::convert::TryFrom;
use std::marker::Sync;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use futures::future::Future;
use futures::stream::{Stream, StreamExt};
use russh_cryptovec::CryptoVec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;
use {std, tokio};

use super::{msg, Constraint};
use crate::encoding::{Encoding, Position, Reader};
use crate::{key, Error};

#[derive(Clone)]
#[allow(clippy::type_complexity)]
struct KeyStore(Arc<RwLock<HashMap<Vec<u8>, (Arc<key::KeyPair>, SystemTime, Vec<Constraint>)>>>);

#[derive(Clone)]
struct Lock(Arc<RwLock<CryptoVec>>);

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub enum MessageType {
    RequestKeys,
    AddKeys,
    RemoveKeys,
    RemoveAllKeys,
    Sign,
    Lock,
    Unlock,
}

#[async_trait]
pub trait Agent: Clone + Send + 'static {
    fn confirm(
        self,
        _pk: Arc<key::KeyPair>,
    ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }

    async fn confirm_request(&self, _msg: MessageType) -> bool {
        true
    }
}

pub async fn serve<S, L, A>(mut listener: L, agent: A) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<S>> + Unpin,
    A: Agent + Send + Sync + 'static,
{
    let keys = KeyStore(Arc::new(RwLock::new(HashMap::new())));
    let lock = Lock(Arc::new(RwLock::new(CryptoVec::new())));
    while let Some(Ok(stream)) = listener.next().await {
        let mut buf = CryptoVec::new();
        buf.resize(4);
        tokio::spawn(
            (Connection {
                lock: lock.clone(),
                keys: keys.clone(),
                agent: Some(agent.clone()),
                s: stream,
                buf: CryptoVec::new(),
            })
            .run(),
        );
    }
    Ok(())
}

impl Agent for () {
    fn confirm(
        self,
        _: Arc<key::KeyPair>,
    ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent> {
    lock: Lock,
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
        let is_locked = {
            if let Ok(password) = self.lock.0.read() {
                !password.is_empty()
            } else {
                true
            }
        };
        writebuf.extend(&[0, 0, 0, 0]);
        let mut r = self.buf.reader(0);
        let agentref = self.agent.as_ref().ok_or(Error::AgentFailure)?;
        match r.read_byte() {
            Ok(11) if !is_locked && agentref.confirm_request(MessageType::RequestKeys).await => {
                // request identities
                if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (k, _) in keys.iter() {
                        writebuf.extend_ssh_string(k);
                        writebuf.extend_ssh_string(b"");
                    }
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(13) if !is_locked && agentref.confirm_request(MessageType::Sign).await => {
                // sign request
                let agent = self.agent.take().ok_or(Error::AgentFailure)?;
                let (agent, signed) = self.try_sign(agent, r, writebuf).await?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4);
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(17) if !is_locked && agentref.confirm_request(MessageType::AddKeys).await => {
                // add identity
                if let Ok(true) = self.add_key(r, false, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(18) if !is_locked && agentref.confirm_request(MessageType::RemoveKeys).await => {
                // remove identity
                if let Ok(true) = self.remove_identity(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(19) if !is_locked && agentref.confirm_request(MessageType::RemoveAllKeys).await => {
                // remove all identities
                if let Ok(mut keys) = self.keys.0.write() {
                    keys.clear();
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(22) if !is_locked && agentref.confirm_request(MessageType::Lock).await => {
                // lock
                if let Ok(()) = self.lock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(23) if is_locked && agentref.confirm_request(MessageType::Unlock).await => {
                // unlock
                if let Ok(true) = self.unlock(r) {
                    writebuf.push(msg::SUCCESS)
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(25) if !is_locked && agentref.confirm_request(MessageType::AddKeys).await => {
                // add identity constrained
                if let Ok(true) = self.add_key(r, true, writebuf).await {
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            _ => {
                // Message not understood
                writebuf.push(msg::FAILURE)
            }
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[..], len as u32);
        Ok(())
    }

    fn lock(&self, mut r: Position) -> Result<(), Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
        lock.extend(password);
        Ok(())
    }

    fn unlock(&self, mut r: Position) -> Result<bool, Error> {
        let password = r.read_string()?;
        let mut lock = self.lock.0.write().or(Err(Error::AgentFailure))?;
        if &lock[..] == password {
            lock.clear();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_identity(&self, mut r: Position) -> Result<bool, Error> {
        if let Ok(mut keys) = self.keys.0.write() {
            if keys.remove(r.read_string()?).is_some() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn add_key(
        &self,
        mut r: Position<'_>,
        constrained: bool,
        writebuf: &mut CryptoVec,
    ) -> Result<bool, Error> {
        let (blob, key_pair) = {
            use ssh_encoding::{Decode, Encode};

            let private_key = ssh_key::private::PrivateKey::new(
                ssh_key::private::KeypairData::decode(&mut r)?,
                "",
            )?;
            let _comment = r.read_string()?;
            let key_pair = key::KeyPair::try_from(&private_key)?;

            let mut blob = Vec::new();
            private_key.public_key().key_data().encode(&mut blob)?;

            (blob, key_pair)
        };
        writebuf.push(msg::SUCCESS);
        let mut w = self.keys.0.write().or(Err(Error::AgentFailure))?;
        let now = SystemTime::now();
        if constrained {
            let mut c = Vec::new();
            while let Ok(t) = r.read_byte() {
                if t == msg::CONSTRAIN_LIFETIME {
                    let seconds = r.read_u32()?;
                    c.push(Constraint::KeyLifetime { seconds });
                    let blob = blob.clone();
                    let keys = self.keys.clone();
                    tokio::spawn(async move {
                        sleep(Duration::from_secs(seconds as u64)).await;
                        if let Ok(mut keys) = keys.0.write() {
                            let delete = if let Some(&(_, time, _)) = keys.get(&blob) {
                                time == now
                            } else {
                                false
                            };
                            if delete {
                                keys.remove(&blob);
                            }
                        }
                    });
                } else if t == msg::CONSTRAIN_CONFIRM {
                    c.push(Constraint::Confirm)
                } else {
                    return Ok(false);
                }
            }
            w.insert(blob, (Arc::new(key_pair), now, c));
        } else {
            w.insert(blob, (Arc::new(key_pair), now, Vec::new()));
        }
        Ok(true)
    }

    async fn try_sign(
        &self,
        agent: A,
        mut r: Position<'_>,
        writebuf: &mut CryptoVec,
    ) -> Result<(A, bool), Error> {
        let mut needs_confirm = false;
        let key = {
            let blob = r.read_string()?;
            let k = self.keys.0.read().or(Err(Error::AgentFailure))?;
            if let Some((key, _, constraints)) = k.get(blob) {
                if constraints.iter().any(|c| *c == Constraint::Confirm) {
                    needs_confirm = true;
                }
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };
        let agent = if needs_confirm {
            let (agent, ok) = agent.confirm(key.clone()).await;
            if !ok {
                return Ok((agent, false));
            }
            agent
        } else {
            agent
        };
        writebuf.push(msg::SIGN_RESPONSE);
        let data = r.read_string()?;
        key.add_signature(writebuf, data)?;
        let len = writebuf.len();
        BigEndian::write_u32(writebuf, (len - 4) as u32);

        Ok((agent, true))
    }
}
