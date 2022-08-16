// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::cell::RefCell;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::task::{Context, Poll};
use futures::Future;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::{Encoding, Reader};
use russh_keys::key::{self, parse_public_key, SignatureHash};
use tokio;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::pin;

use crate::channels::{Channel, ChannelMsg};
use crate::key::PubKey;
use crate::pty::Pty;
use crate::session::*;
use crate::ssh_read::SshRead;
use crate::sshbuffer::*;
use crate::{auth, negotiation, ChannelId, ChannelOpenFailure, Disconnect, Limits, Sig};

mod kex;
use crate::cipher::{self, clear, CipherPair, OpeningKey};
use crate::{msg, Error};
mod encrypted;
mod session;

use tokio::sync::mpsc::*;

pub struct Session {
    common: CommonSession<Arc<Config>>,
    receiver: Receiver<Msg>,
    sender: UnboundedSender<Reply>,
    channels: HashMap<ChannelId, UnboundedSender<ChannelMsg>>,
    target_window_size: u32,
    pending_reads: Vec<CryptoVec>,
    pending_len: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        debug!("drop session")
    }
}

#[derive(Debug)]
enum Reply {
    AuthSuccess,
    AuthFailure,
    ChannelOpenFailure,
    SignRequest {
        key: russh_keys::key::PublicKey,
        data: CryptoVec,
    },
}

#[derive(Debug)]
pub enum Msg {
    Authenticate {
        user: String,
        method: auth::Method,
    },
    Signed {
        data: CryptoVec,
    },
    ChannelOpenSession {
        sender: UnboundedSender<ChannelMsg>,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        sender: UnboundedSender<ChannelMsg>,
    },
    ChannelOpenDirectTcpIp {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        sender: UnboundedSender<ChannelMsg>,
    },
    TcpIpForward {
        want_reply: bool,
        address: String,
        port: u32,
    },
    CancelTcpIpForward {
        want_reply: bool,
        address: String,
        port: u32,
    },
    Disconnect {
        reason: Disconnect,
        description: String,
        language_tag: String,
    },
    Channel(ChannelId, ChannelMsg),
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle<H: Handler> {
    sender: Sender<Msg>,
    receiver: UnboundedReceiver<Reply>,
    join: tokio::task::JoinHandle<Result<(), H::Error>>,
}

impl<H: Handler> Drop for Handle<H> {
    fn drop(&mut self) {
        debug!("drop handle")
    }
}

impl<H: Handler> Handle<H> {
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub async fn authenticate_password<U: Into<String>, P: Into<String>>(
        &mut self,
        user: U,
        password: P,
    ) -> Result<bool, Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::Password {
                    password: password.into(),
                },
            })
            .await
            .map_err(|_| Error::SendError)?;
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(true),
                Some(Reply::AuthFailure) => return Ok(false),
                None => return Ok(false),
                _ => {}
            }
        }
    }

    pub async fn authenticate_publickey<U: Into<String>>(
        &mut self,
        user: U,
        key: Arc<key::KeyPair>,
    ) -> Result<bool, Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::PublicKey { key },
            })
            .await
            .map_err(|_| Error::SendError)?;
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(true),
                Some(Reply::AuthFailure) => return Ok(false),
                None => return Ok(false),
                _ => {}
            }
        }
    }

    pub async fn authenticate_future<U: Into<String>, S: auth::Signer>(
        &mut self,
        user: U,
        key: key::PublicKey,
        mut future: S,
    ) -> (S, Result<bool, S::Error>) {
        let user = user.into();
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::FuturePublicKey { key },
            })
            .await
            .is_err()
        {
            return (future, Err((crate::SendError {}).into()));
        }
        loop {
            let reply = self.receiver.recv().await;
            match reply {
                Some(Reply::AuthSuccess) => return (future, Ok(true)),
                Some(Reply::AuthFailure) => return (future, Ok(false)),
                Some(Reply::SignRequest { key, data }) => {
                    let (f, data) = future.auth_publickey_sign(&key, data).await;
                    future = f;
                    let data = match data {
                        Ok(data) => data,
                        Err(e) => return (future, Err(e)),
                    };
                    if self.sender.send(Msg::Signed { data }).await.is_err() {
                        return (future, Err((crate::SendError {}).into()));
                    }
                }
                None => return (future, Ok(false)),
                _ => {}
            }
        }
    }

    async fn wait_channel_confirmation(
        &self,
        mut receiver: UnboundedReceiver<ChannelMsg>,
    ) -> Result<Channel<Msg>, Error> {
        loop {
            match receiver.recv().await {
                Some(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                }) => {
                    return Ok(Channel {
                        id,
                        sender: self.sender.clone(),
                        receiver,
                        max_packet_size,
                        window_size,
                    });
                }
                None => {
                    return Err(Error::Disconnect);
                }
                msg => {
                    debug!("msg = {:?}", msg);
                }
            }
        }
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Some(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&mut self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenSession { sender })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    pub async fn channel_open_x11<A: Into<String>>(
        &mut self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                sender,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &mut self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenDirectTcpIp {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                sender,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    /// Send data to the session referenced by this handler.
    ///
    /// This is useful for server-initiated channels; for channels created by
    /// the client, prefer to use the Channel returned from the `open_*` methods.
    pub async fn data(&self, id: ChannelId, data: CryptoVec) -> Result<(), CryptoVec> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Data { data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::Data { data, .. }) => data,
                _ => unreachable!(),
            })
    }

    /// Send data to the session referenced by this handler.
    ///
    /// This is useful for server-initiated channels; for channels created by
    /// the client, prefer to use the Channel returned from the `open_*` methods.
    pub async fn extended_data(
        &self,
        id: ChannelId,
        ext: u32,
        data: CryptoVec,
    ) -> Result<(), CryptoVec> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExtendedData { data, ext }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::ExtendedData { data, .. }) => data,
                _ => unreachable!(),
            })
    }

    /// Sends a disconnect message.
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description: description.into(),
                language_tag: language_tag.into(),
            })
            .await
            .map_err(|_| Error::SendError)?;
        Ok(())
    }
}

impl<H: Handler> Future for Handle<H> {
    type Output = Result<(), H::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.join), cx) {
            Poll::Ready(r) => Poll::Ready(match r {
                Ok(Ok(x)) => Ok(x),
                Err(e) => Err(crate::Error::from(e).into()),
                Ok(Err(e)) => Err(e),
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}

use std::net::SocketAddr;
pub async fn connect<H: Handler + Send + 'static>(
    config: Arc<Config>,
    addr: SocketAddr,
    handler: H,
) -> Result<Handle<H>, H::Error> {
    let socket = TcpStream::connect(addr).await.map_err(crate::Error::from)?;
    connect_stream(config, socket, handler).await
}

pub async fn connect_stream<H, R>(
    config: Arc<Config>,
    mut stream: R,
    handler: H,
) -> Result<Handle<H>, H::Error>
where
    H: Handler + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Writing SSH id.
    let mut write_buffer = SSHBuffer::new();
    write_buffer.send_ssh_id(config.as_ref().client_id.as_bytes());
    stream
        .write_all(&write_buffer.buffer)
        .await
        .map_err(crate::Error::from)?;

    // Reading SSH id and allocating a session if correct.
    let mut stream = SshRead::new(stream);
    let sshid = stream.read_ssh_id().await?;
    let (sender, receiver) = channel(10);
    let (sender2, receiver2) = unbounded_channel();
    if config.maximum_packet_size > 65535 {
        error!(
            "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
            config.maximum_packet_size
        );
    }
    let mut session = Session {
        target_window_size: config.window_size,
        common: CommonSession {
            write_buffer,
            kex: None,
            auth_user: String::new(),
            auth_method: None, // Client only.
            cipher: CipherPair {
                local_to_remote: Box::new(clear::Key),
                remote_to_local: Box::new(clear::Key),
            },
            encrypted: None,
            config,
            wants_reply: false,
            disconnected: false,
            buffer: CryptoVec::new(),
        },
        receiver,
        sender: sender2,
        channels: HashMap::new(),
        pending_reads: Vec::new(),
        pending_len: 0,
    };
    session.read_ssh_id(sshid)?;
    let (encrypted_signal, encrypted_recv) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(session.run(stream, handler, Some(encrypted_signal)));

    if encrypted_recv.await.is_err() {
        join.await.map_err(crate::Error::Join)??;
        return Err(H::Error::from(crate::Error::Disconnect));
    }

    Ok(Handle {
        sender,
        receiver: receiver2,
        join,
    })
}

async fn start_reading<R: AsyncRead + Unpin>(
    mut stream_read: R,
    mut buffer: SSHBuffer,
    mut cipher: Box<dyn OpeningKey + Send>,
) -> Result<(usize, R, SSHBuffer, Box<dyn OpeningKey + Send>), Error> {
    buffer.buffer.clear();
    let n = cipher::read(&mut stream_read, &mut buffer, &mut *cipher).await?;
    Ok((n, stream_read, buffer, cipher))
}

impl Session {
    async fn run<H: Handler + Send, R: AsyncRead + AsyncWrite + Unpin + Send>(
        mut self,
        mut stream: SshRead<R>,
        mut handler: H,
        mut encrypted_signal: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<(), H::Error> {
        self.flush()?;
        if !self.common.write_buffer.buffer.is_empty() {
            debug!("writing {:?} bytes", self.common.write_buffer.buffer.len());
            stream
                .write_all(&self.common.write_buffer.buffer)
                .await
                .map_err(crate::Error::from)?;
            stream.flush().await.map_err(crate::Error::from)?;
        }
        self.common.write_buffer.buffer.clear();
        let mut decomp = CryptoVec::new();

        let (stream_read, mut stream_write) = stream.split();
        let buffer = SSHBuffer::new();

        // Allow handing out references to the cipher
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.cipher.remote_to_local);

        let reading = start_reading(stream_read, buffer, opening_cipher);
        pin!(reading);

        #[allow(clippy::panic)] // false positive in select! macro
        while !self.common.disconnected {
            tokio::select! {
                r = &mut reading => {
                    let (stream_read, buffer, mut opening_cipher) = match r {
                        Ok((_, stream_read, buffer, opening_cipher)) => (stream_read, buffer, opening_cipher),
                        Err(e) => return Err(e.into())
                    };

                    std::mem::swap(&mut opening_cipher, &mut self.common.cipher.remote_to_local);

                    if buffer.buffer.len() < 5 {
                        break
                    }
                    let buf = if let Some(ref mut enc) = self.common.encrypted {
                        #[allow(clippy::indexing_slicing)] // length checked
                        if let Ok(buf) = enc.decompress.decompress(
                            &buffer.buffer[5..],
                            &mut decomp,
                        ) {
                            buf
                        } else {
                            break
                        }
                    } else {
                        #[allow(clippy::indexing_slicing)] // length checked
                        &buffer.buffer[5..]
                    };
                    if !buf.is_empty() {
                        #[allow(clippy::indexing_slicing)] // length checked
                        if buf[0] == crate::msg::DISCONNECT {
                            break;
                        } else if buf[0] > 4 {
                            let (h, s) = reply(self, handler, &mut encrypted_signal, buf).await?;
                            handler = h;
                            self = s;
                        }
                    }

                    std::mem::swap(&mut opening_cipher, &mut self.common.cipher.remote_to_local);
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                msg = self.receiver.recv(), if !self.is_rekeying() => {
                    match msg {
                        Some(Msg::Authenticate { user, method }) => {
                            self.write_auth_request_if_needed(&user, method);
                        }
                        Some(Msg::Signed { .. }) => {},
                        Some(Msg::ChannelOpenSession { sender }) => {
                            let id = self.channel_open_session()?;
                            self.channels.insert(id, sender);
                        }
                        Some(Msg::ChannelOpenX11 { originator_address, originator_port, sender }) => {
                            let id = self.channel_open_x11(&originator_address, originator_port)?;
                            self.channels.insert(id, sender);
                        }
                        Some(Msg::ChannelOpenDirectTcpIp { host_to_connect, port_to_connect, originator_address, originator_port, sender }) => {
                            let id = self.channel_open_direct_tcpip(&host_to_connect, port_to_connect, &originator_address, originator_port)?;
                            self.channels.insert(id, sender);
                        }
                        Some(Msg::TcpIpForward { want_reply, address, port }) => {
                            self.tcpip_forward(want_reply, &address, port)
                        },
                        Some(Msg::CancelTcpIpForward { want_reply, address, port }) => {
                            self.cancel_tcpip_forward(want_reply, &address, port)
                        },
                        Some(Msg::Disconnect { reason, description, language_tag }) => {
                            self.disconnect(reason, &description, &language_tag)
                        },
                        Some(Msg::Channel(id, ChannelMsg::Data { data })) => { self.data(id, data) },
                        Some(Msg::Channel(id, ChannelMsg::Eof)) => { self.eof(id); },
                        Some(Msg::Channel(id, ChannelMsg::ExtendedData { data, ext })) => { self.extended_data(id, ext, data); },
                        Some(Msg::Channel(id, ChannelMsg::RequestPty { want_reply, term, col_width, row_height, pix_width, pix_height, terminal_modes })) => {
                            self.request_pty(id, want_reply, &term, col_width, row_height, pix_width, pix_height, &terminal_modes)
                        },
                        Some(Msg::Channel(id, ChannelMsg::WindowChange { col_width, row_height, pix_width, pix_height })) => {
                            self.window_change(id, col_width, row_height, pix_width, pix_height)
                        },
                        Some(Msg::Channel(id, ChannelMsg::RequestX11 { want_reply, single_connection, x11_authentication_protocol, x11_authentication_cookie, x11_screen_number })) => {
                            self.request_x11(id, want_reply, single_connection, &x11_authentication_protocol, &x11_authentication_cookie, x11_screen_number)
                        },
                        Some(Msg::Channel(id, ChannelMsg::SetEnv { want_reply, variable_name, variable_value })) => {
                            self.set_env(id, want_reply, &variable_name, &variable_value)
                        },
                        Some(Msg::Channel(id, ChannelMsg::RequestShell { want_reply })) => {
                            self.request_shell(want_reply, id)
                        },
                        Some(Msg::Channel(id, ChannelMsg::Exec { want_reply, command })) => {
                            self.exec(id, want_reply, &command)
                        },
                        Some(Msg::Channel(id, ChannelMsg::Signal { signal })) => {
                            self.signal(id, signal)
                        },
                        Some(Msg::Channel(id, ChannelMsg::RequestSubsystem { want_reply, name })) => {
                            self.request_subsystem(want_reply, id, &name)
                        },
                        Some(_) => {
                            // should be unreachable, since the receiver only gets
                            // messages from methods implemented within russh
                            unimplemented!("unimplemented (server-only?) message: {:?}", msg)
                        },
                        None => {
                            self.common.disconnected = true;
                            break
                        }
                    }
                }
            }
            self.flush()?;
            if !self.common.write_buffer.buffer.is_empty() {
                debug!(
                    "writing to stream: {:?} bytes",
                    self.common.write_buffer.buffer.len()
                );
                stream_write
                    .write_all(&self.common.write_buffer.buffer)
                    .await
                    .map_err(crate::Error::from)?;
                stream_write.flush().await.map_err(crate::Error::from)?;
            }
            self.common.write_buffer.buffer.clear();
            if let Some(ref mut enc) = self.common.encrypted {
                if let EncryptedState::InitCompression = enc.state {
                    enc.client_compression.init_compress(&mut enc.compress);
                    enc.state = EncryptedState::Authenticated;
                }
            }
        }
        debug!("disconnected");
        if self.common.disconnected {
            stream_write.shutdown().await.map_err(crate::Error::from)?;
        }
        Ok(())
    }

    fn is_rekeying(&self) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.rekey.is_some()
        } else {
            true
        }
    }

    fn read_ssh_id(&mut self, sshid: &[u8]) -> Result<(), Error> {
        // self.read_buffer.bytes += sshid.bytes_read + 2;
        let mut exchange = Exchange::new();
        exchange.server_id.extend(sshid);
        // Preparing the response
        exchange
            .client_id
            .extend(self.common.config.as_ref().client_id.as_bytes());
        let mut kexinit = KexInit {
            exchange,
            algo: None,
            sent: false,
            session_id: None,
        };
        self.common.write_buffer.buffer.clear();
        kexinit.client_write(
            self.common.config.as_ref(),
            &mut *self.common.cipher.local_to_remote,
            &mut self.common.write_buffer,
        )?;
        self.common.kex = Some(Kex::Init(kexinit));
        Ok(())
    }

    /// Flush the temporary cleartext buffer into the encryption
    /// buffer. This does *not* flush to the socket.
    fn flush(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut *self.common.cipher.local_to_remote,
                &mut self.common.write_buffer,
            )? {
                info!("Re-exchanging keys");
                if enc.rekey.is_none() {
                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                        let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                        kexinit.client_write(
                            self.common.config.as_ref(),
                            &mut *self.common.cipher.local_to_remote,
                            &mut self.common.write_buffer,
                        )?;
                        enc.rekey = Some(Kex::Init(kexinit))
                    }
                }
            }
        }
        Ok(())
    }

    /// Send a `ChannelMsg` from the background handler to the client.
    pub fn send_channel_msg(&self, channel: ChannelId, msg: ChannelMsg) -> bool {
        if let Some(chan) = self.channels.get(&channel) {
            chan.send(msg).unwrap_or(());
            true
        } else {
            false
        }
    }
}
thread_local! {
    static HASH_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl KexDhDone {
    async fn server_key_check<H: Handler>(
        mut self,
        rekey: bool,
        mut handler: H,
        buf: &[u8],
    ) -> Result<(Kex, H), H::Error> {
        let mut reader = buf.reader(1);
        let pubkey = reader.read_string().map_err(crate::Error::from)?; // server public key.
        let pubkey = parse_public_key(
            pubkey,
            SignatureHash::from_rsa_hostkey_algo(self.names.key.0.as_bytes()),
        )
        .map_err(crate::Error::from)?;
        debug!("server_public_Key: {:?}", pubkey);
        if !rekey {
            let ret = handler.check_server_key(&pubkey).await?;
            handler = ret.0;
            let check = ret.1;
            if !check {
                return Err(Error::UnknownKey.into());
            }
        }
        HASH_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            let hash = {
                let server_ephemeral = reader.read_string().map_err(crate::Error::from)?;
                self.exchange.server_ephemeral.extend(server_ephemeral);
                let signature = reader.read_string().map_err(crate::Error::from)?;

                self.kex
                    .compute_shared_secret(&self.exchange.server_ephemeral)?;
                debug!("kexdhdone.exchange = {:?}", self.exchange);

                let mut pubkey_vec = CryptoVec::new();
                pubkey.push_to(&mut pubkey_vec);

                let hash =
                    self.kex
                        .compute_exchange_hash(&pubkey_vec, &self.exchange, &mut buffer)?;

                debug!("exchange hash: {:?}", hash);
                let signature = {
                    let mut sig_reader = signature.reader(0);
                    let sig_type = sig_reader.read_string().map_err(crate::Error::from)?;
                    debug!("sig_type: {:?}", sig_type);
                    sig_reader.read_string().map_err(crate::Error::from)?
                };
                use russh_keys::key::Verify;
                debug!("signature: {:?}", signature);
                if !pubkey.verify_server_auth(hash.as_ref(), signature) {
                    debug!("wrong server sig");
                    return Err(Error::WrongServerSig.into());
                }
                hash
            };
            let mut newkeys = self.compute_keys(hash, false)?;
            newkeys.sent = true;
            Ok((Kex::Keys(newkeys), handler))
        })
    }
}

async fn reply<H: Handler>(
    mut session: Session,
    mut handler: H,
    sender: &mut Option<tokio::sync::oneshot::Sender<()>>,
    buf: &[u8],
) -> Result<(H, Session), H::Error> {
    match session.common.kex.take() {
        Some(Kex::Init(kexinit)) => {
            if kexinit.algo.is_some()
                || buf.get(0) == Some(&msg::KEXINIT)
                || session.common.encrypted.is_none()
            {
                session.common.kex = Some(Kex::DhDone(kexinit.client_parse(
                    session.common.config.as_ref(),
                    &mut *session.common.cipher.local_to_remote,
                    buf,
                    &mut session.common.write_buffer,
                )?));
                session.flush()?;
            }
            Ok((handler, session))
        }
        Some(Kex::DhDone(mut kexdhdone)) => {
            if kexdhdone.names.ignore_guessed {
                kexdhdone.names.ignore_guessed = false;
                session.common.kex = Some(Kex::DhDone(kexdhdone));
                Ok((handler, session))
            } else if buf.get(0) == Some(&msg::KEX_ECDH_REPLY) {
                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                let (kex, h) = kexdhdone.server_key_check(false, handler, buf).await?;
                handler = h;
                session.common.kex = Some(kex);
                session
                    .common
                    .cipher
                    .local_to_remote
                    .write(&[msg::NEWKEYS], &mut session.common.write_buffer);
                session.flush()?;
                Ok((handler, session))
            } else {
                error!("Wrong packet received");
                Err(Error::Inconsistent.into())
            }
        }
        Some(Kex::Keys(newkeys)) => {
            debug!("newkeys received");
            if buf.get(0) != Some(&msg::NEWKEYS) {
                return Err(Error::Kex.into());
            }
            if let Some(sender) = sender.take() {
                sender.send(()).unwrap_or(());
            }
            session.common.encrypted(
                EncryptedState::WaitingServiceRequest {
                    accepted: false,
                    sent: false,
                },
                newkeys,
            );
            // Ok, NEWKEYS received, now encrypted.
            Ok((handler, session))
        }
        Some(kex) => {
            session.common.kex = Some(kex);
            Ok((handler, session))
        }
        None => session.client_read_encrypted(handler, buf).await,
    }
}

/// The configuration of clients.
#[derive(Debug)]
pub struct Config {
    /// The client ID string sent at the beginning of the protocol.
    pub client_id: String,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Lists of preferred algorithms.
    pub preferred: negotiation::Preferred,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!(
                "SSH-2.0-{}_{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ),
            limits: Limits::default(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            preferred: Default::default(),
            connection_timeout: None,
        }
    }
}

/// A client handler. Note that messages can be received from the
/// server at any time during a session.
pub trait Handler: Sized {
    type Error: From<crate::Error> + Send;
    /// A future ultimately resolving into a boolean, which can be
    /// returned by some parts of this handler.
    type FutureBool: Future<Output = Result<(Self, bool), Self::Error>> + Send;

    /// A future ultimately resolving into unit, which can be
    /// returned by some parts of this handler.
    type FutureUnit: Future<Output = Result<(Self, Session), Self::Error>> + Send;

    /// Convert a `bool` to `Self::FutureBool`. This is used to
    /// produce the default handlers.
    fn finished_bool(self, b: bool) -> Self::FutureBool;

    /// Produce a `Self::FutureUnit`. This is used to produce the
    /// default handlers.
    fn finished(self, session: Session) -> Self::FutureUnit;

    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    ///
    /// The returned Boolean is ignored.
    #[allow(unused_variables)]
    fn auth_banner(self, banner: &str, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    #[allow(unused_variables)]
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        self.finished_bool(false)
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(
        self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: Session,
    ) -> Self::FutureUnit {
        if let Some(channel) = session.channels.get(&id) {
            channel
                .send(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                })
                .unwrap_or(());
        } else {
            error!("no channel for id {:?}", id);
        }
        self.finished(session)
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    fn channel_success(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Success).unwrap_or(())
        }
        self.finished(session)
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        session.channels.remove(&channel);
        self.finished(session)
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Eof).unwrap_or(())
        }
        self.finished(session)
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(
        self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        mut session: Session,
    ) -> Self::FutureUnit {
        session.channels.remove(&channel);
        session.sender.send(Reply::ChannelOpenFailure).unwrap_or(());
        self.finished(session)
    }

    /// Called when a port foward request is made on a channel.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(
        self,
        channel: ChannelId,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the server gets an unknown channel. It may return `true`,
    /// if the channel of unknown type should be handled. If it returns `false`,
    /// the channel will not be created and an error will be sent to the server.
    #[allow(unused_variables)]
    fn server_channel_handle_unknown(&self, channel: ChannelId, channel_type: &[u8]) -> bool {
        false
    }

    /// Called when the server opens a session channel.
    #[allow(unused_variables)]
    fn server_channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the server opens a direct tcp/ip channel.
    #[allow(unused_variables)]
    fn server_channel_open_direct_tcpip(
        self,
        channel: ChannelId,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the server opens an X11 channel.
    #[allow(unused_variables)]
    fn server_channel_open_x11(
        self,
        channel: ChannelId,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Data {
                data: CryptoVec::from_slice(data),
            })
            .unwrap_or(())
        }
        self.finished(session)
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn extended_data(
        self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExtendedData {
                ext,
                data: CryptoVec::from_slice(data),
            })
            .unwrap_or(())
        }
        self.finished(session)
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(
        self,
        channel: ChannelId,
        client_can_do: bool,
        session: Session,
    ) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::XonXoff { client_can_do })
                .unwrap_or(())
        }
        self.finished(session)
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(
        self,
        channel: ChannelId,
        exit_status: u32,
        session: Session,
    ) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExitStatus { exit_status })
                .unwrap_or(())
        }
        self.finished(session)
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(
        self,
        channel: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: &str,
        lang_tag: &str,
        session: Session,
    ) -> Self::FutureUnit {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message: error_message.to_string(),
                lang_tag: lang_tag.to_string(),
            })
            .unwrap_or(())
        }
        self.finished(session)
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(
        self,
        channel: ChannelId,
        mut new_size: u32,
        mut session: Session,
    ) -> Self::FutureUnit {
        if let Some(ref mut enc) = session.common.encrypted {
            new_size -= enc.flush_pending(channel) as u32;
        }
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::WindowAdjusted { new_size })
                .unwrap_or(())
        }
        self.finished(session)
    }

    /// Called when this client adjusts the network window. Return the
    /// next target window and maximum packet size.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, window: u32) -> u32 {
        window
    }
}
