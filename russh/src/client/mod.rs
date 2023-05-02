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

//! # Implementing clients
//!
//! Maybe surprisingly, the data types used by Russh to implement
//! clients are relatively more complicated than for servers. This is
//! mostly related to the fact that clients are generally used both in
//! a synchronous way (in the case of SSH, we can think of sending a
//! shell command), and asynchronously (because the server may send
//! unsollicited messages), and hence need to handle multiple
//! interfaces.
//!
//! The [Session](client::Session) is passed to the [Handler](client::Handler)
//! when the client receives data.
//!
//! ```no_run
//! use async_trait::async_trait;
//! use std::sync::Arc;
//! use russh::*;
//! use russh::server::{Auth, Session};
//! use russh_keys::*;
//! use futures::Future;
//! use std::io::Read;
//!
//! struct Client {
//! }
//!
//! #[async_trait]
//! impl client::Handler for Client {
//!    type Error = anyhow::Error;
//!
//!    async fn check_server_key(self, server_public_key: &key::PublicKey) -> Result<(Self, bool), Self::Error> {
//!        println!("check_server_key: {:?}", server_public_key);
//!        Ok((self, true))
//!    }
//!
//!    async fn data(self, channel: ChannelId, data: &[u8], session: client::Session) -> Result<(Self, client::Session), Self::Error> {
//!        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
//!        Ok((self, session))
//!    }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!   let config = russh::client::Config::default();
//!   let config = Arc::new(config);
//!   let sh = Client{};
//!
//!   let key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
//!   let mut agent = russh_keys::agent::client::AgentClient::connect_env().await.unwrap();
//!   agent.add_identity(&key, &[]).await.unwrap();
//!   let mut session = russh::client::connect(config, ("127.0.0.1", 22), sh).await.unwrap();
//!   if session.authenticate_future(std::env::var("USER").unwrap_or("user".to_owned()), key.clone_public_key().unwrap(), agent).await.1.unwrap() {
//!     let mut channel = session.channel_open_session().await.unwrap();
//!     channel.data(&b"Hello, world!"[..]).await.unwrap();
//!     if let Some(msg) = channel.wait().await {
//!         println!("{:?}", msg)
//!     }
//!   }
//! }
//! ```
//!
//! [Session]: client::Session

use std::cell::RefCell;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::task::{Context, Poll};
use futures::Future;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Reader;
#[cfg(feature = "openssl")]
use russh_keys::key::SignatureHash;
use russh_keys::key::{self, parse_public_key, PublicKey};
use tokio;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::pin;
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};
use log::{debug, error, info, trace};

use crate::channels::{Channel, ChannelMsg};
use crate::cipher::{self, clear, CipherPair, OpeningKey};
use crate::key::PubKey;
use crate::session::{CommonSession, EncryptedState, Exchange, Kex, KexDhDone, KexInit, NewKeys};
use crate::ssh_read::SshRead;
use crate::sshbuffer::{SSHBuffer, SshId};
use crate::{auth, msg, negotiation, ChannelId, ChannelOpenFailure, Disconnect, Limits, Sig};

mod encrypted;
mod kex;
mod session;


/// Actual client session's state.
///
/// It is in charge of multiplexing and keeping track of various channels
/// that may get opened and closed during the lifetime of an SSH session and
/// allows sending messages to the server.
pub struct Session {
    common: CommonSession<Arc<Config>>,
    receiver: Receiver<Msg>,
    sender: UnboundedSender<Reply>,
    channels: HashMap<ChannelId, UnboundedSender<ChannelMsg>>,
    target_window_size: u32,
    pending_reads: Vec<CryptoVec>,
    pending_len: u32,
    inbound_channel_sender: Sender<Msg>,
    inbound_channel_receiver: Receiver<Msg>,
}

impl Drop for Session {
    fn drop(&mut self) {
        debug!("drop session")
    }
}


#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Reply {
    AuthSuccess,
    AuthFailure,
    ChannelOpenFailure,
    SignRequest {
        key: key::PublicKey,
        data: CryptoVec,
    },
    AuthInfoRequest {
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
}

#[derive(Debug)]
pub enum Msg {
    Authenticate {
        user: String,
        method: auth::Method,
    },
    AuthInfoResponse {
        responses: Vec<String>,
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
    ChannelOpenDirectStreamLocal {
        socket_path: String,
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
    Close {
        id: ChannelId,
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

#[derive(Debug)]
pub enum KeyboardInteractiveAuthResponse {
    Success,
    Failure,
    InfoRequest {
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
}


#[derive(Debug)]
pub struct Prompt {
    pub prompt: String,
    pub echo: bool,
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

    /// Perform no authentication. This is useful for testing, but should not be
    /// used in most other circumstances.
    pub async fn authenticate_none<U: Into<String>>(
        &mut self,
        user: U,
    ) -> Result<bool, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::None,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Perform password-based SSH authentication.
    pub async fn authenticate_password<U: Into<String>, P: Into<String>>(
        &mut self,
        user: U,
        password: P,
    ) -> Result<bool, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::Password {
                    password: password.into(),
                },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Initiate Keyboard-Interactive based SSH authentication.
    ///
    /// * `submethods` - Hnts to the server the preferred methods to be used for authentication
    pub async fn authenticate_keyboard_interactive_start<
        U: Into<String>,
        S: Into<Option<String>>,
    >(
        &mut self,
        user: U,
        submethods: S,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        self.sender
            .send(Msg::Authenticate {
                user: user.into(),
                method: auth::Method::KeyboardInteractive {
                    submethods: submethods.into().unwrap_or_else(|| "".to_owned()),
                },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_keyboard_interactive_reply().await
    }

    /// Respond to AuthInfoRequests from the server. A server can send any number of these Requests
    /// including empty requests. You may have to call this function multple times in order to 
    /// complete Keyboard-Interactive based SSH authentication.
    ///
    /// * `responses` - The responses to each prompt. The number of responses must match the number
    /// of prompts. If a prompt has an empty string, then the response should be an empty string.
    pub async fn authenticate_keyboard_interactive_respond(
        &mut self,
        responses: Vec<String>,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        self.sender
            .send(Msg::AuthInfoResponse { responses })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_keyboard_interactive_reply().await
    }

    async fn wait_recv_keyboard_interactive_reply(
        &mut self,
    ) -> Result<KeyboardInteractiveAuthResponse, crate::Error> {
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(KeyboardInteractiveAuthResponse::Success),
                Some(Reply::AuthFailure) => return Ok(KeyboardInteractiveAuthResponse::Failure),
                Some(Reply::AuthInfoRequest {
                    name,
                    instructions,
                    prompts,
                }) => {
                    return Ok(KeyboardInteractiveAuthResponse::InfoRequest {
                        name,
                        instructions,
                        prompts,
                    });
                },
                _ => {},
            }
        }
    }

    async fn wait_recv_reply(&mut self) -> Result<bool, crate::Error> {
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(true),
                Some(Reply::AuthFailure) => return Ok(false),
                None => return Ok(false),
                _ => {}
            }
        }
    }

    /// Perform public key-based SSH authentication.
    pub async fn authenticate_publickey<U: Into<String>>(
        &mut self,
        user: U,
        key: Arc<key::KeyPair>,
    ) -> Result<bool, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::PublicKey { key },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Authenticate using a custom method that implements the
    /// [`Signer`][auth::Signer] trait. Currently, this crate only provides an
    /// implementation for an [SSH
    /// agent][russh_keys::agent::client::AgentClient].
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

    /// Wait for confirmation that a channel is open
    async fn wait_channel_confirmation(
        &self,
        mut receiver: UnboundedReceiver<ChannelMsg>,
    ) -> Result<Channel<Msg>, crate::Error> {
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
                Some(ChannelMsg::OpenFailure(reason)) => {
                    return Err(crate::Error::ChannelOpenFailure(reason));
                }
                None => {
                    return Err(crate::Error::Disconnect);
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
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenSession { sender })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`. After writing a stream to a channel using
    /// [`.data()`][Channel::data], be sure to call [`.eof()`][Channel::eof] to
    /// indicate that no more data will be sent, or you may see hangs when
    /// writing large streams.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, crate::Error> {
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
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    pub async fn channel_open_direct_streamlocal<S: Into<String>>(
        &self,
        socket_path: S,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = unbounded_channel();
        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver).await
    }

    pub async fn tcpip_forward<A: Into<String>>(
        &mut self,
        address: A,
        port: u32,
    ) -> Result<bool, crate::Error> {
        self.sender
            .send(Msg::TcpIpForward {
                want_reply: true,
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        if port == 0 {
            self.wait_recv_reply().await?;
        }
        Ok(true)
    }

    pub async fn cancel_tcpip_forward<A: Into<String>>(
        &self,
        address: A,
        port: u32,
    ) -> Result<bool, crate::Error> {
        self.sender
            .send(Msg::CancelTcpIpForward {
                want_reply: true,
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        Ok(true)
    }

    /// Sends a disconnect message.
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description: description.into(),
                language_tag: language_tag.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        Ok(())
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

/// Connect to a server at the address specified, using the [`Handler`]
/// (implemented by you) and [`Config`] specified. Returns a future that
/// resolves to a [`Handle`]. This handle can then be used to create channels,
/// which in turn can be used to tunnel TCP connections, request a PTY, execute
/// commands, etc. The future will resolve to an error if the connection fails.
/// This function creates a connection to the `addr` specified using a
/// [`tokio::net::TcpStream`] and then calls [`connect_stream`] under the hood.
pub async fn connect<H: Handler + Send + 'static, A: ToSocketAddrs>(
    config: Arc<Config>,
    addrs: A,
    handler: H,
) -> Result<Handle<H>, H::Error> {
    let socket = TcpStream::connect(addrs)
        .await
        .map_err(crate::Error::from)?;
    connect_stream(config, socket, handler).await
}

/// Connect a stream to a server. This stream must implement
/// [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`], as well as [`Unpin`]
/// and [`Send`]. Typically, you may prefer to use [`connect`], which uses a
/// [`tokio::net::TcpStream`] and then calls this function under the hood.
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
    write_buffer.send_ssh_id(&config.as_ref().client_id);
    stream
        .write_all(&write_buffer.buffer)
        .await
        .map_err(crate::Error::from)?;

    // Reading SSH id and allocating a session if correct.
    let mut stream = SshRead::new(stream);
    let sshid = stream.read_ssh_id().await?;
    let (handle_sender, session_receiver) = channel(10);
    let (session_sender, handle_receiver) = unbounded_channel();
    if config.maximum_packet_size > 65535 {
        error!(
            "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
            config.maximum_packet_size
        );
    }
    let mut session = Session::new(
        config.window_size,
        CommonSession {
            write_buffer,
            kex: None,
            auth_user: String::new(),
            auth_attempts: 0,
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
        session_receiver,
        session_sender,
    );
    session.read_ssh_id(sshid)?;
    let (encrypted_signal, encrypted_recv) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(session.run(stream, handler, Some(encrypted_signal)));

    if encrypted_recv.await.is_err() {
        join.await.map_err(crate::Error::Join)??;
        return Err(H::Error::from(crate::Error::Disconnect));
    }

    Ok(Handle {
        sender: handle_sender,
        receiver: handle_receiver,
        join,
    })
}

async fn start_reading<R: AsyncRead + Unpin>(
    mut stream_read: R,
    mut buffer: SSHBuffer,
    mut cipher: Box<dyn OpeningKey + Send>,
) -> Result<(usize, R, SSHBuffer, Box<dyn OpeningKey + Send>), crate::Error> {
    buffer.buffer.clear();
    let n = cipher::read(&mut stream_read, &mut buffer, &mut *cipher).await?;
    Ok((n, stream_read, buffer, cipher))
}

impl Session {
    fn new(
        target_window_size: u32,
        common: CommonSession<Arc<Config>>,
        receiver: Receiver<Msg>,
        sender: UnboundedSender<Reply>,
    ) -> Self {
        let (inbound_channel_sender, inbound_channel_receiver) = channel(10);
        Self {
            common,
            receiver,
            sender,
            target_window_size,
            inbound_channel_sender,
            inbound_channel_receiver,
            channels: HashMap::new(),
            pending_reads: Vec::new(),
            pending_len: 0,
        }
    }

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
                        Some(msg) => self.handle_msg(msg)?,
                        None => {
                            self.common.disconnected = true;
                            break
                        }
                    };

                    // eagerly take all outgoing messages so writes are batched
                    while !self.is_rekeying() {
                        match self.receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
                msg = self.inbound_channel_receiver.recv(), if !self.is_rekeying() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => (),
                    }

                    // eagerly take all outgoing messages so writes are batched
                    while !self.is_rekeying() {
                        match self.inbound_channel_receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
            }
            self.flush()?;
            if !self.common.write_buffer.buffer.is_empty() {
                trace!(
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

    fn handle_msg(&mut self, msg: Msg) -> Result<(), crate::Error> {
        match msg {
            Msg::Authenticate { user, method } => {
                self.write_auth_request_if_needed(&user, method);
            }
            Msg::Signed { .. } => {}
            Msg::AuthInfoResponse { .. } => {}
            Msg::ChannelOpenSession { sender } => {
                let id = self.channel_open_session()?;
                self.channels.insert(id, sender);
            }
            Msg::ChannelOpenX11 {
                originator_address,
                originator_port,
                sender,
            } => {
                let id = self.channel_open_x11(&originator_address, originator_port)?;
                self.channels.insert(id, sender);
            }
            Msg::ChannelOpenDirectTcpIp {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                sender,
            } => {
                let id = self.channel_open_direct_tcpip(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, sender);
            }
            Msg::ChannelOpenDirectStreamLocal {
                socket_path,
                sender,
            } => {
                let id = self.channel_open_direct_streamlocal(
                    &socket_path,
                )?;
                self.channels.insert(id, sender);
            }
            Msg::TcpIpForward {
                want_reply,
                address,
                port,
            } => self.tcpip_forward(want_reply, &address, port),
            Msg::CancelTcpIpForward {
                want_reply,
                address,
                port,
            } => self.cancel_tcpip_forward(want_reply, &address, port),
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => self.disconnect(reason, &description, &language_tag),
            Msg::Channel(id, ChannelMsg::Data { data }) => self.data(id, data),
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id);
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { data, ext }) => {
                self.extended_data(id, ext, data);
            }
            Msg::Channel(
                id,
                ChannelMsg::RequestPty {
                    want_reply,
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes,
                },
            ) => self.request_pty(
                id,
                want_reply,
                &term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                &terminal_modes,
            ),
            Msg::Channel(
                id,
                ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                },
            ) => self.window_change(id, col_width, row_height, pix_width, pix_height),
            Msg::Channel(
                id,
                ChannelMsg::RequestX11 {
                    want_reply,
                    single_connection,
                    x11_authentication_protocol,
                    x11_authentication_cookie,
                    x11_screen_number,
                },
            ) => self.request_x11(
                id,
                want_reply,
                single_connection,
                &x11_authentication_protocol,
                &x11_authentication_cookie,
                x11_screen_number,
            ),
            Msg::Channel(
                id,
                ChannelMsg::SetEnv {
                    want_reply,
                    variable_name,
                    variable_value,
                },
            ) => self.set_env(id, want_reply, &variable_name, &variable_value),
            Msg::Channel(id, ChannelMsg::RequestShell { want_reply }) => {
                self.request_shell(want_reply, id)
            }
            Msg::Channel(
                id,
                ChannelMsg::Exec {
                    want_reply,
                    command,
                },
            ) => self.exec(id, want_reply, &command),
            Msg::Channel(id, ChannelMsg::Signal { signal }) => self.signal(id, signal),
            Msg::Channel(id, ChannelMsg::RequestSubsystem { want_reply, name }) => {
                self.request_subsystem(want_reply, id, &name)
            }
            Msg::Channel(id, ChannelMsg::AgentForward { want_reply }) => {
                self.agent_forward(id, want_reply)
            }
            Msg::Channel(id, ChannelMsg::Close) => {
                self.close(id)
            }
            msg => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (server-only?) message: {:?}", msg)
            }
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

    fn read_ssh_id(&mut self, sshid: &[u8]) -> Result<(), crate::Error> {
        // self.read_buffer.bytes += sshid.bytes_read + 2;
        let mut exchange = Exchange::new();
        exchange.server_id.extend(sshid);
        // Preparing the response
        exchange
            .client_id
            .extend(self.common.config.client_id.as_kex_hash_bytes());
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
    fn flush(&mut self) -> Result<(), crate::Error> {
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
    ) -> Result<(NewKeys, H), H::Error> {
        let mut reader = buf.reader(1);
        let pubkey = reader.read_string().map_err(crate::Error::from)?; // server public key.
        let pubkey = parse_public_key(
            pubkey,
            #[cfg(feature = "openssl")]
            SignatureHash::from_rsa_hostkey_algo(self.names.key.0.as_bytes()),
        )
        .map_err(crate::Error::from)?;
        debug!("server_public_Key: {:?}", pubkey);
        if !rekey {
            let ret = handler.check_server_key(&pubkey).await?;
            handler = ret.0;
            let check = ret.1;
            if !check {
                return Err(crate::Error::UnknownKey.into());
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
                    return Err(crate::Error::WrongServerSig.into());
                }
                hash
            };
            let mut newkeys = self.compute_keys(hash, false)?;
            newkeys.sent = true;
            Ok((newkeys, handler))
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
                || buf.first() == Some(&msg::KEXINIT)
                || session.common.encrypted.is_none()
            {
                let done = kexinit.client_parse(
                    session.common.config.as_ref(),
                    &mut *session.common.cipher.local_to_remote,
                    buf,
                    &mut session.common.write_buffer,
                )?;

                if done.kex.skip_exchange() {
                    session.common.encrypted(
                        initial_encrypted_state(&session),
                        done.compute_keys(CryptoVec::new(), false)?,
                    );

                    if let Some(sender) = sender.take() {
                        sender.send(()).unwrap_or(());
                    }
                } else {
                    session.common.kex = Some(Kex::DhDone(done));
                }
                session.flush()?;
            }
            Ok((handler, session))
        }
        Some(Kex::DhDone(mut kexdhdone)) => {
            if kexdhdone.names.ignore_guessed {
                kexdhdone.names.ignore_guessed = false;
                session.common.kex = Some(Kex::DhDone(kexdhdone));
                Ok((handler, session))
            } else if buf.first() == Some(&msg::KEX_ECDH_REPLY) {
                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                let (kex, h) = kexdhdone.server_key_check(false, handler, buf).await?;
                handler = h;
                session.common.kex = Some(Kex::Keys(kex));
                session
                    .common
                    .cipher
                    .local_to_remote
                    .write(&[msg::NEWKEYS], &mut session.common.write_buffer);
                session.flush()?;
                Ok((handler, session))
            } else {
                error!("Wrong packet received");
                Err(crate::Error::Inconsistent.into())
            }
        }
        Some(Kex::Keys(newkeys)) => {
            debug!("newkeys received");
            if buf.first() != Some(&msg::NEWKEYS) {
                return Err(crate::Error::Kex.into());
            }
            if let Some(sender) = sender.take() {
                sender.send(()).unwrap_or(());
            }
            session
                .common
                .encrypted(initial_encrypted_state(&session), newkeys);
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

fn initial_encrypted_state(session: &Session) -> EncryptedState {
    if session.common.config.anonymous {
        EncryptedState::Authenticated
    } else {
        EncryptedState::WaitingAuthServiceRequest {
            accepted: false,
            sent: false,
        }
    }
}

/// The configuration of clients.
#[derive(Debug)]
pub struct Config {
    /// The client ID string sent at the beginning of the protocol.
    pub client_id: SshId,
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
    /// Whether to expect and wait for an authentication call.
    pub anonymous: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            client_id: SshId::Standard(format!(
                "SSH-2.0-{}_{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )),
            limits: Limits::default(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            preferred: Default::default(),
            connection_timeout: None,
            anonymous: false,
        }
    }
}

/// A client handler. Note that messages can be received from the
/// server at any time during a session.
///
/// Note: this is an `async_trait`. Click `[source]` on the right to see actual async function definitions.

#[async_trait]
pub trait Handler: Sized + Send {
    type Error: From<crate::Error> + Send;

    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    ///
    /// The returned Boolean is ignored.
    #[allow(unused_variables)]
    async fn auth_banner(
        self,
        banner: &str,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    #[allow(unused_variables)]
    async fn check_server_key(
        self,
        server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, false))
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    async fn channel_open_confirmation(
        self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
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
        Ok((self, session))
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    async fn channel_success(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Success).unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the server signals failure.
    #[allow(unused_variables)]
    async fn channel_failure(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Failure).unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    async fn channel_close(
        self,
        channel: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.channels.remove(&channel);
        Ok((self, session))
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    async fn channel_eof(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Eof).unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    async fn channel_open_failure(
        self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(sender) = session.channels.remove(&channel) {
            let _ = sender.send(ChannelMsg::OpenFailure(reason));
        }
        session.sender.send(Reply::ChannelOpenFailure).unwrap_or(());
        Ok((self, session))
    }

    /// Called when the server opens a channel for a new remote port forwarding connection
    #[allow(unused_variables)]
    async fn server_channel_open_forwarded_tcpip(
        self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the server opens an agent forwarding channel
    #[allow(unused_variables)]
    async fn server_channel_open_agent_forward(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
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
    async fn server_channel_open_session(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the server opens a direct tcp/ip channel.
    #[allow(unused_variables)]
    async fn server_channel_open_direct_tcpip(
        self,
        channel: ChannelId,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the server opens an X11 channel.
    #[allow(unused_variables)]
    async fn server_channel_open_x11(
        self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Data {
                data: CryptoVec::from_slice(data),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    async fn extended_data(
        self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExtendedData {
                ext,
                data: CryptoVec::from_slice(data),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    async fn xon_xoff(
        self,
        channel: ChannelId,
        client_can_do: bool,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::XonXoff { client_can_do })
                .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    async fn exit_status(
        self,
        channel: ChannelId,
        exit_status: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExitStatus { exit_status })
                .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    async fn exit_signal(
        self,
        channel: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: &str,
        lang_tag: &str,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message: error_message.to_string(),
                lang_tag: lang_tag.to_string(),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    async fn window_adjusted(
        self,
        channel: ChannelId,
        mut new_size: u32,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(ref mut enc) = session.common.encrypted {
            new_size -= enc.flush_pending(channel) as u32;
        }
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::WindowAdjusted { new_size })
                .unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when this client adjusts the network window. Return the
    /// next target window and maximum packet size.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, window: u32) -> u32 {
        window
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    async fn openssh_ext_host_keys_announced(
        self,
        keys: Vec<PublicKey>,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        debug!("openssh_ext_hostkeys_announced: {:?}", keys);
        Ok((self, session))
    }
}
