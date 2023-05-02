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

//! # Writing servers
//!
//! There are two ways of accepting connections:
//! * implement the [Server](server::Server) trait and let [run](server::run) handle everything
//! * accept connections yourself and pass them to [run_stream](server::run_stream)
//!
//! In both cases, you'll first need to implement the [Handler](server::Handler) trait -
//! this is where you'll handle various events.
//!
//! Here is an example server, which forwards input from each client
//! to all other clients:
//!
//! ```
//! use async_trait::async_trait;
//! use std::sync::{Mutex, Arc};
//! use russh::*;
//! use russh::server::{Auth, Session, Msg};
//! use russh_keys::*;
//! use std::collections::HashMap;
//! use futures::Future;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client_key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
//!     let client_pubkey = Arc::new(client_key.clone_public_key().unwrap());
//!     let mut config = russh::server::Config::default();
//!     config.connection_timeout = Some(std::time::Duration::from_secs(3));
//!     config.auth_rejection_time = std::time::Duration::from_secs(3);
//!     config.keys.push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
//!     let config = Arc::new(config);
//!     let sh = Server{
//!         client_pubkey,
//!         clients: Arc::new(Mutex::new(HashMap::new())),
//!         id: 0
//!     };
//!     tokio::time::timeout(
//!        std::time::Duration::from_secs(1),
//!        russh::server::run(config, ("0.0.0.0", 2222), sh)
//!     ).await.unwrap_or(Ok(()));
//! }
//!
//! #[derive(Clone)]
//! struct Server {
//!     client_pubkey: Arc<russh_keys::key::PublicKey>,
//!     clients: Arc<Mutex<HashMap<(usize, ChannelId), Channel<Msg>>>>,
//!     id: usize,
//! }
//!
//! impl server::Server for Server {
//!     type Handler = Self;
//!     fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
//!         let s = self.clone();
//!         self.id += 1;
//!         s
//!     }
//! }
//!
//! #[async_trait]
//! impl server::Handler for Server {
//!     type Error = anyhow::Error;
//!
//!     async fn channel_open_session(self, channel: Channel<Msg>, session: Session) -> Result<(Self, bool, Session), Self::Error> {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             clients.insert((self.id, channel.id()), channel);
//!         }
//!         Ok((self, true, session))
//!     }
//!     async fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Result<(Self, Auth), Self::Error> {
//!         Ok((self, server::Auth::Accept))
//!     }
//!     async fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Result<(Self, Session), Self::Error> {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             for ((id, _channel_id), ref mut channel) in clients.iter_mut() {
//!                 channel.data(data);
//!             }
//!         }
//!         Ok((self, session))
//!     }
//! }
//! ```
//!
//! Note the call to `session.handle()`, which allows to keep a handle
//! to a client outside the event loop. This feature is internally
//! implemented using `futures::sync::mpsc` channels.
//!
//! Note that this is just a toy server. In particular:
//!
//! - It doesn't handle errors when `s.data` returns an error, i.e. when the
//!   client has disappeared
//!
//! - Each new connection increments the `id` field. Even though we
//! would need a lot of connections per second for a very long time to
//! saturate it, there are probably better ways to handle this to
//! avoid collisions.

use std;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use log::{error, info};
use async_trait::async_trait;
use futures::future::Future;
use russh_keys::key;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::pin;
use tokio::task::JoinHandle;

use crate::cipher::{clear, CipherPair, OpeningKey};
use crate::session::*;
use crate::ssh_read::*;
use crate::sshbuffer::*;
use crate::*;

mod kex;
mod session;
pub use self::kex::*;
pub use self::session::*;
mod encrypted;

#[derive(Debug)]
/// Configuration of a server.
pub struct Config {
    /// The server ID string sent at the beginning of the protocol.
    pub server_id: SshId,
    /// Authentication methods proposed to the client.
    pub methods: auth::MethodSet,
    /// The authentication banner, usually a warning message shown to the client.
    pub auth_banner: Option<&'static str>,
    /// Authentication rejections must happen in constant time for
    /// security reasons. Russh does not handle this by default.
    pub auth_rejection_time: std::time::Duration,
    /// Authentication rejection time override for the initial "none" auth attempt.
    /// OpenSSH clients will send an initial "none" auth to probe for authentication methods.
    pub auth_rejection_time_initial: Option<std::time::Duration>,
    /// The server's keys. The first key pair in the client's preference order will be chosen.
    pub keys: Vec<key::KeyPair>,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Internal event buffer size
    pub event_buffer_size: usize,
    /// Lists of preferred algorithms.
    pub preferred: Preferred,
    /// Maximal number of allowed authentication attempts.
    pub max_auth_attempts: usize,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: SshId::Standard(format!(
                "SSH-2.0-{}_{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )),
            methods: auth::MethodSet::all(),
            auth_banner: None,
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: None,
            keys: Vec::new(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            event_buffer_size: 10,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10,
            connection_timeout: Some(std::time::Duration::from_secs(600)),
        }
    }
}

/// A client's response in a challenge-response authentication.
///
/// You should iterate it to get `&[u8]` response slices.
#[derive(Debug)]
pub struct Response<'a> {
    pos: russh_keys::encoding::Position<'a>,
    n: u32,
}

impl<'a> Iterator for Response<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            self.pos.read_string().ok()
        }
    }
}

use std::borrow::Cow;
/// An authentication result, in a challenge-response authentication.
#[derive(Debug, PartialEq, Eq)]
pub enum Auth {
    /// Reject the authentication request.
    Reject {
        proceed_with_methods: Option<MethodSet>,
    },
    /// Accept the authentication request.
    Accept,

    /// Method was not accepted, but no other check was performed.
    UnsupportedMethod,

    /// Partially accept the challenge-response authentication
    /// request, providing more instructions for the client to follow.
    Partial {
        /// Name of this challenge.
        name: Cow<'static, str>,
        /// Instructions for this challenge.
        instructions: Cow<'static, str>,
        /// A number of prompts to the user. Each prompt has a `bool`
        /// indicating whether the terminal must echo the characters
        /// typed by the user.
        prompts: Cow<'static, [(Cow<'static, str>, bool)]>,
    },
}

/// Server handler. Each client will have their own handler.
///
/// Note: this is an `async_trait`. Click `[source]` on the right to see actual async function definitions.
#[async_trait]
pub trait Handler: Sized {
    type Error: From<crate::Error> + Send;

    /// Check authentication using the "none" method. Russh makes
    /// sure rejection happens in time `config.auth_rejection_time`,
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    async fn auth_none(self, user: &str) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: None,
            },
        ))
    }

    /// Check authentication using the "password" method. Russh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: None,
            },
        ))
    }

    /// Check authentication using the "publickey" method. This method
    /// should just check whether the public key matches the
    /// authorized ones. Russh then checks the signature. If the key
    /// is unknown, or the signature is invalid, Russh guarantees
    /// that rejection happens in constant time
    /// `config.auth_rejection_time`, except if this method takes more
    /// time than that.
    #[allow(unused_variables)]
    async fn auth_publickey(
        self,
        user: &str,
        public_key: &key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: None,
            },
        ))
    }

    /// Check authentication using the "keyboard-interactive"
    /// method. Russh makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    async fn auth_keyboard_interactive(
        self,
        user: &str,
        submethods: &str,
        response: Option<Response<'async_trait>>,
    ) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: None,
            },
        ))
    }

    /// Called when authentication succeeds for a session.
    #[allow(unused_variables)]
    async fn auth_succeeded(self, session: Session) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    async fn channel_close(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        Ok((self, session))
    }

    /// Called when the client sends EOF to a channel.
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

    /// Called when a new session channel is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_session(
        self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }

    /// Called when a new X11 channel is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_x11(
        self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }

    /// Called when a new TCP/IP is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_direct_tcpip(
        self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }

    /// Called when a new forwarded connection comes in.
    /// <https://www.rfc-editor.org/rfc/rfc4254#section-7>
    #[allow(unused_variables)]
    async fn channel_open_forwarded_tcpip(
        self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }

    /// Called when the client confirmed our request to open a
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

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
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

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    async fn extended_data(
        self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::ExtendedData {
                ext: code,
                data: CryptoVec::from_slice(data),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes.
    #[allow(unused_variables)]
    async fn window_adjusted(
        self,
        channel: ChannelId,
        new_size: u32,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(ref mut enc) = session.common.encrypted {
            enc.flush_pending(channel);
        }
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::WindowAdjusted { new_size })
                .unwrap_or(())
        }
        Ok((self, session))
    }

    /// Called when this server adjusts the network window. Return the
    /// next target window.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, current: u32) -> u32 {
        current
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    #[allow(unused_variables, clippy::too_many_arguments)]
    async fn pty_request(
        self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::RequestPty {
                want_reply: true,
                term: term.into(),
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes: modes.into(),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client requests an X11 connection.
    #[allow(unused_variables)]
    async fn x11_request(
        self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::RequestX11 {
                want_reply: true,
                single_connection,
                x11_authentication_cookie: x11_auth_cookie.into(),
                x11_authentication_protocol: x11_auth_protocol.into(),
                x11_screen_number,
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    #[allow(unused_variables)]
    async fn env_request(
        self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::SetEnv {
                want_reply: true,
                variable_name: variable_name.into(),
                variable_value: variable_value.into(),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::RequestShell { want_reply: true })
                .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    async fn exec_request(
        self,
        channel: ChannelId,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Exec {
                want_reply: true,
                command: data.into(),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client asks to start the subsystem with the given name
    /// (such as sftp).
    #[allow(unused_variables)]
    async fn subsystem_request(
        self,
        channel: ChannelId,
        name: &str,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::RequestSubsystem {
                want_reply: true,
                name: name.into(),
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    async fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            })
            .unwrap_or(())
        }
        Ok((self, session))
    }

    /// The client requests OpenSSH agent forwarding
    #[allow(unused_variables)]
    async fn agent_request(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::AgentForward { want_reply: true })
                .unwrap_or(())
        }
        Ok((self, false, session))
    }

    /// The client is sending a signal (usually to pass to the
    /// currently running process).
    #[allow(unused_variables)]
    async fn signal(
        self,
        channel: ChannelId,
        signal: Sig,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(chan) = session.channels.get(&channel) {
            chan.send(ChannelMsg::Signal { signal }).unwrap_or(())
        }
        Ok((self, session))
    }

    /// Used for reverse-forwarding ports, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    /// If `port` is 0, you should set it to the allocated port number.
    #[allow(unused_variables)]
    async fn tcpip_forward(
        self,
        address: &str,
        port: &mut u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }
    /// Used to stop the reverse-forwarding of a port, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    async fn cancel_tcpip_forward(
        self,
        address: &str,
        port: u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, false, session))
    }
}

/// Trait used to create new handlers when clients connect.
pub trait Server {
    /// The type of handlers.
    type Handler: Handler + Send;
    /// Called when a new client connects.
    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler;
}

/// Run a server.
/// Create a new `Connection` from the server's configuration, a
/// stream and a [`Handler`](trait.Handler.html).
pub async fn run<H: Server + Send + 'static, A: ToSocketAddrs>(
    config: Arc<Config>,
    addrs: A,
    mut server: H,
) -> Result<(), std::io::Error> {
    let socket = TcpListener::bind(addrs).await?;
    if config.maximum_packet_size > 65535 {
        error!(
            "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
            config.maximum_packet_size
        );
    }
    while let Ok((socket, _)) = socket.accept().await {
        let config = config.clone();
        let server = server.new_client(socket.peer_addr().ok());
        tokio::spawn(run_stream(config, socket, server));
    }
    Ok(())
}

use std::cell::RefCell;
thread_local! {
    static B1: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static B2: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

pub(crate) async fn timeout(delay: Option<std::time::Duration>) {
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await
    } else {
        futures::future::pending().await
    };
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

/// An active server session returned by [run_stream].
///
/// Implements [Future] and needs to be awaited to allow the session to run.
pub struct RunningSession<H: Handler> {
    handle: Handle,
    join: JoinHandle<Result<(), H::Error>>,
}

impl<H: Handler> RunningSession<H> {
    /// Returns a new handle for the session.
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

impl<H: Handler> Future for RunningSession<H> {
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

/// Run a single connection to completion.
pub async fn run_stream<H, R>(
    config: Arc<Config>,
    mut stream: R,
    handler: H,
) -> Result<RunningSession<H>, H::Error>
where
    H: Handler + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Writing SSH id.
    let mut write_buffer = SSHBuffer::new();
    write_buffer.send_ssh_id(&config.as_ref().server_id);
    stream
        .write_all(&write_buffer.buffer[..])
        .await
        .map_err(crate::Error::from)?;
    info!("wrote id");
    // Reading SSH id and allocating a session.
    let mut stream = SshRead::new(stream);
    let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
    let common = read_ssh_id(config, &mut stream).await?;
    info!("read other id");
    let handle = server::session::Handle { sender };
    let session = Session {
        target_window_size: common.config.window_size,
        common,
        receiver,
        sender: handle.clone(),
        pending_reads: Vec::new(),
        pending_len: 0,
        channels: HashMap::new(),
    };

    let join = tokio::spawn(session.run(stream, handler));

    info!("session is running");
    Ok(RunningSession { handle, join })
}

async fn read_ssh_id<R: AsyncRead + Unpin>(
    config: Arc<Config>,
    read: &mut SshRead<R>,
) -> Result<CommonSession<Arc<Config>>, Error> {
    let sshid = if let Some(t) = config.connection_timeout {
        tokio::time::timeout(t, read.read_ssh_id()).await??
    } else {
        read.read_ssh_id().await?
    };
    let mut exchange = Exchange::new();
    exchange.client_id.extend(sshid);
    // Preparing the response
    exchange
        .server_id
        .extend(config.as_ref().server_id.as_kex_hash_bytes());
    let mut kexinit = KexInit {
        exchange,
        algo: None,
        sent: false,
        session_id: None,
    };
    let mut cipher = CipherPair {
        local_to_remote: Box::new(clear::Key),
        remote_to_local: Box::new(clear::Key),
    };
    let mut write_buffer = SSHBuffer::new();
    kexinit.server_write(
        config.as_ref(),
        &mut *cipher.local_to_remote,
        &mut write_buffer,
    )?;
    Ok(CommonSession {
        write_buffer,
        kex: Some(Kex::Init(kexinit)),
        auth_user: String::new(),
        auth_method: None, // Client only.
        auth_attempts: 0,
        cipher,
        encrypted: None,
        config,
        wants_reply: false,
        disconnected: false,
        buffer: CryptoVec::new(),
    })
}

async fn reply<H: Handler + Send>(
    mut session: Session,
    handler: H,
    buf: &[u8],
) -> Result<(H, Session), H::Error> {
    // Handle key exchange/re-exchange.
    if session.common.encrypted.is_none() {
        match session.common.kex.take() {
            Some(Kex::Init(kexinit)) => {
                if kexinit.algo.is_some() || buf.first() == Some(&msg::KEXINIT) {
                    session.common.kex = Some(kexinit.server_parse(
                        session.common.config.as_ref(),
                        &mut *session.common.cipher.local_to_remote,
                        buf,
                        &mut session.common.write_buffer,
                    )?);
                    return Ok((handler, session));
                } else {
                    // Else, i.e. if the other side has not started
                    // the key exchange, process its packets by simple
                    // not returning.
                    session.common.kex = Some(Kex::Init(kexinit))
                }
            }
            Some(Kex::Dh(kexdh)) => {
                session.common.kex = Some(kexdh.parse(
                    session.common.config.as_ref(),
                    &mut *session.common.cipher.local_to_remote,
                    buf,
                    &mut session.common.write_buffer,
                )?);
                return Ok((handler, session));
            }
            Some(Kex::Keys(newkeys)) => {
                if buf.first() != Some(&msg::NEWKEYS) {
                    return Err(Error::Kex.into());
                }
                // Ok, NEWKEYS received, now encrypted.
                session.common.encrypted(
                    EncryptedState::WaitingAuthServiceRequest {
                        sent: false,
                        accepted: false,
                    },
                    newkeys,
                );
                session.maybe_send_ext_info();
                return Ok((handler, session));
            }
            Some(kex) => {
                session.common.kex = Some(kex);
                return Ok((handler, session));
            }
            None => {}
        }
        Ok((handler, session))
    } else {
        Ok(session.server_read_encrypted(handler, buf).await?)
    }
}
