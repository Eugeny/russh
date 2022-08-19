#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(clippy::single_match)]
// length checked
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

//! Server and client SSH asynchronous library, based on tokio/futures.
//!
//! The normal way to use this library, both for clients and for
//! servers, is by creating *handlers*, i.e. types that implement
//! `client::Handler` for clients and `server::Handler` for
//! servers.
//!
//! # Writing servers
//!
//! In the specific case of servers, a server must implement
//! `server::Server`, a trait for creating new `server::Handler`. The
//! main type to look at in the `server` module is `Session` (and
//! `Config`, of course).
//!
//! Here is an example server, which forwards input from each client
//! to all other clients:
//!
//! ```
//! extern crate russh;
//! extern crate russh_keys;
//! extern crate futures;
//! extern crate tokio;
//! use std::sync::{Mutex, Arc};
//! use std::str::FromStr;
//! use russh::*;
//! use russh::server::{Auth, Session};
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
//!        russh::server::run(config, &std::net::SocketAddr::from_str("0.0.0.0:2222").unwrap(), sh)
//!     ).await.unwrap_or(Ok(()));
//! }
//!
//! #[derive(Clone)]
//! struct Server {
//!     client_pubkey: Arc<russh_keys::key::PublicKey>,
//!     clients: Arc<Mutex<HashMap<(usize, ChannelId), russh::server::Handle>>>,
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
//! impl server::Handler for Server {
//!     type Error = anyhow::Error;
//!     type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), anyhow::Error>>;
//!     type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
//!     type FutureBool = futures::future::Ready<Result<(Self, Session, bool), anyhow::Error>>;
//!
//!     fn finished_auth(mut self, auth: Auth) -> Self::FutureAuth {
//!         futures::future::ready(Ok((self, auth)))
//!     }
//!     fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
//!         futures::future::ready(Ok((self, s, b)))
//!     }
//!     fn finished(self, s: Session) -> Self::FutureUnit {
//!         futures::future::ready(Ok((self, s)))
//!     }
//!     fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             clients.insert((self.id, channel), session.handle());
//!         }
//!         self.finished(session)
//!     }
//!     fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
//!         self.finished_auth(server::Auth::Accept)
//!     }
//!     fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             for ((id, channel), ref mut s) in clients.iter_mut() {
//!                 if *id != self.id {
//!                     s.data(*channel, CryptoVec::from_slice(data));
//!                 }
//!             }
//!         }
//!         session.data(channel, CryptoVec::from_slice(data));
//!         self.finished(session)
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
//!
//!
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
//! The important types in the `client` module are `Session` and
//! `Connection`. A `Connection` is typically used to send commands to
//! the server and wait for responses, and contains a `Session`. The
//! `Session` is passed to the `Handler` when the client receives
//! data.
//!
//! ```
//! extern crate russh;
//! extern crate russh_keys;
//! extern crate futures;
//! extern crate tokio;
//! extern crate env_logger;
//! use std::sync::Arc;
//! use russh::*;
//! use russh::server::{Auth, Session};
//! use russh_keys::*;
//! use futures::Future;
//! use std::io::Read;
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//!
//! struct Client {
//! }
//!
//! impl client::Handler for Client {
//!    type Error = anyhow::Error;
//!    type FutureUnit = futures::future::Ready<Result<(Self, client::Session), anyhow::Error>>;
//!    type FutureBool = futures::future::Ready<Result<(Self, bool), anyhow::Error>>;
//!
//!    fn finished_bool(self, b: bool) -> Self::FutureBool {
//!        futures::future::ready(Ok((self, b)))
//!    }
//!    fn finished(self, session: client::Session) -> Self::FutureUnit {
//!        futures::future::ready(Ok((self, session)))
//!    }
//!    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
//!        println!("check_server_key: {:?}", server_public_key);
//!        self.finished_bool(true)
//!    }
//!    fn channel_open_confirmation(self, channel: ChannelId, max_packet_size: u32, window_size: u32, session: client::Session) -> Self::FutureUnit {
//!        println!("channel_open_confirmation: {:?}", channel);
//!        self.finished(session)
//!    }
//!    fn data(self, channel: ChannelId, data: &[u8], session: client::Session) -> Self::FutureUnit {
//!        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
//!        self.finished(session)
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
//!   let mut session = russh::client::connect(config, SocketAddr::from_str("127.0.0.1:22").unwrap(), sh).await.unwrap();
//!   if session.authenticate_future(std::env::var("USER").unwrap(), key.clone_public_key().unwrap(), agent).await.1.unwrap() {
//!     let mut channel = session.channel_open_session().await.unwrap();
//!     channel.data(&b"Hello, world!"[..]).await.unwrap();
//!     if let Some(msg) = channel.wait().await {
//!         println!("{:?}", msg)
//!     }
//!   }
//! }
//! ```
//! # Using non-socket IO / writing tunnels
//!
//! The easy way to implement SSH tunnels, like `ProxyCommand` for
//! OpenSSH, is to use the `russh-config` crate, and use the
//! `Stream::tcp_connect` or `Stream::proxy_command` methods of that
//! crate. That crate is a very lightweight layer above Russh, only
//! implementing for external commands the traits used for sockets.
//!
//! # The SSH protocol
//!
//! If we exclude the key exchange and authentication phases, handled
//! by Russh behind the scenes, the rest of the SSH protocol is
//! relatively simple: clients and servers open *channels*, which are
//! just integers used to handle multiple requests in parallel in a
//! single connection. Once a client has obtained a `ChannelId` by
//! calling one the many `channel_open_…` methods of
//! `client::Connection`, the client may send exec requests and data
//! to the server.
//!
//! A simple client just asking the server to run one command will
//! usually start by calling
//! `client::Connection::channel_open_session`, then
//! `client::Connection::exec`, then possibly
//! `client::Connection::data` a number of times to send data to the
//! command's standard input, and finally `Connection::channel_eof`
//! and `Connection::channel_close`.
//!
//! # Design principles
//!
//! The main goal of this library is conciseness, and reduced size and
//! readability of the library's code. Moreover, this library is split
//! between Russh, which implements the main logic of SSH clients
//! and servers, and Russh-keys, which implements calls to
//! cryptographic primitives.
//!
//! One non-goal is to implement all possible cryptographic algorithms
//! published since the initial release of SSH. Technical debt is
//! easily acquired, and we would need a very strong reason to go
//! against this principle. If you are designing a system from
//! scratch, we urge you to consider recent cryptographic primitives
//! such as Ed25519 for public key cryptography, and Chacha20-Poly1305
//! for symmetric cryptography and MAC.
//!
//! # Internal details of the event loop
//!
//! It might seem a little odd that the read/write methods for server
//! or client sessions often return neither `Result` nor
//! `Future`. This is because the data sent to the remote side is
//! buffered, because it needs to be encrypted first, and encryption
//! works on buffers, and for many algorithms, not in place.
//!
//! Hence, the event loop keeps waiting for incoming packets, reacts
//! to them by calling the provided `Handler`, which fills some
//! buffers. If the buffers are non-empty, the event loop then sends
//! them to the socket, flushes the socket, empties the buffers and
//! starts again. In the special case of the server, unsollicited
//! messages sent through a `server::Handle` are processed when there
//! is no incoming packet to read.
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;
extern crate russh_libsodium as sodium;
#[macro_use]
extern crate thiserror;

use std::fmt::{Display, Formatter};

pub use russh_cryptovec::CryptoVec;

mod auth;
pub mod cipher;
mod compression;
pub mod kex;
mod key;
pub mod mac;
mod msg;
mod negotiation;
mod ssh_read;
mod sshbuffer;

pub use negotiation::{Named, Preferred};

mod pty;

pub use pty::Pty;

macro_rules! push_packet {
    ( $buffer:expr, $x:expr ) => {{
        use byteorder::{BigEndian, ByteOrder};
        let i0 = $buffer.len();
        $buffer.extend(b"\0\0\0\0");
        let x = $x;
        let i1 = $buffer.len();
        use std::ops::DerefMut;
        let buf = $buffer.deref_mut();
        #[allow(clippy::indexing_slicing)] // length checked
        BigEndian::write_u32(&mut buf[i0..], (i1 - i0 - 4) as u32);
        x
    }};
}

mod session;

/// Server side of this library.
pub mod server;

/// Client side of this library.
pub mod client;

#[derive(Debug, Error)]
pub enum Error {
    /// The key file could not be parsed.
    #[error("Could not read key")]
    CouldNotReadKey,

    /// Unspecified problem with the beginning of key exchange.
    #[error("Key exchange init failed")]
    KexInit,

    /// Unknown algorithm name.
    #[error("Unknown algorithm")]
    UnknownAlgo,

    /// No common key exchange algorithm.
    #[error("No common key exchange algorithm")]
    NoCommonKexAlgo,

    /// No common signature algorithm.
    #[error("No common key algorithm")]
    NoCommonKeyAlgo,

    /// No common cipher.
    #[error("No common key cipher")]
    NoCommonCipher,

    /// No common compression algorithm.
    #[error("No common compression algorithm")]
    NoCommonCompression,

    /// No common MAC algorithm.
    #[error("No common MAC algorithm")]
    NoCommonMac,

    /// Invalid SSH version string.
    #[error("invalid SSH version string")]
    Version,

    /// Error during key exchange.
    #[error("Key exchange failed")]
    Kex,

    /// Invalid packet authentication code.
    #[error("Wrong packet authentication code")]
    PacketAuth,

    /// The protocol is in an inconsistent state.
    #[error("Inconsistent state of the protocol")]
    Inconsistent,

    /// The client is not yet authenticated.
    #[error("Not yet authenticated")]
    NotAuthenticated,

    /// Index out of bounds.
    #[error("Index out of bounds")]
    IndexOutOfBounds,

    /// Unknown server key.
    #[error("Unknown server key")]
    UnknownKey,

    /// The server provided a wrong signature.
    #[error("Wrong server signature")]
    WrongServerSig,

    /// Message received/sent on unopened channel.
    #[error("Channel not open")]
    WrongChannel,

    /// Disconnected
    #[error("Disconnected")]
    Disconnect,

    /// No home directory found when trying to learn new host key.
    #[error("No home directory when saving host key")]
    NoHomeDir,

    /// Remote key changed, this could mean a man-in-the-middle attack
    /// is being performed on the connection.
    #[error("Key changed, line {}", line)]
    KeyChanged { line: usize },

    /// Connection closed by the remote side.
    #[error("Connection closed by the remote side")]
    HUP,

    /// Connection timeout.
    #[error("Connection timeout")]
    ConnectionTimeout,

    /// Missing authentication method.
    #[error("No authentication method")]
    NoAuthMethod,

    #[error("Channel send error")]
    SendError,

    #[error("Pending buffer limit reached")]
    Pending,

    #[error("Failed to decrypt a packet")]
    DecryptionError,

    #[error(transparent)]
    Keys(#[from] russh_keys::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Compress(#[from] flate2::CompressError),

    #[error(transparent)]
    Decompress(#[from] flate2::DecompressError),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    #[error(transparent)]
    #[cfg(feature = "openssl")]
    Openssl(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    Elapsed(#[from] tokio::time::error::Elapsed),
}

#[derive(Debug, Error)]
#[error("Could not reach the event loop")]
pub struct SendError {}

/// Since handlers are large, their associated future types must implement this
/// trait to provide reasonable default implementations (basically, rejecting
/// all requests).
pub trait FromFinished<T>: futures::Future<Output = Result<T, Error>> {
    /// Turns type `T` into `Self`, a future yielding `T`.
    fn finished(t: T) -> Self;
}

impl<T> FromFinished<T> for futures::future::Ready<Result<T, Error>> {
    fn finished(t: T) -> Self {
        futures::future::ready(Ok(t))
    }
}

impl<T: 'static> FromFinished<T> for Box<dyn futures::Future<Output = Result<T, Error>> + Unpin> {
    fn finished(t: T) -> Self {
        Box::new(futures::future::ready(Ok(t)))
    }
}

// mod mac;
// use mac::*;
// mod compression;

/// The number of bytes read/written, and the number of seconds before a key
/// re-exchange is requested.
#[derive(Debug, Clone)]
pub struct Limits {
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit: std::time::Duration,
}

impl Limits {
    /// Create a new `Limits`, checking that the given bounds cannot lead to
    /// nonce reuse.
    pub fn new(write_limit: usize, read_limit: usize, time_limit: std::time::Duration) -> Limits {
        assert!(write_limit <= 1 << 30 && read_limit <= 1 << 30);
        Limits {
            rekey_write_limit: write_limit,
            rekey_read_limit: read_limit,
            rekey_time_limit: time_limit,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        // Following the recommendations of
        // https://tools.ietf.org/html/rfc4253#section-9
        Limits {
            rekey_write_limit: 1 << 30, // 1 Gb
            rekey_read_limit: 1 << 30,  // 1 Gb
            rekey_time_limit: std::time::Duration::from_secs(3600),
        }
    }
}

pub use auth::{AgentAuthError, MethodSet, Signer};

/// A reason for disconnection.
#[allow(missing_docs)] // This should be relatively self-explanatory.
#[derive(Debug)]
pub enum Disconnect {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    #[doc(hidden)]
    Reserved = 4,
    MACError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

/// The type of signals that can be sent to a remote process. If you
/// plan to use custom signals, read [the
/// RFC](https://tools.ietf.org/html/rfc4254#section-6.10) to
/// understand the encoding.
#[allow(missing_docs)]
// This should be relatively self-explanatory.
#[derive(Debug, Clone)]
pub enum Sig {
    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    Custom(String),
}

impl Sig {
    fn name(&self) -> &str {
        match *self {
            Sig::ABRT => "ABRT",
            Sig::ALRM => "ALRM",
            Sig::FPE => "FPE",
            Sig::HUP => "HUP",
            Sig::ILL => "ILL",
            Sig::INT => "INT",
            Sig::KILL => "KILL",
            Sig::PIPE => "PIPE",
            Sig::QUIT => "QUIT",
            Sig::SEGV => "SEGV",
            Sig::TERM => "TERM",
            Sig::USR1 => "USR1",
            Sig::Custom(ref c) => c,
        }
    }
    fn from_name(name: &[u8]) -> Result<Sig, Error> {
        match name {
            b"ABRT" => Ok(Sig::ABRT),
            b"ALRM" => Ok(Sig::ALRM),
            b"FPE" => Ok(Sig::FPE),
            b"HUP" => Ok(Sig::HUP),
            b"ILL" => Ok(Sig::ILL),
            b"INT" => Ok(Sig::INT),
            b"KILL" => Ok(Sig::KILL),
            b"PIPE" => Ok(Sig::PIPE),
            b"QUIT" => Ok(Sig::QUIT),
            b"SEGV" => Ok(Sig::SEGV),
            b"TERM" => Ok(Sig::TERM),
            b"USR1" => Ok(Sig::USR1),
            x => Ok(Sig::Custom(std::str::from_utf8(x)?.to_string())),
        }
    }
}

/// Reason for not being able to open a channel.
#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum ChannelOpenFailure {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
    Unknown = 0,
}

impl ChannelOpenFailure {
    fn from_u32(x: u32) -> Option<ChannelOpenFailure> {
        match x {
            1 => Some(ChannelOpenFailure::AdministrativelyProhibited),
            2 => Some(ChannelOpenFailure::ConnectFailed),
            3 => Some(ChannelOpenFailure::UnknownChannelType),
            4 => Some(ChannelOpenFailure::ResourceShortage),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// The identifier of a channel.
pub struct ChannelId(u32);

impl Display for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The parameters of a channel.
#[derive(Debug)]
pub(crate) struct Channel {
    recipient_channel: u32,
    sender_channel: ChannelId,
    recipient_window_size: u32,
    sender_window_size: u32,
    recipient_maximum_packet_size: u32,
    sender_maximum_packet_size: u32,
    /// Has the other side confirmed the channel?
    pub confirmed: bool,
    wants_reply: bool,
    pending_data: std::collections::VecDeque<(CryptoVec, Option<u32>, usize)>,
}

#[derive(Debug)]
pub enum ChannelMsg {
    /// Contains data sent by the other side. This is the most common message
    /// type, and is the one returned when expecting data during
    /// [`Channel::wait`][client::Channel::wait] operations. The maximum amount
    /// of data allowed is determined by the maximum packet size for the
    /// channel, and the current window size, whichever is smaller. The
    /// window size is decremented by the amount of data sent. Both parties
    /// MAY ignore all extra data sent after the allowed window is empty.
    Data {
        data: CryptoVec,
    },
    /// Some channels can transfer several types of data. An example of this is
    /// `stderr` data from interactive sessions. Such data can be passed with
    /// [`ChannelMsg::ExtendedData`] messages, where a separate integer
    /// specifies the type of data (The `ext` field). The available types and
    /// their interpretation depend on the type of channel.
    ///
    /// Data sent with these messages consumes the same window as ordinary
    /// data.
    ///
    /// Currently, only the following type is defined by the IETF.
    /// ```text
    ///             Symbolic name                  data_type_code
    ///             -------------                  --------------
    ///           SSH_EXTENDED_DATA_STDERR               1
    /// ```
    /// Extended Channel Data Transfer `ext` (known as 'data_type_code' in [RFC
    /// 4254](https://www.rfc-editor.org/rfc/rfc4254))  values MUST be assigned sequentially. The IANA will not
    /// assign Extended Channel Data Transfer 'data_type_code' values in the
    /// range of 0xFE000000 to 0xFFFFFFFF. Extended Channel Data Transfer
    /// `ext` values in that range are left for private use.
    ExtendedData {
        data: CryptoVec,
        ext: u32,
    },
    /// When a party will no longer send more data to a channel, it should
    /// send [`ChannelMsg::Eof`].
    ///
    /// No explicit response is sent to this message. However, the
    /// application may send EOF to whatever is at the other end of the
    /// channel. Note that the channel remains open after this message, and
    /// more data may still be sent in the other direction. This message
    /// does not consume window space and can be sent even if no window space
    /// is available.
    Eof,
    /// When either party wishes to terminate the channel, it sends
    /// [`ChannelMsg::Close`]. Upon receiving this message, a party MUST
    /// send back a [`ChannelMsg::Close`] unless it has already sent this
    /// message for the channel. Generally when using this library, this should
    /// only be implemented for servers, as the [`client::Handler`] handles
    /// close messages internally. The channel is considered closed for a
    /// party when it has both sent and received [`ChannelMsg::Close`], and
    /// the party may then reuse the channel number. A party may send
    /// [`ChannelMsg::Close`] without having sent or received
    /// [`ChannelMsg::Eof`].
    Close,
    /// On many systems, it is possible to determine if a pseudo-terminal is
    /// using control-S/control-Q flow control. When flow control is
    /// allowed, it is often desirable to do the flow control at the client
    /// end to speed up responses to user requests. This is facilitated by
    /// the following notification. Initially, the server is responsible for
    /// flow control. (Here, again, client means the side originating the
    /// session, and server means the other side.)
    ///
    /// The message below is used by the server to inform the client when it
    /// can or cannot perform flow control (control-S/control-Q processing).
    /// If `client_can_do` is true, the client is allowed to do flow control
    /// using control-S and control-Q. The client may ignore this message.
    XonXoff {
        client_can_do: bool,
    },
    /// When the command running at the other end terminates, the following
    /// message can be sent to return the exit status of the command.
    /// Returning the status is RECOMMENDED. No acknowledgement is sent for
    /// this message. The channel needs to be closed with
    /// [`ChannelMsg::Close`] after this message.
    ///
    /// The client may choose to ignore these messages.
    ExitStatus {
        exit_status: u32,
    },
    /// The remote command may also terminate violently due to a signal.
    /// Such a condition can be indicated by the following message.  A zero
    /// [`ChannelMsg::ExitSignal`] usually means that the command terminated
    /// successfully.
    ExitSignal {
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    /// The window size specifies how many bytes the other party can send
    /// before it must wait for the window to be adjusted.  Both parties use
    /// the following message to adjust the window.
    ///
    /// After receiving this message, the recipient may send the given number
    /// of bytes more than it was previously allowed to send; the window size
    /// is incremented. The window MUST NOT be increased above
    /// 2^32 - 1 bytes (hence the [u32][std::u32] type).
    WindowAdjusted {
        new_size: u32,
    },
    Success,
}

#[cfg(test)]
mod test_compress {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::server::{Auth, Server as _, Session};
    use super::*;

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
        let mut config = server::Config::default();
        config.preferred = Preferred::COMPRESSED;
        config.connection_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
        let config = Arc::new(config);
        let mut sh = Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let server = sh.new_client(socket.peer_addr().ok());
            server::run_stream(config, socket, server).await.unwrap();
        });

        let mut config = client::Config::default();
        config.preferred = Preferred::COMPRESSED;
        let config = Arc::new(config);

        dbg!(&addr);
        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(std::env::var("USER").unwrap(), Arc::new(client_key))
            .await
            .unwrap();
        assert!(authenticated);
        let mut channel = session.channel_open_session().await.unwrap();

        let data = &b"Hello, world!"[..];
        channel.data(data).await.unwrap();
        let msg = channel.wait().await.unwrap();
        match msg {
            ChannelMsg::Data { data: msg_data } => {
                assert_eq!(*data, *msg_data)
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    }

    #[derive(Clone)]
    struct Server {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), super::server::Handle>>>,
        id: usize,
    }

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;
        type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), Self::Error>>;
        type FutureUnit = futures::future::Ready<Result<(Self, Session), Self::Error>>;
        type FutureBool = futures::future::Ready<Result<(Self, Session, bool), Self::Error>>;

        fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
            futures::future::ready(Ok((self, auth)))
        }
        fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
            futures::future::ready(Ok((self, s, b)))
        }
        fn finished(self, s: Session) -> Self::FutureUnit {
            futures::future::ready(Ok((self, s)))
        }
        fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel), session.handle());
            }
            self.finished(session)
        }
        fn auth_publickey(self, _: &str, _: &russh_keys::key::PublicKey) -> Self::FutureAuth {
            debug!("auth_publickey");
            self.finished_auth(server::Auth::Accept)
        }
        fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
            debug!("server data = {:?}", std::str::from_utf8(data));
            session.data(channel, CryptoVec::from_slice(data));
            self.finished(session)
        }
    }

    struct Client {}

    impl client::Handler for Client {
        type Error = super::Error;
        type FutureUnit = futures::future::Ready<Result<(Self, client::Session), Self::Error>>;
        type FutureBool = futures::future::Ready<Result<(Self, bool), Self::Error>>;

        fn finished_bool(self, b: bool) -> Self::FutureBool {
            futures::future::ready(Ok((self, b)))
        }
        fn finished(self, session: client::Session) -> Self::FutureUnit {
            futures::future::ready(Ok((self, session)))
        }
        fn check_server_key(
            self,
            _server_public_key: &russh_keys::key::PublicKey,
        ) -> Self::FutureBool {
            // println!("check_server_key: {:?}", server_public_key);
            self.finished_bool(true)
        }
    }
}
