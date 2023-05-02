#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(clippy::single_match, clippy::upper_case_acronyms)]
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
//! * [Writing SSH clients - the `russh::client` module](client)
//! * [Writing SSH servers - the `russh::server` module](server)
//!
//! # Important crate features
//!
//! * RSA key support is gated behind the `openssl` feature (disabled by default).
//! * Enabling that and disabling the `rs-crypto` feature (enabled by default) will leave you with a very basic, but pure-OpenSSL RSA+AES cipherset.
//!
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

use std::fmt::{Debug, Display, Formatter};

use parsing::ChannelOpenConfirmation;
pub use russh_cryptovec::CryptoVec;
use thiserror::Error;

mod auth;

/// Cipher names
pub mod cipher;
/// Key exchange algorithm names
pub mod kex;
/// MAC algorithm names
pub mod mac;

mod compression;
mod key;
mod msg;
mod negotiation;
mod ssh_read;
mod sshbuffer;

pub use negotiation::Preferred;

mod pty;

pub use pty::Pty;
pub use sshbuffer::SshId;

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

mod channels;
pub use channels::{Channel, ChannelMsg};

mod channel_stream;
pub use channel_stream::ChannelStream;

mod parsing;
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

    /// Server refused to open a channel.
    #[error("Failed to open channel ({0:?})")]
    ChannelOpenFailure(ChannelOpenFailure),

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
    #[cfg(feature = "flate2")]
    Compress(#[from] flate2::CompressError),

    #[error(transparent)]
    #[cfg(feature = "flate2")]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
pub(crate) struct ChannelParams {
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

impl ChannelParams {
    pub fn confirm(&mut self, c: &ChannelOpenConfirmation) {
        self.recipient_channel = c.sender_channel; // "sender" is the sender of the confirmation
        self.recipient_window_size = c.initial_window_size;
        self.recipient_maximum_packet_size = c.maximum_packet_size;
        self.confirmed = true;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod test_compress {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use log::debug;

    use super::server::{Server as _, Session};
    use super::*;
    use crate::server::Msg;

    #[cfg(feature = "rs-crypto")]
    fn geneate_keypair() -> russh_keys::key::KeyPair {
        russh_keys::key::KeyPair::generate_ed25519().unwrap()
    }

    #[cfg(all(feature = "openssl", not(feature = "rs-crypto")))]
    fn geneate_keypair() -> russh_keys::key::KeyPair {
        russh_keys::key::KeyPair::generate_rsa(2048, russh_keys::key::SignatureHash::SHA2_256)
            .unwrap()
    }

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = geneate_keypair();
        let mut config = server::Config::default();
        config.preferred = Preferred::COMPRESSED;
        config.connection_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(geneate_keypair());
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

        let config = client::Config {
            preferred: Preferred::COMPRESSED,
            ..Default::default()
        };
        let config = Arc::new(config);

        dbg!(&addr);
        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                Arc::new(client_key),
            )
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

    #[async_trait]
    impl server::Handler for Server {
        type Error = super::Error;

        async fn channel_open_session(
            self,
            channel: Channel<Msg>,
            session: Session,
        ) -> Result<(Self, bool, Session), Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            Ok((self, true, session))
        }
        async fn auth_publickey(
            self,
            _: &str,
            _: &russh_keys::key::PublicKey,
        ) -> Result<(Self, server::Auth), Self::Error> {
            debug!("auth_publickey");
            Ok((self, server::Auth::Accept))
        }
        async fn data(
            self,
            channel: ChannelId,
            data: &[u8],
            mut session: Session,
        ) -> Result<(Self, Session), Self::Error> {
            debug!("server data = {:?}", std::str::from_utf8(data));
            session.data(channel, CryptoVec::from_slice(data));
            Ok((self, session))
        }
    }

    struct Client {}

    #[async_trait]
    impl client::Handler for Client {
        type Error = super::Error;

        async fn check_server_key(
            self,
            _server_public_key: &russh_keys::key::PublicKey,
        ) -> Result<(Self, bool), Self::Error> {
            // println!("check_server_key: {:?}", server_public_key);
            Ok((self, true))
        }
    }
}

#[cfg(test)]
use futures::Future;

#[cfg(test)]
async fn test_session<RC, RS, CH, SH, F1, F2, CERR, SERR>(
    client_handler: CH,
    server_handler: SH,
    run_client: RC,
    run_server: RS,
) where
    RC: FnOnce(crate::client::Handle<CH>) -> F1 + Send + Sync + 'static,
    RS: FnOnce(crate::server::Handle) -> F2 + Send + Sync + 'static,
    F1: Future<Output = crate::client::Handle<CH>> + Send + Sync + 'static,
    F2: Future<Output = crate::server::Handle> + Send + Sync + 'static,
    CERR: std::fmt::Debug + Send,
    SERR: std::fmt::Debug + Send,
    CH: crate::client::Handler<Error = CERR> + Send + Sync + 'static,
    SH: crate::server::Handler<Error = SERR> + Send + Sync + 'static,
{
    use std::sync::Arc;


    use crate::*;

    #[cfg(feature = "rs-crypto")]
    fn generate_keypair() -> russh_keys::key::KeyPair {
        russh_keys::key::KeyPair::generate_ed25519().unwrap()
    }

    #[cfg(not(feature = "rs-crypto"))]
    fn generate_keypair() -> russh_keys::key::KeyPair {
        russh_keys::key::KeyPair::generate_rsa(2048, russh_keys::key::SignatureHash::SHA2_256)
            .unwrap()
    }

    let _ = env_logger::try_init();
    let client_key = generate_keypair();
    let mut config = server::Config::default();
    config.connection_timeout = None;
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config.keys.push(generate_keypair());
    let config = Arc::new(config);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    #[derive(Clone)]
    struct Server {}

    let server_join = tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();

        server::run_stream(config, socket, server_handler)
            .await
            .map_err(|_| ())
            .unwrap()
    });

    let client_join = tokio::spawn(async move {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect(config, addr, client_handler)
            .await
            .unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                Arc::new(client_key),
            )
            .await
            .unwrap();
        assert!(authenticated);
        session
    });

    let (server_session, client_session) = tokio::join!(server_join, client_join);
    let client_handle = tokio::spawn(run_client(client_session.unwrap()));
    let server_handle = tokio::spawn(run_server(server_session.unwrap().handle()));

    let (server_session, client_session) = tokio::join!(server_handle, client_handle);
    drop(client_session);
    drop(server_session);
}

#[cfg(test)]
mod test_channels {
    use async_trait::async_trait;
    use russh_cryptovec::CryptoVec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::server::Session;
    use crate::{client, server, test_session, Channel, ChannelId, ChannelMsg};

    #[tokio::test]
    async fn test_server_channels() {
        #[derive(Debug)]
        struct Client {}

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<(Self, bool), Self::Error> {
                Ok((self, true))
            }

            async fn data(
                self,
                channel: ChannelId,
                data: &[u8],
                mut session: client::Session,
            ) -> Result<(Self, client::Session), Self::Error> {
                assert_eq!(data, &b"hello world!"[..]);
                session.data(channel, CryptoVec::from_slice(&b"hey there!"[..]));
                Ok((self, session))
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<(Self, server::Auth), Self::Error> {
                Ok((self, server::Auth::Accept))
            }
            async fn auth_succeeded(
                mut self,
                session: Session,
            ) -> Result<(Self, Session), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok((self, session))
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                let mut ch = s.channel_open_session().await.unwrap();
                ch.data(&b"hello world!"[..]).await.unwrap();

                let msg = ch.wait().await.unwrap();
                if let ChannelMsg::Data { data } = msg {
                    assert_eq!(data.as_ref(), &b"hey there!"[..]);
                } else {
                    panic!("Unexpected message {:?}", msg);
                }
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_streams() {
        #[derive(Debug)]
        struct Client {}

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<(Self, bool), Self::Error> {
                Ok((self, true))
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<(Self, server::Auth), Self::Error> {
                Ok((self, server::Auth::Accept))
            }

            async fn channel_open_session(
                mut self,
                channel: Channel<server::Msg>,
                session: server::Session,
            ) -> Result<(Self, bool, Session), Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {:?}", a);
                    a.send(channel).unwrap();
                }
                Ok((self, true, session))
            }
        }

        let mut sh = ServerHandle { channel: None };
        let scw = sh.get_channel_waiter();

        test_session(
            Client {},
            sh,
            |client| async move {
                let ch = client.channel_open_session().await.unwrap();
                let mut stream = ch.into_stream();
                stream.write_all(&b"request"[..]).await.unwrap();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"response"[..]);

                stream.write_all(&b"reply"[..]).await.unwrap();

                client
            },
            |server| async move {
                let channel = scw.await.unwrap();
                let mut stream = channel.into_stream();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"request"[..]);

                stream.write_all(&b"response"[..]).await.unwrap();

                buf.clear();

                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"reply"[..]);

                server
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_objects() {
        #[derive(Debug)]
        struct Client {}

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<(Self, bool), Self::Error> {
                Ok((self, true))
            }
        }

        struct ServerHandle {}

        impl ServerHandle {}

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<(Self, server::Auth), Self::Error> {
                Ok((self, server::Auth::Accept))
            }

            async fn channel_open_session(
                self,
                mut channel: Channel<server::Msg>,
                session: Session,
            ) -> Result<(Self, bool, Session), Self::Error> {
                tokio::spawn(async move {
                    while let Some(msg) = channel.wait().await {
                        match msg {
                            ChannelMsg::Data { data } => {
                                channel.data(&data[..]).await.unwrap();
                                channel.close().await.unwrap();
                                break;
                            }
                            _ => {}
                        }
                    }
                });
                Ok((self, true, session))
            }
        }

        let sh = ServerHandle {};
        test_session(
            Client {},
            sh,
            |c| async move {
                let mut ch = c.channel_open_session().await.unwrap();
                ch.data(&b"hello world!"[..]).await.unwrap();

                let msg = ch.wait().await.unwrap();
                if let ChannelMsg::Data { data } = msg {
                    assert_eq!(data.as_ref(), &b"hey there!"[..]);
                } else {
                    panic!("Unexpected message {:?}", msg);
                }

                let msg = ch.wait().await.unwrap();
                let ChannelMsg::Close = msg else {
                    panic!("Unexpected message {:?}", msg);
                };

                ch.close().await.unwrap();
                c
            },
            |s| async move { s },
        )
        .await;
    }
}
