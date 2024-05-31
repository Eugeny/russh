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

use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};

use log::debug;
use parsing::ChannelOpenConfirmation;
pub use russh_cryptovec::CryptoVec;
use thiserror::Error;

#[cfg(test)]
mod tests;

mod auth;

/// Cipher names
pub mod cipher;
/// Key exchange algorithm names
pub mod kex;
/// MAC algorithm names
pub mod mac;

mod cert;
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
pub use channels::{Channel, ChannelMsg, ChannelStream};

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

    /// Keepalive timeout.
    #[error("Keepalive timeout")]
    KeepaliveTimeout,

    /// Inactivity timeout.
    #[error("Inactivity timeout")]
    InactivityTimeout,

    /// Missing authentication method.
    #[error("No authentication method")]
    NoAuthMethod,

    #[error("Channel send error")]
    SendError,

    #[error("Pending buffer limit reached")]
    Pending,

    #[error("Failed to decrypt a packet")]
    DecryptionError,

    #[error("The request was rejected by the other party")]
    RequestDenied,

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

    #[error("Violation detected during strict key exchange, message {message_type} at seq no {sequence_number}")]
    StrictKeyExchangeViolation {
        message_type: u8,
        sequence_number: usize,
    },
}

pub(crate) fn strict_kex_violation(message_type: u8, sequence_number: usize) -> crate::Error {
    debug!(
        "strict kex violated at sequence no. {:?}, message type: {:?}",
        sequence_number, message_type
    );
    crate::Error::StrictKeyExchangeViolation {
        message_type,
        sequence_number,
    }
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
#[allow(clippy::manual_non_exhaustive)]
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

impl TryFrom<u32> for Disconnect {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MACError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            _ => return Err(crate::Error::Inconsistent),
        })
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
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
    pending_eof: bool,
    pending_close: bool,
}

impl ChannelParams {
    pub fn confirm(&mut self, c: &ChannelOpenConfirmation) {
        self.recipient_channel = c.sender_channel; // "sender" is the sender of the confirmation
        self.recipient_window_size = c.initial_window_size;
        self.recipient_maximum_packet_size = c.maximum_packet_size;
        self.confirmed = true;
    }
}

pub(crate) fn future_or_pending<F: futures::Future, T>(
    val: Option<T>,
    f: impl FnOnce(T) -> F,
) -> futures::future::Either<futures::future::Pending<<F as futures::Future>::Output>, F> {
    val.map_or(
        futures::future::Either::Left(futures::future::pending()),
        |x| futures::future::Either::Right(f(x)),
    )
}
