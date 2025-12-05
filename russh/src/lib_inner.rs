use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::future::{Future, Pending};

use futures::future::Either as EitherFuture;
use log::{debug, warn};
use parsing::ChannelOpenConfirmation;
pub use russh_cryptovec::CryptoVec;
use ssh_encoding::{Decode, Encode};
use thiserror::Error;

#[cfg(test)]
mod tests;

mod auth;

mod cert;
/// Cipher names
pub mod cipher;
/// Compression algorithm names
pub mod compression;
/// Key exchange algorithm names
pub mod kex;
/// MAC algorithm names
pub mod mac;

pub mod keys;

mod msg;
mod negotiation;
mod ssh_read;
mod sshbuffer;

pub use negotiation::{Names, Preferred};

mod pty;

pub use pty::Pty;
pub use sshbuffer::SshId;

mod helpers;

pub(crate) use helpers::map_err;

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
pub use channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelStream, ChannelWriteHalf};

mod parsing;
mod session;

/// Server side of this library.
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

/// Client side of this library.
pub mod client;

#[derive(Debug)]
pub enum AlgorithmKind {
    Kex,
    Key,
    Cipher,
    Compression,
    Mac,
}

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

    /// No common algorithm found during key exchange.
    #[error("No common {kind:?} algorithm - ours: {ours:?}, theirs: {theirs:?}")]
    NoCommonAlgo {
        kind: AlgorithmKind,
        ours: Vec<String>,
        theirs: Vec<String>,
    },

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

    /// The client has presented an unsupported authentication method.
    #[error("Unsupported authentication method")]
    UnsupportedAuthMethod,

    /// Index out of bounds.
    #[error("Index out of bounds")]
    IndexOutOfBounds,

    /// Unknown server key.
    #[error("Unknown server key")]
    UnknownKey,

    /// The server provided a wrong signature.
    #[error("Wrong server signature")]
    WrongServerSig,

    /// Excessive packet size.
    #[error("Bad packet size: {0}")]
    PacketSize(usize),

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
    Keys(#[from] crate::keys::Error),

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
    Join(#[from] russh_util::runtime::JoinError),

    #[error(transparent)]
    Elapsed(#[from] tokio::time::error::Elapsed),

    #[error("Violation detected during strict key exchange, message {message_type} at seq no {sequence_number}")]
    StrictKeyExchangeViolation {
        message_type: u8,
        sequence_number: usize,
    },

    #[error("Signature: {0}")]
    Signature(#[from] signature::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    /// This error occurs when the channel is closed and there are no remaining messages in the channel buffer.
    /// This is common in SSH-Agent, for example when the Agent client directly rejects an authorization request.
    #[error("Unable to receive more messages from the channel")]
    RecvError,
}

pub(crate) fn strict_kex_violation(message_type: u8, sequence_number: usize) -> crate::Error {
    warn!(
        "strict kex violated at sequence no. {sequence_number:?}, message type: {message_type:?}"
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

pub use auth::{AgentAuthError, MethodKind, MethodSet, Signer};

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
    fn from_name(name: &str) -> Sig {
        match name {
            "ABRT" => Sig::ABRT,
            "ALRM" => Sig::ALRM,
            "FPE" => Sig::FPE,
            "HUP" => Sig::HUP,
            "ILL" => Sig::ILL,
            "INT" => Sig::INT,
            "KILL" => Sig::KILL,
            "PIPE" => Sig::PIPE,
            "QUIT" => Sig::QUIT,
            "SEGV" => Sig::SEGV,
            "TERM" => Sig::TERM,
            "USR1" => Sig::USR1,
            x => Sig::Custom(x.to_string()),
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

impl Decode for ChannelId {
    type Error = ssh_encoding::Error;

    fn decode(reader: &mut impl ssh_encoding::Reader) -> Result<Self, Self::Error> {
        Ok(Self(u32::decode(reader)?))
    }
}

impl Encode for ChannelId {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.0.encoded_len()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.0.encode(writer)
    }
}

impl From<ChannelId> for u32 {
    fn from(c: ChannelId) -> u32 {
        c.0
    }
}

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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    wants_reply: bool,
    /// (buffer, extended stream #, data offset in buffer)
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

/// Returns `f(val)` if `val` it is [Some], or a forever pending [Future] if it is [None].
pub(crate) fn future_or_pending<R, F: Future<Output = R>, T>(
    val: Option<T>,
    f: impl FnOnce(T) -> F,
) -> EitherFuture<Pending<R>, F> {
    match val {
        None => EitherFuture::Left(core::future::pending()),
        Some(x) => EitherFuture::Right(f(x)),
    }
}
