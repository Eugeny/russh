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
//! Check out the following examples:
//!
//! * [Client that connects to a server, runs a command and prints its output](https://github.com/warp-tech/russh/blob/main/russh/examples/client_exec_simple.rs)
//! * [Client that connects to a server, runs a command in a PTY and provides interactive input/output](https://github.com/warp-tech/russh/blob/main/russh/examples/client_exec_interactive.rs)
//! * [SFTP client (with `russh-sftp`)](https://github.com/warp-tech/russh/blob/main/russh/examples/sftp_client.rs)
//!
//! [Session]: client::Session

use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::num::Wrapping;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use futures::Future;
use futures::task::{Context, Poll};
use kex::ClientKex;
use log::{debug, error, trace, warn};
use russh_util::time::Instant;
use ssh_encoding::Decode;
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::pin;
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tokio::sync::oneshot;

pub use crate::auth::AuthResult;
use crate::channels::{
    Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf, WindowSizeRef,
};
use crate::cipher::{self, OpeningKey, clear};
use crate::kex::{KexAlgorithmImplementor, KexCause, KexProgress, SessionKexState};
use crate::keys::PrivateKeyWithHashAlg;
use crate::msg::{is_kex_msg, validate_server_msg_strict_kex};
use crate::session::{CommonSession, EncryptedState, GlobalRequestResponse, NewKeys};
use crate::ssh_read::SshRead;
use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer, SshId};
use crate::{
    ChannelId, ChannelOpenFailure, CryptoVec, Disconnect, Error, Limits, MethodSet, Sig, auth,
    map_err, msg, negotiation,
};

mod encrypted;
mod kex;
mod session;

#[cfg(test)]
mod test;

/// Actual client session's state.
///
/// It is in charge of multiplexing and keeping track of various channels
/// that may get opened and closed during the lifetime of an SSH session and
/// allows sending messages to the server.
#[derive(Debug)]
pub struct Session {
    kex: SessionKexState<ClientKex>,
    common: CommonSession<Arc<Config>>,
    receiver: Receiver<Msg>,
    sender: UnboundedSender<Reply>,
    channels: HashMap<ChannelId, ChannelRef>,
    target_window_size: u32,
    pending_reads: Vec<CryptoVec>,
    pending_len: u32,
    inbound_channel_sender: Sender<Msg>,
    inbound_channel_receiver: Receiver<Msg>,
    open_global_requests: VecDeque<GlobalRequestResponse>,
    server_sig_algs: Option<Vec<Algorithm>>,
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
    AuthFailure {
        proceed_with_methods: MethodSet,
        partial_success: bool,
    },
    ChannelOpenFailure,
    SignRequest {
        key: ssh_key::PublicKey,
        data: CryptoVec,
    },
    AuthInfoRequest {
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
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
        channel_ref: ChannelRef,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectTcpIp {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectStreamLocal {
        socket_path: String,
        channel_ref: ChannelRef,
    },
    TcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        address: String,
        port: u32,
    },
    CancelTcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        address: String,
        port: u32,
    },
    StreamLocalForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: String,
    },
    CancelStreamLocalForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: String,
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
    Rekey,
    AwaitExtensionInfo {
        extension_name: String,
        reply_channel: oneshot::Sender<()>,
    },
    GetServerSigAlgs {
        reply_channel: oneshot::Sender<Option<Vec<Algorithm>>>,
    },
    /// Send a keepalive packet to the remote
    Keepalive {
        want_reply: bool,
    },
    Ping {
        reply_channel: oneshot::Sender<()>,
    },
    NoMoreSessions {
        want_reply: bool,
    },
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

#[derive(Debug)]
pub enum KeyboardInteractiveAuthResponse {
    Success,
    Failure {
        /// The server suggests to proceed with these auth methods
        remaining_methods: MethodSet,
        /// The server says that though auth method has been accepted,
        /// further authentication is required
        partial_success: bool,
    },
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

#[derive(Debug)]
pub struct RemoteDisconnectInfo {
    pub reason_code: crate::Disconnect,
    pub message: String,
    pub lang_tag: String,
}

#[derive(Debug)]
pub enum DisconnectReason<E: From<crate::Error> + Send> {
    ReceivedDisconnect(RemoteDisconnectInfo),
    Error(E),
}

/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle<H: Handler> {
    sender: Sender<Msg>,
    receiver: UnboundedReceiver<Reply>,
    join: russh_util::runtime::JoinHandle<Result<(), H::Error>>,
    channel_buffer_size: usize,
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
    ) -> Result<AuthResult, crate::Error> {
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
    ) -> Result<AuthResult, crate::Error> {
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
    /// * `submethods` - Hints to the server the preferred methods to be used for authentication
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
    ///   of prompts. If a prompt has an empty string, then the response should be an empty string.
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
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(KeyboardInteractiveAuthResponse::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
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
                }
                None => return Err(crate::Error::RecvError),
                _ => {}
            }
        }
    }

    async fn wait_recv_reply(&mut self) -> Result<AuthResult, crate::Error> {
        loop {
            match self.receiver.recv().await {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    /// Perform public key-based SSH authentication.
    ///
    /// For RSA keys, you'll need to decide on which hash algorithm to use.
    /// This is the difference between what is also known as
    /// `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512` "keys" in OpenSSH.
    /// You can use [Handle::best_supported_rsa_hash] to automatically
    /// figure out the best hash algorithm for RSA keys.
    pub async fn authenticate_publickey<U: Into<String>>(
        &mut self,
        user: U,
        key: PrivateKeyWithHashAlg,
    ) -> Result<AuthResult, crate::Error> {
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

    /// Perform public OpenSSH Certificate-based SSH authentication
    pub async fn authenticate_openssh_cert<U: Into<String>>(
        &mut self,
        user: U,
        key: Arc<PrivateKey>,
        cert: Certificate,
    ) -> Result<AuthResult, crate::Error> {
        let user = user.into();
        self.sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::OpenSshCertificate { key, cert },
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_recv_reply().await
    }

    /// Authenticate using a custom method that implements the
    /// [`Signer`][auth::Signer] trait. Currently, this crate only provides an
    /// implementation for an [SSH agent][crate::keys::agent::client::AgentClient].
    pub async fn authenticate_publickey_with<U: Into<String>, S: auth::Signer>(
        &mut self,
        user: U,
        key: ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        signer: &mut S,
    ) -> Result<AuthResult, S::Error> {
        let user = user.into();
        if self
            .sender
            .send(Msg::Authenticate {
                user,
                method: auth::Method::FuturePublicKey { key, hash_alg },
            })
            .await
            .is_err()
        {
            return Err((crate::SendError {}).into());
        }
        loop {
            let reply = self.receiver.recv().await;
            match reply {
                Some(Reply::AuthSuccess) => return Ok(AuthResult::Success),
                Some(Reply::AuthFailure {
                    proceed_with_methods: remaining_methods,
                    partial_success,
                }) => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                Some(Reply::SignRequest { key, data }) => {
                    let data = signer.auth_publickey_sign(&key, hash_alg, data).await;
                    let data = match data {
                        Ok(data) => data,
                        Err(e) => return Err(e),
                    };
                    if self.sender.send(Msg::Signed { data }).await.is_err() {
                        return Err((crate::SendError {}).into());
                    }
                }
                None => {
                    return Ok(AuthResult::Failure {
                        remaining_methods: MethodSet::empty(),
                        partial_success: false,
                    });
                }
                _ => {}
            }
        }
    }

    /// Wait for confirmation that a channel is open
    async fn wait_channel_confirmation(
        &self,
        mut receiver: Receiver<ChannelMsg>,
        window_size_ref: WindowSizeRef,
    ) -> Result<Channel<Msg>, crate::Error> {
        loop {
            match receiver.recv().await {
                Some(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                }) => {
                    window_size_ref.update(window_size).await;

                    return Ok(Channel {
                        write_half: ChannelWriteHalf {
                            id,
                            sender: self.sender.clone(),
                            max_packet_size,
                            window_size: window_size_ref,
                        },
                        read_half: ChannelReadHalf { receiver },
                    });
                }
                Some(ChannelMsg::OpenFailure(reason)) => {
                    return Err(crate::Error::ChannelOpenFailure(reason));
                }
                None => {
                    debug!("channel confirmation sender was dropped");
                    return Err(crate::Error::Disconnect);
                }
                msg => {
                    debug!("msg = {msg:?}");
                }
            }
        }
    }

    /// See [`Handle::best_supported_rsa_hash`].
    #[cfg(not(target_arch = "wasm32"))]
    async fn await_extension_info(&self, extension_name: String) -> Result<(), crate::Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Msg::AwaitExtensionInfo {
                extension_name,
                reply_channel: sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        let _ = tokio::time::timeout(Duration::from_secs(1), receiver).await;
        Ok(())
    }

    /// Returns the best RSA hash algorithm supported by the server,
    /// as indicated by the `server-sig-algs` extension.
    /// If the server does not support the extension,
    /// `None` is returned. In this case you may still attempt an authentication
    /// with `rsa-sha2-256` or `rsa-sha2-512` and hope for the best.
    /// If the server supports the extension, but does not support `rsa-sha2-*`,
    /// `Some(None)` is returned.
    ///
    /// Note that this method will wait for up to 1 second for the server to
    /// send the extension info if it hasn't done so yet (except when running under
    /// WebAssembly). Unfortunately the timing of the EXT_INFO message cannot be known
    /// in advance (RFC 8308).
    ///
    /// If this method returns `None` once, then for most SSH servers
    /// you can assume that it will return `None` every time.
    pub async fn best_supported_rsa_hash(&self) -> Result<Option<Option<HashAlg>>, Error> {
        // Wait for the extension info from the server
        #[cfg(not(target_arch = "wasm32"))]
        self.await_extension_info("server-sig-algs".into()).await?;

        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(Msg::GetServerSigAlgs {
                reply_channel: sender,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        if let Some(ssa) = receiver.await.map_err(|_| Error::Inconsistent)? {
            let possible_algs = [
                Some(ssh_key::HashAlg::Sha512),
                Some(ssh_key::HashAlg::Sha256),
                None,
            ];
            for alg in possible_algs.into_iter() {
                if ssa.contains(&Algorithm::Rsa { hash: alg }) {
                    return Ok(Some(alg));
                }
            }
        }

        Ok(None)
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Some(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
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
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectTcpIp {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_direct_streamlocal<S: Into<String>>(
        &self,
        socket_path: S,
    ) -> Result<Channel<Msg>, crate::Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Requests the server to open a TCP/IP forward channel
    ///
    /// If port == 0 the server will choose a port that will be returned, returns 0 otherwise
    pub async fn tcpip_forward<A: Into<String>>(
        &mut self,
        address: A,
        port: u32,
    ) -> Result<u32, crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::TcpIpForward {
                reply_channel: Some(reply_send),
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(Some(port)) => Ok(port),
            Ok(None) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive TcpIpForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to close a TCP/IP forward channel
    pub async fn cancel_tcpip_forward<A: Into<String>>(
        &self,
        address: A,
        port: u32,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelTcpIpForward {
                reply_channel: Some(reply_send),
                address: address.into(),
                port,
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive CancelTcpIpForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to open a UDS forward channel
    pub async fn streamlocal_forward<A: Into<String>>(
        &mut self,
        socket_path: A,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::StreamLocalForward {
                reply_channel: Some(reply_send),
                socket_path: socket_path.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive StreamLocalForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
    }

    // Requests the server to close a UDS forward channel
    pub async fn cancel_streamlocal_forward<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<(), crate::Error> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelStreamLocalForward {
                reply_channel: Some(reply_send),
                socket_path: socket_path.into(),
            })
            .await
            .map_err(|_| crate::Error::SendError)?;

        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::RequestDenied),
            Err(e) => {
                error!("Unable to receive CancelStreamLocalForward result: {e:?}");
                Err(crate::Error::Disconnect)
            }
        }
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

    /// Asynchronously perform a session re-key at the next opportunity
    pub async fn rekey_soon(&self) -> Result<(), Error> {
        self.sender
            .send(Msg::Rekey)
            .await
            .map_err(|_| Error::SendError)?;

        Ok(())
    }

    /// Send a keepalive package to the remote peer.
    pub async fn send_keepalive(&self, want_reply: bool) -> Result<(), Error> {
        self.sender
            .send(Msg::Keepalive { want_reply })
            .await
            .map_err(|_| Error::SendError)
    }

    /// Send a keepalive/ping package to the remote peer, and wait for the reply/pong.
    pub async fn send_ping(&self) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Msg::Ping {
                reply_channel: sender,
            })
            .await
            .map_err(|_| Error::SendError)?;
        let _ = receiver.await;
        Ok(())
    }

    /// Send a no-more-sessions request to the remote peer.
    pub async fn no_more_sessions(&self, want_reply: bool) -> Result<(), Error> {
        self.sender
            .send(Msg::NoMoreSessions { want_reply })
            .await
            .map_err(|_| Error::SendError)
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
#[cfg(not(target_arch = "wasm32"))]
pub async fn connect<H: Handler + Send + 'static, A: tokio::net::ToSocketAddrs>(
    config: Arc<Config>,
    addrs: A,
    handler: H,
) -> Result<Handle<H>, H::Error> {
    let socket = map_err!(tokio::net::TcpStream::connect(addrs).await)?;
    if config.as_ref().nodelay {
        if let Err(e) = socket.set_nodelay(true) {
            warn!("set_nodelay() failed: {e:?}");
        }
    }

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

    debug!("ssh id = {:?}", config.as_ref().client_id);

    write_buffer.send_ssh_id(&config.as_ref().client_id);
    map_err!(stream.write_all(&write_buffer.buffer).await)?;

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
    let channel_buffer_size = config.channel_buffer_size;
    let mut session = Session::new(
        config.window_size,
        CommonSession {
            packet_writer: PacketWriter::clear(),
            auth_user: String::new(),
            auth_attempts: 0,
            auth_method: None, // Client only.
            remote_to_local: Box::new(clear::Key),
            encrypted: None,
            config,
            wants_reply: false,
            disconnected: false,
            buffer: CryptoVec::new(),
            strict_kex: false,
            alive_timeouts: 0,
            received_data: false,
            remote_sshid: sshid.into(),
        },
        session_receiver,
        session_sender,
    );
    session.begin_rekey()?;
    let (kex_done_signal, kex_done_signal_rx) = oneshot::channel();
    let join = russh_util::runtime::spawn(session.run(stream, handler, Some(kex_done_signal)));

    if let Err(err) = kex_done_signal_rx.await {
        // kex_done_signal Sender is dropped when the session
        // fails before a succesful key exchange
        debug!("kex_done_signal sender was dropped {err:?}");
        join.await.map_err(crate::Error::Join)??;
        return Err(H::Error::from(crate::Error::Disconnect));
    }

    Ok(Handle {
        sender: handle_sender,
        receiver: handle_receiver,
        join,
        channel_buffer_size,
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
    fn maybe_decompress(&mut self, buffer: &SSHBuffer) -> Result<IncomingSshPacket, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let mut decomp = CryptoVec::new();
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: enc.decompress.decompress(
                    &buffer.buffer[5..],
                    &mut decomp,
                )?.into(),
                seqn: buffer.seqn,
            })
        } else {
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: buffer.buffer[5..].into(),
                seqn: buffer.seqn,
            })
        }
    }

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
            kex: SessionKexState::Idle,
            target_window_size,
            inbound_channel_sender,
            inbound_channel_receiver,
            channels: HashMap::new(),
            pending_reads: Vec::new(),
            pending_len: 0,
            open_global_requests: VecDeque::new(),
            server_sig_algs: None,
        }
    }

    async fn run<H: Handler + Send, R: AsyncRead + AsyncWrite + Unpin + Send>(
        mut self,
        stream: SshRead<R>,
        mut handler: H,
        mut kex_done_signal: Option<oneshot::Sender<()>>,
    ) -> Result<(), H::Error> {
        let (stream_read, mut stream_write) = stream.split();
        let result = self
            .run_inner(
                stream_read,
                &mut stream_write,
                &mut handler,
                &mut kex_done_signal,
            )
            .await;
        trace!("disconnected");
        self.receiver.close();
        self.inbound_channel_receiver.close();
        map_err!(stream_write.shutdown().await)?;
        match result {
            Ok(v) => {
                handler
                    .disconnected(DisconnectReason::ReceivedDisconnect(v))
                    .await?;
                Ok(())
            }
            Err(e) => {
                if kex_done_signal.is_some() {
                    // The kex signal has not been consumed yet,
                    // so we can send return the concrete error to be propagated
                    // into the JoinHandle and returned from `connect_stream`
                    Err(e)
                } else {
                    // The kex signal has been consumed, so no one is
                    // awaiting the result of this coroutine
                    // We're better off passing the error into the Handler
                    debug!("disconnected {e:?}");
                    handler.disconnected(DisconnectReason::Error(e)).await?;
                    Err(H::Error::from(crate::Error::Disconnect))
                }
            }
        }
    }

    async fn run_inner<H: Handler + Send, R: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        stream_read: SshRead<ReadHalf<R>>,
        stream_write: &mut WriteHalf<R>,
        handler: &mut H,
        kex_done_signal: &mut Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<RemoteDisconnectInfo, H::Error> {
        let mut result: Result<RemoteDisconnectInfo, H::Error> = Err(Error::Disconnect.into());
        self.flush()?;

        map_err!(self.common.packet_writer.flush_into(stream_write).await)?;

        let buffer = SSHBuffer::new();

        // Allow handing out references to the cipher
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

        let keepalive_timer =
            crate::future_or_pending(self.common.config.keepalive_interval, tokio::time::sleep);
        pin!(keepalive_timer);

        let inactivity_timer =
            crate::future_or_pending(self.common.config.inactivity_timeout, tokio::time::sleep);
        pin!(inactivity_timer);

        let reading = start_reading(stream_read, buffer, opening_cipher);
        pin!(reading);

        #[allow(clippy::panic)] // false positive in select! macro
        while !self.common.disconnected {
            self.common.received_data = false;
            let mut sent_keepalive = false;
            tokio::select! {
                r = &mut reading => {
                    let (stream_read, mut buffer, mut opening_cipher) = match r {
                        Ok((_, stream_read, buffer, opening_cipher)) => (stream_read, buffer, opening_cipher),
                        Err(e) => return Err(e.into())
                    };

                    std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

                    if buffer.buffer.len() < 5 {
                        break
                    }

                    let mut pkt = self.maybe_decompress(&buffer)?;
                    if !pkt.buffer.is_empty() {
                        #[allow(clippy::indexing_slicing)] // length checked
                        if pkt.buffer[0] == crate::msg::DISCONNECT {
                            debug!("received disconnect");
                            result = self.process_disconnect(&pkt).map_err(H::Error::from);
                        } else {
                            self.common.received_data = true;
                            reply(self, handler, kex_done_signal, &mut pkt).await?;
                            buffer.seqn = pkt.seqn; // TODO reply changes seqn internall, find cleaner way
                        }
                    }

                    std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                () = &mut keepalive_timer => {
                    self.common.alive_timeouts = self.common.alive_timeouts.saturating_add(1);
                    if self.common.config.keepalive_max != 0 && self.common.alive_timeouts > self.common.config.keepalive_max {
                        debug!("Timeout, server not responding to keepalives");
                        return Err(crate::Error::KeepaliveTimeout.into());
                    }
                    sent_keepalive = true;
                    self.send_keepalive(true)?;
                }
                () = &mut inactivity_timer => {
                    debug!("timeout");
                    return Err(crate::Error::InactivityTimeout.into());
                }
                msg = self.receiver.recv(), if !self.kex.active() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => {
                            self.common.disconnected = true;
                            break
                        }
                    };

                    // eagerly take all outgoing messages so writes are batched
                    while !self.kex.active() {
                        match self.receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
                msg = self.inbound_channel_receiver.recv(), if !self.kex.active() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg)?,
                        None => (),
                    }

                    // eagerly take all outgoing messages so writes are batched
                    while !self.kex.active() {
                        match self.inbound_channel_receiver.try_recv() {
                            Ok(next) => self.handle_msg(next)?,
                            Err(_) => break
                        }
                    }
                }
            };

            self.flush()?;
            map_err!(self.common.packet_writer.flush_into(stream_write).await)?;

            if let Some(ref mut enc) = self.common.encrypted {
                if let EncryptedState::InitCompression = enc.state {
                    enc.client_compression
                        .init_compress(self.common.packet_writer.compress());
                    enc.state = EncryptedState::Authenticated;
                }
            }

            if self.common.received_data {
                // Reset the number of failed keepalive attempts. We don't
                // bother detecting keepalive response messages specifically
                // (OpenSSH_9.6p1 responds with REQUEST_FAILURE aka 82). Instead
                // we assume that the server is still alive if we receive any
                // data from it.
                self.common.alive_timeouts = 0;
            }
            if self.common.received_data || sent_keepalive {
                if let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    keepalive_timer.as_mut().as_pin_mut(),
                    self.common.config.keepalive_interval,
                ) {
                    sleep.as_mut().reset(tokio::time::Instant::now() + d);
                }
            }
            if !sent_keepalive {
                if let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    inactivity_timer.as_mut().as_pin_mut(),
                    self.common.config.inactivity_timeout,
                ) {
                    sleep.as_mut().reset(tokio::time::Instant::now() + d);
                }
            }
        }

        result
    }

    fn process_disconnect(
        &mut self,
        pkt: &IncomingSshPacket,
    ) -> Result<RemoteDisconnectInfo, Error> {
        let mut r = &pkt.buffer[..];
        u8::decode(&mut r)?; // skip message type
        self.common.disconnected = true;

        let reason_code = u32::decode(&mut r)?.try_into()?;
        let message = String::decode(&mut r)?;
        let lang_tag = String::decode(&mut r)?;

        Ok(RemoteDisconnectInfo {
            reason_code,
            message,
            lang_tag,
        })
    }

    fn handle_msg(&mut self, msg: Msg) -> Result<(), crate::Error> {
        match msg {
            Msg::Authenticate { user, method } => {
                self.write_auth_request_if_needed(&user, method)?;
            }
            Msg::Signed { .. } => {}
            Msg::AuthInfoResponse { .. } => {}
            Msg::ChannelOpenSession { channel_ref } => {
                let id = self.channel_open_session()?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenX11 {
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_x11(&originator_address, originator_port)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectTcpIp {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_direct_tcpip(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectStreamLocal {
                socket_path,
                channel_ref,
            } => {
                let id = self.channel_open_direct_streamlocal(&socket_path)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::TcpIpForward {
                reply_channel,
                address,
                port,
            } => self.tcpip_forward(reply_channel, &address, port)?,
            Msg::CancelTcpIpForward {
                reply_channel,
                address,
                port,
            } => self.cancel_tcpip_forward(reply_channel, &address, port)?,
            Msg::StreamLocalForward {
                reply_channel,
                socket_path,
            } => self.streamlocal_forward(reply_channel, &socket_path)?,
            Msg::CancelStreamLocalForward {
                reply_channel,
                socket_path,
            } => self.cancel_streamlocal_forward(reply_channel, &socket_path)?,
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => self.disconnect(reason, &description, &language_tag)?,
            Msg::Channel(id, ChannelMsg::Data { data }) => self.data(id, data)?,
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id)?;
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { data, ext }) => {
                self.extended_data(id, ext, data)?;
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
            )?,
            Msg::Channel(
                id,
                ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                },
            ) => self.window_change(id, col_width, row_height, pix_width, pix_height)?,
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
            )?,
            Msg::Channel(
                id,
                ChannelMsg::SetEnv {
                    want_reply,
                    variable_name,
                    variable_value,
                },
            ) => self.set_env(id, want_reply, &variable_name, &variable_value)?,
            Msg::Channel(id, ChannelMsg::RequestShell { want_reply }) => {
                self.request_shell(want_reply, id)?
            }
            Msg::Channel(
                id,
                ChannelMsg::Exec {
                    want_reply,
                    command,
                },
            ) => self.exec(id, want_reply, &command)?,
            Msg::Channel(id, ChannelMsg::Signal { signal }) => self.signal(id, signal)?,
            Msg::Channel(id, ChannelMsg::RequestSubsystem { want_reply, name }) => {
                self.request_subsystem(want_reply, id, &name)?
            }
            Msg::Channel(id, ChannelMsg::AgentForward { want_reply }) => {
                self.agent_forward(id, want_reply)?
            }
            Msg::Channel(id, ChannelMsg::Close) => self.close(id)?,
            Msg::Rekey => self.initiate_rekey()?,
            Msg::AwaitExtensionInfo {
                extension_name,
                reply_channel,
            } => {
                if let Some(ref mut enc) = self.common.encrypted {
                    // Drop if the extension has been seen already
                    if !enc.received_extensions.contains(&extension_name) {
                        // There will be no new extension info after authentication
                        // has succeeded
                        if !matches!(enc.state, EncryptedState::Authenticated) {
                            enc.extension_info_awaiters
                                .entry(extension_name)
                                .or_insert(vec![])
                                .push(reply_channel);
                        }
                    }
                }
            }
            Msg::GetServerSigAlgs { reply_channel } => {
                let _ = reply_channel.send(self.server_sig_algs.clone());
            }
            Msg::Keepalive { want_reply } => {
                let _ = self.send_keepalive(want_reply);
            }
            Msg::Ping { reply_channel } => {
                let _ = self.send_ping(reply_channel);
            }
            Msg::NoMoreSessions { want_reply } => {
                let _ = self.no_more_sessions(want_reply);
            }
            msg => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (server-only?) message: {:?}", msg)
            }
        }
        Ok(())
    }

    fn begin_rekey(&mut self) -> Result<(), crate::Error> {
        debug!("beginning re-key");
        let mut kex = ClientKex::new(
            self.common.config.clone(),
            &self.common.config.client_id,
            &self.common.remote_sshid,
            match &self.common.encrypted {
                None => KexCause::Initial,
                Some(enc) => KexCause::Rekey {
                    strict: self.common.strict_kex,
                    session_id: enc.session_id.clone(),
                },
            },
        );

        kex.kexinit(&mut self.common.packet_writer)?;
        self.kex = SessionKexState::InProgress(kex);
        Ok(())
    }

    /// Flush the temporary cleartext buffer into the encryption
    /// buffer. This does *not* flush to the socket.
    fn flush(&mut self) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut self.common.packet_writer,
            )? && !self.kex.active()
            {
                self.begin_rekey()?;
            }
        }
        Ok(())
    }

    /// Immediately trigger a session re-key after flushing all pending packets
    pub fn initiate_rekey(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.rekey_wanted = true;
            self.flush()?
        }
        Ok(())
    }
}

async fn reply<H: Handler>(
    session: &mut Session,
    handler: &mut H,
    kex_done_signal: &mut Option<tokio::sync::oneshot::Sender<()>>,
    pkt: &mut IncomingSshPacket,
) -> Result<(), H::Error> {
    if let Some(message_type) = pkt.buffer.first() {
        debug!(
            "< msg type {message_type:?}, seqn {:?}, len {}",
            pkt.seqn.0,
            pkt.buffer.len()
        );
        if session.common.strict_kex && session.common.encrypted.is_none() {
            let seqno = pkt.seqn.0 - 1; // was incremented after read()
            validate_server_msg_strict_kex(*message_type, seqno as usize)?;
        }

        if [msg::IGNORE, msg::UNIMPLEMENTED, msg::DEBUG].contains(message_type) {
            return Ok(());
        }
    }

    if pkt.buffer.first() == Some(&msg::KEXINIT) && session.kex == SessionKexState::Idle {
        // Not currently in a rekey but received KEXINIT
        debug!("server has initiated re-key");
        session.begin_rekey()?;
        // Kex will consume the packet right away
    }

    let is_kex_msg = pkt.buffer.first().cloned().map(is_kex_msg).unwrap_or(false);

    if is_kex_msg {
        if let SessionKexState::InProgress(kex) = session.kex.take() {
            let progress = kex.step(Some(pkt), &mut session.common.packet_writer)?;

            match progress {
                KexProgress::NeedsReply { kex, reset_seqn } => {
                    debug!("kex impl continues: {kex:?}");
                    session.kex = SessionKexState::InProgress(kex);
                    if reset_seqn {
                        debug!("kex impl requests seqno reset");
                        session.common.reset_seqn();
                    }
                }
                KexProgress::Done {
                    server_host_key,
                    newkeys,
                } => {
                    debug!("kex impl has completed");
                    session.common.strict_kex =
                        session.common.strict_kex || newkeys.names.strict_kex();

                    // Call the kex_done handler before consuming newkeys
                    let shared_secret = newkeys.kex.shared_secret_bytes();
                    handler
                        .kex_done(shared_secret, &newkeys.names, session)
                        .await?;

                    if let Some(ref mut enc) = session.common.encrypted {
                        // This is a rekey
                        enc.last_rekey = Instant::now();
                        session.common.packet_writer.buffer().bytes = 0;
                        enc.flush_all_pending()?;
                        let mut pending = std::mem::take(&mut session.pending_reads);
                        for p in pending.drain(..) {
                            session.process_packet(handler, &p).await?;
                        }
                        session.pending_reads = pending;
                        session.pending_len = 0;
                        session.common.newkeys(newkeys);
                    } else {
                        // This is the initial kex
                        if let Some(server_host_key) = &server_host_key {
                            let check = handler.check_server_key(server_host_key).await?;
                            if !check {
                                return Err(crate::Error::UnknownKey.into());
                            }
                        }

                        session
                            .common
                            .encrypted(initial_encrypted_state(session), newkeys);

                        if let Some(sender) = kex_done_signal.take() {
                            sender.send(()).unwrap_or(());
                        }
                    }

                    session.kex = SessionKexState::Idle;

                    if session.common.strict_kex {
                        pkt.seqn = Wrapping(0);
                    }

                    debug!("kex done");
                }
            }

            session.flush()?;

            return Ok(());
        }
    }

    session.client_read_encrypted(handler, pkt).await
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

/// Parameters for dynamic group Diffie-Hellman key exchanges.
#[derive(Debug, Clone)]
pub struct GexParams {
    /// Minimum DH group size (in bits)
    min_group_size: usize,
    /// Preferred DH group size (in bits)
    preferred_group_size: usize,
    /// Maximum DH group size (in bits)
    max_group_size: usize,
}

impl GexParams {
    pub fn new(
        min_group_size: usize,
        preferred_group_size: usize,
        max_group_size: usize,
    ) -> Result<Self, Error> {
        let this = Self {
            min_group_size,
            preferred_group_size,
            max_group_size,
        };
        this.validate()?;
        Ok(this)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.min_group_size < 2048 {
            return Err(Error::InvalidConfig(format!(
                "min_group_size must be at least 2048 bits. We got {} bits",
                self.min_group_size
            )));
        }
        if self.preferred_group_size < self.min_group_size {
            return Err(Error::InvalidConfig(format!(
                "preferred_group_size must be at least as large as min_group_size. We have preferred_group_size = {} < min_group_size = {}",
                self.preferred_group_size, self.min_group_size
            )));
        }
        if self.max_group_size < self.preferred_group_size {
            return Err(Error::InvalidConfig(format!(
                "max_group_size must be at least as large as preferred_group_size. We have max_group_size = {} < preferred_group_size = {}",
                self.max_group_size, self.preferred_group_size
            )));
        }
        Ok(())
    }

    pub fn min_group_size(&self) -> usize {
        self.min_group_size
    }

    pub fn preferred_group_size(&self) -> usize {
        self.preferred_group_size
    }

    pub fn max_group_size(&self) -> usize {
        self.max_group_size
    }
}

impl Default for GexParams {
    fn default() -> GexParams {
        GexParams {
            min_group_size: 3072,
            preferred_group_size: 8192,
            max_group_size: 8192,
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
    /// Buffer size for each channel (a number of unprocessed messages to store before propagating backpressure to the TCP stream)
    pub channel_buffer_size: usize,
    /// Lists of preferred algorithms.
    pub preferred: negotiation::Preferred,
    /// Time after which the connection is garbage-collected.
    pub inactivity_timeout: Option<std::time::Duration>,
    /// If nothing is received from the server for this amount of time, send a keepalive message.
    pub keepalive_interval: Option<std::time::Duration>,
    /// If this many keepalives have been sent without reply, close the connection.
    pub keepalive_max: usize,
    /// Whether to expect and wait for an authentication call.
    pub anonymous: bool,
    /// DH dynamic group exchange parameters.
    pub gex: GexParams,
    /// If active, invoke `set_nodelay(true)` on the ssh socket; disabled by default (i.e. Nagle's algorithm is active).
    pub nodelay: bool,
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
            channel_buffer_size: 100,
            preferred: Default::default(),
            inactivity_timeout: None,
            keepalive_interval: None,
            keepalive_max: 3,
            anonymous: false,
            gex: Default::default(),
            nodelay: false,
        }
    }
}

/// A client handler. Note that messages can be received from the
/// server at any time during a session.
///
/// You must at the very least implement the `check_server_key` fn.
/// The default implementation rejects all keys.
///
/// Note: this is an async trait. The trait functions return `impl Future`,
/// and you can simply define them as `async fn` instead.
#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
pub trait Handler: Sized + Send {
    type Error: From<crate::Error> + Send + core::fmt::Debug;

    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    #[allow(unused_variables)]
    fn auth_banner(
        &mut self,
        banner: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    #[allow(unused_variables)]
    fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    /// Called when key exchange has completed.
    ///
    /// This callback provides access to the raw shared secret from the KEX,
    /// which is useful for protocols that derive additional keys from the
    /// SSH shared secret (e.g., for secondary encrypted channels).
    ///
    /// The `names` parameter contains all negotiated algorithms (kex, cipher, mac, etc.).
    ///
    /// **Security Warning:** The shared secret is sensitive cryptographic material.
    /// Handle it with care and zero it after use if stored.
    ///
    /// # Arguments
    ///
    /// * `kex_algorithm` - Name of the key exchange algorithm used
    /// * `shared_secret` - The raw shared secret bytes from the key exchange.
    ///   For some algorithms (like `none`), this may be `None`.
    /// * `names` - The negotiated algorithm names
    /// * `session` - The current session
    #[allow(unused_variables)]
    fn kex_done(
        &mut self,
        shared_secret: Option<&[u8]>,
        names: &negotiation::Names,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    fn channel_success(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server signals failure.
    #[allow(unused_variables)]
    fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a channel for a new remote port forwarding connection
    #[allow(unused_variables)]
    fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    // Called when the server opens a channel for a new remote UDS forwarding connection
    #[allow(unused_variables)]
    fn server_channel_open_forwarded_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens an agent forwarding channel
    #[allow(unused_variables)]
    fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server attempts to open a channel of unknown type. It may return `true`,
    /// if the channel of unknown type should be accepted. In this case,
    /// [Handler::server_channel_open_unknown] will be called soon after. If it returns `false`,
    /// the channel will not be created and a rejection message will be sent to the server.
    #[allow(unused_variables)]
    fn should_accept_unknown_server_channel(
        &mut self,
        id: ChannelId,
        channel_type: &str,
    ) -> impl Future<Output = bool> + Send {
        async { false }
    }

    /// Called when the server opens an unknown channel.
    #[allow(unused_variables)]
    fn server_channel_open_unknown(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a session channel.
    #[allow(unused_variables)]
    fn server_channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a direct tcp/ip channel (non-standard).
    #[allow(unused_variables)]
    fn server_channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens a direct-streamlocal channel (non-standard).
    #[allow(unused_variables)]
    fn server_channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server opens an X11 channel.
    #[allow(unused_variables)]
    fn server_channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(
        &mut self,
        channel: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: &str,
        lang_tag: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(
        &mut self,
        channel: ChannelId,
        new_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when this client adjusts the network window. Return the
    /// next target window and maximum packet size.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, window: u32) -> u32 {
        window
    }

    /// Called when the server signals success.
    #[allow(unused_variables)]
    fn openssh_ext_host_keys_announced(
        &mut self,
        keys: Vec<PublicKey>,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            debug!("openssh_ext_hostkeys_announced: {keys:?}");
            Ok(())
        }
    }

    /// Called when the server sent a disconnect message
    ///
    /// If reason is an Error, this function should re-return the error so the join can also evaluate it
    #[allow(unused_variables)]
    fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async {
            debug!("disconnected: {reason:?}");
            match reason {
                DisconnectReason::ReceivedDisconnect(_) => Ok(()),
                DisconnectReason::Error(e) => Err(e),
            }
        }
    }
}
