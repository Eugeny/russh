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
//! * implement the [Server](server::Server) trait and let [run_on_socket](server::Server::run_on_socket)/[run_on_address](server::Server::run_on_address) handle everything
//! * accept connections yourself and pass them to [run_stream](server::run_stream)
//!
//! In both cases, you'll first need to implement the [Handler](server::Handler) trait -
//! this is where you'll handle various events.
//!
//! Check out the following examples:
//!
//! * [Server that forwards your input to all connected clients](https://github.com/warp-tech/russh/blob/main/russh/examples/echoserver.rs)
//! * [Server handing channel processing off to a library (here, `russh-sftp`)](https://github.com/warp-tech/russh/blob/main/russh/examples/sftp_server.rs)
//! * Serving `ratatui` based TUI app to clients: [per-client](https://github.com/warp-tech/russh/blob/main/russh/examples/ratatui_app.rs), [shared](https://github.com/warp-tech/russh/blob/main/russh/examples/ratatui_shared_app.rs)

use std;
use std::collections::{HashMap, VecDeque};
use std::num::Wrapping;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use client::GexParams;
use futures::future::Future;
use log::{debug, error, info, warn};
use msg::{is_kex_msg, validate_client_msg_strict_kex};
use russh_keys::map_err;
use russh_util::runtime::JoinHandle;
use russh_util::time::Instant;
use ssh_key::{Certificate, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::pin;

use crate::cipher::{clear, OpeningKey};
use crate::kex::dh::groups::{DhGroup, BUILTIN_SAFE_DH_GROUPS, DH_GROUP14};
use crate::kex::{KexProgress, SessionKexState};
use crate::session::*;
use crate::ssh_read::*;
use crate::sshbuffer::*;
use crate::*;

mod kex;
mod session;
pub use self::session::*;
mod encrypted;

/// Configuration of a server.
pub struct Config {
    /// The server ID string sent at the beginning of the protocol.
    pub server_id: SshId,
    /// Authentication methods proposed to the client.
    pub methods: auth::MethodSet,
    /// Authentication rejections must happen in constant time for
    /// security reasons. Russh does not handle this by default.
    pub auth_rejection_time: std::time::Duration,
    /// Authentication rejection time override for the initial "none" auth attempt.
    /// OpenSSH clients will send an initial "none" auth to probe for authentication methods.
    pub auth_rejection_time_initial: Option<std::time::Duration>,
    /// The server's keys. The first key pair in the client's preference order will be chosen.
    pub keys: Vec<PrivateKey>,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Buffer size for each channel (a number of unprocessed messages to store before propagating backpressure to the TCP stream)
    pub channel_buffer_size: usize,
    /// Internal event buffer size
    pub event_buffer_size: usize,
    /// Lists of preferred algorithms.
    pub preferred: Preferred,
    /// Maximal number of allowed authentication attempts.
    pub max_auth_attempts: usize,
    /// Time after which the connection is garbage-collected.
    pub inactivity_timeout: Option<std::time::Duration>,
    /// If nothing is received from the client for this amount of time, send a keepalive message.
    pub keepalive_interval: Option<std::time::Duration>,
    /// If this many keepalives have been sent without reply, close the connection.
    pub keepalive_max: usize,
    /// If active, invoke `set_nodelay(true)` on client sockets; disabled by default (i.e. Nagle's algorithm is active).
    pub nodelay: bool,
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
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: None,
            keys: Vec::new(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            channel_buffer_size: 100,
            event_buffer_size: 10,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10,
            inactivity_timeout: Some(std::time::Duration::from_secs(600)),
            keepalive_interval: None,
            keepalive_max: 3,
            nodelay: false,
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // display everything except the private keys
        f.debug_struct("Config")
            .field("server_id", &self.server_id)
            .field("methods", &self.methods)
            .field("auth_rejection_time", &self.auth_rejection_time)
            .field(
                "auth_rejection_time_initial",
                &self.auth_rejection_time_initial,
            )
            .field("keys", &"***")
            .field("window_size", &self.window_size)
            .field("maximum_packet_size", &self.maximum_packet_size)
            .field("channel_buffer_size", &self.channel_buffer_size)
            .field("event_buffer_size", &self.event_buffer_size)
            .field("limits", &self.limits)
            .field("preferred", &self.preferred)
            .field("max_auth_attempts", &self.max_auth_attempts)
            .field("inactivity_timeout", &self.inactivity_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_max", &self.keepalive_max)
            .finish()
    }
}

/// A client's response in a challenge-response authentication.
///
/// You should iterate it to get `&[u8]` response slices.
pub struct Response<'a>(&'a mut (dyn Iterator<Item = Option<Bytes>> + Send));

impl Iterator for Response<'_> {
    type Item = Bytes;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().flatten()
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
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Check authentication using the "password" method. Russh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Check authentication using the "publickey" method. This method
    /// should just check whether the public key matches the
    /// authorized ones. Russh then checks the signature. If the key
    /// is unknown, or the signature is invalid, Russh guarantees
    /// that rejection happens in constant time
    /// `config.auth_rejection_time`, except if this method takes more
    /// time than that.
    #[allow(unused_variables)]
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    /// Check authentication using the "publickey" method. This method
    /// is called after the signature has been verified and key
    /// ownership has been confirmed.
    /// Russh guarantees that rejection happens in constant time
    /// `config.auth_rejection_time`, except if this method takes more
    /// time than that.
    #[allow(unused_variables)]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Check authentication using an OpenSSH certificate. This method
    /// is called after the signature has been verified and key
    /// ownership has been confirmed.
    /// Russh guarantees that rejection happens in constant time
    /// `config.auth_rejection_time`, except if this method takes more
    /// time than that.
    #[allow(unused_variables)]
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Check authentication using the "keyboard-interactive"
    /// method. Russh makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<Response<'async_trait>>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    /// Called when authentication succeeds for a session.
    #[allow(unused_variables)]
    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when authentication starts but before it is successful.
    /// Return value is an authentication banner, usually a warning message shown to the client.
    #[allow(unused_variables)]
    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }

    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when a new session channel is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Called when a new X11 channel is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Called when a new TCP/IP is created.
    /// Return value indicates whether the channel request should be granted.
    #[allow(unused_variables)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Called when a new forwarded connection comes in.
    /// <https://www.rfc-editor.org/rfc/rfc4254#section-7>
    #[allow(unused_variables)]
    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Called when the client confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    async fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes.
    #[allow(unused_variables)]
    async fn window_adjusted(
        &mut self,
        channel: ChannelId,
        new_size: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when this server adjusts the network window. Return the
    /// next target window.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, current: u32) -> u32 {
        current
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn pty_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     term: &str,
    ///     col_width: u32,
    ///     row_height: u32,
    ///     pix_width: u32,
    ///     pix_height: u32,
    ///     modes: &[(Pty, u32)],
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables, clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client requests an X11 connection.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn x11_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     single_connection: bool,
    ///     x11_auth_protocol: &str,
    ///     x11_auth_cookie: &str,
    ///     x11_screen_number: u32,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn env_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     variable_name: &str,
    ///     variable_value: &str,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client requests a shell.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn shell_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn exec_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     data: &[u8],
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client asks to start the subsystem with the given name
    /// (such as sftp).
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn subsystem_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     name: &str,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client's pseudo-terminal window size has changed.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn window_change_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     col_width: u32,
    ///     row_height: u32,
    ///     pix_width: u32,
    ///     pix_height: u32,
    ///     session: &mut Session,
    /// ) -> Result<(), Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client requests OpenSSH agent forwarding
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively. For
    /// instance:
    ///
    /// ```ignore
    /// async fn agent_request(
    ///     &mut self,
    ///     channel: ChannelId,
    ///     session: &mut Session,
    /// ) -> Result<bool, Self::Error> {
    ///     session.channel_success(channel);
    ///     Ok(())
    /// }
    /// ```
    #[allow(unused_variables)]
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// The client is sending a signal (usually to pass to the
    /// currently running process).
    #[allow(unused_variables)]
    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Used for reverse-forwarding ports, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    /// If `port` is 0, you should set it to the allocated port number.
    #[allow(unused_variables)]
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Used to stop the reverse-forwarding of a port, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    #[allow(unused_variables)]
    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    #[allow(unused_variables)]
    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Override when enabling the `diffie-hellman-group-exchange-*` key exchange methods.
    /// Should return a Diffie-Hellman group with a safe prime whose length is
    /// between `gex_params.min_group_size` and `gex_params.max_group_size` and
    /// (if possible) over and as close as possible to `gex_params.preferred_group_size`.
    ///
    /// OpenSSH uses a pre-generated database of safe primes stored in `/etc/ssh/moduli`
    ///
    /// The default implementation picks a group from a very short static list
    /// of built-in standard groups and is not really taking advantage of the security
    /// offered by these kex methods.
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc4419#section-3
    #[allow(unused_variables)]
    async fn lookup_dh_gex_group(
        &mut self,
        gex_params: &GexParams,
    ) -> Result<Option<DhGroup>, Self::Error> {
        let mut best_group = &DH_GROUP14;

        // Find _some_ matching group
        for group in BUILTIN_SAFE_DH_GROUPS.iter() {
            if group.bit_size() >= gex_params.min_group_size()
                && group.bit_size() <= gex_params.max_group_size()
            {
                best_group = *group;
                break;
            }
        }

        // Find _closest_ matching group
        for group in BUILTIN_SAFE_DH_GROUPS.iter() {
            if group.bit_size() > gex_params.preferred_group_size() {
                best_group = *group;
                break;
            }
        }

        Ok(Some(best_group.clone()))
    }
}

#[async_trait]
/// Trait used to create new handlers when clients connect.
pub trait Server {
    /// The type of handlers.
    type Handler: Handler + Send + 'static;
    /// Called when a new client connects.
    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler;
    /// Called when an active connection fails.
    fn handle_session_error(&mut self, _error: <Self::Handler as Handler>::Error) {}

    /// Run a server on a specified `tokio::net::TcpListener`. Useful when dropping
    /// privileges immediately after socket binding, for example.
    async fn run_on_socket(
        &mut self,
        config: Arc<Config>,
        socket: &TcpListener,
    ) -> Result<(), std::io::Error> {
        if config.maximum_packet_size > 65535 {
            error!(
                "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
                config.maximum_packet_size
            );
        }

        let (error_tx, mut error_rx) = tokio::sync::mpsc::unbounded_channel();

        loop {
            tokio::select! {
                accept_result = socket.accept() => {
                    match accept_result {
                        Ok((socket, _)) => {
                            let config = config.clone();
                            let handler = self.new_client(socket.peer_addr().ok());
                            let error_tx = error_tx.clone();

                            russh_util::runtime::spawn(async move {
                                if config.nodelay {
                                    if let Err(e) = socket.set_nodelay(true) {
                                        warn!("set_nodelay() failed: {e:?}");
                                    }
                                }

                                let session = match run_stream(config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        debug!("Connection setup failed");
                                        let _ = error_tx.send(e);
                                        return
                                    }
                                };

                                match session.await {
                                    Ok(_) => debug!("Connection closed"),
                                    Err(e) => {
                                        debug!("Connection closed with error");
                                        let _ = error_tx.send(e);
                                    }
                                }
                            });
                        }

                        _ => break,
                    }
                },

                Some(error) = error_rx.recv() => {
                    self.handle_session_error(error);
                }
            }
        }

        Ok(())
    }

    /// Run a server.
    /// Create a new `Connection` from the server's configuration, a
    /// stream and a [`Handler`](trait.Handler.html).
    async fn run_on_address<A: ToSocketAddrs + Send>(
        &mut self,
        config: Arc<Config>,
        addrs: A,
    ) -> Result<(), std::io::Error> {
        let socket = TcpListener::bind(addrs).await?;
        self.run_on_socket(config, &socket).await
    }
}

use std::cell::RefCell;
thread_local! {
    static B1: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static B2: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
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
/// Implements [Future] and can be awaited to wait for the session to finish.
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

/// Start a single connection in the background.
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
    map_err!(stream.write_all(&write_buffer.buffer[..]).await)?;

    // Reading SSH id and allocating a session.
    let mut stream = SshRead::new(stream);
    let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
    let handle = server::session::Handle {
        sender,
        channel_buffer_size: config.channel_buffer_size,
    };

    let common = read_ssh_id(config, &mut stream).await?;
    let mut session = Session {
        target_window_size: common.config.window_size,
        common,
        receiver,
        sender: handle.clone(),
        pending_reads: Vec::new(),
        pending_len: 0,
        channels: HashMap::new(),
        open_global_requests: VecDeque::new(),
        kex: SessionKexState::Idle,
    };

    session.begin_rekey()?;

    let join = russh_util::runtime::spawn(session.run(stream, handler));

    Ok(RunningSession { handle, join })
}

async fn read_ssh_id<R: AsyncRead + Unpin>(
    config: Arc<Config>,
    read: &mut SshRead<R>,
) -> Result<CommonSession<Arc<Config>>, Error> {
    let sshid = if let Some(t) = config.inactivity_timeout {
        tokio::time::timeout(t, read.read_ssh_id()).await??
    } else {
        read.read_ssh_id().await?
    };

    let session = CommonSession {
        packet_writer: PacketWriter::clear(),
        // kex: Some(Kex::Init(kexinit)),
        auth_user: String::new(),
        auth_method: None, // Client only.
        auth_attempts: 0,
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
    };
    Ok(session)
}

async fn reply<H: Handler + Send>(
    session: &mut Session,
    handler: &mut H,
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
            validate_client_msg_strict_kex(*message_type, seqno as usize)?;
        }

        if [msg::IGNORE, msg::UNIMPLEMENTED, msg::DEBUG].contains(message_type) {
            return Ok(());
        }
    }

    if pkt.buffer.first() == Some(&msg::KEXINIT) && session.kex == SessionKexState::Idle {
        // Not currently in a rekey but received KEXINIT
        info!("Client has initiated re-key");
        session.begin_rekey()?;
        // Kex will consume the packet right away
    }

    let is_kex_msg = pkt.buffer.first().cloned().map(is_kex_msg).unwrap_or(false);

    if is_kex_msg {
        if let SessionKexState::InProgress(kex) = session.kex.take() {
            let progress = kex
                .step(Some(pkt), &mut session.common.packet_writer, handler)
                .await?;

            match progress {
                KexProgress::NeedsReply { kex, reset_seqn } => {
                    debug!("kex impl continues: {kex:?}");
                    session.kex = SessionKexState::InProgress(kex);
                    if reset_seqn {
                        debug!("kex impl requests seqno reset");
                        session.common.reset_seqn();
                    }
                }
                KexProgress::Done { newkeys, .. } => {
                    debug!("kex impl has completed");
                    session.common.strict_kex =
                        session.common.strict_kex || newkeys.names.strict_kex;

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
                        session.flush()?;
                    } else {
                        // This is the initial kex

                        session.common.encrypted(
                            EncryptedState::WaitingAuthServiceRequest {
                                sent: false,
                                accepted: false,
                            },
                            newkeys,
                        );

                        session.maybe_send_ext_info()?;
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

    // Handle key exchange/re-exchange.
    session.server_read_encrypted(handler, pkt).await
}
