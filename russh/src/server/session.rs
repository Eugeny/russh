use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;

use channels::WindowSizeRef;
use kex::ServerKex;
use log::debug;
use negotiation::parse_kex_algo_list;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

use super::*;
use crate::channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf};
use crate::helpers::NameList;
use crate::kex::{KexCause, SessionKexState, EXTENSION_SUPPORT_AS_CLIENT};
use crate::{map_err, msg};

/// A connected server session. This type is unique to a client.
#[derive(Debug)]
pub struct Session {
    pub(crate) common: CommonSession<Arc<Config>>,
    pub(crate) sender: Handle,
    pub(crate) receiver: Receiver<Msg>,
    pub(crate) target_window_size: u32,
    pub(crate) pending_reads: Vec<CryptoVec>,
    pub(crate) pending_len: u32,
    pub(crate) channels: HashMap<ChannelId, ChannelRef>,
    pub(crate) open_global_requests: VecDeque<GlobalRequestResponse>,
    pub(crate) kex: SessionKexState<ServerKex>,
}

#[derive(Debug)]
pub enum Msg {
    ChannelOpenAgent {
        channel_ref: ChannelRef,
    },
    ChannelOpenSession {
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
    ChannelOpenForwardedTcpIp {
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenForwardedStreamLocal {
        server_socket_path: String,
        channel_ref: ChannelRef,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
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
    Disconnect {
        reason: crate::Disconnect,
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

#[derive(Clone, Debug)]
/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle {
    pub(crate) sender: Sender<Msg>,
    pub(crate) channel_buffer_size: usize,
}

impl Handle {
    /// Send data to the session referenced by this handler.
    pub async fn data(&self, id: ChannelId, data: CryptoVec) -> Result<(), CryptoVec> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Data { data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::Data { data }) => data,
                _ => unreachable!(),
            })
    }

    /// Send data to the session referenced by this handler.
    pub async fn extended_data(
        &self,
        id: ChannelId,
        ext: u32,
        data: CryptoVec,
    ) -> Result<(), CryptoVec> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExtendedData { ext, data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::ExtendedData { data, .. }) => data,
                _ => unreachable!(),
            })
    }

    /// Send EOF to the session referenced by this handler.
    pub async fn eof(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Eof))
            .await
            .map_err(|_| ())
    }

    /// Send success to the session referenced by this handler.
    pub async fn channel_success(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Success))
            .await
            .map_err(|_| ())
    }

    /// Send failure to the session referenced by this handler.
    pub async fn channel_failure(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Failure))
            .await
            .map_err(|_| ())
    }

    /// Close a channel.
    pub async fn close(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Close))
            .await
            .map_err(|_| ())
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub async fn xon_xoff_request(&self, id: ChannelId, client_can_do: bool) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }))
            .await
            .map_err(|_| ())
    }

    /// Send the exit status of a program.
    pub async fn exit_status_request(&self, id: ChannelId, exit_status: u32) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }))
            .await
            .map_err(|_| ())
    }

    /// Notifies the client that it can open TCP/IP forwarding channels for a port.
    pub async fn forward_tcpip(&self, address: String, port: u32) -> Result<u32, ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::TcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;

        match reply_recv.await {
            Ok(Some(port)) => Ok(port),
            Ok(None) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive TcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Notifies the client that it can no longer open TCP/IP forwarding channel for a port.
    pub async fn cancel_forward_tcpip(&self, address: String, port: u32) -> Result<(), ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelTcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;
        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive CancelTcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Open an agent forwarding channel. This can be used once the client has
    /// confirmed that it allows agent forwarding. See
    /// [PROTOCOL.agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent).
    pub async fn channel_open_agent(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenAgent { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Ok(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
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
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a direct streamlocal (Unix domain socket) channel on the client.
    pub async fn channel_open_direct_streamlocal<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_forwarded_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        connected_address: A,
        connected_port: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedTcpIp {
                connected_address: connected_address.into(),
                connected_port,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_forwarded_streamlocal<A: Into<String>>(
        &self,
        server_socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path: server_socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
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
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    async fn wait_channel_confirmation(
        &self,
        mut receiver: Receiver<ChannelMsg>,
        window_size_ref: WindowSizeRef,
    ) -> Result<Channel<Msg>, Error> {
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
                    return Err(Error::ChannelOpenFailure(reason))
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

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub async fn exit_signal_request(
        &self,
        id: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    ) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ))
            .await
            .map_err(|_| ())
    }

    /// Allows a server to disconnect a client session
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: String,
        language_tag: String,
    ) -> Result<(), Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description,
                language_tag,
            })
            .await
            .map_err(|_| Error::SendError)
    }
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

    pub(crate) async fn run<H, R>(
        mut self,
        mut stream: SshRead<R>,
        mut handler: H,
    ) -> Result<(), H::Error>
    where
        H: Handler + Send + 'static,
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.flush()?;

        map_err!(self.common.packet_writer.flush_into(&mut stream).await)?;

        let (stream_read, mut stream_write) = stream.split();
        let buffer = SSHBuffer::new();

        // Allow handing out references to the cipher
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

        let keepalive_timer =
            future_or_pending(self.common.config.keepalive_interval, tokio::time::sleep);
        pin!(keepalive_timer);

        let inactivity_timer =
            future_or_pending(self.common.config.inactivity_timeout, tokio::time::sleep);
        pin!(inactivity_timer);

        let reading = start_reading(stream_read, buffer, opening_cipher);
        pin!(reading);
        let mut is_reading = None;

        #[allow(clippy::panic)] // false positive in macro
        while !self.common.disconnected {
            self.common.received_data = false;
            let mut sent_keepalive = false;
            tokio::select! {
                r = &mut reading => {
                    let (stream_read, mut buffer, mut opening_cipher) = match r {
                        Ok((_, stream_read, buffer, opening_cipher)) => (stream_read, buffer, opening_cipher),
                        Err(e) => return Err(e.into())
                    };
                    if buffer.buffer.len() < 5 {
                        is_reading = Some((stream_read, buffer, opening_cipher));
                        break
                    }

                    let mut pkt = self.maybe_decompress(&buffer)?;

                    match pkt.buffer.first() {
                        None => (),
                        Some(&crate::msg::DISCONNECT) => {
                            debug!("break");
                            is_reading = Some((stream_read, buffer, opening_cipher));
                            break;
                        }
                        Some(_) => {
                            self.common.received_data = true;
                            // TODO it'd be cleaner to just pass cipher to reply()
                            std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

                            match reply(&mut self, &mut handler, &mut pkt).await {
                                Ok(_) => {},
                                Err(e) => return Err(e),
                            }
                            buffer.seqn = pkt.seqn; // TODO reply changes seqn internall, find cleaner way

                            std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);
                        }
                    }
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                () = &mut keepalive_timer => {
                    self.common.alive_timeouts = self.common.alive_timeouts.saturating_add(1);
                    if self.common.config.keepalive_max != 0 && self.common.alive_timeouts > self.common.config.keepalive_max {
                        debug!("Timeout, client not responding to keepalives");
                        return Err(crate::Error::KeepaliveTimeout.into());
                    }
                    sent_keepalive = true;
                    self.keepalive_request()?;
                }
                () = &mut inactivity_timer => {
                    debug!("timeout");
                    return Err(crate::Error::InactivityTimeout.into());
                }
                msg = self.receiver.recv(), if !self.kex.active() => {
                    match msg {
                        Some(Msg::Channel(id, ChannelMsg::Data { data })) => {
                            self.data(id, data)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::ExtendedData { ext, data })) => {
                            self.extended_data(id, ext, data)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::Eof)) => {
                            self.eof(id)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::Close)) => {
                            self.close(id)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::Success)) => {
                            self.channel_success(id)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::Failure)) => {
                            self.channel_failure(id)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::XonXoff { client_can_do })) => {
                            self.xon_xoff_request(id, client_can_do)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::ExitStatus { exit_status })) => {
                            self.exit_status_request(id, exit_status)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, lang_tag })) => {
                            self.exit_signal_request(id, signal_name, core_dumped, &error_message, &lang_tag)?;
                        }
                        Some(Msg::Channel(id, ChannelMsg::WindowAdjusted { new_size })) => {
                            debug!("window adjusted to {:?} for channel {:?}", new_size, id);
                        }
                        Some(Msg::ChannelOpenAgent { channel_ref }) => {
                            let id = self.channel_open_agent()?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenSession { channel_ref }) => {
                            let id = self.channel_open_session()?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenDirectTcpIp { host_to_connect, port_to_connect, originator_address, originator_port, channel_ref }) => {
                            let id = self.channel_open_direct_tcpip(&host_to_connect, port_to_connect, &originator_address, originator_port)?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenDirectStreamLocal { socket_path, channel_ref }) => {
                            let id = self.channel_open_direct_streamlocal(&socket_path)?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenForwardedTcpIp { connected_address, connected_port, originator_address, originator_port, channel_ref }) => {
                            let id = self.channel_open_forwarded_tcpip(&connected_address, connected_port, &originator_address, originator_port)?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenForwardedStreamLocal { server_socket_path, channel_ref }) => {
                            let id = self.channel_open_forwarded_streamlocal(&server_socket_path)?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::ChannelOpenX11 { originator_address, originator_port, channel_ref }) => {
                            let id = self.channel_open_x11(&originator_address, originator_port)?;
                            self.channels.insert(id, channel_ref);
                        }
                        Some(Msg::TcpIpForward { address, port, reply_channel }) => {
                            self.tcpip_forward(&address, port, reply_channel)?;
                        }
                        Some(Msg::CancelTcpIpForward { address, port, reply_channel }) => {
                            self.cancel_tcpip_forward(&address, port, reply_channel)?;
                        }
                        Some(Msg::Disconnect {reason, description, language_tag}) => {
                            self.common.disconnect(reason, &description, &language_tag)?;
                        }
                        Some(_) => {
                            // should be unreachable, since the receiver only gets
                            // messages from methods implemented within russh
                            unimplemented!("unimplemented (client-only?) message: {:?}", msg)
                        }
                        None => {
                            debug!("self.receiver: received None");
                        }
                    }
                }
            }
            self.flush()?;

            map_err!(
                self.common
                    .packet_writer
                    .flush_into(&mut stream_write)
                    .await
            )?;

            if self.common.received_data {
                // Reset the number of failed keepalive attempts. We don't
                // bother detecting keepalive response messages specifically
                // (OpenSSH_9.6p1 responds with REQUEST_FAILURE aka 82). Instead
                // we assume that the client is still alive if we receive any
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
        debug!("disconnected");
        // Shutdown
        map_err!(stream_write.shutdown().await)?;
        loop {
            if let Some((stream_read, buffer, opening_cipher)) = is_reading.take() {
                reading.set(start_reading(stream_read, buffer, opening_cipher));
            }
            match (&mut reading).await {
                Ok((0, _, _, _)) => break,
                Ok((_, r, b, opening_cipher)) => {
                    is_reading = Some((r, b, opening_cipher));
                }
                // at this stage of session shutdown, EOF is not unexpected
                Err(Error::IO(ref e)) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Get a handle to this session.
    pub fn handle(&self) -> Handle {
        self.sender.clone()
    }

    pub fn writable_packet_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(channel) {
                return channel
                    .sender_window_size
                    .min(channel.sender_maximum_packet_size);
            }
        }
        0
    }

    pub fn window_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(channel) {
                return channel.sender_window_size;
            }
        }
        0
    }

    pub fn max_packet_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(channel) {
                return channel.sender_maximum_packet_size;
            }
        }
        0
    }

    /// Flush the session, i.e. encrypt the pending buffer.
    pub fn flush(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut self.common.packet_writer,
            )? && self.kex == SessionKexState::Idle
            {
                debug!("starting rekeying");
                if enc.exchange.take().is_some() {
                    self.begin_rekey()?;
                }
            }
        }
        Ok(())
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.flush_pending(channel)
        } else {
            Ok(0)
        }
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(ref enc) = self.common.encrypted {
            enc.sender_window_size(channel)
        } else {
            0
        }
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.has_pending_data(channel)
        } else {
            false
        }
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        &self.common.config
    }

    /// Sends a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.disconnect(reason, description, language_tag)
    }

    /// Sends a debug message to the client.
    ///
    /// Debug messages are intended for debugging purposes and may be
    /// optionally displayed by the client, depending on the
    /// `always_display` flag and client configuration.
    ///
    /// # Parameters
    ///
    /// - `always_display`: If `true`, the client is encouraged to
    ///   display the message regardless of user preferences.
    /// - `message`: The debug message to be sent.
    /// - `language_tag`: The language tag of the message.
    ///
    /// # Notes
    ///
    /// This message is informational and does not affect the SSH session
    /// state. Most clients (e.g., OpenSSH) will only display the message
    /// if verbose mode is enabled.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.debug(always_display, message, language_tag)
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        if self.common.wants_reply {
            if let Some(ref mut enc) = self.common.encrypted {
                self.common.wants_reply = false;
                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
            }
        }
    }

    /// Send a "failure" reply to a global request.
    pub fn request_failure(&mut self) {
        if let Some(ref mut enc) = self.common.encrypted {
            self.common.wants_reply = false;
            push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
        }
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    debug!("channel_success {:?}", channel);
                    push_packet!(enc.write, {
                        msg::CHANNEL_SUCCESS.encode(&mut enc.write)?;
                        channel.recipient_channel.encode(&mut enc.write)?;
                    })
                }
            }
        }
        Ok(())
    }

    /// Send a "failure" reply to a global request.
    pub fn channel_failure(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_FAILURE);
                        channel.recipient_channel.encode(&mut enc.write)?;
                    })
                }
            }
        }
        Ok(())
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                channel.encode(&mut enc.write)?;
                (reason as u32).encode(&mut enc.write)?;
                description.encode(&mut enc.write)?;
                language.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) -> Result<(), Error> {
        self.common.byte(channel, msg::CHANNEL_CLOSE)
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), Error> {
        self.common.byte(channel, msg::CHANNEL_EOF)
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn data(&mut self, channel: ChannelId, data: CryptoVec) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.data(channel, data, self.kex.active())
        } else {
            unreachable!()
        }
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        extended: u32,
        data: CryptoVec,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.extended_data(channel, extended, data, self.kex.active())
        } else {
            unreachable!()
        }
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "xon-xoff".encode(&mut enc.write)?;
                    0u8.encode(&mut enc.write)?;
                    (client_can_do as u8).encode(&mut enc.write)?;
                })
            }
        }
        Ok(())
    }

    /// Ping the client to verify there is still connectivity.
    pub fn keepalive_request(&mut self) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Keepalive);
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                want_reply.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "exit-status".encode(&mut enc.write)?;
                    0u8.encode(&mut enc.write)?;
                    exit_status.encode(&mut enc.write)?;
                })
            }
        }
        Ok(())
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub fn exit_signal_request(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "exit-signal".encode(&mut enc.write)?;
                    0u8.encode(&mut enc.write)?;
                    signal.name().encode(&mut enc.write)?;
                    (core_dumped as u8).encode(&mut enc.write)?;
                    error_message.encode(&mut enc.write)?;
                    language_tag.encode(&mut enc.write)?;
                })
            }
        }
        Ok(())
    }

    /// Opens a new session channel on the client.
    pub fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"session", |_| Ok(()))
    }

    /// Opens a direct-tcpip channel on the client (non-standard).
    pub fn channel_open_direct_tcpip(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-tcpip", |write| {
            host_to_connect.encode(write)?;
            port_to_connect.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    /// Opens a direct-streamlocal channel on the client (non-standard).
    pub fn channel_open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?; // reserved
            0u32.encode(write)?; // reserved
            Ok(())
        })
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_forwarded_tcpip(
        &mut self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-tcpip", |write| {
            connected_address.encode(write)?;
            connected_port.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    pub fn channel_open_forwarded_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?;
            Ok(())
        })
    }

    /// Open a new X11 channel, when a connection comes to a
    /// local port. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.2).
    /// TCP/IP packets can then be tunneled through the channel using `.data()`.
    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"x11", |write| {
            originator_address.encode(write)?;
            originator_port.encode(write)?;
            Ok(())
        })
    }

    /// Opens a new agent channel on the client.
    pub fn channel_open_agent(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"auth-agent@openssh.com", |_| Ok(()))
    }

    fn channel_open_generic<F>(&mut self, kind: &[u8], write_suffix: F) -> Result<ChannelId, Error>
    where
        F: FnOnce(&mut CryptoVec) -> Result<(), Error>,
    {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            if !matches!(
                enc.state,
                EncryptedState::Authenticated | EncryptedState::InitCompression
            ) {
                return Err(Error::Inconsistent);
            }

            let sender_channel = enc.new_channel(
                self.common.config.window_size,
                self.common.config.maximum_packet_size,
            );
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN);
                kind.encode(&mut enc.write)?;

                // sender channel id.
                sender_channel.encode(&mut enc.write)?;

                // window.
                self.common
                    .config
                    .as_ref()
                    .window_size
                    .encode(&mut enc.write)?;

                // max packet size.
                self.common
                    .config
                    .as_ref()
                    .maximum_packet_size
                    .encode(&mut enc.write)?;

                write_suffix(&mut enc.write)?;
            });
            sender_channel
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }

    /// Requests that the client forward connections to the given host and port.
    /// See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The client
    /// will open forwarded_tcpip channels for each connection.
    pub fn tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::TcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                "tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Cancels a previously tcpip_forward request.
    pub fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelTcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "cancel-tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Returns the SSH ID (Protocol Version + Software Version) the client sent when connecting
    ///
    /// This should contain only ASCII characters for implementations conforming to RFC4253, Section 4.2:
    ///
    /// > Both the 'protoversion' and 'softwareversion' strings MUST consist of
    /// > printable US-ASCII characters, with the exception of whitespace
    /// > characters and the minus sign (-).
    ///
    /// So it usually is fine to convert it to a [`String`] using [`String::from_utf8_lossy`]
    pub fn remote_sshid(&self) -> &[u8] {
        &self.common.remote_sshid
    }

    pub(crate) fn maybe_send_ext_info(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            // If client sent a ext-info-c message in the kex list, it supports RFC 8308 extension negotiation.
            let mut key_extension_client = false;
            if let Some(e) = &enc.exchange {
                let Some(mut r) = &e.client_kex_init.as_ref().get(17..) else {
                    return Ok(());
                };
                if let Ok(kex_string) = String::decode(&mut r) {
                    use super::negotiation::Select;
                    key_extension_client = super::negotiation::Server::select(
                        &[EXTENSION_SUPPORT_AS_CLIENT],
                        &parse_kex_algo_list(&kex_string),
                        AlgorithmKind::Kex,
                    )
                    .is_ok();
                }
            }

            if !key_extension_client {
                debug!("RFC 8308 Extension Negotiation not supported by client");
                return Ok(());
            }

            push_packet!(enc.write, {
                msg::EXT_INFO.encode(&mut enc.write)?;
                1u32.encode(&mut enc.write)?;
                "server-sig-algs".encode(&mut enc.write)?;

                NameList(
                    self.common
                        .config
                        .preferred
                        .key
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                )
                .encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    pub(crate) fn begin_rekey(&mut self) -> Result<(), Error> {
        debug!("beginning re-key");
        let mut kex = ServerKex::new(
            self.common.config.clone(),
            &self.common.remote_sshid,
            &self.common.config.server_id,
            match self.common.encrypted {
                None => KexCause::Initial,
                Some(ref enc) => KexCause::Rekey {
                    strict: self.common.strict_kex,
                    session_id: enc.session_id.clone(),
                },
            },
        );

        kex.kexinit(&mut self.common.packet_writer)?;
        self.kex = SessionKexState::InProgress(kex);
        Ok(())
    }
}
