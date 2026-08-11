use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;

use channels::WindowSizeRef;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use kex::ServerKex;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;

use super::*;
use crate::channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf};
use crate::helpers::NameList;
use crate::kex::{EXTENSION_SUPPORT_AS_CLIENT, KexCause, SessionKexState};
use crate::pending_inbound::{
    self, BoxReserve, DeferredCallback, InboundDelivery, InboundItem, InboundQueue,
};
use crate::{ChannelOpenFailure, map_err, msg};


/// A connected server session. This type is unique to a client.
#[derive(Debug)]
pub struct Session {
    pub(crate) common: CommonSession<Arc<Config>>,
    pub(crate) sender: Handle,
    pub(crate) receiver: Receiver<Msg>,
    pub(crate) target_window_size: u32,
    pub(crate) pending_reads: Vec<Vec<u8>>,
    pub(crate) pending_len: u32,
    pub(crate) channels: HashMap<ChannelId, ChannelRef>,
    /// Per-channel inbound backpressure queues (Scheme C). Present only for channels that are
    /// currently backpressured (their app buffer filled up).
    pub(crate) inbound: HashMap<ChannelId, InboundQueue>,
    /// Channels that have a pending item but no in-flight `reserve_owned()` future yet; the run
    /// loop drains this into its `FuturesUnordered` after each inbound batch.
    pub(crate) inbound_needs_reserve: Vec<ChannelId>,
    /// Producers parked in [`Handle::data`] / [`Handle::extended_data`], keyed by the channel
    /// whose backlog they are waiting to drain. Released by `release_outbound_acks` once that
    /// channel's `pending_data` empties; dropped (waking the producer with an error) when the
    /// channel is torn down.
    pub(crate) outbound_acks: HashMap<ChannelId, VecDeque<oneshot::Sender<()>>>,
    pub(crate) open_global_requests: VecDeque<GlobalRequestResponse>,
    pub(crate) kex: SessionKexState<ServerKex>,
    /// Channel-open replies ([`ChannelOpenHandle::accept`]/`reject`) arrive here, NOT on the
    /// bounded `receiver`: handlers run inline on the run loop, so a bounded send from inside
    /// one would deadlock against the loop whenever other channels' writers keep `receiver`
    /// full. Unbounded is safe — at most one reply per peer CHANNEL_OPEN.
    pub(crate) open_reply_tx: tokio::sync::mpsc::UnboundedSender<Msg>,
    pub(crate) open_reply_rx: tokio::sync::mpsc::UnboundedReceiver<Msg>,
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
    /// Channel payload from [`Handle::data`] / [`Handle::extended_data`], carrying a completion
    /// signal that the session fires once the bytes have actually been written into the peer's
    /// receive window (rather than parked in `pending_data`).
    ///
    /// This is what backpressures those two APIs. `Channel::data` / `Channel::make_writer`
    /// reserve window *before* enqueueing and so need no such signal; `Handle` has no per-channel
    /// window state, so without this it would enqueue without bound. Upstream instead throttled
    /// it by refusing to dispatch any application message while any channel had pending data,
    /// which backpressures every channel because one is blocked — see `enforce_outbound_cap`.
    ChannelDataAcked {
        id: ChannelId,
        ext: Option<u32>,
        data: Bytes,
        ack: oneshot::Sender<()>,
    },
    ChannelOpenReply {
        pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    },
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

pub use crate::PendingChannelOpen;

/// A handle passed to channel-open callbacks that the handler uses to
/// accept or reject the incoming channel request.
///
/// Dropping the handle without calling [`accept`](ChannelOpenHandle::accept) or
/// [`reject`](ChannelOpenHandle::reject) automatically sends an
/// `AdministrativelyProhibited` rejection to the client.
pub type ChannelOpenHandle = crate::ChannelOpenHandleInner<Msg>;

#[derive(Clone, Debug)]
/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle {
    pub(crate) sender: Sender<Msg>,
    pub(crate) channel_buffer_size: usize,
}

impl Handle {
    /// Send data to the session referenced by this handler.
    ///
    /// Applies per-channel backpressure: the returned future resolves only once the bytes have
    /// been written into the peer's receive window, so a peer that stops reading throttles this
    /// channel's producer without affecting any other channel. Returns `Err` if the channel is
    /// gone (the payload is returned when it was never handed over).
    ///
    /// Do not call this from inside a [`Handler`] callback — those run on the session loop, so
    /// awaiting window there would prevent the loop from ever processing the window adjustment
    /// that would release it. Use a spawned task, as the examples do.
    pub async fn data(
        &self,
        id: ChannelId,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        self.send_acked(id, None, data.into()).await
    }

    /// Send data to the session referenced by this handler.
    ///
    /// Backpressures per channel exactly like [`Handle::data`]; the same "not from a `Handler`
    /// callback" caveat applies.
    pub async fn extended_data(
        &self,
        id: ChannelId,
        ext: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        self.send_acked(id, Some(ext), data.into()).await
    }

    async fn send_acked(
        &self,
        id: ChannelId,
        ext: Option<u32>,
        data: bytes::Bytes,
    ) -> Result<(), bytes::Bytes> {
        let (ack, acked) = oneshot::channel();
        self.sender
            .send(Msg::ChannelDataAcked {
                id,
                ext,
                data,
                ack,
            })
            .await
            .map_err(|e| match e.0 {
                Msg::ChannelDataAcked { data, .. } => data,
                _ => unreachable!(),
            })?;
        // Resolves when the bytes reach the peer's window; errors if the channel was torn down
        // first, in which case the payload is already owned by the session and cannot be handed
        // back.
        acked.await.map_err(|_| bytes::Bytes::new())
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
                    return Err(Error::ChannelOpenFailure(reason));
                }
                None => {
                    return Err(Error::Disconnect);
                }
                msg => {
                    debug!("msg = {msg:?}");
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
    /// Deliver one inbound [`InboundItem`] to a channel's application buffer without ever blocking
    /// the shared session loop (Scheme C). Fast path uses `try_send`; on `Full` the channel becomes
    /// backpressured and the item is queued behind a single in-flight `reserve_owned()` future.
    pub(crate) fn deliver_inbound(&mut self, id: ChannelId, item: InboundItem) -> InboundDelivery {
        pending_inbound::deliver_inbound(
            &self.channels,
            &mut self.inbound,
            &mut self.inbound_needs_reserve,
            self.common.config.max_pending_inbound_bytes,
            id,
            item,
        )
    }

    /// For each channel flagged in `inbound_needs_reserve`, register a single `reserve_owned()`
    /// future (tagged with the current generation) into the run loop's `FuturesUnordered`.
    pub(crate) fn drain_needs_reserve(&mut self, reserves: &mut FuturesUnordered<BoxReserve>) {
        pending_inbound::drain_needs_reserve(
            &self.channels,
            &mut self.inbound,
            &mut self.inbound_needs_reserve,
            reserves,
        );
    }

    /// Resolve one completed `reserve_owned()` future: deliver the head item into the application
    /// buffer, grant window (I2) if it was payload, fire the item's handler callback **after**
    /// delivery (so a custom `Handler` never observes data before it reaches the channel buffer —
    /// matching the fast path), finalize a delivered `Close`, and re-arm the next reserve.
    pub(crate) async fn pump_inbound<H: Handler>(
        &mut self,
        id: ChannelId,
        generation: u64,
        res: Result<tokio::sync::mpsc::OwnedPermit<ChannelMsg>, ()>,
        handler: &mut H,
    ) -> Result<(), H::Error> {
        {
            let q = match self.inbound.get_mut(&id) {
                Some(q) => q,
                None => return Ok(()),
            };
            if generation != q.generation {
                // Stale result for a torn-down channel; drop it.
                return Ok(());
            }
            q.reserving = false;
        }

        let permit = match res {
            Ok(p) => p,
            Err(()) => {
                // Application dropped its receiver while we were reserving. If the peer's
                // `Close` is sitting in the queue, its teardown was deferred onto delivery —
                // and delivery can no longer happen. Dropping the queue alone would drop that
                // deferred teardown with it: `handler.channel_close` never fires and the
                // `self.channels` entry (whose enc-side twin was already removed when the
                // CLOSE arrived) leaks for the life of the session. Finalize now instead.
                let close_queued = self
                    .inbound
                    .get(&id)
                    .is_some_and(|q| q.close_queued);
                if close_queued {
                    handler.channel_close(id, self).await?;
                    self.finalize_close(id);
                } else {
                    self.teardown_inbound_channel(id);
                }
                return Ok(());
            }
        };

        let item = match self
            .inbound
            .get_mut(&id)
            .and_then(|q| q.queue.pop_front())
        {
            Some(item) => item,
            None => return Ok(()),
        };
        if let Some(q) = self.inbound.get_mut(&id) {
            q.pending_bytes = q.pending_bytes.saturating_sub(item.byte_len());
        }
        let grants = item.grants_window();
        // Capture the deferred handler-callback payload before the item is consumed (cheap Bytes
        // clone). The callback is fired below, after the data is in the application buffer.
        let callback = DeferredCallback::capture(&item);
        permit.send(item.into_msg());

        if grants {
            self.maybe_grant_after_delivery(id, handler)?;
        }

        match callback {
            DeferredCallback::Data(data) => handler.data(id, &data, self).await?,
            DeferredCallback::ExtendedData { ext, data } => {
                handler.extended_data(id, ext, &data, self).await?
            }
            DeferredCallback::Eof => handler.channel_eof(id, self).await?,
            DeferredCallback::Close => {
                handler.channel_close(id, self).await?;
                self.finalize_close(id);
                return Ok(());
            }
        }

        let more = self
            .inbound
            .get(&id)
            .map(|q| !q.queue.is_empty())
            .unwrap_or(false);
        if more {
            if let Some(q) = self.inbound.get_mut(&id) {
                q.reserving = true;
            }
            self.inbound_needs_reserve.push(id);
        } else {
            // Drained: return the channel to the flowing fast path.
            self.inbound.remove(&id);
        }
        Ok(())
    }

    /// I2: grant more inbound receive window for a channel after its data was accepted into the
    /// application buffer. Only granted at delivery time, so a backpressured channel withholds its
    /// own grant (per-channel backpressure replacing the removed blocking `.await`).
    pub(crate) fn maybe_grant_after_delivery<H: Handler>(
        &mut self,
        id: ChannelId,
        handler: &mut H,
    ) -> Result<(), crate::Error> {
        let target = self.target_window_size;
        // Bytes still queued undelivered for this channel keep occupying its advertised window;
        // only the portion already handed to the application may be re-granted. Callers reach
        // here after `pending_bytes` has been decremented for the item just delivered, so this is
        // exactly the still-outstanding backlog.
        let undelivered = self
            .inbound
            .get(&id)
            .map(|q| q.pending_bytes)
            .unwrap_or(0)
            .try_into()
            .unwrap_or(u32::MAX);
        let granted = self
            .common
            .encrypted
            .as_mut()
            .map(|enc| enc.maybe_grant_recv_window(id, target, undelivered))
            .transpose()?
            .unwrap_or(false);
        if granted {
            let w = handler.adjust_window(id, self.target_window_size);
            if w > 0 {
                self.target_window_size = w;
            }
        }
        Ok(())
    }

    /// Release producers parked in [`Handle::data`] for any channel whose outbound backlog has
    /// drained. Cheap: only channels with parked producers are examined.
    pub(crate) fn release_outbound_acks(&mut self) {
        if self.outbound_acks.is_empty() {
            return;
        }
        let Some(enc) = self.common.encrypted.as_ref() else {
            return;
        };
        // Reaching here with no pending data means the backlog went out on the wire: either the
        // channel drained and is still open, or it drained and was then removed by an orderly
        // `flush_pending` -> `pending_close`. Both delivered. Channels whose backlog was
        // *discarded* never appear here — `discard_channel_outbound` already took their acks.
        let drained: Vec<ChannelId> = self
            .outbound_acks
            .keys()
            .copied()
            .filter(|id| !enc.has_pending_data(*id))
            .collect();
        for id in drained {
            if let Some(acks) = self.outbound_acks.remove(&id) {
                for ack in acks {
                    let _ = ack.send(());
                }
            }
        }
    }

    /// Outbound mirror of the inbound `Overflow` path: bound how much un-transmitted data a
    /// single channel may accumulate while its peer's receive window is exhausted, and close that
    /// one channel if it runs away.
    ///
    /// This replaces upstream's session-wide `has_any_pending_data()` gate. That gate bounded the
    /// backlog by refusing to dispatch *any* application message while *any* channel had pending
    /// data, which is correct on memory but converts one stalled peer into a session-wide
    /// outbound stall. Capping per channel keeps the isolation property the inbound path already
    /// has: a runaway channel is dropped, everyone else keeps flowing.
    ///
    /// Producers that reserve window before enqueueing (`Channel::data` / `make_writer`) cannot
    /// exceed their window and so never reach the cap; it is `Handle::data` and
    /// `Handle::extended_data`, which enqueue unconditionally, that this contains.
    /// Tear a channel down on the wire, discarding everything still queued for it, and fail any
    /// producers parked on that backlog.
    ///
    /// Keeping these two together is the point: the bytes are being thrown away, so the parked
    /// `Handle::data` callers must resolve to `Err`. Inferring that later from "is the channel
    /// gone?" cannot work — a channel is also removed after an *orderly* flush, where the bytes
    /// really were delivered.
    pub(crate) fn discard_channel_outbound(&mut self, id: ChannelId) -> Result<(), crate::Error> {
        if let Some(enc) = self.common.encrypted.as_mut() {
            enc.close_discarding_pending(id)?;
        }
        // Dropping the senders resolves each producer's await to Err.
        self.outbound_acks.remove(&id);
        Ok(())
    }

    pub(crate) fn enforce_outbound_cap(&mut self, id: ChannelId) -> Result<(), crate::Error> {
        let cap = self.common.config.max_pending_outbound_bytes;
        let Some(enc) = self.common.encrypted.as_mut() else {
            return Ok(());
        };
        if enc.pending_data_bytes(id) <= cap {
            return Ok(());
        }
        log::warn!(
            "outbound pending cap exceeded for channel {id:?}; closing channel (peer window stalled and producer bypassed window accounting)"
        );
        self.discard_channel_outbound(id)?;
        self.finalize_close(id);
        Ok(())
    }

    /// Deferred CHANNEL_CLOSE teardown: only run once the queued `Close` has actually been
    /// delivered, so queued data ahead of it is never dropped. Bumps the generation so any
    /// late-resolving reserve future is recognised as stale.
    pub(crate) fn finalize_close(&mut self, id: ChannelId) {
        if let Some(q) = self.inbound.get_mut(&id) {
            q.generation = q.generation.wrapping_add(1);
        }
        self.inbound.remove(&id);
        self.channels.remove(&id);
        // Dropping any parked `Handle::data` producers wakes them with an error, which is the
        // correct signal now that the channel is gone.
        self.outbound_acks.remove(&id);
        if let Some(enc) = self.common.encrypted.as_mut() {
            // Safe to drop unconditionally: every path that reaches `finalize_close` has already
            // emitted the peer's `CHANNEL_CLOSE` reply via `close_discarding_pending`, so there
            // is never a parked `pending_close` left to lose here.
            enc.channels.remove(&id);
        }
    }

    /// Tear down a channel's inbound queue when its application receiver was dropped mid-flight.
    /// Bumps the generation so a stale reserve result is ignored.
    pub(crate) fn teardown_inbound_channel(&mut self, id: ChannelId) {
        pending_inbound::teardown_inbound(&mut self.inbound, id);
    }

    fn maybe_decompress(&mut self, buffer: &SSHBuffer) -> Result<IncomingSshPacket, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let mut decomp = Vec::new();
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

    /// Apply every queued channel-open reply. Must run before dispatching any `receiver`
    /// message: a writer's first `Data` for a channel is enqueued strictly after `accept()`
    /// queued that channel's reply, so finalizing replies first guarantees no `Data` is ever
    /// dispatched against a channel that is not yet registered (such data would be silently
    /// discarded, since the channel maps have no entry to route it to).
    fn drain_open_replies(&mut self) -> Result<(), Error> {
        while let Ok(msg) = self.open_reply_rx.try_recv() {
            if let Msg::ChannelOpenReply { pending, result } = msg {
                self.finalize_channel_open_reply(pending, result)?;
            }
        }
        Ok(())
    }

    /// Dispatch a single message received on the session's internal channel
    /// (sent via [`Handle`]). Shared by the `select!` receiver arm and the
    /// pre-`select!` backlog drain so the two can't drift apart.
    fn dispatch_msg(&mut self, msg: Msg) -> Result<(), Error> {
        self.drain_open_replies()?;
        match msg {
            Msg::Channel(id, ChannelMsg::Data { data }) => {
                self.data(id, data)?;
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { ext, data }) => {
                self.extended_data(id, ext, data)?;
            }
            Msg::ChannelDataAcked { id, ext, data, ack } => {
                match ext {
                    None => self.data(id, data)?,
                    Some(ext) => self.extended_data(id, ext, data)?,
                }
                let (exists, pending) = self
                    .common
                    .encrypted
                    .as_ref()
                    .map(|enc| (enc.channel_exists(id), enc.has_pending_data(id)))
                    .unwrap_or((false, false));
                if !exists {
                    // The channel was torn down while this message sat in the session queue, so
                    // `Encrypted::data` silently discarded the payload. Drop the ack rather than
                    // reporting success for bytes that never reached the peer.
                } else if pending {
                    // Park until this channel's backlog drains, so `Handle::data` is throttled to
                    // the rate the peer grants window — without stalling any other channel.
                    self.outbound_acks.entry(id).or_default().push_back(ack);
                } else {
                    // Fully absorbed by the peer's window.
                    let _ = ack.send(());
                }
            }
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id)?;
            }
            Msg::Channel(id, ChannelMsg::Close) => {
                self.close(id)?;
            }
            Msg::Channel(id, ChannelMsg::Success) => {
                self.channel_success(id)?;
            }
            Msg::Channel(id, ChannelMsg::Failure) => {
                self.channel_failure(id)?;
            }
            Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }) => {
                self.xon_xoff_request(id, client_can_do)?;
            }
            Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }) => {
                self.exit_status_request(id, exit_status)?;
            }
            Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ) => {
                self.exit_signal_request(id, signal_name, core_dumped, &error_message, &lang_tag)?;
            }
            Msg::Channel(id, ChannelMsg::WindowAdjusted { new_size }) => {
                debug!("window adjusted to {new_size:?} for channel {id:?}");
            }
            Msg::ChannelOpenAgent { channel_ref } => {
                let id = self.channel_open_agent()?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenSession { channel_ref } => {
                let id = self.channel_open_session()?;
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
            Msg::ChannelOpenForwardedTcpIp {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_forwarded_tcpip(
                    &connected_address,
                    connected_port,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path,
                channel_ref,
            } => {
                let id = self.channel_open_forwarded_streamlocal(&server_socket_path)?;
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
            Msg::TcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::CancelTcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.cancel_tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => {
                self.common.disconnect(reason, &description, &language_tag)?;
            }
            other => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (client-only?) message: {other:?}")
            }
        }
        Ok(())
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

        // Scheme C: in-flight `reserve_owned()` futures for backpressured channels. Kept local to
        // the run loop (not on `Session`, which must stay `Debug`). Each resolution delivers one
        // queued inbound item without the loop ever blocking on a single channel's slow consumer.
        let mut inbound_reserves: FuturesUnordered<BoxReserve> = FuturesUnordered::new();

        #[allow(clippy::panic)] // false positive in macro
        while !self.common.disconnected {
            self.common.received_data = false;
            let mut sent_keepalive = false;

            // Drain messages already queued on the session channel (e.g. shell
            // output pushed via `Handle::data()` from a spawned task) before
            // blocking in `select!`. `select!` only handles one queued message
            // per loop iteration, so a task producing faster than the loop
            // drains falls behind. Capped so high-rate output can't starve
            // client input (Ctrl+C, resize): once the cap is hit we fall through
            // to `select!`, which picks up any client-side event first. Gated on
            // `!kex.active()` to match the `select!` receiver arm.
            const MAX_MESSAGES_PER_BATCH: usize = 64;
            // NB: deliberately *not* gated on `has_any_pending_data()` (upstream de96ad1).
            // That check is session-wide, so a single channel whose peer stopped reading —
            // leaving its window exhausted and its `pending_data` non-empty — would halt this
            // drain and the `select!` receiver arm for *every* channel, and only a
            // CHANNEL_WINDOW_ADJUST from that one stalled peer could restart them. A peer that
            // never adjusts (or a rekey, which forces all outbound data into `pending_data`)
            // therefore stalled the whole session's outbound path. Per-channel isolation is
            // enforced by `enforce_outbound_cap` below instead.
            //
            // The high-watermark gate pairs with the concurrent flush arm in `select!`: bytes
            // now leave via that arm while the loop keeps reading, so intake of new outbound
            // work must pause once too much is already buffered, or a slow-draining peer would
            // grow the write buffer without bound.
            let can_receive_outbound = !self.kex.active()
                && self.common.packet_writer.pending_bytes()
                    < crate::sshbuffer::OUTBOUND_HIGH_WATERMARK;
            if can_receive_outbound {
                let mut drained = 0;
                while drained < MAX_MESSAGES_PER_BATCH {
                    // Only Empty/Disconnected end the drain; both mean "nothing
                    // more to hand off right now", so treat them the same.
                    let Ok(msg) = self.receiver.try_recv() else {
                        break;
                    };
                    self.dispatch_msg(msg)?;
                    drained += 1;
                }
                if drained > 0 {
                    self.flush()?;
                }
                // A drained Disconnect sets this; don't block in `select!` after.
                if self.common.disconnected {
                    continue;
                }
            }

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
                            // Register reserve futures for any channels that became backpressured
                            // while handling this packet (their app buffer filled up).
                            self.drain_needs_reserve(&mut inbound_reserves);
                            buffer.seqn = pkt.seqn; // TODO reply changes seqn internall, find cleaner way

                            std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);
                        }
                    }
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                Some((cid, generation, res)) = inbound_reserves.next(), if !inbound_reserves.is_empty() && !self.kex.active() => {
                    // A backpressured channel's application buffer freed a slot: deliver its head
                    // item and re-arm. The grant for that channel is emitted into `self.write` and
                    // goes out via the flush below — never blocking the loop on this channel.
                    self.pump_inbound(cid, generation, res, &mut handler).await?;
                    self.drain_needs_reserve(&mut inbound_reserves);
                }
                // Channel-open replies from handlers that stashed the `ChannelOpenHandle` and
                // accepted/rejected later from a spawned task. Same kex gate as the `receiver`
                // arm: no packets may be written mid-rekey.
                Some(msg) = self.open_reply_rx.recv(), if !self.kex.active() => {
                    if let Msg::ChannelOpenReply { pending, result } = msg {
                        self.finalize_channel_open_reply(pending, result)?;
                    }
                    self.drain_open_replies()?;
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
                // Concurrent outbound flush: pushes pending bytes while the loop stays free to
                // read, run timers, and take other arms. Cancel-safe (cursor lives in the
                // writer), so losing the race to another arm never loses write progress. This
                // is the arm that breaks the full-duplex stall where our blocked write used to
                // stop our reads, starving the peer whose reads would have unblocked our write.
                r = self.common.packet_writer.flush_into(&mut stream_write), if self.common.packet_writer.has_pending() => {
                    map_err!(r)?;
                }
                // See the batch-drain comment above: gating this arm on `has_any_pending_data()`
                // would let one stalled channel block outbound progress for all of them.
                msg = self.receiver.recv(), if can_receive_outbound => {
                    match msg {
                        Some(msg) => self.dispatch_msg(msg)?,
                        None => {
                            debug!("self.receiver: received None");
                        }
                    }
                }
            }
            // Stage whatever this iteration produced; the concurrent flush arm above writes it
            // out next time around without blocking the loop.
            self.flush()?;
            self.release_outbound_acks();

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
        // Shutdown. Try to flush anything still buffered (e.g. our DISCONNECT) before closing
        // the write half — the in-loop flush arm no longer guarantees an empty buffer at exit.
        // Best-effort with a deadline: the peer may be gone (write errors) or may have stopped
        // reading entirely (write blocks); neither may fail or hang the teardown.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.common.packet_writer.flush_into(&mut stream_write),
        )
        .await;
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
                    debug!("channel_success {channel:?}");
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

    fn finalize_channel_open_reply(
        &mut self,
        pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            match result {
                Ok(()) => {
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_CONFIRMATION.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        pending.sender_channel.0.encode(&mut enc.write)?;
                        pending.window_size.encode(&mut enc.write)?;
                        pending.packet_size.encode(&mut enc.write)?;
                    });
                    enc.channels
                        .insert(pending.sender_channel, pending.channel_params);
                    self.channels
                        .insert(pending.sender_channel, pending.channel_ref);
                }
                Err(reason) => {
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_FAILURE.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        reason.code().encode(&mut enc.write)?;
                        reason.description().encode(&mut enc.write)?;
                        "en".encode(&mut enc.write)?;
                    });
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
                reason.code().encode(&mut enc.write)?;
                description.encode(&mut enc.write)?;
                language.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) -> Result<(), Error> {
        let emitted = if let Some(ref mut enc) = self.common.encrypted {
            enc.close(channel)?;
            // `Encrypted::close` drops the protocol entry only when it actually wrote
            // CHANNEL_CLOSE; otherwise it parked as `pending_close` behind queued data.
            !enc.channel_exists(channel)
        } else {
            unreachable!()
        };
        if emitted {
            // The close is on the wire and the peer owes only its mandatory reply. If nothing is
            // reading this channel any more — the dominant path, since dropping a `Channel` is
            // what sent the close — release the application-side state now rather than waiting
            // for that reply, which a broken or hostile peer may never send. If the application
            // still holds the read half it may legitimately keep receiving until the peer's
            // close, so teardown is left to the CHANNEL_CLOSE handler in that case.
            let reader_gone = self
                .channels
                .get(&channel)
                .is_some_and(|c| std::ops::Deref::deref(c).is_closed());
            if reader_gone {
                self.finalize_close(channel);
            }
        }
        Ok(())
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.eof(channel)
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
    pub fn data(&mut self, channel: ChannelId, data: impl Into<bytes::Bytes>) -> Result<(), Error> {
        let is_rekeying = self.kex.active();
        let common = &mut self.common;
        if let Some(enc) = common.encrypted.as_mut() {
            enc.data_with_writer(&mut common.packet_writer, channel, data, is_rekeying)?;
        } else {
            unreachable!()
        }
        // Enforce here rather than at the run loop's dispatch sites: this is the single point
        // where a channel's outbound backlog grows, and `Handler` callbacks call it directly
        // while the loop is inside `reply()` — a path no dispatch-site check can see.
        self.enforce_outbound_cap(channel)
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
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), Error> {
        let is_rekeying = self.kex.active();
        let common = &mut self.common;
        if let Some(enc) = common.encrypted.as_mut() {
            enc.extended_data_with_writer(
                &mut common.packet_writer,
                channel,
                extended,
                data,
                is_rekeying,
            )?;
        } else {
            unreachable!()
        }
        // See `Session::data`: enforced here so `Handler`-callback writes are covered too.
        self.enforce_outbound_cap(channel)
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

    /// Ping the client with a Keepalive and get a notification when the client responds.
    pub fn send_ping(&mut self, reply_channel: oneshot::Sender<()>) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Ping(reply_channel));
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
        F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
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
                let Some(mut r) = e.client_kex_init.get(17..) else {
                    return Ok(());
                };
                if let Ok(kex_list) = NameList::decode(&mut r) {
                    use super::negotiation::Select;
                    key_extension_client = super::negotiation::Server::select(
                        &[EXTENSION_SUPPORT_AS_CLIENT],
                        &kex_list,
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

#[cfg(all(test, feature = "flate2"))]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::io::Write;
    use std::num::Wrapping;
    use std::sync::Arc;

    use super::*;
    use crate::compression::{Compression, Decompress};
    use crate::kex::{KEXES, NONE, SessionKexState};
    use crate::session::{CommonSession, Encrypted, EncryptedState, Exchange};
    use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer};
    use crate::{CryptoVec, cipher, mac};

    struct TestHandler;

    impl crate::server::Handler for TestHandler {
        type Error = crate::Error;
    }

    fn authenticated_session() -> Session {
        authenticated_session_with(crate::server::Config::default())
    }

    fn authenticated_session_with(config: crate::server::Config) -> Session {
        let config = Arc::new(config);
        let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
        let (open_reply_tx, open_reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = Handle {
            sender,
            channel_buffer_size: config.channel_buffer_size,
        };

        Session {
            common: CommonSession {
                auth_user: String::new(),
                remote_sshid: b"SSH-2.0-test".to_vec(),
                config: config.clone(),
                encrypted: Some(Encrypted {
                    state: EncryptedState::Authenticated,
                    exchange: Some(Exchange::default()),
                    kex: KEXES.get(&NONE).unwrap().make(),
                    key: 0,
                    client_mac: mac::NONE,
                    server_mac: mac::NONE,
                    session_id: CryptoVec::new(),
                    channels: HashMap::new(),
                    last_channel_id: Wrapping(0),
                    write: Vec::new(),
                    write_cursor: 0,
                    last_rekey: russh_util::time::Instant::now(),
                    server_compression: Compression::None,
                    client_compression: Compression::None,
                    decompress: Decompress::Zlib(flate2::Decompress::new(true)),
                    rekey_wanted: false,
                    received_extensions: Vec::new(),
                    extension_info_awaiters: HashMap::new(),
                }),
                auth_method: None,
                auth_attempts: 0,
                packet_writer: PacketWriter::clear(),
                remote_to_local: Box::new(cipher::clear::Key),
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
            },
            sender: handle,
            receiver,
            target_window_size: config.window_size,
            pending_reads: Vec::new(),
            pending_len: 0,
            channels: HashMap::new(),
            inbound: HashMap::new(),
            inbound_needs_reserve: Vec::new(),
            outbound_acks: std::collections::HashMap::new(),
            open_global_requests: VecDeque::new(),
            kex: SessionKexState::Idle,
            open_reply_tx,
            open_reply_rx,
        }
    }

    fn compressed_debug_payload(payload_len: usize) -> Vec<u8> {
        let mut payload = vec![b'A'; payload_len];
        payload[0] = crate::msg::DEBUG;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 256 * 1024);
        compressed
    }

    fn incoming_packet(compressed: Vec<u8>) -> SSHBuffer {
        let mut buffer = SSHBuffer::new();
        buffer.buffer.extend_from_slice(&[0; 5]);
        buffer.buffer.extend_from_slice(&compressed);
        buffer
    }

    #[tokio::test]
    async fn compressed_debug_is_ignored_after_server_parses_it() {
        let mut session = authenticated_session();
        let mut handler = TestHandler;
        let buffer = incoming_packet(compressed_debug_payload(200 * 1024));
        let mut pkt: IncomingSshPacket = session.maybe_decompress(&buffer).unwrap();

        super::super::reply(&mut session, &mut handler, &mut pkt)
            .await
            .unwrap();

        assert!(!session.common.disconnected);
    }

    #[test]
    fn oversized_compressed_debug_is_rejected_before_server_ignores_it() {
        let mut session = authenticated_session();
        let buffer = incoming_packet(compressed_debug_payload(
            crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024,
        ));

        let err = session.maybe_decompress(&buffer).unwrap_err();
        assert!(
            matches!(err, crate::Error::PacketSize(len) if len > crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN)
        );
    }

    // ----- RC2 inbound head-of-line-blocking fix (Scheme C) -----

    use bytes::Bytes;

    /// Insert a channel whose application buffer holds `buf` messages, returning a spare sender
    /// clone (for minting reserve permits) and the receiver (to drain the buffer).
    fn insert_test_channel(
        session: &mut Session,
        id: ChannelId,
        buf: usize,
    ) -> (
        tokio::sync::mpsc::Sender<ChannelMsg>,
        tokio::sync::mpsc::Receiver<ChannelMsg>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel::<ChannelMsg>(buf);
        session.channels.insert(id, ChannelRef::new(tx.clone()));
        (tx, rx)
    }

    /// Register a channel in the encrypted state (its inbound window starts at `window`) so
    /// window accounting has something to act on. Returns the allocated id.
    fn insert_encrypted_channel(session: &mut Session, window: u32) -> ChannelId {
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .new_channel(window, 32768)
    }

    /// Confirm a test channel with a zero peer window, so anything written queues as
    /// `pending_data` (writes require `confirmed`).
    fn confirm_test_channel(session: &mut Session, id: ChannelId, peer_window: u32) {
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .channels
            .get_mut(&id)
            .unwrap()
            .confirm(&crate::parsing::ChannelOpenConfirmation {
                recipient_channel: 0,
                sender_channel: 0,
                initial_window_size: peer_window,
                maximum_packet_size: 32768,
            });
    }

    /// Server-initiated close: `Encrypted::close` removes the protocol entry immediately, so
    /// the peer's mandatory CHANNEL_CLOSE reply fails `is_established_channel`. Before the fix
    /// the reply was simply ignored, leaving the `self.channels` entry registered forever —
    /// a per-closed-channel leak on any long-lived connection that churns channels.
    #[tokio::test]
    async fn server_initiated_close_is_cleaned_up_by_peer_reply() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        // We close first: protocol entry goes away, application entry stays.
        session.close(id).unwrap();
        assert!(!session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .channel_exists(id));
        assert!(
            session.channels.contains_key(&id),
            "precondition: app-side entry outlives our own close"
        );

        // The peer's reply must complete the teardown rather than being dropped by the guard.
        let mut handler = TestHandler;
        let mut pkt = Vec::new();
        pkt.push(crate::msg::CHANNEL_CLOSE);
        pkt.extend_from_slice(&id.0.to_be_bytes());
        session
            .server_read_authenticated(&mut handler, crate::msg::CHANNEL_CLOSE, &mut &pkt[1..])
            .await
            .unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "peer's close reply must release the application-side channel entry"
        );
    }

    /// The leak must not depend on the peer behaving: once our CHANNEL_CLOSE is on the wire and
    /// nothing is reading the channel any more, the application-side entry is released
    /// immediately rather than waiting for a mandatory reply a broken or hostile peer may never
    /// send.
    #[tokio::test]
    async fn server_initiated_close_releases_state_without_peer_reply() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, rx) = insert_test_channel(&mut session, id, 8);

        // Nothing is reading any more — this is what dropping a `Channel` looks like.
        drop(rx);

        session.close(id).unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "state must be released without waiting on the peer"
        );
    }

    /// ...but an application that closed the write side while still reading keeps its channel,
    /// since it may legitimately receive until the peer's own close arrives.
    #[tokio::test]
    async fn server_initiated_close_keeps_state_while_app_still_reads() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);
        confirm_test_channel(&mut session, id, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        session.close(id).unwrap();

        assert!(
            session.channels.contains_key(&id),
            "a live reader must not have its channel torn out from under it"
        );
    }

    /// D6: a `Handler` callback writes through `Session::data` directly, never through the run
    /// loop's message dispatch. Enforcing the outbound cap only at the dispatch sites left that
    /// path completely unbounded — an echo-style handler against a zero peer window could grow
    /// `pending_data` without limit. The cap must be applied at the write itself.
    #[tokio::test]
    async fn handler_side_writes_are_capped() {
        let mut config = crate::server::Config::default();
        config.max_pending_outbound_bytes = 4096;
        let mut session = authenticated_session_with(config);
        let id = insert_encrypted_channel(&mut session, 0);
        confirm_test_channel(&mut session, id, 0);

        // Peer window is 0, so every write lands in pending_data — exactly the handler-echo
        // shape. No run-loop dispatch is involved.
        for _ in 0..8 {
            if session
                .common
                .encrypted
                .as_ref()
                .is_some_and(|enc| enc.channel_exists(id))
            {
                session.data(id, Bytes::from_static(&[0u8; 1024])).unwrap();
            }
        }

        assert!(
            !session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channel_exists(id),
            "handler-side writes must hit the outbound cap and close the runaway channel"
        );
    }

    /// A window grant must never re-authorise the peer for bytes that are off the wire but still
    /// queued undelivered. Topping straight back up to `target` did exactly that: one delivered
    /// item released credit for the whole backlog, so a *compliant* peer could keep refilling the
    /// queue until `max_pending_inbound_bytes` tripped and its channel was closed as a protocol
    /// violation.
    #[tokio::test]
    async fn window_grant_excludes_undelivered_backlog() {
        let mut session = authenticated_session();
        let target = session.target_window_size;
        let id = insert_encrypted_channel(&mut session, target);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        // Peer spends its whole window; only a small part has reached the application.
        let undelivered = target / 2;
        {
            let enc = session.common.encrypted.as_mut().unwrap();
            enc.consume_recv_window(id, target as usize);
            assert_eq!(enc.sender_window_size(id), 0);
        }
        session.inbound.entry(id).or_default().pending_bytes = undelivered as usize;

        let mut handler = TestHandler;
        session.maybe_grant_after_delivery(id, &mut handler).unwrap();

        // The advertised window may cover only what the application actually consumed.
        let enc = session.common.encrypted.as_ref().unwrap();
        assert_eq!(
            enc.sender_window_size(id),
            (target - undelivered) as usize,
            "grant must leave the undelivered backlog occupying the window"
        );
    }

    /// With nothing queued the grant still tops all the way back up to `target`, so the fix above
    /// costs nothing on the steady-state fast path.
    #[tokio::test]
    async fn window_grant_restores_full_target_when_drained() {
        let mut session = authenticated_session();
        let target = session.target_window_size;
        let id = insert_encrypted_channel(&mut session, target);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .consume_recv_window(id, target as usize);

        let mut handler = TestHandler;
        session.maybe_grant_after_delivery(id, &mut handler).unwrap();

        assert_eq!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .sender_window_size(id),
            target as usize
        );
    }

    /// A producer parked in `Handle::data` whose channel is torn down (peer close / inbound
    /// overflow both discard the outbound backlog) must be woken with an **error**. Reporting
    /// success would tell the caller its bytes were sent when they were thrown away — and
    /// `has_pending_data` alone cannot tell "gone" from "drained", since it returns false for
    /// both.
    #[tokio::test]
    async fn discarded_producer_is_woken_with_error_not_success() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 0);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        // Channel torn down with its backlog discarded, exactly as peer-close does.
        session.discard_channel_outbound(id).unwrap();

        session.release_outbound_acks();

        assert!(
            acked.await.is_err(),
            "discarded data must not be reported as delivered"
        );
    }

    /// Regression for the opposite error: a channel removed by an *orderly* flush+close
    /// delivered its bytes, so its parked producer must be told `Ok`. Inferring failure from
    /// "channel is gone" reported `Err` for data that really was sent.
    #[tokio::test]
    async fn producer_is_woken_with_success_after_orderly_flush_and_close() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        // Orderly close after the backlog drained: `Encrypted::close` emits and removes the
        // channel, so it is gone but everything was delivered.
        session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .close(id)
            .unwrap();
        assert!(!session
            .common
            .encrypted
            .as_ref()
            .unwrap()
            .channel_exists(id));

        session.release_outbound_acks();

        assert!(
            acked.await.is_ok(),
            "delivered data must not be reported as failed"
        );
    }

    /// The ordinary path still reports success: channel alive, backlog drained.
    #[tokio::test]
    async fn drained_producer_is_woken_with_success() {
        let mut session = authenticated_session();
        let id = insert_encrypted_channel(&mut session, 1024);

        let (ack, acked) = oneshot::channel();
        session.outbound_acks.entry(id).or_default().push_back(ack);

        session.release_outbound_acks();

        assert!(acked.await.is_ok());
    }

    /// Once a channel is backpressured, further items queue in FIFO order across kinds (Data before
    /// Close), exactly one reserve is requested, and the grant is withheld (the queue just grows).
    #[tokio::test]
    async fn inbound_fifo_preserves_order_and_backpressures() {
        let mut session = authenticated_session();
        let id = ChannelId(1);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        // First item fits the buffer (capacity 1).
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"a"))),
            InboundDelivery::Delivered
        ));
        // Buffer now full: subsequent items queue, preserving arrival order including Close.
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"bb"))),
            InboundDelivery::Queued
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"ccc"))),
            InboundDelivery::Queued
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Close),
            InboundDelivery::Queued
        ));

        let q = session.inbound.get(&id).expect("backpressured");
        assert_eq!(q.queue.len(), 3);
        assert_eq!(q.pending_bytes, 2 + 3); // "bb" + "ccc"; Close carries no bytes
        assert!(q.reserving);
        assert!(matches!(q.queue.front(), Some(InboundItem::Data(d)) if d.as_ref() == b"bb"));
        assert!(matches!(q.queue.back(), Some(InboundItem::Close)));
        // Exactly one reserve requested for the channel despite three queued items.
        assert_eq!(session.inbound_needs_reserve, vec![id]);
    }

    /// A queued payload item must NOT trigger its `Handler` callback until it is actually delivered
    /// into the application buffer (the RC2 ordering fix). The fast path fires inline; the queued
    /// path fires from `pump_inbound`, after `permit.send`.
    #[tokio::test]
    async fn queued_handler_callback_is_deferred_until_delivery() {
        struct Rec(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
        impl crate::server::Handler for Rec {
            type Error = crate::Error;
            async fn data(
                &mut self,
                _channel: ChannelId,
                data: &[u8],
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                self.0.lock().unwrap().push(data.to_vec());
                Ok(())
            }
        }

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let mut handler = Rec(seen.clone());
        let mut session = authenticated_session();
        let id = ChannelId(1);
        let (tx, mut rx) = insert_test_channel(&mut session, id, 1);

        // Fill the buffer, then queue "b".
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"a"))),
            InboundDelivery::Delivered
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"b"))),
            InboundDelivery::Queued
        ));
        // The queued item's handler callback must not have fired yet.
        assert!(seen.lock().unwrap().is_empty());

        // Free a slot and pump: now "b" is delivered AND its callback fires (in that order).
        assert!(matches!(rx.recv().await, Some(ChannelMsg::Data { .. })));
        let generation = session.inbound.get(&id).unwrap().generation;
        let permit = tx.clone().reserve_owned().await.unwrap();
        session
            .pump_inbound(id, generation, Ok(permit), &mut handler)
            .await
            .unwrap();

        assert_eq!(seen.lock().unwrap().as_slice(), &[b"b".to_vec()]);
        match rx.recv().await {
            Some(ChannelMsg::Data { data }) => assert_eq!(data.as_ref(), b"b"),
            other => panic!("expected delivered Data(b), got {other:?}"),
        }
        // Queue drained -> channel returns to the flowing fast path.
        assert!(!session.inbound.contains_key(&id));
    }

    /// The hard per-channel cap is enforced on the FIRST overflowing item, not only once already
    /// backpressured — even when the buffer just became full.
    #[tokio::test]
    async fn first_full_item_respects_pending_cap() {
        let config = crate::server::Config {
            max_pending_inbound_bytes: 4,
            ..Default::default()
        };
        let mut session = authenticated_session_with(config);
        let id = ChannelId(1);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        // Fills the single buffer slot.
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"aaaa"))),
            InboundDelivery::Delivered
        ));
        // Buffer full now; the very first queued item already exceeds the 4-byte cap -> Overflow,
        // and nothing is queued.
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"bbbbb"))),
            InboundDelivery::Overflow
        ));
        assert!(!session.inbound.contains_key(&id));
    }

    /// Exceeding the cap while already backpressured returns Overflow and leaves the existing queue
    /// (and other channels) untouched — the caller closes just this one channel.
    #[tokio::test]
    async fn overflow_while_backpressured_isolated_to_channel() {
        let config = crate::server::Config {
            max_pending_inbound_bytes: 6,
            ..Default::default()
        };
        let mut session = authenticated_session_with(config);
        let victim = ChannelId(1);
        let other = ChannelId(2);
        let (_tx_v, _rx_v) = insert_test_channel(&mut session, victim, 1);
        let (_tx_o, _rx_o) = insert_test_channel(&mut session, other, 1);

        assert!(matches!(
            session.deliver_inbound(victim, InboundItem::Data(Bytes::from_static(b"aa"))),
            InboundDelivery::Delivered
        ));
        assert!(matches!(
            session.deliver_inbound(victim, InboundItem::Data(Bytes::from_static(b"bbbb"))),
            InboundDelivery::Queued
        ));
        // 4 (queued) + 3 > cap 6 -> Overflow; the queued "bbbb" stays, nothing new added.
        assert!(matches!(
            session.deliver_inbound(victim, InboundItem::Data(Bytes::from_static(b"ccc"))),
            InboundDelivery::Overflow
        ));
        assert_eq!(session.inbound.get(&victim).unwrap().queue.len(), 1);
        // The other channel is entirely unaffected and still on the fast path.
        assert!(matches!(
            session.deliver_inbound(other, InboundItem::Data(Bytes::from_static(b"z"))),
            InboundDelivery::Delivered
        ));
        assert!(!session.inbound.contains_key(&other));
    }

    /// A peer CLOSE for a server-initiated open that is still awaiting OPEN_CONFIRMATION must be
    /// ignored (upstream 7c5659f), not treated as "the peer acked our close". Running the
    /// teardown there removed the unconfirmed enc entry, so the confirmation still in flight hit
    /// the unknown-channel arm of CHANNEL_OPEN_CONFIRMATION and killed the entire session with
    /// `Error::Inconsistent` — a hostile peer could do this to any multiplexed connection.
    #[tokio::test]
    async fn peer_close_before_open_confirmation_is_ignored() {
        let mut session = authenticated_session();
        // Server-initiated open: enc entry exists but is NOT confirmed yet.
        let id = insert_encrypted_channel(&mut session, 1024);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 8);

        let mut handler = TestHandler;
        let mut pkt = vec![crate::msg::CHANNEL_CLOSE];
        pkt.extend_from_slice(&id.0.to_be_bytes());
        session
            .server_read_authenticated(&mut handler, crate::msg::CHANNEL_CLOSE, &mut &pkt[1..])
            .await
            .unwrap();

        // The premature CLOSE must not have torn anything down.
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channel_exists(id),
            "premature peer CLOSE must not remove the unconfirmed enc entry"
        );
        assert!(session.channels.contains_key(&id));

        // The confirmation that was already in flight must still be accepted.
        let mut pkt = vec![crate::msg::CHANNEL_OPEN_CONFIRMATION];
        pkt.extend_from_slice(&id.0.to_be_bytes()); // recipient_channel (our id)
        pkt.extend_from_slice(&7u32.to_be_bytes()); // sender_channel (peer's id)
        pkt.extend_from_slice(&2_097_152u32.to_be_bytes()); // initial_window_size
        pkt.extend_from_slice(&32768u32.to_be_bytes()); // maximum_packet_size
        session
            .server_read_authenticated(
                &mut handler,
                crate::msg::CHANNEL_OPEN_CONFIRMATION,
                &mut &pkt[1..],
            )
            .await
            .expect("confirmation after a premature peer CLOSE must not kill the session");
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .channels
                .get(&id)
                .unwrap()
                .confirmed,
            "the channel must end up established"
        );
    }

    /// The inbound pending cap counts payload bytes, so zero-byte items are invisible to it.
    /// While a channel is backpressured, empty DATA is dropped outright and repeated Eof/Close
    /// queue at most one each — otherwise a hostile peer could grow the queue without bound
    /// through items the cap never sees.
    #[tokio::test]
    async fn zero_byte_items_cannot_grow_queue_unboundedly() {
        let mut session = authenticated_session();
        let id = ChannelId(1);
        let (_tx, _rx) = insert_test_channel(&mut session, id, 1);

        // Fill the buffer, then backpressure with one real payload item.
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"a"))),
            InboundDelivery::Delivered
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"bb"))),
            InboundDelivery::Queued
        ));

        // Empty DATA delivers nothing: dropped, never queued.
        for _ in 0..64 {
            assert!(matches!(
                session.deliver_inbound(id, InboundItem::Data(Bytes::new())),
                InboundDelivery::Delivered
            ));
            assert!(matches!(
                session.deliver_inbound(
                    id,
                    InboundItem::ExtendedData {
                        ext: 1,
                        data: Bytes::new()
                    }
                ),
                InboundDelivery::Delivered
            ));
        }
        assert_eq!(session.inbound.get(&id).unwrap().queue.len(), 1);

        // Eof and Close queue once each; repeats are dropped (reported Queued so callers defer).
        for _ in 0..64 {
            assert!(matches!(
                session.deliver_inbound(id, InboundItem::Eof),
                InboundDelivery::Queued
            ));
        }
        for _ in 0..64 {
            assert!(matches!(
                session.deliver_inbound(id, InboundItem::Close),
                InboundDelivery::Queued
            ));
        }
        let q = session.inbound.get(&id).unwrap();
        assert_eq!(q.queue.len(), 3, "bb + one Eof + one Close, nothing else");
        assert_eq!(q.pending_bytes, 2);
    }

    /// If the application bare-drops its channel receiver while a peer `Close` is queued behind
    /// data, the deferred teardown must still run: the reserve resolves `Err`, and dropping just
    /// the queue would leak the `self.channels` entry (its enc twin is already gone) and skip
    /// `handler.channel_close` for the rest of the session.
    #[tokio::test]
    async fn receiver_drop_with_queued_close_still_finalizes() {
        struct CloseRec(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl crate::server::Handler for CloseRec {
            type Error = crate::Error;
            async fn channel_close(
                &mut self,
                _channel: ChannelId,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handler = CloseRec(closes.clone());
        let mut session = authenticated_session();
        let id = ChannelId(1);
        let (_tx, rx) = insert_test_channel(&mut session, id, 1);

        // Backpressure the channel, then queue the peer's Close behind the data.
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"a"))),
            InboundDelivery::Delivered
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"bb"))),
            InboundDelivery::Queued
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Close),
            InboundDelivery::Queued
        ));

        // App bare-drops the receiver; the in-flight reserve resolves Err.
        drop(rx);
        let generation = session.inbound.get(&id).unwrap().generation;
        session
            .pump_inbound(id, generation, Err(()), &mut handler)
            .await
            .unwrap();

        assert!(
            !session.channels.contains_key(&id),
            "queued Close must still tear down the app-side entry"
        );
        assert!(!session.inbound.contains_key(&id));
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Contrast: a bare receiver drop with no Close queued keeps the app-side entry (the peer may
    /// still close later, and that path — try_send returning Closed — cleans it up then).
    #[tokio::test]
    async fn receiver_drop_without_queued_close_only_drops_queue() {
        let mut session = authenticated_session();
        let id = ChannelId(1);
        let (_tx, rx) = insert_test_channel(&mut session, id, 1);

        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"a"))),
            InboundDelivery::Delivered
        ));
        assert!(matches!(
            session.deliver_inbound(id, InboundItem::Data(Bytes::from_static(b"bb"))),
            InboundDelivery::Queued
        ));

        drop(rx);
        let generation = session.inbound.get(&id).unwrap().generation;
        let mut handler = TestHandler;
        session
            .pump_inbound(id, generation, Err(()), &mut handler)
            .await
            .unwrap();

        assert!(session.channels.contains_key(&id));
        assert!(!session.inbound.contains_key(&id));
    }
}
