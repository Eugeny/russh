//! Per-channel non-blocking inbound delivery (Scheme C — see `RC2_HOL_FIX_DESIGN.md`).
//!
//! Shared by the server and client session loops: inbound `CHANNEL_DATA` / `EXTENDED_DATA` /
//! `EOF` / `CLOSE` is handed to the per-channel application buffer with `try_send`; when the
//! buffer is full the channel becomes backpressured and items queue here behind a single
//! in-flight `reserve_owned()` future, so the shared session loop never blocks on one channel's
//! slow consumer, and the channel's inbound window grant is withheld until delivery.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;

use futures::stream::FuturesUnordered;
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::mpsc::error::TrySendError;

use crate::ChannelId;
use crate::channels::{ChannelMsg, ChannelRef};

/// A single inbound message destined for a channel's application buffer. Held in an
/// [`InboundQueue`] when the channel's bounded buffer is full, so the shared session loop never
/// blocks on one channel's slow consumer.
#[derive(Debug)]
pub(crate) enum InboundItem {
    Data(bytes::Bytes),
    ExtendedData { ext: u32, data: bytes::Bytes },
    Eof,
    Close,
}

impl InboundItem {
    /// Number of payload bytes this item contributes to the per-channel pending budget.
    pub(crate) fn byte_len(&self) -> usize {
        match self {
            InboundItem::Data(data) => data.len(),
            InboundItem::ExtendedData { data, .. } => data.len(),
            InboundItem::Eof | InboundItem::Close => 0,
        }
    }

    /// Build the corresponding [`ChannelMsg`] without consuming `self` (cheap: `Bytes` clone).
    pub(crate) fn to_msg(&self) -> ChannelMsg {
        match self {
            InboundItem::Data(data) => ChannelMsg::Data { data: data.clone() },
            InboundItem::ExtendedData { ext, data } => ChannelMsg::ExtendedData {
                ext: *ext,
                data: data.clone(),
            },
            InboundItem::Eof => ChannelMsg::Eof,
            InboundItem::Close => ChannelMsg::Close,
        }
    }

    /// Move into the corresponding [`ChannelMsg`].
    pub(crate) fn into_msg(self) -> ChannelMsg {
        match self {
            InboundItem::Data(data) => ChannelMsg::Data { data },
            InboundItem::ExtendedData { ext, data } => ChannelMsg::ExtendedData { ext, data },
            InboundItem::Eof => ChannelMsg::Eof,
            InboundItem::Close => ChannelMsg::Close,
        }
    }

    /// Whether delivering this item should trigger a deferred inbound window grant (I2).
    pub(crate) fn grants_window(&self) -> bool {
        matches!(
            self,
            InboundItem::Data(_) | InboundItem::ExtendedData { .. }
        )
    }
}

/// The deferred `Handler` callback for a queued inbound item, captured at delivery time so a
/// custom handler never observes data before it reaches the channel application buffer (matching
/// the fast-path order: buffer first, then callback). Fast-path (immediately-delivered) items
/// fire their callback inline in the read path instead.
pub(crate) enum DeferredCallback {
    Data(bytes::Bytes),
    ExtendedData { ext: u32, data: bytes::Bytes },
    Eof,
    Close,
}

impl DeferredCallback {
    pub(crate) fn capture(item: &InboundItem) -> Self {
        match item {
            InboundItem::Data(d) => DeferredCallback::Data(d.clone()),
            InboundItem::ExtendedData { ext, data } => DeferredCallback::ExtendedData {
                ext: *ext,
                data: data.clone(),
            },
            InboundItem::Eof => DeferredCallback::Eof,
            InboundItem::Close => DeferredCallback::Close,
        }
    }
}

/// Per-channel inbound backpressure state (Scheme C). While non-empty / `reserving`, the channel
/// is backpressured: its inbound window grant is withheld so the peer stops sending, isolating
/// the slow consumer instead of stalling the whole session.
#[derive(Debug, Default)]
pub(crate) struct InboundQueue {
    pub(crate) queue: VecDeque<InboundItem>,
    pub(crate) pending_bytes: usize,
    /// Bumped on teardown so a late-resolving `reserve_owned()` future is recognised as stale.
    pub(crate) generation: u64,
    /// At most one `reserve_owned()` future is in flight per channel at a time.
    pub(crate) reserving: bool,
    /// An `Eof` is already queued. `pending_bytes` counts payload bytes only, so zero-byte
    /// items are invisible to the cap; a compliant peer sends Eof at most once, so a repeat
    /// while one is still queued is dropped instead of growing the queue without bound.
    pub(crate) eof_queued: bool,
    /// Same, for `Close`.
    pub(crate) close_queued: bool,
}

/// Outcome of [`deliver_inbound`].
pub(crate) enum InboundDelivery {
    /// The item was handed to the application buffer immediately (fast path).
    Delivered,
    /// The buffer was full (or already backpressured); the item is queued.
    Queued,
    /// The per-channel pending cap was exceeded; the item was NOT queued.
    Overflow,
    /// The channel's application receiver is gone; the item was dropped.
    ChannelGone,
}

/// Boxed `reserve_owned()` future carried in the run loop's `FuturesUnordered`. Resolves to the
/// channel id, the generation it was issued under (stale results are dropped), and either the
/// owned permit or `Err(())` when the application receiver was dropped.
pub(crate) type BoxReserve = Pin<
    Box<
        dyn std::future::Future<
                Output = (
                    ChannelId,
                    u64,
                    Result<OwnedPermit<ChannelMsg>, ()>,
                ),
            > + Send,
    >,
>;

/// Deliver one inbound [`InboundItem`] to a channel's application buffer without ever blocking
/// the session loop. Fast path uses `try_send`; on `Full` the channel becomes backpressured and
/// the item is queued behind a single in-flight `reserve_owned()` future.
pub(crate) fn deliver_inbound(
    channels: &HashMap<ChannelId, ChannelRef>,
    inbound: &mut HashMap<ChannelId, InboundQueue>,
    needs_reserve: &mut Vec<ChannelId>,
    cap: usize,
    id: ChannelId,
    item: InboundItem,
) -> InboundDelivery {
    // A payload item with no payload delivers nothing: drop it rather than buffer it. The
    // pending cap counts payload bytes only, so without this a peer could park a channel
    // (fill its app buffer) and then queue an unbounded number of zero-byte DATA packets
    // the cap never sees. Nothing is lost — and delivering one is not even desirable, as a
    // zero-length read on the app stream reads as EOF to `AsyncRead` consumers.
    match &item {
        InboundItem::Data(data) if data.is_empty() => return InboundDelivery::Delivered,
        InboundItem::ExtendedData { data, .. } if data.is_empty() => {
            return InboundDelivery::Delivered
        }
        _ => {}
    }

    // Already backpressured for this channel: preserve FIFO by queueing behind existing items.
    if let Some(q) = inbound.get(&id) {
        if !q.queue.is_empty() || q.reserving {
            // Safe: get_mut after the immutable borrow above is dropped.
            let q = match inbound.get_mut(&id) {
                Some(q) => q,
                None => return InboundDelivery::ChannelGone,
            };
            // Eof/Close are the other zero-byte hole in the cap: a compliant peer sends
            // each at most once, so while one is still queued a repeat is dropped, not
            // queued. Reported as Queued so callers defer to the queued original.
            match &item {
                InboundItem::Eof if q.eof_queued => return InboundDelivery::Queued,
                InboundItem::Close if q.close_queued => return InboundDelivery::Queued,
                _ => {}
            }
            if q.pending_bytes.saturating_add(item.byte_len()) > cap {
                return InboundDelivery::Overflow;
            }
            // Window grant is withheld while backpressured (per-channel backpressure, I2/I4).
            let needs = !q.reserving;
            q.pending_bytes = q.pending_bytes.saturating_add(item.byte_len());
            q.eof_queued |= matches!(item, InboundItem::Eof);
            q.close_queued |= matches!(item, InboundItem::Close);
            q.queue.push_back(item);
            if needs {
                q.reserving = true;
                needs_reserve.push(id);
            }
            return InboundDelivery::Queued;
        }
    }

    // Fast path: try to hand the item straight to the application buffer.
    let chan = match channels.get(&id) {
        Some(chan) => chan,
        None => return InboundDelivery::ChannelGone,
    };
    match std::ops::Deref::deref(chan).try_send(item.to_msg()) {
        Ok(()) => InboundDelivery::Delivered,
        Err(TrySendError::Full(_)) => {
            let len = item.byte_len();
            // First item to queue for this channel: enforce the same hard cap as the
            // already-backpressured path (matters only if the cap is configured small;
            // a sane cap is >= window_size + maximum_packet_size).
            let existing = inbound.get(&id).map(|q| q.pending_bytes).unwrap_or(0);
            if existing.saturating_add(len) > cap {
                return InboundDelivery::Overflow;
            }
            let q = inbound.entry(id).or_default();
            q.pending_bytes = q.pending_bytes.saturating_add(len);
            q.eof_queued |= matches!(item, InboundItem::Eof);
            q.close_queued |= matches!(item, InboundItem::Close);
            q.queue.push_back(item);
            q.reserving = true;
            needs_reserve.push(id);
            InboundDelivery::Queued
        }
        Err(TrySendError::Closed(_)) => InboundDelivery::ChannelGone,
    }
}

/// For each channel flagged in `needs_reserve`, register a single `reserve_owned()` future
/// (tagged with the current generation) into the run loop's `FuturesUnordered`.
pub(crate) fn drain_needs_reserve(
    channels: &HashMap<ChannelId, ChannelRef>,
    inbound: &mut HashMap<ChannelId, InboundQueue>,
    needs_reserve: &mut Vec<ChannelId>,
    reserves: &mut FuturesUnordered<BoxReserve>,
) {
    for id in std::mem::take(needs_reserve) {
        let generation = match inbound.get(&id) {
            Some(q) if q.reserving && !q.queue.is_empty() => q.generation,
            // Either already drained or no longer needs a reserve.
            Some(_) => continue,
            None => continue,
        };
        match channels.get(&id) {
            Some(chan) => {
                let sender = std::ops::Deref::deref(chan).clone();
                let fut: BoxReserve = Box::pin(async move {
                    let r = sender.reserve_owned().await.map_err(|_| ());
                    (id, generation, r)
                });
                reserves.push(fut);
            }
            None => {
                // Application receiver gone before we could reserve: drop the queue.
                teardown_inbound(inbound, id);
            }
        }
    }
}

/// Tear down a channel's inbound queue when its application receiver was dropped mid-flight.
/// Bumps the generation so a stale reserve result is ignored.
pub(crate) fn teardown_inbound(inbound: &mut HashMap<ChannelId, InboundQueue>, id: ChannelId) {
    if let Some(q) = inbound.get_mut(&id) {
        q.generation = q.generation.wrapping_add(1);
    }
    inbound.remove(&id);
}
