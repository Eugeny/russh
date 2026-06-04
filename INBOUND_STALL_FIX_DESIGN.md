# russh inbound-proxy stall — fix design (RC1 window lost-wakeup, RC2 HoL)

Context: russh 0.61.1 fork (`fix/inbound-window-stall`) used by zfc as an **SSH inbound
proxy**. One SSH connection multiplexes many `direct-tcpip` channels; each channel is wrapped
as a `ChannelStream` and bidi-copied against an upstream relay. Symptom: a long-lived
downstream-heavy channel (e.g. proxying a 10-minute streaming HTTP response) **permanently
stalls and never recovers**; client eventually reports "socket closed unexpectedly". SS over
the same path is fine. Already fixed in this fork: server-initiated rekey disabled (872c389);
HOLDIAG instrumentation (963af35). `event_buffer_size` already raised 10→64 on the zfc side.

We need to validate the mechanism below against ACTUAL tokio source (`tokio::sync::Notify`,
`mpsc`) and confirm the proposed fixes are correct and strictly safer.

## Downstream data path (server → client)

Two independent window counters that are *supposed* to track the same client receive-window
but are updated at different times:

- **A = producer gate**: `ChannelTx.window_size: Arc<Mutex<u32>>` (`channels/io/tx.rs`).
  zfc's relay writes into the channel via `AsyncWrite::poll_write` → `poll_writable`
  (tx.rs:82). It computes `writable = min(max_packet, *window_size, buf_len)`, does
  `*window_size -= writable` (tx.rs:94), and pushes `ChannelMsg::Data` into the shared
  per-session mpsc (`reserve_owned`, tx.rs:133). When `writable == 0` it parks waiting on a
  `Notify` (tx.rs:100-106).
- **B = wire gate**: `ChannelParams.recipient_window_size` (`session.rs`). The session run
  loop drains the shared mpsc, calls `Session::data` → `data_noqueue` (session.rs:441) which
  emits CHANNEL_DATA up to `recipient_window_size`, does `recipient_window_size -= off`
  (session.rs:492), and queues any remainder into `pending_data`.

On client `CHANNEL_WINDOW_ADJUST` (`server/encrypted.rs:875-902`):
1. `recipient_window_size = recipient_window_size.saturating_add(amount)` (B, incremental — ok)
2. `flush_pending_with_writer` drains queued pending_data, `new_size -= flushed`
3. `chan.window_size().update(new_size).await` → **absolute SET of A** (`channels/mod.rs:131`:
   `*self.value.lock().await = value; self.notifier.notify_one();`)

## RC1 — the permanent stall (primary)

`poll_writable` window-exhausted branch (tx.rs:100-106):
```rust
Err(_) => {
    drop(window_size);
    ready!(self.window_size_notication.poll_unpin(cx)); // wait on current notified() future
    self.window_size_notication = WatchNotification::new(Arc::clone(&self.notify)); // re-arm NEW future
    cx.waker().wake_by_ref();
    Poll::Pending
}
```
`WatchNotification::new` boxes a fresh `async move { n.notified().await }`. A `tokio::Notify`
waiter only registers when the `notified()` future is first polled. The code **recreates** the
future on every wakeup and only arms it on the *next* poll. Combined with the self-notify at
tx.rs:96 (`if *window_size > 0 { self.notify.notify_one() }`) and the `Drop` notify
(tx.rs:200), `notify_one()` is frequently issued with no registered waiter → stored as a single
permit (Notify permits do not accumulate past 1). Hypothesised failure: a `notify_one()` that
fires in the gap between the old `notified()` resolving and the new one being armed collapses
into an already-present permit and is lost; the producer is left parked at `window==0` while B
(wire) actually has window and no further `WINDOW_ADJUST` arrives to re-notify → permanent
one-way stall. (Also a real multi-waiter loss IF a channel has both a Data and an ExtendedData
`ChannelTx` sharing one window+Notify: `notify_one` wakes only one.)

**Proposed fix (RC1):** make the window a single-source-of-truth that cannot lose a wakeup.
Replace the `Arc<Mutex<u32>> + Arc<Notify>` pair behind `WindowSizeRef` and `ChannelTx` with a
`tokio::sync::watch::Sender<u32>/Receiver<u32>`:
- `update(new_size)` → `tx.send_replace(new_size)` (authoritative latest value, no loss).
- producer parks on `rx.changed().await` then reads `*rx.borrow()`; `watch` always delivers the
  latest value and never drops it. Decrement-on-write is local; the periodic `update()` SET
  remains the reconciliation against B.
- removes the recreate-future dance, the self-notify, and the multi-waiter `notify_one` hazard.

Questions for review:
- Is the lost-wakeup real given tokio Notify's single-permit semantics + the recreate pattern,
  or is the single stored permit always sufficient here (making RC1 actually the
  dual-counter drift, not a wakeup loss)?
- Does the watch-based rewrite preserve the existing semantics the russh unit tests assert
  (channels/mod.rs and session.rs window tests)? Any ordering trap with `send_replace` vs the
  Mutex the producer also reads under?
- Is there a smaller, equally-correct fix (e.g. hold ONE pinned `Notified` across polls, arm
  before checking the condition per tokio docs) preferable to the type change?

## RC2 — cross-channel head-of-line (secondary)

Single session `run` loop (`server/session.rs:525-718`) does, inline:
- `flush_into(&mut stream_write).await` (session.rs:690) — downstream socket write. Under client
  TCP backpressure this parks the loop; while parked the shared `event_buffer` mpsc is not
  drained → every channel's downstream stalls together.
- `reply(..).await` (session.rs:564) for inbound CHANNEL_DATA → `chan.send(Data).await` into the
  bounded per-channel `channel_buffer_size` buffer; full when zfc drains that channel's upstream
  slowly → parks the loop → same all-channel HoL.

**Proposed fix (RC2):** move the downstream socket write off the select loop into a dedicated
writer task fed by a channel (loop produces encrypted buffers, writer task awaits the socket),
so a slow client backpressures only its own channel via the window mechanism, not the shared
loop. Keep it minimal; do not regress ordering of control vs data packets.

Questions for review:
- Correctness of splitting the writer out given `PacketWriter`/cipher state ownership and packet
  sequence numbers.
- Whether RC1 alone resolves the user's permanent-stall symptom and RC2 can be deferred (RC2's
  HoL is transient/recoverable, less aligned with "never recovers + socket closed").

## Constraints
- Production traffic; a wrong flow-control change wedges ALL inbound worse than the status quo.
- zfc consumes this via git branch dep; local build switches to a path patch. No commit/push
  without explicit approval.
