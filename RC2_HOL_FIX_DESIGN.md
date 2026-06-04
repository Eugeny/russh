# RC2 fix design — inbound per-channel head-of-line blocking in the server session loop

Status: DESIGN ONLY (no code changes yet). For review by codex before implementation.

## 0. What we are fixing (confirmed root cause)

The server session run loop (`russh/src/server/session.rs:525+`) is a single `tokio::select!` loop.
Its `reading` arm calls `reply(&mut self, …).await` (session.rs:564), and for inbound
`CHANNEL_DATA`/`CHANNEL_EXTENDED_DATA`/`CHANNEL_EOF`/`CHANNEL_CLOSE` that path does a **blocking
`chan.send(ChannelMsg::…).await`** into the bounded per-channel buffer
(`server/encrypted.rs:818,828,857,867`; `chan` is a `ChannelRef` that `Deref`s to a tokio
`mpsc::Sender<ChannelMsg>` of depth `channel_buffer_size`).

When one channel's consumer (zfc's relay → landing upstream) stops draining, that channel's
buffer fills and `chan.send().await` **parks the entire loop**. The same loop also:
- drains the downstream `ChannelTx` mpsc (`self.receiver.recv()` arm, session.rs:603) → emits
  CHANNEL_DATA to the socket for **every** channel;
- processes inbound `CHANNEL_WINDOW_ADJUST` (the grant that un-parks a downstream producer);
- flushes encrypted packets to the socket.

So one stuck upstream wedges **all** channels' downstream. This is reproduced deterministically
in `russh/tests/test_inbound_window_stall.rs`: freezing **only channel 0's** upstream drives the
aggregate throughput of the **healthy, downstream-only channels** to `0.00 MB/s` and never
recovers — matching production "never recovers + socket closed after ~10 min". (RC1 window
accounting was ruled out: pure park storms, `pending_data`, multi-second freezes, and real socket
backpressure all self-recover.)

## 1. The load-bearing subtlety (why `try_send` alone is wrong)

Today the **inbound receive-window replenishment happens at packet-receive time, before
delivery.** In `reply()` for DATA/EXTENDED_DATA (`server/encrypted.rs:846-854`):

```rust
if enc.adjust_window_size(channel_num, &data, target)? { … }   // session.rs:285-316
self.flush()?;                                                  // emit WINDOW_ADJUST to client
… chan.send(ChannelMsg::Data { data }).await …                 // THEN deliver to app
```

`adjust_window_size` (session.rs:298-312) does two things at once:
1. `sender_window_size -= data.len()` — consume the client's send allowance (correct at receive);
2. if `sender_window_size < target/2`: push `CHANNEL_WINDOW_ADJUST` and reset `sender_window_size
   = target` — **grant more allowance, before the data is delivered**.

Consequence: **the blocking `.await` is the only inbound backpressure that exists.** When the app
buffer is full the loop parks, no further packets are read, `adjust_window_size` is not reached,
the client's mirrored send window depletes, and the client stops. Remove the `.await` and replace
it with `try_send` + a stash, and you **lose all backpressure**: the window keeps being granted at
receive time, the client keeps sending, and the stash grows without bound.

**Therefore the fix is not "stop awaiting" — it is "move the window grant from receive-time to
delivery-time."** Backpressure must come from *withholding the grant* for a stuck channel, not
from blocking the shared loop.

## 2. Target invariants

- **I1 (decrement at receive):** `sender_window_size -= len` stays at packet-receive (the bytes
  are off the wire; the allowance is genuinely consumed). Unchanged.
- **I2 (grant at delivery):** the replenish `WINDOW_ADJUST` (raise back to `target`) fires **only
  after** the bytes are accepted into the per-channel app buffer. New.
- **I3 (per-channel isolation):** a full/stuck channel withholds *its own* grant only; the loop
  never `.await`s on a single channel, so other channels' inbound, downstream, and WINDOW_ADJUST
  proceed.
- **I4 (bounded memory):** with I1+I2, a stuck channel can hold at most ~`target` bytes of
  un-granted in-flight data before the client's window hits 0 and it stops. The per-channel stash
  is therefore naturally bounded; add a hard safety cap and treat overflow as a protocol violation
  (client ignored its window) → close that channel only.
- **I5 (ordering):** per-channel FIFO across message kinds — `Data`/`ExtendedData` in receive
  order, and `Eof`/`Close` delivered **after** all queued data for that channel. WINDOW_ADJUST
  emission, packet writer, cipher, and `seqn` remain **loop-owned and otherwise untouched**.
- **I6 (no busy-poll):** capacity becoming available must wake the loop via a real future, not
  per-iteration polling.

## 3. Required decisions (codex's checklist) — answers

1. **When is inbound data "consumed" / when may we send WINDOW_ADJUST?** On successful insertion
   into the per-channel app buffer (`try_send` Ok, or a later pumped `permit.send`). Not at
   receive. (I2)
2. **Where does data live when the app buffer is full?** In a per-channel `pending_inbound:
   VecDeque<InboundItem>` held in the session state, where `InboundItem ∈ {Data(Bytes),
   ExtendedData(u32,Bytes), Eof, Close}`. (I5)
3. **Is the stash bounded; how do we backpressure only that channel?** Bounded by construction
   (I4) because we stop granting window for a pending channel; plus a hard cap
   `max_pending_inbound_bytes` per channel as a safety net. Only that channel is throttled because
   the loop never blocks. (I3, I4)
4. **How does the loop keep serving other channels without awaiting one?** Delivery uses
   `try_send`; on `Full`, the channel enters a Pending state holding a `reserve_owned()` future,
   and the loop's `select!` gains an arm that completes when *any* pending channel's permit frees
   (see §4). The loop body never `.await`s a specific channel's `send`. (I3, I6)
5. **How is EOF/CLOSE/EXTENDED_DATA/handler-callback ordering preserved?** All four become
   `InboundItem`s in the same per-channel FIFO. Handler callbacks (`handler.data/extended_data/
   eof/channel_close`) are invoked at **delivery** of the corresponding item (inline in the loop,
   `&mut self` available), preserving today's "callback after delivery" order. `CHANNEL_CLOSE`
   defers `self.channels.remove`/`enc.channels.remove` until its `Close` item is delivered (queue
   drained), so no queued data is dropped. (I5)
6. **Are rekey / packet writer / cipher / seqn touched?** No. WINDOW_ADJUST is still emitted from
   the loop via `self.write`/`self.flush()` exactly as today (just triggered at delivery instead
   of receive). The downstream emit path (`self.receiver.recv()` arm → `self.data`), rekey gating
   (`if !self.kex.active()`), `PacketWriter`, cipher, and `seqn` are unchanged. The fix touches
   only the **inbound app-delivery** side.

## 4. Candidate schemes

### Scheme A — per-channel inbound delivery task  *(rejected as primary)*
Loop forwards inbound items to a per-channel queue; a spawned task does `chan.send().await`.
- Window grant must round-trip **back** to the loop (WINDOW_ADJUST writes loop-owned `self.write`/
  cipher/seqn) — an extra signaling channel + latency.
- If the loop→task queue is unbounded → memory blowup (lost backpressure); if bounded → the loop
  blocks pushing to it = the **same HoL moved one hop**.
- Per-channel task lifecycle/cancellation/panic-safety and cross-task callback ordering add risk.
- **Verdict:** reintroduces the problem or its complexity; do not use.

### Scheme B — in-loop per-channel pending + non-blocking pump  *(viable only with capacity notification)*
`try_send`; on `Full`, stash in `pending_inbound`; each loop iteration tries to pump. Without a
capacity-ready future this **busy-polls** (I6 violated). Adding the capacity notification is
exactly `reserve_owned()` futures → converges to Scheme C. Keep as the conceptual model; implement
as C.

### Scheme C — `reserve_owned()` state machine in the loop  *(recommended)*
Per-channel inbound state:

```
enum InboundState {
    Flowing,                               // buffer has room; deliver via try_send
    Backpressured {
        queue: VecDeque<InboundItem>,      // FIFO, includes Eof/Close
        // exactly one in-flight permit reservation for this channel:
        // tracked in `pending_reserves` (see below), keyed by ChannelId
    },
}
```

Loop-level additions:
- `pending_reserves: FuturesUnordered<BoxFuture<'static, (ChannelId, Result<OwnedPermit<ChannelMsg>, SendError>)>>`
  — each entry is `sender.clone().reserve_owned()` mapped to carry its `ChannelId`.
- A new `select!` arm, **guarded so it never fires when empty** (avoids the `FuturesUnordered`
  empty-→-`Ready(None)` busy-loop):
  ```rust
  Some((cid, res)) = pending_reserves.next(), if !pending_reserves.is_empty() => {
      self.pump_inbound(cid, res)?;   // §4.1
  }
  ```

#### 4.1 Algorithm

On inbound `InboundItem` for channel `C` (in `reply()`):
1. **I1**: for Data/ExtendedData, `C.sender_window_size -= len` now (split out of
   `adjust_window_size`; see §5). Do **not** emit the grant here.
2. If `C` is `Flowing`:
   - `try_send(item)`:
     - `Ok` → delivered. Run **maybe_grant(C)** (I2). Then run the handler callback for this item
       kind (inline, as today).
     - `Err(Full)` → transition `C` to `Backpressured{queue:[item]}`; push
       `reserve_owned()`(for the *next* free slot) into `pending_reserves`. Do **not** grant.
   - `Err(Closed)` → channel gone; drop (as today's `.unwrap_or(())`).
3. If `C` is `Backpressured` → push `item` to its `queue` (preserve order). Do **not** grant.
   (Exactly one reservation per channel is in flight; we do not add another here.)

On `pending_reserves` yielding `(C, res)`:
- `res = Ok(permit)`: `let item = queue.pop_front().unwrap(); permit.send(item)` → delivered.
  - Run **maybe_grant(C)** for the delivered item's bytes (I2), then its handler callback.
  - If the delivered item was `Close`: now perform the deferred `self.channels.remove(C)` /
    `enc.channels.remove(C)` and `handler.channel_close`.
  - If `queue` non-empty → push a fresh `reserve_owned()` for `C` (stay Backpressured).
  - Else → `C` returns to `Flowing`.
- `res = Err(SendError)`: receiver dropped (app closed the channel) → drop queue, remove channel.

`maybe_grant(C)` (the deferred half of old `adjust_window_size`): `if C.sender_window_size <
target/2 { push CHANNEL_WINDOW_ADJUST(target - sender_window_size); sender_window_size = target;
self.flush()? }`. Identical bytes-on-wire to today, only later in time.

#### 4.2 Why C satisfies every invariant
- I1/I2: decrement at step 1, grant only at delivery (Flowing `Ok` or pump). 
- I3: loop never awaits a channel; `pending_reserves` multiplexes all channels' capacity waits.
- I4: while Backpressured we never grant → client window → 0 → client stops at ≤ `target` in
  flight; queue bounded; hard cap `max_pending_inbound_bytes` → close offending channel only.
- I5: per-channel FIFO `queue` holds all kinds; Close deferral keeps data-before-close.
- I6: `reserve_owned()` wakes the loop only when a slot frees; empty-guard avoids spin.
- §3.6: WINDOW_ADJUST still emitted on the loop; writer/cipher/seqn/rekey untouched.

**Recommendation: Scheme C.** (Scheme B's mental model, realized with `reserve_owned` so it is
event-driven, not polled.)

## 5. Concrete code changes (smallest correct surface)

1. **Split the window method — but it is SHARED with the client (codex IMPORTANT).** The method
   lives on the common `Encrypted`/`Session` and is also called by the client inbound DATA paths
   (`client/encrypted.rs:459,482`). Do **not** rename/remove it. Instead:
   - **Keep** the existing `adjust_window_size` as a compatibility wrapper with today's
     receive-time grant behavior, so the **client path is unchanged** in this PR.
   - **Add** `consume_recv_window(channel, len)` (decrement, I1) and
     `maybe_grant_recv_window(channel, target) -> Result<bool>` (the `< target/2` push + reset, I2;
     keep the `handler.adjust_window` interaction from encrypted.rs:848-851 attached to the grant).
     The **server** inbound path calls these two; the client keeps the old wrapper. (Applying the
     delivery-gated scheme to the client too is a possible follow-up, out of scope here.)
   - Preserve existing unit tests; add tests asserting decrement-without-grant and
     grant-only-after-delivery.
2. **`server/encrypted.rs` DATA/EXTENDED_DATA/EOF/CLOSE arms (808-872):** replace the four
   `chan.send(...).await` with enqueue-or-`try_send` via a new `self.deliver_inbound(channel_num,
   InboundItem)` helper implementing §4.1 step 2-3. Move `maybe_grant_recv_window` to the delivery
   points. Defer the CLOSE removals (812,820) until the `Close` item is delivered.
3. **`server/session.rs` run loop (525+):** add `pending_reserves` field + the guarded `select!`
   arm calling `pump_inbound` (§4.1). Add per-channel `InboundState` storage (a
   `HashMap<ChannelId, InboundQueue>` or fold into the existing `self.channels` value).
4. **Config:** add `max_pending_inbound_bytes` (default e.g. `8 * target_window_size`) to
   `server::Config`; document it.
5. **Do NOT touch** the downstream `ChannelTx`/`WindowSizeRef`/`Notify` (RC1) code, `PacketWriter`,
   cipher, `seqn`, or rekey gating in this PR.

## 6. Test / regression plan
- **Gate:** `russh/tests/test_inbound_window_stall.rs` must PASS post-fix — i.e. freezing the
  victim channel's upstream must **not** stall the healthy downstream-only channels (assert holds).
  Add a second assertion that the victim's own downstream also keeps flowing (per-channel
  isolation), and that victim upstream correctly backpressures (client write parks) without
  unbounded memory.
- **Unit tests (new):** decrement-at-receive/grant-at-delivery; pending FIFO ordering;
  Data-before-Eof-before-Close; Close deferral drains queue; `max_pending_inbound_bytes` overflow
  closes only that channel; reserve future cleanup on app-side channel drop (no leak in
  `pending_reserves`).
- **Existing 143 russh unit tests** (esp. `flush_pending_with_writer_*`, window tests) stay green.
- **zfc end-to-end:** build worker against local path patch; the 12510 SSH-inbound + Claude Code
  long-session scenario; confirm a stalled upstream no longer kills unrelated traffic.

## 7. Rollout / PR sequencing
1. Implement Scheme C + split window accounting + config knob. Keep the existing **HOLDIAG A3**
   (session.rs:553-582) and **HOLDIAG WINDOW** (tx.rs / encrypted.rs) instrumentation in place —
   even though RC1 was the wrong target, these logs are cheap insurance to confirm we did **not**
   introduce A/B anomalies while reworking inbound flow control.
2. Land the regression test as a required gate.
3. Soak (local repro matrix + zfc e2e). Only after the gate is stable across the matrix:
4. **Final commit:** remove HOLDIAG A3 + HOLDIAG WINDOW instrumentation, restore the zfc
   `Cargo.toml` `[patch.crates-io]` from the local `path` back to the git branch dep, and push the
   russh fork branch.

## 8. Risks & mitigations
- **Wrong window accounting wedges ALL inbound (worse than status quo).** → I1/I2 split is the
  single riskiest change; cover with the new unit tests + the e2e gate before removing the de-facto
  `.await` backpressure. Consider a feature flag / `cfg` to fall back to the old await path during
  soak.
- **Ordering corruption** (data after close, ext vs data interleave). → single per-channel FIFO for
  all kinds; Close deferral; explicit ordering unit tests.
- **`pending_reserves` leak / spin.** → empty-guarded select arm; remove a channel's in-flight
  reserve when the app drops the channel; one reservation per channel max.
- **Unbounded memory if a client ignores its window.** → hard `max_pending_inbound_bytes` cap →
  close that channel with a protocol error, never the session.
- **Handler-induced blocking** (`handler.data().await` doing real work) is **out of scope** — that
  is a handler bug, not the per-channel-buffer HoL; note it but do not solve here.

## 9b. Codex review — incorporated deltas (no BLOCKING findings)

Codex validated I1/I2 as RFC4254-5.2-correct (`sender_window_size` = server inbound receive
window, init from `config.window_size` at encrypted.rs:1401; `recipient_window_size` = peer's,
1400) and Scheme C as sound, with no simpler equally-correct fix. Five refinements folded in:

1. **(IMPORTANT) Shared method — don't break the client.** `adjust_window_size` is common and is
   called by client inbound paths (`client/encrypted.rs:459,482`). Keep it as a compat wrapper
   (receive-time grant) for the client; add the split methods for the server path only. (See §5.1.)
2. **(MINOR) `reserve_owned()` needs an owned `Sender`; server holds `&ChannelRef`.** Use
   `Deref::deref(chan).clone().reserve_owned()` or add a `ChannelRef::reserve_owned_clone()`
   helper. (`ChannelRef: Deref<Target=Sender<ChannelMsg>>`, channel_ref.rs:27.)
3. **Stale-permit / keyed cancellation.** Tag each in-flight reserve with `(ChannelId,
   generation)`. If the channel closes (or the app drops the receiver) while its reserve is
   pending, the future may still resolve with a permit for a gone channel → **drop the stale
   result** (ignore permit, do not send), and remove the channel's queue. One reservation per
   channel; bump generation on close so a late resolution is recognizably stale.
4. **CLOSE lifecycle must not leave the channel half-open.** When deferring `Close` behind queued
   data, ensure the **outbound** side (downstream `ChannelTx`/receiver, `enc.channels` window
   state) is torn down consistently when `Close` is finally delivered — don't leave the channel
   outbound-open. Mirror today's removal at encrypted.rs:812,820 but at delivery time.
5. **Rekey gating for delivery-triggered grants.** The downstream emit arm is gated `if
   !self.kex.active()` (session.rs:603). The new delivery-triggered `WINDOW_ADJUST` emission must
   respect the **same** gating: during `kex.active()`, do **not** flush — push the grant into the
   normal `self.write` queue (or defer the pump) so it goes out after rekey, consistent with
   existing channel output. Verify `push_packet!`/`flush` ordering vs rekey before relying on it.

## 9. Non-goals (separate follow-ups)
- Outbound `flush_into().await` HoL (session.rs:690): same defect *class*, but it only wedges
  permanently under whole-socket TCP backpressure (real network) and did **not** reproduce
  deterministically on loopback. Address separately if/when reproduced.
- RC1 multi-waiter `notify_one` hazard (shared `WindowSizeRef`/`Notify` across a Data + ExtendedData
  `ChannelTx`): theoretical, not this symptom; leave the HOLDIAG WINDOW probes until §7.4.
