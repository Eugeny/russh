# Review task: commits 94b3a20 + 917d0c5 on this repo (russh fork)

Read-only adversarial review of `git show 94b3a20` and `git show 917d0c5` (HEAD of main).
94b3a20 contains two independent deadlock fixes to the SSH session run loops; 917d0c5 is
post-review hardening (from two prior adversarial reviews) — bounded teardown flush,
open-reply gating alignment, watermark accounting, capped client drains, dead-arm removal.
Your job: find real defects — correctness regressions, new race/deadlock windows, protocol
violations — in the COMBINED state at HEAD, including defects the hardening commit may have
introduced (e.g. the 5s teardown flush deadline, the capped eager drains, the changed
pending_bytes accounting). Not style nits.

## Context

This fork (BlackLuny/russh, based on upstream v0.62.5) is used by a production reverse-proxy
(many concurrent channels, heavy bidirectional flood, frequent channel opens, rekey enabled).

**Fix 1 — channel-open reply self-deadlock.** `ChannelOpenHandle::accept()/reject()` used to
`send().await` `Msg::ChannelOpenReply` / `Msg::ServerChannelOpenReply` into the session's
*bounded* Msg queue (server `event_buffer_size` default 10; client `inbound_channel_sender`
cap 10). Handlers run inline on the run loop, so with the queue kept full by other channels'
`ChannelTx` writers, the loop deadlocked against itself (empirically reproduced 3/3, fixed).
The commit reroutes replies over a new per-session unbounded `open_reply_tx/rx` channel:
- `russh/src/lib_inner.rs` — handle holds `UnboundedSender`; accept/reject/Drop now sync send.
- `russh/src/server/session.rs` — new fields, `drain_open_replies()` called at the top of
  `dispatch_msg`, new kex-gated `select!` arm in `run()`.
- `russh/src/client/mod.rs` — same pattern (`handle_msg` top, new arm in `run_inner`).
- Claimed ordering invariant: a writer's first `Data` for a channel is enqueued strictly
  after `accept()` queued that channel's reply, and replies are drained before dispatching
  any queued channel message, so `Data` can never be dispatched against an unconfirmed
  channel (which would return `Error::WrongChannel` and `?`-kill the session).

**Fix 2 — full-duplex flush stall.** Both run loops were "select one event → unbounded
`flush_into().await` (write_all + flush) → loop". A blocked write stopped reads AND timers.
The commit makes `PacketWriter::flush_into` cancel-safe/resumable (`flush_cursor`, one
socket `write` per await, buffer cleared only when fully written+flushed) and moves flushing
into a `select!` arm concurrent with reading (`has_pending()` condition, NOT kex-gated).
Intake of new outbound Handle messages is gated by `OUTBOUND_HIGH_WATERMARK` (128 KiB,
`russh/src/sshbuffer.rs`) — server batch drain + receiver arm, client `can_receive_outbound`
(which also gates client's `inbound_channel_receiver` and the new open-reply arm). Both
loops now do a final `flush_into` before `shutdown()`.

## Focus your scrutiny on

1. The ordering invariant of Fix 1: any path where `Msg::Channel(id, Data/Eof/Close)` (or
   any channel msg) can be dispatched BEFORE that channel's open reply is finalized. Consider
   handlers that write via the `Channel` object *before* calling accept, deferred accepts
   from spawned tasks, the select-arm race between `reading`/`receiver`/`open_reply_rx`, and
   the client's eager `try_recv` batching loops inside arm bodies.
2. Kex interactions: replies are finalized only via kex-gated paths — can a reply be
   *written* mid-rekey through some ungated path (e.g. `drain_open_replies` inside
   `dispatch_msg` — verify every dispatch_msg/handle_msg caller is kex-gated)? Conversely,
   can pending replies be starved forever?
3. Cancel-safety of the new `flush_into`: partial-write cursor vs. buffer growth between
   polls, `w.flush()` cancellation, `write_buffer.buffer.clear()` timing, interaction with
   rekey/cipher swap (`reset_seqn`, NEWKEYS) while `flush_cursor > 0`, and any other caller
   of `flush_into`/`write_buffer` that assumes the old all-or-nothing semantics.
4. The watermark gate: can it livelock (intake gated while flush arm never enabled, or
   vice versa)? Is the reading-arm-generated outbound (window adjusts, kex replies, handler
   `session.data()` calls) safely bounded without the gate? Client `can_receive_outbound`
   now also gates the open-reply select arm — starvation risk?
5. Shutdown/teardown paths: every loop exit (DISCONNECT rx/tx, errors, keepalive timeout)
   — is pending outbound flushed where it matters, and is the added final flush correct
   (e.g. server returns error from `map_err!` on a dead socket where old code would have...)?
6. select! borrow/fairness concerns: the flush arm's future borrows
   `common.packet_writer` mutably each iteration — verify no arm-body conflicts and no
   busy-loop (e.g. flush arm ready-looping when socket returns Ready(0)/errors).
7. Anything ELSE in the commit that looks wrong, including the test-file changes.
8. Over-engineering check (避免过度设计): flag anything in the commit that is more
   mechanism than the problem needs — e.g. state/fields/arms that a simpler construct
   would cover, dead paths kept alive (like the now-unreachable `Msg::ChannelOpenReply`
   arm in dispatch_msg — needed or noise?), comments restating code, or the watermark
   constant being config-worthy vs. fine as-is. Simplification suggestions must preserve
   the two fixes' guarantees; do not propose adding new abstractions.

## Deliverable

Write your findings to the file named in your spawn prompt (`.omc/review-94b3a20-<your-name>.md`):
- Verdict per focus area (OK / DEFECT / SUSPICIOUS) with file:line evidence.
- For each defect: concrete failure scenario (inputs/state → wrong behavior).
- End with an overall verdict: SHIP / FIX-FIRST (with the must-fix list).
Do not modify any source files. Base claims on the actual code, not the commit message.
