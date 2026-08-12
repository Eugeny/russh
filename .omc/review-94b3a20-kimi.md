# Adversarial review: `94b3a20` + `917d0c5` (combined state at HEAD)

**Repo:** BlackLuny/russh, HEAD = `917d0c5`
**Scope:** read-only review of the two deadlock fixes (`94b3a20`) plus the post-review
hardening (`917d0c5`: 5s teardown flush deadline, kex-only open-reply gating on the client,
`pending_bytes` accounting, 64-msg eager-drain caps, dead reply-arm removal), as one
combined state. Findings formed independently before reading the prior gpt/grok reports;
comparison in §9.

Verified during review: `cargo test -p russh --lib sshbuffer` (12 passed) and
`cargo test -p russh --lib session` (43 passed) at HEAD.

---

## 1. Fix 1 ordering invariant — **OK** (documented caveat)

**Evidence**

- Replies ride the unbounded queue: `lib_inner.rs:587-591` (sync `send`), constructed only at
  `server/encrypted.rs:1811-1815` and `client/encrypted.rs:770-774`.
- Drain-before-dispatch: `server/session.rs:815-828` (`dispatch_msg` head),
  `client/mod.rs:1474-1484` (`handle_msg` head). Every dispatch site for queued channel
  messages goes through one of these two functions (server batch drain
  `server/session.rs:1057`, receiver arm `server/session.rs:1149`; client arms
  `client/mod.rs:1369/1382/1390/1398`).
- Deferred-accept arm: `server/session.rs:1118-1123`, `client/mod.rs:1344-1349`.
- Peer-initiated channels are inserted with `confirmed: true` at finalize
  (`server/encrypted.rs:1788`, `client/encrypted.rs:747`), so a drained-then-dispatched
  `Data` can never hit the `WrongChannel` path (`session.rs:648-649`).

**Why the invariant holds.** `UnboundedSender::send` completes synchronously, so when a
writer's first `Data` is enqueued (bounded queue) strictly after `accept()` returned, the
reply is already in `open_reply_rx`. Dispatch of that `Data` happens at some later time T;
`drain_open_replies()` at T observes every reply enqueued before T, including this one, and
finalizes it first. The select-arm race (receiver vs `open_reply_rx` both ready) is
therefore harmless: whichever arm wins, replies are finalized before the data is dispatched.
The client's eager `try_recv` loops call `handle_msg` per message, so each iteration
re-drains. Checked and rejected as holes: pre-select batch drain (drains per message),
reject-then-write (channel never registered → silent discard, consistent), Drop-reject
(cannot be silently lost any more — only fails if the session is already dead).

**Caveat (not a defect of these commits).** Writing the channel *before* `accept()` still
silently discards (`session.rs:659-661` missing-entry path). This is now explicitly
documented on `ChannelOpenHandleInner` (`lib_inner.rs:565-567`, added by `917d0c5`), and the
same race existed when both messages shared one queue — data enqueued before the reply was
dispatched first then too. Not a regression; see §9 on gpt's stronger position.

**Residual pre-existing hazard (note, out of scope):** `ChannelWriteHalf::send_msg` still
does a bounded `send().await` (`channels/mod.rs:418-423`). A handler that calls
`channel.data_bytes(...).await` *inline* while the bounded queue is full can still
self-deadlock the loop exactly like the old `accept()` did. Fix 1 only removed the reply
from that queue. Handlers that spawn a writer task (the dominant pattern) are unaffected.

---

## 2. Kex interactions — **OK**

- Every `drain_open_replies` caller is kex-gated: server batch drain and receiver arm via
  `can_receive_outbound` (`server/session.rs:1046-1049, 1147`), client receiver arms
  (`client/mod.rs:1289-1291`) with the eager loops re-checking `!self.kex.active()` each
  iteration (`client/mod.rs:1380, 1396`), and both dedicated reply arms gated on
  `!self.kex.active()` (`server/session.rs:1118`, `client/mod.rs:1344`). `finalize_*` stages
  via `push_packet!(enc.write, …)` and the post-select `flush()` encrypts it, so no reply
  bytes can be emitted mid-rekey.
- Starvation: replies wait only while kex is active; a completing rekey ungates them, and a
  never-completing rekey is a pre-existing session-wide exposure (all outbound was always
  kex-gated), backstopped by keepalive/inactivity timers.
- `reset_seqn`/NEWKEYS vs `flush_cursor > 0`: safe. The cipher is applied at packet-build
  time (`sshbuffer.rs:432-460`); `flush_into` moves opaque bytes in order. Rekey completion
  appends new-cipher packets after any still-unflushed old-cipher prefix
  (`server/mod.rs:1196-1205`, `client/mod.rs:2056-2066`), preserving the wire order
  old-ciphertext → NEWKEYS → new-ciphertext. `reset_seqn` (`sshbuffer.rs:578-580`) only
  touches the sequence counter used for subsequent packet building.

**Pre-existing observation (not introduced here):** the keepalive arms are not kex-gated
(`server/session.rs:1124-1132`, `client/mod.rs:1350-1362`), so a keepalive firing mid-rekey
stages a `GLOBAL_REQUEST` that the end-of-iteration `flush()` encrypts and the flush arm
sends during the exchange. Same before these commits; flagged only because focus area 2
asks about ungated write paths — the open-reply paths themselves are correctly gated.

---

## 3. `flush_into` cancel-safety — **OK**

`sshbuffer.rs:603-621`:

- `flush_cursor` advances only after a successful `write`; one write per await point, so a
  cancelled future loses nothing and resumes exactly.
- `n == 0` → `WriteZero` error (no ready-spin); write errors propagate via `map_err!` and end
  the session — correct for a dead socket.
- Buffer growth between polls is append-only (`write_payload_into_output` uses
  `offset = buffer.len()`, `sshbuffer.rs:436`); error paths truncate back to `offset`, never
  below the cursor.
- Cancellation during `w.flush().await`: cursor == len, buffer retained; the next call skips
  the write loop and retries `flush()`. There is no await between a completed `flush()` and
  `clear()` + cursor reset, so a completed flush can never be torn down half-recorded.
- `pending_bytes()` now returns the full retained `buffer.len()` (`sshbuffer.rs:592-594`,
  changed by `917d0c5`), so the watermark accounts for the written-but-unflushed prefix
  retained while a buffering writer's `poll_flush` is pending. This closes the accounting
  hole from the first round of reviews (§9).
- Other callers audited: startup flushes (`server/session.rs:993`, `client/mod.rs:1249`)
  still await to completion (unchanged semantics); teardown flushes are timeout-bounded
  (§5); cleartext-phase `disconnect`/`debug` append directly to the buffer
  (`session.rs:208-240`) without touching the cursor. `packet_writer.buffer()` mutators
  outside `sshbuffer.rs` only reset the `bytes` rekey counter (`server/mod.rs:1201`,
  `client/mod.rs:2061`).

No defect found here.

---

## 4. Watermark gate — **OK as designed (documented soft bound); no livelock**

- **No livelock in either direction.** Intake paused ⇒ `pending_bytes() >= 128 KiB` ⇒
  buffer non-empty ⇒ `has_pending()` true ⇒ flush arm enabled (`server/session.rs:1142`,
  `client/mod.rs:1337`). A blocked flush parks in `select!`; keepalive/inactivity timers
  still fire and eventually kill the session if the peer never drains — the hard backstop
  the fix promised. If the socket drains, `pending_bytes` falls and intake resumes.
- **Soft spots, all deliberate and documented** (`sshbuffer.rs:361-369`, commit message):
  read-path-generated output (window adjusts, open confirmations, kex replies) bypasses the
  gate; the 64-msg batch caps (`server/session.rs:1051-1059`, `client/mod.rs:1379-1386,
  1395-1402`) bound overshoot per select win but can still stage up to ~64 max-size payloads
  past the watermark. Channel data itself is additionally window-capped by the peer.
- **Client/server gating parity** restored by `917d0c5`: both open-reply arms are kex-only
  gated (`server/session.rs:1118`, `client/mod.rs:1344`), so server-initiated channel
  confirmations are no longer delayed by upload backpressure. Replies are tiny; correct
  tradeoff.
- **Edge note (parity, not regression):** `Msg::Disconnect` and other `Handle` control
  messages are watermark-gated with everything else on the receiver arm. Under a peer that
  keeps sending but never reads (`received_data` resets keepalive counters; loop activity
  resets the inactivity timer), a queued disconnect can stay unprocessed indefinitely — but
  the old code hung in the blocking `flush_into` in the same scenario, so this is unchanged
  exposure, just relocated.

---

## 5. Shutdown/teardown — **SUSPICIOUS** (one pre-existing unbounded wait remains)

`917d0c5` fixes the round-1 findings: both loops now do a best-effort final flush under a
5 s deadline (`server/session.rs:1191-1195`, `client/mod.rs:1207-1211`), so a dead or
non-draining peer can neither error out a clean exit nor hang teardown at the flush. Error
exits (keepalive/inactivity/read errors) skip the flush — correct; the flush is cancel-safe
so the timeout loses nothing.

**Remaining gap (pre-existing, but it undercuts the "neither may fail or hang the teardown"
guarantee):** after the bounded flush and `shutdown()`, the server runs an *unbounded*
read-drain loop (`server/session.rs:1197-1210`) waiting for peer EOF. Failure scenario:
peer sent DISCONNECT (or we exit cleanly) and then keeps its TCP write side open without
sending — common for half-broken proxies and trivially done by a hostile peer. `shutdown()`
only closes *our* write half; the read future then pends forever with no timer, so the
server session task never completes. The hardening bounded the flush but not this wait.
Recommend a follow-up deadline (or byte cap) on that drain loop. The client has no such
loop and is fine.

Minor (pre-existing, narrow): `map_err!(stream_write.shutdown().await)?` on both sides
(`server/session.rs:1196`, `client/mod.rs:1212`) can still mask the original exit reason
with an IO error if the socket is fully dead before `shutdown()`; on common platforms
shutdown-after-RST succeeds, so impact is small.

---

## 6. `select!` borrow/fairness — **OK**

- The flush arm's future mutably borrows `packet_writer` and `stream_write` per iteration;
  losing futures are dropped before arm bodies run, and the end-of-iteration `flush()` runs
  after `select!` completes — no overlapping borrows (and it compiles clean).
- tokio `select!` random fairness means the flush arm cannot starve or be starved.
- No busy-loop: a completed flush clears the buffer and disables the arm via `has_pending()`;
  `Ready(Ok(0))` → `WriteZero` error; a backpressured socket returns Pending.
- Behavioral note (not a defect): staged bytes are written at the earliest one select cycle
  after staging, versus inline write in the old loop — sub-millisecond latency change,
  irrelevant beside the deadlock it removes.

---

## 7. Other changes / tests — **OK**

- `lib_inner.rs`: `accept`/`reject`/`Drop` now share `try_send_reply`; Drop can no longer
  silently drop the rejection on a full queue — a real side fix. `accept`/`reject` stay
  `async` for API compatibility (never await — fine).
- `server/mod.rs`, `encrypted.rs` test-constructor changes: mechanical field additions.
- `tests/test_inbound_window_stall.rs`: adds `eprintln!` probes and the `REPRO_EVENT_BUF`
  knob — diagnostics only, no assertions weakened. The probes (`OPEN_SEQ` static) are noisy
  but this is a repro/stress test where that is the point.
- No deterministic unit test covers the new cancel-safety/watermark behavior (partial write
  + cancel + regrow, flush-pending watermark accounting, teardown deadline). The stress
  suite passing is decent evidence, but a small deterministic `flush_into` test with a
  scripted mock `AsyncWrite` would be cheap insurance for the cursor logic. Suggestion, not
  a blocker.

---

## 8. Over-engineering check — **OK**

- The removed main-queue reply arms (`917d0c5`) were genuinely dead: the only constructors
  of `Msg::ChannelOpenReply`/`Msg::ServerChannelOpenReply` send to `open_reply_tx`
  (verified by grep: `server/encrypted.rs:1814`, `client/encrypted.rs:773`). Their removal
  turns accidental re-routing into an obvious `unimplemented!` instead of a silent duplicate
  path. Good deletion, not noise.
- The dedicated select arm is *not* redundant with drain-at-dispatch: without it, a deferred
  accept arriving while the loop idles in `select!` would wait for unrelated traffic.
  Drain-at-dispatch is likewise required for the ordering guarantee. Both earn their keep.
- `OUTBOUND_HIGH_WATERMARK` as a plain constant with a documenting comment is the right
  weight for a fix commit; making it config would be the over-engineering.
- Minor dead state spotted while auditing (from earlier commits, not these two):
  `pending_reads`/`pending_len` (`client/mod.rs:109-110`, `server/session.rs:31-32`) are
  only ever initialized, taken, and re-stored — nothing pushes to them anywhere in the tree.
  Optional cleanup; harmless.
- Comment volume is high but consistent with this file's existing convention, and for this
  bug class the rationale comments are worth keeping.

---

## 9. Comparison with prior reviews (gpt, grok)

Both prior reports reviewed `94b3a20` alone; `917d0c5` is their direct output. Against the
**combined** state:

- **gpt §5 / grok DEFECT 1 (unbounded/fallible final flush):** AGREED then; **fixed** — 5 s
  best-effort timeout both sides (`server/session.rs:1191-1195`, `client/mod.rs:1207-1211`).
  Verified the fix, not just the commit message. Neither prior reviewer flagged the
  *read-drain* wait that follows (`server/session.rs:1197-1210`) — my §5 finding; teardown
  is still not fully bounded on the server.
- **gpt §3 (`pending_bytes` excludes written-but-unflushed prefix):** AGREED then; **fixed**
  — now `buffer.len()` (`sshbuffer.rs:592-594`).
- **grok SUSPICIOUS 2 (client open-reply arm watermark-gated):** AGREED then; **fixed** —
  kex-only gate (`client/mod.rs:1344`).
- **grok SUSPICIOUS 3 (uncapped eager drains):** AGREED then; **fixed** — 64-msg caps
  (`client/mod.rs:1374-1402`).
- **Dead reply arms (both reviewers):** **fixed** in `917d0c5`; verified the arms were truly
  unreachable before removal.
- **grok §1 caveat (WrongChannel wording overstates the failure mode):** was correct;
  comments corrected in `917d0c5` (silent-discard wording at `server/session.rs:810-814`,
  `client/mod.rs:1469-1473`).
- **gpt §1 (pre-accept / deferred-accept channel use must be *enforced*, "documentation
  alone would not repair the silent-loss race"):** PARTIAL DISAGREEMENT for the combined
  state. The race is real but pre-dates these commits (on the old single queue, data sent
  before the reply was likewise dispatched first and discarded), and the invariant the fix
  claims is explicitly scoped to accept-then-write usage, now documented at
  `lib_inner.rs:565-567`. Enforcement (parking or loudly failing pre-accept writes) is a
  legitimate follow-up API hardening, but I would not hold this fix hostage to it.
- **gpt §4 / grok SUSPICIOUS 1 (read-path-generated output bypasses the watermark → unbounded
  memory with a send-but-never-read peer):** AGREED it is theoretically unbounded; AGREE
  with `917d0c5`'s decision to document it as an accepted soft bound (`sshbuffer.rs:361-369`)
  rather than hard-cap it now — the old "bound" was precisely the full-duplex deadlock being
  fixed, and a naive hard cap risks killing legitimate heavy sessions. Reasonable follow-up,
  not a blocker.
- **gpt §1's secondary point (inline `channel.data_bytes().await` can still self-deadlock on
  the full bounded queue):** AGREED and confirmed at `channels/mod.rs:418-423`; pre-existing,
  outside Fix 1's reply-only scope. Worth a doc note or a future `try_send`-based path.

Nothing in the prior reports is made *wrong* by `917d0c5`; conversely I found no new defect
introduced by the hardening commit itself (the 5 s deadline, the caps, the accounting change,
and the gating alignment all check out under the failure scenarios they address).

---

## Overall verdict: **SHIP**

No must-fix defects in the combined state. The two original fixes are mechanically sound,
the ordering invariant holds for the documented usage, and every round-1 must-fix was
addressed and verified in code.

**Follow-ups (non-blocking, priority order):**

1. Bound the server's post-shutdown read-drain loop (`server/session.rs:1197-1210`) with a
   deadline or byte cap — teardown can still hang there on a peer that never closes.
2. Optional hard cap for read-path-generated outbound (drop keepalives / refuse new
   CHANNEL_OPENs above a hard max) — the documented soft-bound follow-up.
3. Consider making pre-accept channel writes fail loudly (or park) instead of silently
   discarding; document the remaining inline-write bounded-send hazard
   (`channels/mod.rs:418-423`) for handler authors.
4. Cheap deterministic unit test for `flush_into` cursor/watermark behavior with a scripted
   mock `AsyncWrite`.
5. Optional: remove dead `pending_reads`/`pending_len` state.
