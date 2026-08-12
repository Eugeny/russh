# Adversarial review: commit 94b3a20

**Repo:** BlackLuny/russh (HEAD `94b3a20`)  
**Scope:** Read-only review of `git show 94b3a20` — two deadlock fixes (unbounded channel-open replies; concurrent cancel-safe flush).  
**Lens:** Correctness, races/deadlocks, protocol, teardown. Style nits ignored unless they mask a real hazard.

---

## Summary

Both fixes attack real production stall modes and the core mechanisms look sound:

1. **Open-reply path** correctly escapes the bounded `Msg` queue self-deadlock, and the “drain replies before any channel `Msg`” rule preserves write-after-accept ordering across the split queues.
2. **Concurrent `flush_into`** is cancel-safe in the single-threaded session loop, and the high-watermark gate prevents unbounded *Handle-path* intake while a peer drains slowly.

I did **not** find a must-fix session-kill race in the claimed Fix‑1 ordering invariant under the intended accept-then-write usage. I did find one real teardown regression (server final flush), one real soft-bound gap in the watermark design (non-Handle outbound + client eager batch), and several consistency / dead-path over-engineering notes.

**Overall: FIX-FIRST** for the server shutdown flush error mapping; the rest is shippable with follow-ups.

---

## Focus area verdicts

### 1. Fix 1 ordering invariant — **OK** (with caveat)

**Evidence**

- `ChannelOpenHandleInner::{accept,reject}` now sync-`send` on an unbounded queue (`russh/src/lib_inner.rs:583–603`).
- Server: `dispatch_msg` starts with `drain_open_replies()` (`server/session.rs:826–827`); client: `handle_msg` same (`client/mod.rs:1467–1468`).
- Select arms also finalize deferred accepts (`server/session.rs:1120–1124`, `client/mod.rs:1335–1339`).
- Peer-initiated open builds `Channel` *before* insert into `enc.channels`; insert happens only in `finalize_*_channel_open_reply` (`server/encrypted.rs:1795–1815` + `server/session.rs:1391–1409`; client analogue).

**Why the invariant holds for intended use**

Under “`accept()` then first write”:

1. `accept()` enqueues the reply on `open_reply_*` *before* returning.
2. The writer’s first `Data` is enqueued on the *bounded* session/`inbound_channel` queue *after* that.
3. Any dispatch of that `Data` calls `drain_open_replies()` first, so the channel is inserted before `Encrypted::data*` runs.

Select-arm interleaving (receiver vs `open_reply_rx`) does not break this: even if `receiver` wins, `dispatch_msg`/`handle_msg` drains replies first.

**Caveat (not a regression of this commit, but the commit comment is wrong)**

For peer-initiated channels, a write dispatched *before* finalize does **not** hit `Error::WrongChannel` and kill the session. `Encrypted::data*` only returns `WrongChannel` when the channel **exists** and `confirmed == false` (`session.rs:648–649`). Missing map entry is a silent no-op (`session.rs:692–694` / drop path). So the real failure mode of a broken order is **silent data loss**, not session death. `drain_open_replies` still correctly prevents that for accept-then-write.

Write-*before*-accept was already racy when both messages shared one queue (Data could sit ahead of the reply). Not introduced here.

**Deferred accept from a spawned task:** covered by the kex-gated `open_reply_rx` select arm. OK.

**Verdict:** OK for the stated invariant.

---

### 2. Kex interactions — **OK**

**Can a reply be written mid-rekey?**

All finalization paths are kex-gated:

| Path | Gate |
|------|------|
| Server `open_reply_rx` arm | `if !self.kex.active()` (`server/session.rs:1120`) |
| Server `receiver` / batch drain | `can_receive_outbound` ⇒ `!kex.active()` (`server/session.rs:1048–1051`, `1149`) |
| Client open-reply / receivers | `can_receive_outbound` ⇒ `!kex.active()` (`client/mod.rs:1281–1283`, `1335`, `1358`, `1375`) |

`drain_open_replies` itself is not kex-aware, but every caller is. CHANNEL_OPEN can still be *handled* during rekey via `reply` → `server_read_encrypted` (non-kex fallthrough at `server/mod.rs:1245–1246`); `accept()` only queues. Finalize waits until kex is idle. Correct.

**Can pending replies starve forever?**

Only while `kex.active()` (or, on the client, while also above the write watermark — see §4). After kex completes, the open-reply arm or the next `dispatch_msg`/`handle_msg` drains them. No permanent starvation under a completing rekey.

`reset_seqn` only resets the sequence counter (`sshbuffer.rs:573–575`); it does not clear `write_buffer` or `flush_cursor`. NEWKEYS + later packets append after any still-unflushed pre-NEWKEYS ciphertext; the cursor walks the byte stream in order. Correct for SSH.

**Verdict:** OK.

---

### 3. Cancel-safety of `flush_into` — **OK** (minor notes)

**Implementation** (`sshbuffer.rs:595–612`):

- `flush_cursor` tracks bytes already handed to the socket.
- One `write` await per poll point → cancel-safe under `select!`.
- Buffer cleared and cursor reset only after a successful `w.flush()`.
- `WriteZero` on `n == 0` avoids a ready-spin.

**Partial write + later growth:** new packets only append (`write_payload_into_output` uses `offset = buffer.len()`). On the next `flush_into`, the loop continues from `flush_cursor`. OK in the single-threaded session task (no concurrent mutation during an await — only after cancel).

**Cancel during `w.flush()`:** cursor already equals `len`; next call re-enters `flush`, may write any newly appended tail, then flushes again. OK.

**Rekey / cipher swap with `flush_cursor > 0`:** cipher is only used when *building* packets; flush writes opaque bytes. Ordering stays old-ciphertext → NEWKEYS → new-ciphertext. OK.

**Callers assuming all-or-nothing flush:** run loops no longer `await` a full drain after every event; both add a final `flush_into` before `shutdown` (`server/session.rs:1189–1196`, `client/mod.rs:1203–1206`). Early `return Err(...)` paths (keepalive/inactivity/read errors) still skip that final flush — same class of “drop pending on error exit” as before for those arms, slightly more residual buffer possible now. Acceptable for error exits.

**Verdict:** OK.

---

### 4. Watermark gate — **SUSPICIOUS**

**No intake/flush livelock**

- Intake pauses when `pending_bytes() >= OUTBOUND_HIGH_WATERMARK` (`128 KiB`, `sshbuffer.rs:364`, `pending_bytes` = `len - flush_cursor`).
- Flush arm enabled on `has_pending()` (`!buffer.is_empty()`), **not** kex-gated.
- Whenever intake is paused due to watermark, `has_pending` is true, so the flush arm can run. No “gated forever with flush disabled” state.

**Soft bound, not a hard cap**

1. **Client eager `try_recv` batches ignore the watermark after the first message** (`client/mod.rs:1367–1372`, `1382–1387`): only the select condition checks `can_receive_outbound`; the inner `while !kex.active() { try_recv }` does not re-check `pending_bytes`. Queues are small (capacity 10), but a single large `ChannelDataAcked` / window-sized payload can encrypt far more than 128 KiB in one arm (default window **2 MiB**). Server batch drain is better (`MAX_MESSAGES_PER_BATCH = 64`) but also checks the watermark only once per loop (`server/session.rs:1051–1060`).

2. **Reading-path and timer outbound are not gated.** Window adjusts, kex traffic, keepalives, and (server) channel-open confirmations can still append while Handle intake is paused. That is intentional for full-duplex progress, but it means a peer that **stops reading while still sending** (or while we still emit keepalives because `received_data` resets `alive_timeouts`) can grow `write_buffer` without the watermark ever applying.

3. **Client open-reply arm is watermark-gated; server is not.**  
   - Server: `if !self.kex.active()` only (`server/session.rs:1120`).  
   - Client: `if can_receive_outbound` (kex **and** watermark) (`client/mod.rs:1335`).  
   Comments on the client arm claim “same kex gate as the receiver arms” — incomplete. Effect: under sustained outbound pressure, server-initiated open confirmations on the **client** are delayed until the buffer drains below 128 KiB. Not a permanent deadlock (flush still runs; tokio `select!` is fair), but extra open latency under load. Prefer server’s gate (`!kex.active()` only) for open replies — they are tiny and latency-sensitive.

**Verdict:** SUSPICIOUS — no livelock; bound is soft; client open-reply gating is stricter than needed.

---

### 5. Shutdown / teardown — **DEFECT**

**Server final flush is fallible; client is best-effort**

```text
server/session.rs:1191–1196  map_err!(packet_writer.flush_into(...).await)?;
client/mod.rs:1206             let _ = packet_writer.flush_into(...).await;
```

**Failure scenario**

1. Peer sends `DISCONNECT` (or closes) while this side still has pending ciphertext (common now that flush is concurrent and the DISCONNECT arm `break`s out of the loop before the per-iteration stage/flush).
2. Server hits the new post-loop `flush_into`.
3. Write fails with `BrokenPipe` / `ConnectionReset`.
4. `map_err!` turns a previously clean `Ok(())` session exit into `Error::IO`.

Pre-change, the server went straight to `shutdown()` after the loop without a final flush; in-loop flush had already emptied the buffer on every prior iteration, so peer DISCONNECT almost always exited cleanly. The new final flush is desirable for sending a local DISCONNECT, but **must not fail the whole run when the peer is already gone**.

**Also:** keepalive / inactivity / read-error paths still `return Err(...)` without the final flush — fine for hard errors; only the normal-exit path needs best-effort semantics.

**Verdict:** DEFECT — fix server to match client (`let _ =` or map only non-peer-gone errors).

---

### 6. `select!` borrow / fairness / busy-loop — **OK**

- Flush future mutably borrows `packet_writer` only inside its arm; other arms run after cancel; bottom-of-loop `flush()` runs after `select!` completes. No overlapping borrows.
- Fairness: tokio `select!` is fair among ready arms; open-reply vs receiver contention is OK given `drain_open_replies` in dispatch.
- Busy-loop: completed flush clears the buffer → `has_pending()` false next iteration. `n == 0` errors out. No ready-spin on a stuck socket (socket returns Pending).

**Verdict:** OK.

---

### 7. Other issues / tests — **OK** with notes

**Tests** (`tests/test_inbound_window_stall.rs`): open-sequence probes + `REPRO_EVENT_BUF` are diagnostic only; they do not weaken assertions. Fine.

**Drop of `ChannelOpenHandle`:** unbounded `send` no longer drops the rejection when the old bounded queue was full — real side fix. If the session is already dead (rx dropped), send still fails quietly; session is dying anyway.

**`accept`/`reject` remain `async` but never await:** API stability; fine.

**Silent drop of non-`ChannelOpenReply` on the open-reply queue:** only `ChannelOpenHandle` sends there; OK.

**Comment accuracy:** “WrongChannel” wording in `drain_open_replies` docs overstates the failure mode for peer-initiated opens (see §1).

**Verdict:** OK.

---

### 8. Over-engineering — **SUSPICIOUS** (noise, not wrong)

| Item | Assessment |
|------|------------|
| Dedicated unbounded open-reply channel + select arm + drain-at-dispatch | **Necessary** for Fix 1. Not overbuilt. |
| `Msg::ChannelOpenReply` arm in `dispatch_msg` (`server/session.rs:972–974`) and `Msg::ServerChannelOpenReply` in `handle_msg` (`client/mod.rs:1665–1667`) | **Dead for normal traffic** after the sender was moved to `open_reply_tx`. Harmless fallback if something still injects on the main queue; could be removed or left as belt-and-suspenders. Prefer delete + compile-time proof, or a debug_assert unreachable. |
| Long comments restating the deadlock story | Useful for this class of bug; slightly heavy but not harmful. |
| Hard-coded `OUTBOUND_HIGH_WATERMARK = 128 KiB` | Fine for a fix commit; config knob only if production needs tuning. Not required to ship. |
| Client open-reply sharing `can_receive_outbound` with data intake | **Extra mechanism vs need** — kex gate alone matches the server and the comment. |

Simplification that preserves both fixes: gate client open-reply on `!kex.active()` only; drop dead main-queue open-reply match arms (or assert).

**Verdict:** SUSPICIOUS (dead path + client gate asymmetry), not a functional blocker.

---

## Defects and suspicious items (actionable)

### DEFECT 1 — Server final flush can convert clean peer-disconnect into `Error::IO`

- **Where:** `russh/src/server/session.rs:1191–1196`
- **Scenario:** Peer closes after `DISCONNECT` (or RST) while local `write_buffer` still has bytes → `flush_into` fails → session `run` returns IO error instead of `Ok(())`.
- **Fix:** Mirror client: best-effort final flush (`let _ = ...`), then `shutdown()`. Optionally still surface flush errors when *we* initiated disconnect and need to deliver our DISCONNECT, but never fail “peer already gone” clean exits.

### SUSPICIOUS 1 — Watermark is soft; non-Handle outbound unbounded

- **Where:** flush arm + keepalive/read paths vs intake gate (`server/session.rs:1048–1145`, `client/mod.rs:1281–1330`, `sshbuffer.rs:364`)
- **Scenario:** Peer stops draining our TCP write but still produces enough traffic (or we keep sending keepalives while `received_data` clears timeouts) → `write_buffer` grows past 128 KiB without the gate applying.
- **Mitigation (optional follow-up):** hard cap on `write_buffer.len()` (drop keepalives / delay window adjusts / stop accepting new CHANNEL_OPENs when over hard max), or apply watermark to timer-generated packets. Do not re-serialize flush with reads.

### SUSPICIOUS 2 — Client open-reply arm unnecessarily watermark-gated

- **Where:** `russh/src/client/mod.rs:1335` (`if can_receive_outbound`)
- **Scenario:** Heavy client→server upload keeps `pending_bytes` high → server-initiated channel confirmations delayed.
- **Fix:** `if !self.kex.active()` only, matching server.

### SUSPICIOUS 3 — Client eager `try_recv` does not re-check watermark

- **Where:** `russh/src/client/mod.rs:1367–1372`, `1382–1387`
- **Scenario:** One select win drains the whole capacity-10 queue and encrypts window-sized payloads → multi‑MiB spike above the soft watermark.
- **Fix:** Re-check `pending_bytes() < OUTBOUND_HIGH_WATERMARK` in the inner loop (and/or adopt a server-style batch cap).

### Note — Dead open-reply match arms on the main `Msg` queue

- **Where:** `server/session.rs:972–974`, `client/mod.rs:1665–1667`
- Safe to delete if you want less surface; keep only if you want a panic-on-unexpected for diagnostics.

---

## What looks correct (do not “simplify” away)

1. Unbounded open-reply channel — required; bounded send from an in-loop handler is the original deadlock.
2. `drain_open_replies` before channel `Msg` dispatch — required for accept-then-write across split queues.
3. Cancel-safe `flush_cursor` + flush as a `select!` arm — required for full-duplex progress and timer liveness.
4. Handle-path watermark — required so concurrent flush does not let Handle producers grow memory without bound.
5. Drop → unbounded send for default reject — required so full queues do not leave opens unanswered.

---

## Overall verdict: **FIX-FIRST**

| Priority | Item |
|----------|------|
| **Must-fix before ship** | Server final `flush_into` should be best-effort (DEFECT 1). |
| **Should-fix soon** | Client open-reply gate = kex-only (SUSPICIOUS 2). |
| **Follow-up** | Soft watermark documentation / optional hard cap; client try_recv re-check (SUSPICIOUS 1 & 3); remove dead main-queue open-reply arms. |

With DEFECT 1 fixed, the two deadlock fixes are worth shipping for the stated production reverse-proxy load. I would not block on the soft watermark alone: it is a boundedness refinement, not a reintroduction of the original permanent stalls.
