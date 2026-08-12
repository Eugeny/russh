# Adversarial review: `94b3a20`

## Summary

The two main mechanisms are directionally sound: moving channel-open decisions off the
bounded session queue removes the reproduced `accept().await` self-deadlock, and
`PacketWriter::flush_into` correctly remembers partial `write` progress across cancellation.
However, the commit does not establish its claimed ordering invariant for deferred accepts,
and moving writes into `select!` introduces both an unbounded-output path and teardown hangs.

Risk: **HIGH**. Overall verdict: **FIX-FIRST**.

## 1. Channel-open reply ordering — DEFECT

### [high] Deferred acceptance can let channel traffic run before the channel exists

Evidence:

- Incoming handlers receive a usable `Channel` immediately, backed by the ordinary bounded
  session sender (`russh/src/server/encrypted.rs:1795-1815`,
  `russh/src/client/encrypted.rs:754-774`).
- The channel is not inserted into protocol/application maps until the reply is finalized
  (`russh/src/server/session.rs:1391-1410`, `russh/src/client/mod.rs:1677-1695`).
- `dispatch_msg`/`handle_msg` drain only replies already present at that instant and then
  dispatch the channel message (`russh/src/server/session.rs:810-839`,
  `russh/src/client/mod.rs:1454-1539`). If a deferred reply has not arrived, shared
  `Encrypted::data_with_writer` finds no channel and silently returns success after discarding
  the payload (`russh/src/session.rs:665-695`).
- The public handler documentation only says the handle must be accepted or rejected; it does
  not prohibit using the supplied channel before acceptance
  (`russh/src/server/mod.rs:371-383`, `russh/src/client/mod.rs:2736-2751`).

Concrete failure scenario:

1. A handler moves `Channel` to a producer task and moves `ChannelOpenHandle` to a separate
   authorization task, then returns (the new select arm explicitly claims to support a stashed,
   later-accepted handle).
2. The producer enqueues `Data`, `Eof`, `Close`, or a request before authorization completes.
3. The session dequeues that message; `drain_open_replies()` is empty, so the message is
   processed against a channel not yet installed. Data is silently discarded and controls are
   no-ops.
4. Authorization then calls `accept()`. The channel is confirmed, but the earlier traffic is
   not replayed. The producer observed a successful bounded-channel send, so this is silent
   application data loss/protocol-state loss.

There is also a remaining self-deadlock variant: if the bounded session queue is already full
and an inline handler calls `channel.data_bytes(...).await` before `reply.accept().await`, the
send at `russh/src/channels/mod.rs:384-422` waits for the same run loop currently executing the
handler. Moving only the reply to an unbounded queue does not protect this allowed ordering.

The invariant in the new comments (for example `russh/src/server/session.rs:810-813`) is thus
an application convention, not something the implementation guarantees. The fix must either
make pre-accept channel messages wait behind the decision or make the supplied channel
unusable until acceptance; documentation alone would not repair the silent-loss race for
existing callers.

## 2. KEX interactions — OK

All paths that call `dispatch_msg`/`handle_msg` are kex-gated: the server batch and receiver
paths use `can_receive_outbound` (`russh/src/server/session.rs:1048-1060,1147-1152`), and both
client receivers use the same gate (`russh/src/client/mod.rs:1281-1283,1358-1387`). The eager
client drains re-check `!self.kex.active()` on each iteration. Therefore the implicit reply
drain at the top of those functions does not finalize a reply mid-rekey.

The ungated flush arm writes already-encoded bytes in buffer order. Cipher replacement and
post-kex pending-data generation append packets after the old-key `NEWKEYS` bytes rather than
rewriting the buffered prefix (`russh/src/session.rs:130-146`,
`russh/src/client/mod.rs:2043-2052`, `russh/src/server/mod.rs:1196-1205`). I found no cipher-swap
or sequence-number violation in that ordering.

A peer that starts but never completes a non-strict rekey can still postpone an open reply
indefinitely, but all ordinary outbound work was already kex-gated in this way; it is not a new
path created by this commit.

## 3. `flush_into` cancellation safety — DEFECT

### [medium] A pending `flush()` defeats the memory watermark

The partial-write cursor itself is cancel-safe: it advances only after a successful `write`,
`WriteZero` terminates instead of spinning, and there is no cancellation point between a
successful `flush().await` and clearing/resetting the buffer
(`russh/src/sshbuffer.rs:596-612`). Appending encoded packets between polls also preserves byte
order.

The retained-buffer accounting is not safe, however. `pending_bytes()` excludes the entire
already-written prefix (`russh/src/sshbuffer.rs:583-585`), while that prefix remains allocated
and present until `w.flush()` completes (`russh/src/sshbuffer.rs:606-611`). Both run loops use
that reduced value as their memory gate (`russh/src/server/session.rs:1048-1050`,
`russh/src/client/mod.rs:1281-1283`).

Concrete failure scenario:

1. A valid generic `AsyncWrite` accepts writes into its own buffer but returns `Pending` from
   `poll_flush` while its underlying transport is backpressured. (`run_stream`/`connect_stream`
   accept arbitrary `AsyncRead + AsyncWrite`, not only a TCP half.)
2. `flush_cursor == write_buffer.len()`, so `pending_bytes()` reports zero even though the
   retained `Vec` may already be large.
3. Another select arm wins and appends more packets. Intake remains enabled; the next flush
   writes the suffix and again parks in `flush()`.
4. Repeating this grows both the retained packet buffer and the writer's accepted backlog
   without the advertised 128 KiB bound.

The gate needs to account for memory actually retained (or the writer must safely discard the
written prefix before a pending flush). The current implementation is usually hidden by
`TcpStream::poll_flush` being effectively immediate, but it violates the generic stream API.

## 4. Watermark/liveness — DEFECT

### [high] Inbound-generated output bypasses the only high-watermark gate

The watermark gates only application message receivers
(`russh/src/server/session.rs:1048-1069,1147-1156`,
`russh/src/client/mod.rs:1281-1283,1358-1388`). The read arm remains enabled while the socket
write is blocked (`russh/src/server/session.rs:1071-1109`,
`russh/src/client/mod.rs:1284-1316`), as it must for the full-duplex fix, but processing inbound
packets can itself create arbitrary outbound data: channel-open confirmations, window adjusts,
request replies, kex replies, and handler calls such as `session.data()`.

The new reply queue is also unbounded (`russh/src/lib_inner.rs:564-585`) and “one reply per peer
CHANNEL_OPEN” is not a total bound: a peer can have arbitrarily many opens over the lifetime of
the connection. On the server, the open-reply arm is not watermark-gated at all
(`russh/src/server/session.rs:1117-1125`); on the client it is gated, but accepted decisions can
continue accumulating in the unbounded queue while the read arm processes more opens
(`russh/src/client/mod.rs:1332-1340`).

Concrete failure scenario:

1. The peer stops reading its TCP receive half, so our flush arm stays pending, but continues
   writing requests/open packets to us on the independent TCP direction.
2. Inline handlers accept opens and/or generate output. The read arm keeps consuming input;
   received traffic continually resets inactivity/keepalive state.
3. Confirmations and other replies accumulate in `open_reply_rx`, `Encrypted::write`, the
   packet writer, and accepted-channel maps. The Handle-receiver watermark never gates this
   source.
4. Memory grows without bound while the connection remains active. The old synchronous flush
   incidentally applied TCP backpressure after the first response; this commit removes that
   bound without replacing it for read-generated output.

There is no basic livelock when `write` returns zero or an error: those cases terminate the
session. The defect is unbounded intake/output while `write` remains legitimately pending.

## 5. Shutdown/teardown — DEFECT

### [high] Final flush can hang forever after the loop has already timed out or disconnected

The server unconditionally awaits a full flush after breaking from the run loop
(`russh/src/server/session.rs:1188-1197`). The client does the same after every `run_inner`
result, including errors and timeout errors; ignoring the returned error does not make the
await best-effort (`russh/src/client/mod.rs:1190-1207`). Neither call has a deadline or
cancellation path.

Concrete failure scenarios:

- A peer stops reading, causing an in-loop flush to remain pending, then sends SSH DISCONNECT
  or closes its write half. The read arm wins and exits the loop. Teardown immediately awaits
  the same blocked write forever, so the session task and disconnected callback never finish.
- On the client, the keepalive or inactivity timer can correctly win the concurrent select and
  return an error from `run_inner`, but outer `run` then blocks forever in the added final
  flush. Thus the commit's claimed timer “hard backstop” is not actually a backstop on the
  client.
- If the socket is already dead, the server maps the added flush error out of `run`, potentially
  replacing what was previously a graceful received-disconnect/EOF teardown with an I/O error.

Only a locally initiated graceful disconnect has a reason to attempt to deliver a buffered
DISCONNECT packet. Remote-disconnect, EOF, timeout, and I/O-error exits must not wait
indefinitely to drain a dead/backpressured peer.

## 6. `select!` borrows/fairness — OK

The select macro can borrow the packet writer for the flush future because other arms mutate
session state only after losing futures have been dropped. `flush_cursor` persists outside the
future, so cancellation does not repeat a successful partial write. `Ready(0)` becomes
`WriteZero` and immediate errors propagate (`russh/src/sshbuffer.rs:596-605`), so neither
creates a ready-loop. Tokio select fairness is adequate for ordinary ready arms; it does not
repair the unbounded-source and final-flush defects above.

## 7. Other changes and test coverage — SUSPICIOUS

The changed integration test adds diagnostic `eprintln!` probes and a queue-size environment
knob (`russh/tests/test_inbound_window_stall.rs:125-128,317-323,353-360`) but no deterministic
assertion for the new mechanisms. In particular, there is no test for:

- partial write followed by cancellation and buffer growth;
- cancellation while `poll_flush` is pending;
- deferred accept racing channel data/control messages;
- rekey with a partially written old-key buffer;
- disconnect/timeout while the write half is blocked; or
- bounding replies generated from continuously readable inbound traffic.

Executed during review:

- `cargo test -p russh --lib sshbuffer -- --nocapture`: 12 passed.
- `test_inbound_window_stall`: passed (45.72 s).
- `test_rekey_strict_kex`: passed.
- `test_rekey_under_load`: passed (32 MiB, 34 kex completions).

Those successes validate the happy/stress paths but do not cover the failure scenarios above.

## 8. Over-engineering/simplification — SUSPICIOUS

The dedicated reply queue and resumable cursor are justified by the two deadlocks; they are
not inherently over-designed. There is minor mechanism drift:

- `Msg::ChannelOpenReply` and `Msg::ServerChannelOpenReply` remain explicitly handled in the
  ordinary receiver dispatch matches (`russh/src/server/session.rs:972-974`,
  `russh/src/client/mod.rs:1665-1667`) even though all constructors now send them exclusively to
  `open_reply_tx`. Those arms are dead paths and obscure the two-queue invariant.
- The same invariants are restated in field, helper, and select-arm comments, while the most
  important precondition—do not use the channel before acceptance—is neither enforced nor
  documented.

Removing the dead ordinary-queue arms and consolidating the comments would simplify the code,
but these are not ship blockers. The fixed 128 KiB constant is reasonable as an internal
starting point; correctness matters more than making it configurable until the missing output
sources and retained-prefix accounting are addressed.

## Overall verdict — FIX-FIRST

Must fix before shipping:

1. Enforce ordering/state for **all** messages emitted from an incoming `Channel`, including
   deferred accepts and pre-accept writes; do not silently discard messages that beat the
   decision.
2. Bound output generated by the read arm and the unbounded open-reply path when the socket
   write is backpressured.
3. Make watermark accounting include memory retained while `poll_flush` is pending (or safely
   release the written prefix).
4. Do not perform an unlimited final flush on remote-disconnect, EOF, timeout, or error paths;
   preserve the original exit reason and guarantee teardown completion.
