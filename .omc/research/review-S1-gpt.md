# S1 对抗评审：ConnSupervisor 接入现有 server loop

- 评审者：gpt-5.6-sol high
- 日期：2026-08-12
- 范围：`server/supervisor.rs`、`server/session.rs::run` 及必要的 config/writer/调用方语义追踪

## 判决：CONDITIONAL

当前 S0/S1 目标 suite 8/8 全绿，supervisor unit 3/3 全绿；但默认生产策略会误杀合法慢连接，write progress 在 `select!` cancel 时可丢观测，初始 KEX 也会被错归为 rekey timeout。以下均可在 S1 seam 内局部修复；修复并补回归后可 GO。

## S1 必修

### 1. P0 生产回归：`write_min_drain` 默认 ON 会误杀合法慢速下行

**定性：默认 `Some((4096, 30s))` 对通用 russh server 和当前 zfc 代理都不安全，必须默认 OFF。**

- 持续 `wire_eligible > 0` 时，该策略要求平均至少 4096/30 ≈ 136.5 B/s；对端即使一直有读进度，30s 内不足 4 KiB 也会被归为 `WriteStalled`（`russh/src/server/supervisor.rs:180-205`；默认值 `russh/src/server/mod.rs:117-129,164-168`）。协议上无法仅凭低吞吐区分恶意 trickle 和合法弱网/限速。
- 交互 shell 或 keepalive-only 空闲在 buffer 迅速清空时会 disarm，通常不误触发；但小输出/keepalive 若在慢 socket 上持续 pending 仍可被误杀。合法大文件或代理慢下载最危险：长期有 backlog 且低于阈值就必杀。
- zfc 的 config 使用 `..Default::default()`（`zfc/zf-worker/src/protocol/inbound/ssh/mod.rs:118-138`），会无意继承该 ON 策略，与移动网络/长下载用途冲突。

**最小修法：**库默认改为 `write_min_drain: None`；zfc 也显式写 `None`，避免后续默认漂移。保留 `Some((bytes, window))` 作为有明确最低带宽 SLA 的部署端 opt-in；不建议换一个更小的全局 ON 默认值。`write_progress_deadline=30s` 的“完全无 `Ok(n>0)`”活性层可继续默认开启。

### 2. P0 正确性：`flush_into` 被 cancel 后 partial write 永久丢观测

- `flush_into` 在每个 `w.write().await` 后先推进持久化 `flush_cursor`，但只把字节累加到 future 局部 `written`，必须整个 future 正常返回才会交给 watchdog（`russh/src/sshbuffer.rs:608-630`、`russh/src/server/session.rs:1212-1223`）。
- 若某次 socket `Ok(n>0)` 后下一次 write/flush 仍 pending，而 read/timer 臂赢得 `select!`，future 被 drop：字节不会重发（cursor cancel-safe），但 `note_write_ok` 也永远不发生。全双工活跃连接可真实持续写出却被看成零进度。当前“including partial progress before a cancel”注释与 future drop 语义不符。

**最小修法：**使每个 socket `Ok(n>0)` 立即可观测。可让 `flush_into` 每次最多执行一次 write 并立即返回 n；或在 `PacketWriter` 内维护单调 drained counter，每轮 `select!` 结束后用差额更新 watchdog。补“partial write 成功后 future 被另一臂 cancel”的回归测试。

### 3. P1 首因/握手边界：初始 KEX 被当作 rekey，handshake deadline 未覆盖全区间

- `run_stream` 对**初始** KEX 调用 `begin_rekey()`（`russh/src/server/mod.rs:1120-1143`），而后者无条件增 generation 并注册 rekey deadline（`russh/src/server/session.rs:1994-2016`）。该时钟早于 `run()` 内的 handshake 时钟；两者同为 30s 时，初始 KEX 卡死可先报 `RekeyTimeout`，而非 `HandshakeTimeout`（top-of-loop：`russh/src/server/session.rs:1053-1082`）。
- handshake 时钟直到初始 KEX 输出已经无定时器 `flush_into().await` 后才创建（`russh/src/server/session.rs:997-1029`）；server banner write/client banner read 在 spawn `run()` 前，read 只受默认 600s 的 inactivity timeout（`russh/src/server/mod.rs:1095-1119,1146-1154`）。所以“banner + initial kex + auth 整体 30s”并未实现。
- `reading`/`flush_into` future 与 timer 本身能正常竞争；但 read 臂赢后，`reply(...).await` 在臂体内执行（`russh/src/server/session.rs:1144-1181`）。它会 await KEX `lookup_dh_gex_group` 及 auth handler/拒绝延时（`russh/src/server/kex.rs:164-187`、`russh/src/server/encrypted.rs:650-980`），此期间 handshake/rekey timer 不被 poll，自定义 handler 可使 deadline 无界超时。

**最小修法：**

1. 只在 `common.encrypted.is_some()` / `KexCause::Rekey` 时注册 rekey generation/deadline；初始 KEX 只归 handshake。
2. 在 `run_stream` 入口生成绝对 `handshake_deadline_at`，同一 deadline 覆盖 banner write/read、初始 KEX 首次 flush，传入 session 继续覆盖 auth，不要中途重启 30s。
3. handshake/rekey 活跃时，把 `reply`/handler await 也纳入同一 absolute deadline 的 `select!`/`timeout_at`。

### 4. P1 策略时序/覆盖：sleep 忽略 min-drain deadline，集成用例也不是 trickle-read

- `supervisor_sleep` 只取 activity/rekey/handshake 的最小值，没有 `drain_window_start + min_drain.window`（`russh/src/server/session.rs:1129-1143`；`russh/src/server/supervisor.rs:210-219`）。窗口内一次小写重置 activity 后，策略层可超过自己的 window 继续睡到下一 activity 时刻。
- `s1_trickle_read_min_drain_on` 实际是 `freeze_read()`，activity deadline 和 min-drain window 都为 2s，完全可由 activity 层转绿（`russh/tests/test_malicious_client_s0.rs:403-460`）。OFF 案又把 activity deadline 改为 120s（`:463-517`），不是同一 trickle 负载的反向对照。harness 的 `set_trickle()` 没有任何用例调用（`russh/tests/harness/mod.rs:139-153`）。

**最小修法：**增加 min-drain remaining deadline 并纳入 `supervisor_sleep` 的 `min`；ON/OFF 使用同一 `set_trickle(<min_bytes, window)`、同一足够长的 activity deadline，仅切换 `write_min_drain=Some/None`，并断言 ON 在策略窗口附近拆除。

### 5. P1 拆除活性：`teardown_grace` 被叠加，`shutdown()` 不受界

supervisor 拆除先用完整 grace 等 flush，然后无 timeout await `stream_write.shutdown()`，再新建一个完整 grace 等 peer drain（`russh/src/server/session.rs:1271-1313`）。总时间可达 2×grace，通用 `AsyncWrite` wrapper 还可因 shutdown 永久 pending，违反“总 grace，不叠加，到期 drop socket”。

**最小修法：**进入 Cancelling 时只计算一个 `grace_at`，用单个 `timeout_at(grace_at, async { flush; shutdown; drain })` 包住全部 best-effort 拆除；到期立即 drop stream halves。

## 已核对，不构成 S1 blocker

- **`run() -> Err`：**typed supervisor `Err` 由 `RunningSession` 原样传递；`run_on_socket` 只交给单连接 `handle_session_error`，不终止 accept loop（`russh/src/server/session.rs:1315-1328`、`russh/src/server/mod.rs:998-1027,1081-1092`）。zfc 把它转成该 mux task 的 `anyhow::Err`（`zfc/zf-worker/src/protocol/inbound/ssh/server.rs:905-909`），影响限于已被拆的连接。修掉默认假阳性后，异常终止返 Err 的契约合理，应补 API 回归而不必改回 `Ok(())`。
- **rekey deadline 清理：**正常 `Done -> Idle` 立即 clear（`russh/src/server/mod.rs:1257-1262`）；KEX/strict-kex/handler 失败会直接终止 session，不会在活连接留旧 deadline；active KEX 不叠加新 generation，`active_rekey_gen()` 又有 `kex.active()` 门（`russh/src/server/session.rs:2020-2035`）。除初始 KEX 不该注册外，未见无关时刻误 fire 路径。
- **1ms sleep：**已过期 deadline 在下一轮 top-of-loop 即被消费，`max(1ms)` 本身不持续忙轮询。实质漏洞是未纳入 sleep 的 min-drain、臂体内 await 和拆除总 grace。

## S2+ 再补

- `WriteProgress` 当前只由 server session 单 task 内联读写，无并发观察者，S1 不会撕裂。S2/S3 分出 Writer/Supervisor 后必须改成单快照 release-store/acquire-load 或等价 watch，不能分字段原子化。
- 独立任务 panic/Err 的统一 cancellation broadcast、唤醒所有 waiter，以及跨任务 `RekeyTimeout(gen)` 首因快照，留到 S2/S3 真正拆分 ConnSupervisor/Writer/Session 时完成。
