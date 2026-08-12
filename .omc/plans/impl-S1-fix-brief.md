# S1 修复任务(第 1 轮对抗评审后)

S1 评审 **CONDITIONAL**(gpt-5.6-sol high + Claude)。目标 suite 8/8、supervisor unit 3/3 绿,
但有生产误杀 + 写进度丢观测 + 首因错归 + 策略层未真正测到 + 拆除 grace 叠加。5 条必修,均可在 S1 seam 内局部修。
完整评审见 `.omc/research/review-S1-gpt.md`(每条有精确 file:line 与最小修法)。先读它全文再动手。

## 必修 1(P0 生产回归):`write_min_drain` 默认改 `None`
默认 `Some((4096,30s))` 要求持续 ≥136 B/s,合法弱网/限速/慢下载(尤其 zfc 移动端长下载)会被误杀 `WriteStalled`。
协议上无法凭低吞吐区分恶意 trickle 与合法慢连。
- **库默认改 `write_min_drain: None`**(`server/mod.rs` Default)。活性层 `write_progress_deadline=30s`(完全无 `Ok(n>0)`)保持默认开——事故楔死由它捕获,不依赖策略层。
- 策略层保留为**部署方 opt-in**(有明确最低带宽 SLA 才开)。
- 注:zfc 侧用 `..Default::default()` 会继承,改默认即修复;无需改 zfc。

## 必修 2(P0 正确性):`flush_into` 被 cancel 后 partial write 丢观测
`flush_into` 每次 `w.write().await` 后推进持久 `flush_cursor`,但字节只累加到 future 局部 `written`;
若某次 `Ok(n>0)` 后仍 pending、而 read/timer 臂赢得 `select!` 使 future 被 drop → `note_write_ok` 永不发生。
**全双工活跃连接可真实持续写出却被判零进度 → 误杀。**
- **最小修法**(择一):(a) `PacketWriter` 内置单调 `drained_total` counter,每次 `w.write` 成功即自增;
  loop 每轮 `select!` 结束后用 `drained_total` 的差额喂 `note_write_ok`(cursor 与 counter 都持久,cancel 不丢);
  或 (b) `flush_into` 每轮最多一次 write 后即返回 n。**优先 (a)**(不改 select! 结构、不牺牲聚写)。
- 补回归测试:partial write 成功后该臂被另一臂 cancel,watchdog 不得误判停滞。

## 必修 3(P1 首因/握手边界):初始 KEX 错归 rekey + handshake deadline 未覆盖全区间
- `run_stream` 对**初始** KEX 也调 `begin_rekey()` → 注册 rekey deadline,初始握手卡死会先报 `RekeyTimeout` 而非 `HandshakeTimeout`。
- handshake 时钟在初始 KEX 首次 flush **之后**才建;banner write/client banner read 在 spawn `run()` 前,只受默认 600s inactivity。
- read 臂赢后 `reply(...).await` 在臂体内跑(含 gex 组查、auth handler/拒绝延时),此间 timer 不被 poll,handler 可使 deadline 无界。
- **最小修法**:
  1. **仅** `common.encrypted.is_some()` 或 `KexCause::Rekey` 时注册 rekey generation/deadline;初始 KEX 只归 handshake。
  2. `run_stream` 入口生成**绝对** `handshake_deadline_at`,覆盖 banner 收发 + 初始 KEX 首 flush,传入 session 继续覆盖到 auth,**不中途重启 30s**。
  3. handshake 未完成期间,把臂体内 `reply`/handler 的 await 用 `timeout_at(handshake_deadline_at, …)` 包住(超时→ `HandshakeTimeout` 拆)。若 3 触及 handler 语义超出 S1 seam,先做 1+2 并在报告标注 3 的范围,等裁决。

## 必修 4(P1 策略时序 + 覆盖):sleep 漏 min-drain deadline + trickle 用例没测策略层
- `supervisor_sleep` 只取 activity/rekey/handshake 最小值,**漏了** `drain_window_start + min_drain.window`——窗口内一次小写重置 activity 后,策略层可睡过自己的窗口。
- `s1_trickle_read_min_drain_on` 实为 `freeze_read()`、activity 与 min-drain window 都 2s → 完全可由**活性层**转绿,没证明策略层;OFF 案又把 activity 改 120s,不是同一负载反向对照;harness 的 `set_trickle()` 无人调用。
- **最小修法**:(a) `WriteWatchdog` 暴露 min-drain remaining,纳入 `supervisor_sleep` 的 `min`;
  (b) trickle ON/OFF 用**同一** `set_trickle(min_bytes, window)` 真 trickle 负载(每 (window/2) 发/读 < min_bytes)、**同一足够长 activity deadline**,只切 `write_min_drain=Some/None`;ON 必须在**策略窗口附近**被拆且首因 WriteStalled、OFF 不拆。

## 必修 5(P1 拆除活性):`teardown_grace` 叠加 + `shutdown()` 无界
现拆除:整 grace 等 flush → 无 timeout await `shutdown()` → 再一整 grace 等 drain,总可达 2×grace,且 generic `AsyncWrite` 的 shutdown 可永久 pending。违反「总 grace,不叠加,到期 drop socket」。
- **最小修法**:进入 Cancelling 只算**一个** `grace_at`,用单个 `timeout_at(grace_at, async { flush; shutdown; drain })` 包住全部 best-effort 拆除;到期立即 drop 两个 stream half。

## 不改(已核实非 blocker,别动)
- `run()→Err`:`run_on_socket` 只交单连接 `handle_session_error`,不终止 accept loop;zfc 仅影响被拆的那条 mux task。修掉误杀后此契约合理——**补 API 回归即可,别改回 Ok(())**。
- rekey deadline 清理(除必修 3.1 的初始 KEX 外)完备。
- `max(1ms)` sleep 非忙轮询。
- `WriteProgress` 非原子:S1 单任务无撕裂,S2/S3 再改原子快照——**本轮别提前做**。

## 交付
- 改 `server/supervisor.rs` / `server/session.rs` / `server/mod.rs` / `sshbuffer.rs` + harness/用例(必修 4 的真 trickle)。
- 远程编译 + 跑全 suite:S0 四用例仍翻绿且首因正确、trickle ON/OFF 真分层、他连零影响、现有 9 tests 全绿 + 新增回归(必修 2 的 cancel-不丢进度)。
- 更新 `.omc/research/impl-S1-report.md` 加「第 1 轮修复」,逐条给 5 必修闭合证据 + 必修 3.3 的范围申报(如触及 handler 语义)。
