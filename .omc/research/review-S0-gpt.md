# S0 对抗评审：恶意客户端 harness

- 评审者：gpt-5.6-sol high
- 日期：2026-08-12
- 范围：仅 S0 三件交付物；生产代码仅作因果核对

## 判决：CONDITIONAL

现交付能驱动现架构，也能稳定制造“连接仍活、应用 writer 停更”的表象；但尚未满足 S0 的唯一硬标准：四个用例没有各自锚定可区分的缺陷。`incident-repro` 与 `write-stall-during-rekey` 实质同构，且三条红路径都没有证明停滞时 §4.2 的 watchdog 应处于 armed 状态。按当前信号进入 S1，正确实现也可能不翻转，或因错误首因一起翻转。

闭合下列三项 S0 必修后可 GO；无需先实现 supervisor。

## S0 必修（阻断进 S1）

### 1. P1 用例没有隔离 `kex.active()`，与 write-stall 退化成同一个测试

**定位**

- `russh/tests/test_malicious_client_s0.rs:68-125`、`354-388`
- `russh/tests/harness/mod.rs:260-301`、`507-515`
- 因果路径：`russh/src/server/session.rs:1046-1048`，`russh/src/channels/io/tx.rs:82-107`
- 错误自证：`.omc/research/impl-S0-report.md:71-74,123,136-139`

**为何是实质问题**

两个用例都是：正常 flood → `freeze_read()` → `rekey_soon()` → 观察服务端 `writer.write_all` 停更并断言连接仍活。该停更同时可由三条路径造成：

1. 冻 TCP 后客户端不再产生 `WINDOW_ADJUST`，`WindowSizeRef` 归零，应用 writer 合法阻塞；
2. TCP 收窗填满，现 session 的 packet writer/high-watermark 反压应用入口；
3. 若 KEXINIT 确已被处理，`kex.active()` 关闭 receiver arm并把 bulk 留在 `pending_data`。

当前观测只记录第一个 `write_all` 完成了多少字节，不观测 server 是否进入 rekey，也不观测尚余 SSH 窗口或 wire-eligible 字节。删掉 `rekey_soon()`，现有断言仍可能通过。反过来，`rekey_soon().await` 只保证消息入 client 队列，固定 sleep 50 ms 也不是 KEXINIT 已上 wire/server 已进入 InKex 的证据。

因此 case1 不能证明 P1；S1 里只要 `WriteStalled` 或 `RekeyTimeout` 任一个能拆连接，两用例就会一起“转绿”，无法证明对应机制正确。仅把报告改称“复合锚”不满足本轮“四用例真实锚定各自缺陷”的硬门。

**最小修法建议**

- 为 case1 增加可判定的 KEX-only 故障：优先按 brief 下沉 raw-wire/测试侧协议注入，让客户端继续消费 bulk、持续返窗，只阻止本轮 KEX 完成；或使用等价的确定性测试闸，证明 server 已进入指定 kex generation 且 SSH 窗口仍有信用。
- 加负对照：相同 bulk/窗口条件但不进入 rekey 时，不得满足 P1 的停滞断言。
- 预先写死 S1 首因契约：case1 只能由 `RekeyTimeout(gen)` 转绿；case4 只能由 `WriteStalled` 转绿。首因导出本身可在 S1 加，见后文。

### 2. write-stall / talk-no-read 没证明 watchdog 应 armed，正确 S1 可能不拆

**定位**

- `russh/tests/test_malicious_client_s0.rs:151-220`（talk-no-read）
- `russh/tests/test_malicious_client_s0.rs:331-388`（write-stall-during-rekey）
- `russh/tests/harness/mod.rs:262-301,507-515,628-666`
- 目标规格：`.omc/plans/russh-proxy-session-rewrite.md:110-116`

**为何是实质问题**

§4.2 明确排除“仅因 peer-window=0 而不能 seal”的积压。现测试却很容易只造出这种合法状态：

- write-stall 使用默认 64 KiB SSH 窗口。冻读后最多再消耗这点信用，完全可能在 TCP 收窗填满前先归零；随后应用 writer 停更，但 `wire_eligible_bytes` 应为 0，正确 supervisor 不应拆。
- talk-no-read 在冻 TCP 前就把下行 channel 的应用消费者冻结，并只给 2 MiB 初始窗口；300 ms loopback flood 可能已经耗尽该窗口。测试甚至不要求 `report.stalled`，只断言连接仍活。因此即使场景已经退化为“合法零窗 + 持续上行”，当前红断言仍通过，S1 后也理应继续活。
- `Progress::note_bytes` 在整次应用层 `write_all` 成功后才计数，它既不是 socket `Ok(n>0)`，也不能证明还有 wire-eligible bytes。

这会直接破坏红用例的翻转性，不是观测精度上的小瑕疵。

**最小修法建议**

- 将两方向 SSH 窗口分开配置：客户端公布的下行窗口须显著大于故障期间可能消耗的量；服务端给上行 feeder 的窗口按速率 × 观察期单独计算。
- 在断言中证明停滞发生时尚未耗尽下行 SSH 信用，例如 `accepted + max_one_inflight_chunk < initial_peer_window`；也可在测试侧限制 TCP recv buffer，使“SSH 信用仍正、socket 已背压”可重复。
- talk-no-read 必须断言存在终态写停滞，而不只是 session 存活。
- case4 还必须证明指定 rekey 已开始且未完成；仅 `rekey_soon().await + sleep(50 ms)` 不足。

### 3. G2 用例没有证明已经到达并停留在 peer-window=0

**定位**

- `russh/tests/test_malicious_client_s0.rs:241-310`
- `russh/tests/harness/mod.rs:641-652`

**为何是实质问题**

用例只在 500 ms 后断言 `filled > 0`，随后无论 `Progress` 是否继续增长都只检查连接存活。于是“冻结消费者没有真正令窗口耗尽”也会绿；这种情况下未来错误的 armed predicate 根本没有被触发。当前构造会自然经过“最后一份信用被耗尽”的边沿，缺的是对该前置状态的验证，而不是再增加 close/EOF 变体。

此外，计划默认 watchdog/rekey deadline 是 30 s，而当前默认观察期仅 10 s。S1 若沿用默认值，即使错误 armed，测试也会在误杀发生前结束。

**最小修法建议**

- 先等待 `Progress` 在一个明确稳定期内不再增长（或增加测试侧剩余窗口观测），再开始 G2 观察并断言整个观察期仍保持零进度且 session 存活。
- S1 接入时给该测试配置短 watchdog deadline，并强制 `observe >= deadline + epsilon`。这一计时配置可等 S1 有 supervisor 配置后补，但“确已零窗”的断言属于 S0 必修。
- `secondary_mode=Idle` 正好符合本轮 §5 的反例定义；“另一 channel 仍可传输”以及 close-at-zero-window 属后续隔离/I3 矩阵，不是 S0 缺口。

## S1+ 再补（记录即可）

### A. 拆连首因与 client liveness 的断言契约

**定位：** `russh/tests/harness/mod.rs:208-219,251-257,432-457`；`test_malicious_client_s0.rs:108-125,212-220,373-388`

`FloodHandler::Drop` 的 authenticated 门控在本轮每测试只有一个真实鉴权连接时可靠，`wait_listening` probe 不会误置 `session_ended`；这里没有 S0 blocker。

但 TCP read 被冻结后，客户端无法读取 FIN/EOF，incident/case4 又没有持续写操作，因此 `session.is_closed()` 不保证随服务端拆除及时变 true。S1 翻转断言应以 server session end + supervisor 首因为权威；若还要求 client closed，先 `unfreeze_read()` 并有界等待。S1 同时应导出 `WriteStalled` / `RekeyTimeout(gen)` 首因，满足方案 S1 完成门“触发者是 supervisor”。

### B. 观察器应判“终态停滞”，并约束 env 组合

**定位：** `russh/tests/harness/mod.rs:264-301`；`test_malicious_client_s0.rs:43-44,331-332`

`observe_write_stall` 用历史 `max_idle`：中途长停后恢复，结束时仍会报 stalled；两个 rekey 用例再以 `stalled || end==start` 放宽，会掩盖无效的 `stall_for`。此外 `S0_OBSERVE_SECS < 4` 时 `stall_for=max(observe-2,4)` 大于观察期，env 调短会产生假失败。

最小修法：记录最后一次进度时间，只在观察结束时仍连续无进度达到阈值才判 stalled；移除 `|| end==start`；启动时 fail-fast 保证 `observe > stall_for`，或从 observe 安全推导阈值。talk-no-read 的上行初始信用也要随 observe 计算，避免长观察时 feeder 先耗尽信用、被 keepalive 拆除。

### C. server 启动与多连接复用

`free_addr()` 释放端口后再 bind，`wait_listening()` 无 deadline；端口被抢或 server bind 失败会永久挂测试。`chan_seq`/`Progress.session_ended` 又是 server 级共享，未来做 §5 的“他连零影响”时不能区分连接。这不影响当前四个单连接用例，但扩 harness 前应改为已绑定 listener + ready 信号，并把 channel ordinal/liveness 做成 per-connection。

## 已核对为可接受

- 红用例以“坏行为仍存在”保持当前 CI 绿，落法符合 S0 brief；问题在因果锚，不在红/绿表达方式。
- `FloodHandler::Drop` 的 auth 门控排除了 readiness probe；当前四用例的 `session_alive` 没发现竞态误报。
- zero-window-legit 只做应用层 consumer freeze、不冻 TCP，方向正确。
- “恰好耗尽窗口后的 EOF/fence”明确属于方案 S2/I3，不应塞回 S0。
- 未发现 `russh/src/**` 被 S0 修改。

## Coverage

| 检查项 | 覆盖 |
|---|---|
| S0 三件交付物 | exhaustive |
| 方案 §4.2 / §5 / S0-S1 完成门 | exhaustive |
| 四用例红因、翻转性、G2、liveness、env 时序 | exhaustive |
| 生产代码 | sampled：仅核对 channel writer/window、server session kex gate/keepalive、client rekey enqueue 路径 |
| 实际编译/运行 | skipped：实现报告已有远程 4/4 结果；本评审判决取决于静态因果，重复运行不能证明缺陷首因 |

## 进 S1 前检查单

- [ ] case1 的 KEX-only 故障与负对照能把 P1 从 TCP/窗口停滞中区分出来。
- [ ] talk-no-read 与 case4 证明停滞时 SSH 窗口仍有信用，且 case4 证明 rekey 已开始、未完成。
- [ ] zero-window-legit 证明窗口已耗尽并稳定，再断言不拆连。

三项闭合后：**GO**。若只改注释/报告而不改变可判定信号：仍为 **NO-GO**。
