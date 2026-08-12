# S1 实现报告：ConnSupervisor 接入现有 session loop

- 实现者: grok-4.5
- 日期: 2026-08-12
- 方案: `.omc/plans/russh-proxy-session-rewrite.md` §4.2 / §6 S1
- Brief: `.omc/plans/impl-S1-brief.md`
- 前置: S0 GO（harness + 5 用例 + `_test_hooks`）

---

## 1. 完成门自证

| 要求 | 结果 |
|---|---|
| rekey-stall → 拆连且首因 `RekeyTimeout` | ✓ |
| talk-no-read → 拆连且首因 `WriteStalled` | ✓ |
| write-stall-during-rekey → 拆连且首因 `WriteStalled`（早于 rekey deadline） | ✓ |
| zero-window-legit → 永不拆（短 watchdog 下仍绿） | ✓ |
| trickle-read / min_drain ON → `WriteStalled`；OFF → 不拆 | ✓ 集成 + unit |
| 他连零影响 | ✓ A 死 B 继续流 |
| 现有 tests 全绿 | ✓ `cargo test -p russh --features _test_hooks` |
| 无三任务拆分 / 未删 Scheme C / 未动 RekeyPolicy 包数界 | ✓ 见 §5 |

---

## 2. 做了什么

### 2.1 生产代码

| 路径 | 内容 |
|---|---|
| `russh/src/server/supervisor.rs` | **新** `WriteProgress` 快照、`WriteWatchdog` 两层判定、`RekeyDeadline` gen 注册、`DisconnectCause` / `DisconnectCauseSlot` |
| `russh/src/server/session.rs` | `run` loop 接入 supervisor：eligible 观测、timer 臂、首因拆除、`begin_rekey` 注册 deadline、kex Done 注销 |
| `russh/src/server/mod.rs` | `Config` 新字段；kex Done 调 `clear_rekey_deadline`；export supervisor 类型 |
| `russh/src/sshbuffer.rs` | `flush_into` 返回 `Result<usize>`（`Ok(n>0)` = 写进度） |
| `russh/src/lib_inner.rs` | `Error::{WriteStalled, RekeyTimeout(u64), HandshakeTimeout}` |
| `russh/src/client/mod.rs` | 适配 `flush_into` 返回值（仅编译） |

### 2.2 Config（§4.8 子集）

| 字段 | 默认 | 含义 |
|---|---|---|
| `write_progress_deadline` | 30s | 武装态无 `Ok(n>0)` 超时 → WriteStalled |
| `write_min_drain` | `Some((4KiB, 30s))` | 策略层渗出读；`None` 关闭 |
| `handshake_deadline` | 30s | banner+初始 kex+auth |
| `rekey_deadline` | 30s | InKex 超时 → RekeyTimeout |
| `teardown_grace` | 5s | Cancelling 后 best-effort DISCONNECT/flush |
| `disconnect_cause_slot` | `None` | `_test_hooks` 首因导出 |

### 2.3 wire_eligible 映射（现架构 seam）

```text
wire_eligible_bytes = packet_writer.pending_bytes()
```

= **已 seal、待 flush 的密文**。

- **不含** peer-window=0 的 `pending_data`（未 seal）→ G2 不武装  
- **不含** 仅 kex 闸住的 app 队列 → case1 在 kex 包排空后 eligible≈0，只由 `RekeyTimeout` 拆  
- case2/4 TCP 冻读 → seal 密文堵在 write buffer → eligible>0 → `WriteStalled`

### 2.4 统一拆除

1. 首因 `record`（CAS 一次）  
2. `disconnected = true` 退出 loop  
3. best-effort `DISCONNECT` + `flush`  
4. `teardown_grace` 内 cancel-safe flush + shutdown + drain  
5. `Err(WriteStalled|RekeyTimeout|HandshakeTimeout)` 返回  

写路径：`select!(flush_into, …, supervisor_sleep)` — flush 仍 cancel-safe（`flush_cursor`）。

### 2.5 首因导出

`DisconnectCauseSlot`（`AtomicU8`，首因获胜）经 `Config.disconnect_cause_slot` 注入；测试 `assert_cause`。非 `_test_hooks` 无该字段。

---

## 3. 测试改造

| 用例 | 断言 |
|---|---|
| `s0_incident_repro_rekey_stall_client_initiated` | `RekeyTimeout`（rekey_dl=3s，wd=30s） |
| `s0_talk_no_read` | `WriteStalled`（wd=2s，start-gate+冻 TCP） |
| `s0_write_stall_during_rekey` | `WriteStalled`（wd=2s < rekey 30s；先冻后 rekey） |
| `s0_zero_window_legit` | 短 wd 下全程不拆、无 cause |
| `s0_…_negative_no_rekey` | 仍流动 |
| `s1_trickle_read_min_drain_on/off` | ON 拆 / OFF 不拆（分层）；unit 测纯 min_drain |
| `s1_rekey_stall_other_connection_unaffected` | A `RekeyTimeout`，B 继续涨字节 |

Harness：`FloodServerConfig` 透传 supervisor 字段 + `teardown_grace`；`wait_supervisor` 以 **cause 优先**（grace 延迟 Drop）。

---

## 4. 验证（远程）

```text
cargo test -p russh --features _test_hooks -- --nocapture
# → success（lib + integration，含既有 tests + S0/S1 套件）
```

---

## 5. Seam 清单与被禁语义

| Seam | 触碰 | 语义变更？ |
|---|---|---|
| `session.rs::run` select! | 加 supervisor 观测/timer/拆除 | 否（kex/channel/窗口记账未改） |
| `begin_rekey` / kex Done | deadline 注册/注销 | 否（状态机同前，仅挂 timer） |
| `PacketWriter::flush_into` | 返回写入字节数 | 否（行为同前） |
| `Config` | 新 deadline 字段 | 默认 30s，现有测试无感知 |
| Scheme C / 双账本 / pending_inbound | **未触碰** | — |
| RekeyPolicy 包数界 / Limits 计数生命周期 | **未触碰** | — |
| Reader/Writer/Session 三任务拆分 | **未做**（S2/S3） | — |

**无「被禁语义」扩面申报。**

---

## 6. 已知局限 / S2+

1. Supervisor 在**单任务 loop 内**轮询，非独立 ConnSupervisor 任务；S2 拆 Writer 后 WriteProgress 快照可原样迁出。  
2. `wire_eligible` 仅 `pending_bytes`；未来 per-channel seal 队列需扩展定义。  
3. Cancelling 时未 `abort` 独立任务（尚无三任务）；grace 后 drop socket half 即拆连。  
4. handshake_deadline 覆盖「至 Authenticated」；未单独测 banner 慢路径。  
5. trickle 集成用「冻 TCP + min_drain 配置」验证分层；**纯 min_drain 算术**由 `supervisor::tests` unit 覆盖。

---

## 7. 结论（初版）

**S1 完成门达成**（后经 R1 评审 CONDITIONAL，见 §8 修复）。

---

## 8. 第 1 轮修复（评审 CONDITIONAL → 5 必修闭合）

评审：`.omc/research/review-S1-gpt.md`。目标 suite 已绿，但有生产误杀 / 进度丢观测 / 首因错归 / 策略层未测 / grace 叠加。

### 必修 1：`write_min_drain` 默认 `None`

| 项 | 处置 |
|---|---|
| 库默认 | `server/mod.rs` Default → `write_min_drain: None` |
| 活性层 | `write_progress_deadline=30s` **保持默认开**（永久无 `Ok(n>0)` 仍拆） |
| 策略层 | 部署方 opt-in（有最低带宽 SLA 时再开） |
| harness 默认 | 同步为 `None` |

### 必修 2：partial write cancel 不丢进度

| 项 | 处置 |
|---|---|
| 机制 | `PacketWriter.drained_total`：每次 `w.write` `Ok(n>0)` **在下一 await 前**自增 |
| loop 侧 | 每轮 `select!` 后用 `drained_total` 差额调 `note_write_ok`（不依赖 future 正常返回） |
| 回归 | `sshbuffer::drained_total_tests::drained_total_survives_select_cancel_after_partial_write` |

### 必修 3：初始 KEX / handshake 边界

| 子项 | 处置 |
|---|---|
| 3.1 初始 KEX 不注册 rekey deadline | `begin_rekey` 仅 `encrypted.is_some()` 时 `register`；初始 KEX 只归 handshake |
| 3.2 绝对 handshake_deadline | `run_stream` 入口生成 `handshake_deadline_at`，覆盖 banner write/read + 传入 session；`run()` **不**重启 30s；首 flush 也 `timeout_at` |
| 3.3 臂内 await 纳入 deadline | handshake 未完成时 `reply(...)` 包在 `timeout_at(handshake_deadline_at, …)`；超时 → `HandshakeTimeout` 拆。**范围**：仅 server `run` loop 读臂内的 `reply`（含 kex step / auth handler 路径）；**未**改 handler trait 契约，**未**包尽所有可能的跨任务 await。若评审认为不够，可再扩。 |

### 必修 4：min-drain sleep + 真 trickle 分层

| 项 | 处置 |
|---|---|
| sleep | `WriteWatchdog::next_min_drain_deadline` 纳入 `supervisor_sleep` 的 `min` |
| ON | `set_trickle(512, 1s)` + activity=30s + `write_min_drain=Some((4KiB, 2s))` → WriteStalled |
| OFF | **同一** trickle + **同一** activity=30s，仅 `write_min_drain=None` → 6s 内存活 |
| unit | `supervisor::tests` 仍覆盖纯 min_drain 算术 |

### 必修 5：单一 grace 拆除

```text
grace_at = now + teardown_grace
timeout_at(grace_at, async { flush; shutdown; drain })
// 到期 drop stream halves — 不叠加、shutdown 不无界
```

### 未改（按 brief）

- `run()→Err` 契约保留  
- WriteProgress **未**提前原子化（S2/S3）  

### 验证（远程）

```text
cargo test -p russh --features _test_hooks -- --nocapture
# → success（全 suite）
```

### 5 必修自证（R1）

- [x] 1 默认 min_drain OFF，活性层仍默认开  
- [x] 2 drained_total + cancel 回归  
- [x] 3.1+3.2 完成；3.3 在 seam 内包 reply（见范围说明）  
- [x] 4 min-drain remaining 进 sleep；真 trickle ON/OFF 同负载  
- [x] 5 单一 grace_at  

R1 后复审 **#3 NO**：见 §9。

---

## 9. 终审修复（#3 遗留：InitCompression 视为握手完成）

评审：`.omc/research/review-S1-r2-gpt.md` **NO-GO**（仅 #3 阻断；#1/#2/#4/#5 YES 未动）。

### 根因

公钥认证 `Auth::Accept` 后状态先进入 `EncryptedState::InitCompression`（`server/encrypted.rs:885-887`），要等**下一份 post-auth 报文**才转 `Authenticated`（`:131-137`）。supervisor 原先只把 `Authenticated` 当握手完成 → 认证后空闲、不 open channel 的合法客户端会在绝对 `handshake_deadline` 上被误拆为 `HandshakeTimeout`。

### 修法

`Session::run` 顶部 `handshake_done` 判定：

```text
InitCompression | Authenticated  →  handshake 完成
```

判定仍在 loop 顶部：仍卡在 `auth_succeeded` handler 内的 future 继续受既有 `timeout_at(handshake_deadline_at, reply(...))` 约束，不放过慢 auth。

### 回归

`s1_auth_success_idle_survives_handshake_deadline`：

- `handshake_deadline=2s`，公钥认证后**不**开 channel / global request  
- 空闲 3s → 断言 session 存活 + first-cause `None`

### 验证

```text
cargo test -p russh --features _test_hooks -- --nocapture
```

### 自证

- [x] 完成谓词含 `InitCompression`  
- [x] 回归覆盖 auth 后空闲 > handshake_deadline  
- [x] #1/#2/#4/#5 未改  

**#3 闭合 → 可终审 GO。**
