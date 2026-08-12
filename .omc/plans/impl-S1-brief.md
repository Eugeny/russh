# 实现任务 S1:ConnSupervisor 接入现有 session loop

S0 已 GO(harness + 5 用例 + `_test_hooks`)。本轮 **S1**:实现 `ConnSupervisor`(方案 §4.2 全规格),
接入**现有** server session loop,使 S0 红用例**翻绿且首因是 supervisor**。评审仍是 gpt-5.6-sol high + Claude 对抗循环。
方案:`.omc/plans/russh-proxy-session-rewrite.md` §4.1 拓扑 / §4.2 supervisor 规格 / §6 切片表。

## 完成门(硬标准,§6 S1 行)
> `write-stall / talk-no-read / trickle-read / zero-window-legit / rekey-stall` 全绿,
> **且断言触发者是 supervisor**(首因正确)。现有 9 个 tests/ 全绿。

即:S0 的 4 个红用例翻绿(case1 由 `RekeyTimeout` 拆、case2/case4 由 `WriteStalled` 拆),
`zero-window-legit` 保持绿(**永不误杀**),新增 `trickle-read` 用例(策略层 `write_min_drain` 拆、关闭策略则不拆)。

## 范围边界(避免过度设计 + 控风险)
- **本片只做 supervisor 接入,不做三任务拆分**(Reader/Session/Writer 独立是 S2/S3)。在**现有单任务 `tokio::select!` loop** 上:
  允许改 `select!` 结构、flush/write 钩子、加 CancellationToken 与定时器臂;**禁止**改 kex 状态机语义、channel 生命周期语义、窗口记账口径(那些是后续片)。
- **禁止**删 Scheme C / 双账本 / `max_pending_inbound_bytes`(S5)。**禁止**动 RekeyPolicy 包数界(S6)。本片 rekey/handshake **deadline** 要做,但 rekey 的**计数生命周期**不动。
- 若某子项必须触碰被禁语义才能达成完成门,**先停下在报告里说明**,不要擅自扩面。

## 必做(§4.2 规格,逐条)
1. **WriteProgress 原子快照**:`{ generation, last_write_ok_at, wire_eligible_bytes, drained_bytes_epoch }`,
   **单结构一次 release store 更新**,supervisor 一次 load,禁分字段读。现有 loop 的 socket write 点
   每次 `Ok(n>0)`(含 partial)更新它。`wire_eligible_bytes` 定义见 §4.2:staging 已 seal 密文 + 在制包 +
   因**窗口/调度以外**原因待 seal 的项;**不含**「仅因 peer-window=0 无法 seal 的 per-channel 积压」(G2 合法反压)、
   不含「仅在等 permit 的应用调用」。（在现架构里用现有 sshbuffer/flush 状态映射出该量;找准 seam,别新造账本。）
2. **写看门狗(两层)**:
   - **武装谓词(活性层)**:`wire_eligible_bytes > 0`;武装时钟只在 **idle→eligible 边沿**采样(`armed_at=now`),
     空闲恢复不得用旧 `last_write_ok_at` 立即误杀。
   - **进度判据**:自 `armed_at`/上次进度,任一 socket write `Ok(n>0)` 即进度。
   - **策略层 `write_min_drain`(默认 4 KiB/30s,可配可关,独立 counter)**:武装态窗口内累计写出 < 阈值 → 视同无进度。专杀渗出读。
   - 无进度 > `write_progress_deadline`(默认 30s)→ `Cancelling(WriteStalled)`。
3. **rekey/handshake deadline**:进入 InKex 注册 deadline(**watch + kex generation**,不走可满队列);
   supervisor 触发前**校验 generation 仍在 InKex**(消注销竞态误杀)→ `Cancelling(RekeyTimeout)`。
   banner/初始 kex/auth 整体受 `handshake_deadline`(默认 30s)。
4. **统一拆除**:任一 deadline/watchdog 触发或任务 Err/panic → **首因获胜** → 广播 CancellationToken →
   现有 loop 的每个 socket write 点是 `select!(write, token, …)` **cancel-safe** 结构,Cancelling 时立即弃当前 bulk write、
   best-effort 排一次 DISCONNECT;**总 grace(默认 5s,不叠加)**到期 → drop socket(现架构下即终止 loop/连接)→
   唤醒**全部** waiter 为 Err。Cancelling 期间看门狗停计时(grace 自带 timer)。
5. **首因可观测(测试可读)**:导出拆连首因枚举 `{ WriteStalled, RekeyTimeout(gen), HandshakeTimeout, PeerError, ... }`——
   test-only 导出即可(如 `_test_hooks` 下的 watch/AtomicU8,或 tracing 字段 + harness 抓取)。用例据此断言**首因正确**,不只是「连接被拆」。

## 用例改造(harness 复用 S0 基础设施)
- **翻绿 case1/2/4**:把 S0 的「KNOWN-RED 断言坏行为」翻成:supervisor 在 `deadline+ε` 内拆连 **且首因匹配契约**
  (case1=RekeyTimeout、case2/case4=WriteStalled)。`zero-window-legit` 保持绿(整 observe 期不拆)。
  测试给**短 deadline**(如 write_progress_deadline=2s、rekey_deadline=3s)并 `observe >= deadline+ε`。
  case4 需保证 **write-watchdog 早于 rekey deadline** 到期(见 §4.2 时序,B2 遗留项),使首因确为 WriteStalled。
- **新增 `trickle-read`**:每 ~29s 读 1 字节(或按短 deadline 缩放:每 (window+1)ms 读 1 字节使排空 < write_min_drain)。
  断言:开启 `write_min_drain` → 被拆(首因 WriteStalled/策略);**关闭该策略** → 不拆(验证分层)。
- **他连零影响**:rekey-stall/write-stall 拆连时,另开一条正常连接不受影响(§5「他连零影响」最小版,单独 Progress/连接)。

## 交付
- 生产:`ConnSupervisor` 实现(建议 `russh/src/server/` 下新模块)+ 接入现 server loop;`Config` 加 §4.8 新 config
  (`write_progress_deadline`、`write_min_drain`、`handshake_deadline`、rekey `deadline`;其余 S4+ 的暂不加)。
  首因导出走 `_test_hooks` 或 tracing。**非 `_test_hooks` build 行为**:supervisor 生效(这是生产特性),但测试观测钩子零成本。
- 测试:S0 四用例翻绿 + trickle-read + 他连零影响;现有 9 tests 全绿。
- 远程编译(`check`)+ 远程跑全 suite;**client 侧**若因 Scheme C 双端共享受影响需同改(仅限接入所需,别删)。
- 报告 `.omc/research/impl-S1-report.md`:逐条对应完成门 + 首因证据 + 触碰的 seam 清单 + 任何「被禁语义」触碰的申报。

先读 §4.1/§4.2/§4.4 与现 `russh/src/server/session.rs`(run loop ~982、kex.active 闸 ~1046/1108、teardown ~1191)、
`russh/src/session.rs`(Encrypted::flush ~758、rekey trigger ~798)、`russh/src/sshbuffer.rs`(HWM ~369)。保持每步全仓库编译 + 既有测试绿。
