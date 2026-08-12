# S0 修复任务(第 1 轮对抗评审后)

评审结论 **CONDITIONAL**(gpt-5.6-sol high + Claude 交叉,收敛一致)。
完整评审见 `.omc/research/review-S0-gpt.md`。三条必修都是**信号有效性**问题——
红用例现在可能「因错误的原因通过」,导致 S1 装上 supervisor 后**不翻转**或**因错误首因一起翻转**。
逐条闭合,不要只改注释/报告(那样仍判 NO-GO)。

## 贯穿原则:避免过度设计
每条修复取「能让信号可判定的最小改动」。**必修 1** 若你发现所需钩子超出「一个 cfg/feature 门控的
小注入点」,先停下在报告里说明成本,等裁决——**不要**擅自造整套 raw-wire SSH 客户端。

---

## 必修 1:隔离 P1(incident-repro 必须与 write-stall 可区分)
**问题**:case1 与 case4 手法同构(都 `freeze_read()`+`rekey_soon()`)。TCP 冻结同时造成
①客户端不再返窗→合法零窗、②TCP 收窗填满→背压、③kex.active 闸。当前只测「writer 停更+连接活」,
删掉 `rekey_soon()` 断言仍会通过。所以 case1 证明不了 P1;S1 里 `WriteStalled` 或 `RekeyTimeout`
任一能拆连,两用例就一起转绿,无法验证各自机制。

**要求**:让 case1 变成 **KEX-only 故障**——客户端**继续正常消费 bulk、持续返还窗口、TCP 不冻**,
只阻止**本轮 KEX 完成**。这样出站停滞只可能来自 kex.active 闸,与 TCP/窗口背压隔离。
- 最小实现路径(优先级从低成本到高):
  1. **客户端 test-gated 注入钩子**:`#[cfg(test)]` 或 `feature = "_test_hooks"` 门控,在 client
     transport 收到/即将处理 NEWKEYS(或 KEX_ECDH_REPLY)时**丢弃/无限延迟**该步,其余数据/窗口照常。
     这是「注入点」不是语义改动——非 test build 零影响。若走这条,把钩子加在 client 收包分发处,
     用一个 `AtomicBool`/回调门控。**这是允许的最小生产触碰**(brief 原「不改生产」在此让位于硬门,
     但必须 feature/cfg 门控 + 报告列清)。
  2. 若 1 不可行才考虑 raw-wire——**先回报**,不要直接上。
- **加负对照**:同样 bulk+窗口条件但**不进入 rekey**时,P1 停滞断言**必须不成立**(证明 case1 抓的是 rekey)。
- **首因契约**(写进注释,S1 落):case1 只能由 `RekeyTimeout(gen)` 转绿;case4 只能由 `WriteStalled` 转绿。

## 必修 2:write-stall / talk-no-read 必须证明 watchdog **应** armed(而非合法零窗)
**问题**:§4.2 明确排除「仅因 peer-window=0 不能 seal」的积压。现测试很容易只造出这种合法状态:
- write-stall 用默认 64 KiB 窗,冻读后可能在 TCP 收窗填满**前**就把 SSH 窗口耗尽归零→合法零窗,正确 supervisor 不该拆→红用例永不翻转。
- talk-no-read 冻 TCP 前就冻了下行消费者且只给 2 MiB 窗,300ms flood 可能已耗尽;且它**只断言连接活**,不要求 `report.stalled`——场景退化成「合法零窗+持续上行」时红断言照样过。

**要求**:
- 两方向 SSH 窗口分开配置:下行(client 公布)窗口须**显著大于**故障期间可能消耗量;上行 feeder 窗口按 `速率 × 观察期` 单独算,别让 feeder 自己饿死被 keepalive 拆。
- 断言中**证明停滞时下行 SSH 信用尚未耗尽**:如 `accepted + 单块最大 inflight < 初始 peer window`;或测试侧限制 TCP recv buffer,造出「SSH 信用仍正、socket 已背压」的可复现态。
- **talk-no-read 必须断言存在终态写停滞**,不能只断言 session 存活。
- **case4 必须证明指定 rekey 已开始且未完成**(仅 `rekey_soon().await + sleep(50ms)` 不足;配合必修 1 的钩子/观测即可)。

## 必修 3:G2 用例必须证明**已到达并停留在** peer-window=0
**问题**:只在 500ms 后断言 `filled > 0`,之后不管窗口是否真耗尽都只查连接活。若「冻结消费者没真正耗尽窗口」也会绿,未来错误的 armed-predicate 根本没被触发→G2 防线形同虚设。

**要求**:
- 先等 `Progress` 在一个明确稳定期内**不再增长**(或加测试侧剩余窗口观测),再开始 G2 观察;
  断言**整个观察期零进度 + session 存活**。
- 计时:S1 接入时给该测试**短 watchdog deadline** 且强制 `observe >= deadline + ε`(计划默认 deadline 30s,当前 observe 仅 10s——错误 armed 也会在误杀前结束)。计时配置可等 S1 有 supervisor 配置后补,但**「确已零窗」断言属 S0 必修,现在做**。

---

## S1+ 再补(本轮**只记录**,别实现)
- A. 拆连首因契约 + client liveness:冻读后 `session.is_closed()` 不保证及时变 true;S1 翻转断言以 **server session end + supervisor 首因**为权威,需要时先 `unfreeze_read()` 有界等待。S1 导出 `WriteStalled`/`RekeyTimeout(gen)` 首因。
- B. `observe_write_stall` 改判**终态**停滞(记录最后进度时刻,仅结束时仍连续无进度达阈值才判 stalled);移除 `|| end==start`;启动 fail-fast 保 `observe > stall_for`。
- C. server 启动/多连接:`free_addr` 释放后再 bind 有竞态、`wait_listening` 无 deadline;`chan_seq`/`session_ended` 是 server 级共享——扩「他连零影响」矩阵前改 per-connection + 已绑 listener ready 信号。

---

## 交付
- 改 `russh/tests/harness/mod.rs` + `russh/tests/test_malicious_client_s0.rs`(必要时最小 test-gated 生产钩子)。
- 远程编译 + 跑 4 用例(红仍红/绿仍绿,但现在**信号可判定**);负对照用例也要过。
- 更新 `.omc/research/impl-S0-report.md`:逐条对应三必修的闭合证据 + 若加了生产钩子,列清门控方式与影响面。
- 把改动摘要追加到报告末尾「第 1 轮修复」小节。

先读 `.omc/research/review-S0-gpt.md` 全文,再动手。
