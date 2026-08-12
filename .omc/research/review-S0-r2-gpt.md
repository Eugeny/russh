# S0 第 2 轮验证复审

- 评审者：gpt-5.6-sol high
- 日期：2026-08-12
- 范围：逐条复核 R1 三项必修，并检查本轮修复副作用

## 判决：CONDITIONAL

R1 的 P1 隔离与 G2 零窗锚已经闭合；NEWKEYS hold 在现架构下也未引入忙转、错钥或提前关连。但 watchdog armed 证明仍不成立，并且 case4 的新时序使它在 S1 下更可能由 `RekeyTimeout` 而非约定的 `WriteStalled` 拆除。以下两项必须在 S0 闭合后再进 S1。

## A. 三项必修复核

| R1 必修 | 结论 | 依据 |
|---|---|---|
| A1 P1 隔离 | **YES** | case1 不冻 TCP；client 到达并抑制 outbound NEWKEYS，可因果推出 server 已处理 KEXINIT/ECDH_INIT、进入 `WaitingForNewKeys`；TCP 有序且 server 在同一 step 写 ECDH_REPLY+NEWKEYS 后才返回。负对照在相同 flood/window、无 rekey 时持续流动。无需额外 server generation 观测。见 `test_malicious_client_s0.rs:80-143,154-214`、`client/kex.rs:312-329`、`server/kex.rs:287-319`。 |
| A2 watchdog 应 armed | **NO** | `assert_ssh_credit_remaining` 只证明故障后 growth `< initial_window/4`，不能证明故障瞬间剩余窗口大于 0；合法零窗的 growth=0 同样通过。case2/4 的 16 MiB 窗只是降低误判概率，不构成可判定信号。见 `harness/mod.rs:376-398`、`test_malicious_client_s0.rs:300-329,525-539`。 |
| A3 G2 已到零窗 | **YES** | 无 TCP fault、单 channel 冻消费者；先等 producer 连续稳定，再在整个 observe 内逐次断言 total 恒等且 session 存活。此处长期零进度是 peer-window=0 的充分代理。见 `test_malicious_client_s0.rs:383-430`、`harness/mod.rs:347-374`。 |

## B. 改变判决的实质问题

### 1. `growth < window/4` 不能证明剩余 SSH 信用，A2 仍是假信号 — S0 必修

**定位**

- `russh/tests/harness/mod.rs:376-398`
- `russh/tests/test_malicious_client_s0.rs:243-316,456-526`

**为何实质**

helper 假设冻结时 peer window 仍接近初始值，因而认为“合法零窗需要在 fault 后再增长约一整窗”。实际窗口是滑动信用；fault 发生前可能已有大量字节尚未被 WINDOW_ADJUST 补回。如下两种状态都会得到很小的 post-fault growth：

1. socket/HWM 已阻塞，但 SSH 信用仍正，§4.2 应 armed；
2. fault 时 SSH 信用已经为 0，只有合法窗口反压，§4.2 不应 armed。

尤其 growth=0 会无条件通过当前断言。`Progress` 又只是应用 `write_all` 完成字节，不是当前 peer window 或 `wire_eligible_bytes`。因此正确 S1 仍可能不拆 case2/4，使红用例不翻转。

**最小修法**

- 推荐给 flood 增加 start gate：先开 channel，确认尚未发送下行；冻结 TCP 后再放行 flood。这样 fault 起点信用确定为完整初始窗，`accepted + max_inflight < initial_window` 才能证明停滞时仍有信用。
- 或加 `_test_hooks` 只读导出 server 当前 recipient window，在断言点直接要求 `remaining > max_inflight`。
- `growth < window/4` 可保留作辅助阈值，不能单独承担 armed 证明。

### 2. case4 先 hold 完整 KEX 输出、再冻 TCP，实际没有 write stall 可武装 — S0 必修

**定位**

- `russh/tests/test_malicious_client_s0.rs:498-507`
- `russh/src/client/kex.rs:312-382`
- `russh/src/server/kex.rs:287-341`
- `russh/src/server/session.rs:1046-1048`

**为何实质**

case4 先等待 `wait_rekey_held`。该事件发生时 client 已收到并处理 server 的 ECDH_REPLY；server 在同一个 KEX step 中已把 ECDH_REPLY 与 NEWKEYS 写入 PacketWriter，随后进入 `WaitingForNewKeys`。TCP 此时仍可读，少量 KEX 输出及既有 staging 极可能已经排空。

之后才 `freeze_read()`，而 server 正处于 `kex.active()`：bulk 不再被 intake/seal，只留在应用/pending 队列。此时通常没有尚待 socket write 的密文，目标规格的 `wire_eligible_bytes` 应为 0。测试看到的应用 writer 停更仍是 kex gate，即与 case1 同构；冻结 TCP 对 server 写路径没有新增可阻塞对象。

结果是：

- 正确 S1 会由 `RekeyTimeout` 拆 case4，违反 `WriteStalled only` 契约；或
- 若翻转断言严格要求 `WriteStalled`，case4 永远不能转绿。

首因注释本身不能修复信号构造。

**最小修法**

- 先在“已证明 SSH 信用仍正”的状态冻结 TCP并确认 write path 已堵，再从仍可工作的 client 写半发起 rekey；增加最小 server test event，确认 KEXINIT 已被 server 接收、连接已进入 InKex。不要用“client 已收到 ECDH_REPLY”的 hold 事件作为冻结前置条件。
- S1 接入时同时固定时序：case4 的 write watchdog 必须早于 rekey deadline 到期；case1 则不得 armed write watchdog，只允许 `RekeyTimeout(gen)`。

闭合后，两用例才能形成真正的反向对照：case1 是 InKex 但 socket 可写；case4 是 InKex 且已有 wire-eligible 密文写不动。

## B. 已核对、不改变判决

### NEWKEYS hold 当前无忙转、错钥或提前关连

- `client/kex.rs:321-328,374-381` 返回 `NeedsReply` 后只在下一份入站 KEX 包到达时再次调用 `step`，没有自唤醒循环；正常交换中 held/dropped counter 各只增加一次量级。
- client 与 server 都只在 `KexProgress::Done` 后调用 `common.newkeys()`。client 抑制自己的 NEWKEYS并丢弃 server NEWKEYS后，双方都不能 Done，均留在旧 epoch；当前 hold 用例关闭 keepalive，server kex gate 又阻止后续 bulk，因此没有新钥密文导致 client 解密失败/提前关闭。
- hold 路径没有发出 client NEWKEYS，故 `reset_seqn:false` 合理；分支只在 `_test_hooks` 且 per-session gate armed 时生效，不污染普通 strict-kex 路径。

S1+ 注意：目标 Writer 规格会在发出 NEWKEYS 后立即安装 outbound epoch。到 S1/S2 迁移这段状态机时，当前“丢 inbound NEWKEYS”的 hold 可能造成错钥；届时须把 hook 改为在任一方安装新 epoch 前暂停，不能原样沿用。这不阻断当前 S0。

### feature 门控完整

`client::test_hooks`、`Config::rekey_hold`、Default 字段及两处 kex 分支均受 `#[cfg(feature="_test_hooks")]` 控制；无 feature 时 `Config` 形状与默认值不变。S0 test binary 又有 `required-features=["_test_hooks"]`。未发现非 feature 生产路径语义变化。

## S0 / S1 分界

**S0 必修：**

1. 用确定起点或当前窗口快照，真实证明 case2/case4 停滞时 SSH 信用仍正。
2. 重排 case4，使 rekey 期间确有 wire-eligible 密文卡在 socket，并能与 case1 首因分开。

**可挪 S1：**首因枚举导出、测试用短 deadline 与 `observe >= deadline + epsilon`、重写后 NEWKEYS hold 的 epoch 安装适配。

## Coverage

| 检查项 | 覆盖 |
|---|---|
| R1 三必修闭合性 | exhaustive（静态因果） |
| NEWKEYS hold 两处分支、client/server Done 装钥路径 | exhaustive |
| case1/case4 首因对打 | exhaustive |
| feature/Config/Default/test target 门控 | exhaustive |
| 生产 writer/window 与 session loop | sampled：只追与四用例信号有关的路径 |
| 实际编译运行 | skipped：实现报告已有远程 5/5；本轮阻断项是这些运行结果无法证明的因果前置条件 |

两项 S0 必修闭合后：**GO**。只调整阈值、注释或报告：仍为 **NO-GO**。
