# 实现任务 S0:恶意客户端 harness + 事故复刻 + 基线用例

你是本重构的**实现者**(grok-4.5 high)。Claude + gpt-5.6-sol high 会对抗评审你的产出。方案全文见
`.omc/plans/russh-proxy-session-rewrite.md`(§5 测试矩阵、§6 切片表)。本轮只做 **S0**。

## S0 完成门(唯一硬标准)
> harness 能驱动**现架构**(未重构的 server session loop)并**暴露已知缺陷**。

即:写一个可复用的 raw-wire / 故障注入客户端 harness,用它复刻 2026-08-10 事故,并落几个基线用例。
对现架构**允许红**(事故用例预期挂),这正是后续切片要修的靶子。

## 强约束(避免过度设计)
- **不要**把 §5 那张大矩阵一次性实现完。S0 只做下面「必做用例」4 个。其余矩阵项属 S1–S8。
- **不改任何 `russh/src/**` 生产代码**。S0 纯测试侧。若发现必须加测试钩子(如暴露某内部构造),
  先在报告里列出「最小钩子清单」等评审,不要擅自改生产路径语义。
- 优先**复用 russh 现有 client 能力**;只有正常 client 做不出的故障(发起 rekey 后拖住不发
  NEWKEYS、停读但持续上行、raw KEXINIT 洪泛)才需要下沉到 raw-wire 或注入层。
  能用 `russh::client` + 冻结消费者复刻的,就别手搓密码学。
- 参考现有测试风格:`tests/test_rekey_under_load.rs`(client-initiated rekey + 冻结消费者)、
  `tests/test_inbound_window_stall.rs`(env 可调、多 channel flood)。保持同样的 env 可调 + `--nocapture` 风格。

## 必做用例(4 个,来自 §5「恶意客户端 harness」表)
1. **incident-repro / rekey-stall(client-initiated)**:复刻 2026-08-10——传输跨过 volume rekey 阈值,
   客户端发起 rekey 但在饱和下行下**不完成**(拖住 NEWKEYS),验证现架构 server 出站被 `kex.active()`
   永久闸死。断言:现架构下**超 deadline 仍未拆连/未推进**(记录为已知红)。若现架构默认关掉了 volume
   rekey(fork 止血),用 server 端 `rekey_write_limit` 极小值 + client `rekey_soon()` 强制触发。
2. **talk-no-read(P7)**:客户端停止读取但持续发上行数据(喂活 keepalive)。现架构无写进度看门狗,
   验证连接**不会**在有界时间内被拆(记录为已知红)。
3. **zero-window-legit(G2 反例锚)**:单 channel peer-window=0、其余 channel 空闲。断言现架构
   **永不因此拆连**——这是**必须绿**的基线(重构后不得回归破坏它)。这个用例现在就应绿。
4. **write-stall-during-rekey**:rekey 进行中对端 TCP 层不收(zero-window / 冻结 socket 读),
   验证现架构无 supervisor 拆连(已知红)。

每个用例顶部注释写清:**预期红/绿**、锚定的缺陷编号、复刻机理。红用例用 `#[ignore]` 或
显式 `assert!` 记录「现架构此处应失败」——让后续切片把它转绿时有明确信号,不要让 CI 直接崩。
推荐:红用例断言「现架构确实卡住」(即断言坏行为存在),这样切片修好后该断言翻转、用例改判绿。

## 交付
- 新增 `tests/harness/mod.rs`(或 `tests/common/`,按 cargo 惯例)放可复用 harness:建 server、
  故障注入客户端、deadline 观测、内存/拆连观测辅助。
- 新增测试文件(如 `tests/test_malicious_client_s0.rs`)含上述 4 用例。
- 全仓库 `cargo test` 可编译;4 用例可跑(红用例按上述方式落,不让 suite 崩)。
- 用**远程编译** `check` 验证编译(勿本地 cargo)。
- 交付报告写到 `.omc/research/impl-S0-report.md`:做了什么、harness API、4 用例现状(红/绿+机理)、
  「最小生产钩子清单」(如有)、你对 S0 完成门的自证。

先读方案 §0/§2/§5,和上面两个现有测试,再动手。保持小而准。
