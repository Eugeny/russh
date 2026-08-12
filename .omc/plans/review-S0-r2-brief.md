# S0 第 2 轮验证复审(修复后)

你上轮判 CONDITIONAL,三条必修。grok 已修复。**本轮只做两件事**:
(A) 逐条验证三必修是否**真闭合**(信号可判定、能在 S1 翻转);(B) 猎修复**新引入**的缺陷。
你上轮评审见 `.omc/research/review-S0-gpt.md`。**避免过度设计**:只报会改变判决的实质项。

## 修复摘要(待你核实)
- 新增 `feature = "_test_hooks"`(默认空)+ `russh/src/client/test_hooks.rs::RekeyHoldGate`
  (per-session `Arc`,挂 `Config.rekey_hold`,全 `#[cfg]` 门控)。
- `russh/src/client/kex.rs` 两处注入:武装时**抑制出站 NEWKEYS** + **丢弃入站 NEWKEYS**,
  状态回 `WaitingForNewKeys`,`reset_seqn:false`。
- case1 改 **KEX-only**:TCP 不冻、drainer 持续读返窗、hold 扣 NEWKEYS;新增负对照
  `s0_incident_repro_rekey_stall_negative_no_rekey`(不 rekey → 必须继续流)。
- case2/4 加 `assert_ssh_credit_remaining(growth, window)`(增长 < window/4 证明非零窗)、
  talk-no-read 强制 `report.stalled`、case4 先 `wait_rekey_held` 再冻 TCP。
- G2 加 `wait_progress_stable`(确已零窗)+ 整 observe 期恒等断言。
- `observe_write_stall` 改**终态** idle、移除 `|| end==start`、`observe>stall_for` fail-fast。
- `[[test]] required-features=["_test_hooks"]`;无 feature 时整套 tests 仍编译。

## A. 三必修闭合验证(逐条给 YES/NO + 依据)
1. **P1 隔离**:case1 的停滞现在是否**只能**由 kex.active 闸解释?因果链
   「client 发 KEXINIT ⇒ server 必入 kex」+「TCP live + drainer 返窗 ⇒ 非零窗、非 TCP 背压」
   +「负对照不 rekey 则流动」是否成立?还是仍有未堵的第三解释?
   (注意:本方案**不**直接观测 server kex generation,而用因果推断替代——这是否足够,还是必须加 server 侧观测?)
2. **watchdog 应 armed**:`assert_ssh_credit_remaining` 的 window/4 阈值 + 多 MiB 窗,
   能否**可靠**保证 case2/4 停滞时 SSH 下行信用为正(即正确 S1 supervisor**应当**拆)?
   talk-no-read 里 drainer 不再预冻消费者——TCP 冻后 growth 真会 ≪ window 吗?有无反例参数?
3. **G2 确已零窗**:`wait_progress_stable` + 恒等断言是否真证明「到达且停留在 peer-window=0」?

## B. 新缺陷猎杀(修复副作用)
- **NEWKEYS-hold 副作用**:出站抑制路径返回 `NeedsReply{reset_seqn:false}` 并回 `WaitingForNewKeys`
  —— client 会话循环会不会**忙转**(重复命中 hold、`held_outbound` 暴涨、烧 CPU),或
  **解密错乱**(丢入站 NEWKEYS 后 server 已切新钥、client 仍旧钥,后续包解密失败→client 报错关连,
  使 `!session.is_closed()` 红断言**提前假翻转**)?给出为何安全/不安全。
- **seqn/strict-kex**:`reset_seqn:false` 在 hold 路径是否与 strict-kex 语义冲突,污染非 hold 用例?
- **翻转性反向验证**:S1 装 supervisor 后,case1 会不会被 `WriteStalled` 抢先拆(而非 `RekeyTimeout`)
  导致首因契约破裂?case4 会不会被 `RekeyTimeout` 抢先(而非 `WriteStalled`)?两者首因能否真正区分?
- **feature 门控完整性**:非 `_test_hooks` build,`Config` 结构/Default/公共 API 是否零变化?

## 输出
写 `.omc/research/review-S0-r2-gpt.md`:
- 判决:**GO / CONDITIONAL(列必修)/ NO-GO**
- A 三条逐条 YES/NO;B 每条新缺陷定位(文件:行)+ 严重度 + 最小修法
- 明确:哪些必须 S0 闭合,哪些可挪 S1
先读 `russh/src/client/kex.rs`、`test_hooks.rs`、`tests/test_malicious_client_s0.rs`、`tests/harness/mod.rs`。
