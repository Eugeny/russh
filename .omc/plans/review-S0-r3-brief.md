# S0 终审(第 3 轮,窄口径)

前两轮对抗评审(gpt-5.6-sol high + Claude)已确认:A1(P1 隔离)、A3(G2 零窗)、
NEWKEYS-hold 安全性、feature 门控完整——**全部闭合,本轮不必复查**。
第 2 轮判 CONDITIONAL,剩两条 S0 必修(B1/B2),grok 已用「flood start-gate + case4 先冻后 rekey」修复。
**本轮只验这两处,判 GO / NO-GO。** 完整历史见 `.omc/research/review-S0-r2-gpt.md`。

## 待验交付(只看这些)
- `russh/tests/harness/mod.rs`:新增 `FloodStartGate`、`assert_down_credit_positive`、
  `run_channel_mode` 的 flood-release await。
- `russh/tests/test_malicious_client_s0.rs`:`s0_talk_no_read`(case2,行 ~235-339)、
  `s0_write_stall_during_rekey`(case4,行 ~460-569)。case1/G2/负对照未动,别复查。

## 必验两点

### B1:「停滞时 SSH 下行信用为正」现在是否**可判定**?
核心断言 `assert_down_credit_positive(report.end_bytes, down_window, pkt)` = `end_bytes + pkt < window`。
- `report.end_bytes` 是**服务端** `Progress`(server app `write_all` 成功字节),start-gate 使故障起点 = 0。
- **要你判定的逻辑**:server app 写入字节是否是「已消费 SSH 信用」的**上界**
  (消费信用 = 已 seal+发送 ≤ app 写入)?若是,则 `end_bytes < window-pkt ⇒ 消费 < window ⇒ 剩余信用 > 0`,
  证明成立。若 server app 能写入远超已消费信用(如巨大 channel 缓冲)导致 end_bytes 逼近 window,
  是否会假失败/假通过?给出结论。
- start-gate 是否真的把「故障前未被 ADJUST 补回的既有消费」清零(冻结前 `progress.total()==0` 断言)?

### B2:case4 是否真与 case1 反向对照、锚定 WriteStalled 而非 RekeyTimeout?
- case4 现在:冻 TCP @ accepted=0 → 放行 flood → `wait_progress_stable` 确认写路径 parked
  (`stalled_level>0` 且信用为正)→ **再** `rekey_soon()`。
- **要你判定**:停滞是否**先于且独立于** rekey 存在(即 wire-eligible 密文在 rekey 前已卡 socket)?
  这是否使它与 case1(InKex + socket 可写、无卡滞密文)构成真正反向对照?
- kex_before/after 相等是否可靠证明 rekey 在飞未完成(client 读冻结)?
- 残留:S1 里 write-watchdog 与 rekey deadline 的**时序竞争**(谁先拆)——确认这是否已被正确
  归为 S1 调参项(测试用短 write deadline),**不是** S0 blocker。

## 新副作用(快速扫,只报 blocker)
- `FloodStartGate`(`AtomicBool + Notify`)有无丢唤醒/竞态致测试挂死?
- 冻 TCP 后才 `rekey_soon`:client 写半发 KEXINIT 是否可靠让 server 进 InKex?有无 client 提前
  报错关连使 `!is_closed()` 假翻转?

## 输出
写 `.omc/research/review-S0-r3-gpt.md`:判决 **GO / NO-GO**;B1/B2 各 YES/NO + 依据(文件:行);
任何 blocker 的最小修法。只报会改变判决的项。先读上述两文件相关段。
