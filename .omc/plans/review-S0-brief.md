# 对抗评审任务:S0 恶意客户端 harness

你是本重构的**对抗评审者**(gpt-5.6-sol high)。实现者是 grok-4.5。方案见
`.omc/plans/russh-proxy-session-rewrite.md`(§5 测试矩阵 / §6 切片表);S0 任务书见
`.omc/plans/impl-S0-brief.md`。本轮只评审 **S0** 交付,不评审后续切片。

## 待评审交付物
- `russh/tests/harness/mod.rs`(可复用 harness)
- `russh/tests/test_malicious_client_s0.rs`(4 个用例)
- `.omc/research/impl-S0-report.md`(实现报告)

grok 自报:4 用例远程编译+运行通过;incident-repro / talk-no-read / write-stall-during-rekey
现架构判**红**(断言坏行为存在),zero-window-legit 判**绿**;未改 `russh/src/**`。

## S0 完成门(唯一硬标准)
> harness 能驱动**现架构**并**暴露已知缺陷**——即 4 个用例真实锚定各自缺陷,
> 且红用例在 S1 装上 supervisor 后能翻转为绿(有效信号)。

## 评审重点(对抗视角,只报实质问题)
1. **红用例是否真锚定了目标缺陷,还是"因错误的原因通过"?**
   - incident-repro(P1:kex.active 全连接出站闸)与 write-stall-during-rekey(§4.2:无写进度看门狗)
     两个用例的注入手法几乎一致(都 `freeze_read()` + `rekey_soon()`)。它们是否**退化成同一个测试**?
     "outbound stalled" 的判据是服务端**应用层 writer.write_all 阻塞**——这跟普通 channel 窗口耗尽
     (TCP 冻结后 drainer 读不到→窗口不返还)**无法区分**。stalled 信号真能证明是 kex.active 闸,
     而非普通零窗反压吗?若不能,P1 锚定是否失效?
   - 若要干净隔离 P1,应让**对端继续正常读 bulk(窗口持续返还)、只卡住 KEX 握手完成**;
     现手法用 TCP 冻结把两者混在一起。这是否是必须修的缺陷,还是 S0 可接受的近似(brief 允许暂缓 raw-wire)?
2. **红用例翻转有效性**:S1 装 supervisor 后,这些断言会不会因为"翻转判据不精确"而**假绿或假红**?
   例如 `report.stalled || end==start` 这种或条件,在重构后是否仍成立/失效得明确?
3. **绿用例(zero-window-legit)是否真是 G2 反例**:它现在绿,但重构后 armed-predicate 若实现错误
   会误杀。这个用例的构造(app-level freeze 单 channel + 另一 idle)是否足以在 S1 后仍守住 G2?
   有没有漏掉"必须绿"的关键变体(如冻结 channel 恰好耗尽窗口那一刻)?
4. **session_alive 观测正确性**:`FloodHandler::drop` 标 `session_ended`,`authenticated` 门控,
   `wait_listening` 探测连接的 Drop 被排除。这个"存活"信号在 4 个用例里都可靠吗?有无竞态/误报?
5. **harness 稳定性**:loopback 上 rekey 与 freeze 的时序竞态(报告提到缩短窗口规避);
   `S0_OBSERVE_SECS` 调短会不会让红用例偶发假绿(flaky)?

## 输出
写到 `.omc/research/review-S0-gpt.md`:
- 判决:**GO / CONDITIONAL(列必修项)/ NO-GO**
- 每条问题:定位(文件:行)、为何是实质问题、最小修法建议
- 明确区分「S0 必修」(阻断进 S1)vs「S1+ 再补」(记录即可)
- 避免吹毛求疵:只报会导致锚定失效 / 假信号 / G2 回归的问题。红用例本身允许近似,
  但近似若使其**无法在 S1 翻转成有效信号**,就是必修。

先读交付物三件与方案 §4.2/§5,再动手。
