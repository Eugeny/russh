# 评审任务:russh Session Loop 全量重构方案(对抗式设计检视)

你是被请来对一份**尚未实施**的架构重构方案做对抗式检视的资深评审。请独立工作,不要客气,目标是把方案打穿而不是背书。

## 待评审对象

- 方案文档:`.omc/plans/russh-proxy-session-rewrite.md`(必读,逐节读完)
- 代码现状(选读,用于核实方案对现状的描述是否准确):
  - `russh/src/server/session.rs`(现有 run loop,982 行起;Scheme C;outbound cap)
  - `russh/src/session.rs`(`Encrypted::flush` 758 行起,rekey 触发 798-800;`data` 的 `is_rekeying` 分支 742)
  - `russh/src/sshbuffer.rs`(PacketWriter、flush 游标、OUTBOUND_HIGH_WATERMARK)
  - `russh/src/pending_inbound.rs`(方案计划删除的 Scheme C 机制)
  - `russh/src/kex/mod.rs`、`russh/src/negotiation.rs`(strict-kex)
  - `russh/tests/`(现有回归)

## 背景(一句话)

zfc 用此 russh fork 做 SSH 代理服务端,对端是不可控的第三方 SSH 客户端(单 TCP 多 direct-tcpip channel);2026-08-10 真机发生 1 GiB rekey 触发的出站永久僵死事故;方案要求"永不僵死 + 代理场景性能",全量重构,无兼容包袱。

## 评审要求

按以下维度逐一给出结论,每条结论标注严重级别 [BLOCKER] / [MAJOR] / [MINOR] / [OK]:

1. **正确性**:三任务拆分下 SSH 协议正确性(密钥切换边界、strict-kex seqn 重置、压缩状态、报文次序保证)。方案 §7 R1。
2. **活性论证完备性**:攻击 §4.3 的表——找出任何遗漏的等待点、隐藏的环、deadline 覆盖不到的路径。方案 §7 R2/R3。这是最高优先级维度。
3. **有界性**:§4.4 内存上界是否真的闭式成立?kex 期间的暂存、control lane、teardown 路径是否有洞?
4. **性能设计**:DRR/聚包/窗口策略对代理负载是否最优?§7 R4。有无更好的调度或零拷贝机会?
5. **协议合规与互操作**:对第三方客户端(OpenSSH、libssh2、golang x/crypto/ssh、Apache MINA 等)的容忍度假设是否成立?window-overflow 即断连、kex 期间收 DATA 的处理、1 TiB 不 rekey(§7 R7)是否会踩某些客户端的坑?
6. **可实施性**:Phase A 一步到位的风险;是否有更稳的切分;删除清单(§4.6)是否删多了/删少了。
7. **测试充分性**:§5 的恶意客户端矩阵还缺什么用例?
8. **方案对现状的描述是否属实**:对照代码核实 §2 病灶表,指出任何与代码不符的断言。

## 输出

将完整评审写入本仓库文件(markdown,中文):**输出路径见派发 prompt 中指定的 OUTPUT_PATH**。
结构:先一段总评(方案能不能走/最大的一颗雷),然后按上述 8 维度列结论,最后单独一节回答方案 §7 的 R1–R7。
所有 [BLOCKER]/[MAJOR] 必须给出具体的失败场景或反例,不接受泛泛的"建议考虑"。
不要修改仓库中任何其他文件。
