# 实现任务 S2:WriterTask 独立(§4.3 Writer 半)

S0/S1 已 GO(harness + ConnSupervisor 接入现 loop,事故已修)。S2 开始**真正的三任务拆分**——
把出站写路径从现有单任务 `select!` loop 剥成**独立 WriterTask**。这是全案体量最大、风险最高的切片。
方案 §4.1 拓扑 / §4.3 WriterTask 规格 / §6 切片表。评审:gpt-5.6-sol high + Claude 对抗循环。

## 本轮分两步交付(先规划,后第一增量)

### 第一步:S2 拆解方案(必交,先于代码)
写 `.omc/research/impl-S2-plan.md`:把 WriterTask 提取拆成**若干可独立编译+过测的子增量 S2a/S2b/…**,每个子增量:
- 明确改哪些文件、引入哪些任务间通道(Session→Writer 的 item 通道、Writer→Session 的 InstallAck 通道等)、
- 如何**保持每步全仓库编译 + 现有 9 tests + S0/S1 用例全绿**,
- 明确哪些留给后续切片(**双账本 `WindowSizeRef`/`outbound_acks` 删除是 S5**,本片**不删**,只让 Writer 成为窗口记账权威时与旧账本并存或桥接;Reader 独立是 S3;HandlerExecutor 是 S4)。
给出子增量顺序与每步验收。**这一步等我和 gpt 审方向后再大规模写代码**——若第一增量已顺带落地也可,但拆解方案必须清晰。

### 第二步:落地第一个连贯增量(建议 S2a)
最小可独立验证的一步,建议:
- **抽出 WriterTask 骨架**:一个独占 outbound epoch(cipher+MAC+compressor+出站 seqn)的 tokio 任务;
  Session 经**有界 item 通道**向它提交出站项;Writer 内 cancel-safe 写 socket(移植现有 `flush_into` 光标语义 + `drained_total`/WriteProgress 更新到 Writer 内)。
- **kex 专用队列**(容量 16,`try_push`,满→Cancelling):KexStarted/KEXINIT/回包/NEWKEYS/InstallEpoch/DISCONNECT 走此队,优先于 bulk;Writer 阻塞于 write 时可被 CancellationToken 打断转向 kex 队列(§4.2 cancel-safe 结构)。
- **NEWKEYS 原子序**:`seal(NEWKEYS,旧 epoch)` → 同任务内**无 await 间隔**安装新 outbound epoch → 回 `InstallAck{Outbound,gen}` → 即刻恢复 seal bulk(新 epoch,不等对端 NEWKEYS)。与 SessionTask 的 kex 完成判定对接(S1 的 rekey deadline 在双向 InstallAck+对端 NEWKEYS 齐后才注销——本片对接**出站半边** ACK)。

**暂不做**(留后续 S2 子增量或后片):per-channel 车道 + 因果 fence + 队首 CONFIRMATION、ready-set+gather+boost 调度、StopDiscard、单一窗口账本收口。第一增量只求「Writer 成独立任务、epoch 归属清晰、kex 序正确、全绿」。

## 强约束
- **禁止**删 Scheme C / 双账本 / `max_pending_inbound_bytes`(S5);**禁止**动 Reader 独立(S3)、HandlerExecutor(S4)。
- **禁止**改 kex 状态机语义、channel 生命周期语义、窗口记账口径(只做任务归属迁移,不改口径)。
- S1 的 ConnSupervisor 语义(看门狗两层、rekey/handshake deadline、单一 grace、首因)**必须保持**;WriteProgress 现由 Writer 更新——若 Writer 成独立任务,注意 §4.2「单结构原子快照 release-store / supervisor acquire-load」现在**真的跨任务了**,本片须把 WriteProgress 改成原子快照(S1 遗留的 S2 项,见 review-S1-r2 与方案 §4.2)。
- client 侧若因共享 `PacketWriter`/Scheme C 受影响,仅做**编译对接所需**的最小同改,别删别扩。
- 每步远程编译(`check`)+ 远程跑全 suite。

## 完成门(整个 S2,分子增量累计达成)
close-with-backlog 全变体、NEWKEYS 出站半边、stop-discard-race、顺序矩阵绿(§5)。**第一增量的门**:
Writer 独立任务成立 + kex 序/NEWKEYS 出站 ACK 正确 + 现有 9 tests + S0/S1 全绿 + WriteProgress 跨任务原子快照无撕裂。

## 交付
- `.omc/research/impl-S2-plan.md`(拆解方案)+ 第一增量代码 + `.omc/research/impl-S2-report.md`(第一增量:做了什么、任务拓扑、epoch 归属、原子快照、门禁自证、后续子增量清单)。
先读 §4.1/§4.3/§4.4、现有 `server/session.rs::run`(S1 后的 loop)、`sshbuffer.rs`(PacketWriter/epoch)、`server/supervisor.rs`(WriteProgress)。
