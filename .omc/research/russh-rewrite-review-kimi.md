# russh Session Loop 全量重构方案 —— 对抗式评审(kimi)

- 评审对象:`.omc/plans/russh-proxy-session-rewrite.md`(DRAFT v1, 2026-08-11)
- 评审日期:2026-08-11
- 核实基础:本仓库代码 `russh/src/{session.rs, sshbuffer.rs, pending_inbound.rs, kex/mod.rs, negotiation.rs, server/{mod.rs, session.rs, encrypted.rs}, client/mod.rs}`

---

## 总评

**方向是对的,但按当前文本不能开工。** 三任务拆分、车道分离、显式 kex 状态机、"宁断勿僵"的不变量体系,都对症 2026-08-10 事故的根因;§2 病灶表经逐条对照代码基本属实。但方案里有两颗必须在动工前拆掉的雷:

1. **最大的一颗雷(BLOCKER,维度 2):§4.3 活性表的关键一行不成立。** "WriterTask socket write 的僵死由 keepalive 覆盖(现有机制保留)"——现有机制一是默认关闭(`keepalive_interval: None`,server/mod.rs:140),二是 `alive_timeouts` 在收到**任意**对端数据时清零(server/session.rs:1161-1167),而不是只对 keepalive 响应清零。一个"只发不收"的对端(恶意刷字节,或更现实的:direct-tcpip 上行流持续而 App 下行路径停读)会让 keepalive 永不触发,写侧永久 stall,bulk 全堵,连接不死不活——这正是 G1 立誓要消灭的僵死类,也是本方案存在的理由。活性表必须加一行"写进度看门狗",否则整个"永不僵死"论证在最强敌意场景下塌方。

2. **第二颗雷(BLOCKER,维度 1):CLOSE/EOF 走 control lane 严格优先,会越过同 channel 排在 bulk lane 的数据。** RFC 4254 要求 CLOSE 在 DATA 之后;方案 §4.1 把 CLOSE/EOF 列入 control lane 且"严格优先于 bulk",zfc relay"写完最后一段数据→关 channel"是代理场景每天发生的路径,按现方案会系统性截断下载。

此外还有两颗 MAJOR 级的洞:I5 的字节制 1 TiB rekey 上限漏算了 2^32 包序号回绕(chacha20-poly1305 以 seqn 为 nonce,回绕即 nonce 重用);入站授窗(SessionTask 决策)与 reader 侧队列容量扩容之间存在跨任务时序窗口,会误杀完全合规的客户端。

结论:**修掉上述四点后方案可走,架构骨架(车道分离 + 显式状态机 + 全 deadline)值得保留。** 实施序列需要重切(Phase A 的"server 先行 client 随后"不成立,详见维度 6)。

---

## 1. 正确性(§7 R1)

- **[BLOCKER] CLOSE/EOF 车道超车,同 channel 报文次序被破坏。**
  方案 §4.1 把 "kex/ADJUST/OPEN 回复/CLOSE/EOF/keepalive/DISCONNECT" 全部列入 control lane,并规定"control 严格优先"。失败场景:zfc relay 转发完一个 1 MiB 下载,最后 512 KiB 还在该 channel 的 bulk 队列里(DRR 没轮到/窗口不足),relay 调用 `close()` → CHANNEL_CLOSE 进 control lane → 严格优先 → CLOSE 先于残余 DATA 上线。客户端(OpenSSH、x/crypto/ssh 均如此)在收到 CLOSE 后丢弃该 channel 后续 DATA → 下载系统性截断。EOF 同理。OPEN_CONFIRMATION 先于该 channel DATA 反而是需要的次序,control 优先恰好给对;但 **CLOSE/EOF 必须排在本 channel bulk 队列的队尾**,与该 channel 的 DATA 同车道保序(把 per-channel 控制项串进 per-channel bulk 队列),或由 WriterTask 在发 CLOSE 前显式等该 channel 队列排空。对端 CLOSE 的**回执** CLOSE 走 control lane + 丢弃本 channel 出站积压是对的(现代码 `close_discarding_pending` 即此语义,server/encrypted.rs:1141-1146),两种 CLOSE 不能混为一谈。CHANNEL_SUCCESS/FAILURE 与同 channel DATA 的相对次序属同一类,需一并规定。

- **[MAJOR] KexStarted 时刻 write staging 中已加密旧密钥 bulk 的处置,方案未规定。**
  §4.1 说"rekey gate:收到 KexStarted → bulk 暂停",但暂停的是**队列到 staging** 的方向;staging(flush 游标机制保留)里可能已有几百 KiB 用旧密钥加密好的 bulk,部分已写 socket(flush_cursor 之前)。两个选择都必须写进方案:(a) 继续发完 staging 残余 → 对端在 kex 期间收到 non-kex 报文:OpenSSH rekey 期间排队容忍、初始 strict-kex 期间直接断连,x/crypto/ssh 等实现的容忍度不一,是互操作风险;(b) 回收游标之后未上线的字节、退回 per-channel 队列、NEWKEYS 后用新密钥重加密——保序且零互操作风险,但方案完全没提这条回收路径。推荐 (b)+(a) 兜底(无法回收时宁发勿丢,并记 tracing)。

- **[MAJOR] 入站授窗与 reader 队列容量扩容的跨任务时序洞。**
  §4.1:队列容量 ≡ 已授窗口,窗口授予决策在 SessionTask,超容即 DISCONNECT。时序反例:队列满 → 应用消费 → SessionTask 决定补窗 W → 两件事并发发生:ADJUST 经 control lane 发给对端、"cap += W" 消息发给 ReaderTask。**这两条通道之间没有任何次序保证。** 合规的 OpenSSH 客户端收到 ADJUST 可立即发 W 字节;reader 若在 cap 更新消息之前先处理了这些 DATA → try_push 超容 → 把完全合规的对端当协议违例 DISCONNECT。高负载下 ctrl 队列有积压时几乎必现。修复:**入站窗口记账放进 ReaderTask**(它本来就解析每个 DATA、最适合维护窗口账本);SessionTask 的授予决策发给 reader,由 reader 先扩 cap 再请求 writer 发 ADJUST,次序天然闭合。

- **[OK] 密钥切换边界本身在三分拆下可以做到精确。**
   sealing cipher + 出站 seqn 由 WriterTask 独占,NEWKEYS 发出与切钥在同一任务内相邻执行,不存在交错窗口;ReaderTask 收 NEWKEYS 后阻塞等新 opening key(deadline 覆盖),对端后续新密钥报文在 socket/内核缓冲等待,无旧新交错。这个设计比现在"newkeys 在 loop 里换 cipher、读侧 seqn 靠 `pkt.seqn` 回写"(server/mod.rs:1231-1233 → server/session.rs:1101)干净得多。移植时注意一个细节:NEWKEYS 包本身用旧密钥、旧 seqn 计数,重置发生在它之后。

- **[MINOR] strict-kex seqn 重置:现实现读侧是"借 NEWKEYS 包的 seqn 回写"隐式完成的**(server/mod.rs:1231-1233 把 `pkt.seqn` 置 0,run loop 再 `buffer.seqn = pkt.seqn`)。新架构 reader/writer 各自在 NEWKEYS 边界重置自有 seqn,更显式,但要写测试锚定:重置后第一个包必须是 seqn 0,且 strict-kex 初始 kex 期间插入 non-kex 报文必须断连(msg.rs:118-129 的校验链不能丢)。

- **[MINOR] 压缩状态归属方案只字未提(R1 问了,§4 没答)。**
  现状:`CommonSession::newkeys` 在**每次 rekey** 都重置压缩/解压状态(session.rs:143-146),`encrypted()` 对非 deferred zlib 在初始 kex 后立即启用、deferred(zlib@openssh.com)在 auth 后启用(session.rs:177-188)。新架构必须把 `Compress` 随 sealing cipher 归 WriterTask、`Decompress` 归 ReaderTask,并在 KexDone/key-install 处逐字保留"何时重置、何时启用"的语义——包括 deferred 压缩在 auth 完成时才初始化这条跨任务消息(auth 状态在 SessionTask,压缩状态在 reader/writer)。压缩默认不协商,但这是真协议面,不能靠"到时候再说"。

## 2. 活性论证完备性(§7 R2/R3)—— 最高优先级维度

- **[BLOCKER] socket write 行的解锁机制不成立,G1 在最强敌意场景下失效。**
  §4.3 表:"WriterTask | socket write | 对端读/内核 | keepalive_max × interval(现有)"。两个事实:
  (a) `keepalive_interval` 默认 `None`(server/mod.rs:140),机制默认不存在,zfc 不配就没有;
  (b) 即使配了,`alive_timeouts` 在**收到任何对端数据**时清零(server/session.rs:1161-1167 注释自述:"we assume that the client is still alive if we receive any data"),`inactivity_timer` 同样被任意活动重置(server/session.rs:1177-1184)。
  失败场景:对端 TCP 收窗归零(永不再读),但每 keepalive_interval 周期发 1 字节 junk,或更现实地——代理场景双向流,客户端经 direct-tcpip 持续**上行**(App 上传路径活着)而下行完全停读。入站数据持续喂活 keepalive 计数 → 无任何 timer 触发 → 写永久 stall → control lane 满(256)→ SessionTask 阻塞 → ctrl 队列满(256)→ ReaderTask 阻塞 → 全连接冻结,永不恢复、永不断连。这与 2026-08-10 事故是同一个失效类(出站永久 gate),只是触发器从 rekey 换成了 TCP 停读。
  **修复(必须进方案):WriterTask 写进度看门狗**——距上次 flush 有字节上线超过 T(如 30s,可配)即 DISCONNECT,与入站流量、keepalive 完全解耦。keepalive 降级为辅助。§5 测试矩阵须加对应用例(见维度 7)。

- **[MAJOR] kex deadline 的执行者可以被它要防的东西阻塞。**
  deadline timer 放在 SessionTask 内,而 SessionTask 的 Handler 回调是同步 await 的,方案对回调的约束只是"契约:快速返回(文档化 + debug_assert)"。失败场景:kex 进行中某回调阻塞(zfc 未来某次改动在 open 回调里同步做了 DNS/connect;或第三方 Handler 实现者不知道这条契约)→ SessionTask 卡住 → rekey deadline 的 timer 根本轮不到 poll → deadline 形同虚设,ReaderTask 在新 opening key 上等死。修复二选一:(a) deadline 由独立 supervisor 任务持有,超时直接 abort 全连接;(b) Handler 回调全部 spawn 到有界 worker 池,SessionTask 自身永不执行用户代码。(b) 同时解决"契约靠自觉"的系统性脆弱,推荐。至少要承认:debug_assert 在 release 下不存在,这行活性论证目前是空的。

- **[MAJOR] kex 预留槽位的充分性需要枚举证明。**
  §4.3 的环消解依赖"kex 相关消息单独小队列或 lane 预留 8 槽"。方案应枚举 kex 期间 Session→Writer 的全部消息种类(KEXINIT 回包、KEX_ECDH_REPLY/GEX_REPLY、NEWKEYS、DISCONNECT、KexDone/KexStarted、strict-kex 违规断连)并证明峰值 ≤ 预留槽数;否则预留槽打满时环重新闭合。枚举后大概率 ≤ 8,但这是论证义务不是结论。

- **[MINOR] R2 点名的遗漏项,逐一回答:**
  - channel open confirm 的 oneshot:open 回复现走 **unbounded** channel,且是有意的——client/mod.rs:114-117 注释写明"handler 内联 accept 时,有界队列会自死锁"。新设计若改有界,必须区分 inline accept(在回调返回值里直接 finalize,不入队)与 spawned accept(有界队列进 SessionTask)。这一条方案 §4.6 删了 gating 特判但没回答自产自销路径。
  - `wait_channel_confirmation` / `outbound_acks`:反压点改为出站队列容量后,ack 机制的唤醒者从"loop 释放"变为"WriterTask 发走",需要 WriterTask→channel waiter 的计数/oneshot 回传路径,方案未写;ChannelStream 的 AsyncWrite 语义(poll_write 何时完成)须一并钉死。
  - teardown:现有 5s flush + 5s drain deadline(server/session.rs:1191-1208)要原样保留,并补"三任务 join 顺序"(见 R5)。

- **[OK] 表中其余各行成立。** Reader→Session(ctrl 队列 256)、Session→Writer(control lane 256)、zfc relay 的 `data().await`(只反压该流)、入站 recv 空等,链式无环,前提都是上面 BLOCKER 行被修复——目前整张表的活性最终都汇到 socket write 那一行,它是单点。

## 3. 有界性(§4.4)

- **[OK] 主体闭式成立。** Σw_in + Σout_cap + 两个 256 队列 + staging,N_chan 由 max_channels 封顶后,每连接上界确为可静态计算的闭式。默认值(≈1 GiB/连接)偏高,方案自己也给了 384 MiB 实配建议,可接受。

- **[MINOR] kex 期间暂存量的论证写错了上界(但结论仍成立)。**
  §4.3 说"暂存量 O(channel 数)"——不准。入站 ADJUST 经 ctrl 队列封顶(256 条),应用消费产生的 ADJUST 每次 rekey 窗口期内每 channel 至多一条,正确闭式是 `256 × maxpacket + Σ_chan(单次授予量)`。仍闭式,但公式要写对,否则下次有人按 O(channel 数) 去证明会漏掉 ctrl 队列那一项。

- **[MINOR] 删除 pending_inbound 会一并删掉零字节报文去重,产生新洞。**
  现机制对重复 EOF/CLOSE 去重、对零字节 DATA 直接丢弃(pending_inbound.rs:108-113、158-165),因为按字节的 cap 看不见零字节项。新设计"DATA/EOF/CLOSE 同队列、容量 = 窗口字节数"同样按字节计,恶意对端可刷无限个 EOF/CLOSE/零字节 DATA 把队列(按条数)打爆。修复:队列除字节界外保留条数界或沿用去重规则;§4.6 删除清单应写明"去重逻辑随队列迁移",而不是整层删光。

- **[MINOR] teardown 路径**:5s 双 deadline 保留即闭式;注意三任务 join 时 reader 若正阻塞在"等新 opening key",join 必须有 abort 路径,否则 teardown 本身引入新的无界等待(与 R5 合并处理)。

## 4. 性能设计(§7 R4)

- **[OK] 方向全部正确。** credit 到账零延迟、聚包"有 backlog 凑满 maxpacket、无 backlog 立即发"(不引入人为延迟——这一点很多人做错,方案做对了)、ADJUST 半窗滞回批量、OPEN_CONFIRMATION 走 control lane 降 open→first-byte 延迟、"下行窗口由客户端授予、服务端不可调大"的事实陈述准确。

- **[MINOR] DRR quantum 64 KiB 建议改为 1 个 maxpacket(实质即 RR)。**
  方案的账:32 大流下小流最坏排队 31×64 KiB ≈ 2 MB ≈ 16ms@1Gbps。包化本来就要按 min(peer_maxpacket, 余窗) 切,quantum = 1 packet(≤32 KiB)让最坏排队减半、实现还更简单(不需要 deficit 计数器),DRR 相对 RR 的收益(摊薄小包开销)在 maxpacket=32 KiB 的负载下几乎不存在。无论选哪个,**必须用 ready-set(有数据且有窗的 channel 链表)而不是每轮扫 256 个 channel**。

- **[MINOR] 缺"新 channel first-byte 加速"。**
  G3 要求 open→first byte 最小化;但新 channel 的第一段数据在 DRR 里与 31 条大流同权,最坏排在 ~1-2 MB 之后。可选优化:新 channel 的前 N 字节(如 64 KiB)进独立优先轮次。不阻塞方案,但验收指标(open→first-byte p99)在饱和背景下会暴露这一点。

- **[MINOR] 零拷贝机会。**
  bulk 队列存 `Bytes`,包化时经 `cipher.write` 拷入 write_buffer(sshbuffer.rs:492),每包一次 memcpy + 加密一次 pass。可从队列队头的 Bytes 切片直接加密入 staging,省掉明文拷贝;千兆下行 + 每核单连接时这是可测的开销。现成基础:`reserve_cleartext_packet_output`(sshbuffer.rs:521-536)已经在做批量预留,顺这条路延伸即可。

## 5. 协议合规与互操作

- **[MAJOR] I5 的字节制 1 TiB 上限漏算 seqn 回绕——密码学上这不是"2 个数量级余量"。**
  方案 §3 I5 的论证:"协议硬界是 2^32 包序号回绕,按 32 KB 包算 ≈ 137 TB"。这个换算是按**最大包**算的;回绕按**包数**发生,包尺寸由对端(读侧)和应用写模式(写侧)决定。最小合法包 ~28 字节,小报文流下 **~120 GB 读流量即可回绕 seqn**,比 1 TiB 低一个数量级;交互式小写(写侧)同样。后果按套件分:chacha20-poly1305@openssh.com 以 seqn 为 nonce,回绕 = 同密钥 nonce 重用 = Poly1305 可伪造 + 密钥流重用,灾难级;aes-ctr+ETM 的 MAC 输入含 seqn,回绕破坏 MAC 唯一性假设;aes-gcm 用独立 64 位 invocation counter,密码学上最耐,但 seqn 回绕仍违反 RFC 4253 §6.4(2^32 包前 MUST rekey)。**修复:Limits 增加包数制上限(如 2^31 包/方向)触发 rekey**,字节制保留为第二道;或按套件差异化默认值(R7 详答)。改动很小,但必须做。

- **[MINOR] window-overflow 即断全连接,比现状更激进,建议保留"关单 channel"语义。**
  现状对超窗对端的处理是关闭**该 channel** 而不是断连(server/encrypted.rs:1244-1255,注释自述 "close this one channel only, never the session")。方案 §4.1 改为超 1×maxpacket 容差即 DISCONNECT 全连接。对 OpenSSH/x/crypto/ssh 精确记账的实现无差别;但某些嵌入式/老旧实现超发超过 1 个 maxpacket 的历史是存在的,代理场景对端不可控,误杀成本是整连重拨。建议:容差可配、先按"关 channel + 计数器"上线观察,违例率确认为零再收紧。至少要在方案里写明这是有意的语义收紧。

- **[OK] kex 期间的收发方向选择是正确的。** 收:容忍(RFC 与现实都要求,OpenSSH rekey 期间对入站 non-kex 排队);发:bulk 暂停、非 kex 控制暂存(RFC 4253 §7.1:发出 KEXINIT 后到发出 NEWKEYS 前,MUST NOT 发 kex 规定以外的报文)。唯一未定的 staging 残余处置见维度 1。

- **[OK] 不主动 rekey 对第三方客户端无坑。** 没有任何主流客户端要求服务端发起 rekey;OpenSSH 客户端 `RekeyLimit` 默认 1G 会自己发起,方案"全力配合 + deadline"正确。1 TiB 不 rekey 本身(在包数界修复后)对 aes-gcm/chacha20 无密码学问题。

## 6. 可实施性

- **[MAJOR] Phase A 的"server 先行,client 随后对齐"不成立。**
  `pending_inbound.rs` 开头自述 "Shared by the server and client session loops",client 侧结构体原样内嵌 InboundQueue/needs_reserve(client/mod.rs:102-105);Scheme C、flush 游标、OUTBOUND_HIGH_WATERMARK 都在共享 core。Phase A 删除清单一旦执行,client 侧不编译;而 9 个回归测试全部走 russh↔russh 双端,client 不同步改则测试体系先红。所以"server 先行"是个假阶段边界,实际 Phase A = 双端同时重写,比方案呈现的更大。
  **建议重切:** Phase A0 = 恶意客户端 harness **先于一切重构**落地(它对现架构也能跑,既验收现状又锁定基线,零风险);Phase A1 = core 三任务双端同改 + 车道分离 + kex 状态机,完成门 = 现有 9 测试全绿 + harness 基线不劣化;Phase B 性能(DRR/聚包/调参,数据驱动);Phase C soak + 真机。"单程无止血分支"可以接受,但 A0 前置能把最大风险(重写后才发现 harness 测不出事故复刻)消掉。

- **[MINOR] 删除清单:删多了没有,删少了两处。**
  (a) `pending_reads`/`pending_len` 是**死代码**——全仓库 grep 无任何 push,只有初始化和 kex 完成后的 drain(server/session.rs:31-32、server/mod.rs:1208-1213),应列入删除清单;
  (b) `outbound_acks`/`wait_channel_confirmation` 机制随反压语义变化需要重写而不是"删除",§4.6 一句话带过,实施时会发现它牵着 ChannelStream 的 AsyncWrite 语义。
  删 `max_pending_inbound_bytes`(窗口即界)方向正确,但生效前提是维度 1 的授窗时序洞先堵上,否则"窗口即界"在跨任务下不等价。

- **[MINOR] `event_buffer_size`(Handle mpsc 容量)的新角色未定义。** 现状它是 Handle→loop 的唯一队列;新架构 Handle→SessionTask 一跳、SessionTask→per-channel 队列一跳,两跳的容量与反压语义(zfc 的 `Handle::data` 现在是 await ack 的)都要在 Phase A1 设计文档里钉死。

## 7. 测试充分性

§5 矩阵的方向对(复刻事故的 rekey-stall-under-load 是核心用例),但按本评审发现的问题,**至少缺以下用例**:

- **[MAJOR] talk-no-read**(对应维度 2 BLOCKER):对端 TCP 停读,但每 keepalive_interval 周期发 1 字节 junk(变体:持续发合法上行 CHANNEL_DATA)→ 验收写看门狗在 T 内断连。现有 tcp-zero-window 用例覆盖不了,因为 keepalive 会被入站数据喂活——这个用例不复测,BLOCKER 修复就没有验收。
- **[MAJOR] close-with-backlog**(对应维度 1 BLOCKER):channel 出站队列压满 → 本端 close → 验收残余 DATA 全部先于 CLOSE 上线、对端收全不截断;镜像用例:对端 CLOSE 到达时本端队列有积压 → 回执 CLOSE + 丢弃积压。
- **[MINOR] window-grant-race**:窗口耗尽 → 应用消费 → 授窗,对端在收到 ADJUST 后**立即**用满新窗口突发发送(高负载下重复 N 次)→ 不得误 DISCONNECT(维度 1 时序洞的回归锚)。
- **[MINOR] seqn-wrap-near**:以缩小上限的 build(或测试钩子)把包数界降到可测值,验证包数制 rekey 触发、chacha20-poly1305 套件下不发生 nonce 重用。
- **[MINOR] strict-kex 初始 kex 期间插入 non-kex 报文 → 断连**(Terrapin 回归;现有 test_rekey_strict_kex 覆盖 rekey 路径,初始 kex 路径要确认)。
- **[MINOR] adjust-overflow**:ADJUST 累计使窗口超 2^32−1 → 按 RFC 4254 §5.2 断连。
- **[MINOR] oversized-packet**:单 DATA 超 advertised maxpacket → 断连。
- **[MINOR] mid-kex 混合轰炸**:kex 期间并发 OPEN + CLOSE + EXTENDED_DATA + ADJUST,不 panic、保序、暂存有界。
- **[MINOR] 压缩开启(flate2 feature)下的 rekey + mid-kex data**,锚定压缩状态重置语义(维度 1 MINOR)。
- **[MINOR] kex-init-flood pre-auth**:未认证状态反复 KEXINIT,验收 CPU/内存有界 + auth_timeout 兜底。

## 8. 方案对现状描述的属实性

逐条对照代码,**基本属实,两处不准、三处遗漏**:

- P1 ✓ 机制属实:`kex.active()` gate 三个 arm(server/session.rs:1046 批 drain 前置条件、1108、1118);`Encrypted::flush` 的 rekey 触发在 session.rs:798-800。**行号小错**:`data` 的 `is_rekeying` 分支实际在 session.rs:651-654;742 行是 `extended_data_with_writer` 的同名分支(brief 与方案 P1 都引了 742)。
- P2 ✓ 机制属实,**数字偏小**:OUTBOUND_HIGH_WATERMARK(sshbuffer.rs:369)只是 intake 软上限,其注释自述 "soft bound";一次 pending_data 批量 flush 可使其远超 128 KiB,真正滞留还含 per-channel pending_data(受 `max_pending_outbound_bytes` 封顶)。"最多 128 KiB + sndbuf"应改为"至少 128 KiB,实际可大得多"——这反而加强 P2 的论点。
- P3 ✓、P4 ✓、P5 ✓(reserve/generation/deferred teardown/双路径均见代码)。
- P6 ✓ 机制属实,默认值为 8×2,000,000 = 16,000,000 字节(server/mod.rs:134),方案写"16 MB"可接受。"7 个 arm" ✓。
- **遗漏一(重要)**:§2 未提 keepalive 的两个现状事实——默认 `None`(server/mod.rs:140)、计数被任意入站数据清零(server/session.rs:1161-1167)。方案 §4.3 恰好把活性押在这个机制上,自己对现状的描述漏了最致命的两行。
- **遗漏二**:`pending_reads` 死代码(见维度 6),§2 病灶表和 §4.6 删除清单都没提。
- **遗漏三**:open-reply 的 unbounded channel 是有意设计(client/mod.rs:114-117 的注释),§2 把它归入"补丁堆叠"时未说明这一层,重构时若不知缘由会踩回自死锁。
- 0.1 事故表的根因自述与代码内注释(session.rs:787-795 的 rekey 史、server/session.rs:1033-1040 的 HOL 注释)一致 ✓。

---

## 附:对方案 §7 R1–R7 的逐条回答

- **R1(密钥切换边界)**:可以做到精确,前提是:(a) NEWKEYS 与切钥在 WriterTask 内相邻执行、strict-kex seqn 重置各向本地完成(现代码已是这个结构,移植即可);(b) 补齐方案没写的两件事——staging 旧密钥 bulk 残余的处置(推荐回收重加密)与压缩状态跨 rekey 的语义保留(现代码每次 newkeys 都重置,session.rs:143-146);(c) reader 等新 key 的唯一等待点保留 deadline。旧新密钥包交错窗口不存在:reader 阻塞即物理隔离。
- **R2(活性表完备性)**:不完备。缺:写进度看门狗(BLOCKER,表的唯一单点);kex deadline 与 Handler 阻塞的隔离(supervisor 或回调 worker 化);open-confirm 自产自销路径(inline accept 直接 finalize);outbound_acks 的新唤醒路径;teardown 三任务 join 顺序。`wait_channel_confirmation` 与 teardown 5s deadline 的现有语义可保留,但要写进新表。
- **R3(kex 期间控制暂存)**:有界性成立但要写对闭式(256×maxpacket + Σ授予量,不是 O(channel 数))。"kex 期间 ADJUST 照发"**不可行**:RFC 4253 §7.1 明确 MUST NOT——发出 KEXINIT 后到发出 NEWKEYS 前只允许传输层 kex 相关报文。接收方向必须容忍(in-flight 报文),OpenSSH 即排队处理。维持"发送暂存、接收容忍",并给暂存设显式 cap。
- **R4(DRR quantum)**:16ms@1Gbps 的最坏排队对代理场景可接受,不需要小报文 fast-path 的复杂机制;但建议 quantum 直接取 1 个 maxpacket(RR),效果等价且实现更简单,配 ready-set。真正值得加的是新 channel first-byte 优先与包化零拷贝(维度 4)。
- **R5(取消/关闭一致性)**:方案必须写死:任一任务 Err → 其余任务立即 abort(JoinSet + AbortHandle,或共享 CancellationToken);shutdown 顺序 = 先停 reader(止摄入)→ writer 带 deadline flush 完 DISCONNECT 与残余 control → SessionTask join;半关闭(对端 EOF、本端还在发)= reader 退出、writer 继续到 bulk 排空或写看门狗触发;现有 5s flush + 5s drain 双 deadline 原样保留。reader 阻塞在"等新 opening key"时必须有 abort 路径,不能靠 join 等。
- **R6(client 侧对齐成本)**:不能延后——pending_inbound 与 flush 游标、水位线是双端共享 core,Phase A 的删除清单执行时 client 必须同步改,否则 workspace 不编译、9 个双端测试全红(维度 6)。zfc 是否有 `russh::client` 使用点超出本仓库可见范围,动工前应 grep ../zfc 确认;即使没有,client 也必须在同一 Phase 完成。
- **R7(I5 密码学审慎性)**:字节制 1 TiB 单独不成界(维度 5 MAJOR):seqn 回绕按包数发生,小报文流 ~120 GB 即达 2^32 包;chacha20-poly1305 以 seqn 为 nonce,回绕是灾难;aes-ctr+ETM 的 MAC 含 seqn;aes-gcm 的 invocation counter(2^64)最耐但仍受 RFC 4253 §6.4 的 2^32 包 MUST-rekey 约束。**结论:加包数制上限(建议 2^31 包/方向)作为第一触发器,字节制保留为第二触发器,比按套件差异化默认值更简单也更安全**;若要差异化,唯一有理由放宽的是 aes-gcm(仍不得超过包数界)。time = 无穷可以接受(无已知套件有时效性密钥消耗),rekey 配合客户端发起 + deadline 即可。
