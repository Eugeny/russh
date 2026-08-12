# 复审报告(第 2 轮):russh Session Loop 全量重构方案 v2

- 评审者: kimi(对抗式复审)
- 评审日期: 2026-08-11
- 评审对象: `.omc/plans/russh-proxy-session-rewrite.md`(v2)
- 对照材料: 第 1 轮三份评审(`.omc/research/russh-rewrite-review-{gpt,grok,kimi}.md`);代码抽查:`client/mod.rs:105-119`(open-reply unbounded 有意设计注释,属实)、`server/mod.rs:140`(keepalive 默认 None,属实)、`server/session.rs:1167`(alive_timeouts 被任意入站清零,属实)、`server/encrypted.rs:1244-1255`(超窗关单 channel,属实)、`cipher/chacha20poly1305.rs:67-137`(seqn 作为 sequence_number 逐包传入 seal/open,属实)、`cipher/mod.rs:249/291/343`(seqn 为 Wrapping\<u32\>,属实)、`lib_inner.rs:274`(Limits::new assert ≤1 GiB,属实)、`russh/tests/`(9 个测试文件,属实)
- 原则: 逐行核验附录 A 裁决表;攻击 v2 新机制;不接受"附录声称关闭"而正文规格不足

---

## 总评

**v2 是一次实质性的修订,不是表面补丁。** 附录 A 裁决表经逐行核验,第 1 轮交叉确认的 BLOCKER 中,写进度看门狗/强制拆除、方向性 NEWKEYS epoch、因果序 fence、包数界四项在正文均有可编码的规格支撑,判 [CLOSED];Handler 一律 spawn 的结构处置成立,但衍生出两个正文未规格化的新缺口。**但 v2 仍不能进入 S0/S1**:三任务拓扑引入了两个正文级的活性/协议缺陷(渗出读规避看门狗、fence 项被窗口谓词锁死),一处入站 ADJUST 路由的规格空白,以及实施序列把两个已承诺的 BLOCKER 级改动(Handler spawn、全局预算)漏排在所有切片之外。缺口清单见 C 节,均为可关闭项,关闭后可开工。

---

## A. 第 1 轮缺陷关闭核验(按附录 A 裁决表逐行)

### A.1 重点项 1:ConnSupervisor 写进度看门狗与强制拆除

**[CLOSED]**(原缺陷:Writer 卡 socket write 时一切 deadline 失效,keepalive 默认关且被任意入站喂活,BLOCKER 3/3)
依据:§4.1 ConnSupervisor 三点职责 + §4.3 活性表"Writer | socket write | write_progress_deadline(supervisor)"行 + §4.3 末段"supervisor→任务只有单向 abort,不经任何队列" + §5 talk-no-read/write-stall-during-rekey 两用例专杀 v1 塌方点。机制可实现:tokio `JoinHandle::abort()` 可在任务阻塞于 `write().await` 时注入取消,两 socket half 随任务帧 drop 而关闭,supervisor 经 JoinSet 确认 Joined;DISCONNECT 降级为 best-effort 且以总 grace 为界,不以发出为前提——G1 的"拆除"定义自洽。**原缺陷关闭。**

但看门狗的判定语义留下两个正文未答的问题(计入 B 节新风险):

- "最后一次有字节成功写入"按**任意字节 >0** 即刷新,可被渗出读(trickle-read)对端无限喂活 → **B.1 [MAJOR]**。
- "有待写数据"的判定者未定义:supervisor 不在数据面,需要 Writer 发布 backlog 状态(原子计数/标志),其设置/清除的次序协议(尤其与 kex staging 残余、teardown flush 的交互)正文未写 → **B.2 [MINOR]**。

### A.2 重点项 2:方向性 NEWKEYS epoch(§4.1/4.2)

**[CLOSED]**(原缺陷:NEWKEYS 方向性 epoch 未规格化,BLOCKER gpt/grok)
依据:§4.1 WriterTask"NEWKEYS 原子序"段逐字给出了 grok 失败场景 A 要求的序列(`seal(NEWKEYS, 旧 epoch)` → 原子安装新 outbound epoch → 后续一切包用新 epoch,含 rekey 超时路径的 DISCONNECT);Reader 侧对称(旧 epoch 打开 NEWKEYS → 等新 inbound epoch → 原子安装 → 读下一包),等待点受 rekey_deadline 覆盖且 CancellationToken 可打断(回应 grok 失败场景 B);"两方向独立……合法中间态"一句正面处理了 gpt 的 DISCONNECT 用钥反例。压缩随 epoch 重建 + deferred 压缩的 EnableCompression 跨任务消息在 §4.2 写明(回应 grok 失败场景 D 与 kimi 的压缩 MINOR)。strict-kex seqn 按方向在各自安装点置 0 + "重置后第一包 seqn=0"测试锚定(§4.2)。§5 NEWKEYS 边界矩阵(我先/对先/同时、partial write、strict on/off、新旧 epoch 各只解对应包)构成验收。规格已够编码,交错窗口在单 Writer 单 Reader + seal 点规则下不存在。**原缺陷关闭。**

残留 [MINOR]:Session→Reader 的 InstallInboundEpoch 通道未出现在任何队列枚举中(kex 专队枚举的 InstallEpoch×2 是 Session→Writer 方向);Reader 阻塞等新 epoch 时由谁投递、该通道满了会怎样,正文未写。实施时补一条"Session→Reader epoch 投递为 oneshot/容量 1 通道,Reader 唯一等待点"即可,不构成复燃。

### A.3 重点项 3:per-channel 因果序 fence 与三级车道

**[CLOSED]**(原缺陷:CLOSE/EOF/SUCCESS 车道超车,BLOCKER 3/3)
依据:I3 修正版"per-channel 因果序高于车道优先级",DATA/EXTENDED_DATA/EOF/CLOSE/SUCCESS/FAILURE 同队列、EOF/CLOSE 为 fence 项永不超车;§5 close-with-backlog 双镜像用例(本端 close 残余 DATA 全量先上线/对端 CLOSE 丢弃积压+回执)锚定验收。两个 control lane 例外论证核验:

- WINDOW_ADJUST 走 control lane: **[OK]**。ADJUST 与本端出站数据无因果关系(它影响的是对端发送权),超车无害;越过 EOF/CLOSE 到达对端亦合法(对端可忽略已关闭 channel 的 ADJUST)。论证成立。
- OPEN_CONFIRMATION 走 control lane: **[OK]**。accept 返回之前应用无法提交该 channel 的数据(permit 尚未发放),confirm 在 wire 上必然先于数据,不存在可被破坏的因果序。论证成立。

**原缺陷关闭。** 但 fence 项进入 ready-set 轮转后引入了一个 v1 不存在的新谓词错误 → **B.3 [MAJOR]**。

### A.4 重点项 4:RekeyPolicy 包数界

**[CLOSED]**(原缺陷:1 TiB 字节界漏 seqn 回绕,BLOCKER 3/3)
依据:I5 修正版——包数界每方向 2^31 为第一触发器,明确写出 v1 论证的根本错误("回绕按包数不按字节");字节界 1 TiB 降为第二触发器;读写双向独立记账且点名"现状 `rekey_read_limit` 未接入,须真正实现"(代码抽查属实);`Limits` → `RekeyPolicy{max_packets: u64, max_bytes: u64, deadline}` 的 API 重设计回应了 `lib_inner.rs:274` 的 assert 冲突与 32 位 target 问题;§5 seqn-wrap-near 用例(test-only 初始计数 = limit−2,绝不 wrap 后继续 seal)锚定。2^31 < 2^32,无论计数器是否在 rekey 时清零,触发点都在回绕之前,密码学结论稳妥。**原缺陷关闭。**

残留 [MINOR]:计数器清零语义未定义——nonce 重用风险按"当前密钥下的包数"计量,严格说应在每次 NEWKEYS 安装时清零;按连接累计清零(更保守,无害但会随 rekey 次数累积触发额外 rekey)。建议在 S5 规格中写死"epoch 安装即清零该方向包计数",一句话的事。

另注一个 I5 的衍生压力(信息性,不评级):2^31 包 × 最小包 ~28 B ≈ 60 GB,小报文洪泛下千兆链路 ~8 分钟即触发一次 rekey。攻击者可迫使连接进入"持续 rekey"状态,但每次 rekey 是毫秒级且有 deadline 兜底,活性论证覆盖;这是策略的有意取舍,可接受。

### A.5 重点项 5:Handler 全部 spawn

**[CLOSED]**(原缺陷:Handler 内联 await 架空一切 deadline,BLOCKER gpt/grok、MAJOR kimi)
依据:§4.1 SessionTask"Handler 一律 spawn,SessionTask 永不内联 await 用户代码"——结构上消除了"被防对象阻塞 deadline 执行者"的路径;kex 相关回调(`lookup_dh_gex_group` 等)同属 Handler trait,一并落入 spawn + rekey_deadline(supervisor 持有,不被 Session 状态影响)覆盖;回调结果有界队列回流 + auth/OPEN 决策 deadline(默认 30s)超时按 reject 并释放 slot;§5 handler-block 用例(auth/OPEN/DATA/gex 分别注入 pending/panic/CPU)锚定。活性环检查:Session 不再持有任何指向用户代码的 await,§4.3 表该行("Handler 结果回流 | per-callback deadline")成立。**原缺陷关闭。**

brief 点名问题"reject 后对端重试怎么办":每次重试 OPEN 重新预占一个 opening slot,受 `opening + active + closing ≤ max_channels` 封顶;handler 持续卡死时每次重试占 slot 30s,恶意 open 洪泛 + 卡死 handler 的最坏驻留 = 128 slot × 30s 窗口,闭式有界,不击穿 G4。语义自洽,**[OK]**。

但"一律 spawn"衍生两个正文未规格化的缺口(计入 B 节):回调结果的** per-channel 次序**与**并发任务数上界** → **B.4 [MAJOR]**。

### A.6 附录 A 其余各行核验

| 附录 A 行 | 裁决 | 依据/说明 |
|---|---|---|
| 零字节/EOF 洪泛打穿字节界(BLOCKER grok) | **[CLOSED]** | §4.1 ReaderTask"队列双界:字节界 = 已授窗口+容差;条数界 = window/min_packet+K,重复 EOF/CLOSE 去重、零字节 DATA 丢弃(计数)";§4.7 删除清单明确"零字节/去重护栏随迁"。随迁承诺 + 双界公式,关闭。 |
| ChannelOpenHandle 改有界即自死锁(BLOCKER gpt) | **[CLOSED]** | §4.1"保留免死锁路径:inline 场景直接 finalize 不入队;spawn 场景每个 opening slot 预留一个回复位,天然有界于 max_channels"。与 `client/mod.rs:114-117` 注释的原始意图一致且给出有界性论证,关闭。 |
| 授窗与队列扩容跨任务竞态误杀(MAJOR kimi) | **[CLOSED]** | §4.1"入站窗口记账权威在 Reader……Session 授窗决策 → 消息给 Reader → Reader 先扩本地 cap,再请求 Writer 发 ADJUST"。次序在 Reader 内闭合,对端收到 ADJUST 时 cap 必已扩,window-grant-race 用例锚定,关闭。 |
| Reader await 满 ctrl 队列违反 I1(MAJOR grok) | **[CLOSED]** | I2' 修正版:try_push + 2 MiB 字节预算 + 超限 DISCONNECT,并把"对 RFC 任意 in-flight 的取舍"显式列入 §4.6 策略表。I1 恢复为真,关闭。 |
| 超窗断整连过苛(3/3) | **[CLOSED]** | §4.6 默认关单 channel + 计数,strict 模式可配升级;与 `server/encrypted.rs:1244-1255` 现状语义对齐,关闭。 |
| control 洪泛饿死 bulk(MAJOR gpt) | **[CLOSED]** | I3 第(2)级 burst cap:连续 16 包后若 bulk 可发必须让出一个 quantum;bulk 最小服务率有下界,关闭。burst cap 自身的新风险见 B.5。 |
| "kex 包插队已排 bulk"不成立(gpt/grok) | **[CLOSED]** | §4.1 WriterTask"KexStarted 语义(修正版)":承认 seal 点边界,staging 残余合法发完(RFC 4253 §7.1 以 KEXINIT 上线为界),rekey 启动延迟上界 = staging 高水位 + 一个在制包。kimi 第 1 轮主张的"回收重加密"被明确论证为不必要,论证正确,关闭。 |
| mpsc 条数界限不住 payload;opening 不计 slot;全局 DoS(gpt) | **[CLOSED]**(前两项)/ **[MAJOR] 处置未排期**(第三项) | byte permit(移交所有权前取 permit)+ 全生命周期 slot 记账(§4.1)关闭前两项;global budget 在 §4.4 有公式、§4.7 有 config 项,但**未出现在 S0–S7 任何切片**(见 B.8),处置停留在纸面。 |
| "server 先行"不成立(kimi/gpt) | **[CLOSED]** | §1 非目标与 §6 改为"client 机械同改保编译,行为对齐延后",S4 括号注明"双端同改",关闭。 |
| 事实错误一批(P6 全局→每 channel 等) | **[CLOSED]** | §2 病灶表 P2/P6/P8 已按评审修正;抽查 P6/P8 相关代码属实,关闭。 |
| DRR quantum、聚包、local packet cap、first-byte boost(各家) | **[CLOSED]** | §4.1 采纳 1-packet ready-set 轮转 + 跨条目 gather 聚包 + `local_transport_payload_cap` 默认 32 KiB + 首包 boost;§5 有对应 scheduler 对抗验收。关闭(ready-set 的新缺陷见 B.3)。 |

---

## B. v2 新机制的新风险

### B.1 [MAJOR] 写进度看门狗被"渗出读"对端无限喂活

**机制**: §4.1"最后一次有字节成功写入 socket 的时间戳……有待写数据且超过 write_progress_deadline 无进度 → Cancelling"。

**失败场景**: 恶意(或劣化)客户端把 TCP 接收窗压到极小,每 29s 读 1 字节(deadline 默认 30s)。Writer 的 `write()` 每 29s 成功返回 1 字节 → 时间戳持续刷新 → 看门狗永不触发。出站吞吐被压到 ~0.03 B/s,per-channel 出站队列全部顶满,byte permit 全部耗尽,zfc 全部 relay 卡在 `data().await` —— 与 2026-08-10 事故同构的"连接活着但不可用"状态,只是触发器从 rekey 换成 TCP 渗出。G1 的措辞("要么继续工作,要么有界拆除")在此失效:它既不工作也不拆除。keepalive、inactivity、rekey deadline 均不覆盖此路径(入站无义务、无 kex)。

**要求**: 看门狗判定从"有字节 >0"改为"backlog 有实质排空进度"——例如观测队头包(最老未发字节)的年龄,或窗口期内写出字节数低于阈值且 backlog 非空即视为无进度;规格中写明"进度"的定义与测量点。这不是实现细节,是 G1 在最强敌意场景下是否成立的判定条件。

### B.2 [MINOR] "有待写数据"判定者与时间戳语义未定义

supervisor 不在数据面,需要 Writer 发布两个原子量(最后成功写字节时间戳、backlog 非空标志/字节数)。正文未写:(a) 标志在 kex staging 残余期间是否置位(残余也是"有待写数据");(b) teardown grace 内 best-effort flush 是否重置看门狗(若不重置,Cancelling 中的 flush 会被同一看门狗再次计时,无害但语义含糊);(c) partial write 返回 Ok(n>0) 即刷新(与 B.1 联动)。实施时可定,但 S1 的完成门(write-stall/talk-no-read 绿)依赖这些定义,应在 S1 开工前补一小节。

### B.3 [MAJOR] ready-set 谓词把不耗窗口的 fence 项锁死在零窗 channel 上

**机制**: §4.1"bulk 对'有窗口余额 && 队列非空'的 channel 用 ready-set 轮转";同 channel 的 EOF/CLOSE/SUCCESS/FAILURE 作为 fence 项排在该 channel 出站队列中。

**失败场景**: channel 窗口 2 MiB,relay 写完最后一段数据恰好耗尽窗口,随即 `eof()` → EOF 作为 fence 项入队尾。该 channel 窗口余额 = 0 → 不在 ready-set → EOF 永远排不到调度。对端是"消费完数据、等 EOF 收尾才关闭本地写侧"的实现(代理场景常见:对端把流交给本地连接,本地连接 close 后等 SSH 侧 EOF);若对端的 ADJUST 策略是滞回批量(消费过半才补窗,§4.5 我们自己就这么设计),恰好耗尽且不触发补窗的边界情形下,ADJUST 可能迟迟不来 —— EOF/CLOSE 被本端自造的窗口谓词无限期压住。RFC 4254 §5.2:只有 DATA/EXTENDED_DATA 消耗窗口,EOF/CLOSE/SUCCESS/FAILURE 的发送**不以窗口余额为前提**。这是 v2 新引入的自伤:把 fence 项塞进 bulk 调度域,却沿用了 bulk 的准入谓词。

**要求**: ready-set 准入谓词改为"队列非空 &&(队头可达的第一个 fence 项之前没有阻塞 DATA || 有窗口余额)";或等价地:fence 项到达队头时无视窗口余额直接发送。一句规格,但必须在 S2 开工前写死,否则 close-with-backlog 用例的镜像变体(恰耗窗 + eof)会红。

### B.4 [MAJOR] Handler 一律 spawn:per-channel 次序与并发任务上界双双未规格化

**机制**: §4.1"Handler 一律 spawn……回调结果经有界队列回流"。

**失败场景 1(次序)**: 若 spawn 范围包含 per-message 回调(Handler::data / extended_data / request 响应),同一 channel 两个连续 DATA 触发两个并发 spawn,完成序反转 → 回流队列中结果乱序 → 应用可见序与 wire 序不一致 → 下载内容错位。正文未写"spawn 结果的 per-channel 保序"(单调序号 + 重排缓冲,或数据面不经 spawn 直接走 per-channel 队列)。zfc 的数据面走 Channel receiver,若 v2 意图是数据面绕过 Handler 直投队列,必须写明文;否则按 trait 现状 Handler::data 是必经路径。

**失败场景 2(任务数)**: 恶意对端在已建立 channel 上以线速洪泛 want-reply REQUEST(每条 spawn 一个 handler 任务),handler 是 zfc 的慢路径(如下游 connect,耗时至 deadline 30s)。spawn 无并发上界 → 任务数 = 入站速率 × 30s,10k/s 洪泛 = 30 万个任务与各自的回流 oneshot。per-callback deadline 界的是单任务寿命,不是任务总量;回流队列有界但满时 spawn 的任务 await send 反而堆积更多任务。G4 闭式里没有这一项。

**要求**: (a) 写明数据面回调不经 spawn(直投 per-channel 队列)或 spawn 结果按 channel 单调序号重排;(b) 全局/每连接 spawn 并发上限(semaphore),超限对入站施加反压或直接按策略处置;(c) 把"handler 任务驻留 ≤ 并发上限 × 单任务内存"补进 §4.4 公式。

### B.5 [MINOR] kex 专用队列"按枚举定容,永不满"的论证依赖 Writer 消费

容量 16 的枚举(KEXINIT、ECDH/GEX 回包×2、NEWKEYS、InstallEpoch×2、DISCONNECT、strict 违例断连)在单轮 kex 内成立。但"永不满"隐含 Writer 持续消费:Writer 卡 socket write 时,rekey-storm(对端连续 KEXINIT,§5 已有用例)使 Session 每轮产生 ~5 条 kex 消息,Writer 不消费 → 16 槽可被打满。满时行为正文未定义:Session 若 await push 则 Session 卡死(靠 supervisor 的 write_progress/rekey deadline 兜底拆除,结果正确但路径肮脏);若为 try_push 失败 → 应明确按 I2' 同例 Cancelling。**要求**: 写明 kex 专队满 → Cancelling(计数 + tracing),与 I6 一致;论证改为"稳态不满 + 满时 fail-closed",而非"永不满"。

### B.6 [MINOR] rekey deadline 的注册/注销竞态

Session 进入 InKex 注册 deadline、双向 NEWKEYS 生效后注销(§4.2)。竞态窗口:kex 完成的瞬间注销消息与 supervisor 的 deadline 触发同时发生 → 健康连接被以 RekeyTimeout 拆除。概率极低(30s deadline vs 毫秒级 kex),但"首个 Cancelling reason 获胜"意味着误杀无后悔药。**要求**: 注册/注销带 generation,supervisor 触发前校验当前 generation 仍处于 InKex;或注销要求 supervisor 确认。一句话规格。

另注:Session→supervisor 的注册通道是正文新增的第 4 条跨任务通道,未出现在任何活性/有界论证中;容量 1 或 unbounded 均可,但应写明它不参与任何等待环。

### B.7 [MINOR] 首包 boost 可被 channel churn 注水

"新激活 channel 的首个 packet 给一次优先轮次"——攻击者反复 open/close channel(每 open 一次换来一个优先 quantum),open 速率 r/s 即注入 r 个插队包/s。每个 open 成本是一次完整 channel 握手,且 slot 上限 128 并发,攻击成本高、收益小;但若 boost 实现为严格优先队列而非加权轮次,理论上可持续压低稳态 bulk 的服务率。**要求**: boost 预算化(如每 N 个 bulk quantum 至多 1 个 boost),或写明 boost 只在 ready-set 轮转中插一次队、不构成独立严格优先 lane。

### B.8 [MAJOR] 切片 S0–S7 漏排两个已承诺的 BLOCKER 级改动

附录 A 声称关闭的两项处置,在 §6 实施序列中找不到归属切片:

1. **Handler 一律 spawn + per-callback deadline + 决策 deadline + 全生命周期 slot 记账**(关闭第 1 轮 BLOCKER"内联 await 架空 deadline"与"opening 不计 slot"):S1 是 supervisor,S2 Writer,S3 Reader,S4 窗口/permit,S5 RekeyPolicy,S6 性能,S7 矩阵——无一包含 Handler 执行模型改造。这意味着按现序列走到 S7,活性表第 4 行仍是空的,handler-block 用例(S5 之前的切片就无法绿)无归属。
2. **进程级 global byte budget**(gpt 的 G4 补齐项,§4.4 自称"单连接闭式必须配全局预算才构成 G4"):§4.4/§4.7 有定义,切片中无实现排期。

**失败场景(规划层)**: S4 删 Scheme C 后、Handler spawn 未落地时,zfc 一次回调阻塞(zfc 已有手工加 timeout 的前科,`server.rs:250-267` 被 gpt 引用)→ SessionTask 卡死 → ctrl 队列满 → Reader try_push 失败 → Cancelling 断连。连接不死(守住了 G1),但**误杀率**取决于用户代码质量——这正是第 1 轮 BLOCKER 想要消灭的耦合,按现切片序列它会在整个实施期间持续存在,且没有一片的完成门能发现它。**要求**: Handler spawn + slot 生命周期单独成切片(建议插入 S3 与 S4 之间,数据面次序问题 B.4 同片解决);global budget 并入该切片或 S4,写入完成门。

### B.9 [MINOR] 双路径 CLOSE 的 slot 驻留与 wire-lifecycle 通道

wire-lifecycle 事件直发 Session(立即回 CLOSE、停止出站、丢弃积压)+ app-delivery marker 队尾保序,generation 关联——语义与现状 `close_discarding_pending` 对齐,方向正确。两个未写清的点:(a) 应用永不 drain 时,该 channel 的 closing slot 与队列驻留至连接拆除(有界于 max_channels × 队列双界,可接受,但 §4.4 公式应点名"closing 驻留"一项);(b) wire-lifecycle 事件走哪条通道进 Session——若走 ctrl 队列 try_push,满即 Cancelling,mandatory close reply 失败即断整连,略苛但与"宁断勿僵"自洽,写明即可。

### B.10 [OK] supervisor 状态机 / byte permit / 全局预算的其余面

- supervisor `Running → Cancelling(reason,deadline) → Aborting → Joined`:单向 abort、无队列、首 reason 获胜、总 grace 不叠加,环检查通过(§4.3 末段论证成立)。残留:spawn 的 handler 任务若陷入阻塞式 CPU/同步 syscall,abort 无法生效(tokio 不能取消不 yield 的任务),zombie handler 持内存至其自行返回——这是对用户代码的固有残余,per-callback deadline 管不到真正的死循环;可接受,建议 I6 加"handler 超 deadline 后仍驻留"计数。
- byte permit 双信号量(per-channel + global)按固定顺序(先 channel 后 global)获取,无 ABBA 环;permit 释放在 Writer seal/发送路径,与 kex/teardown 的交互(teardown 全部 Err 唤醒)已写;channel 被对端 CLOSE 时积压 permit 的归还路径建议补一句。
- ready-set 的唤醒闭合(ADJUST 入账与 ready-set 同在 Writer 任务内,credit 到账即重激活)无跨任务 lost-wakeup,成立。

---

## C. 可开工判定

**裁决:v2 不能直接进入 S0/S1。** 方向与骨架经第二轮攻击依然成立,第 1 轮 BLOCKER 的主体确已关闭;剩余缺口均为可在一轮修订内关闭的规格/排期项,不需要改架构。

仍需关闭的最小缺口清单(按优先级):

1. **[MAJOR] B.1 看门狗进度定义**:把"任意字节 >0 即刷新"改为对 backlog 实质排空进度的判定(队头年龄或窗口期吞吐下限),否则 G1 在渗出读场景失效,S1 的完成门(write-stall/talk-no-read)测不出这条路径——S1 开工前必须关闭。
2. **[MAJOR] B.3 fence 项零窗锁死**:ready-set 准入谓词为 EOF/CLOSE/SUCCESS/FAILURE 开"不耗窗口"豁免——S2 开工前必须关闭,否则 close-with-backlog 的边界变体必红。
3. **[MAJOR] B.8 切片补排**:Handler spawn(含 B.4 的次序与并发上界规格)与 global budget 落入具体切片及完成门——这是排期缺口,不补则两个已承诺的 BLOCKER 处置永远停在附录里。
4. **[MAJOR] B.4 Handler spawn 规格**:数据面回调是否经 spawn、结果的 per-channel 保序、spawn 并发上界与 §4.4 公式补项。
5. **[MINOR] 打包关闭**(B.2/B.5/B.6/B.7/B.9):"有待写数据"判定与 teardown 交互;kex 专队满 → Cancelling;deadline 注册/注销 generation;boost 预算化;closing slot 驻留计入公式。

1–4 关闭后,方案可进入 S0。S0(harness 先行)与 S1(supervisor 先行)的排序本身正确,最大风险(看门狗语义)恰好排在最先验证的位置——前提是把缺口 1 的定义写进 S1 完成门。

—— 复审结束。与第 1 轮相同:本文不是背书,缺口 1–4 清零前不要写数据面代码。
