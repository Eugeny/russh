# russh Session Loop 全量重构方案 —— 代理场景专用、永不僵死架构

- 状态: **v2.1**,经两轮三模型对抗评审(gpt-5.6-sol / grok-4.5 / kimi-k3)修订
  - 第 1 轮(对 v1,均判 NO-GO):`.omc/research/russh-rewrite-review-{gpt,grok,kimi}.md`
  - 第 2 轮(对 v2,复审):`.omc/research/russh-rewrite-review-r2-{gpt,grok,kimi}.md`
  - v2→v2.1 修订清单见附录 B。**诚实声明**:v1 三家 BLOCKER 均有正文对症机制,其中大部分完全闭合;第 2 轮指出的规格级缺口(看门狗谓词、NEWKEYS 安装 ACK、Handler 执行模型、G4 口径、OPEN_CONFIRM fence、入站 ADJUST 旁路等)已在本版逐条写入正文。
- 日期: 2026-08-12
- 范围: russh fork(本仓库)双端 core(server 先验收,client 机械同改保编译、行为对齐延后);上层消费者为 ../zfc SSH 入站(已核实 zfc 仅用 `russh::server`)
- 前提: 未发布,无兼容包袱;按纵向切片实施但**不发布中间版本**

---

## 0. 背景与动机

zfc 以本 russh fork 作为 SSH 服务端承接代理入站。对端是用户 App 内嵌的**第三方通用 SSH 客户端**(不可控、不可改配置),单条 TCP 上多路复用大量 `direct-tcpip` channel(真机观测:YouTube×2 + speedtest 三条流共 ~1.42 GB 下行走同一 TCP)。

### 0.1 事故史(为什么补丁路线走到头了)

| 事件 | 根因 | 补丁 |
|---|---|---|
| YouTube 偶发卡死不自愈 | 全连接共享 event buffer,单 channel 满 gate 整条连接 | `event_buffer_size: 64` 调参(未治根) |
| session loop 死锁族 | 入站投递阻塞 loop / open-reply 无界 / flush 与读互锁 | a7e9688(Scheme C)、94b3a20、917d0c5、9f772b0 |
| **2026-08-10 真机 wedge** | speedtest 推过 1 GiB → 服务端主动 rekey → 第三方客户端在饱和下行中未完成 rekey → `kex.active()` 屏障永久 gate 出站,13 条 relay 全部写超时,直到客户端自行新开 TCP 才恢复 | 无(本方案的直接动机) |

补丁史的模式:每个死锁修复都在单任务 `select!` loop 里加一个 gate / cap / generation / deferred teardown,不变量靠注释维护。**结论:单 loop 架构复杂度已越过可维护线,重构。**

### 0.2 已论证排除的方向

**"每代理连接一条 TCP(1 session + 1 channel)"不可行**:RFC 4254 中 `CHANNEL_OPEN` 纯客户端发起,协议无"请新开连接"信号;拒绝第 2+ 个 open 的通用客户端行为是让该流失败而非重拨。本方案面向**单连接多 channel 的极限鲁棒 + 极限性能**。

---

## 1. 目标 / 非目标

### 目标

- **G1 永不永久僵死**:任意对端行为下,连接要么继续工作,要么在**有界时间**内被拆除。"拆除"= supervisor 强制 abort 三任务并 drop 两个 socket half,**不以任何协议报文(含 DISCONNECT)成功发出为前提**。"继续工作"的活性判据是字节级进度;在其之上另有**显式标注为策略**的最低排空阈值(§4.2 watchdog),把"渗出读"式的假活连接也纳入拆除范围——这是运营取舍,不冒充活性公理。
- **G2 断流隔离**:单 channel 的慢消费/停读/窗口耗尽只影响该 channel。特别地,**合法的 peer-window=0 反压永不触发连接级拆除**。
- **G3 代理性能**:下行吞吐逼近链路上限;open→first-byte 延迟最小化;大流不饿死小流,**新流 boost 也不得饿死老流**(配额化)。
- **G4 内存有界(诚实口径)**:core 已接管字节的每连接上界为闭式,并配进程级全局预算(含**入站授窗**与连接数上限)。**显式排除**:仍由调用方 async future 持有、尚未通过同步预检+permit 移交给 core 的 payload(由单次 payload 同步上限限制其单笔尺寸,但调用方任务总数不在 core 控制内)。
- **G5 API 兼容 zfc(源码级)**:`Handler` trait、`Handle`、`Channel` 的**方法名与调用点源码不变**;`Session` 重实现为命令 facade(类型名与方法名保留,内部消息化)。完成时机语义变化逐项 contract test(§4.8)。
- **G6 客户端零假设**:所有比 RFC 更严/更宽的策略集中在 §4.7 策略表,经真实客户端矩阵验证。

### 非目标

- 不改 SSH 线上协议,不要求客户端配合。
- 不追求服务端主动 rekey 的密码学卫生(由包数硬界兜底,I5)。
- client 侧行为优化延后;代码随共享 core 机械迁移保编译与测试绿。

---

## 2. 现状架构与病灶清单

现状:每连接一个任务,`server/session.rs::run`(982 行起)单 `tokio::select!`,7 个 arm:读、Scheme C reserve、open-reply、keepalive、inactivity、并发 flush(cancel-safe 游标)、Handle 消息。

| # | 病灶 | 位置 | 后果 |
|---|---|---|---|
| P1 | **kex 是无 deadline 的全连接屏障**:`kex.active()` gate 三个 arm;`data`/`extended_data` 在 `is_rekeying` 时压入 `pending_data`(session.rs:651-654、742) | server/session.rs:1046,1108,1118 | rekey 不完成 → 出站永久 gate(事故) |
| P2 | **车道混用**:kex 与 bulk 共用 `write_buffer` 单 FIFO;`OUTBOUND_HIGH_WATERMARK`(128 KiB)只是 intake 软上限,pending_data 批量 flush 可远超 | sshbuffer.rs:369 | KEXINIT 排在至少 128 KiB、实际可能多得多的 bulk + TCP sndbuf 之后 |
| P3 | **无跨 channel 公平调度**:per-channel FIFO;`flush_all_pending_with_writer` 按 HashMap 任意序 | session.rs | 大流饿死小流 |
| P4 | **kex 状态机隐式**:`kex.active()`/`rekey_wanted`/`skip_exchange` 散布 | session.rs:783-800 | 不变量靠注释 |
| P5 | **补丁堆叠**:Scheme C + generation + deferred teardown + 双路径 drain + outbound cap;open-reply 的 unbounded 是**有意设计**(防 handler 内联 accept 自死锁,client/mod.rs:114-117) | server/session.rs | 复杂度越线 |
| P6 | **入站有界但机制昂贵**:`max_pending_inbound_bytes` = 每 channel 16 MB + reserve futures | pending_inbound.rs | 与 window 语义重复的第二层反压 |
| P7 | **keepalive 兜底是纸面的**:默认 `None`(server/mod.rs:140);`alive_timeouts` 被任意入站数据清零(server/session.rs:1161-1167);zfc 现网 `inactivity_timeout: None` | — | "只发不收"对端使写 stall 无 deadline |
| P8 | **存量协议缺口**:`rekey_read_limit` 未接入触发路径;rekey 换压缩算法时 `newkeys` 不写回新算法枚举;`pending_reads`/`pending_len` 死代码;`Limits::new` assert ≤1 GiB 与 usize 字段 | session.rs:131-147,787-800; lib_inner.rs:274 | 重构时显式修/删 |
| P9 | **出站窗口双账本**:`WindowSizeRef`(channels/io/tx 预扣)与 wire 侧 `recipient_window_size` 两处记账 | channels/mod.rs | lost-wakeup / 假满风险,新架构须单一权威 |

---

## 3. 设计不变量

- **I1 读永续**:Reader 除两个显式等待点外永不等待——(a) 等新 inbound epoch(受 rekey deadline 覆盖,token 可打断);(b) ctrl `try_push` 失败时不等待,按 I2' 断连。
- **I2 隔离**:所有 per-channel 状态有**字节界+条数界**;满 → 只反压/处置该 channel。
- **I2' 有界摄入**:Reader 对 ctrl 队列只 `try_push`;超字节预算(默认 2 MiB)→ Cancelling(计数+tracing)。这是对 RFC 4253 §7.1 "须处理任意数量 in-flight 报文"的显式取舍。**同规则适用于 kex 专用队列与 wire-lifecycle 事件**:任何"必须送达"的内部消息通道满 = fail-closed 拆连,绝不静默丢弃或无界等待。
- **I3 车道与因果序**:三级——(1) KEX/NEWKEYS/DISCONNECT 绝对抢占;(2) 普通 control(出站 ADJUST/keepalive/global 回复)高优先 + **burst cap**(连续 16 包后若 bulk 可发让出一个 quantum);(3) bulk。**per-channel 因果序高于车道优先级**:同 channel 的 OPEN_CONFIRMATION/DATA/EXTENDED_DATA/EOF/CLOSE/REQUEST/SUCCESS/FAILURE 全部经该 channel 出站队列按提交序上线(CONFIRMATION 是队首 fence,EOF/CLOSE 是队尾 fence);**唯一旁路**是出站 WINDOW_ADJUST(与出站数据无因果依赖)。fence 项(CONFIRMATION/EOF/CLOSE/SUCCESS/FAILURE)**不消耗窗口,调度准入不看窗口余额**(RFC 4254 §5.2 只有 DATA 耗窗)——否则恰好耗尽窗口后的 EOF 会被自造谓词锁死。
- **I4 一切 progress-wait 有 deadline**:idle wait(空队列 recv、合法反压如 peer-window=0 或 permit 等待)无需界;progress wait(持有资源/协议义务的等待)必须有界,界由 supervisor 强制,不经任何可阻塞队列。permit 等待归为反压类 idle wait 的前提是:**获取序全局唯一 + teardown 全量 Err 唤醒**(§4.5),排除 ABBA 与遗留挂起。
- **I5 rekey 策略**:服务端默认不主动 volume/time rekey;硬界双触发器——**每方向每 key-epoch 包数 2^31**(第一触发器;计数含 kex/IGNORE 等一切消耗 seqn 的包,在该方向**新 epoch 安装 ACK 时归零**;与 strict-kex 的 wire seqn 置 0 是两件事,都发生在安装点)+ 字节 1 TiB(第二触发器,同 epoch 生命周期)。读写双向独立记账(Reader open 成功/Writer seal 成功时递增);**双向同时触发合并为单次 InKex**。触发或配合的 rekey 在 deadline(默认 30s)内未完成 → 拆连;绝不静默越过 2^32−ε。API:`RekeyPolicy { max_packets: u64, max_bytes: u64, deadline: Duration }`(替换 `Limits`,修 P8 的 assert/usize 问题)。
- **I6 一切 cap/丢弃/截断/降级/超时可观测**:tracing + counter,含"handler 超 deadline 后任务仍驻留"计数。

---

## 4. 目标架构

### 4.1 任务拓扑

```
                  ┌──────────────────── ConnSupervisor ────────────────────┐
                  │ 持有: JoinHandle×4 + abort 权(三任务+HandlerExecutor)   │
                  │      + 两个 socket half 的最终 drop 权                  │
                  │ 定时器: write_watchdog / rekey / handshake / grace      │
                  │ 状态: Running → Cancelling(首因,deadline) → Aborting    │
                  │        → Joined ;监督输入 = 原子快照/watch,非队列      │
                  └────┬──────────┬──────────┬──────────┬──────────────────┘
                       │          │          │          │
socket ─read─► ReaderTask ─ctrl(try_push)─► SessionTask ⇄ HandlerExecutor(独占 &mut Handler,串行)
               │ inbound epoch 独占          │ kex 状态机(计算)              │ 超时=drop future
               │ 入站窗口记账权威            │ channel 生命周期+slot(gen)    │ zfc 用户代码
               │ ADJUST 旁路→Writer          │ 授窗决策 / 命令 facade        │
               ▼                             ▼(control/kex 专队)            │
     per-channel 入站队列(双界,全序)   WriterTask ── cancel-safe write ──► socket
               ▼                       │ outbound epoch 独占;peer 窗口记账权威(checked)
        zfc relay(app)                 │ per-channel 出站队列(fence 项+DATA 同队保序)
               └── data().await(同步预检+permit)──┘ ready-set 1-packet 轮转 + 配额化 boost
```

### 4.2 ConnSupervisor(规格)

**监督输入**:Writer 维护一个**单结构原子快照** `WriteProgress { generation, last_write_ok_at, wire_eligible_bytes, drained_bytes_epoch }`,同一 release store 更新;supervisor 一次 load 读取,**禁止分字段读**(消除撕裂竞态)。Session 的 rekey deadline 注册/注销走 `watch`(带 kex generation),不走可满队列;supervisor 触发前校验 generation 仍在 InKex(消除注销竞态误杀)。

**写看门狗(两层判定)**:

1. **武装谓词(活性层)**:`wire_eligible_bytes > 0` —— 定义为 *staging 中已 seal 密文 + 在制包 + 因窗口/调度以外原因待 seal 的项*;**不含**"仅因 peer-window=0 而无法 seal 的 per-channel 队列积压"(RFC 合法反压,G2)、不含"仅在等 permit 的应用调用"。武装时钟只在 **idle→eligible 边沿**采样(`armed_at = now`);连接空闲后恢复工作不得拿旧 `last_write_ok_at` 立即误杀。
2. **进度判定**:
   - *活性判据*:自 `armed_at`/上次进度起,任意一次 socket write 返回 `Ok(n>0)`(含 partial)即进度。
   - *策略判据(显式标注为运营策略,可配可关)*:`write_min_drain`(默认 4 KiB / 30s 窗口)——武装状态下窗口期内累计写出字节低于阈值 → 视同无进度。此层专杀"每 29s 读 1 字节"的渗出读假活;它是吞吐 SLO 而非活性公理,故独立配置项、独立 counter、默认开启。
3. 无进度超过 `write_progress_deadline`(默认 30s)→ Cancelling(WriteStalled)。

**统一拆除**:任一任务 Err/panic、任一 deadline/watchdog 触发 → 首因获胜 → 广播 CancellationToken → **Writer 的每个 socket write 点都是 `select!(write, token, kex 专队)` 的 cancel-safe 结构**,Cancelling 时立即放弃当前 bulk write,尝试排一次 DISCONNECT(best-effort);总 grace(默认 5s,不叠加)到期 → `abort()` 全部任务 → drop 两个 socket half(generic `AsyncRead+AsyncWrite` 无第三份 fd,drop 即关);唤醒**全部** waiter(per-channel permit、global permit、oneshot、结果队列)为 Err。Cancelling 期间看门狗停止计时(grace 自带 timer)。handshake(banner/初始 kex/auth)整体受 `handshake_deadline` 覆盖。已知残余:陷入同步死循环的 handler 任务 abort 不掉(tokio 不能取消不 yield 的代码),其内存驻留至自行返回——I6 计数可观测,文档标注为用户代码固有风险。

### 4.3 三任务与 HandlerExecutor(规格)

**ReaderTask**:独占 inbound epoch(cipher+MAC+decompressor+入站 seqn)。
- channel-scoped 报文 → 该 channel 入站队列**全序** `try_push`(DATA/EXTENDED_DATA/EOF/CLOSE/REQUEST/SUCCESS/FAILURE)。**入站 WINDOW_ADJUST 例外**:app 无需消费它,其唯一副作用是出站信用——Reader 在**解析点**直接向 Writer 发信用通知(专用低延迟路径),不入 app 队列、不经 Session(消除"ADJUST 排在满 app 队列尾 → 出站停摆"的跨任务冲突;对齐现状 server/encrypted.rs:1263+ 的立即入账)。
- 队列双界:字节界 = 已授窗口 + 1×maxpacket 容差;条数界 = window/min_packet + K;重复 EOF/CLOSE 去重、零字节 DATA 丢弃(计数)。超窗默认关单 channel(§4.7)。
- **入站窗口记账在 Reader**:Session 授窗决策 → Reader 先扩本地 cap → 再请求 Writer 发 ADJUST(次序内部闭合)。授窗前须先取得 **global inbound credit**(§4.5)。
- peer CLOSE 双路径:app-delivery marker 入队尾保序;**wire-lifecycle 事件**经 ctrl `try_push` 直发 Session(满 → Cancelling,I2';mandatory close reply 的义务宁断勿僵)。
- 收到 NEWKEYS:旧 epoch 打开并处理完 → 等新 inbound epoch(Session→Reader 专用容量 1 通道;**key 先到与 NEWKEYS 先到两态都合法**,状态机双态)→ 原子安装(含 strict seqn 置 0、decompressor 重建、I5 计数归零)→ 回 `InstallAck{Inbound, gen}` → 读下一包。

**WriterTask**:独占 outbound epoch。
- 每 channel 一个出站队列:OPEN_CONFIRMATION(队首 fence)、DATA、EOF/CLOSE/SUCCESS/FAILURE(fence 项)按提交序;**channel 状态 `Opening → Confirmed → Closing`,仅 Confirmed 且非 Closing 者进 ready-set**;fence 项调度不看窗口余额(I3)。CONFIRMATION 未上线前该 channel 的 DATA 不可能先发(同队列保序)——§4.5 v2 的"accept 返回即安全"论断废除,以 Writer 内状态机为准。
- ready-set 1-packet 轮转 + 跨条目 gather 聚包(上限 `min(peer_maxpacket, 余窗, local_transport_payload_cap=32 KiB)`);**boost 配额化**:新 Confirmed channel 首 packet 的 boost 每 N 个普通 quantum 至多 1 次(默认 N=8),计入公平债;scheduler 测试断言老 bulk 最小服务率 > 0(防 open/close churn 注水)。
- peer 窗口记账权威(checked 算术;ADJUST 累计溢出 u32 → 断连)。**单一账本**:`WindowSizeRef`/`outbound_acks` 双账本机制删除,生产者只等 permit,窗口只在 Writer(修 P9)。
- **KexStarted**:立即停止 seal bulk;staging 已 seal 残余照常 FIFO 发完(wire 序先于 KEXINIT,合法);kex 报文经**kex 专用队列**(容量 16;`try_push`,满 → Cancelling——"永不满"论断废除,改为"稳态不满 + 满时 fail-closed";枚举含 KexStarted/KEXINIT/回包/NEWKEYS/InstallEpoch/DISCONNECT,GEX 多两条,simultaneous rekey 单飞行不复用并发轮次)。Writer 阻塞于 write 时仍能被 token 打断并转向 kex 队列(cancel-safe 结构,§4.2)。
- **NEWKEYS 原子序**:`seal(NEWKEYS, 旧 epoch)` → **同任务内无 `.await` 间隔**地原子安装新 outbound epoch(cipher+MAC+compressor+seqn policy+I5 计数归零)→ 回 `InstallAck{Outbound, gen}` → **即刻恢复 seal bulk(新 epoch)**——RFC 4253 允许发出 NEWKEYS 后立即用新钥发送,**不等对端 NEWKEYS**(bulk 恢复点与 Session 的 Idle 解耦;Idle 只负责注销 deadline)。
- peer CLOSE 停止边:Session 处理 wire-lifecycle 后向 Writer 发 `StopDiscard(c, gen)`,走 kex 级优先(不排 bulk 后);Writer 置 closing tombstone,**每次 seal 前校验**;正在 seal 的一包可完成,**未开始 seal 的队列项全部丢弃**(已 seal staging 不可截断——包边界+seqn 已分配);本端排队中的应用 CLOSE 与回执 CLOSE 按 gen 去重仲裁。CLOSE 已发出后,该 channel 禁止再发 ADJUST/SUCCESS 等控制包(生命周期门闩)。
- 每次 write `Ok(n>0)` 更新 WriteProgress 快照。

**SessionTask**:kex 计算与状态机、auth、channel 生命周期与 slot、授窗决策、命令 facade 后端。
- **kex 完成判定 = ACK 驱动**:进入 InKex 时注册 deadline(watch+gen);算出密钥后 `InstallInboundEpoch{gen}` → Reader(尽早,不等出站)、`EmitNewkeysAndInstallOutbound{gen}` → Writer;**仅当收到双方向 `InstallAck{gen}` 且对端 NEWKEYS 已处理**才回 Idle 并注销 deadline——"命令已入队"绝不等于完成;投递失败/超时 → Cancelling。迟到的 Install/Ack 按 gen 丢弃(错代密钥不可能被安装)。
- **channel slot**:`opening + active + closing ≤ max_channels`(默认 128),OPEN 解析即预占;每个 opening 持 `(id, generation)`;decision deadline(默认 30s)超时 → 发 OPEN_FAILURE、释放 slot;**晚到的 accept/reject 按 gen 校验后丢弃**,handler 侧得 `Err(Expired)`(免死锁路径保留:inline finalize 不入队;stashed reply 走每 slot 预留回复位)。
- 授窗决策、`RekeyPolicy` 双向触发合并、DISCONNECT 编排。

**HandlerExecutor**(新增,独立任务):**唯一持有 `&mut Handler` 者,串行执行回调**。
- Session 经有界队列发 `Invoke{gen, op}`;Executor 串行跑回调,**per-callback timeout 到期即 drop 该 future**(借用随 drop 结束,Handler 所有权保留;部分变更风险文档化,用户代码须 cancel-safe——标准 async 假设);结果 `Result{gen, …}` 回流有界队列。
- **串行 ⇒ per-channel 回调次序天然保序;in-flight ≤ 1 运行 + 队列深度**,内存驻留闭式可计(修 v2 的并发 spawn 次序/无界两洞)。队列满 → 对 Reader ctrl 施加 try_push 反压(按 I2' 处置)。
- **数据面不经 Handler**:zfc 场景 `Channel`/`ChannelStream` receiver 被取走后,DATA 由 Reader 直投 per-channel 队列(现状即如此);`Handler::data` 仅在无 receiver 的 handler-mode 生效,且经 Executor 串行(保序自动成立)。
- **`Session` 类型重实现为命令 facade**:方法名/签名保留(G5 源码级兼容),内部为有界命令队列到 SessionTask;回调拿到的 `&mut Session` 是 facade 实例,不再是共享可变状态——"一律 spawn 与 `&mut self`/`&mut Session` 类型矛盾"由"单拥有者串行 + facade"解决,不靠 `Arc<Mutex>`。zfc 侧语义差异(命令异步生效)列入 contract test。

### 4.4 kex 状态机

```
Idle ──KEXINIT(收/发)──► InKex{gen=G, deadline 注册(watch)}
  阶段: WaitKexInit? → WaitReply → WaitNewKeys(双向独立跟踪)
  完成: InstallAck{In,G} ∧ InstallAck{Out,G} ∧ 对端 NEWKEYS 已处理 ──► Idle(注销 deadline,gen 校验)
  超时: supervisor 按 G 校验后 Cancelling(RekeyTimeout)
```

首次 kex 与 rekey 同状态机;首次 kex+auth 受 handshake_deadline。strict-kex:初始 kex 收非 kex 报文断连(现 msg.rs 校验链迁移);seqn 置 0 在各方向安装点;测试锚定"重置后第一包 seqn=0"。压缩:`Compress`/`Decompress` 随各方向 epoch,安装时按**新协商算法**重建(修 P8);deferred 压缩由 Session 在 auth 成功时发 EnableCompression。

### 4.5 permit 与全局预算

- **单次 payload 同步预检**:`data()`/`data_bytes()` 在任何挂起点之前检查长度,超 `max_payload_per_call`(默认 4 MiB)→ **同步 Err**,不进入 parked-future 路径(堵住"N 个 future 各持 512 MiB 等槽位"的主通道;G4 口径见 G4 声明)。可选补充 reservation-first API(`reserve(n) → Permit → commit`)供 zfc 热路径。
- **获取序全局唯一:先 global 后 per-channel**(全仓库唯一约定,消 ABBA);释放 exactly-once(成功上线、失败、cancel、channel close、teardown、Drop 同一路径);teardown 时**两级全部** close/Err 唤醒。
- **global budget 覆盖三类**:出站 permit、**入站授窗信用**(初始窗口与每次 ADJUST 前由 Reader/Session 预留;消费/关 channel/拆连退款)、opening 预留。**每连接固定协议预算(ctrl 2 MiB + writer control 2 MiB 等)计入同一会计,并设全局连接数上限**——否则千连接 × 固定预算线性打穿主机。大连接长期占满 global 的饥饿:per-connection 保底配额,文档化。

### 4.6 内存上界(G4 口径)

```
core 接管字节 ≤ Σ_chan(w_in + out_cap) [chan ≤ max_channels,含 opening/closing 驻留]
             + ctrl/writer-control/kex 专队字节预算 + kex 暂存(条数×字节双 cap)
             + staging 高水位 + 读侧半包缓冲(1×max wire packet)
             + HandlerExecutor 队列深度 × 单项上限 + 瞬态 epoch(密钥材料/新旧压缩 context)
排除: 内核 socket buffer;调用方 future 持有的 payload(单笔 ≤ max_payload_per_call,总量不受 core 控制)
全局: global_byte_budget(三类覆盖) + max_connections;单连接闭式 + 全局预算才构成抗 DoS 论证
```

zfc 实配建议:`w_in=1 MiB`、`out_cap=2 MiB`、`max_channels=128`。

### 4.7 显式策略表(全部可配+可观测)

| 场景 | 默认策略 |
|---|---|
| 入站超窗 | 关单 channel + 计数(strict 可配断连) |
| 零字节 DATA / 重复 EOF/CLOSE | 丢弃/去重 + 计数 |
| ctrl / kex 专队 / wire-lifecycle 通道满 | Cancelling(fail-closed,I2') |
| 收到对端 KEXINIT 后仍到达的上层报文 | 容忍处理 + 计数(strict-kex 初始 kex:断连) |
| ADJUST 累计溢出 u32 / 单包超 cap | 断连 |
| 对端不回 OPEN confirm / want-reply | per-request deadline → 调用者 Err |
| handler 回调超时 | drop future + `Err(Expired)` 给晚到 disposition + 计数 |
| 渗出读(排空低于 write_min_drain) | Cancelling(策略层,可关) |
| CLOSE 后同 channel 控制包 | 生命周期门闩,丢弃 + 计数 |

### 4.8 API 兼容与删除清单

**保持(源码级)**:`Handler`/`Handle`/`Channel`/`ChannelStream` 方法名与签名;`Session` 类型名与方法名(重实现为 facade)。
**语义变化(逐项 contract test)**:`data()` 反压点(permit)与同步预检 Err;`Handle::data` 完成=入队;`Session` 方法命令化(异步生效);Handler 回调在 Executor 上串行、可被 timeout drop;`Limits`→`RekeyPolicy`。
**删除(附替代物)**:Scheme C 全套(→ 窗口双界队列,护栏随迁);`max_pending_inbound_bytes`(→ 窗口即界,前提是消费返窗权威路径闭合:partial-read 按实际返给调用者的字节记账、handler-mode 由 Executor 记账、receiver drop 走 teardown 返窗);pre-select 双路径 drain;`pending_reads`/`pending_len` 死代码;**`WindowSizeRef`/`outbound_acks` 双账本**(→ Writer 单一权威 + permit);`event_buffer_size` 调参项。
**不删**:open-reply 免死锁路径(slot 预留重实现);teardown flush/drain 语义(并入统一 grace);`close_discarding_pending` 语义(并入 StopDiscard)。
**新增 config**:`rekey_policy{max_packets=2^31,max_bytes=1TiB,deadline=30s}`、`write_progress_deadline=30s`、`write_min_drain=4KiB/30s(策略层,可关)`、`handshake_deadline=30s`、`open_decision_deadline=30s`、`handler_callback_timeout=30s`、`max_in_flight_handler_queue`、`max_channels=128`、`channel_out_cap=2MiB`、`max_payload_per_call=4MiB`、`ctrl_byte_budget=2MiB`、`global_byte_budget`、`max_connections`、`strict_window_enforcement=false`。

---

## 5. 测试与验收

**恶意客户端 harness**(raw wire + 故障注入;先于一切重构落地,对现架构可跑、允许红、锁基线):

| 用例 | 验收 | 锚定 |
|---|---|---|
| rekey-stall(server/client-initiated,后者复刻 2026-08-10) | ≤ deadline+ε 拆连;他连零影响;内存 ≤ §4.6 | 事故主路径 |
| write-stall-during-rekey | supervisor 拆连,DISCONNECT 无需成功 | §4.2 |
| talk-no-read(停读但持续发上行) | 看门狗 T 内拆连(keepalive 被喂活也不影响) | P7 |
| **trickle-read**(每 29s 读 1 字节) | 策略层 `write_min_drain` 拆连;关闭该策略时不拆(验证分层) | §4.2 |
| **zero-window-legit**(单 channel peer-window=0,其余空闲) | **永不拆连**,仅该流停(G2 反例锚定) | 武装谓词 |
| handler-block(auth/OPEN/DATA/gex:pending/panic/CPU/死循环) | callback timeout drop;死循环任务驻留计数;连接依 deadline 处置 | Executor |
| close-with-backlog(双镜像)+ **close-at-zero-window**(恰耗窗后 eof) | 残余 DATA 先于 CLOSE;fence 不被窗口谓词锁死 | I3 |
| **stop-discard-race**(对端 CLOSE 时本端正 seal 中) | 在制包完成、未 seal 项丢弃、无 CLOSE 后 DATA 上线 | StopDiscard |
| window-grant-race / **adjust-under-full-queue**(app 队列满时对端发 ADJUST) | 不误杀;出站信用即时生效(旁路验证) | Reader 旁路 |
| **open-confirm-race**(accept 后立即 data) | CONFIRMATION 必先于 DATA 上线 | 队首 fence |
| **late-disposition**(decision deadline 后 accept) | gen 校验丢弃,`Err(Expired)`,无双 reply | slot gen |
| NEWKEYS 矩阵(我先/对先/同时;发后对端停;partial write;strict on/off;**Install 通道投递失败**;**Ack 未齐时 deadline 不注销**) | 无交错无错钥;假完成路径必拆 | ACK 闭环 |
| 压缩矩阵 / seqn-wrap-near(含 **rekey 后计数归零**、自激风暴不发生) / ctrl-flood / zero-byte&EOF flood / open-flood(囤 handle) / **handler-flood**(want-reply 洪泛,Executor 队列反压) / tcp-zero-window / rekey-storm(kex 专队满 → Cancelling) / mid-kex 混合 / adjust-overflow / oversized-packet / kex-init-flood / half-close / 多连接隔离 / **global-budget**(百连接入站填窗不破全局界) | 各按 §4.7 与 §4.6 | — |

**真实客户端矩阵**:OpenSSH(当前+旧 LTS)、libssh2、golang x/crypto/ssh、Apache MINA——多 channel、双向 rekey、strict/非 strict、多 cipher、zero-window、>1 GiB 长流。deadline 测试用 paused tokio time。**性能基线与 scheduler 对抗**(含老 bulk 最小服务率、churn 注水、1 KiB 条目聚包率)同 v2。回归:现有 9 个 tests/ 全绿。真机:复刻事故 + 24h soak。

---

## 6. 实施序列(纵向切片;不发布中间版本)

| 片 | 内容 | 完成门 |
|---|---|---|
| S0 | harness 骨架 + 事故复刻 + 基线用例(对现架构,允许红) | harness 能打现架构并暴露已知缺陷 |
| S1 | ConnSupervisor:**§4.2 全规格**(武装谓词、原子快照、双层进度、cancel-safe write、统一拆除、rekey/handshake deadline 挂靠);现有 loop 接入(允许改 select!/flush 钩子,禁改 kex/channel 语义) | write-stall / talk-no-read / trickle-read / **zero-window-legit** / rekey-stall 全绿,且断言触发者是 supervisor |
| S2 | Writer 独立:outbound epoch+ACK、车道+因果 fence(含队首 CONFIRMATION、fence 免窗口谓词)、ready-set+配额 boost、gather、KexStarted/kex 专队(try_push)、StopDiscard、bulk 恢复点、窗口单账本 | close-with-backlog 全变体、NEWKEYS 出站半边、stop-discard-race、顺序矩阵绿 |
| S3 | Reader 独立:inbound epoch+ACK(双态)、per-channel 全序、窗口记账迁入、ADJUST 旁路、ctrl try_push | NEWKEYS 全矩阵、window-grant-race、adjust-under-full-queue、洪泛类绿 |
| **S4** | **HandlerExecutor + Session facade + slot(gen)/decision deadline + global budget(三类覆盖+连接数上限)** | handler-block/handler-flood/late-disposition/global-budget 绿 |
| S5 | 窗口即界收口:消费返窗权威路径、permit(预检+获取序+exactly-once)→ **删 Scheme C 与双账本**(双端同改) | 现 9 测试 + 有界性验收绿 |
| S6 | RekeyPolicy(计数生命周期)+ 策略表 + 压缩 epoch + P8/P9 存量修复 | seqn-wrap-near(含归零/风暴)、压缩矩阵绿 |
| S7 | 性能:调参、first-byte、零拷贝(队头 Bytes 直接加密入 staging) | 性能基线 + scheduler 对抗达标 |
| S8 | 真实客户端矩阵 + 真机 soak;client 行为对齐评估 | 全绿 + 24h soak |

S1 先行消最大风险;S4 独立成片(第 2 轮 kimi 指出 v2 把 Handler/global budget 漏排在所有切片之外);S5 必须在 S3+S4 之后。每片保持全仓库编译+既有测试绿。

---

## 附录 A:第 1 轮评审裁决(v1 → v2)

(保留原表,略有更新:所有"关闭"声明以第 2 轮复审核验为准,见附录 B。)

| 缺陷(级别,来源) | 处置 |
|---|---|
| Writer 卡 write 时队列 deadline 全失效;keepalive 纸面兜底(BLOCKER 3/3) | supervisor+看门狗(v2.1 补齐谓词/快照/cancel-safe,§4.2) |
| NEWKEYS 方向性 epoch(BLOCKER) | 方向性命令+原子序(v2.1 补 ACK+gen 闭环,§4.3/4.4) |
| CLOSE/EOF 车道超车(BLOCKER 3/3) | per-channel fence(v2.1 补 StopDiscard 停止边+队首 CONFIRMATION+免窗口谓词) |
| 1 TiB 漏 seqn 回绕(BLOCKER 3/3) | 包数界 2^31(v2.1 补 per-epoch 归零/计数点/合并触发,I5) |
| Handler 内联 await(BLOCKER) | v2.1 改为 HandlerExecutor 单拥有者+facade+timeout drop(§4.3) |
| 零字节/EOF 洪泛(BLOCKER grok) | 双界+护栏随迁 |
| ChannelOpenHandle 自死锁(BLOCKER gpt) | 免死锁路径保留,slot 预留+gen |
| 授窗跨任务竞态(MAJOR kimi) | Reader 记账,次序闭合 |
| Reader await ctrl 违 I1 / 超窗断整连 / control 饿死 bulk / "插队已排 bulk" / server 先行 / 事实错误 / 调度参数(各家) | I2' / §4.7 / burst cap / seal 点承认 / 双端同改 / §2 修正 / §4.3 采纳 |
| mpsc 条数界·opening slot·全局 DoS(gpt) | v2.1:同步预检+permit 获取序+global 三类覆盖+连接数上限(§4.5) |

未采纳:止血发布(用户明确不发中间版本;工程内核吸收为 S0/S1);R7 按套件差异化(采包数界统一上限)。

## 附录 B:第 2 轮复审裁决(v2 → v2.1)

第 2 轮总裁决:gpt "S0 GO / S1 NO-GO(条件)";grok "S0 GO / S1 CONDITIONAL / S2+ 待补丁";kimi "缺口 1–4 清零后可进 S0"。以下为交叉确认项与 v2.1 处置:

| # | 缺陷(来源,级别) | v2.1 处置 |
|---|---|---|
| 1 | 看门狗谓词:zero-window 误杀(gpt/grok BLOCKER/MAJOR)、idle→armed 缺失(gpt)、快照撕裂(gpt)、cancel-safe write(grok)、渗出读假活(kimi MAJOR;gpt 认为属 SLO) | §4.2 双层判定:wire-eligible 武装谓词+边沿采样+单结构原子快照+cancel-safe write;渗出读以**显式策略层** `write_min_drain` 处置(裁决:采 kimi 的威胁模型、用 gpt 的分层口径);zero-window-legit/trickle-read 用例 |
| 2 | NEWKEYS 缺 install ACK+gen,"入队=完成"假活/错代密钥(gpt BLOCKER;grok MINOR 双态/无 await) | §4.3/4.4 ACK 驱动完成判定+gen 校验+双态 Reader+seal→install 无 await;NEWKEYS 矩阵加假完成用例 |
| 3 | Handler "一律 spawn" 与 `&mut self`/`&mut Session` 类型矛盾、in-flight 无界、晚到 accept 串台、abort 语义(gpt/grok BLOCKER;kimi MAJOR 次序/上界) | §4.3 HandlerExecutor:单拥有者串行(次序自动保序、in-flight 有界)+timeout drop future(无晚到结果)+`Session` facade(G5 源码级)+slot gen+`Err(Expired)`;数据面不经 Handler |
| 4 | G4/permit:签名先 `into()` 后挂起,"permit 在移交前"不成立(gpt BLOCKER);ABBA 获取序(grok);global 不覆盖入站授窗(gpt BLOCKER);固定预算×千连接(gpt);连接数上限 | §4.5 同步预检+固定获取序(global→channel)+exactly-once+teardown 双级唤醒+global 三类覆盖+max_connections;G4 口径诚实化(§1) |
| 5 | OPEN_CONFIRMATION 走 control 可与 DATA 乱序(gpt BLOCKER) | CONFIRMATION 改为 per-channel 队首 fence;仅 Confirmed 进 ready-set;open-confirm-race 用例 |
| 6 | peer CLOSE 停止边:Writer 何时停 seal 未规格(gpt MAJOR) | StopDiscard(c,gen) kex 级优先+seal 前 tombstone 校验+未 seal 项丢弃+CLOSE 仲裁+生命周期门闩;stop-discard-race 用例 |
| 7 | 入站 ADJUST 入 app 全序队列 vs Writer 权威冲突(gpt MAJOR) | Reader 解析点旁路直通 Writer;adjust-under-full-queue 用例 |
| 8 | fence 项被窗口谓词锁死(kimi MAJOR) | I3:fence 不耗窗、准入免窗口谓词;close-at-zero-window 用例 |
| 9 | bulk 恢复点未钉(grok MAJOR) | Writer outbound install ACK 后即恢复(不等对端 NEWKEYS);Idle 只管 deadline |
| 10 | kex 专队"永不满"过声称(gpt/grok/kimi) | try_push+满即 Cancelling;write 点 select kex 队列+token;枚举修正 |
| 11 | rekey 计数归零/计数点/合并触发(grok/gpt MAJOR) | I5 per-epoch 归零于 install ACK、Reader/Writer 计数点、双向合并、硬顶 |
| 12 | boost 无额度饿死老流(gpt MAJOR;kimi/grok MINOR) | 配额化(N=8)+最小服务率测试 |
| 13 | 切片漏排 Handler/global budget(kimi MAJOR);S1 范围句(grok) | 新 S4 独立切片;S1 写明允许/禁止改动范围与断言 |
| 14 | 消费返窗权威路径、WindowSizeRef 双账本(grok/gpt MAJOR) | §4.8 删除清单点名+S5 前置条件;P9 入病灶表 |
| 15 | MINOR 打包:deadline 注册 gen 竞态、注册通道非队列、closing 驻留入公式、CLOSE 后控制门闩、payload 拷贝、Cancelling 期看门狗停表、partial write 刷新、Install 通道容量 1、GEX 枚举 | §4.2/4.3/4.6/4.7 逐条落笔 |

**分歧裁决记录**:渗出读(kimi MAJOR vs gpt "不得伪装成活性要求")——两层判定,活性层从 gpt、威胁处置从 kimi,策略显式标注;"v2 可否进 S0"(gpt/grok GO vs kimi 缺口清零后 GO)——v2.1 即为清零动作,S0 立即可开工。
