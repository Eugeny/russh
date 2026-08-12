# 对抗式设计检视：russh Session Loop 全量重构方案

- 评审者: grok-4.5（独立对抗视角）
- 日期: 2026-08-11
- 对象: `.omc/plans/russh-proxy-session-rewrite.md`（DRAFT v1）
- 代码对照: `server/session.rs` run loop、`session.rs` Encrypted::data/flush、`sshbuffer.rs`、`pending_inbound.rs`、`kex/mod.rs`、`negotiation.rs`、`tests/*`
- 原则: 打穿优先；[BLOCKER]/[MAJOR] 必须给失败场景

---

## 总评

**方向对，但还不能按 Phase A「一步到位」开工。** 三任务拆分 + control/bulk 车道分离 + rekey deadline + 默认不主动 volume rekey，确实对准了 2026-08-10「1 GiB rekey → 出站永久 gate」的根因；比继续在单 `select!` 上堆 gate 更有前途。

**最大的一颗雷：活性在「Writer 卡在 socket write」与「Session 卡在 Handler」两条路径上没有真正的 deadline 闭环；再叠加三任务 NEWKEYS 密钥安装时序几乎未规格化。** 前者会让 G1「有界时间断连」在真机场景里再次落空（恰是事故同类：对端不配合时我们拆不掉）；后者会在 Phase A 一上线就用错误密钥/序号拆包，表现为随机断连或更糟的状态错乱。

次雷：删除 Scheme C 时**没有把现有代码里已经修过的零字节/EOF/CLOSE 洪泛护栏写进新设计**，§4.4 的「闭式上界」在字节容量队列上被轻易打穿。

**结论：可以继续推进，但必须先补规格再写代码。** 建议把 Phase A 收成「先上 rekey deadline + 默认不主动 rekey + 明确 NEWKEYS 状态机」，再动三任务骨架；否则是用更大复杂度重写同一类楔死。

---

## 1. 正确性（密钥边界 / strict-kex / 压缩 / 次序）

### 1.1 [BLOCKER] 三任务 NEWKEYS 密钥安装时序未规格化

方案 §4.1/§4.2 只写了「Reader 收 NEWKEYS 后等新 opening key」「Writer 在 NEWKEYS 发出后切 sealing key」「Session 通知双方」，**没有给出可实施的状态转移与消息契约**。

SSH（RFC 4253 §7.3）硬约束：

- **发出** NEWKEYS 之前的报文：旧 sealing key + 旧出站 seqn  
- **发出** NEWKEYS 之后的报文：新 sealing key（strict-kex 下出站 seqn 归零）  
- **收到** NEWKEYS 之前的报文：旧 opening key + 旧入站 seqn  
- **收到** NEWKEYS 之后的报文：新 opening key（strict-kex 下入站 seqn 归零）  
- 两侧 NEWKEYS **独立**，可出现「我已发、对端未发」或相反

**失败场景 A（Writer 过早切 key）：**  
Session 在算完密钥后一次性 `KexDone{open_key, seal_key}` 广播。Writer 先装 seal_key 再排 NEWKEYS → NEWKEYS 本身被新 key 密封 → 对端用旧 key 解失败 → 连接死。严格顺序必须是：`seal(NEWKEYS, old_key)` → `install(seal_key)` → `maybe reset_seqn` → 之后才能 seal 其它包。

**失败场景 B（Reader 装 key 与收包竞态）：**  
对端 NEWKEYS 之后紧跟用新 key 加密的 CHANNEL_DATA（合法）。Reader 解密 NEWKEYS（旧 key）后 await Session 给新 opening key；若 Session 还在算/还在与 Writer 同步，TCP 上后续包已到达。实现若把「等 key」做成「先读进 buffer 再切」，容易用旧 key 去 open 下一包 → MAC/GCM 失败 → 误杀连接。必须规定：**opening key 切换与「下一包解密」在同一任务内原子完成，且 key 必须在读下一包前就绪**；Session 应在发出本端 NEWKEYS 相关步骤允许的前提下尽早把 *receive* key 单独送给 Reader（不必等 Writer 发完）。

**失败场景 C（strict-kex seqn 重置位置错误）：**  
现状（`server/mod.rs` kex Done 分支 + `reset_seqn` + `pkt.seqn = Wrapping(0)`）在单任务里顺序清晰。拆成 Reader/Writer 后，若 Writer 在 NEWKEYS **之前** reset 出站 seqn，或 Reader 在处理完 NEWKEYS 明文**之前** reset 入站 seqn，对端（OpenSSH strict kex）会直接断开。方案仅一句「各自执行」，无验收断言。

**失败场景 D（压缩上下文）：**  
RFC 4253 §9：rekey 后 compression context **reset**。现状 `CommonSession::newkeys` 对 compress/decompress 一并 `init_*`。三任务下 compress 属 Writer、decompress 属 Reader；若只换 cipher 不换压缩状态，zlib 流错位 → 后续所有包解压失败。方案 R1 提到了问题但**没有设计解**。

**要求（进入 Phase A 前必须写成规范小节）：**

```
ReaderKexState  = { OpenOld, WaitOpenKey { after_newkeys_rx }, OpenNew }
WriterKexState  = { SealOld, EmitNewkeys, SealNew }
SessionKexState = 现有 Idle/InKex + 显式 "opening_key_ready" / "sealing_key_ready" 边

消息至少拆成:
  InstallOpeningKey { key, compress, reset_seqn }
  InstallSealingKey { key, compress, reset_seqn }  // 仅在 NEWKEYS 已入 sealing 流水线之后生效
  EmitNewkeys       // Writer: 用旧 key 密封 NEWKEYS，再原子切 SealNew
```

并附「禁止交错」不变量测试（见维度 7）。

### 1.2 [MAJOR] Control 优先不能违背已密封包的 seqn 次序

方案宣称「即使 bulk 已排 128 KiB，kex 包也插队」从而解 P2。但 **SSH 包序号在 seal 时分配**（见 `cipher` + `PacketWriter`），已写入 `write_buffer`、占了 seqn 的 bulk **不能**被 KEXINIT 插到前面。

**失败场景：**  
Writer 已 seal 了 128 KiB bulk（seqn 1000..N）。此时 Session 发 KexStarted。KEXINIT 只能排在已 seal 字节**之后**发出。插队只对**尚未 seal** 的队列有效。

影响：P2 的改善上界 =「未 seal 的 bulk 队列深度」，不是「含 TCP sndbuf 的全部在途数据」。方案应改写为：

- seal 点之前：control 严格优先（真）  
- 已 seal / 已 write 到内核：无法插队（必须承认）  
- 因此 KexStarted 后必须**立刻停止 seal bulk**，把 staging 上限压到「最多一个 maxpacket 量级的在制包」，否则 rekey 启动延迟仍随 staging 增长

当前 `OUTBOUND_HIGH_WATERMARK = 128 KiB` 在 1 Gbps 上约 1ms，通常可接受；但若实现把 per-chan 队列在 Writer 内再二次堆积后批量 seal，延迟会回到事故同构形态。**规格必须钉死：InKex 期间 seal 调度只出 kex 合法包与 DISCONNECT。**

### 1.3 [MAJOR] 入站 DATA 与控制报文的「连接级次序」被拆队列削弱

方案：DATA/EOF/CLOSE → per-chan 队列；其余 → ctrl 队列 → Session。

**失败场景：**  
对端顺序发送：`CHANNEL_DATA(c1)` → `CHANNEL_CLOSE(c1)` → `GLOBAL_REQUEST`。  
DATA/CLOSE 进 c1 队列，GLOBAL_REQUEST 进 ctrl。Session 先处理 GLOBAL_REQUEST；c1 的 CLOSE 由 app 稍后 `recv`。对合规 peer 通常无害，但若 Handler 依赖「全局到达序」（例如用 GLOBAL_REQUEST 做 barrier），语义变化。更实质的是 **同一 channel 上 DATA 与 OPEN/REQUEST 的相对序**：`CHANNEL_REQUEST` 走 ctrl、`CHANNEL_DATA` 走 data 队列时，可能出现 REQUEST 先于仍在 data 队列中的先序 DATA 被 Handler 看见。

RFC 4254 要求 channel 上消息有序处理。**同一 channel 的 DATA/EOF/CLOSE/REQUEST/SUCCESS/FAILURE/WINDOW_ADJUST 应共享 per-chan 全序**，不能只把 DATA/EOF/CLOSE 绑在一起而把 REQUEST 扔进全局 ctrl。

建议：

- per-chan 队列承载**所有 channel-scoped 消息**  
- 仅 transport/global（kex、GLOBAL_*、IGNORE、DEBUG、DISCONNECT、SERVICE_*）走 ctrl  

否则这是静默语义回归。

### 1.4 [OK] 出站 per-chan 队列 + Writer 切包

出站由 Writer 按 peer 窗口与 maxpacket 切 DATA，天然保 per-chan 字节序；control 优先只要遵守 1.2 的 seal 点规则，连接级控制先于 bulk 的意图成立。

### 1.5 [MINOR] 首次 kex 与 rekey 共用状态机

方向正确，但首次 kex 时尚无 channel、无 bulk，Reader「等 opening key」与 auth 阶段 `inactivity_timeout` 的交互要单独画时间线，避免 auth 卡在 WaitNewKeys 时超时原因含糊。

---

## 2. 活性论证完备性（最高优先级）

§4.3 表是方案的核心交付物。逐行攻击如下。

### 2.1 [BLOCKER] Writer 卡在 `socket write` 时，rekey deadline 无法拆连

表中：

| WriterTask | socket write | keepalive_max × interval |
| WriterTask | kex 期间等 KexDone | rekey deadline |

**失败场景（复刻事故变体，且方案自伤）：**

1. 饱和下行，客户端发起 rekey（OpenSSH 默认 ~1 GiB，**即使服务端 I5 不主动 rekey 仍会发生**）。  
2. 本端进入 InKex，bulk 暂停；Writer 仍在把 **已 seal 的 bulk 尾** 或 **本端 KEXINIT** 写入 socket。  
3. 对端停读（或只读不回 NEWKEYS）→ TCP 发送窗口耗尽 → `write` 永久 Pending。  
4. Session 的 rekey deadline 30s 到期，向 control lane 塞 `DISCONNECT`。  
5. Writer 卡在 `write` future 内，**无法 poll control lane、无法改发 DISCONNECT**。  
6. 表声称的 keepalive 覆盖：RFC 4253 §7.1 在本端已发 KEXINIT 之后、发 NEWKEYS 之前，**禁止**发 keepalive 类非 kex 传输消息；即便策略上想发，同样卡在 write。  
7. 结果：连接在「已判定 rekey 失败」后仍僵死，直到 TCP 层超时（可能远大于 30s）——**直接违反 G1**。

**必补：**

- 所有 socket write 带 **独立 I/O deadline**（或 `poll` + 外部 timer cancel），超时 → 不经协议 DISCONNECT，直接 `shutdown`/drop fd（宁脏断，勿僵）。  
- rekey deadline 触发路径不得假设 Writer 还能从 lane 取包；应是 **Session 置 `abort` 标志 + 取消 Writer 的 write**（`tokio::select!` 竞态 abort，或 `AsyncWrite` 侧 drop）。  
- 活性表增加一行：`WriterTask | write 被取消/超时 | Session abort / I/O deadline | 有界`。

### 2.2 [BLOCKER] Session 卡在 Handler 时，整表解锁链断裂

| SessionTask | Handler 回调 | 契约：快速返回 + debug_assert |

`debug_assert` 在 release 为零；**契约不是界**。

**失败场景：**

1. Handler（或 zfc 误用：在回调里 `recv` 另一 channel / 等 DNS / 同步写盘）阻塞 60s+。  
2. Session 不消费 ctrl 队列 → Reader 在「ctrl 队列 push」上 await（表第二行）。  
3. Reader 不再读 socket → 对端 TCP 窗口满；本端 **inactivity_timer 若只挂在 socket read 上则不触发**（read 根本没在 poll）。  
4. keepalive 若由 Session 驱动，也不再发出。  
5. Writer 可能仍在发 bulk（非 kex），但控制面与 rekey 状态机全停。  
6. 有界时间断连失败 → 永久僵死（或直到 OS 级超时）。

这不是「对端恶意」，但是 **G1 在代理进程内的真实故障模式**；zfc 现状「open 即 spawn」不能用注释保证未来所有 Handler 路径。

**必补：**

- Handler 回调硬超时（例如 50–100ms warn，1–5s `DISCONNECT`/`drop`），或  
- 强制：run loop **从不 await Handler**——所有 Handler 改为 `spawn` + 有界 channel 回传结果（API 兼容可用「异步回调仍存在但内部强制 spawn」）。  
- 活性表把 Handler 行改成有 deadline 的解锁者，否则 I4 不成立。

### 2.3 [MAJOR] I1「读永续」与表第二行自相矛盾

I1：Reader 除等新 opening key 外永不 waiting。  
表：Reader 可 await **满的 ctrl 队列**。

**失败场景：**  
恶意 peer 洪泛 `GLOBAL_REQUEST` / `CHANNEL_OPEN`（在 max_channels 拒绝前仍占 ctrl 处理）或 Session 短暂慢于线速 → ctrl 256 满 → Reader 停读 → 对端 kex 包也读不进来 → 依赖「Session 活性」的环变长。虽有 rekey deadline，但 **非 kex 路径下的停读** 只剩 inactivity——而 inactivity 在 2.2 下可被一起拿掉。

**建议：** Reader 对 ctrl 使用 `try_push`；满则 **DISCONNECT（ctrl flood）** 或丢弃可丢消息（IGNORE），**禁止** Reader await Session。这样 I1 才真。

### 2.4 [MAJOR] 遗漏等待点清单

下列在 §4.3 未出现，但代码与 API 真实存在：

| 遗漏等待点 | 现状位置 | 风险 |
|---|---|---|
| `wait_channel_confirmation`（`receiver.recv().await` 无超时） | `server/session.rs` Handle | OPEN 发出后 peer 不确认 → app task 永挂；连接其它 channel 仍活，但代理会堆积僵尸 relay |
| `ChannelOpenReply` / accept 延迟路径 | `open_reply_rx` | kex 期间暂存后，若 deadline 断连，oneshot/app 是否被唤醒为 Err？未写 |
| `Handle::data` / `outbound_acks` oneshot | 现状 cap 路径 | 新设计改为 per-chan 队列后 ack 语义变了；关闭时是否全部 Err 唤醒？未写 |
| 三任务 join / 任一任务 panic | 无 | 一个 task panic，另外两个是否 abort？半开连接？ |
| teardown 5s flush + 5s drain | 现状 `run` 末尾 | 三任务下谁持 read half / write half？重复 shutdown？ |
| Reader 等 `InstallOpeningKey` 时 Session 已决定 Disconnect | — | 必须用 abort 打断 WaitOpenKey，否则 30s 内读路径假活 |
| 上游 zfc `copy_bidirectional` 卡在 `data().await` | 出站满 | kex 30s 内 bulk 暂停 → 所有满队列 channel 的 relay 写超时；需确认 zfc 超时 < 客户端体验，或 kex 期间允许队列有「快速失败」 |

**失败场景（open confirm）：**  
客户端 OPEN 后不发 CONFIRM/FAILURE（或包在 kex 暂存中丢失）→ `wait_channel_confirmation` 永挂 → 连接级看似 fine，进程 fd/task 泄漏。G1 只保证连接，不保证 per-open；代理场景仍应有 open deadline。

### 2.5 [MAJOR] kex 期间「唯一潜在环」的消解不完整

方案用 control lane **预留 8 槽** 保证 KexDone 等不被堵。但：

1. 预留槽与「非 kex 控制暂存于 Session」的交互未定义：kex 结束后 Session 突发 dump 256 路 ADJUST/OPEN_CONFIRM，可能立刻打满 256 槽，Session 反压，若此时又要处理异常路径 DISCONNECT，是否占用预留槽？  
2. **KexStarted 本身**若在 Writer 仍卡在 write（2.1），预留槽无意义。  
3. 8 是否够用取决于 kex 算法消息数（DH-GEX 更多）+ DISCONNECT + 重试；应写成「kex 专用无界/高优先子队列」，而不是魔法数 8。

### 2.6 [MAJOR] kex 期间暂存非 kex 控制：有界性论证过粗

「O(channel 数)，deadline 兜底」不够：

- 每个 channel 在 kex 窗口内可能产生多次 **peer→us** 的 WINDOW_ADJUST、REQUEST、以及 **本端想发** 的 OPEN_CONFIRM/ADJUST/CLOSE。  
- 若暂存的是「本端待发控制」，生产者是 Session；Session 在 kex 期间仍可能因 OPEN 洪泛尝试入队。  
- 若暂存无 **条数 × 字节** 双 cap，恶意 peer 在 kex 前打开 256 channel，kex 中对每个 channel 狂发 REQUEST（若仍被 Reader 接受进 ctrl），Session 暂存可爆。

**失败场景：** rekey-storm + open 满配 + 每 channel 控制洪泛 → 内存超出 §4.4，deadline 到时才断，但进程可能已 OOM（多连接时）。

### 2.7 [OK] 方向性：rekey deadline + 默认不主动 rekey

对「对端不完成 rekey → 永久 gate 出站」这一事故主路径，**有 deadline 的 InKex** 是正确药方；I5 降低事故触发频率也合理。但不能替代 2.1/2.2 的闭环。

### 2.8 [MINOR] zfc relay `recv` 空等标「无需界」

正确（正常阻塞）。但 channel 已 CLOSE 时必须保证 `recv` 返回 None/Err，且与 Writer/Session teardown 无锁序问题（见 R5）。

---

## 3. 有界性

### 3.1 [BLOCKER] 字节容量队列无法约束 0 字节报文洪泛

方案：`try_push` 容量 ≡ 已授窗口 + 1×maxpacket，超出 DISCONNECT。  
现状 `pending_inbound.rs` **明确**处理了三类洞：

- 空 `DATA`/`EXTENDED_DATA` 直接丢弃（否则 pending 字节 cap 看不见）  
- `EOF`/`CLOSE` 在已 queued 时去重  
- 注释写明：零字节项会让队列无界增长  

方案删除 Scheme C 时 **未迁回这些护栏**。

**失败场景：**  
恶意客户端对已建立 channel 发送 N 个 `CHANNEL_EOF` 或空 `CHANNEL_DATA`（窗口不减）。队列按「字节」计为 0，`try_push` 永远成功 → `VecDeque` 无限涨 → G4 破裂；多连接可打爆代理。

**必补：** per-chan **消息条数 cap**（例如 ≤ window/min_packet + K）+ EOF/CLOSE 去重 + 空 DATA 丢弃；与窗口字节 cap 同时生效。

### 3.2 [MAJOR] §4.4 闭式上界不闭

公式遗漏或低估：

| 项 | 问题 |
|---|---|
| ctrl 队列 `256 × maxpacket` | `maximum_packet_size` 默认 32 KiB → **8 MiB**，不是「小」 |
| writer control lane 同上 | 再 +8 MiB 量级（若按 maxpacket 计） |
| kex 暂存 | 未计入 |
| Reader 半包重装缓冲区 | 未计入（至少 1× max wire packet） |
| encrypt staging 128 KiB | 有，但 per-connection 还有 cipher/compress 状态 |
| `pending_reads` 类缓冲 | 现状字段仍在；新设计若「kex 中 DATA 直进 per-chan」可删，但 mid-kex 非法/合法 in-flight 控制暂存仍要 cap |
| 应用侧 ChannelStream / 上游 TCP | 严格说不在 russh 连接公式内，但代理 RSS 上界必须另写 |
| 出站 `out_cap × N` 在 kex 期间 | 会顶满（bulk 暂停仍允许 `data()` 填队列）→ 公式上有，但 **瞬时必达上界**，不是「远低」 |

**失败场景：** `max_channels=256`, `w_in=out_cap=2MiB` → 仅 channel 队列 1 GiB；再加 ctrl 两侧、暂存、staging，单连接设计上可 >1 GiB。文档写「可配可降」可以，但 **默认值对多租户代理不安全**；应把默认 `max_channels`/`w_in` 降到 zfc 实配量级，或强制配置审查。

### 3.3 [MAJOR] 入站「容量 ≡ 已授窗口」与授窗时序必须耦合证明

**失败场景（off-by-grant）：**  
队列容量 = 当前已授信用。App 消费后 Session 发 ADJUST 补窗 **先于** 队列 free 槽发布（或 Reader 与 Session 并发），对端按新信用发送 → `try_push` 失败 → 方案选择 **DISCONNECT 整连接**。  
现状 fork 对 inbound overflow 是 **关单 channel**（`server/encrypted.rs` Overflow 分支），更宽容。

必须规定不变量：

```
queue.free_bytes() >= peer_send_credit_remaining
授窗增量 Δ 仅在 free_bytes 已增加 Δ 之后发送 ADJUST
```

并用单测钉死。1×maxpacket 容差只覆盖 peer 轻微越界，不覆盖自身授窗竞态。

### 3.4 [MAJOR] 出站双账本若残留 WindowSizeRef，有界与活性都可能假

现状生产者路径（`channels/io/tx.rs`）先扣 `WindowSizeRef` 再进 session mpsc；wire 侧再扣 `recipient_window_size`。方案称反压改为 `out_cap`，但未写是否删除 WindowSizeRef 双账本。

**失败场景：** 保留双账本 + Writer 单独记 peer 窗口 → 三方不一致 → 再现 RC1 类 lost-wakeup（`INBOUND_STALL_FIX_DESIGN.md` 已讨论）或假满。  
**要求：** Phase A 规格明确 **单一 credit 权威**（建议 Writer 为 peer window 权威，生产者只等 out_cap；ADJUST 只唤醒 Writer）。

### 3.5 [OK] 有 `max_channels` 封顶的方向

需要，且应与 open-flood 测试绑定。默认 256 对代理偏大（见 3.2）。

---

## 4. 性能设计

### 4.1 [OK] 控制优先 + OPEN_CONFIRM 走 control

对「open→first byte」和 rekey 启动延迟是正确优先级。代理场景收益明确。

### 4.2 [MINOR] DRR quantum=64 KiB 可接受，但非最优

§7 R4 自算 32 流最坏 ~2 MB ~16ms@1Gbps，量级可接受。更糟在 **非对称**：单流 speedtest + 多流小请求时，64 KiB quantum 对网页流仍偏大。

**可选改进（非阻塞）：**

- 双层：`first_packet_fast_path`（每 channel 队头 ≤2 KiB 或首包优先）+ 其后 DRR  
- quantum 按 `min(64KiB, peer_maxpacket * k)`  
- 对 `direct-tcpip` 可配置 class（交互/大流），避免一刀切  

### 4.3 [MINOR] 聚包策略

「有 backlog 凑满 maxpacket，无 backlog 立即发」正确。注意与 `TCP_NODELAY` 组合：无 backlog 时小包会打满 PPS；代理可接受。可配 `cork`/短暂延迟聚包（默认关）即可。

### 4.4 [MINOR] 零拷贝机会

现状已用 `Bytes`。三任务后典型路径：`relay → out 队列(Bytes) → Writer seal 拷贝进 write_buffer → kernel`。  
可做：`reserve_cleartext_packet_output` 式预留、减少 `Bytes` 中间段；真正 zero-copy 受 cipher in-place 与 poly1305/GCM 约束，收益有限。**不值得挡 Phase A。**

### 4.5 [MAJOR] 下行窗口「不可调大」下的真实瓶颈未谈调度之外的事

客户端授窗与 maxpacket 决定下行上限。服务端还能做：

- 尽早 ADJUST（上行）不阻塞在 bulk 后——方案有  
- 避免 rekey 与饱和写锁死——方案有意图，实现见 2.1  
- **kex 期间 bulk 暂停 30s** 会让所有 channel 的下行在对端授窗仍在时停住 → 应用层吞吐断崖；应用是否应在 InKex 时对 `data().await` 返回「可重试错误」而非塞满 out_cap？未写  

**失败场景：** 客户端每 1 GiB rekey，30s deadline 内若客户端慢，代理所有流停 30s——相对「永久僵死」是进步，但对 YouTube 仍可能触发客户端读超时。应在验收里量化 p99 停顿，并考虑 **更短 rekey deadline（5–10s）** 对代理更优。

### 4.6 [OK] Phase B 再调 DRR 的分期

合理。

---

## 5. 协议合规与互操作

### 5.1 [OK] RFC 4253 §7.1：kex 期间不得发送传输层以上消息

方案 R3 自问「ADJUST 是否照发」——**答案是否定的（MUST NOT）**。OpenSSH 等实现同样在 rekey 中停止连接协议消息。暂存 ADJUST/OPEN_CONFIRM 正确。  
对 **接收** 端：RFC 要求 rekey 开始后仍能处理 **in-flight** 消息。方案让 Reader 继续 demux DATA 到 per-chan 队列，方向对。

### 5.2 [MAJOR] mid-kex DATA：规格写「按 RFC 处理/断连」过于含糊

- **In-flight**（对端 KEXINIT 之前已在途）：应照常处理。  
- **对端已发 KEXINIT 之后仍发 CHANNEL_DATA**：严格说违规；OpenSSH/strict 行为需对照。粗暴 DISCONNECT 可能误杀「流水线多包」客户端；一律静默也可能掩盖 bug。

**要求：** 写成明确策略，例如：

- 记录 counter + tracing  
- 默认：仍入 per-chan 队列（最大化互操作），strict-kex 初始阶段另论  
- 可选 hard 模式：DISCONNECT  

并用 OpenSSH / golang `x/crypto/ssh` / libssh2 实机矩阵验证（不仅 russh↔russh）。

### 5.3 [MAJOR] window-overflow → 整连接 DISCONNECT 过苛

方案 §5：`window-overflow` → DISCONNECT。  
**现状 fork：关单 channel，不断连接**（`server/encrypted.rs` Overflow）。

**失败场景：** 某嵌入式/老 libssh2 客户端单 channel 窗口记账漂移越界 → 方案拆整条多路复用连接 → YouTube+speedtest 全部掉线。对代理，**单 channel 处死**几乎总是更好。

建议：默认 **channel 级** 关闭 + 计数器；仅在「越界超过阈值阈值」或「无 channel 上下文」时升级到 DISCONNECT。

### 5.4 [MAJOR] I5「1 TiB 不主动 rekey」密码学与包计数

- RFC 4253 §9 推荐 1 GB / 1h——那是 **推荐**，服务端不主动、等客户端发起，在代理场景可接受。  
- OpenSSH 客户端默认会 rekey，事故路径仍在（客户端发起），靠 deadline 救——OK。  
- **包计数：** AES-GCM 实践上应限制 ~2^32 次调用/密钥。`Limits::default` 现状是 1 GiB 字节；改 1 TiB **仅字节**时，若平均包很小（聊天式/多小包 channel），包次数可能逼近或超过 2^32。  
- 代码 `Limits::new` 现有 `assert!(write_limit <= 1 << 30)`，与 I5 直接冲突——实施时必改，但断言反映了作者曾担心的 nonce 空间。

**失败场景：** 怪异客户端从不 rekey + 长期小包代理 → 同一 AES-GCM key 使用过久。  
**要求：** 字节阈值 + **包序号阈值**（例如 2^31 packets）+ 时间阈值（可无穷）；按 suite 差异化（GCM/CTR/chacha）写进 I5，而不是单一 1 TiB。

### 5.5 [MINOR] 第三方客户端「停读 / 半死不活」

tcp-zero-window 用例依赖 keepalive；默认 `keepalive_interval: None`（`server/mod.rs` Config）→ **现网若未显式配置 keepalive，表中 Writer 行的解锁者根本不存在**。方案应把代理推荐配置写死：强制默认 keepalive 或文档标红。

### 5.6 [OK] 不要求客户端非标准行为

G6 方向正确；但 5.3/5.2 的过严策略会在实践中破坏 G6。

---

## 6. 可实施性

### 6.1 [MAJOR] Phase A 一步到位风险过高

Phase A 同时：

- 拆三任务  
- 车道分离  
- 显式 kex + deadline  
- 改 Limits 默认  
- 删除 Scheme C / max_pending_inbound_bytes / open-reply gating / pre-select drain  

任一缺陷都会导致「全连接不可用」。现有回归几乎全是 russh↔russh（`tests/test_rekey_under_load.rs` 等），**挡不住第三方客户端**。

**更稳切分建议：**

| 步 | 内容 | 验收 |
|---|---|---|
| A0 | **仅** InKex deadline + DISCONNECT；I5 默认不主动 rekey；保留单 loop | 复刻 2026-08-10：≤deadline 断连，不再永久 wedge |
| A1 | Writer 独立任务 + control/bulk 队列（Reader 仍在 session） | 吞吐与 rekey 插队 |
| A2 | Reader 独立 + 删除 Scheme C | 入站有界与 per-chan 全序 |
| A3 | DRR/聚包（现 Phase B） | 性能基线 |

A0 可单独上线止住真机血，且改动面小一个数量级。

### 6.2 [MAJOR] 删除清单删多了也删少了

**删多了（必须先有替代再删）：**

- `pending_inbound` 的 **空包/EOF/CLOSE 护栏**（见 3.1）  
- 单 channel overflow 处置策略（见 5.3）  
- `outbound_acks` / `enforce_outbound_cap` 在 Handle::data 路径的语义——若 API 仍公开 `Handle::data`，要有等价有界  

**删少了 / 未提：**

- `pending_reads` / `pending_len`：全仓库几乎只 drain、不见 push，像死代码；重构时应删除或恢复明确语义  
- 双路径 pre-select drain **与** `MAX_MESSAGES_PER_BATCH` 注释中的历史包袱——同意删，但要迁移「Disconnect 不阻塞在 select」等行为  
- client 侧镜像（`client/mod.rs` 同样 Scheme C + kex gate）——方案说随后对齐，但共享 core 意味着 **A 阶段 API 边界必须一次想清**，否则 server/client 分叉两周  

**API：** `Limits` 默认变更属行为变化；`data().await` 反压语义变化对 zfc「无感」是假设，需要 zfc 侧用超时/cancel 测一次。

### 6.3 [MINOR] `handler_slow_warn` 不够

见 2.2：要 hard timeout 或强制 spawn，不是 warn 频率配置。

### 6.4 [OK] 无兼容包袱允许重写

前提成立；但仍应用 A0 降风险，不是为了兼容，是为了 **可验证**。

---

## 7. 测试充分性

### 7.1 [MAJOR] §5 矩阵是好种子，但缺关键用例

已有用例（kex-stall、rekey-stall-under-load、never-adjust、tcp-zero-window、rekey-storm、open-flood、window-overflow、mid-kex-data）方向对。仍缺：

| 用例 | 为何必须 |
|---|---|
| **rekey-stall-client-initiated-under-load** | 事故在 I5 后仍由客户端触发；须与 server-initiated 分开测 |
| **write-stall-during-rekey** | 直接打 2.1：对端停读 + 不回 NEWKEYS，断言 ≤deadline 进程内连接拆除 |
| **handler-block** | Session 回调 sleep 60s，断言连接被硬超时拆掉 |
| **ctrl-flood** | 非 channel 消息打满 ctrl，断言 DISCONNECT/有界而非 Reader 死等 |
| **zero-byte / EOF flood** | 打 3.1 |
| **NEWKEYS 边界交错** | 注入「NEWKEYS 后立即 DATA」「本端 NEWKEYS 前后包 key」；strict-kex 开/关 |
| **compression rekey** | zlib / zlib@openssh.com 下 rekey 后继续传 |
| **per-chan REQUEST vs DATA 次序** | 防 1.3 回归 |
| **half-close** | 对端写半关、本端仍下行；以及本端 DISCONNECT 后任务 join |
| **max_channels 边界** | 第 256/257 个 OPEN 的回复与内存 |
| **多连接隔离** | 一连接 kex-stall 不影响其它连接（§5 写了「进程内其它连接零影响」但无用例行） |
| **第三方真客户端** | OpenSSH `ssh -N` 多 `-L`、`sftp`、golang proxy、libssh2；不是 raw harness 可替代 |
| **包计数 rekey** | 小包灌到阈值 |
| **ADJUST 在 kex 前后的 credit 一致性** | kex 中消费上行后 kex 结束突发 ADJUST |

### 7.2 [MAJOR] 现有 `test_rekey_under_load` 不能当「事故永不再现」的门禁

该测试是 **russh client + 配合完成 rekey** 的成功路径；事故是 **对端不完成 rekey**。方案已提 rekey-stall-under-load，必须变成 **merge 门禁**，且用「写满 + 冻结 peer 读」模拟，而不是 mock 内部状态而已。

### 7.3 [MINOR] 性能基线

应写明硬件/并发/是否 nodelay/sndbuf，否则「达标」不可比。

---

## 8. 方案对现状描述是否属实

### 8.1 [OK] 大图正确

对照代码，下列属实：

- 单任务 `run`（`server/session.rs` ~982+）`tokio::select!` 多 arm：读、`inbound_reserves`、`open_reply_rx`、keepalive、inactivity、`flush_into`、`receiver` —— 方案写 7 个 arm **正确**。  
- `kex.active()` gate：`can_receive_outbound`、`inbound_reserves` arm、`open_reply_rx` arm **确实**被 gate（约 1046、1108、1118 行）。  
- `is_rekeying` 时 `pending_data.push_back`（`session.rs` 742 行附近）**属实**。  
- `Encrypted::flush` 用 `rekey_write_limit` / `rekey_time_limit` / `rekey_wanted` 触发（798–800）**属实**；默认 `Limits` 为 1 GiB / 1h（`lib_inner.rs`）**属实**。  
- `OUTBOUND_HIGH_WATERMARK = 128 KiB`、`flush_into` cancel-safe 游标 **属实**。  
- Scheme C 在 `pending_inbound.rs`，reserve futures + generation **属实**。  
- 无 DRR，pending 按 channel 队列 drain **属实**。  

### 8.2 [MAJOR] P6「max_pending_inbound_bytes 全局 16 MB」不实

代码：`deliver_inbound(..., cap: max_pending_inbound_bytes, id, item)`，cap 用于 **每个 channel** 的 `pending_bytes` 比较。默认 `8 * 2_000_000` ≈ 16 MB 是 **每 channel 上限**，不是连接全局。  
注释（`server/mod.rs`）也写 per-channel。  
方案 P6 写成「全局 16 MB」→ **低估了恶意/多 channel 下的内存**，也误导「窗口即界可删 cap」的论证（窗口是 per-chan，与现状 cap 同级，不是「全局 vs 窗口」）。

### 8.3 [MINOR] P1 对事故的归纳基本对，但注释过度乐观

`session.rs` flush 注释称 Scheme C 后「re-exchange always completes」。  
**代码只能保证本端继续读**；若对端不完成 rekey，`kex.active()` 仍永久为 true，出站 receiver 仍永久 gate——这与 2026-08-10 事故一致。方案正文判断对；**上游注释不应对伪**。

### 8.4 [MINOR] `pending_reads` 未在病灶表出现

结构体仍有 `pending_reads`/`pending_len`，kex Done 后 drain，但未见 push 路径（疑似死代码/未完成功能）。不是方案错误，但是 **现状复杂度比病灶表更深**，删除清单应点名。

### 8.5 [OK] P2 车道混用

`PacketWriter` 单 `write_buffer` FIFO，kex 与 bulk 同队 —— 属实。但「插队」能力受 1.2 限制，方案对 P2 治愈程度略夸大。

### 8.6 [OK] 事故动机与「单 TCP 多 channel 不可拆」论证

合理；CHANNEL_OPEN 仅客户端发起的协议事实正确。

---

## 方案 §7 开放问题逐条回答

### R1 密钥切换边界

**结论：当前规格不足以保证正确；[BLOCKER]。**

- 必须按方向拆分 **InstallOpeningKey / EmitNewkeys+InstallSealingKey**，禁止单广播「同时切两端」。  
- strict-kex seqn：Reader 在 **成功处理完 NEWKEYS 明文后** 置 0；Writer 在 **NEWKEYS 密文进入出站序后** 置 0。  
- 压缩：随各自方向 key 安装 reset（对齐 RFC 4253 §9 与现状 `newkeys`）。  
- 旧/新密钥包交错窗口：在 **单 Writer 单 Reader 且 seal 点遵守 1.2** 时，线序上不应交错；风险在任务间 **安装时序** 而非 TCP 重排。  
- 应用 1.1 的状态机与负面测试后再开工。

### R2 4.3 活性表完备性

**结论：不完备；[BLOCKER]+[MAJOR]。**

遗漏/不实解锁者至少包括：

1. Writer `write` 无独立 deadline / 不可被 rekey abort 取消（BLOCKER，见 2.1）  
2. Handler 无 deadline（BLOCKER/MAJOR，见 2.2）  
3. Reader await ctrl 满违背 I1（MAJOR，见 2.3）  
4. `wait_channel_confirmation`、open-reply、outbound ack、三任务 abort/join、teardown 5s、WaitOpenKey vs Disconnect 竞态（MAJOR，见 2.4）  

「表无环」在预留槽假设下局部成立，但被 2.1 的 **物理写阻塞** 一票否决。

### R3 kex 期间控制消息暂存

**结论：暂存方向正确；有界论证不足；ADJUST 不得照发。**

- RFC 4253 §7.1：已发 KEXINIT 至本端 NEWKEYS 前，MUST NOT 发送连接协议消息（含 WINDOW_ADJUST、OPEN 回复等）。**不应改为 kex 期间 ADJUST 照发。**  
- 互操作：主流实现按此收敛；kex 期间上行窗口耗尽导致的短暂停顿可接受，应用更短 deadline 缓解。  
- 暂存必须有 **条数+字节** cap，超限 DISCONNECT；「O(N_chan)+deadline」不够（2.6）。  
- 接收路径继续处理 in-flight 是 RFC 要求，与发送限制分开写清。

### R4 DRR quantum 与延迟

**结论：64 KiB 可作默认；非最优但非阻塞。[MINOR]/建议 fast-path。**

- 最坏 31×64 KiB@1Gbps ~ms～十余 ms 量级，代理可接受。  
- 若在意小流 p99：队首小报文 / 首包优先，不必上复杂 WFQ。  
- 先 A0/A1 正确性，再 Phase B 用数据调 quantum。

### R5 取消/关闭一致性

**结论：方案几乎未设计；[MAJOR]，实施前必须补一节。**

最低要求：

- 任一 task `Err`/panic → 取消另外两个 + drop socket（统一 `ConnectionAbort`）。  
- 半关闭：peer EOF → Reader 停、Writer 可继续至 app 结束或超时；本端 `Disconnect` → Writer 尽力 flush DISCONNECT（短 deadline）后 hard close。  
- 所有 `oneshot`/队列 waiters 在 abort 时被唤醒为 Err。  
- 禁止三任务各自 5s flush 串成 15s 无响应。

### R6 client 侧对齐

**结论：可延后行为对齐，不可延后 core 抽象形状。[MAJOR] 规划问题。**

- zfc 若只用 server：client 可暂时旧 loop。  
- 但「共享 core」意味着 PacketWriter/kex/队列抽象会动；client 半迁移极易双份 bug。  
- 建议：core 模块一次切完，client 用 feature/旧路径编译开关短期共存，而不是两套 kex 状态机。

### R7 I5 密码学审慎性

**结论：服务端默认不主动 rekey 可接受；1 TiB 单一字节阈值不够。[MAJOR]。**

| 套件 | 建议 |
|---|---|
| aes128/256-gcm | 字节阈值宜保守；**必须**加 packet 上限（≪2^32）；服务端可不主动，但若 peer 永不 rekey 应在包阈值强制 rekey 或断连 |
| chacha20-poly1305 | 比 GCM 宽裕，仍建议包/字节双阈值 |
| aes-ctr+ETM | 依赖 MAC 与 CTR 安全边际；对齐 OpenSSH 量级更稳 |

1 TiB「距 2^32 包两个数量级」**仅在大包假设下成立**；代理不能假设平均 32 KiB。  
**更实际策略：** 默认不主动；`rekey_write_limit` 保持 1 GiB 或「仅响应 peer」；另设 `max_packets_per_key` hard stop。I5 写成「不主动」即可，不必绑死 1 TiB。

---

## 必须在开工前关闭的缺口（清单）

1. **[BLOCKER]** NEWKEYS / opening / sealing / compress / strict-seqn 的跨任务状态机与消息契约（R1）  
2. **[BLOCKER]** socket write 可取消 + I/O deadline；rekey 失败 hard abort（R2/2.1）  
3. **[BLOCKER]** 入站队列字节 cap **之外** 的消息数 cap + EOF/CLOSE/空包护栏（3.1）  
4. **[MAJOR]** Handler 硬超时或禁止在 loop 内 await（2.2）  
5. **[MAJOR]** Reader 对 ctrl `try_push`，满则断，恢复 I1（2.3）  
6. **[MAJOR]** per-chan 全序包含 channel-scoped 控制消息（1.3）  
7. **[MAJOR]** 窗口授信与队列 free 的耦合不变量（3.3）  
8. **[MAJOR]** window-overflow 默认 channel 级（5.3）；I5 加包计数（5.4/R7）  
9. **[MAJOR]** 测试门禁补 write-stall-during-rekey、client-initiated rekey stall、零字节洪泛、NEWKEYS 边界（§7）  
10. **[MAJOR]** 实施序列插入 **A0 止血**（deadline + 不主动 rekey），再拆三任务（6.1）

---

## 最终裁决

| 问题 | 裁决 |
|---|---|
| 架构方向是否对症？ | **是** — 针对事故根因 |
| 活性证明是否成立？ | **否** — 缺 write abort 与 Handler 界 |
| 有界证明是否成立？ | **否** — 0 字节洪泛 + 公式不全 |
| 协议正确性是否可实施？ | **否** — NEWKEYS 边界未规格化到可编码 |
| 现在能否按 Phase A 开工？ | **不能**；先 A0 + 补齐上述 BLOCKER 规格 |
| 最大一颗雷 | **deadline 拆不掉卡住的 Writer + 三任务密钥安装时序** |

—— 评审结束。不要把本文当背书；把 BLOCKER 清零后再叫下一轮检视。
