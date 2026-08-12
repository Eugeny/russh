# 复审报告(第 2 轮):russh Session Loop 全量重构方案 v2

- 评审者: grok-4.5（对抗式复审）
- 日期: 2026-08-12
- 评审对象: `.omc/plans/russh-proxy-session-rewrite.md`（**v2**）
- 对照材料: `.omc/research/russh-rewrite-review-{gpt,grok,kimi}.md`（v1 三家）；代码 `session.rs` / `server/session.rs` / `pending_inbound.rs` / `lib_inner.rs` / `cipher/chacha20poly1305.rs` / `client/mod.rs`
- 原则: 核验关闭证据；攻击 v2 新机制；[BLOCKER]/[MAJOR] 必须有失败场景

---

## 总评

**v2 相对 v1 是实质性修订，不是附录涂脂。** 三家 v1 的主干 BLOCKER（写侧无独立 deadline、NEWKEYS 方向性 epoch、EOF/CLOSE 车道超车、包数界、Handler 架空 deadline、零字节洪泛、ChannelOpenHandle 自死锁、授窗跨任务竞态）在正文里都有对应机制，不再是“意图正确、规格空洞”。

**但 v2 仍不能诚实标成“全部 BLOCKER 已关闭”。** 附录 A 的若干行被正文**方向性关闭**，却留下足以在实现期复燃的规格洞；同时 v2 新引入的 byte permit × global budget 获取序、Handler spawn 与 `&mut Session` 签名的矛盾、rekey 计数器重置、bulk 恢复触发点、kex 专队“永不满”过声称等，构成新的 [MAJOR]（个别逼近 [BLOCKER]）。

**可开工判定（见 §C）: S0 立即 GO；S1 在补齐写进度语义 + cancel-safe 写之后 CONDITIONAL GO；进入 S2 前仍须关闭 §C 最小缺口清单。** 不是 v1 那种架构级 NO-GO，但也不是“按 v2 全文直接编码”。

---

## A. 第 1 轮缺陷关闭核验

以下按附录 A 裁决表逐行核验，并展开派发 prompt 点名的 5 个重点。

### A.0 附录 A 全表逐行

| 缺陷(v1) | 附录声称 | 复审裁决 | 依据 / 残留 |
|---|---|---|---|
| Writer 卡 socket write 时一切队列 deadline 失效；keepalive 默认关且被任意入站喂活 | ConnSupervisor + 写进度看门狗 + drop socket | **[MAJOR] 半关闭** | 机制方向正确(§4.1/4.3)；**“有待写数据”与 cancel-safe 写未钉死**，见 A.1 |
| NEWKEYS 方向性 epoch 未规格化 | 方向性命令 + 原子安装序 | **[CLOSED]**（残留 [MINOR]） | §4.1 `seal(NEWKEYS,旧)→紧接着装新 outbound`；Reader 对称；两方向独立中间态写明。残留见 A.2 |
| CLOSE/EOF/SUCCESS 车道超车 | per-channel fence，因果序 > 车道 | **[CLOSED]**（残留 [MINOR]） | I3 + fence 项；close-with-backlog 用例。残留见 A.3 |
| 1 TiB 字节界漏 seqn 回绕 | 包数界 2^31 第一触发器 | **[MAJOR] 半关闭** | I5 触发点正确；**计数器在 rekey 成功后是否归零未写**，见 A.4 |
| Handler 内联 await 架空 deadline | 一律 spawn + per-callback deadline | **[MAJOR] 半关闭** | 方向对；**与 G5 `&mut Session` 签名冲突 + in-flight 无界 + deadline 后晚到 accept**，见 A.5 |
| 零字节/EOF 洪泛打穿字节界 | 双界 + 去重随迁 | **[CLOSED]** | §4.1「条数界=window/min_pkt+K，重复 EOF/CLOSE 去重、零字节 DATA 丢弃」；与现 `pending_inbound.rs:108-165` 护栏对齐 |
| ChannelOpenHandle 改有界即自死锁 | 保留免死锁路径 / slot 预留 | **[CLOSED]** | §4.1「inline finalize 不入队；spawn 走 slot 预留，有界于 max_channels」；承认 P5 有意设计 |
| 授窗与队列扩容跨任务竞态 | 入站记账迁 Reader，先扩 cap 再发 ADJUST | **[CLOSED]** | §4.1 明确次序闭合；window-grant-race 用例锚定 |
| Reader await 满 ctrl 违反 I1 | try_push + 字节预算 + 显式 RFC 取舍 | **[CLOSED]** | I1/I2'：满即 Cancelling，不等待 |
| 超窗断整连过苛 | 默认关单 channel | **[CLOSED]** | §4.6 默认关单 channel + 可配 strict |
| control 洪泛饿死 bulk | burst cap | **[CLOSED]** | I3：连续 16 包后若 bulk 可发必须让 quantum |
| “kex 插队已排 bulk”不成立 | 承认 seal 点；KexStarted 停 seal + staging 残余合法发完 | **[CLOSED]** | §4.1 KexStarted 段改写正确，且把 rekey 启动延迟上界钉到 staging |
| mpsc 条数界限不住 payload；opening 不计 slot；全局 DoS | byte permit + 全生命周期 slot + global budget | **[MAJOR] 半关闭** | 三件套方向对；**global×channel permit 获取序未定义 → 死锁面**，见 B.2 |
| “server 先行”不成立 | client 机械同改保编译 | **[CLOSED]** | 范围段 + §6：双端共享 core 同迁，行为对齐延后 |
| 事实错误一揽子(P6 每 channel、P2 软上限、rekey_read_limit 未接入、压缩 bug、pending_reads 死代码、Limits assert、行号) | §2/P8/I5 修正 | **[CLOSED]** | 代码复核: `rekey_read_limit` 仅出现于 `lib_inner.rs` 定义/测试配置，flush 路径只看 `rekey_write_limit`+时间(`session.rs:798-800`)；`alive_timeouts` 被任意入站清零(`server/session.rs:1161-1167`)；`keepalive_interval` 默认 `None`；`newkeys` 重置压缩 context 但不切换算法枚举(`session.rs:131-147`)；`pending_inbound` 零字节/EOF 去重属实。P 表修正与代码一致 |
| DRR quantum / 聚包 / local cap / first-byte boost | 1-packet 轮转 + gather + 32KiB + boost | **[CLOSED]** | §4.1/4.5 已采纳；性能细节属 S6 |

---

### A.1 ConnSupervisor 写进度看门狗与强制拆除 — **[MAJOR] 半关闭**

**已关闭部分（有正文支撑）:**

- §4.1: 观察「最后一次有字节成功写入 socket」的原子时间戳；与 keepalive/入站完全解耦——直接针对 v1 三家对 P7/`alive_timeouts` 的攻击。
- 超时 → Cancelling → token → grace 内 best-effort DISCONNECT → `abort()` + **drop 两个 socket half**；DISCONNECT 非拆除前提(G1)。
- §4.3 表把 Writer socket write 的界改为 `write_progress_deadline(supervisor)`，并写明 supervisor 通道是 CancellationToken + abort，不经业务队列。
- 测试: talk-no-read / write-stall-during-rekey 锚定。

**仍未关闭（规格不足以编码）:**

#### A.1.1 [MAJOR] 「有待写数据」未定义 → 合法 zero-window 被整连处死

正文只说「有待写数据且超过 deadline 无进度」，未区分:

| 状态 | 是否应触发看门狗 |
|---|---|
| staging/在制 ciphertext 非空，或 `poll_write` 曾返回 Pending | **是**（真 TCP/对端停读） |
| per-channel 出站队列非空，但 **所有** 就绪 channel 的 peer window=0，staging 空 | **否**（RFC 4254 合法反压） |
| 仅应用想 `data()` 但 byte permit 未取得 | **否** |

**失败场景:**

1. 多路 `direct-tcpip`：channel A 承载 speedtest 下行，peer window 打到 0 且对端迟迟不 ADJUST（移动网 / 应用停读）。
2. 其它 channel 空闲；Writer 无任何可 seal 的包，staging 空，socket 写路径空闲。
3. 若实现把「`Σ out_queue > 0`」当成「有待写」，30s 后 supervisor **拆整条连接**。
4. 结果: 单 channel 合法 zero-window → 违反 G2 断流隔离；比现状更糟（现状只是该流停，连接与其它流仍活）。

**规格必须改成可判定谓词**（建议原文级替换）:

```
write_progress 武装条件 =
  (staging 或在制 ciphertext 非空)
  ∨ (Writer 正处于对 socket 的 write/poll_write 且已观察到 Pending)
解除/不武装 =
  仅有「peer window=0 导致无法 seal」的应用队列积压，且 staging 空
进度事件 = 任意一次 socket write 返回 n>0（含 partial）
```

#### A.1.2 [MAJOR] teardown grace 与卡死 write 的 cancel-safe 交互未写

§4.1:「Writer 在总 teardown grace 内 best-effort flush DISCONNECT → grace 到期 abort()」。

**失败场景:**

1. Writer 阻塞在 `write(bulk_ciphertext).await`（对端 TCP 零窗）。
2. supervisor 因 rekey/write_progress 进入 Cancelling，广播 token。
3. 若 Writer 的 write **未** `select!` token / 可取消，则 grace 5s 内 **无法** 离开 write，DISCONNECT 零机会发出。
4. grace 到期 abort 任务 → 连接是拆了（G1 字面满足），但「grace 用于 best-effort DISCONNECT」整段成为空话；更糟的是：若有人把 grace 理解成「等待 Writer 自觉收尾」而迟迟不 abort，又回到无界。

**要求:** 每一个 socket 写点必须是 cancel-safe（`select!` CancellationToken 与 write）；Cancelling 时 **立即放弃** 当前 bulk write，改 try 排 DISCONNECT 一次，再允许卡在写上直到 grace→abort。abort 路径本身 [OK]。

#### A.1.3 [MINOR] 时间戳与「成功写」粒度

「每次 write 成功后更新」应明确: `poll_write`/`write` 返回 `Ok(n)` 且 `n>0` 即更新，不要求整包。否则大包卡在 partial 时看门狗误判。可实现，但正文未写。

#### A.1.4 [OK] 与 keepalive 解耦、强制 drop half

P7 事实（默认 None + 任意入站清零）已被 §2/§4.1 吸收；拆除不以 DISCONNECT 成功为前提——相对 v1 活性表单点塌方，**这一刀是真的**。

---

### A.2 方向性 NEWKEYS epoch — **[CLOSED]**（残留 [MINOR]）

**关闭依据:**

- §4.1 Writer: `seal(NEWKEYS, 旧 epoch) → 紧接着原子安装新 outbound epoch(cipher+MAC+compressor+seqn policy) → 之后一切包用新 epoch`。
- §4.1 Reader: 旧 epoch 打开 NEWKEYS → 等新 inbound epoch → 原子安装 → 再读下一包；等待受 rekey_deadline + token 覆盖。
- 明确「本端已发、对端未发」时出站新/入站旧为合法中间态。
- §4.2: InstallInbound 尽早、不等出站；压缩随方向 epoch；换算法时按新协商重建（修 P8）。
- §5 NEWKEYS 矩阵覆盖我先/对先/同时/partial write/strict/seqn=0。

**残留 [MINOR]（不阻 S0/S1，阻「无脑编码 S2/S3」）:**

1. **InstallInbound 与收 NEWKEYS 的先后双态未画:** key 先到 vs NEWKEYS 先到都合法，Reader 状态机需两态（`HaveKeyWaitNewkeys` / `HaveNewkeysWaitKey`），正文只写了后者叙事。
2. **「紧接着原子」必须落实为同任务、中间无 `.await`。** 若 seal 后 await 刷新 control 再 install，会重开交错窗。应在规范加一句禁止。
3. **bulk 从 KexStarted 暂停到何时恢复未钉死**——见 B.8（升为 [MAJOR]）。

相对 v1「只有笼统 KexDone」：**CLOSED**。

---

### A.3 per-channel 因果序 fence × 三级车道 — **[CLOSED]**（残留 [MINOR]）

**关闭依据:**

- I3: 因果序 **高于** 车道优先级；同 channel 的 DATA/EXTENDED_DATA/EOF/CLOSE/SUCCESS/FAILURE 按应用提交序；EOF/CLOSE 为 fence，永不超车。
- 入站 channel-scoped **全序**进 per-channel 队列（含 REQUEST/SUCCESS/FAILURE/ADJUST），修复 v1 grok 的「REQUEST 走全局 ctrl 打乱 channel 序」。
- WINDOW_ADJUST 出站走 control:「与出站数据无因果依赖」——对 **我方发送的 ADJUST**（授对端发送信用）成立。
- OPEN_CONFIRMATION 走 control:「数据必然在 confirm 之后提交」——对本端 outbound 成立。
- 对端 CLOSE → wire-lifecycle 立即回 CLOSE + `close_discarding_pending`；app-delivery 仍在队列尾——对齐 `server/encrypted.rs:1140-1166`。

**WINDOW_ADJUST / OPEN_CONFIRMATION 例外论证严密性:**

| 例外 | 论证 | 裁决 |
|---|---|---|
| 出站 ADJUST | 不依赖本端已排队 DATA 的交付；RFC 允许与数据并发 | **[OK]** |
| OPEN_CONFIRMATION | 确认前本端不应提交该 channel DATA | **[OK]** |
| 本端 app `close()` | fence 在 per-channel 队尾，不得走可超车 control | **[OK]**（I3） |
| 对端 CLOSE 的回执 | 必须丢积压 + 立即回，不得等本端 DATA | **[OK]**（双路径） |

**残留 [MINOR]:**

- 未写「channel 已发 CLOSE 之后禁止再发该 channel 的 ADJUST/SUCCESS」（生命周期门闩）；实现若漏检会在 CLOSE 后多发控制包。属状态机边角，不是 v1 超车复燃。

相对 v1 系统性截断下载：**CLOSED**。

---

### A.4 RekeyPolicy 包数界 — **[MAJOR] 半关闭**

**已关闭部分:**

- I5: 每方向 **2^31 包** 第一触发器 + 1 TiB 字节第二触发器；取消时间界；**读写各自独立记账**（对照代码: 现状 flush 只看写字节与时间，`rekey_read_limit` 未接入——P8 属实）。
- 论证修正 v1「按 32KiB 包估 137TB」的错误；chacha 以 u32 seqn 为 nonce（`chacha20poly1305.rs:130-140`）——包数界是真密码学门槛。
- API: `RekeyPolicy { max_packets: u64, max_bytes: u64, deadline }`，修 `Limits::new` assert ≤1GiB / usize 装不下 1TiB。
- seqn-wrap-near 测试锚定。

**复燃点:**

#### A.4.1 [MAJOR] 成功 rekey 后包/字节计数是否归零——未写 → rekey 风暴

**失败场景:**

1. 出站包计数到 2^31 → 触发 rekey → 双向 NEWKEYS 完成，连接回到 Idle。
2. 若计数器是连接级累加且 **不归零**，则下一包 seal 时 `count >= 2^31` 仍成立 → **立即再次 InKex**。
3. 对端每次配合完成 → 连接进入「一包一 rekey」；对端若偶尔慢 → 反复撞 30s deadline → 周期性拆连。
4. 内存/CPU: kex 状态机与密钥材料在热路径上被打满（rekey-storm 变体，但是 **自激** 而非对端恶意）。

**规格必补一句:**  
`max_packets` / `max_bytes` 计数器在 **该方向新 epoch 安装成功时归零**（或改为 per-epoch 计数）；与 strict-kex 的 **wire seqn 置 0** 是两件不同的事——seqn 重置跟 epoch 安装走，**策略计数**跟 epoch 生命周期走，二者都要在 Install 点发生。

#### A.4.2 [MINOR] 计数权威位置

包计数应在 Reader open 成功 / Writer seal 成功时递增（含 kex 包本身是否计入——建议计入，与 nonce 消耗一致）。正文未写，可推断但应钉死。

#### A.4.3 [OK] 与「服务端默认不主动 volume rekey」的关系

硬界仍触发；客户端发起全力配合 + deadline。事故主路径覆盖 [OK]。

---

### A.5 Handler 全部 spawn — **[MAJOR] 半关闭**

**已关闭部分:**

- §4.1:「Handler 一律 spawn，SessionTask 永不内联 await 用户代码」——直接回应 v1「契约 + debug_assert 不是界」。
- 结果有界队列回流；auth/OPEN 决策 deadline 默认 30s → **按 reject 处理并释放 slot**。
- handler-block 用例（pending/panic/CPU）。
- open slot 覆盖 opening+active+closing（修囤 Handle）。

**复燃 / 新洞:**

#### A.5.1 [MAJOR] G5「Handler 签名保持」与 spawn 在类型上矛盾

现 `Handler::data` / `channel_open_*` 等签名形如（`server/mod.rs:478+`）:

```text
fn data(&mut self, channel, data: &[u8], session: &mut Session) -> Future
```

**失败场景（实现二选一必撞墙）:**

1. **保持 `&mut Session` 并 spawn:** 不能把 `&mut Session` 移入 `'static` 任务；若 SessionTask 继续跑，则两处同时可变借用 Session → 未定义 / 编译不过。
2. **spawn 后 SessionTask join 该 future:** 回到「内联 await 用户代码」，deadline 再次可被长 future 架空（除非 join 带 timeout——此时等价 timeout 包裹 await，与「spawn 隔离」话术不一致，且仍占用 SessionTask 逻辑线程除非真并行）。
3. **改签名为 `Handle`:** 与 G5「Handler trait 签名保持」字面冲突；zfc 若在回调里用 `session` 直接写包，会静默破坏。

方案 §4.7 只写「执行上下文变化做 contract test」，**没有选定 (Handle-only / 代理 Session / 超时 join) 中的任何一种**。这不是文风问题，是 **S3/S4 无法编码**。

#### A.5.2 [MAJOR] in-flight spawn 无界

「回调结果经有界队列回流」只限制 **完成态**，不限制 **同时存在的任务数**。

**失败场景:**

1. 对端对 128 channel 狂发 `CHANNEL_REQUEST` want-reply（或走 `Handler::data` 的每包回调路径）。
2. Session 每条 spawn 一个任务；结果队列容量 M，任务数可先涨到「未完成回调数」。
3. 每个任务栈 + 闭包捕获（若拷贝 payload）→ 内存在 deadline 批量到期前突破 §4.4 闭式（公式未含 task 数 × 栈）。
4. 决策 deadline 只覆盖 auth/OPEN，**未声明 channel request / data / gex 回调同样有 in-flight cap**。

**必补:** `max_in_flight_handlers`（或按类型分桶）+ 超额策略（对端该 channel 失败 / 丢弃 / 断连）+ data 路径是否还走 Handler（代理场景多走 `ChannelStream`，应显式降级）。

#### A.5.3 [MAJOR] deadline reject 后晚到的 accept/reject

**失败场景:**

1. OPEN 到达 → 占 slot → spawn handler（下游 dial 30s+）。
2. `open_decision_deadline` 到期 → Session 发 `CHANNEL_OPEN_FAILURE`，**释放 slot**，channel id 可复用给新 OPEN。
3. 旧 handler 终于 `accept()` → 经「免死锁路径」注入 → 作用在 **错误的 generation / 新占用者** 上，或二次 finalize 已失败的 open。
4. 对端看到: 先 FAILURE 再对同一 id 的 CONFIRM 混乱；或本端状态机 panic。

**必补:** 每个 opening 的 **generation / oneshot 单次消费**；timeout 后 cancel 或忽略一切晚到 disposition；handler 侧 `accept` 返回 `Err(Expired)`。

#### A.5.4 [OK] 对端重试

reject 后对端再 OPEN 是合法行为；slot 归还后可再占。语义正确，前提是 A.5.3 的 generation 不串台。

---

### A.6 其余附录项补遗

- **[CLOSED] 零字节洪泛 / 授窗竞态 / try_push / 超窗策略 / burst / seal 点 / server-client 边界 / 事实纠错 / 调度参数** — 见 A.0 表，正文有可定位语句。
- **v1 grok [MAJOR] WindowSizeRef 双账本:** v2 写「peer 窗口权威在 Writer」「出站 byte permit」，**未点名删除** `channels/mod.rs` 的 `WindowSizeRef` 与 `outbound_acks`。若 S4 残留生产者预扣窗 + Writer 再扣，会重现 lost-wakeup / 假满。标 **[MAJOR] 残留规格债**（见 B.2 旁注），附录 A 未单列但 v1 grok 3.4 提过。

---

## B. v2 新机制的新风险

### B.1 ConnSupervisor 状态机 Running→Cancelling→Aborting→Joined — **[OK]** 为主，残留 **[MINOR]**

- 首因获胜、统一 grace、abort+drop half: 正确，且是 v1 活性论证的真正补丁。
- **[MINOR]** 「Session 注册 rekey_deadline」若走可满 mpsc，注册本身可被堵。应用 `watch`/原子 + supervisor 侧 `select!` 定时器，正文「不经任何队列」仅保证拆除方向，注册方向应同样无阻塞。
- **[MINOR]** 部分 spawn 失败时 JoinHandle×3 的残缺状态未写。

### B.2 byte permit — **[MAJOR] 全局预算获取序死锁**

**机制价值 [OK]:** 在移交 `Bytes` 所有权前取 permit，堵住「多 caller 各持 512MiB 等 mpsc 槽」——v1 gpt BLOCKER 的正对修复。

**新死锁面 [MAJOR]:**

§4.4: 进程级 `global_byte_budget` 在 **permit 层联动**；同时每 channel 有 `out_cap` semaphore。

**失败场景（经典 ABBA）:**

1. 连接 C1 任务 T1: 先 `channel_permit.acquire(1MiB)` 成功，再 `global.acquire(1MiB)` —— global 已尽，等待。
2. 连接 C2 任务 T2: 先 `global.acquire(1MiB)` 成功，再 `channel_permit`（该 channel 被其它 holder 占满）等待。
3. 或同连接: 协程 A 持 channel permit 等 global；协程 B 持 global 等 channel。
4. 无人释放 → **永久等待**；若两者都不算「socket 写进度」，write_progress **不触发**；inactivity 若被对端上行喂活也不触发 → **G1 回归僵死**（应用层 `data().await` 永挂，连接级 supervisor 不知情）。

**必补:**

1. 全局固定获取序: **永远先 global 后 channel**（或相反），全仓库唯一；
2. 持 permit 等待下一层的时间纳入 progress wait（per-request deadline 或写入「blocked-on-permit」监督）；
3. teardown 时 **两级 permit 全部 close/Err 唤醒**（正文只写了 permit 在 teardown 时 Err——须覆盖 global）。

### B.3 全局预算 — **[OK]** 方向，**[MINOR]** 饥饿

- 100×384MiB 的 DoS 面必须靠全局预算——采纳 gpt 意见 [OK]。
- **[MINOR]** 大连接长期占满 global → 新连接 open 后 `data()` 全堵，形似活连接实则无代理能力；需文档化为有意降级，或 per-conn 下限保留。

### B.4 ready-set 1-packet 轮转 + first-byte boost — **[OK]** / **[MINOR]**

- 相对 v1 DRR 64KiB: 最坏排队减半、无 deficit 状态 [OK]。
- **[MINOR]** open-flood 至 max_channels 时，每个新 channel 一次 boost → 最多 128 个插队包，可短暂饿老流；可接受，应用例钉 p99。

### B.5 control burst cap(16) — **[OK]**

- KEX/NEWKEYS/DISCONNECT 绝对优先不吃 cap；普通 control 让 bulk——闭合 v1 starvation。
- 与 fence 组合: bulk quantum 推进 per-channel 队列才能到 fence，逻辑自洽。

### B.6 wire-lifecycle × app-delivery 双路径 CLOSE — **[OK]**，残留 **[MINOR]**

- 对齐现状 `close_discarding_pending` + 入站 Close 保序投递 [OK]。
- generation 关联 [OK]。
- **[MINOR]** app 侧 Close marker 到达时 channel 已 finalize：须保证 `recv` 仍能看见 Close 或等价 EOF，避免 relay 只见 `None` 无法区分。

### B.7 kex 专用队列容量 16 — **[MAJOR] 「永不满」过声称**

§4.1 枚举定容 16 合理量级；§4.3 环检查写「专队按枚举定容，**永不满**」。

**失败场景:**

1. Session 推 `KexStarted` + 密封用 KEXINIT 载荷进入 Writer kex 队列。
2. Writer 卡在 **旧 staging bulk** 的 socket write（KexStarted 已到但尚未执行到「停 seal / 改发 kex」——若先阻塞在写，**根本不能 drain kex 队列**）。
3. Session 继续推 ECDH 回包 / NEWKEYS 命令 → 有界 kex 队列满 → Session 阻塞在 push。
4. 不是「永不满」，而是 **依赖 write_progress/rekey_deadline 拆连**——这本来就是 supervisor 的工作，但正文用「永不满」假装环不存在。

**裁决:** 队列定容 [OK]；「永不满」**改为**「满则 Session 侧属 progress wait，由 rekey_deadline/write_progress 终止」。实现上 Writer 每次 write 必须 select kex 队列与 token（cancel-safe），否则 KexStarted 无法打断 bulk write。

枚举完整性 **[MINOR]:** 正文枚举偏 ECDH；DH-GEX 多 `GEX_GROUP` 等，仍应 ≤16；须写明 **含 KexStarted**、simultaneous rekey 时第二轮是否复用同一队列（InKex 中再收 KEXINIT 的策略与槽位）。

### B.8 bulk 恢复触发点缺失 — **[MAJOR]**

KexStarted:「立即停止 seal bulk」。**何时恢复 seal bulk？** 正文只写 Session「双向 NEWKEYS 生效 → Idle」。

RFC 4253: 本端 **发出 NEWKEYS 之后** 即可用新密钥发送，**不必**等对端 NEWKEYS。

**失败场景（性能/活性）:**

1. 本端已 `EmitNewkeysAndInstallOutbound`，对端迟迟不发 NEWKEYS（或包在路上）。
2. 若 Writer 死等 Session Idle 才恢复 bulk → 在 rekey_deadline 剩余时间内 **全 channel 下行停死**，即使对端已能用新密钥收数据。
3. 代理 p99 多停一轮 RTT～数秒；与「对端已就绪却不发」叠加时放大 30s 停顿面。

**失败场景（实现分歧）:**

- 实现者 A: 出站 NEWKEYS 后立即恢复 bulk（RFC）。
- 实现者 B: 等双向（正文 Idle 叙事）。
- 测试矩阵两边绿不了同一套断言。

**必补:**  
`Writer: 完成 EmitNewkeysAndInstallOutbound 后允许 seal bulk（新 epoch）`；  
`Session Idle 仅表示注销 rekey_deadline 与状态机回静`；二者解耦。

### B.9 策略表 §4.6 — **[OK]** / **[MINOR]**

- 显式严于/宽于 RFC 的表是 v2 正确加法 [OK]。
- 「对端 KEXINIT 之后仍到的上层报文: 容忍」——互操作友好；须与 strict-kex 初始断连并列测试 [MINOR 已有用例名]。
- ctrl 洪泛 DISCONNECT 与 I2' 一致 [OK]。

### B.10 切片 S0–S7 — **[OK]** 结构，**[MINOR]** 门禁

- S0 harness 先于重构、S1 先上 supervisor 不改数据面: 正确吸收 v1 可实施性批评 [OK]。
- S4 删 Scheme C 依赖 S3 记账闭合 [OK]。
- **[MINOR]** S1 完成门写 write-stall/talk-no-read/rekey-stall 三绿——但现架构 **无** 独立 write_progress，S1 必改 loop；「不改数据面」与「接入看门狗」边界要在 S1 设计里写清（允许改 select! arm / flush 钩子，不准改 kex/channel 语义）。

### B.11 跨任务消息次序假设（汇总攻击）

| 路径 | 次序假设 | 风险 |
|---|---|---|
| Session→Reader 授窗 → Reader 扩 cap → Writer ADJUST | 正文闭合 | **[OK]** |
| Session→Writer KexStarted 先于 kex 载荷 | 隐含 | Writer 必须先处理 KexStarted 再 seal 任何非 kex；与卡死 write 交叉见 B.7 |
| Session→Reader InstallInbound ∥ Session→Writer EmitNewkeys | 允许并行 | **[OK]** 方向独立 |
| Reader wire-CLOSE → Session lifecycle ∥ app 队列 Close | generation | **[OK]** 若 generation 贯穿 |
| Handler 结果 → Session finalize | 单次消费 | **[MAJOR]** 见 A.5.3 |
| 消费返窗: app → ? → Reader/Session | 「按实际消费」 | **[MAJOR] 残留:** 谁发 consumption ack、handler-only 无 ChannelStream 时谁记账——§4.1 一行带过，S4 删 Scheme C 前必须闭合，否则 partial-read 仍可虚增窗口 |

### B.12 Handler::data 与 `&[u8]` 生命周期 — **[MINOR]**

spawn 前必须拷贝 payload；否则悬垂。常识级，但高 PPS 下多一次拷贝影响 G3，S6 再优化。

### B.13 内存公式与 spawn/oneshot — **[MINOR]**

§4.4 仍低估: in-flight handler、opening 字段 String、oneshot 图、三任务同时持队列峰值。global budget 是后盾，不是证明。

---

## C. 可开工判定

### 结论

| 切片 | 判定 | 理由 |
|---|---|---|
| **S0** 恶意 harness + 事故复刻 | **GO** | 不依赖未闭合规格；对现架构跑、允许红、锁基线。应立即开工。 |
| **S1** ConnSupervisor + 三 deadline + 统一拆除 | **CONDITIONAL GO** | 架构正确且最大风险应先消；但 **必须先用一页规格补丁钉死 A.1.1 谓词 + A.1.2 cancel-safe 写**，否则 S1 会把「合法 zero-window」做成新的误杀事故，或把 teardown grace 做成空操作。 |
| **S2+** Writer/Reader/窗口/RekeyPolicy/性能 | **NO-GO until 最小缺口关闭** | 见下表；不阻塞 S0/S1 编码，阻塞「按 v2 正文无补丁推进 S2」。 |

**整份 v2 相对 v1:** 从 **架构 NO-GO** 提升为 **S0/S1 可进、全量实施仍有条件**。附录 A「已关闭全部 BLOCKER」**不成立**——至少 A.1 / A.4 / A.5 / B.2 / B.8 仍是带失败场景的 [MAJOR]；其中 A.5.1 与 B.2 在对应切片上具备 [BLOCKER] 杀伤力。

### 仍需关闭的最小缺口清单（按优先级）

#### P0 — 阻塞 S1 验收正确性（半页～一页补丁即可）

1. **写进度武装谓词**（A.1.1）: 仅 staging/在制写/Pending write；**排除** 纯 peer-window=0 队列积压。
2. **所有 socket write cancel-safe**（A.1.2）: Cancelling 时能打断 bulk write，grace 内尝试 DISCONNECT，再 abort。
3. **S1 范围句**: 允许钩 flush/select!/token，禁止改 kex 语义；三用例判定标准写明触发的是 supervisor 而非 keepalive。

#### P1 — 阻塞 S2（Writer / kex 车道）

4. **bulk 恢复点**（B.8）: 出站 NEWKEYS 安装后即可 seal bulk；Idle 只撤 deadline。
5. **kex 专队**（B.7）: 删除「永不满」；写明 Writer 在 write 路径上必须 poll kex 队列 + token；枚举含 KexStarted / GEX。
6. **NEWKEYS 双态 + 禁止 await**（A.2 残留）: Reader key/NEWKEYS 先后；Writer seal→install 无 await。

#### P2 — 阻塞 S3/S4（Session / Handler / 窗口收口）

7. **Handler spawn 的 API 决议**（A.5.1）: 三选一写死——(a) 签名改为 Handle；(b) Session 方法全部消息化；(c) 仅 auth/open 等决策类 spawn+timeout，data 路径不走可阻塞 Handler。不能再「签名保持 + 一律 spawn」并列空话。
8. **in-flight handler 上界 + generation 单次 disposition**（A.5.2/A.5.3）。
9. **global × channel permit 固定获取序 + teardown 双唤醒 + 阻塞在 permit 上的 deadline**（B.2）。
10. **Rekey 计数器 per-epoch 归零**（A.4.1）及计数点（seal/open）。
11. **消费返窗权威路径**（B.11）: partial-read / handler-only / receiver drop；删 Scheme C 的前置条件。
12. **WindowSizeRef / outbound_acks 删除或单一化**（A.6）: 与 Writer peer-window 权威合并，防双账本。

#### P3 — 不阻塞开工，但进 S5/S6/S7 前要有

13. ADJUST/SUCCESS 在 CLOSE 后的生命周期门闩（A.3）。
14. global 预算下的连接间公平/保底（B.3）。
15. 真实客户端矩阵与 24h soak（正文已列，保持为门禁而非事后）。

---

## 附: 对 v2 自夸句的直接回应

- **「v2 已关闭全部 BLOCKER 缺口」** — **否。** 主干机制就位，但 A.1/A.4/A.5/B.2/B.8 仍可以在真机/恶意对端下打出永久僵死、误杀整连、rekey 风暴或无法编码的 API 矛盾。应改为:「v1 三家 BLOCKER 均有正文对症机制；其中 N 项完全闭合，M 项方向闭合、规格仍缺可编码细节」。
- **「宁断勿僵」** — 在 supervisor+abort 下 **方向成立**；在 permit 死锁（B.2）与「有待写」误定义（A.1.1）两条上 **仍可僵或误断**。
- **活性表「所有边失败终止于 supervisor」** — 拆 socket 的边 [OK]；**应用卡在 global/channel permit 且无 progress 武装** 的边 **未进入表**。

---

## 复审签名

- 未修改仓库内除本文件外的任何文件。
- 输出路径: `.omc/research/russh-rewrite-review-r2-grok.md`
- 建议作者: 先出 **v2.1 补丁页**（P0+P1+P2 清单逐条改正文），再开 S1；S0 可并行。
