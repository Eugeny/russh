# 复审（第 2 轮）：russh Session Loop 全量重构方案 v2

- 评审者: gpt（对抗式复审，修订稿）
- 日期: 2026-08-12
- 评审对象: `.omc/plans/russh-proxy-session-rewrite.md`（**v2 全文**）
- 对照材料: `.omc/research/russh-rewrite-review-{gpt,grok,kimi}.md`（第 1 轮）
- 代码核验: `russh/src/server/{mod.rs,session.rs,encrypted.rs}`、`session.rs`、`sshbuffer.rs`、`pending_inbound.rs`、`lib_inner.rs`、`channels/mod.rs`、`cipher/chacha20poly1305.rs`、`client/mod.rs`、`kex/`、`negotiation.rs`
- 约束: 只读代码；只写本文件

---

## 总评

v2 相对 v1 **正确选定了第 1 轮 3/3 BLOCKER 的机制位**（ConnSupervisor、方向性 epoch 叙述、因果 fence、包数触发点、Handler 不得内联 await、双界、slot、byte permit 意图、S0–S7）。附录 A 多数条目在正文有对应段落，不是纯口号。

但 v2 **仍不能当作 S1 施工图**。至少五处规格在「写进正文」与「可无歧义编码且不破坏 G1/G4」之间断裂：

1. **写进度看门狗** wire-eligible 谓词、idle→armed、原子快照、abort/cancel-safe 未钉 → **[BLOCKER]**；慢进度刷新时间戳 **不是** 活性缺陷。S1 可接非 watchdog 骨架，**不可编码 watchdog 验收**。  
2. **NEWKEYS** 缺 actual-install ACK + kex generation → **[BLOCKER]**。  
3. **Handler「一律 spawn」**与 `&mut self`/`&mut Session` 冲突 → **[BLOCKER]**。  
4. **G4 / byte permit / global budget** 签名与 inbound 会计 → **[BLOCKER]**。  
5. **OPEN_CONFIRM** Writer fence 与 **peer CLOSE 跨任务停止边** → 分别为 **[BLOCKER]** / **[MAJOR]**。

**可开工判定: [BLOCKER] 条件 NO-GO**（S0 **[OK] GO**；S1 按 v2 完成门 **[BLOCKER] NO-GO**）。允许预研非 watchdog 的 supervisor 骨架，**不等于 S1 完成**。

---

## A. 第 1 轮缺陷关闭核验（附录 A 逐行，共 16 行）

### A.1 裁决表

| # | 附录 A 缺陷 | 复审判定 | 依据 / 复燃说明 |
|---|---|---|---|
| 1 | Writer 卡 socket write；keepalive 被入站喂活（BLOCKER 3/3） | **[BLOCKER] 机制位就位，规格不可编码** | 正文有 ConnSupervisor + 看门狗 + drop socket（§4.1/4.3）。缺 wire-eligible 谓词、idle→armed、原子快照、abort/cancel-safe（A.2.1）。慢 n>0 进度**不是**阻断项。**不能 CLOSED。** |
| 2 | NEWKEYS 方向性 epoch（BLOCKER） | **[BLOCKER] 主序叙述有，安装闭环无** | §4.1/4.2 写了方向性 seal/install 序与双向独立。真正缺口是 **actual-install ACK + kex generation**：Session「发命令/见 NEWKEYS」≠ Reader/Writer 已原子安装；据此注销 deadline 会假活——见 A.2.2。 |
| 3 | CLOSE/EOF/SUCCESS 车道超车（BLOCKER 3/3） | **[CLOSED] 本端出站因果意图**；**[MAJOR] 入站 CLOSE 跨任务停止边未关** | I3+§5 关闭「本端 EOF/CLOSE 超车 bulk」；v2 双路径 peer CLOSE 的 Writer 停止边见 B.6.1，**不得**把 CLOSE 整体标 CLOSED。 |
| 4 | 1 TiB 漏 seqn 回绕 / chacha nonce（BLOCKER 3/3） | **[MAJOR] 触发点关闭，计数生命周期未关** | I5：2^31 包/方向第一触发器正确；chacha 确用 u32 seqn（`cipher/chacha20poly1305.rs:130-140`）。缺 per-key-epoch 归零时机、KEX 包是否计入、双方向同时触发合并——见 A.2.4。 |
| 5 | Handler 内联 await 架空 deadline（BLOCKER） | **[BLOCKER] 「一律 spawn」与 trait 冲突** | §4.1 主策略方向对，但现 `Handler` 回调签名强制 `&mut self` + 常带 `&mut Session`（`server/mod.rs` 全族），连接级可变状态不可并发 spawn——见 A.2.5。 |
| 6 | 零字节/EOF 洪泛（BLOCKER grok） | **[CLOSED]** | §4.1 双界 + 重复 EOF/CLOSE 去重 + 零字节 DATA 丢弃；与 `pending_inbound.rs:108-113,154-181` 一致并写明随迁。 |
| 7 | ChannelOpenHandle 改有界自死锁（BLOCKER gpt） | **[CLOSED]** | §4.1/P5 保留免死锁路径、slot 预留；与 `lib_inner.rs:558-599`、`client/mod.rs:114-117` 意图一致。 |
| 8 | 授窗与队列扩容跨任务竞态（MAJOR kimi） | **[CLOSED]（本端出站 ADJUST 发送侧）** | §4.1：Reader 入站记账；「先扩本地 cap，再请求 Writer 发 ADJUST」。注意：入站 peer ADJUST 另有冲突（A.2.3 / B.8）。 |
| 9 | Reader await 满 ctrl 违反 I1（MAJOR grok） | **[CLOSED]** | I2'：`try_push`，满即 Cancelling。 |
| 10 | 超窗断整连过苛（3/3） | **[CLOSED]** | §4.6 默认关单 channel；对照 `server/encrypted.rs:1244-1255`。 |
| 11 | control 洪泛饿死 bulk（MAJOR gpt） | **[CLOSED]** | I3 burst cap：连续 16 普通 control 后若 bulk 可发让出 1 quantum。 |
| 12 | 「kex 插队已排 bulk」不成立（gpt/grok） | **[CLOSED]** | §4.1 KexStarted：停 seal bulk；staging 残余合法 FIFO 发完；插队仅对未 seal 队列。 |
| 13 | mpsc 条数界 / opening slot / 全局 DoS（gpt） | **[BLOCKER] 未关闭** | slot 全生命周期与 byte permit **意图**在 §4.1/4.4，但保持 `Handle::data`/`data_bytes(impl Into<Bytes>)` 时「permit 在收下所有权前取得」**不成立**；global budget 又不覆盖 inbound grant——见 A.2.6 / B.2–B.5。 |
| 14 | 「server 先行」不成立（kimi） | **[CLOSED]** | §6：client 机械同改保编译；S4 双端同删 Scheme C。 |
| 15 | 事实错误修正（P6/P2/P8/Limits 等） | **[CLOSED]** | §2/P8/I5 已改。核验：`rekey_read_limit` 无生产触发（`session.rs:798-800` 只看 write/time）；`newkeys` 不写回压缩枚举（`session.rs:131-147`）；`pending_reads` 无 push；`OUTBOUND_HIGH_WATERMARK` soft（`sshbuffer.rs:369`）；keepalive 默认 None 且任意入站清零（`server/mod.rs:140`、`server/session.rs:1161-1167`）。 |
| 16 | DRR/聚包/local cap/boost | **[CLOSED] 采纳意图**；**[MAJOR] boost 公平（新风险）** | §4.1/4.5 采纳 1-packet/gather/32 KiB/boost；boost 无额度可饿死老 bulk 见 B.4。 |

### A.2 重点深挖

#### A.2.1 ConnSupervisor 写进度看门狗 — **[BLOCKER]**

**已就位（架构层）:**  
Supervisor 持 `write_progress` / rekey / handshake / teardown_grace；超时 → Cancelling → abort + **drop 两个 socket half**；DISCONNECT best-effort（§4.1 G1 / §4.3）。与 keepalive 解耦正确；代码侧 P7 属实。

**不可编码的缺口（任一足以否决 S1 编码 watchdog）:**

**(1) wire-eligible / staging vs peer-window=0**  
§4.1：「有待写数据且超过 deadline 无进度」。§4.3 行却只写 socket write。  
**失败场景（误拆）:** channel A `recipient_window=0`，bulk 队列非空但 **不可上线**；Writer 合法空转。字面「有待写」武装 30s → 拆整连。多 channel 代理中单流反压变成 G2 失败。  
**失败场景（漏拆）:** 若实现只看「队列非空」之外的过严条件、却忘记 **已 seal staging / 正在 `poll_write` 的密文**，对端 TCP 停读时 staging 卡住而队列已空 → 永不武装。

**(2) idle→armed 起点缺失**  
若 `last_success_write` 在连接空闲 1h 后仍停在旧值，**新工作一到达**（第一包 seal 入 staging）时，`now - last_success` 已 ≫ 30s → **立即 Cancelling**。  
**失败场景序列:**  
`t=0` 末次成功写；`t=0..3600` 无出站；`t=3600` 应用 `data()` 入队 → Writer seal → 看门狗采样见 pending∧(now-last≫deadline) → 误拆。  
必须规定：**仅在「从 idle 进入 wire-eligible 的边沿」采样武装时钟**（`armed_at = now` when pending 从 false→true），或 `last_success` 在 idle 时不参与比较。

**(3) pending 与 last_success 的原子快照竞态**  
**失败场景（假活 / 误超时）:**  
1. Supervisor 读 `pending=false`；  
2. Writer 成功写完最后字节，更新 `last_success`，随即又 seal 新包 `pending=true` 并卡住 `poll_write`；  
3. Supervisor 基于陈旧 `pending=false` 不武装；或交错读到 `pending=true` 配上 **写成功前的旧 last_success** 导致瞬时误判超时。  
需要 **单字/单结构原子快照**（例如 `(generation, last_success, wire_eligible_bytes)` 由 Writer 在同一 release 更新；Supervisor 一次 load），禁止分字段分别 load。

**(4) abort / cancel-safe 与 write 的交互（规格未钉）**  
§4.1 要求 grace 内 best-effort DISCONNECT，grace 后 abort+drop half。须规定：Writer 每次 `poll_write` 与 CancellationToken 竞态；**不得**在 Drop 路径上无限 `write_all`；socket half 关闭权在 supervisor。缺此则 S1 接入现 loop 时实现分叉（对照现状 teardown 5s timeout：`server/session.rs:1191-1208`）。

**明确不作为活性 BLOCKER:**  
对端极慢但 **每次 `write` 成功字节数 n>0 即刷新 `last_success`** 的路径符合 G1「继续工作」——连接仍有进展，不是永久僵死。吞吐 SLO /「1 字节/29s 是否算可用」属于运营指标，**不得**伪装成活性正确性要求；rekey 另有独立 `rekey_deadline` 覆盖密钥卫生。正文「write 成功后更新时间戳」本身已足够清晰。

**S1 边界:**  
- **可做:** CancellationToken 化 teardown、rekey/handshake deadline 挂 supervisor、强制 abort/drop half、总 teardown_grace（非 watchdog）。  
- **不可做:** 按当前正文编码 `write_progress_deadline` 并以其作为 S1 完成门（talk-no-read/write-stall 最终绿）。S0 可先写红/预期用例锚定缺口。  
- **非 watchdog 骨架 ≠ S1 完成**（见 §C）。

#### A.2.2 方向性 NEWKEYS + actual-install ACK — **[BLOCKER]**

**正文已有:**  
`seal(NEWKEYS, 旧) → 装 outbound epoch`；Reader 旧钥开 NEWKEYS 后再装 inbound；两方向独立；压缩随 epoch；strict-kex 在安装点重置 seqn（§4.1/4.2）。

**真正缺口不是「staging 必须排空才能 seal NEWKEYS」。**  
已 seal 的旧密文与随后 seal 的 NEWKEYS/新密文可在 staging/TCP 上 **FIFO 连续共存**；只要 NEWKEYS 本身用旧 epoch seal、其后包用新 epoch，边界正确即可。v2 §4.1「staging 残余合法发完」在这一点上方向对——**不要**再要求「排空 staging 才允许 seal(NEWKEYS)」（那会把 rekey 启动延迟绑死在对端读速度上）。

**缺口是安装闭环与 deadline 注销条件:**

Session 今日叙述等价于：算出密钥 → 发 `InstallInbound` / `EmitNewkeysAndInstallOutbound` → 见双向 NEWKEYS → Idle 并 **注销 rekey_deadline**（§4.2）。  
但 **发命令成功 ≠ 所有者已原子安装**。

**失败场景 A（Reader 永等 Install，deadline 已注销）:**  
1. 对端 NEWKEYS 到达；Reader 进入 WaitInstall(gen=G)。  
2. Session 向 Reader 发 `InstallInbound{G, epoch}`，**ctrl/专队 try_push 失败被丢**或 Reader 尚未 poll 到。  
3. Session 已见本端 Writer 路径「完成」及对端 NEWKEYS，按 §4.2 回 Idle **注销 deadline**。  
4. Reader 永久阻塞等 Install；I1 唯一允许的等待点失去 supervisor 覆盖 → **G1 假活**（连接不拆，读永久停，对端继续发新钥包 → 或协议错乱或静默）。

**失败场景 B（Writer 命令丢/卡，Session 仍注销）:**  
Session 发 `EmitNewkeysAndInstallOutbound{G}` 后，Writer 卡在 socket write 排旧 staging；Session 以「消息已入队」当作完成。若仅用「入队」注销 deadline，Writer 从未 install → 随后误用旧钥 seal 应用包，对端已切新钥 → MAC 失败。

**失败场景 C（无 generation 的迟到 Install）:**  
rekey G 超时拆连/新 rekey G+1 已开始；G 的迟到 Install 被 Reader 应用 → **错代密钥**。

**规格必须补:**  
- 每个 kex 轮次 `kex_generation`；所有 Install/Emit/ACK 绑定 generation。  
- Reader/Writer 在 **原子安装点** 回 `InstallAck{direction, gen}`（或等价 watch）。  
- Supervisor/`Session`：**仅双方向需要的 ACK 到齐**（本端 outbound install ACK + 对端 NEWKEYS 已处理并 inbound install ACK，按角色）才 Idle 并注销 deadline。  
- 命令路径满/失败 → 不得假装完成；应重试至 deadline 或 Cancelling。  
- bulk 恢复边：本端 outbound install ACK 之后即可按 RFC 用新钥发非 kex（可选策略写死一种）。

#### A.2.3 因果 fence 与车道例外 — **[CLOSED] 本端 EOF/CLOSE 因果意图 + [BLOCKER] OPEN_CONFIRM + [MAJOR] 入站 CLOSE 停止边 / REQUEST / ADJUST**

**CLOSED（有限）:** I3 纠正「本端应用提交的 EOF/CLOSE 走 control 超车 bulk」的 v1 截断问题；SUCCESS/FAILURE 为 fence；WINDOW_ADJUST **出站**可走 control 的论证成立；§5 close-with-backlog 锚定的是 **本端因果序** 意图。

**未关闭:** v2 新增 **wire-lifecycle 与 app-delivery 双路径 CLOSE** 的跨任务停止边——见 **B.6 [MAJOR]**。不得把 CLOSE「整体」标 CLOSED。

**[BLOCKER] OPEN_CONFIRMATION 例外论证不足（见 B.6）:**  
§4.5「数据必然在 confirm 之后提交」在 **应用契约** 上不成立。`ChannelOpenHandle::accept` 仅 `unbounded send` 回复（`lib_inner.rs:597-599`），返回不代表 Writer 已发 CONFIRM 或 channel 已可发数据；注释亦写 accept 前写入会被静默丢弃（:565-567），**accept 后立即 data 的跨队列竞态未禁止**。

**[MAJOR] 出站 CHANNEL_REQUEST 未进 fence 白名单:**  
DATA 在 bulk、REQUEST 被放 control → REQUEST 超车。须默认 channel 作用域全序，仅显式旁路。

**[MAJOR] 入站 WINDOW_ADJUST 进 app 全序队列 vs Writer peer 窗口权威:**  
见 B.8。这是 v2「所有 channel-scoped 进 app 队列」与「credit 到账即唤醒 ready-set」的 **跨任务规格冲突**。

#### A.2.4 RekeyPolicy 包数界 — **[MAJOR]**

**已关闭:** 2^31 第一触发、1 TiB 第二、时间取消、读写分账、`RekeyPolicy` API 动机（`Limits::new` assert ≤1GiB，`lib_inner.rs:274`）；现状 read 未接入属实。

**须补语义（否则 S5 仍会打错）:**

1. **计数器 = per-key-epoch，与 wire seqn 策略解耦。** strict 重置 seqn ≠ 自动归零包数计数；non-strict 不重置 seqn 时更不能用绝对 seqn 当界。  
2. **归零时机 = 该方向 actual epoch install ACK 成功之后**，不是「Session 进入 Idle」或「发出 KEXINIT」。  
   **失败场景:** 计数在发 KEXINIT 时归零，rekey 失败回退旧钥继续 seal → 计数低估 → 逼近 2^32 nonce 重用。  
3. **触发前与 rekey 期间：所有方向包均计数（含 KEX/NEWKEYS/IGNORE）**，因均消耗 seqn/nonce。  
4. **读写同时触及阈值:** 合并为单次 InKex，不启动两个并行 rekey 状态机。  
5. **硬顶:** 触发后停 bulk seal；kex 裕量后仍无 ACK → deadline 拆连，禁止静默越过 2^32−ε。

#### A.2.5 Handler「一律 spawn」— **[BLOCKER]**

**问题不是「deadline 数字」而是「无法按字面 spawn」。**

现 `Handler` trait（`server/mod.rs`）典型签名：

- `fn data(&mut self, channel, data, session: &mut Session)`  
- `fn channel_open_direct_tcpip(&mut self, …, reply, session: &mut Session)`  
- `fn auth_*(&mut self, …)`  

回调 **借用 handler 的 `&mut self`（连接级状态）且经常 `&mut Session`**。zfc/示例在 handler 内可变状态上记账、开 relay、写 session。  
**无法**在无 facade 的情况下把多次回调 `tokio::spawn` 到并行任务：Rust 拒绝别名 `&mut`；即便 `Arc<Mutex<H>>` 绕过编译，**连接级状态与 Session 可变 API 的串并行/因果序**仍未定义。

**失败场景 1（直接不可编码）:**  
OPEN 与 DATA 回调被 spawn 并行；两者 `&mut self` → 必须在执行器内串行化；v2 未定义执行器 → 实现者若 `spawn` 裸 future 则 **编译不过** 或内部锁死。

**失败场景 2（timeout + late accept / 双回复）:**  
OPEN deadline 30s 到 → Session **已发 CHANNEL_OPEN_FAILURE 并释放 opening slot**；spawn 中任务稍后仍 `reply.accept()` → 又一次 unbounded 回复入队。  
**无 generation 时（即便 ChannelId 尚未复用）:**  
- 迟到 accept 对 **已失败/已拆除的旧 channel** 再 finalize → 双 reply、ghost 状态、错误 handler 回调，或对已不存在 id 的 wire 包。  
- 现状 id 分配为单调递增（`session.rs:803-811` `last_channel_id += Wrapping(1)`，冲突则再加），**通常不会在刚释放后立刻复用同一 id**；不可断言「allocator 立即复用」。  
- **若** 未来改为 slot 表复用 id、或 `Wrapping<u32>` 回绕后撞上仍存活/刚打开的 channel，迟到 accept 会 **污染新 channel**（错绑 pending、错发 CONFIRM）。  
必须 **opening generation**：accept/reject 令牌绑定 `(id, gen)`，迟到令牌丢弃——与是否立即复用 id 无关。

**失败场景 3（abort 丢 handler）:**  
若超时 `abort()` 掉持有 `Handler` 所有权的任务，**连接级 Handler 状态机被抽走**，后续任意回调无法运行 → 连接必须拆且不可恢复。v2 未选「超时后仍保留 Handler 所有权、仅 ignore 结果」还是「超时即拆连」。

**失败场景 4（CPU 不让出 ≠ 进程隔离）:**  
`handler-block` 用例写「连接与进程隔离」。在同一 tokio worker 上 `spawn` 的回调若 **忙等/重 CPU 不 await**，同线程上的 deadline timer **得不到 poll** → 连接级 deadline 失效；其它连接若同 runtime 亦被饿死。隔离需要 **独立线程/进程或强制 yield 的协作契约**，不是 `tokio::spawn` 一词。

**规格必须补（否则保持 BLOCKER）:**  
- **HandlerExecutor（单拥有者）**：唯一可 `&mut Handler` 的任务；Session 只发 `Invoke{gen, op}` / 收 `Result{gen, …}`。  
- Session 可变 API 经 **有界命令 facade**（禁止回调直接 `&mut Session` 跨任务），或规定回调只返回「意图」由 Session 应用。  
- 串行默认；可选 per-channel 并行须证明不共享 `&mut self` 字段。  
- 有界 in-flight；满则反压 Reader/ctrl（try_push 策略）。  
- timeout：结果 `(id, gen)` 校验；**late accept 丢弃**（防双 reply/ghost；不依赖 id 立刻复用）；abort 策略显式（保留 owner vs 拆连）。  
- CPU 隔离目标降级为「有界 in-flight + 可观测」或要求 blocking pool/独立线程。

#### A.2.6 mpsc 条数 / slot /「permit 前所有权」/ G4 — **[BLOCKER]**

附录 A 把本项标成 v2 已关闭。**复审否定。**

**代码事实（保持签名时 permit-first 不成立）:**

```164:169:russh/src/server/session.rs
    pub async fn data(
        &self,
        id: ChannelId,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        self.send_acked(id, None, data.into()).await
```

`data.into()` 在 **await 任何队列/permit 之前** 已构造 `Bytes`。`Channel::data_bytes` 同样 `data.into()` 后进入 `send_bytes`（`channels/mod.rs:326-327`）。async future 状态机捕获该 `Bytes` 后，可在窗口/permit 上挂起。

**失败场景（内存路径）:**  
1. 攻击者/误用方创建 N 个 task，各 `Handle::data(Bytes::from(vec![0u8; 512<<20]))`。  
2. 每 future 在首行 `into()` 后持有 512 MiB；然后卡在 mpsc/permit。  
3. 即使 `channel_out_cap=2MiB` 且 permit 在 Session 内，**外部已驻留 N×512MiB**。  
4. §4.4「显式排除调用者尚未移交所有权的内存，由 byte permit 在移交前限制」——在 **保持现签名** 时自相矛盾：所有权在 API 边界已进入 future。

opening slot 全生命周期（§4.1）可挡「无限 OPEN handle」结构体增殖，**挡不住大 Bytes future 阵列**。

**要求（关闭本 BLOCKER 的最小集）:**  
- **单次 payload 硬上限**（配置，超则同步 Err，不入 future 挂起路径）；且/或  
- **reservation-first API**（先 `reserve(n) -> Permit`，再 `commit(permit, Bytes)`；旧签名改为内部先检查 `data.as_ref().len()` 同步拒绝超限）；且/或  
- **诚实缩小 G4**：明确「G4 不含已进入调用方 async future 的 payload；仅含 core 已接管字节」，并另列 DoS 建议。  
不得再写「permit 在收下所有权前取得」而不改签名/同步预检。

---

## B. v2 新机制的新风险

### B.1 supervisor 状态机 — **[OK] 骨架 / [BLOCKER] 与写看门狗耦合**

Running→Cancelling(reason)→Aborting→Joined、首 reason 胜、总 grace、abort+drop half：正确。  
但 S1 若用未定义的 write_progress 武装 Cancelling，会把 **误拆** 焊进状态机。supervisor 其它 deadline（rekey/handshake）可先落地；write_progress 保持未实现直至 A.2.1 补丁。

### B.2 byte permit — **[BLOCKER] 与 G4 / 签名**

见 A.2.6。另须：

- **固定获取序:** 建议 `global → per-channel`（或反序，全局唯一），禁止实现分叉。  
- **归还 exactly-once:** 成功上线 partial、失败、cancel、channel close、teardown、permit Drop 必须同一路径 `release`；双放会放大配额，漏放会永久饿死。  
- 不要把活性只押在「AB-BA 死锁」故事上：更硬的是 **签名导致的预持有内存** 与 **teardown 归还**。

### B.3 全局预算 — **[BLOCKER]**

v2 §4.4 写 global budget「在 permit 层联动」，permit 叙述绑定 **outbound `data().await`**。  

**失败场景（inbound 合法填窗打爆进程）:**  
- 默认建议 `w_in=1MiB`、`max_channels=128`、100 连接。  
- 每 channel 初始授窗 1MiB（或 OPEN 时授窗），对端合法打满。  
- **outbound semaphore 占用可为 0**（无人调用 data）。  
- 进程 RSS ≈ 100×128×1MiB = **12.8 GiB** 仅入站 payload，外加队列元数据。  
G4「单连接闭式 + 全局预算」在只有 outbound 联动时 **不构成抗 DoS**。

**须覆盖:**  
- 初始入站窗口 / 后续 ADJUST **前** 预留 global inbound credit；  
- opening reserve（pending open 字段与预占队列）；  
- 消费、channel close、连接 teardown 的 **退款**；  
- 预算作用域（进程 / 监听器 / 多 server 实例）写死。  
否则删掉「全局预算构成 G4」的断言，改称 best-effort。

**附带 [MAJOR]（次要，勿盖过 inbound 主洞）:**  
§4.4 每连接 **ctrl 队列 2 MiB + writer control 2 MiB** 为固定协议预算，正文未说明其计入 global budget，亦无 **global connection cap**。  
**失败场景:** 攻击者开 1000 条连接，每连仅灌满 ctrl/writer-control 固定预算、几乎不占 outbound permit → 约 \(1000 \times 4\,\mathrm{MiB} \approx 4\,\mathrm{GiB}\) 线性放大，仍可在「单连接闭式成立」下打满主机。global 方案须含连接数上限或把固定协议预算纳入同一会计。

### B.4 ready-set 1-packet 轮转 + 首包 boost — **[MAJOR] boost 可永久饿死老 bulk**

1-packet ready-set 本身合理。  

**[MAJOR] first-byte boost 无额度:**  
§4.1「新激活 channel 的首个 packet 给一次 latency boost」。`max_channels` 只界 **瞬时并发**，不界 **时间轴上的 open 频率**。  
**失败场景:**  
攻击者（或忙碌客户端）循环：`OPEN → accept → 塞 1 个小 DATA（吃 boost）→ CLOSE/再 OPEN`（slot 释放后立即新开，并发始终 ≤ max_channels）。每个「新激活」都插队优先轮次；若 boost 路径 **总优先于** 普通 ready-set 轮转且无 burst/每轮 boost 配额，则 **长期存活的大 bulk channel 可永久得不到 seal quantum** → 违反 G3「大流不饿死小流」的对偶（小流/新流饿死大流），连接仍「工作」故 G1 不拆。  
**要求:** boost 也有 **burst/每调度轮次额度**（例如每 N 个普通 quantum 最多 1 次 boost，或 boost 仅一次性且计入 fairness 债）；§5 scheduler 对抗测试断言 **老 bulk 最小服务率 > 0**。

**与 OPEN_CONFIRM 交互:** 若 Confirmed 前可 boost，会放大 B.6 乱序（未确认 channel 的 DATA 优先上线）。

### B.5 burst cap 16 — **[OK] / 放大 OPEN 竞态**

普通 control 让 bulk：正确。  
**与 OPEN_CONFIRM 交互:** CONFIRM 在 control 车道、DATA 在 bulk 时，burst 让出 quantum 使 DATA 更早被调度——**更依赖 Writer 侧 Confirmed 状态，而非 lane 口头约定**。

### B.6 CLOSE 双路径停止边 + OPEN_CONFIRM — **[MAJOR] CLOSE 跨任务未关 / [BLOCKER] OPEN_CONFIRM**

#### B.6.1 peer CLOSE 双路径 — **[MAJOR] 停止边未规格化**

v2 §4.1：Reader 收 peer CLOSE → **wire-lifecycle 事件直发 Session**（立即回 CLOSE、停出站、丢弃出站积压）+ app-delivery marker 仍在队列尾。意图对齐现状「应用停消费不挡 mandatory close reply」（`server/encrypted.rs:1140-1166`）。

**原始 app 阻塞问题：意图可视为关闭。**  
**跨任务「何时停止 seal 该 channel」：未关。**

**失败场景（收到 CLOSE 后仍上线 DATA）:**

```
t0  Peer → CHANNEL_CLOSE(c)          Reader 解析
t1  Reader → Session: WireClose(c, gen=G)     （直发）
t2  Reader → app_q(c): CloseMarker(G)         （队尾）
t3  同时 Writer ready-set 仍含 c，队列有 DATA
    Writer seal(CHANNEL_DATA(c)) …            （尚未收到 Stop）
t4  Session 处理 WireClose → 发 Writer: StopDiscard(c,G)
t5  Writer 才标记 closing；但 t3 已 seal 的密文在 staging
t6  Writer 继续 poll_write → 对端在「我已发 CLOSE」之后仍收到 DATA
```

已 seal staging **不可对中间任意字节「截断」**（SSH 包边界 + 已分配 seqn）；只能整包发完或在 **尚未开始 seal 的队列项** 上丢弃。v2 写了 discard pending，未写：

1. Writer 可见的 **同 generation closing tombstone / 高优先控制事件**（不得排在普通 bulk 后被饿死）；  
2. **每次 seal 前** 校验 `channel_gen` 未 closing；  
3. **partial：** 正在 seal 的一包可完成；**未开始** 的 staging/queue 项必须可丢；  
4. **reply CLOSE 与本地 pending CLOSE 仲裁**（本端已排队的应用 CLOSE、peer CLOSE 回执、双 CLOSE 去重）的 wire 序与 generation。

缺以上时，close-with-backlog 镜像用例（对端 CLOSE + 本端积压）在三任务下会 **系统性地在 CLOSE 后漏 DATA**，或对端已关 channel 仍收数据。

#### B.6.2 OPEN_CONFIRMATION — **[BLOCKER] 报文序列**

```
Peer:  CHANNEL_OPEN(direct-tcpip, id=c)
Sess:  slot 预占; enqueue Handler
App:   reply.accept().await     // 仅 unbounded 入 open_reply 队列 (lib_inner.rs:597-599)
App:   channel.data_bytes(payload).await   // 经另一路径进 Writer bulk
Writer 调度:
  - bulk 先到或 CONFIRM 仍在 Session 未 finalize:
      可能 seal(CHANNEL_DATA) 而从未 seal(CHANNEL_OPEN_CONFIRMATION)
  - 或 finalize 后 CONFIRM 入 control、DATA 入 bulk;
      burst cap 让出后 DATA 与 CONFIRM 在 Writer 内乱序
Peer:  先收 DATA 或无 CONFIRM 的 DATA → 协议违例 / 实现相关丢弃
```

§4.5「数据必然在 confirm 之后提交」被证伪。  
**要求:** Writer `Opening → Confirmed`；**仅 Confirmed 后进入 ready-set**；OPEN_CONFIRMATION 为出站 fence 头；accept 完成 ≠ Confirmed。

### B.7 kex 专队容量 16 — **[MAJOR] 「永不满」与枚举定容论证不严谨**

§4.3 环检查写专队「按枚举定容，**永不满**」。该证明不成立，但原因须写严谨：

- Writer 在 socket write 阻塞时，**仍可能**以 cancel-safe 方式在同一 `select!` 中 poll kex 队列（正文未禁止）；故 **不能**断言「write 卡住 ⇒ 必然不 drain 专队」。  
- 真正缺口是：**正文未规定** 在 intake/staging 高水位、或 `poll_write` Pending 时，Writer 是否 **必须继续** drain kex 专队 / 是否允许 kex 入队反压 Session。实现分叉会直接决定 rekey 能否推进。  
- 「按消息**种类**枚举」≠「每种最多一条」：可出现重复 KEXINIT、并发异常路径上多个终止原因（DISCONNECT + strict 违例 + 超时拆除）、Install 重试等，**条数**可超过种类数。  
- **失败场景:** Session 向容量 16 的专队放入第 17 条（例：风暴下重复控制 + 多个终止原因）。若 `await` push → Session 阻塞，kex 状态机与「入队即完成」假设（A.2.2）交叉恶化；若未定义 try_push 失败语义 → 静默丢命令或死等。  
**要求:** 专队 **try_push**；满 → 明确 Cancelling 或合并/去重策略；删「永不满」；用 **单飞行 kex + 有界重试** 证明峰值，而非种类枚举。

### B.8 入站 WINDOW_ADJUST 旁路 — **[MAJOR] 规格冲突**

v2 §4.1：channel-scoped（含 ADJUST）→ **per-channel 入站全序 app 队列**。  
v2 §4.1/4.5：peer 窗口权威在 Writer；credit 到账即唤醒 ready-set。

**失败场景（等待环 / 吞吐塌方）:**  
1. Peer 发送 `DATA×K` 填满 app 队列（应用慢读）；  
2. Peer 再发 `WINDOW_ADJUST(+W)` 授予本端出站窗口；  
3. ADJUST 排在 app 队列尾，**在应用 recv 完 K 条 DATA 前不生效**；  
4. Writer 认为 window=0，出站（含其它方向代理流量）停；  
5. 应用可能正阻塞在 `data().await` 等对端读 —— 若对端也在等本端出站，形成 **跨方向类死锁/假活**（各实现处理不同，但 G2/G3 已破）。

现状：run loop 读到 ADJUST **立即**改 `recipient_window_size`（`server/encrypted.rs:1263+`）。  

**结论:** 保留「channel 报文对 Handler/app 的可见序」可以，但 **窗口副作用必须在 Reader 解析点同步通知 Writer**（旁路），与「全部进 app 队列再生效」不可兼容。这是 v2 跨任务次序假设的直接冲突，不是实现细节。

### B.9 策略表 §4.6 — **[OK] 主体 / [MAJOR] 缺行**

缺：write_progress 武装谓词；Handler 超时/late token；inbound ADJUST 旁路；OPEN 未 Confirmed 的 data；global inbound 预算；payload 同步上限。

### B.10 切片 S0–S7 — **[OK] 切分 / [BLOCKER] S1 完成门 NO-GO**

- **S0 [OK] GO:** harness + 事故复刻基线（允许对现架构红）。  
- **S1 [BLOCKER] NO-GO**（按 v2 当前完成门）: 「write-stall / talk-no-read / rekey-stall 三用例绿」隐含可编码且正确的 write_progress；谓词未关则不可宣称 S1 完成。  
- **允许的工程活动:** 仅做 **非 watchdog** 骨架（token、abort、rekey/handshake deadline、总 grace）——这是预研/铺路，**不等于 S1 完成**，也不得用三用例全绿验收。

### B.11 跨任务消息次序（综合）

| 路径 | 风险 |
|---|---|
| accept 队列 vs data 队列 | OPEN_CONFIRM 与 DATA 乱序（B.6.2） |
| peer CLOSE → Session → Writer | CLOSE 后仍 seal DATA（B.6.1） |
| Install 命令 vs ACK | deadline 提前注销（A.2.2） |
| 入站 ADJUST → app 队列 | 出站窗口延迟（B.8） |
| Handler 回流 vs 已 reject | late accept 双 reply / 未来 id 污染（A.2.5） |
| kex 专队满 + 未定义 drain 策略 | 第 17 条 try_push/await 语义（B.7） |
| global/local permit | 归还 exactly-once；签名预持有内存（B.2） |
| 首包 boost 无额度 | 持续 open 饿死老 bulk（B.4） |

---

## C. 可开工判定

### 结论

| 阶段 | 判定 |
|---|---|
| **S0** harness + 事故复刻基线（允许红） | **[OK] GO** |
| **S1**（v2 完成门：write-stall / talk-no-read / rekey-stall 绿） | **[BLOCKER] NO-GO** |
| S1 仅非 watchdog 骨架（token / abort / rekey·handshake deadline / grace） | 工程上可做，**≠ S1 完成**，不得标切片验收通过 |
| **S2+** | **[BLOCKER]**（P0 未关前不可进入；关闭并写入正文后再评估） |

**总裁决: [BLOCKER] 条件 NO-GO**（S0 **[OK] GO**；S1 按当前完成门 **[BLOCKER] NO-GO**）。  
v2 文首「已关闭全部 BLOCKER」不成立。仍为 **[BLOCKER]** 的主项：写看门狗谓词（wire-eligible / idle→armed / 原子快照 / abort 契约）、NEWKEYS install-ACK、HandlerExecutor、G4/permit 与 inbound global、OPEN_CONFIRM Writer fence。另有多项 **[MAJOR]**（CLOSE 停止边、boost 公平、kex 专队、Rekey 计数生命周期、固定协议预算跨连接等）。

### 最小缺口清单（优先级）

#### P0（挡 S1 完成门 / 挡「可编码 watchdog 与核心正确性」）

1. **写看门狗谓词（仅活性正确性，不含吞吐 SLO）**  
   wire-eligible ≠ peer-window=0；idle→armed；原子快照；abort/cancel-safe。S1 **完成门前不得编码** watchdog 验收。

2. **NEWKEYS actual-install ACK + kex_generation**  
   双所有者 ACK 后才 Idle/注销 deadline；旧/新密文允许 FIFO 共存。

3. **HandlerExecutor 单拥有者**  
   有界 in-flight；结果 `(id, gen)`；late accept 丢弃（不依赖 id 立即复用）；timeout 后 owner 去留；CPU 隔离目标诚实化。

4. **G4：同步 payload 上限 / reservation-first / 或缩小口径**  
5. **global budget：inbound grant + opening + 退款 + 作用域**（主）；连接 cap / 固定 2+2 MiB 纳入会计（次）。  
6. **Writer OPEN confirmation fence**

#### P1（S2/S3 前）

7. **peer CLOSE：Writer 同 gen tombstone、seal 前校验、未开始包可丢、reply/pending CLOSE 仲裁**（B.6.1）。  
8. 入站 WINDOW_ADJUST 解析点旁路。  
9. RekeyPolicy：per-key-epoch；含 KEX 包；合并触发；**install ACK 后归零**。  
10. boost 额度 + 老 bulk 最小服务率测试；出站 REQUEST fence；kex 专队 try_push 语义；permit 获取序 + exactly-once 归还；§4.6 补行。

#### P2

11. 参数可配；GEX 消息峰值表；global 默认静态字节。

---

## 附录 R：代码核验摘录

| 断言 | 证据 |
|---|---|
| Handler 需 `&mut self` + 常 `&mut Session` | `server/mod.rs`：`data`/:478+、`channel_open_*`/:377+、`auth_*` 等 |
| accept 仅入队、不阻塞 | `lib_inner.rs:597-599` `try_send_reply`；注释 :565-567 禁止 accept 前写 channel |
| ChannelId 单调递增（非立即复用） | `session.rs:803-811` `last_channel_id += Wrapping(1)` |
| `Handle::data` 先 `into()` 再 await | `server/session.rs:164-169` → `send_acked` 持有 `Bytes` |
| `Channel::data_bytes` 同 | `channels/mod.rs:326-327` |
| 入站 ADJUST 现状立即入账 | `server/encrypted.rs:1263+` |
| rekey 无 read 触发 | `session.rs:798-800` |
| chacha 用 seqn | `cipher/chacha20poly1305.rs:130-140` |
| keepalive P7 | `server/mod.rs:140`；`server/session.rs:1161-1167` |
| CLOSE 双路径现状（单任务内闭合） | `server/encrypted.rs:1140-1166` |
| 零字节/EOF 护栏 | `pending_inbound.rs:108-113,154-181` |

---

## 一句话裁决

**[BLOCKER] 条件 NO-GO**（S0 **[OK] GO**；S1 **[BLOCKER] NO-GO**；非 watchdog 骨架 ≠ 完成）。写看门狗只卡 wire-eligible / idle→armed / 原子竞态 / abort，不把慢进度当活性缺陷；CLOSE 双路径须补 Writer 停止边；另卡 NEWKEYS ACK、HandlerExecutor、G4/global、OPEN_CONFIRM fence。
