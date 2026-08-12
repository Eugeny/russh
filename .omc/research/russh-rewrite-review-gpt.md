# russh Session Loop 全量重构方案评审

## 总评

**结论：当前 DRAFT v1 不可进入 Phase A，实现门禁应为 NO-GO。** 拆成 Reader/Session/Writer 三个所有权域是正确方向，但方案尚未把“任务拆分”提升成可证明的协议状态机。最大的一颗雷在 §4.3：它把 `socket write` 的活性归因于 keepalive，实际上 Writer 一旦阻塞在写 socket，keepalive 也只能排在同一个 Writer 后面；若对端停止读、却继续向我方发送合法流量，读侧 inactivity 还会持续被刷新，连接可以永久存活而出站永久不动。这正是一个未被 deadline 覆盖的等待环，而不是实现细节。

此外还有三个独立的开工阻断项：control/bulk 两队列会让 `EOF/CLOSE` 越过同 channel 已排队的 DATA；NEWKEYS 后的方向性密钥、压缩上下文和 strict-kex seqn 切换没有原子交接协议；“1 TiB byte limit”没有 packet limit，无法防止小包流量令 `u32` seqn 回绕并让 chacha20-poly1305 重用序号。三者任一都足以否决当前方案。

建议保留三任务方向，但先补一份可执行的“传输 epoch + 因果顺序 + supervisor”契约，再分可独立回归的纵向切片实施。不能以当前 §4.1 的框图直接开写。

## 1. 正确性

- **[BLOCKER] control 严格优先破坏同 channel 的报文因果顺序。** 失败场景：relay 依次调用 `data(2 MiB).await`、`eof().await`；DATA 留在 bulk queue，而 EOF 进入 control lane。Writer 按“control 永远优先”先发 EOF，再发 DATA。对端已经把 EOF 解释为“本方向不会再有数据”，随后 DATA 至少是协议次序错误，部分实现会丢弃或断连。`CLOSE`、`CHANNEL_SUCCESS/FAILURE` 与它们所响应的请求也有同类越序风险。入站把 DATA/EOF/CLOSE 放同一队列并不能修复出站。必须给每 channel 一个单调发送序号/causal fence：KEX/DISCONNECT 可抢占，普通 control 只有在它之前的同 channel bulk 已封包后才能发送。

- **[BLOCKER] NEWKEYS 不是“双向一起完成后换钥”，而是两个独立方向的精确边界。** [RFC 4253 §7.3](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.3) 要求 NEWKEYS 本包用旧算法，发送后的下一包立即用新发送算法；收到对端 NEWKEYS 后，下一入站包立即用新接收算法。当前设计只有 `KexDone { new_seal_key }` 和“到双向 NEWKEYS 生效止”的总状态，未定义以下原子动作：

  1. Writer 用旧 epoch 封装 NEWKEYS；
  2. 仅在该包完成封装后安装 `(seal key, MAC, compressor, outbound seqn policy)`；
  3. Reader 用旧 epoch 打开 NEWKEYS；
  4. 在读取下一包前安装 `(open key, MAC, decompressor, inbound seqn policy)`。

  具体反例：服务端已发 NEWKEYS，对端尚未发 NEWKEYS，此时 rekey timeout 要发送 DISCONNECT。如果 Writer 仍等“双向完成”才换发送密钥，DISCONNECT 会用旧钥，对端已经依据服务端 NEWKEYS 切换接收钥，无法解密；若 Writer 提前换，则 NEWKEYS 本身无法解密。应设计方向性 `SendNewKeysAndInstall(epoch)` 与 `InstallAfterReceivedNewKeys(epoch)`，而不是一个笼统的 `KexDone`。

- **[MAJOR] 压缩状态没有进入三任务所有权模型。** RFC 4253 要求每个方向的 stateful compression 在每次 KEX 后重置；当前代码确实分别在 `CommonSession::newkeys` 中重建 compressor/decompressor（`russh/src/session.rs:131-147`）。方案只写 Reader 持 opening cipher、Writer 持 sealing cipher，没有说明 compressor/decompressor 归属和切换时刻。失败场景：双方继续协商 `zlib`，Writer 换了密钥却沿用旧 deflate history，客户端在 NEWKEYS 后重置 inflater，第一包即解压失败。压缩必须与方向性 cipher/MAC/seqn 作为同一个不可拆的 epoch 安装。

- **[MAJOR] 现有压缩 rekey 代码本身还有迁移陷阱。** `CommonSession::newkeys` 重置了现存 `enc.client_compression/server_compression` 的 context，却没有先把它们更新为 `newkeys.names` 新协商的算法。失败场景：rekey 从 `none` 改成 `zlib`（RFC 允许换算法），cipher/MAC 已换而 compressor 仍为 none，对端则已启用 zlib，下一包失败。新 core 不能机械搬运这段逻辑；epoch 必须携带新算法枚举并安装后初始化 context。

- **[MAJOR] “control lane 可插到已排 128 KiB bulk 前”在 TCP 上不成立。** 已经封装进 `PacketWriter`、甚至交给内核 sndbuf 的旧 epoch 字节不能被后来的 KEXINIT 越过。失败场景：Writer 正在对 128 KiB ciphertext 做 `write_all`，TCP window 归零；Session 发来 `KexStarted`，单 Writer 任务无法 poll 控制队列，更不可能把 KEXINIT 插入已写前缀。设计必须限定 Writer 每次只做有界的一次 `poll_write`/一个 packet，并把“尚未序列化的 bulk 可抢占”与“已序列化字节只能先排空”分开陈述。

- **[MAJOR] channel/window 状态的唯一所有者没有闭合。** Writer 持 peer window，Session 却“校验 WINDOW_ADJUST 后转发”。若 Session 没有实时 window 值，它只能校验 channel 是否存在，不能校验 `old + amount <= 2^32-1`。两个连续 ADJUST 各自相对旧快照合法，合并后可溢出。加法和 DATA 扣减必须都在 Writer 内原子 checked；Session 只做语法和生命周期验证。Reader 侧的我方 receive window 也必须有唯一记账者，否则 Session 授窗与 Reader 扣窗之间会出现同类竞态。

- **[BLOCKER] 入站 CLOSE 的双重语义在框图中丢失。** §4.1 让 Reader 把 CLOSE 只放入 per-channel 入站队列以保持应用可见顺序，但收到 CLOSE 还要求连接层立即停止该 channel 出站、丢弃不再可交付的数据并回 CLOSE。失败场景：应用停止消费且队列前有 DATA，CLOSE 永远排不到应用；若 Session 不另获通知，mandatory close reply 永远不发。当前代码在 `server/encrypted.rs:1140-1166` 是“立即回 wire CLOSE、应用 CLOSE 仍在 DATA 后投递”两条动作。新设计也必须把 wire-lifecycle event 与 app-delivery marker 分开，并用同一 generation 关联。

- **[OK] Reader/Writer 分别独占 opening/sealing cipher 与方向 seqn 是正确的基础。** 只要上述 epoch handoff 和任务监督明确，这比在共享 Session 中交换 cipher 更容易证明。

## 2. 活性论证完备性

- **[BLOCKER] `WriterTask | socket write | keepalive` 这一行是错误证明。** 失败场景：客户端 TCP 接收窗归零，但仍每秒向服务端发送 IGNORE、WINDOW_ADJUST 或另一方向的 DATA。Writer 卡在 bulk 的 `write().await`；keepalive request 需要同一 Writer 才能上 wire，无法“解锁 Writer”；读侧持续有包，inactivity 又不会触发。zfc 当前还显式设置 `inactivity_timeout: None`（`../zfc/zf-worker/src/protocol/inbound/ssh/mod.rs:127-128`），因此这个路径在真实上层配置中确实无界。必须新增独立于 keepalive 的 `write_progress_deadline`，由 root supervisor 观察“最后成功写入字节时间”；超时直接取消并 drop 两个 socket half，DISCONNECT 只能 best-effort，不能是退出前提。

- **[BLOCKER] SessionTask 的 Handler 等待没有 deadline，`debug_assert` 计时不构成活性保证。** 失败场景：恶意客户端发 CHANNEL_OPEN，Handler 卡在下游 `mpsc::send().await` 或外部 ACL/DNS；Session 停止消费 reader ctrl，Reader 随后在 ctrl push 上停住，KEX timer 也因 Session 正在 await callback 而不能执行。zfc 已经为一个具体的 `sub_tx.send` 手工加 timeout（`server.rs:250-267`），恰好证明“快速返回契约”不是架构保证。所有 Handler await（含 auth、channel request、`lookup_dh_gex_group` 和 kex 回调）要么由 `timeout_at` 包裹并定义超时语义，要么搬到可取消 worker；只在返回后报警没有用。

- **[BLOCKER] rekey deadline 放在 SessionTask 内不足以终止整个连接。** 失败场景：deadline 到期时 writer control lane 已满且 Writer 卡 socket；Session 若 await enqueue DISCONNECT 也会卡。即使 Session 自己返回 Err，Reader/Writer 仍各自持有 socket half，TCP 不会关闭。需要一个不依赖三任务任一队列的 root supervisor：任一 child Err/panic、rekey timer 或 write-progress timer触发时先广播 cancellation，等待一个总 teardown grace，随后 abort 全部 child 并确保两个 half 被 drop。

- **[BLOCKER] 预留 8 个 KEX 槽只消掉一个队列环，没有消掉 I/O 环。** Session→Writer 的 KexDone 可入预留槽，但 Writer 仍可能等 socket；Session deadline 又只能要求 Writer 发 DISCONNECT。环仍是 `Writer write → peer read` 与 `peer waits for our KEX packet → Writer write`。正确的终点是 deadline 后从 supervisor 强制关闭 socket，不是保证 KexDone 可排队。

- **[MAJOR] 表中遗漏 outbound request/oneshot 的无界等待。** 当前 API 有 `wait_channel_confirmation`（`server/session.rs:454-488`）、tcpip-forward/cancel reply oneshot（`262-299`）、ping/global request队列，以及 close handshake。失败场景：对端继续回复 keepalive但永不回复服务端发起的 CHANNEL_OPEN；调用者的 `channel_open_*().await` 永久等待，连接不会因 inactivity 断开。新架构要给 open confirmation、want-reply global/channel request、close ack 明确 deadline，连接 teardown 时必须 drop 所有 sender 唤醒 awaiter。

- **[MAJOR] 握手前等待不在表内。** SSH identification 的 write/read、初始 KEX、auth rejection sleep、任务 spawn/join 和最终 shutdown/flush 都在“三任务 steady state”之外。失败场景：`inactivity_timeout=None` 时客户端只发半条 banner 后沉默，Reader 尚未进入表中状态而永久等待。G1 若真覆盖“半途沉默”，必须定义 handshake deadline；teardown 应只有一个总 deadline，不能三个任务各自串行等 5 秒。

- **[MAJOR] 普通 control 的“永远优先”允许永久 bulk starvation。** 失败场景：客户端持续发送合法的 GLOBAL_REQUEST want-reply 或大量 OPEN（到 cap 后仍需失败回复），Session 持续生产 control，Writer 的 bulk 分支永远没有机会。连接仍在工作，但所有代理流永久停滞，违反 G2/G3。KEX/NEWKEYS/DISCONNECT 可以绝对优先；普通 control 应采用有 burst budget 的高优先级，例如最多连续 16 包后若有可发 bulk 至少服务一个 quantum。

- **[MINOR] `relay recv(empty)` 被称为“无需界”，与 I4“一切等待有 deadline”字面冲突。** 可以把它定义为“无 work 的稳定阻塞，不是 progress wait”，但应在不变量中正式区分 idle wait 和持有资源/债务的 progress wait，否则表无法机械审计。

## 3. 有界性

- **[BLOCKER] §4.4 只有消息数 cap，没有证明 byte cap。** `mpsc(cap=...)` 限的是 item 数；`Bytes`、String、channel-open 字段和应用传入的 `data()` 可以大小不同。失败场景：同一 channel 上多个 task 各调用一次 `data(512 MiB).await`；即使 writer queue 只有一个槽，其余 future 已经持有参数 buffer，所谓 `out_cap=2 MiB` 并不约束这些 bytes。必须在接收 payload 所有权前取得 byte semaphore permit，限制单次 payload，并说明 blocked caller 持有的外部内存是否在 G4 口径内。

- **[BLOCKER] `max_channels` 没有覆盖 opening channel。** 失败场景：客户端连续发 OPEN，Handler 把 `ChannelOpenHandle` 存起来不 accept/reject；这些 channel 尚未进入 active count，却各自持有 PendingChannelOpen、ChannelRef、字段 String 和队列。256 active cap 永远不触发，内存随 OPEN 数增长。必须在解析 OPEN 时就预占 `opening + active + closing <= max_channels` 的 slot，给 open decision deadline，并在 handle drop/timeout/reject 时归还。

- **[MAJOR] “kex 非 KEX 暂存量 O(channel 数)”是错误的。** 反例是同一 channel 的任意多个 REQUEST/WINDOW_ADJUST、任意多个 GLOBAL_REQUEST、DEBUG/IGNORE，以及尚未收到对端 KEXINIT 前合法在途的 DATA；数量不受 channel 数约束。固定 256 槽只把内存变成有界，却会把 Reader 卡住并可能让对端 KEXINIT 排在 backlog 后直到本地 timeout。应按 KEX phase 处理在途包（见第 5 节），对确需延迟的“出站回复”使用 byte budget，而不是宣称 O(Nchannel)。

- **[MAJOR] control “均为小报文”不成立。** 当前 transport 接收上限约 256 KiB（`cipher/mod.rs:354-368`），GLOBAL_REQUEST、CHANNEL_OPEN、auth 和 DEBUG 都可携带接近 packet cap 的字符串；应用侧生成的 description/request String 还未见 byte 限制。两个 256 槽 ctrl queue 最坏可各占约 64 MiB，而不是模糊的“256×小报文”。必须给 control ingress、deferred replies、KEX transcript 和 app-generated control 分别设 byte cap。

- **[MAJOR] 闭式漏算生命周期重叠和 staging。** 至少遗漏：read ciphertext scratch、decompressed packet、KEXINIT/exchange/hash/key material、plaintext queue、encrypted staging、压缩输出、Tokio channel node/`Bytes` 元数据、socket buffers、pending open、outstanding oneshot/global request、teardown 时三任务同时保留的队列。失败场景：重 key 的瞬间旧 ciphertext staging 未排空，新 epoch/压缩器已经生成，同时每 channel 双向队列满，实际驻留明显超过公式。公式应写成“payload budget + fixed protocol budget + transient epoch budget + allocator overhead bound”，并标明是否排除内核 socket buffer和调用者内存。

- **[MAJOR] 384 MiB/连接虽可计算，但不是可接受的默认防 DoS。** 100 个连接即可仅按 payload cap 占约 38.4 GiB。G4 还需要进程级/global semaphore 与 per-connection 配额联动；否则单连接闭式成立仍会被 open flood 跨连接击穿。

- **[OK] 将 receive-window grant 改为“应用实际消费 N 字节后返还 N”可以让合规对端的入站 payload 上界接近 advertised window。** 但 AsyncRead partial read 必须按实际返回给调用者的字节记账，不能在整条 `ChannelMsg` 从 mpsc dequeue 时一次性返窗；handler-only 模式也要定义谁发 consumption ack。

## 4. 性能设计

- **[MAJOR] 64 KiB DRR quantum 和普通 control 绝对优先都没有性能目标支撑。** 方案自己算出 32 流时约 16 ms 的单轮排队，这还没算 cipher、socket stall 和 control burst。对网页首包/小对象，16 ms 已足以显著抬高 p99。具体反例：31 条持续大流总有 backlog，第 32 条刚入队 1 KiB；它至少等前面约 2 MiB。建议 active-list O(1) DRR，基础 quantum 取 `min(local_packet_cap, 16~32 KiB)`，新激活/短队列给一个 packet 的 latency boost；最终参数由 p99 与 CPU/吞吐曲线决定，而不是先固定 64 KiB。

- **[MAJOR] “切队头天然聚包”是错误的。** 若应用连续 enqueue 100 个 1 KiB `Bytes`，只切队头会生成 100 个小 SSH DATA 包；它不会自动跨 queue entries 合并。Writer 应在不等待新数据的前提下，把当前已就绪、同 channel、同 extended-data 类型的相邻 slices gather 到一个 `max_packet` payload；EOF/CLOSE fence 截止聚合。否则小 chunk relay 的 packet/AEAD/syscall 开销会很高。

- **[MAJOR] 只取 `min(peer_maxpacket, window)` 可能生成本地或对端实现无法接收的大 transport packet。** 对端广告 1 MiB maxpacket、queue 有 1 MiB 时，方案会发 1 MiB DATA；RFC 4254 要求发送方还受自身 transport 上限约束，老 libssh2 等实现也常见较小 packet buffer。必须再取 `local_transport_payload_cap`，默认宜贴近 32 KiB，明确协商/识别后才扩大。

- **[MINOR] 真正可取的“零拷贝”空间有限。** 加密/压缩要求构造连续 packet，无法直接把上游 TCP buffer 零拷贝进内核。可做的是：队列持有 `Bytes` slice、不复制 backlog；无压缩时在可复用 `BytesMut` 中就地封包/加密；每次只消费 queue slice；批量 `write_vectored` 多个已封好的 packet（若 cipher buffer 布局允许）；压缩路径单独接受一次复制。不要把零拷贝作为架构卖点，应测 allocation/byte 和 copies/byte。

- **[OK] WINDOW_ADJUST 走高优先级、消费过半批量补窗、credit 到账即激活 channel，方向是对的。** 但 window 大小应由 bandwidth-delay product 与进程内存预算共同调参；固定 1/2 MiB 不是所有移动网络/高速链路的最优值。

建议的调度层次是：`KEX/NEWKEYS/DISCONNECT` 绝对优先；普通 control 有 burst cap；bulk 用带 causal fence 的 DRR；新 flow 有一次性短流 boost。这样同时保住协议边界、活性和小流延迟。

## 5. 协议合规与互操作

- **[BLOCKER] `mid-kex-data` 不能统一“处理/断连”。** [RFC 4253 §7.1](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.1) 明确：我方发 KEXINIT 后，在收到对端 KEXINIT 前，必须准备处理任意数量的、在对端收到我方 KEXINIT 前已在途的消息。故阶段规则应是：

  - 我方已发 KEXINIT、尚未收到对端 KEXINIT：可收到并正常处理上层消息，但我方不能把上层回复发在自己的 KEXINIT 与 NEWKEYS 之间；
  - 已收到对端 KEXINIT：其后到达的上层消息违反对端的发送限制（注意 TCP 顺序保证真正“在途于其 KEXINIT 前”的包会排在 KEXINIT 前）；
  - strict-kex 对初始 KEX 更严，只允许指定 KEX 消息，收到非 KEX 必须断连；strict 的 seqn reset 则初始和后续 KEX 都执行。参考 [strict-kex draft §5.2–5.3](https://datatracker.ietf.org/doc/html/draft-miller-sshm-strict-kex-00#section-5.2)。

  当前 256 槽 gate 会对“超过 256 个合法在途包后才到 KEXINIT”的实现自造超时，G6 与固定 deadline/固定内存三者存在必须明确接受的取舍。

- **[MAJOR] WINDOW overflow 断整条连接是比 RFC 更严的策略，`+1×maxpacket` 容差却没有协议依据。** [RFC 4254 §5.2](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.2) 允许接收方忽略窗口耗尽后的额外数据。失败场景：一个有 off-by-one bug 的移动端在某 channel 超 1 字节；方案若超过容差即断全 session，会连带所有健康代理流，违背 G2。更稳的默认是精确 checked accounting、记录 violation、丢弃 excess 并关闭该 channel；重复/大幅违规再断连接。若坚持 fail-closed，必须列为显式 policy 并用四类真实客户端验证，不能称为“任意 RFC 客户端容忍”。

- **[BLOCKER] 1 TiB byte threshold 没有 packet threshold，可能先发生 seqn 回绕。** 方案按 32 KiB 包估算约 137 TB，但攻击者/真实控制流可以使用最小 packet。以 16 字节 payload 为例，`2^32` 包只对应约 64 GiB payload，远小于 1 TiB；本仓库的 seqn 使用 `Wrapping<u32>`（`cipher/mod.rs:247-249, 341-343`），chacha20-poly1305 又直接把该 u32 传入每包 seal/open（`cipher/chacha20poly1305.rs:130-140`）。必须有每方向 packet counter hard limit，在回绕前 rekey；若对端不完成，rekey deadline 后断开。

- **[MAJOR] 1 TiB 对所有 cipher 一刀切没有密码学依据。** RFC 4253 推荐约 1 GiB/1h；OpenSSH 默认依 cipher 约 1–4 GiB（[OpenBSD sshd_config RekeyLimit](https://man.openbsd.org/sshd_config#RekeyLimit)）；Go x/crypto/ssh 也按 cipher 给 AES 约 64 GiB、其他 1 GiB（[源码 `rekeyBytes`](https://raw.githubusercontent.com/golang/crypto/master/ssh/common.go)）。AES-GCM 使用独立递增 nonce，chacha 使用 packet seqn，CTR+MAC 又受 block/认证界影响，不能用一句“均远在其上”替代推导。应按方向维护 `bytes + packets + elapsed` 三门限，取 cipher/MAC 安全上限、互操作建议和运营目标的最小值。

- **[MAJOR] “服务端不主动 rekey”通常不会直接导致互操作失败，但会把压力转给客户端发起的 rekey。** OpenSSH、Go、MINA 等常有自己的低阈值，长流仍会频繁触发 client-initiated rekey；这次事故的关键能力不是推迟到 1 TiB，而是任何时刻都能完成或超时拆连接。把 1 TiB 当主修复会掩盖真正门禁。

- **[MAJOR] 真实互操作证据目前为零。** `russh/tests/` 的 9 个回归文件都由 russh client/server 或内部 raw helper 驱动，没有 OpenSSH、libssh2、Go x/crypto/ssh、Apache MINA 的矩阵。失败场景包括：老实现只接收约 32 KiB transport packet、不同 NEWKEYS 先后顺序、strict-kex 标记差异和 simultaneous KEXINIT。G6 在跑完真实矩阵前不能标 [OK]。

- **[OK] kex 期间不发送 ADJUST/OPEN reply 等连接层消息的基本判断是对的。** 发送方从发出自己的 KEXINIT 到发出 NEWKEYS，只能发送 RFC 4253 §7.1 允许的 transport/KEX 范围；应“处理状态、延迟回复”，不是让 Reader 停止解析。

## 6. 可实施性

- **[BLOCKER] Phase A 同时替换读循环、写循环、KEX、channel 生命周期、窗口和 public API 语义，无法定位首个回归。** 失败场景：首次端到端测试在 rekey 后丢最后一段 DATA；可能来自 epoch handoff、EOF 越序、window 重复扣减、task cancel 或 client core，diff 没有可二分的绿色边界。应拆成始终可运行的纵向切片，而不是部署止血分支：

  1. 先落 root supervisor、write-progress deadline、统一 teardown，保持现有 packet/KEX 状态机；
  2. 抽出单 Writer owner，建立三优先级 lane、causal fence、方向性 epoch 命令，Reader/Session 暂仍同任务；
  3. 抽 Reader owner，完成 NEWKEYS/opening key/decompressor handoff，并上边界故障注入；
  4. 改为 consumption-based per-channel inbound byte queue，证明窗口上界后再删除 Scheme C；
  5. 加 DRR/聚包与性能调优；
  6. server 真机稳定后再决定是否把 client 接到共享 core。

- **[BLOCKER] §4.6 不能直接删除 `Msg::ChannelOpenReply` 特殊通路。** 现有 `ChannelOpenHandle::accept/reject` 是 async 签名但实际用 unbounded `send`，正是为了允许 Handler 在 Session loop 内调用而不自锁（`lib_inner.rs:553-613`）。失败场景：替换成容量 256 的普通 control send，Session 正在 await Handler；Handler await accept 入队时队列满，而唯一消费者就是当前 Session，形成立即自死锁。可替代方案是 Session-local reply slot/oneshot、`try_send` 加每个 opening 预留槽，或把 callback 与 actor mailbox 分离；没有替代前不能删。

- **[MAJOR] Scheme C 不能在“窗口即界”落地前先删。** 当前方案只有概念上的按字节消费确认，尚未处理 AsyncRead partial read、handler-only channel、应用 receiver drop、CLOSE 双路径。失败场景：仍按 message dequeue 返整包窗口，应用只读 1 字节却获整包 grant，队列可再次累积；删掉 pending cap 后失去最后保护。删除应是第 4 个切片的最后一步，并保留由 window 派生的 invariant assertion/violation counter。

- **[MAJOR] client 侧不应绑在 Phase A。** 对 `../zfc` 的检索只发现 `russh::server` 入站使用，没有 `russh::client` 使用点；因此 zfc 上线不依赖 client 同步重构。具体失败场景：共享 core 同时迁移后，client 的 host-key-check await、extension-info awaiter 或主动 CHANNEL_OPEN confirmation 出现回归，整个 Phase A 即使 server 已满足事故验收也不能形成绿色提交，问题又混入两套生命周期。可以先抽无行为变化的 packet/epoch primitives，server 验证后再迁 client。

- **[MAJOR] `Limits` API 与 1 TiB 默认本身需要另案设计。** 当前 `Limits::new` 明确 assert byte limit `<= 1 << 30`（`lib_inner.rs:270-279`），字段又是 `usize`，1 TiB 在 32 位 target 不可表示；`rekey_time_limit` 还是 `Duration`，不存在文档中的真正“无穷”。这不是改 default 常量即可完成，应改成显式 policy/Option、packet limit 和按 cipher resolved limits。

- **[MAJOR] generic `AsyncRead + AsyncWrite` 的 shutdown 权限要先解决。** 三 child 分持 `tokio::io::split` half 时，root 没有第三份 fd 可直接 shutdown。失败场景：Session Err 后只 cancel Writer，Reader 仍持 read half 等包；底层对象直到两 half 都 drop 才释放。supervisor 必须拥有 JoinHandle 并能 abort/drop 两 half；zfc 的 `CancellableStream` 语义也应被回归，不能依赖“发一条 Handle::Disconnect”。

- **[OK] 保留 Handler/Handle/Channel 表面 API、内部彻底换 actor/queue 是可行方向。** 但“方法签名兼容”不等于“完成时机兼容”；`Handle::data`、`Channel::data`、AsyncWrite 的成功语义要逐项写 contract tests。

## 7. 测试充分性

- **[MAJOR] 缺 NEWKEYS 边界矩阵。** 需要覆盖我方先发/对方先发/同时发、发完我方 NEWKEYS 后对方停住、NEWKEYS 后立即 DISCONNECT、每个字节位置 partial write/cancel、旧/新 cipher 各自只能解正确 epoch，并分别断言 inbound/outbound strict seqn reset 为 0。

- **[MAJOR] 缺压缩矩阵。** `none`、`zlib`、`zlib@openssh.com`，同算法 rekey、换算法 rekey、auth 前后 deferred compression、压缩炸弹、NEWKEYS 后第一包和跨包 history。zfc 当前 pin `none` 不能代替 core 测试。

- **[MAJOR] 缺报文顺序测试。** DATA→EOF、DATA→CLOSE、REQUEST→SUCCESS/FAILURE、OPEN_CONFIRMATION→首个 DATA、peer CLOSE 与本地 pending DATA、入站 DATA→EOF→CLOSE；每个都在 bulk/control backlog 和 rekey 边界下断言 wire 顺序与应用可见顺序。

- **[MAJOR] `tcp-zero-window` 用例定义不足。** 还要覆盖“对端不读但持续写”，否则现有错误 keepalive 论证也会通过；断言触发的是 write-progress deadline，且无需成功发送 DISCONNECT，所有 child/relay/oneshot 在总 grace 内退出。

- **[MAJOR] 缺 slow/hung Handler。** 对 auth、OPEN、DATA、channel request、`lookup_dh_gex_group` 分别注入 pending future、超时 future、panic 和 CPU-heavy 回调，验证 supervisor 行为及其他连接隔离。仅测 zfc 正常 handler 无法证明 I4。

- **[MAJOR] 缺 RFC KEX 在途消息测试。** 我方发 KEXINIT 后，对端先发 0/1/256/257/数千个合法在途 DATA/ADJUST/GLOBAL，再发 KEXINIT；已收到其 KEXINIT 后再发 DATA；initial strict-kex 非 KEX；重复 KEXINIT；错误 `first_kex_packet_follows`；simultaneous rekey。每种必须明确 process/ignore/disconnect，而不是“按 RFC”。

- **[MAJOR] 缺资源上界的逐项验收。** pending OPEN handle 不回复、variable-size control、多个 blocked producer、大 `Bytes` 单调用、所有 channel 双向满、KEX stall、teardown 中任务不退出、跨连接 global budget、compressed expansion；用 allocator/RSS 或内部 byte permits 断言公式每一项，而不只写“≤4.4 上界”。

- **[MAJOR] 缺窗口边界与恶意算术。** window=0、恰好耗尽、超 1 字节、超 1 packet、DATA 大于 advertised maxpacket、连续 ADJUST 令 u32 overflow、unknown/closed/reused channel id、zero-length DATA flood、EXTENDED_DATA 与 DATA 共窗。

- **[MAJOR] 缺 scheduler 对抗测试。** 无限 ordinary-control flood 下 bulk 仍有最小服务率；31 大流+1 小流 p50/p99；channel churn；new-flow boost 不饿死老流；不同 peer maxpacket；大量 1 KiB queue entries 确实被聚成大 packet。

- **[MAJOR] 缺真实客户端 CI/soak 矩阵。** 至少 OpenSSH 当前版+一个旧 LTS、libssh2、Go x/crypto/ssh、Apache MINA；各跑 direct-tcpip 多 channel、server/client initiated rekey、strict/non-strict、不同 cipher、zero-window、1 GiB+长流。raw harness 负责恶意精确包序列，真实客户端负责容忍度，不应互相替代。

- **[MAJOR] 缺 seqn/packet-limit 接近回绕测试。** 不必真发数十亿包，应提供 test-only 初始 counter，把它设到 limit-2，验证先触发 rekey；对端 stall 时 deadline 断连；绝不能 wrap 后继续 seal/open。

- **[MINOR] 所有 deadline 测试应使用 paused Tokio time 和明确的总 teardown bound。** 真实 sleep 容易慢且抖动，`deadline+1s` 不能检查 timer 被某个 callback/queue await 饿死的逻辑。

## 8. 方案对现状的描述是否属实

- **[OK] P1 基本属实。** `server/session.rs:1046` 的 receiver intake、`:1108` 的 inbound reserve、`:1118` 的 open reply 都受 `!kex.active()` gate；`session.rs:680-682/742-744` 在 rekey 时把新 DATA 放入 per-channel pending_data。没有 rekey deadline也属实。

- **[MAJOR] P2 的“最多 128 KiB + TCP sndbuf”不属实。** 128 KiB 是 soft intake watermark（`sshbuffer.rs:359-369`），只 gate Handle receiver；读包处理生成的回复、Handler 内直接 `Session::data`、rekey 结束的 `flush_all_pending_with_writer` 都可继续向 PacketWriter 加数据。失败场景：多个 channel 在 rekey 中各积满窗口，KEX 完成后一次遍历把每个 window 的 DATA 都 seal 到 staging，远超 128 KiB。KEX 与 bulk 共用 PacketWriter FIFO 这个病灶成立，但排队上界不能写 128 KiB。

- **[MINOR] P3“pending_data 按 channel 先到先服务”表述不准确。** per-channel 内是 FIFO；`flush_all_pending_with_writer` 按 HashMap key 的任意顺序逐 channel 尽量排空（`session.rs:460-468`）；平时 WINDOW_ADJUST 只 flush 对应 channel，Handle 路径还受共享 mpsc 到达顺序影响。准确结论应是“没有显式跨 channel 公平调度，某些路径一次 drain 单 channel/任意 HashMap 顺序”，而不是一个统一 FCFS 算法。

- **[OK] P4/P5 基本属实。** `SessionKexState::{Idle,InProgress,Taken}`、`rekey_wanted`、`skip_exchange` 分散；server run loop 确有所列七类 select arm，加上 pre-select batch drain 和 teardown 双 deadline，审查面很大。

- **[MAJOR] P6 把 `max_pending_inbound_bytes` 说成“全局 16 MB”是事实错误。** config 注释和 `deliver_inbound(... cap, id, ...)` 都表明它是**每 channel** cap（`server/mod.rs:88-102`、`pending_inbound.rs:146-153,183-215`）。失败影响是 §4.4 对现状内存和删除收益的比较基础算错：256 channel 理论上不是共享 16 MB，而可能每 channel 各有 pending cap。

- **[MAJOR] “窗口本身已经是界”对现状不成立，只对拟议的新 consumption accounting 才可能成立。** 当前 fast path 在 DATA 进入 channel mpsc 后就调用 `maybe_grant_after_delivery`，不是应用实际 read 后才 grant（`server/encrypted.rs:1222-1238`）；因此 app buffer 可继续积累，Scheme C/cap 不是简单重复。若以该断言为依据直接删除，慢应用可重新造成超窗口级内存。

- **[MAJOR] §4.6 混淆了 `Channel::data` 与 `Handle::data` 当前完成语义。** `ChannelWriteHalf` 先 reserve peer window 再向 session 发消息；`Handle::data` 则通过 `ChannelDataAcked` 等 pending_data drain 后 ack（`server/session.rs:153-207, 836-858`）。统一改成“本地出站 byte queue 有容量即完成”是可行的新 contract，但不是一个单一旧语义的平移，必须分别做兼容测试。

- **[MAJOR] 现有 `rekey_read_limit` 实际未接入触发路径。** 仓库内它除定义/配置外没有读侧使用；`Encrypted::flush` 只比较 PacketWriter 的 write bytes 和 time（`session.rs:787-800`）。所以 §I5 同时把 read/write 默认改 1 TiB 之前，应先承认并修复 read accounting，而不是假设两方向现状对称。

- **[MAJOR] 现有 rekey 对“更换压缩算法”的处理有缺口，方案没有把它列入病灶。** `CommonSession::newkeys` 没有把 `newkeys.names.client_compression/server_compression` 写回 `Encrypted`，只按旧枚举 reset context（`session.rs:131-147`）。反例是 rekey 从 `none` 协商到 `zlib`：本端仍按 none 发/收，对端已切 zlib。即使 zfc 当前禁用压缩，这仍是 client/core 对齐和 R1 必须显式修掉的现状问题。

- **[MINOR] 现有第三方回归缺口描述属实。** `russh/tests/` 有 9 个文件，但 rekey/backpressure/strict 等关键集成测试仍是 russh↔russh；这会共同复制同一边界错误。

## 对方案 §7 R1–R7 的直接回答

### R1 密钥切换边界

**[BLOCKER] 当前设计不能保证。** 旧/新 key、MAC、压缩 context、strict seqn 必须组成方向性 epoch；Writer 在“用旧 epoch 封完本方 NEWKEYS”这一原子点切 outbound epoch，Reader 在“用旧 epoch 验完对端 NEWKEYS、读取下一包前”切 inbound epoch。普通消息不得越过 epoch fence；已序列化旧 ciphertext 不能被 KEXINIT 插队。压缩 context 每方向在各自 NEWKEYS 边界重置。没有这套命令/状态定义，三任务存在旧钥包、新钥包和错误压缩 history 交错窗口。

### R2 活性表完备性

**[BLOCKER] 不完备。** 至少漏了 banner/初始 handshake、所有 Handler await、KEX 内 `lookup_dh_gex_group`、outbound open confirmation、want-reply global/channel request oneshot、close ack、control starvation、child panic/join、teardown flush/shutdown，以及最关键的“Writer write stall 时 keepalive也发不出”。必须由 root supervisor 持 deadline/cancellation 权威；不能让被监督任务自己通过其可能堵塞的队列完成自救。

### R3 kex 期间控制消息暂存

**[BLOCKER] `O(channel 数)` 不成立，也不应简单把 ADJUST 一律发送或一律拒绝。** 我方发 KEXINIT 后、收到对端 KEXINIT 前到达的 ADJUST/DATA 可能是合法在途包，应处理其状态；但我方从自己的 KEXINIT 到 NEWKEYS 之间不能发送连接层 ADJUST/OPEN reply。收到对端 KEXINIT 后再到达的上层包才可按 phase/strict 规则判违规。固定暂存 cap 与 RFC 的“arbitrary number of in-flight messages”存在明确取舍，需写成资源策略和互操作门禁。

### R4 DRR quantum 与延迟

**[MAJOR] 64 KiB 不能直接定案。** 32 活跃流约 16 ms 的单轮延迟还未包含 control burst；应测试 16/32/64 KiB，给新/短 flow 一包 fast path，并给 ordinary control 设置 burst cap。聚包必须跨相邻 queue entries gather，不能只切队头。

### R5 取消/关闭一致性

**[BLOCKER] 方案尚未设计。** 推荐状态为 `Running → Cancelling(reason, absolute_deadline) → Aborting → Joined`。任一 child Err/panic 只允许第一个 reason 获胜；广播 cancellation 后关闭所有 producer，唤醒 byte permits/oneshot/channel recv；Writer 在剩余总 grace 内 best-effort 发 DISCONNECT/flush；deadline 到立即 abort Reader/Writer/Session，drop 两 half；所有 relay 以 connection generation 取消。TCP read EOF 是对端写半关闭，不应自动禁止本端继续发；SSH CHANNEL_EOF/CLOSE 仍按每 channel 双向语义处理。

### R6 client 侧对齐成本

**[OK] zfc 当前没有 `russh::client` 使用点，可以延后。** 检索 `../zfc` 只见 SSH 入站 `russh::server`，另有 `socks5_client` 但不是 russh client。应先共享无行为的 packet/epoch primitives，server 完成真实验收后再迁 client；不要把 client 放进 Phase A 的阻断路径。

### R7 1 TiB 的密码学审慎性

**[BLOCKER] 不能认定“各套件均安全”。** byte-only 推导忽略 packet 数，小包可在远低于 1 TiB 时达到 u32 seqn wrap；chacha 直接使用 seqn。AES-GCM、chacha、AES-CTR+ETM 的安全/互操作上限也不同。新 policy 至少要每方向跟踪 bytes、packets、elapsed，按 negotiated cipher/MAC 解析阈值；packet hard stop 必须在 wrap 前，rekey 失败按 deadline 断连。1 TiB 可作为某些套件的运营上限候选，但不能作为统一默认，更不能替代可完成/可终止的 rekey 架构。

## 开工前最低门禁

只有以下五项都落成设计级 contract 后，方案才适合从 DRAFT 进入实施：

1. 方向性 transport epoch 状态机：NEWKEYS、key/MAC/compression/seqn 的原子切换与 simultaneous rekey；
2. root supervisor：write-progress/rekey/handler/request deadlines、强制 drop socket、总 teardown bound；
3. per-channel causal ordering：DATA/EXTENDED/EOF/CLOSE/回复在多 lane 下不越序；
4. 真正按 byte/packet/opening-count 闭合的内存公式和 global budget；
5. raw adversarial harness + 四类真实客户端矩阵先写成可执行验收，尤其覆盖“对端不读但持续写”。

在此之前，三任务只是一个有吸引力的并发拓扑，不是“永不僵死”的证明。
