# S0 修复任务(第 2 轮对抗评审后)

第 2 轮验证复审 **CONDITIONAL**(gpt-5.6-sol high + Claude)。A1(P1 隔离)、A3(G2 零窗)、
NEWKEYS-hold 安全性——**已闭合,别动**。剩两条 S0 必修,都是「信号仍不可判定」。
完整评审见 `.omc/research/review-S0-r2-gpt.md`。**避免过度设计**:两条必修有一个统一最小修法(见下),
优先用它,**不要**新增 server 侧观测钩子(除非统一修法走不通再回报)。

## 必修 1(B1):证明**故障瞬间** SSH 下行信用为正 —— 现 `growth<window/4` 是假信号
**问题**:窗口是滑动信用。冻结前可能已有大量字节未被 WINDOW_ADJUST 补回,故障瞬间剩余信用可能已接近 0。
`assert_ssh_credit_remaining` 只比故障**后**增长,`growth=0`(合法零窗)与「socket 堵但信用正」两态都过——
证明不了 watchdog **应** armed。case2(talk-no-read)与 case4 都受此影响。

## 必修 2(B2):case4 必须真有 wire-eligible 密文卡在 socket,且与 case1 首因可分
**问题**:case4 先 `wait_rekey_held`(client 已收 ECDH_REPLY)再冻 TCP。那一刻 server 已把 ECDH_REPLY+NEWKEYS
写完、进 `WaitingForNewKeys`,bulk 被 kex.active 闸**不再 seal**,socket 上通常已无待发密文 →
`wire_eligible_bytes = 0`。冻 TCP 没有新增可阻塞对象,停滞仍是 kex gate,**与 case1 同构**。
结果:正确 S1 会用 `RekeyTimeout` 拆 case4(违反 `WriteStalled only` 契约),或严格要 `WriteStalled` 则永不翻转。

---

## 统一最小修法:flood start-gate + case4 改「先冻后 rekey」

### (a) 给 FloodServer 加 start-gate(harness)
- `FloodServerConfig` 加一个 `flood_release: Arc<tokio::sync::Notify>`(或 `Arc<AtomicBool>`+轮询)。
- `ServerMode::FloodForever`/`FloodBytes` 在**开始写之前**先 await release;channel 已 accept 但**零下行字节**直到测试放行。
- 目的:让「冻 TCP」发生在**已知满窗**起点——放行前下行 accepted=0,client 公布的整窗都是已知信用。

### (b) case2 talk-no-read 重排
1. 开 down channel(FloodForever,**未放行**)+ up feeder channel。
2. **先冻 TCP 读**(此刻下行 0 字节,down 信用 = 完整初始窗)。
3. **放行 flood**:server 开始 seal 下行 bulk,消耗信用直到 socket sndbuf/HWM 堵住(远早于 16 MiB 窗耗尽)。
4. 断言:`bytes_through + max_one_packet < initial_down_window` —— 证明停滞时**下行 SSH 信用仍为正**(watchdog 应 armed);
   且 `report.stalled`(终态);uplink feeder 持续喂 keepalive 但连接现架构不拆(P7 红)。

### (c) case4 write-stall-during-rekey 重排(先冻后 rekey)
1. 开 channel(FloodForever)**并放行**,drainer 读,让 bulk 正常流(信用为正,TCP live)。
2. **先冻 TCP 读** → server 下行密文堆入 sndbuf,产生 **wire-eligible 且卡住**的密文(信用仍正,因窗远大于 sndbuf)。
   在冻结后断言:进度确实停住(sealed 但 socket 写不动),证明 write path 已堵。
3. **再发 rekey**:client 写半仍可用,`rekey_soon()` 发出 KEXINIT → server 收后进 InKex。
   (client 收不到 server KEXINIT 回复,rekey 自然悬空;`kex_count` 不前进即证未完成。)
4. 断言:停滞时 down 信用为正(同 (b) 的 `accepted+max_inflight<window`)+ `report.stalled` +
   `kex_after==kex_before`(rekey 在飞未完成)。
   —— 现在 case4 = 「InKex **且**有 wire-eligible 密文写不动」,与 case1「InKex 但 socket 可写」成反向对照。
   首因契约不变:case4 只由 `WriteStalled` 翻转,case1 只由 `RekeyTimeout` 翻转。
- 注:case4 现在**不需要** `RekeyHoldGate`(悬空由 TCP 冻结保证);若你仍想用 hold 证明「rekey 已进入」,
  可留,但冻结前置条件**不得**再用「client 已收 ECDH_REPLY」的 hold 事件(那正是 B2 病根)。

### (d) case1 保持不变
case1 已闭合(A1 YES):KEX-only、TCP 不冻、负对照。**别动它**,只需确保它与新 case4 不再同构
(case1 无 TCP 冻、无 wire-eligible 卡滞;case4 有)。

---

## 不在本轮(记录,别做)
- S1 首因枚举导出;测试用短 deadline + `observe>=deadline+ε`;S2 Writer 装 outbound epoch 后 NEWKEYS-hold 的错钥适配(gpt r2 §B 已记)。

## 交付
- 改 `harness/mod.rs`(start-gate)+ `test_malicious_client_s0.rs`(case2/case4 重排)。case1、G2、负对照不动。
- 远程编译 + 跑全用例:case2/case4 现在**信用为正可判定** + 终态停滞;负对照仍过;G2 仍绿。
- 更新 `.omc/research/impl-S0-report.md` 加「第 2 轮修复」小节,逐条给 B1/B2 闭合证据
  (尤其:如何证明停滞瞬间 `accepted+max_inflight < initial_window`)。
先读 `.omc/research/review-S0-r2-gpt.md` 全文再动手。
