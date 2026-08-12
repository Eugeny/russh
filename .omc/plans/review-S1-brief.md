# 对抗评审:S1 ConnSupervisor 接入现有 loop

grok 实现了 S1(§4.2 supervisor 接入现有 server `select!` loop)。你(gpt-5.6-sol high)+ Claude 对抗复审。
方案 §4.1/§4.2/§4.4;S1 brief `.omc/plans/impl-S1-brief.md`;实现报告 `.omc/research/impl-S1-report.md`。
**避免过度设计**:只报会改变判决 / 生产回归 / 首因错误 / G2 破坏的实质问题。

## 完成门(硬标准)
S0 红用例翻绿且**首因正确**(case1=RekeyTimeout、case2/4=WriteStalled)、zero-window-legit 保持绿、
trickle-read 分层(min_drain ON 拆 / OFF 不拆)、他连零影响、现有 9 tests 全绿。grok 自报全绿。

## 交付物
- 生产:`russh/src/server/supervisor.rs`(WriteWatchdog / RekeyDeadline / DisconnectCause,323 行)、
  `server/session.rs::run`(loop 接入:top-of-loop 检查 + select! sleep 臂 + 首因拆除 + teardown grace)、
  `server/mod.rs`(Config 新字段 + 默认值)、`sshbuffer.rs`(`flush_into` 改返 `Ok(usize)`、新增 `pending_bytes()`)、
  `lib_inner.rs`(新增 Error 变体)、`client/*`(flush_into 签名吸收)。

## Claude 已核实(可复用,别重复)
- `pending_bytes()=write_buffer.buffer.len()`(已 seal 密文)**不含** pending_data → 零窗不误武装,G2 安全。
- `flush_into` 6 处调用点签名吸收正确,远程编译过。
- `RekeyDeadline.poll` 校验 generation 防注销竞态;`observe_eligible` 边沿武装、零 eligible 即 disarm。

## 请你重点对抗核查(按严重度)
1. **生产误杀(最重要)**:`write_min_drain` **默认开 `Some((4096, 30s))`**。武装态(有 sealed 密文待发)下
   30s 窗口排空 <4KiB 即 WriteStalled 拆连。**合法慢速读者**(如对端合法地每 30s 只读 3KiB、或移动网络弱下行)
   会不会被误杀?交互式 shell / keepalive-only 空闲 / 合法大文件慢速下载 各自会不会误触发?
   给出:默认 ON 对 zfc 代理是否安全,还是应默认 OFF / 调阈值。这是生产行为变更,必须定性。
2. **首因归属**:初始握手期 `begin_rekey()`(session 启动即调)会 arm `rekey_deadline`,而初始 kex+auth
   又受 `handshake_deadline`——两者都 30s。初始 kex 卡住时首因会是 RekeyTimeout 还是 HandshakeTimeout?
   是否造成 case/生产的首因错误归属?是否该在初始 kex 不 arm rekey_deadline?
3. **run() 返回值语义变更**:supervisor 拆连现在使 `run()` 返回 `Err(WriteStalled/RekeyTimeout/HandshakeTimeout)`
   (原正常断开返 Ok)。有无调用方(zfc / 现有 server accept 循环)因此回归?
4. **rekey deadline 清除完备性**:`clear_rekey_deadline` 只在 reply() 的 NEWKEYS→Idle 路径调用。
   有无其他 kex 退出路径(kex 失败、strict-kex 违规、同时 rekey)使 deadline 残留、之后对**无关**时刻误 fire?
   `active_rekey_gen` 用 `kex.active()` 门控是否堵住了所有残留?
5. **loop 活性 / cancel-safety**:top-of-loop 检查 + `select!{ sleep(supervisor_sleep) }` 臂,能否保证
   被卡在 `flush_into`/`reading` 臂时看门狗仍按时 fire(sleep 与阻塞臂竞争)?`supervisor_sleep` 计算
   (min(wd, rekey, hs).max(1ms))有无退化成忙轮询(1ms 空转)或错过 deadline?
6. **WriteProgress 非原子**:S1 单任务内联,watchdog 与 note_write_ok 同任务,无跨任务撕裂——确认这在 S1 成立
   (原子快照是 S2/S3 才需)。有无遗漏的并发读者?

## 输出
`.omc/research/review-S1-gpt.md`:判决 GO / CONDITIONAL(列必修)/ NO-GO;每条定位(文件:行)+ 严重度 + 最小修法;
明确 S1 必修 vs S2+ 再补。**问题 1(误杀)务必给出明确定性与默认值建议。**
先读 supervisor.rs 全文 + session.rs::run 的 S1 段(~1016-1330、~2008-2045)。
