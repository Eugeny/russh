# S1 终审(第 2 轮,窄口径):验证 5 条必修闭合

前一轮 S1 评审(gpt-5.6-sol high + Claude)判 CONDITIONAL,5 条 S1 必修。grok 已修。
**本轮只验这 5 条是否真闭合 + 修复有无新副作用,判 GO / NO-GO。** 上轮评审见 `.omc/research/review-S1-gpt.md`。
**避免过度设计**:只报会改变判决的实质项。

## Claude 已逐条核对(请独立复核,别默认采信)
1. **write_min_drain 默认 None**:`server/mod.rs` Default 改 `None`;活性层 `write_progress_deadline=30s` 保持开。
2. **partial-write cancel 不丢进度**:`PacketWriter.drained_total`(每次 `w.write` 成功后、下次 await 前自增);
   loop 用 `drained_seen→drained_now` 差额喂 `note_write_ok`;回归 `drained_total_survives_select_cancel_after_partial_write`。
3. **初始 KEX / handshake**:(3.1) `begin_rekey` 仅 `encrypted.is_some()` 注册 rekey deadline;
   (3.2) `run_stream` 绝对 `handshake_deadline_at` + `timeout_at` 包 banner/初始 flush;
   (3.3) handshake 未完成时 `reply` 包 `timeout_at(handshake_deadline_at,…)`,超时 HandshakeTimeout(未改 handler trait)。
4. **策略时序 + 真 trickle**:`next_min_drain_deadline` 纳入 `supervisor_sleep`;
   trickle ON/OFF 用同一 `set_trickle(512,1s)` + 同一 activity deadline,只切 write_min_drain,ON 断言首因 WriteStalled。
5. **单一 grace**:一个 `grace_at` + 单个 `timeout_at(grace_at, async{flush;shutdown;drain})`,到期 drop halves。

## 请你独立判定(每条 YES/NO + 依据 file:line)
- **#2 是否真闭合**:`drained_total` 差额法能否覆盖「partial Ok(n>0) 后 future 被取消」这一确切场景?
  `note_write_ok(delta)` 每轮喂入是否可能**漏喂**(如 select! 未走到差额计算点就 continue/break)或**重复计**?
  回归测试是否真复现取消场景(`PartialThenPend`)?
- **#3 是否真闭合且无新洞**:handshake 期把 `reply().await` 包 `timeout_at` 会不会误伤**合法慢 auth handler**
  (正常但慢的公钥校验/网络 auth 后端在 30s 内完成却被拆)?`timeout_at` 触发后是否干净拆连(不 panic、不半状态)?
  banner 阶段 `timeout_at` 覆盖是否真包含 spawn `run()` 前的 banner 收发?
- **#4 是否真测到策略层**:ON 用例的活性层(512B/s 持续 Ok(n>0))是否确实**不会**先于策略层 fire
  (即绿→拆确由 min_drain 而非 activity)?`next_min_drain_deadline` 计算有无 off-by 或退化忙轮询?
- **#1/#5**:默认 None 是否彻底(harness/其它构造点无遗留 ON)?单一 grace 是否真不叠加、generic AsyncWrite 的
  shutdown pending 是否被 `grace_at` 兜住?
- **回归**:现有 9 tests + S0 五用例 + trickle + 他连零影响是否仍全绿(可远程跑目标 suite 抽验)?

## 输出
`.omc/research/review-S1-r2-gpt.md`:判决 **GO / CONDITIONAL(列必修)/ NO-GO**;5 条各 YES/NO;
任何新副作用定位 + 最小修法。只报改变判决的项。先读 `sshbuffer.rs`、`server/session.rs::run` S1 段、
`server/supervisor.rs`、`server/mod.rs` Default、trickle 用例。
