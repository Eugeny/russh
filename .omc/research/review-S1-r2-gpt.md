# S1 终审（第 2 轮，窄口径）

- 日期：2026-08-12
- 范围：仅复核前轮 5 条必修及其修复副作用

## 判决：NO-GO

5 条中 **#1/#2/#4/#5 已闭合，#3 未闭合**。唯一改变判决的新副作用是：认证已经成功、但尚未发送第一份 post-auth 报文的合法空闲连接，仍会被 `handshake_deadline` 误拆为 `HandshakeTimeout`。

## 逐条结论

| 必修 | 结论 | 依据 |
|---|---|---|
| #1 默认 `write_min_drain=None` | **YES** | 库默认确为 `None`，活性层仍为 30s（`russh/src/server/mod.rs:165-170`）；harness 默认也为 `None`（`russh/tests/harness/mod.rs:600-603`）。其余 `Some(...)` 仅见于 zero-window 反例和 trickle ON 的显式策略测试。 |
| #2 partial-write cancel 不丢进度 | **YES** | 每次 `write()` 的 `Ok(n>0)` 后，在下一 await 前同步推进 cursor 和 `drained_total`（`russh/src/sshbuffer.rs:633-645`）；每次仍存活的 `select!` 迭代后按 `drained_now-drained_seen` 喂入并同步 cursor（`russh/src/server/session.rs:1289-1296`），因此既不重复也不漏喂。跳过该差额点的 `break`/`return` 都同时终止连接（`:1175-1192,1207-1219,1224-1227,1254-1266`）；`:1145-1147` 的 `continue` 位于 `select!` 前，没有在途 flush 可丢。`PartialThenPend` 首次只写 16B、随后永久 Pending，timer 臂获胜后 future 被 drop，确实复现“partial success 后 cancel”（`russh/src/sshbuffer.rs:664-729`）。 |
| #3 初始 KEX / handshake | **NO** | 3.1 已正确限定为仅 `encrypted.is_some()` 注册 rekey deadline（`russh/src/server/session.rs:2044-2071`）；3.2 的绝对 deadline 确实在 spawn 前覆盖 banner write/read，并传入 session 覆盖初始 flush（`russh/src/server/mod.rs:1109-1167`；`russh/src/server/session.rs:1002-1021`）；3.3 的 `reply` timeout 也会记录首因、恢复 opening cipher 后进入统一 teardown，不见 panic/半状态外泄（`russh/src/server/session.rs:1198-1223,1330-1377`）。但认证接受后状态先变为 `InitCompression`（`russh/src/server/encrypted.rs:875-887`），只有收到下一份 post-auth 报文才转为 `Authenticated`（`:131-137`），而 supervisor 只把 `Authenticated` 当作 handshake 完成（`russh/src/server/session.rs:1074-1085`）。因此已认证但暂不 open channel 的合法客户端到绝对 deadline 仍被误拆。对“慢 auth”本身，`timeout_at` 使用的是文档约定的 banner+kex+auth **总预算**；总握手在预算内完成不会被提前拆，单独 handler 虽少于 30s、但总预算超时则属于配置语义。真正副作用是完成态判定遗漏 `InitCompression`。 |
| #4 min-drain 时序 / 真 trickle | **YES** | remaining 由 `window-elapsed` 计算并以 1ms 为下限（`russh/src/server/supervisor.rs:221-232`），已纳入 activity/rekey/handshake 的最小 sleep（`russh/src/server/session.rs:1150-1171`）；top-of-loop 先消费到期窗口，未见 off-by 或持续忙轮询。ON/OFF 使用同一 `set_trickle(512,1s)` 和同一 30s activity deadline，只切 `write_min_drain`（`russh/tests/test_malicious_client_s0.rs:406-511`）。ON 在最长 12s 内得到 `WriteStalled`，不可能由 30s activity 层先触发；OFF 6s 内存活。 |
| #5 单一 grace | **YES** | 只计算一次 `grace_at`，单个 `timeout_at` 同时包住 flush、generic `AsyncWrite::shutdown()` 和 read drain；到期后无额外 await，stream halves 随函数返回 drop（`russh/src/server/session.rs:1340-1377`）。无 grace 叠加，永久 Pending 的 shutdown 也受同一绝对期限约束。 |

## 唯一必修与最小修法

在 `Session::run` 的 handshake 完成谓词中，将认证已成功且 `auth_succeeded` 已返回的 `EncryptedState::InitCompression` 与 `Authenticated` 一并视为完成。该判断位于下一轮 loop 顶部，所以不会放过仍卡在 `auth_succeeded` 内的 handler future；后者仍受现有 `timeout_at(handshake_deadline_at, reply(...))` 约束。

补一条回归：公钥认证成功后不发送 channel/global request，保持空闲超过短 `handshake_deadline`，断言连接仍存活且 first-cause 为空。本轮一次性诊断用例以 2s deadline 复现：认证成功后空闲 3s，实际得到 `Some(HandshakeTimeout)`。

## 回归抽验

```text
cargo test -p russh --features _test_hooks -- --nocapture
```

结果：exit 0；lib 175/175、`test_malicious_client_s0` 8/8（S0 五场景、trickle ON/OFF、他连零影响均绿）、其余 integration/doc tests 全绿。全绿不推翻上述 NO-GO，因为现有 suite 缺少“auth 成功后、第一份 post-auth 报文前保持空闲”的边界用例。
