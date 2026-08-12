# S0 终审（第 3 轮，窄口径）

- 评审者：gpt-5.6-sol high
- 日期：2026-08-12
- 范围：仅 B1 / B2 及其新增 blocker 副作用

## 判决：GO

B1 与 B2 均已闭合；未发现会改变判决的新 blocker。S1 中 `WriteStalled` 与 `RekeyTimeout` 的 deadline 先后仍需用测试专用短 write deadline 固定，但这是 S1 调参/首因断言项，不再是 S0 blocker。

## B1：YES — 停滞时 SSH 下行信用为正已可判定

- start-gate 在创建 writer/首次 `write_all` 前 await（`russh/tests/harness/mod.rs:660-670`）；case2/case4 均先断言 `progress.total() == 0`，再冻 TCP，最后 release（`russh/tests/test_malicious_client_s0.rs:296-311,503-516`）。因此故障前没有未被 `WINDOW_ADJUST` 补回的 flood 消费；故障起点确为完整初始窗口。
- 严格说，裸 `report.end_bytes` 不是协议消费的绝对上界：当前一次未完成的 `write_all` 可能已在 `ChannelTx` 预扣窗口。但 `ChannelTx` 每次最多预扣 `min(max_packet, buf_len)`，并且只有当前一次 write 可尚未计入 `Progress`（`russh/src/channels/io/tx.rs:82-98,110-146`）。本测试 chunk=16 KiB、`pkt`=32 KiB，故已 seal/发送的信用消费 `C <= end_bytes + pkt`；协议层也只在按 recipient window 生成 channel-data 包时扣减信用（`russh/src/session.rs:525-566,587-627`）。因此 `end_bytes + pkt < window` 可严格推出剩余信用 `> 0`（`russh/tests/harness/mod.rs:376-395`）。
- 巨大 channel buffer 只可能使 app 接受量高于已 seal/发送量，从而使该断言更保守、产生假失败；不能产生“窗口已尽却通过”的假通过。实跑 case2 在 2,785,280 bytes 后稳定停滞，距 16 MiB 窗口仍有充足余量。

## B2：YES — case4 已锚定 WriteStalled，与 case1 构成反向对照

- case4 在调用 `rekey_soon()` 前，已要求 `stalled_level > 0`、连续 300 ms 无进度，且通过 B1 的正信用断言（`russh/tests/test_malicious_client_s0.rs:518-537`）。此时 rekey 尚未发起，零窗又已排除；server loop 在非 kex 时只会因 `PacketWriter` 达 HWM 停止接收 outbound，同时 socket flush arm 仍在尝试排空密文（`russh/src/server/session.rs:1042-1048,1137-1148`）。因此 rekey 之前已存在独立的 wire-eligible ciphertext/socket stall，不可能是 `RekeyTimeout` 所造成。
- 冻结的只是 client read half；client write half 仍能处理 `rekey_soon` 并发 KEXINIT，server 的并发 read arm 不受其阻塞的 write arm 影响。server 收到 KEXINIT 后立即 `begin_rekey()` 进入 `InProgress`（`russh/src/server/mod.rs:1167-1185`）。实跑日志已在 pre-existing stall 之后观测到 `Client has initiated re-key`。
- `kex_after == kex_before` 单独只证明没有新的 `kex_done`，不单独承担“已发起”证明；“已发起”由上述 KEXINIT 发送/接收链路给出。在 client read 持续冻结时，client 无法消费 server KEX reply，故该计数不变可靠证明本次 rekey 未完成（`russh/tests/harness/mod.rs:714-721`、`russh/tests/test_malicious_client_s0.rs:542-553`）。实跑 case4 在 rekey 前 3,129,344 bytes 已停，随后全观测窗口保持不变且 `kex_count` 为 1→1。
- 因而 case1 是 `InKex + socket writable + 无先在密文停滞`，case4 是 `先 wire-eligible write stall + 后 InKex`；两者的反向对照已成立。

## Blocker

无。`FloodStartGate` 使用 `notify_waiters()`；当前 Tokio 1.52.3 的 `Notified` 在创建时记录 broadcast 代数，即使尚未首次 poll，创建后发生的 `notify_waiters()` 也不会丢失；配合 release bit 的两次检查（`russh/tests/harness/mod.rs:430-452`）不会导致挂死。client 若提前关闭，case4 的 `report.session_alive && !session.is_closed()` 会直接失败，不会假翻绿（`russh/tests/test_malicious_client_s0.rs:557-564`）。
