# 复审任务(第 2 轮):russh Session Loop 全量重构方案 v2

你是对抗式设计评审。第 1 轮评审(三家独立)已把方案 v1 判为 NO-GO;作者据此修订出 v2。你的任务是**复审 v2**:核验第 1 轮缺陷是否真正关闭,并攻击 v2 新引入的机制。不要客气,不要背书。

## 材料

- **评审对象(v2 全文,必读)**:`.omc/plans/russh-proxy-session-rewrite.md`
- 第 1 轮三份评审(选读,用于核对缺陷清单):`.omc/research/russh-rewrite-review-{gpt,grok,kimi}.md`
- 代码现状(核实方案断言时用):`russh/src/server/session.rs`、`russh/src/session.rs`、`russh/src/sshbuffer.rs`、`russh/src/pending_inbound.rs`、`russh/src/kex/`、`russh/src/negotiation.rs`、`russh/src/client/mod.rs`、`russh/tests/`

## 复审要求

按以下三部分输出,结论标注 [BLOCKER]/[MAJOR]/[MINOR]/[OK]/[CLOSED]:

### A. 第 1 轮缺陷关闭核验
对 v2 附录 A 裁决表逐行核验:v2 正文的处置是否真正关闭该缺陷([CLOSED]),还是只在附录里声称关闭而正文规格不足以支撑([BLOCKER]/[MAJOR] 复燃)。重点:
1. ConnSupervisor 的写进度看门狗与强制拆除——语义是否完整可实现(时间戳定义、"有待写数据"的判定、abort 与 cancel-safe 的交互)?
2. 方向性 NEWKEYS epoch——§4.1/4.2 的规格现在够编码了吗?还有没有交错窗口?
3. per-channel 因果序 fence 与三级车道的组合——WINDOW_ADJUST/OPEN_CONFIRMATION 走 control lane 的例外论证是否严密?
4. RekeyPolicy 包数界——2^31 触发点、读写双向记账、与 strict-kex seqn 重置的交互。
5. Handler 全部 spawn——回调结果回流的有界性、决策 deadline 的语义(reject 后对端重试怎么办)。

### B. v2 新机制的新风险
v2 相对 v1 新增了:supervisor 状态机、byte permit、全局预算、ready-set 1-packet 轮转、burst cap、wire-lifecycle 与 app-delivery 双路径 CLOSE、kex 专用队列(容量 16 枚举)、策略表 §4.6、切片 S0–S7。逐个攻击:有没有新引入的死锁/竞态/泄漏/协议违例?特别注意跨任务消息的次序假设。

### C. 可开工判定
最终回答:v2 能否进入 S0/S1 实施?若不能,列出仍需关闭的最小缺口清单(按优先级)。

## 输出

写入本仓库文件(markdown,中文):**OUTPUT_PATH 见派发 prompt**。
所有 [BLOCKER]/[MAJOR] 必须给具体失败场景(报文序列/等待环/内存增长路径),不接受"建议考虑"。[CLOSED] 也要一句话说明依据(v2 哪一节哪句话关闭的)。
不要修改仓库中任何其他文件。
