# R1 Control Plane Invariants / 控制平面不变量

任务：`R1_BOUNDARY_FRESH_REVIEW_THEN_INVARIANTS_FREEZE`，阶段 B。
作者：Lead `/root`。本文仅整理要求、前提、反例与未完成责任，不授权执行。
**冻结正文的审查状态：REVIEW PENDING AT FREEZE**；实际最终结论以本轮独立 disposition 为准，
不为把正文改成 PASS 而改变受审字节。此处的 freeze 仅指文档受审快照，不是产品 Candidate Freeze。

## 1. 效力、范围与来源分级

阶段 A 的新 [Boundary disposition](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/boundary-disposition.md)
为 PASS，A/B/C 原始输出均已保存。本文以其中固定的
[Boundary 快照](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/boundary-snapshot.md)
为文档级依据；其 SHA-256 为
`2aac26bd0b95a0b85cc2a869133676e7f4e96b059423c67404842cc8beb35845`。
快照保留原链接，须以原 `docs/` 为解析基准。
历史 Boundary PASS 曾被报告，但原 Reviewer 原文 NOT LOCATED；本轮新 PASS 不补造或复核那次历史过程。

下列来源类别不能互换。每项不变量最后一栏列出类别及当前证据边界。

| 标记 | 含义与效力 |
|---|---|
| U | 本轮用户授权及已明确的范围裁决；决定本轮可做什么，不是实现证明 |
| B | 经阶段 A 新审查的 Boundary 中保留的职责/要求；可作为本轮文档依据，不使 §9 的推荐机制自动获批 |
| K | 既有有界合同要求；保持原适用范围，不能扩大到尚未准入的部署或新生命周期 |
| E | 实际可读的历史 scoped implementation/review evidence；是过去限定范围的证据，不是本轮新执行 |
| N | 由 B/K 推导并供本轮审查的一致性或验收要求；写出“必须”不代表机制已冻结或实现已通过 |
| D | 仍缺范围决定、定义、机制或实证的前置条件；不得由本文填造 |
| X | 被拒绝候选、旧 Findings 与反例；用于保留缺口，不能提升为 accepted 机制 |

本文中的状态词仅是分析维度或引用原有术语，**不定义新持久状态、schema、API、wire、CAS 算法或完整状态机**。
Boundary §9 的 RECOVERY_ONLY 及每次启动人工处理等均是待后续裁决的建议，本文不授予该权限。
文档 PASS 至多表示要求在声明的前提下相容、可检查且诚实保留缺口；不证明完整协议可实现或恢复已可达。

保持不变：

- 原 Minimal Trust Design Gate：**BLOCKED**；Implementation Gate：**BLOCKED**。
- Foundation Closure：**NOT ENTERED**；正式 PostgreSQL Acceptance 本轮不开始。
- C01：**DEFERRED / REMOVED FROM R1 REQUIRED SCOPE**，不是 PASS，也不是等待 Revision 7 的 OPEN。
- 自研 IBCS、witness/consensus/transparency-log 和自动 clone/rollback 证明继续延期。
- Windows Identity、F1/F2/F3/F4/F9 的历史 scoped PASS 保留；六类 Minimal Trust 旧缺口继续 OPEN。
- 本轮没有运行产品/模型/数据库测试，没有访问 Root 私钥、pin、ACL、服务身份或数据库。

## 2. 术语：事实、权限与未知必须分开

| 术语 | 本文精确定义、来源与未定义部分 |
|---|---|
| canonical identity / 规范身份 | 不可变 opaque continuity UUID/ULID 身份与 qingyu_identity_id 的 1:1 关系；当前 F3 wire 约束为 UUID pair 加 committed GENESIS operation reference。alias 仅标签，不能代替身份或授予权限。泛边界允许 UUID/ULID 不意味着当前 UUID 协议已支持 ULID。来源 B §5、K-F3 §2 |
| operation / mutation | 当前 F3 Authority 操作键为 (authority_domain_id, operation_id)，operation_id 是 UUID；业务 mutation/change ID 在 Core durable INTENT 映射到该键。local_commit_id 是事先持久化的独立事务证据身份。新 attempt 与原操作重试不能混同。来源 K-F3 §2、§5 |
| authorization / authorized decision | 经认证且适用于该操作的权限、原请求及持久化 requested decision。当前 F3 原 decision 在 PREPARE 前保存，终态 POST 的精确 authorization bytes 在该 POST 前保存。“authorized_decision”不是本文新增的 wire 类型；新 override 结构尚未定义。来源 K-F3 §2、§5；D-06 |
| Authority terminal evidence / 权威终态证据 | Authority 自身持久历史中唯一 COMMITTED 或 ABORTED 的原始 receipt/签名/链位置及语义绑定；不是仅看到签名字节。PREPARED Ack 不属于终态。签名不证明 Core DB 或客观世界已执行。来源 B §4–6、K-F3 §4–5 |
| local canonical effect / 本地规范效果 | 已验证决定在 Core 受治理状态中的正式可见效果及状态版本；不包括尚未发布的候选、INTENT、协调记录。当前证据范围是限定的确定性状态/结果，不是任意外部世界副作用。来源 K-F3 §2、§5、B §5、§7 |
| Audit / receipt | Audit 是与原身份、状态、候选和历史链绑定的本地记录；receipt 保存与相应 Authority 决定的精确关联。ABORT 也有正式 Audit/receipt，但不推进业务 state_version。不能用当前全局 head 替换旧记录位置。来源 K-F3 §5、K-Core Historical receipts |
| admission / 准入 | 当前指定进程、身份、部署、代际及权限可否接受某类动作的条件；不等于 operation 已决定，也不等于本地已落实。正常写入与合法恢复作业所需权限须分别定义，后者无本文新授权。来源 B §1、§9–10 |
| ordinary crash / 普通崩溃重启 | 进程中断，但指定的已准入持久存储与原授权记录未丢失、未恢复旧副本、未替换，且可核验；不因此自动证明新的运行上下文已准入。区分故障类型不赋予自动探测物理回滚能力。来源 U、B §9、K-F3 §5 |
| restore / clone | 备份/快照恢复、复制数据库、替换存储或其它不能直接证明连续性的环境变化；不得依靠恢复出的 READY 或自洽旧链自动接纳新写入。来源 B §4–9；U-恢复边界 |
| generation / incarnation | 已有合同中各自独立的 Authority、storage、control-plane、lease/session 等代际/实例绑定，不是一个可互换计数。新代际的产生、开启和旧 pending 处理仍有 D-03/D-04，不把 UUID 新鲜性当 provenance 证明 |
| UNKNOWN / unresolved / conflict | UNKNOWN 是观测或资格不足；unresolved 是仍有待处理工作的事实；conflict 是已知证据不相容。它们附着于已知进度，不反转已知终态或删除原 decision。具体字段/枚举沿用各合同，本文不新增状态格式 |

## 3. 信任前提与非保证

下述 T 编号供各不变量引用；引用不免除在实际验收中逐项核实前提。

- **T1：历史与身份边界。** 指定 Authority 的被准入历史及 Core checkpoint 可获得且未被受信任管理员绕过接口改写；
  单一被授权的当前 Authority 写入上下文明确。只保证这个边界内的唯一性，不证明任意复制后的全球唯一。
- **T2：持久事务。** 目标存储按已验证事务/持久性合同工作。两库各有事务，不存在本文赋予的分布式原子提交。
  进程内锁、SQLite 行为或模型断言不能替代目标 PostgreSQL 实证。
- **T3：语义合同。** 对所支持操作，双方共享的输入、scope、效果、Audit、版本、摘要前像和验签规则明确且可重算。
  当前 F3 仅有其 v1 有界映射；新候选的 B-01/A-02/B-02 缺口未满足此前提。
- **T4：认证与当前资格。** 固定信任来源、受保护程序、认证 caller、预置 signer、当前身份/代际/fences 可核验；
  历史证据校验与创建新终态、本地收尾、新业务写入所需资格分别判断。
- **T5：运维信任。** Operator/主机管理员/DB owner/signer 持有人处于声明的可信管理边界内；
  Operator 能说明来源并处置旧执行上下文，但不能以声明替代系统必须验证的证据。
- **T6：条件性恢复活性。** 限定普通故障场景中证据完整、指定组件在故障后持续可用、合法所需权限保留或可按批准合同取得，
  并有公平重试/锁调度。这里不把“已 ACTIVE”或“已经完成 pending”作为恢复完成的前提，也不保证永久分区、丢失记录、
  明确撤销权限或跨连续性链缺口必然可恢复。

这些前提不能通过本地自洽、成功验签、过去 PASS 或“配置形状正确”自动认定满足。
前提无法证明时必须停止**依赖该前提的动作**，保留证据和不确定性；不是禁止所有合法诊断/协调持久化。
不保证对恶意受信任管理员的防篡改、任意 rollback 检测、历史永远最新、任意外部效果、两库即时一致或无条件恢复。

## 4. 写入分类与独立状态维度

以下是约束分类，不是新的权限表或状态转移设计。任何实际可执行动作仍须已有受审合同授权。

| 写入/观测类别 | 所需依据 | 未具备 terminal 时 / 已具备 terminal 后的限制 |
|---|---|---|
| durable 输入、授权、INTENT、原选择、Ack、不可见候选、待协调记录 | 原身份/授权、相应阶段的资格与精确内容约束；网络前先落盘所需材料 | 可在 terminal 之前合法持久化；不能当成业务已完成、也不能创造缺失授权 |
| Authority PREPARED / terminal | 自身认证、完整请求规则、适用最终资格、签名与本库事务 | PREPARED 不消耗 terminal 序列；terminal 原子提交前不得对外称已成立 |
| Core canonical business effect | 正确 terminal 的完整验证、原授权/候选、适用绑定与获准本地收尾资格 | 不得先发布效果再用将来签名追认；有 terminal 不等于可越过恢复边界 |
| Core canonical Audit / receipt / checkpoint | 与已验证 COMMIT/ABORT 和选定分支精确一致的本地事务 | COMMIT 与 ABORT 各落实其应有 Audit；ABORT 不产生 COMMIT 效果或业务版本增长 |
| 只读查询 / 历史重放 / 调查记录 | 正确对象与认证读取范围；调查记录不是 canonical history | 不生成新终态；UNKNOWN 不伪装“查无此操作”；不得借诊断接口绕过写权限 |

至少分别观察：

1. 当前环境的 admission/适用权限。
2. Core 已持久化的操作进度、原 decision 与精确请求。
3. Authority 真实 PREPARED/terminal/可信未找到事实。
4. 本地 canonical effect、Audit、receipt 是否一致完成。
5. 证据不足或冲突的标记及原因。

Authority 已 COMMITTED + 本地待落实 + 新写入关闭是可能的组合，不是终态应被撤销的理由。
“无 terminal 不得业务提交”不能被简写为“无 terminal 不得任何写入”；
“正常写入关闭”也不能被解释成“任何恢复写入已经获准”。

## 5. Authority 不变量

### INV-A-01 — 唯一且不可反转的终态

- **要求：** 在同一 admitted Authority history 内，一个 operation 键最多有一个 canonical terminal；COMMITTED/ABORTED 一经持久成立，不因重启、客户端选择、lease 到期或本地落地失败而反转。
- **对象/范围：** 当前 mutation operation；GENESIS 初始历史另见 INV-R-05，不自动套用 mutation attempt 规则。
- **前提：** T1、T2、T4；原操作作用域可核验。跨任意复制/回滚的全局 exactly-once 不在保证内。
- **分类：** Safety / 历史唯一性。
- **禁止：** 同键双终态、ABORTED 重开、以查询失败补造 ABORT、以新签名替换旧终态。
- **未知/冲突/失败：** 保留真实已存历史；不可判定则不产生假终态，冲突隔离并阻止相关新业务写入。
- **反例/验收：** 同键并发 COMMIT/ABORT 或重复发送产生两套 canonical bytes/序列即违反；应观察最终一套原始证据且后续只重放。
- **来源/状态：** B §5–6；K-F3 §4–5；E-F3 仅有界 mutation 终态并发/原子性证据。N 为后续保留要求；新生命周期未验收。

### INV-A-02 — 授权、签名与语义绑定各自成立

- **要求：** Authority 必须验证服务端认证的 caller scope、该操作授权及其可独立确定的规则，并将决定精确绑定到原请求、身份、效果/结果、Audit 与版本。有效签名不代替这些检查。
- **对象/范围：** 受支持的确定性操作和签署内容；不声称观察 Core DB 或客观世界写入。
- **前提：** T3、T4；摘要前像定义必须真实存在，caller 不能靠请求字段自认证。
- **分类：** Safety / 授权与语义完整性。
- **禁止：** 未知语义照签、仅校验摘要长度、用 label hash 代替 effect/empty effect/identity/scope/payload preimage，或把 claimant attestation 写成独立效果观测。
- **未知/冲突/失败：** 语义未定义、作用域失配或不可重算时拒绝新决定；已有不明来源签名不能直接用作本地提交许可。
- **反例/验收：** 替换 caller/身份/候选语义而保留可验签外壳仍被接受即违反；未来须用真实共享前像验证有效案例与逐字段变异拒绝。
- **来源/状态：** B §3–6、§10；K-F3 §2–4、§6；E-F3 仅 v1 范围。X A-02/B-02 P2 OPEN；D-01/D-02 未冻结，本文不定义新前像。

### INV-A-03 — 最终资格与历史读取分离

- **要求：** 创建新 terminal 时在实际最终事务的序列化边界重检该动作的当前资格：Authority/pin/身份/GENESIS/owner/epoch/state、各自 generation、admission/barrier、lease/session 及时间；旧 PREPARE 不授予永久权限。读取已成立历史不再创造一次决定。
- **对象/范围：** 当前 mutation 的 PREPARE 与 terminal finalize；ABORT 仍需其明确授权与“无本地业务提交”断言，不是自动清理。
- **前提：** T1–T4；具体 eligibility 以 K-F3 为限，未来恢复/治理资格尚需 D-03。
- **分类：** Safety / fencing 与时间有效性。
- **禁止：** 仅凭缓存状态/进程锁/事务开始时间批准迟到提交；过期 lease 被人工口头豁免；把历史 receipt 当新写许可证。
- **未知/冲突/失败：** 新决定资格失配则拒绝；保留 pending/历史证据，不把拒绝解释为已 ABORT。历史读取也须认证正确作用域。
- **反例/验收：** 并发改变任一适用 fence 或在签名等待期间到期后仍新提交即违反；真实 DB 应验证迟到路径拒绝且既有历史原样可查。
- **来源/状态：** B §5；K-F3 §3–5；E-F3 有界 DB race/clock 证据。N 保留；全生命周期资格闭合、正式权限及恢复入口仍未验收。

### INV-A-04 — 可见证据与 Authority 本库事务一致

- **要求：** PREPARE 的 immutable 请求与 signed Ack 同事务成立并在提交后返回；terminal 签名、所认证决定、对应 Authority effect、receipt、sequence/head 同事务成立后才能作为已接受结果暴露。
- **对象/范围：** Authority 自身持久事实；签名服务内部候选字节不是已提交证据。
- **前提：** T1–T4；目标 DB 事务与提交边界可观察。
- **分类：** Safety / 本库原子性。
- **禁止：** 未提交先回成功、签名失败留下 canonical 半终态、回滚消耗 canonical terminal 序列、据此推断 Core 与 Authority 两库同时提交。
- **未知/冲突/失败：** 提交前失败不产生接受结果；提交结果未知由同 ID 查询区分，不能假定事务一定回滚。
- **反例/验收：** 在签名前后/finalize/提交响应断连窗口观察到部分 canonical 决定或重复序列即违反；验收须重读实际 DB 状态，不只统计异常。
- **来源/状态：** K-F3 §4、§8；E-F3 对独立测试 PostgreSQL 有界 PASS。B §5；N 保留；非正式 migration/catalog Acceptance。

### INV-A-05 — 重放原 bytes，不重新制造历史

- **要求：** 同 operation ID 与精确原内容的重复操作返回原 Ack/terminal 字节、序列、hash、签名；同 ID 内容/授权冲突拒绝。历史查询是读取真实记录，不重新签署或重建。
- **对象/范围：** Authority 的 authenticated query 与显式 POST retry；二者所需授权材料不同。
- **前提：** T1、T3、T4；POST retry 需原 canonical authorization bytes，GET 需正确认证读取 scope。
- **分类：** Safety / 内容幂等性。
- **禁止：** 新 key/current head 重签旧结果；仅因已获读取认证的 GET 未附终态 POST 授权，就把实际已存历史报为不存在；不同 POST 决定被当相同 retry 接受。
- **未知/冲突/失败：** 证据丢失/范围不符不能补造；查询失败不是 NOT FOUND。原历史被证明存在时不得因为另一个候选未被接受而删除。
- **反例/验收：** 完成其它操作后重放旧 ID 的 bytes/sequence/hash 变化即违反；相同内容应原样，冲突内容应拒绝且历史不变。
- **来源/状态：** B §5–6；K-F3 §5；E-F3 有界重放证据。N 保留；无跨 arbitrary rollback 恢复历史保证。

## 6. Core 不变量

### INV-C-01 — 身份和原意图先于网络持久化

- **要求：** Core 在任何 Authority 调用前保存该操作的原授权来源、冻结请求、mutation→operation 映射、local_commit_id 与 requested decision。当前 continuity 身份不可变且与 qingyu_identity_id 为 1:1；alias 不参与授权。
- **对象/范围：** 正常 mutation INTENT 与输入边界；新 identity/GENESIS 的建立不由这个规则授权。
- **前提：** T1–T4；已有经独立准入的身份和 GENESIS；输入在等待前冻结为不可变内容。
- **分类：** Safety / 意图和身份持续性。
- **禁止：** PREPARE 先于所需 durable INTENT、retry 生成第二 operation/identity、改 alias 重建身份、外部 mutable 输入在签署期间改变请求。
- **未知/冲突/失败：** 持久化失败不得发送；同 mutation 映射不同原意图应冲突，缺失 GENESIS 不自行初始化。
- **反例/验收：** 网络首次可见时无法从已提交记录重建精确原意图，或 restart 将 ABORT 原意图改为 COMMIT，即违反。
- **来源/状态：** B §5–6；K-F3 §1–2、§5；E-F3 有界 INTENT/mutable-origin/restart 证据；N 保留，新 bootstrap 未实现。

### INV-C-02 — dispatch 选择持久互斥

- **要求：** 同一 durable operation 的发送选择必须与不可变原 decision 一致且互斥；终态 POST 前保存精确 authorization bytes、已验证 Ack 与所需不可见 staged evidence。发送或重发仅使用已落盘的选择。
- **对象/范围：** Core COMMIT/ABORT dispatch，区分 PREPARE 前的 requested decision 与终态 POST 前形成的精确授权。
- **前提：** T2–T4；同操作并发由真实持久事务序列化；本文不新增 CAS 实现。
- **分类：** Safety / 选择不可变。
- **禁止：** 两个分支都获本地发送资格、仅内存固定、超时改分支、用重启重算的新内容替换原授权。
- **未知/冲突/失败：** 保留原选择与进度，阻止冲突发送；不得将“未观测响应”当作原选择未发生。
- **反例/验收：** 竞争 dispatch 或 crash 后发出与 durable decision 不同的字节即违反；未来每个持久边界须检验网络观测与落盘事实一致。
- **来源/状态：** B §5、§9；K-F3 §5；E-F3 当前选择/授权持久化有界证据。X 旧恢复循环仍 OPEN；本条不授予 CLOSED 下的新恢复写权限。

### INV-C-03 — HTTP 不确定性不改变事实或 ID

- **要求：** POST 非 200、超时、连接/进程中断或响应验证不足后，Core 以原 ID 查询并验证实际 Authority 事实，再依合同决定下一步；错误本身不决定 COMMIT/ABORT/不存在。
- **对象/范围：** PREPARE/terminal 的不确定窗口、重试和 startup reconciliation。
- **前提：** T1、T4；可信查询须绑定正确 Authority/operation/scope；T6 仅对恢复活性适用。
- **分类：** Safety；条件性 liveness 由 INV-R-03 单列。
- **禁止：** UNKNOWN→SUCCESS/FAILED/ACTIVE、异常自动 ABORT、换 ID 重发、由本地无 receipt 推断远端未提交。
- **未知/冲突/失败：** 保留原进度与不可变输入，禁止相关新业务写入；查询仍不可得则继续 UNKNOWN，不能猜测结果。
- **反例/验收：** Authority 已提交但响应丢失后出现第二终态/另一 operation/自动 abort 即违反；应同 ID 找回原 terminal 或显式保留未知。
- **来源/状态：** B §5–6、§9；K-F3 §5–6；E-F3 有界断连/重试证据。N 保留，永久不可用不保证最终成功。

### INV-C-04 — 完整终态验证先于本地效果

- **要求：** Core 对实际原 terminal 校验 canonical trust/pin、签名、Authority tuple、operation/request、身份/scope、版本、原 candidate/result、Audit/receipt 链位置及适用原授权，再判断本地收尾资格；验签成功不是这些关系全部成立。
- **对象/范围：** 历史 terminal 读取与本地应用；COMMIT/ABORT 都须对应其分支绑定。
- **前提：** T1–T4；若新语义/代际衔接未定义，不能自动套用 v1 映射。
- **分类：** Safety / 消费者验证。
- **禁止：** receipt 到达即宣布本地一致、跳过原请求/Audit 校验、相反 terminal 被本地选择覆盖，或以签名绕过恢复 admission。
- **未知/冲突/失败：** 已充分证明的 Authority 终态作为历史事实保留；本地授权/候选不相容则隔离，不应用不明效果，不编辑任一方。现有本地路径可能仅支持原分支，不能声称相反终态的自动落实已实现。
- **反例/验收：** 任一签名仍有效但语义/链/作用域失配的 receipt 被本地应用即违反；冲突路径应无 canonical 本地效果变化。
- **来源/状态：** B §5–6、§9.2；K-F3 §5–6；E-F3 有界原分支 finalize 验证，非完整例外/恢复流程证明；D-01/02/03。

### INV-C-05 — 本地效果、Audit、receipt 与 checkpoint 一致

- **要求：** 经合法验证与收尾授权后，本地选定效果、Audit、receipt、state/head/cursor 在单个本地事务中一致发布；COMMIT 推进规定业务版本，ABORT 不推进业务版本但落实其规定 Audit/receipt/head。
- **对象/范围：** 本地 canonical materialization，不包含预先持久化的 INTENT/staging。
- **前提：** T2–T4；已验证正确 terminal、所选 Audit 与当前 checkpoint，具备适用本地收尾权限。
- **分类：** Safety / 本地原子性及至多一次落实。
- **禁止：** 部分成功、ABORT 发布 commit Audit/业务效果、重复 finalize 再推进版本、以“无业务效果”省略 ABORT 的正式审计。
- **未知/冲突/失败：** 本地事务失败保留远端终态已成立这一事实和待落实状态；重读判定是否已完整提交，不向 Authority 创造补偿终态。
- **反例/验收：** 故障注入后只能观察完整一致或尚未发布；当前 wire v1 receipt 的 core_audit_candidate_hash 仍保留 commit 候选，ABORT 实际 audit 经 abort_result/result_payload_hash 绑定。漏查其中任一关系即违反当前 v1 合同。
- **来源/状态：** B §5；K-F3 §2、§5；E-F3 的 Core-local 使用 SQLite，不能证明 Core 目标 PostgreSQL 的并发/事务；D-07 保留。

### INV-C-06 — 历史链与本地 projection 不替代 Authority

- **要求：** 本地 canonical state/metadata、Audit 与 receipt 必须逐项关联其已准入 GENESIS 和保存的历史位置；检查实际 hash-bound 内容，不只看 mutable projection。重放旧结果使用原 cursor/hash，不使用当前全局 head。
- **对象/范围：** 当前单 continuity Core-local checkpoint 与历史消费；Authority 序列全局性仍保留。
- **前提：** T1–T3；原链锚及必要历史可获得；全链校验不等于环境 provenance 证明。
- **分类：** Safety / 历史关联完整性。
- **禁止：** 用 READY/status 位重建 Authority history、缺口填零、自行跳 cursor、用其它 continuity 最新 head 伪装原操作前序。
- **未知/冲突/失败：** 记录缺失、链冲突或跨 continuity gap 时停止相关业务发布且保留待调查；不宣称现有 F3 支持跨 continuity 同步。
- **反例/验收：** 后续 mutation 发生后旧 receipt 改变，或仅修 projection 即通过失配链检查，均违反；完整验证要关联原序号、内容、版本、身份及 head。
- **来源/状态：** K-Core Restore reconciliation / Historical receipts；K-F3 §5；E-Core F2/F9 与 E-F3 各自有界 PASS。D-03/04/07 不因此消失。

### INV-C-07 — 信任来源和组件能力不混用

- **要求：** Core 只通过获准、认证的 Authority API 获取控制平面事实，不获得 Authority SQL/receipt signer/Root 私钥；也不直连 Gateway DB。使用 canonical public/pin 和已核验部署，不以调用者构造的对象替代机器信任来源。
- **对象/范围：** Core/Authority 边界、TLS 与冻结 Windows acceptance 信任边界；Gateway 只沿既有只读 Evidence 边界，本文不设计新接口。
- **前提：** T4、T5；test-only 与 production profile 明确隔离。
- **分类：** Safety / 权限与信任隔离。
- **禁止：** TOFU/运行时生成 Root、fallback 到直连或 memory、向未通过既有 TLS/hostname/SPKI 条件的连接释放 bearer，或把 signed origin 当实际观测的替代。
- **未知/冲突/失败：** pin/部署/身份失配即 fail closed；不替换信任材料使其通过。
- **反例/验收：** 有效 CA/hostname 但错误 SPKI 的连接收到 HTTP credential 或能借任意 public 对象启动 canonical path 即违反；仅在相关实现将来变化时做影响范围回归。
- **来源/状态：** B §5–6；K-F3 §1、§6；K-Core TLS before HTTP；K-Win/K-Root；E-Win/E-Core F4/E-F3 历史限定 PASS。本轮未现场复核 pin/ACL/服务。

## 7. Operator 不变量

### INV-O-01 — Test-only Root 的 custody 与 pin 边界

- **要求：** acceptance Root 仅为 R1_ACCEPTANCE_TEST_ONLY；用户已允许在当前 Windows acceptance 主机本地 ceremony 建立，不能再称独立离线信任根。私钥加密保存在仓库外，passphrase 只由用户交互输入，public/fingerprint/Registry64 pin 按既有 fail-closed 合同预置。
- **对象/范围：** 人工 provisioning/custody 与应用消费 public trust；不是本轮 Root 操作授权。
- **前提：** T4、T5；受信任管理员和受保护 custody 边界，既有 root-loader 合同不被本文放宽。
- **分类：** 环境责任 + Safety / trust bootstrap。
- **禁止：** secret 进 Git/CLI/log/report/Codex、应用/API/migration 自动生成或替换 Root、TOFU、test Root 升格 production，或未经生命周期结束授权立即销毁。
- **未知/冲突/失败：** Root/pin 缺失、冲突、丢失或轮换需求时停止依赖它的新动作，保持现状等待独立明确处理；不偷偷重置。
- **反例/验收：** 缺 pin 仍启动、配置可指定新 Root 自动接纳、创建后自动删除需重签的私钥均违反。未来 production 必须独立离线 ceremony，不能复用本 test Root。
- **来源/状态：** K-Root 的本地 test-only custody amendment、K-Win；E-Win 历史 PASS。N 保留；本轮不读取秘密或现场 pin，不声称新验证。

### INV-O-02 — 环境来源责任不变成历史裁决权

- **要求：** Operator 对恢复来源、当前 Authority、身份/链/版本、旧实例处置与重新准入的明确治理选择负责；系统仍验证所有可验证前提。人工授权是选择，不是“事实已成立”的替代证据。
- **对象/范围：** 部署、restore/clone/re-admission 和需要人工判断的例外，具体恢复权限由后续合同冻结。
- **前提：** T1、T4、T5；provenance 必须有可追溯环境/备份/部署材料，不凭新 UUID 或自洽链。
- **分类：** 环境责任 + Safety / 权限上界。
- **禁止：** COMMITTED→ABORTED、UNKNOWN→SUCCESS、手工造历史/stamp 追认、覆盖原授权、豁免签名/语义/fences、用 Core state 重建 Authority。
- **未知/冲突/失败：** 不能证明来源或历史相容就保持相关写入关闭并记录缺失项；需要新的前向治理动作须先定义、审查和授权。
- **反例/验收：** 单凭 Operator 的“确认”按钮使冲突历史变一致或使过期原 lease 有效即违反；准入必须能指出具体证据及未满足条件。
- **来源/状态：** B §4–10；U-恢复边界；N 保留责任，D-03/D-04/D-06 的具体机制未完成。不是恶意 Operator 防护保证。

### INV-O-03 — 最小权限与迁移授权分别验收

- **要求：** provisioning/migration/runtime/reader/DB operator/Root signing 能力必须按其不同职责隔离。迁移前的独立目标与权限基线 PASS 仅允许获准首次 migration；迁移后实际对象、grants/default privileges 与负向行为也须 PASS，才能计入正式 Acceptance。
- **对象/范围：** 未来全新隔离 R1 目标和正式受审 migration；不得复用 Gateway/legacy 资源。
- **前提：** T4、T5；精确签署对象、部署及数据库观测相符；DB owner 的管理权限不被描述成不可绕过。
- **分类：** 环境责任 + Safety / 最小权限与授权阶段边界。
- **禁止：** runtime DDL/base DML/owner 继承越权、reader 写入、PUBLIC/schema/default privileges 泄漏、以 SQL 文件代替真实权限检验、以初始 Signed Intent 覆盖未签目标或 rotation。
- **未知/冲突/失败：** 角色/owner/继承/search_path/默认权限/catalog 指纹不明则阻止相应阶段；不新建替代环境伪称历史证明，不放宽要求。
- **反例/验收：** 正式验收须真实检查 owner/role/inheritance/search_path/default ACL、运行允许与拒绝矩阵。migrator 的获准临时 owner 窗口拥有该 owner 的实际权限，不得声称其中是语句级强隔离。
- **来源/状态：** B §7.2、§10；D-Owner 为静态设计、D-Intent 仅 initial provisioning 草案；K-F3 §4、§7–8 的有界测试不是正式矩阵。D-07 保留，本轮不执行。

## 8. Recovery 与跨组件不变量

### INV-R-01 — 不合并事实、权限、进度与未知

- **要求：** 保留 §4 五个独立观测维度；某一维度通过不得代替另一维度。合法 terminal 前协调持久化与 terminal 后 canonical materialization 有不同证据要求。
- **对象/范围：** 跨组件状态解释、恢复与对外成功报告；不规定新增字段或状态转移。
- **前提：** T1–T4；每类实际写入有明确的已有或未来经批准权限依据。
- **分类：** Safety / 状态表达与报告真实性。
- **禁止：** ACTIVE⇒operation 完成、terminal⇒本地已提交、本地 READY⇒准入通过、UNKNOWN 清除已固定 decision、无 terminal⇒所有持久化禁止。
- **未知/冲突/失败：** 保留已知维度并单独标注未知/冲突；正常写入关闭不自动授权恢复写入。
- **反例/验收：** 对“Authority COMMITTED、Core 待落实、admission closed”必须能分别回答三项事实；系统或验收若只能报告一个成功/失败位而掩盖差异即不满足。
- **来源/状态：** B §1、§5、§9；K-F3 §5；U 对状态/写入类型的明确区分。N 文档级要求；不宣称已有所有 inspector 状态。

### INV-R-02 — 普通 crash 不被改名为 restore 来免除恢复义务

- **要求：** 故障分析必须区分完整持久历史上的 ordinary crash 与 restore/clone/存储替换。重启不自动恢复写入资格，但不能仅把全部普通重启改成人工恢复来关闭旧 pre-dispatch deadlock。
- **对象/范围：** 故障分类、startup/re-admission 条件及恢复验收；不承诺自动识别任意隐藏物理 rollback。
- **前提：** T1、T2、T4–T6；能核验完整原记录的普通故障场景与来源不明的恢复场景分开列举。
- **分类：** Safety + 条件性 liveness 的范围约束。
- **禁止：** 靠恢复出的 READY 自动开放、把“每次都找人工”直接当旧 P1 CLOSED，或擅自宣称所有普通 crash 已有自动处理机制。
- **未知/冲突/失败：** 连续性/资格不明时关闭依赖该条件的新写入；记录原因，不抹去 ordinary intact case 的可达性验收义务。
- **反例/验收：** 原授权及历史完整、组件恢复可用后仍只有“先 ACTIVE 才能 resolve / 先 resolve 才 ACTIVE”即违反恢复要求；添加人工入口字样而无合法可执行路径不算消除。
- **来源/状态：** U 本轮区别要求；U-恢复边界允许不能直接证明连续性时人工 re-admission，并倾向保守启动；B §9 是建议、§10 待裁决。K-F3 §5 已有 admitted-scope startup 行为，不证明新模型恢复。X A-01/C-MIN-01 仍 OPEN。

### INV-R-03 — 可检查的条件性恢复可达性

- **要求：** 对约定的普通 crash 边界，在 T6 条件满足时，后续设计须给出有限、合法且不循环依赖正常 ACTIVE 的处理轨迹：复用原 ID/授权并核实远端事实，最终一致落实已获准决定、清除该操作协调阻塞，或指出真实不满足条件的具体证据。仅无限拒绝不能作为 T6 满足时的成功。
- **对象/范围：** 原意图已持久但尚未 PREPARE、已发未确认、已 PREPARED 未固定精确 dispatch、已固定 dispatch、远端 terminal 未本地落实，以及本地完成响应丢失六类持久窗口。
- **前提：** T1–T4、T6；同连续性且所需历史完整。T6 不以 ACTIVE/无 pending 为前提；合法权限缺失、已撤销或永久外部失败属于明确不满足条件，不被无限扩大来排除全部 restart。
- **分类：** 条件性 liveness，并受全部 safety 约束。
- **禁止：** 恢复依赖自己必须先完成的条件、把 quarantine 永不离开当恢复 PASS、新 ID/自动 ABORT/免检写入作为出口。
- **未知/冲突/失败：** 无法证明 T6 时允许有证据的 BLOCKED；若条件已满足却没有合法路径，记录恢复缺陷，不能把这种缺陷伪装成预期安全停机。
- **反例/验收：** 后续须对每个窗口提供从实际落盘记录出发的有限合法轨迹、权限依据、断连重试及最终重读结果，并验证 fair/stable 调度下无循环等待；测试选定有限次数展示可达路径，不以一次成功证明所有调度。冲突/撤销等拒绝路径另测。
- **来源/状态：** B §7.2、§9–10；U；N 的可验收恢复义务。X A-01 P1/C-MIN-01 P2 仍 OPEN；D-03 尚无获批完整权限/路径；本文无 bypass。

### INV-R-04 — 历史终态不授予当前恢复或新写权限

- **要求：** 旧 lease/session 后来过期不反转先前成立的 terminal；接受其历史真实性不开放当前新写入。本地尚需落实时仍须核对原请求、原候选、状态/代际绑定与明确合法收尾资格；跨代际处理不得临时猜规则。
- **对象/范围：** terminal replay、本地待落实、restore/clone re-admission 与 generation 变化。
- **前提：** T1、T3–T5；原证据可验证；合法历史验签与当前权限的关系可区分。
- **分类：** Safety / 时间、代际与权限分离。
- **禁止：** 用签名刷新旧 lease、re-admission 自动改旧 operation 的 generation、修改历史匹配新环境、用新 UUID 证明旧 clone 已隔离。
- **未知/冲突/失败：** 保留既有 terminal；缺收尾资格或不明跨代际映射时关闭相关写入，等待明确前向处置，不能制造新 terminal 替代。
- **反例/验收：** 历史查询在合法读取范围返回原证据，同时未准入环境仍拒绝新写；若本地收尾需等待合同，应明确缺项而非反转 terminal 或假称已完成。
- **来源/状态：** B §5 的历史/许可区分、§9–10；K-F3 §5 历史读取；N 保留。D-03/D-04 未完成；不将现有普通 finalize 外推为跨代际恢复支持。

### INV-R-05 — GENESIS、首链与代际来源不可补造

- **要求：** canonical identity/initial ownership 与 committed GENESIS 的关联、duplicate prevention、失败 attempt 永久证据与 canonical receipt #1 的区分必须有独立冻结规则；首个 predecessor/Audit head、V1→后续及 generation opening 必须明确接续可验证原历史。
- **对象/范围：** 初始 GENESIS、attempt、链锚及后续代际/版本衔接；不是新状态机或本轮 GENESIS 实现。
- **前提：** T1、T3–T5；已接受的来源/初始授权事实可核验，不能由待证明状态自证。
- **分类：** Safety / 身份、历史与 lineage。
- **禁止：** 失败 attempt 消耗本应由成功 GENESIS 占有的 canonical receipt #1、constructor/migration 自造 GENESIS、零头/新 seed 替代缺失旧 lineage、按文件名或本地状态补历史。
- **未知/冲突/失败：** 无可信锚或无法解释 predecessor/owner/identity 时拒绝 bootstrap/准入；不新建第二身份来绕开残留 attempt。
- **反例/验收：** 后续必须展示失败 attempt 留证但未占 canonical receipt #1、成功 attempt 唯一占有首 receipt，且具体首链和旧 origin 到新代际映射可核验；本轮只保留验收义务，不提供新编码。
- **来源/状态：** B §5、§7.2、§10；U 已明确 attempt 与 canonical GENESIS 区别；K-F3 §1 把已 committed GENESIS 作为前提而非实现。X A-03 P2 OPEN；D-04；C01 延期不删除这些义务。

### INV-R-06 — 完整输入依赖与摘要语义先于新协议实现

- **要求：** 后续冻结须从真实原 request（含 commit Audit commitment 及 abort_result 内的 abort Audit commitment）开始，闭合 candidate 对 request/payload digest 的引用、结果/签名绑定及双方独立重算的全部依赖；不能只画 certificate→envelope 下游。每个摘要的真实 preimage、版本、效果和空效果、identity、caller scope 必须无歧义。
- **对象/范围：** 后续可能采用的新格式与现有 v1 的兼容边界；本文只规定完成条件，不决定保留/替换何字段。
- **前提：** T3；列举实际源输入而非占位 label；K-F3 原 bytes 不能被默默重解释。
- **分类：** Safety 的设计前置条件 / 可检验性。
- **禁止：** 自引用依赖被遗漏、label vectors 宣称语义已冻、无依据宣称所有摘要域分离、未签字段获得治理意义、新代码先行任选 preimage。
- **未知/冲突/失败：** 任一前像/依赖/旧新映射不明则新协议与产品 Design 保持 BLOCKED；保留旧源字节，不修模型粉饰。
- **反例/验收：** 双方基于同一实际语义输入重算所有 hash 并得到相同规范 bytes，逐层可追溯无未定义/循环输入；改变任一治理语义须触发正确绑定变化/拒绝。当前 request hash 是 SHA256(canonical request bytes)，不能统称已域分离。
- **来源/状态：** B §3、§10；K-F3 §2、§4；源 app/control_plane/r1_commands.py 与 r1_protocol.py 的现有 request hash；X B-01 P1、A-02/B-02 P2 OPEN；D-01/D-02，本文未冻结新 bytes/vectors。

### INV-R-07 — 例外授权不能编辑原 decision

- **要求：** 若后续保留 override/强制解决，每个授权身份必须绑定唯一不可变内容及其原操作/前序/scope/reason；同 ID 同内容仅重放、不同内容冲突。合法前向例外不得原地修改原授权或反转已成立 terminal。
- **对象/范围：** 已明确仍需裁决的 exception/manual recovery 责任；不是新 override API、字段格式或默认使用许可。
- **前提：** T1、T3–T5；须先有另行批准的规则与权限，普通 retry 不属于新例外授权。
- **分类：** Safety / 授权不可变性。
- **禁止：** 重用 ID 改 candidate/decision、用 Operator 签字覆盖终态、模型忽略冲突仍当生产证明。
- **未知/冲突/失败：** 无合同不得通过普通路径执行例外；同 ID 冲突保留原内容并拒绝，不删除前序。若要删减该治理能力须独立用户裁决。
- **反例/验收：** 旧模型 trace 中 override ID 1 重用而内容变更须被忠实建模为冲突；后续还需实际竞争终态优先和合法前向动作证据，不能只修模型计数。
- **来源/状态：** B §3、§8、§10；K-F3 §5 明确未来 forced resolution 不等于普通 ABORT；X C-MIN-02 P2 **模型忠实性缺陷** OPEN，不是生产事故；D-06。

### INV-R-08 — 初始信任、旧签名验证与 rotation 不混同

- **要求：** 保留现有 canonical public/pin、Authority identity/key 映射及历史签名验证义务；新 key label/rotation 需要真实合同或明确范围裁决。初始 provisioning 的 Signed Intent 不授权轮换。
- **对象/范围：** Root/receipt key/pin identity 和历史跨 key 边界；本文不设计轮换协议或宣布延期已批准。
- **前提：** T3–T5；当前固定 pin 合同可核验，D-Intent 作用域仅 initial provisioning/migration。
- **分类：** Safety + 设计范围前置条件。
- **禁止：** 把 APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION 解释成 old/new key rotation、虚构现成 rotation contract、为取得 PASS 静默删除该义务、自动替换 pin。
- **未知/冲突/失败：** 缺映射/rotation 合同时不执行该能力；记录待用户决定项及受影响历史验证，维持旧 Finding。
- **反例/验收：** 后续须提供明确范围裁决；若保留轮换则独立冻结并验收新旧 key identity、授权边界和历史验证。如果延期也必须明确用户批准与固定 pin 下的拒绝语义，而非本文自行裁定。
- **来源/状态：** B §3、§8、§10；K-Root；D-Intent 的 initial-only schema；X B-03 P2 OPEN；D-05 未决定，本文不提升 proposed 内容。

## 9. 六类旧 Findings 的逐项追踪

以下是**旧产品/模型问题**，不是因缺机制而自动生成的本轮文档 Finding。
本轮写清要求不解决机制、不降级、不关闭旧问题；任何本文自身的矛盾/歧义仍必须由本轮 Reviewer 正常提出。

| 原编号、严重性、来源与状态 | 旧问题 → 对应不变量 | 本轮明确了什么 | 仍缺机制/证据；为何仍 OPEN |
|---|---|---|---|
| **A-01 P1 / C-MIN-01 P2**；X-A、X-C、X-STOP；Lead 保留根因 P1；**OPEN** | pre-dispatch restart：resolve 需 ACTIVE，ACTIVE 又需 resolve → INV-C-02/03、INV-R-01/02/03/04 | 分离 admission/operation；完整普通故障有可检查条件性恢复义务；永久拒绝不是活性 | D-03：每个持久窗口合法、非循环的恢复权限与有限轨迹；没有实现、执行或修复旧反例，也没有新 bypass |
| **B-01 P1**；X-B、X-STOP；**OPEN** | 原 request 内 Audit commitments 与新 candidate request/payload 引用未闭合 → INV-A-02、INV-C-04/05、INV-R-06 | 明确从真实上游 request 两个分支 Audit 绑定开始，不能只验下游 certificate 图 | D-01：完整 bytes 依赖、保留/替换与版本关系及真实输入的可重算证明；未冻结新字节，图未证明闭合 |
| **A-02 / B-02 P2**；X-A、X-B；**OPEN** | effect、empty effect、identity、caller scope、payload preimage 未定义 → INV-A-02、INV-C-04、INV-R-06 | 签名/语义/效果观测分开；label hash 不够；当前 request hash 不笼统宣称域分离 | D-02：精确共同前像与 Authority 独立语义规则、真实 vectors/变异拒绝；本轮不提供格式或测试 |
| **A-03 P2**；X-A；**OPEN** | GENESIS、V1→V2 首 predecessor/Audit head 与 opening lineage 未闭合 → INV-C-06、INV-R-04/05 | 保留 origin evidence、身份/initial owner、attempt 与 receipt #1、旧新边界，不准缺口填零 | D-04：独立初始/代际/版本衔接合同及证据；既有 v1 seed/DR helper 不证明新 V1→V2 映射或 canonical GENESIS 完成 |
| **B-03 P2**；X-B；**OPEN** | rotation contract 缺失、key label 未映射 pin identity → INV-C-07、INV-O-01/03、INV-R-08 | initial Signed Intent ≠ rotation；是否延期仍待用户决定 | D-05：明确范围裁决或独立 rotation 合同、old/new key/history 验证规则；本轮未授权删除义务或建立机制 |
| **C-MIN-02 P2**；X-C、X-STOP；**OPEN** | 同 override ID 1 绑定冲突内容仍在模型中通过 → INV-C-02、INV-A-05、INV-R-07 | 同 ID 内容不可变、冲突拒绝、例外不改原历史；仍是模型忠实性缺陷 | D-06：若保留，需授权/前序/竞争终态规则和忠实模型及实现证据；模型、vectors、原反例均未改、未重跑 |

## 10. 后续前置条件：仅列责任，不启动工作

| ID | 必须先交付的决定/设计/证据 | 责任与目前缺口 |
|---|---|---|
| D-01 | 从真实 request/Audit commitments 到 candidate/result/terminal 的完整无歧义依赖及版本映射 | Core + Authority 共同负责；B-01 未闭合；不得先写代码选一种解释 |
| D-02 | 支持操作的 effect/empty effect、identity/scope/payload 等精确语义和前像、双方重算与真实变异测试方案 | Core 构造并验证、Authority 独立校验；A-02/B-02 未闭合；不以签名正确代替语义 |
| D-03 | 明确普通 crash 与 restore 的准入/恢复权限，覆盖 INV-R-03 六类窗口；合法收尾与新写入分开且无循环前提 | 用户先决定建议的权限范围，三方再冻结合同并独立审查；A-01/C-MIN-01 仍在，不擅自引入 RECOVERY_ONLY API |
| D-04 | GENESIS identity/initial ownership、duplicate prevention、attempt 与 receipt #1、V1/后续首链及 generation opening provenance | Authority/Core 验证规则 + Operator 来源；A-03 未闭合；新 UUID/签名不自证来源 |
| D-05 | 是否保留/延期 rotation 的明确范围裁决；保留时才单独冻结 key/pin/授权/旧历史验证合同 | 用户裁决 + trust 责任双方；B-03 未闭合；初始 Signed Intent 不够 |
| D-06 | 若保留 override/forced resolution，明确不可变 ID/content/前序、权限及 terminal 优先；若删减须用户单独决定 | Authority 验证、Core 消费、Operator 有界前向授权；C-MIN-02 模型忠实性缺口未闭合 |
| D-07 | 独立设计审查及明确实施授权后，才有真实目标 DB/schema/migration 指纹、迁移前后权限、Core PG 并发、崩溃路径及 inspector 证据 | 既有 F3 临时 PostgreSQL + Core SQLite 不代替正式验收；第三方安装依赖也需实际 closure，源码 digest 本身不冻结安装环境 |
| D-08 | 仅受影响范围的 Windows trust/signature/deployment/identity/public-pin ACL 回归，以及独立产品 Reviewer 无 P0/P1/P2 | 未影响部分保留 scoped PASS；文档审查不授权签名、部署、migration、Candidate Freeze、产品 Gate 或 Foundation Closure |

以上是后续工作的必要条件，不是本轮自动排程或新实现授权。本文不决定 Revision naming、不修改旧合同，
不创建新模型/字节/vector/数据库对象。用户本轮的 STOP 条件高于任何自动返工流程。

## 11. 证据索引与当前验证界限

### 11.1 可读依据

| 标记 | 实际依据与适用状态 |
|---|---|
| B | [本轮冻结 Boundary](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/boundary-snapshot.md)，以原 docs 为链接基准；[新 disposition](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/boundary-disposition.md) 及其三份新报告。文档 PASS，不是机制获批 |
| K-F3 | [Coordinator contract](CONTROL_PLANE_R1_COORDINATOR_CONTRACT.md) v1，已独立 admitted ACTIVE GENESIS/owner/session/lease 的有界 mutation 路径；§1/5/7/8 排除初始签发、完整恢复及正式 migration |
| K-Core | [Core invariant contract](CONTROL_PLANE_R1_CORE_INVARIANT_CONTRACT.md)，原 aggregate BLOCKED 中“F3 缺失”是当时事实，由之后 E-F3 **限定范围**结果接续；F1/F2/F4/F9 要求保留，不能把旧标题当当前 F3 从未实现 |
| K-Win / K-Root | [Windows Identity contract](CONTROL_PLANE_R1_WINDOWS_IDENTITY_CONTRACT.md)、[Root provisioning](CONTROL_PLANE_R1_ROOT_PROVISIONING.md)，已接受的本机 test-only identity/custody 边界，不对抗已控制的管理员 |
| D-Owner / D-Intent | [Owner contract](CONTROL_PLANE_R1_OWNER_CONTRACT.md)、[Signed Intent contract](CONTROL_PLANE_R1_SIGNED_INTENT_CONTRACT.md)，静态设计/实现草案的 pending acceptance 状态；后者只支持 initial provisioning/migration，不是 accepted rotation 机制 |
| E-Win | [Windows Identity report](CONTROL_PLANE_R1_WINDOWS_IDENTITY_REPORT.md)：历史 7,146 检查、0 failure、283 passed / 4 legacy skipped；不在本轮现场重验 |
| E-Core | [Core Invariant report](CONTROL_PLANE_R1_CORE_INVARIANT_REPORT.md)：历史 367 passed / 4 legacy skipped；F1/F2/F4/F9 各自范围，较早 F3 缺项不抹掉后续有界证据 |
| E-F3 | [F3 Coordinator report](CONTROL_PLANE_R1_F3_COORDINATOR_REPORT.md)及[原 Reviewer A](evidence/r1-f3-coordinator/reviewer-a.md)、[B](evidence/r1-f3-coordinator/reviewer-b.md)、[C](evidence/r1-f3-coordinator/reviewer-c.md)：485 passed / 4 legacy skipped / 415 warnings；Authority 独立测试 PostgreSQL/TLS，Core-local SQLite，不是正式权限/migration Acceptance |
| X-A / X-B / X-C | 原 [Minimal Trust A](evidence/r1-acceptance-marathon/minimal-trust-design-review-a.md)、[B](evidence/r1-acceptance-marathon/minimal-trust-design-review-b.md)、[C](evidence/r1-acceptance-marathon/minimal-trust-design-review-c.md)：三方 BLOCKED，原 Finding 与等级保留 |
| X-STOP | [Minimal Trust disposition](evidence/r1-acceptance-marathon/minimal-trust-disposition.md)、[STOP probes](evidence/r1-acceptance-marathon/minimal-trust-stop-probes.md)：被拒绝的模型/向量不能作为新要求已实现的证明 |
| X-候选 | [Minimal Trust model contract](CONTROL_PLANE_R1_MINIMAL_TRUST_MODEL.md)、[ADR-R1-007](adr/ADR-R1-007-MINIMAL-TRUST-PIVOT.md)：候选 rejected / ADR proposed；C01 延期裁决单独保留，不提升候选机制 |
| E-Checkpoint | [checkpoint](evidence/r1-acceptance-marathon/minimal-pivot-checkpoint.md)：HEAD/tag 保存既有实现；前后各 485/4 的记录中仅前次 raw log 独立留存，后次来自原任务输出；不是新设计证明 |
| 源码只读定位 | [r1_commands.py](../app/control_plane/r1_commands.py)、[r1_protocol.py](../app/control_plane/r1_protocol.py)、[r1_local_store.py](../app/r1_local_store.py)、[r1_service.py](../app/r1_service.py)：仅核对当前术语/bytes/能力边界，不执行、不修改 |

U 为本轮授权附件 `293b8e6c-bc91-419c-9600-48c2019b2260/pasted-text.txt`。
U-恢复边界为 Boundary/旧 Reviewer 直接引用的用户裁决附件
`2b339ff3-c6a2-4175-9168-dc272d154596/pasted-text.txt`（均在 `D:/codex2/attachments/`）。
后者明确 restore/clone 不自动准入，无法直接证明连续性时宁可人工重新准入；
它不使 rejected 候选的完整每次启动状态机或未定义恢复权限获批。本轮新要求明确保留 ordinary crash 义务。

### 11.2 本轮审查与保护

本文及其独立快照由 Lead 编写；三名非作者 Reviewer 的新原始输出、时间、SHA-256 和最终结论另存本轮证据目录。
阶段 A 的 PASS 不能复用为阶段 B PASS。出现本文自身 P0/P1/P2、OPEN 或 PARTIAL 时保存结果并 STOP，
不自动实质修补后换 Reviewer/重审；结构性 P1 立即停止设计扩展。

当前依据 HEAD 为 `e490134ba9ced81be182b4c24eb41c970258f325`，
分支 `ai/task-r1-canonical-implementation`，tag `r1/pre-minimal-trust-pivot-e490134`。
工作树允许 dirty。原 `<repo>/core` 的 9 个 tracked dirty 文件和 diff object
`9594b6b6f5374094a88bcb068d5bcd7afd875d18` 须在任务最终只读复核。

本轮没有新产品测试结论。文件哈希/出处/文档独立审查只证明本轮文档范围，不证明原 root/pin/live ACL 现在有效，
不证明 Gateway/数据库现场状态，也不证明普通 crash 路径、字节合同或模型已经修复。
最终核验、实际原始审查路径与 STOP 以本轮 disposition 和 LONG_RUN_STATE 追加记录为准。
