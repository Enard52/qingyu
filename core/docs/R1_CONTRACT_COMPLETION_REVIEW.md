# R1 Contract Completion Review / 必要合同补齐审查

任务：`R1_CONTRACT_COMPLETION_REVIEW`。作者：Lead `/root`。
**合同完整性：BLOCKED / NOT FROZEN。** 独立 Review 在本受审正文完成后进行；最终结果另存 disposition，正文不回写 PASS。
Boundary 与 Invariants 的既有文档 PASS 保留；Implementation Gate、Minimal Trust Design 仍 BLOCKED。
本报告不是 Minimal Trust Revision 2，也不是任何产品 Candidate Freeze。

## 1. 本轮补齐的层次与不能代行的决定

本轮把六类要求展开成可查的现行定义、前置/失败条件、绑定关系和缺项清单。
其中已有 v1 定义按原义保留；新恢复权限、新终态格式/首链、rotation 范围和 override 治理选择，不能由“补齐”二字自动授权。
**有明确条款不等于六份合同已完整冻结；本报告如实保留 OPEN/PARTIAL，因此不具备推进实现的条件。**

每节都分别列出：

- **已接受 invariant**：来源于已 PASS 不变量的要求；不表示实现已全部满足。
- **可明确的现行合同/边界**：既有 scoped 合同和实际源码已经规定的内容，或不变量的直接条件化展开；不新增权限、字段或操作。
- **缺失 contract**：仍没有唯一规范定义的输入、规则或跨边界关系，状态 OPEN。
- **需要用户决策**：涉及范围/权限/兼容目标的选择，不把技术细节都转嫁给用户。
- **不属于 R1 范围**：仅使用已经授权的延期/威胁模型边界；“本轮禁止”不等于“R1 永久删除”。

约束：本轮不改产品、旧合同、模型、vectors、历史 Review 或反例，不写代码、不跑产品/模型/DB 测试；
不创建 migration、不进行 PostgreSQL Acceptance、Signed Intent、Candidate Freeze、IBCS 或 Revision 2；
不访问秘密、现场 Root/pin/ACL、Docker/数据库，不执行 Git 版本写入。
仅新增本报告、必要受审/Review 证据及追加长期状态。出现 P1/P2/OPEN/PARTIAL 后保存结果 STOP，不自动实质修补重审。

### 1.1 可追溯的依据

| 依据 | 本报告使用的效力 |
|---|---|
| [Boundary](R1_CONTROL_PLANE_BOUNDARY_REVIEW.md)；SHA-256 `2aac26bd0b95a0b85cc2a869133676e7f4e96b059423c67404842cc8beb35845` | 职责/范围文档；§9 恢复建议仍受 §10 的后续决策约束 |
| [Invariants](R1_CONTROL_PLANE_INVARIANTS.md)；SHA-256 `bb7d769a170fe0ade9c6c6faf743c9ade4022b4f7fa211389f6ff2e5276a47b5` | 23 项已审查的要求、T1–T6 信任前提、D-01–D-08 缺口；不是完整协议证明 |
| 上轮 [Boundary disposition](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/boundary-disposition.md)、[Invariants disposition](evidence/r1-acceptance-marathon/boundary-fresh-20260915T125431Z/invariants-disposition.md) | 当前两份文档的实际新 A/B/C 审查依据；更早历史 Boundary Reviewer 原文仍 NOT LOCATED，不重新认证历史过程 |
| [Coordinator v1](CONTROL_PLANE_R1_COORDINATOR_CONTRACT.md)，简称 K-F3 | 已独立准入 ACTIVE GENESIS/owner/session/lease 的 mutation 合同；排除完整 bootstrap/DR/治理发行与正式 migration |
| [Root provisioning](CONTROL_PLANE_R1_ROOT_PROVISIONING.md)，简称 K-Root | 已接受本机 test-only 加密 custody / canonical pin 边界；Root 不在线替换 |
| [Initial Signed Intent](CONTROL_PLANE_R1_SIGNED_INTENT_CONTRACT.md)，简称 K-Intent | 静态 initial-provisioning 草案，尚无可执行目标准入；**其 envelope version 2 不是被拒绝的 terminal V2 协议**，也不授权 rotation |
| 旧 [Review A](evidence/r1-acceptance-marathon/minimal-trust-design-review-a.md)、[B](evidence/r1-acceptance-marathon/minimal-trust-design-review-b.md)、[C](evidence/r1-acceptance-marathon/minimal-trust-design-review-c.md)、[disposition](evidence/r1-acceptance-marathon/minimal-trust-disposition.md)、[STOP](evidence/r1-acceptance-marathon/minimal-trust-stop-probes.md) | 保留原六类 P1/P2、OPEN 与模型反例；rejected 候选不能成为本轮自动 accepted 的合同 |
| [F3 evidence](CONTROL_PLANE_R1_F3_COORDINATOR_REPORT.md)、[Core evidence](CONTROL_PLANE_R1_CORE_INVARIANT_REPORT.md) | 历史 scoped PASS；F3 Authority 临时 PostgreSQL / Core-local SQLite，不是正式 R1 Acceptance 或新恢复证明 |

### 1.2 当前定位与完整性

工作树 `<repo>/core-r1-implementation`，分支 `ai/task-r1-canonical-implementation`，
HEAD `e490134ba9ced81be182b4c24eb41c970258f325`，既有 tag `r1/pre-minimal-trust-pivot-e490134` 指向同 HEAD。
本轮接管 219 个既有 tracked/非忽略 untracked 文件与上轮收口证据一致；主交付路径此前不存在。
原 Core 仍 9 个 tracked dirty，原 diff object
`9594b6b6f5374094a88bcb068d5bcd7afd875d18` 实测匹配。
完整快照/来源哈希和最终保护复核另存本轮 evidence，不改变旧报告。

## 2. Recovery Contract / 恢复合同

### 2.1 已接受 invariant

INV-C-01–06、INV-A-01/03/05、INV-O-02、INV-R-01–04；尤其 T6 的条件性活性。
必须分开判断环境准入、原操作进度、Authority 终态、本地效果与 UNKNOWN。
Authority 历史已成立不等于当前进程有新写权限；无限停机不是完整普通 crash 的恢复成功。

### 2.2 可明确的条款

**REC-01 — 故障分类不改变授权。** ordinary crash 指原指定持久存储、身份、请求、授权及链未丢失/未换副本，
可核验其连续性的进程中断；restore/clone 指恢复备份/快照、复制、替换存储或不能直接证明连续性的环境。
这是一项分类前提，不是系统拥有自动识别任意 rollback 的能力。两类都不能仅凭保存的 READY 位恢复正常写权限。
已有 F3 的 startup reconciliation 仅在 K-F3 的独立 admitted 上下文及适用资格内复用原操作；不能外推成完整恢复 ceremony。

**REC-02 — 保留原选择与持久证据。** 网络前已有 durable INTENT、原 request/decision/ID；
terminal POST 前已有精确 authorization bytes。恢复不重建第二 ID，不更换原 COMMIT/ABORT 选择；
相同 ID 的不同内容为冲突，不得因异常或超时生成 ABORT。已充分验证的远端相反 terminal 作为历史保留，
本地原授权/候选无法解释时隔离，不覆盖历史，也不声称当前 Core 已支持这种例外自动落实。

**REC-03 — UNKNOWN 是知识不足。** 非 200、超时、断连、进程中断、验签或绑定信息不足，均不足以证明
SUCCESS、ABORTED 或 NOT FOUND。必须保留原进度并按原 ID/正确 Authority/认证 scope 查询。
只有可信的正确对象查询结果才能说明未找到；它也不单独授予重发或新建 identity 的权限。
证据永久不可得可 BLOCKED，但不能把尚未取得证据转写为 canonical history。

**REC-04 — 权限按动作分别判定。** 以下是现有边界的条件说明，不是新增恢复入口/角色/API：

| 动作类别 | 必须满足的边界 | 当前合同能否提供完整恢复权限 |
|---|---|---|
| 查历史、核对原请求/链 | 正确部署/信任来源和认证读取 scope；不生成终态。历史 GET 不需要新的终态 POST 授权 | K-F3 §5 定义已准入服务内读取；不证明未准入新部署已经可以启动查询服务 |
| INTENT/Ack/dispatch/待协调持久化 | 按该阶段获准权限，原 ID/content 不变；无 terminal 不禁止这些合法协调记录 | K-F3 已有 admitted mutation 路径；CLOSED/restore 中可做哪些写入仍缺 |
| 创建新 terminal | 当前动作授权、locked current fences、有效 lease/session/epoch/owner/state/generation；PREPARE 非永久许可证 | K-F3 普通路径已定义；过期/跨代际/强制解决不是普通 retry |
| 应用已成立 terminal | 完整历史/语义/原候选校验，加适用本地收尾资格；本地效果/Audit/receipt/head 单事务 | 原分支有界 finalize 已定义；恢复环境的权限和跨代际映射未冻结 |
| 开放新业务写入 | 适用独立准入证据与当前资格，且相关 unresolved 阻塞已合法解决 | 不能用原 READY 或人工一句“已确认”代替；完整 re-admission 合同仍缺 |

**REC-05 — 非循环前置条件。** 需要保留“新业务写入前先解决 pending”时，
合法旧工作恢复资格的取得就不能同时要求“先正常 ACTIVE”；不能靠临时开放全部写入打破环。
T6 成立的普通 crash 必须有有限、合法、保留原意图的处理轨迹。
权限已撤销、证据丢失或永久不可用是具体不满足前提的原因；“恢复设计尚不存在”不能被包装成所有普通故障都不适用 T6。
本文不选择取得这种有限资格的机制，亦不批准 Boundary 的 RECOVERY_ONLY 作为可执行方案。

### 2.3 缺失 contract / OPEN

| 持久窗口 | 已确定的恢复约束 | 仍须冻结的定义 |
|---|---|---|
| 原意图落盘、未 PREPARE | 原 ID/内容/decision 保留 | 新运行上下文凭什么可继续同 ID PREPARE |
| PREPARE 已发、Ack 未确认 | 先查同 ID；未知不造结果 | 读权限的取得与可信未找到后的合法动作 |
| PREPARED、精确 dispatch 尚未落盘 | 不改原 requested decision | 非 ACTIVE 下如需固定选择，其独立权限、检查时点和拒绝条件 |
| dispatch 已固定 | 仅原 bytes 可重发 | 当前资格尚有效/已失效时的分别处理；不能口头豁免 fence |
| Authority terminal、本地未落实 | 不反转 terminal；先验证原候选 | 恢复收尾资格、状态/代际相容规则，以及相反终态的冲突处理责任 |
| 本地已落实、响应丢失 | 验证原 receipt/Audit 并幂等重放 | 不将“可以重放历史”混为“可以开始下一次业务写入” |

需同时给出每个窗口在 T6 下的有限轨迹和拒绝路径；不能由测试 fixture 或旧模型的 PASS 推导权限存在。
**Recovery completion：PARTIAL / NOT FROZEN。A-01 P1 / C-MIN-01 P2 仍 OPEN。**

### 2.4 需要用户决策 / 不属于 R1

- **需要用户决策 Q-REC：** 明确普通完整 crash 的重新准入责任，以及正常新写入保持关闭时允许处理哪些既有工作、
  由谁授权、什么原资格可继承/什么必须重新取得；不能仅批准状态名称。
- **不属于 R1：** 已延期的自动 clone/rollback 发现、任意回滚的全局 exactly-once、恶意受信任管理员防篡改、
  无条件最终恢复。普通完整 crash 和明确的人工恢复责任仍在 R1，不因上述延期删除。

## 3. Byte Binding Contract / 字节绑定合同

### 3.1 已接受 invariant

INV-A-02/04/05、INV-C-01/02/04/05/06、INV-R-06。
固定原 bytes，身份/授权/结果/Audit/receipt 关系须可重算，同 ID 冲突拒绝，不重签历史、不省略上游输入。

### 3.2 可明确的现行 v1 绑定

以下来自 K-F3 §2–5 和当前静态源码；不是设计新格式。JCS 指现有
`r1_protocol.canonical_bytes`；CoreJSON 指现有 `app/canonical.py:canonical_json`。
**二者不是可互换编码器**：前者为 RFC 8785，后者为 ensure_ascii=True、sort_keys=True、紧凑 JSON UTF-8。
此定义仅复述现有用途，不声明 CoreJSON 是通用安全 JSON 协议。

| 对象 | 现行确定定义 / 绑定 | 保留与拒绝要求 |
|---|---|---|
| request | request schema 1 的 exact fields；完整 payload 内已有两分支 Audit commitments 和结果。request_envelope_hash = SHA256(JCS(完整 envelope))；immutable request_wire 是实际输入 | 不只 hash 业务 payload；不添加前缀后称原字节未变；未知字段/版本、重复键或不规范 wire 按原 decoder 拒绝 |
| requested decision / authorization | requested decision 随 source INTENT 在 PREPARE 前冻结；终态 authorization 是独立的 exact version-1 COMMIT/ABORT 命令，绑定 operation/request/local_commit/staged result/Audit predecessor/commit candidate，加各分支证据字段 | 不把这两个保存时点合为必须提前拥有 Ack 后才能产生的授权；POST retry 需原 authorization bytes |
| result | COMMIT 的 staged_result 与 ABORT 的 abort_result 分别 JCS 后普通 SHA256；前者递增业务版本，后者保持版本并含实际 abort Audit hash | 两者已纳入 request；ABORT 结果不是空对象，也不能发布 commit Audit |
| Audit | 两个分支 Audit 行先用 CoreJSON 固定 raw bytes，再 SHA256(raw bytes)。其中 payload_hash 也沿 CoreJSON 原规则；created_at 是生成时保存的原值，重试不能刷新 | 不重编码成 JCS，不在恢复时重建时间/内容；发布只能选择与已验证 terminal 匹配的预冻结行 |
| PrepareAck | 原版本/字段及 request/staged result/Audit 绑定；签名使用原 PREPARE_PREFIX + JCS(不含 ack_signature 的字段) | 由 Authority 提交 PREPARED 后返回；不是 terminal，也不证明 Core 已提交效果 |
| receipt | 原 v1 terminal exact fields；签名是 RECEIPT_PREFIX + JCS(不含 receipt_signature 的字段)，receipt_hash 则为 SHA256(RECEIPT_PREFIX + JCS(包含签名的完整 receipt)) | 保留原 signed bytes、序列和 predecessor，不用当前 global head 替换，不增添未签治理字段 |

现行 evidence hash 是已有 Core stage 函数中固定前缀加
`request_wire || ack_wire || commit_audit_wire || abort_audit_wire` 的 SHA256；
COMMIT/ABORT 保存于各自证据字段，ABORT 另有 `no_local_business_commit=true`。
这是当前 v1 的精确构造事实，不是新设计，也不把 claimant evidence 当 Authority 对 Core DB 的独立观察。

**BB-01 — 存储绑定不等于 receipt 直接签署每个输入。**
当前 SQL 保存不可变 `f3_authorization_wire` 并记录其 SHA256；同 terminal POST 冲突字节被拒绝。
但 v1 receipt 的 exact schema **没有 authorization_digest 字段**。
因此可陈述“Authority 按已认证的精确授权决定，并在持久操作记录中保留关联”，
不能陈述“单凭该 receipt 可重算/证明整个 authorization 原文的直接摘要绑定”。
以后若要求新的独立 certificate 拥有这种能力，需要明确合同，不能暗加字段。

**BB-02 — 两分支 Audit 绑定不可合并。**
v1 receipt 的 `core_audit_candidate_hash` 始终保留 PREPARE 的 COMMIT candidate；
ABORT 的实际 Audit 通过 `result_payload_hash → abort_result → abort Audit hash` 绑定。
验证者必须同时核验原 commit-candidate 绑定和选中结果分支，不能把顶层字段改义为“当前分支 Audit”。

### 3.3 Digest dependency direction / 真实依赖方向

这里 `X → Y` 表示“Y 的构造或验证使用已确定的 X”，不是新协议步骤或数据库写权限。

| 层 | v1 实际已确定的输入顺序 |
|---|---|
| 原输入 | 已准入 scope/checkpoint + 冻结业务输入/decision + 一次生成并保存的 IDs/原 Audit 时间 |
| 本地候选 | 先构造 COMMIT/ABORT Audit bytes/hash 与 staged/abort results；结果和 Audit 输入不是从未来 receipt 反算 |
| 完整 request | 上述候选/结果及各自 hash → request payload → request_wire → request hash |
| 协调证据 | request 与已提交 PREPARED → signed Ack；request/Ack/两份 Audit bytes → stage evidence → exact authorization |
| Authority terminal | exact authenticated command + 当前 fences + 原 request/候选/选定 result → Authority 原子决定和 signed receipt；授权的存储关联见 BB-01 |
| 本地发布 | verified receipt + 原 request/authorization/candidate/保存 cursor + 适用收尾资格 → 本地一致发布；不回写新的候选到原 request |

这只能说明当前有界 v1 的依赖，不能关闭新候选的完整图问题：
rejected V2 candidate 自身要求 request/payload digest，而复用的 request 已要求 Audit commitments。
commitment 指旧独立 Audit、新 candidate 还是最终 Audit，其保留/替换关系仍没有获准的唯一答案；
把 certificate 之后的子图列成有向无环并不能消除这条上游回边。

### 3.4 缺失 contract / 决策 / 范围

- **缺失 contract：** 新目标的完整对象清单、版本/编码、request 内旧 Audit commitment 的准确含义、candidate 对 request/payload 的引用、
  authorization 到独立 terminal 的直接或间接验证边界，以及旧证据消费规则。不能以“原 v1 可解释”代表这些新关系已定义。
- **需要用户决策 Q-VERSION：** R1 是否仍要求新的 V2 terminal/Audit 格式及 V1→V2 共存边界；若保留，
  后续允许补齐到哪一层精确字节合同。当前用户要求本节审查，不等于允许本轮新协议；本文也不自行删去 V2 要求。
  具体字段/前缀应由团队在批准范围内设计，不要求用户手工编写。
- **不属于 R1：** 任意跨外部系统效果的分布式原子证明、IBCS/transparency/witness 扩展；本轮不造新 vectors。
- **Byte completion：PARTIAL / NOT FROZEN；B-01 P1 OPEN。**

源码出处：[r1_protocol.py](../app/control_plane/r1_protocol.py) §REQUEST_FIELDS/RECEIPT_FIELDS、canonical_bytes、request_envelope_hash、
verify_terminal_receipt、receipt_hash；[r1_commands.py](../app/control_plane/r1_commands.py) §§PAYLOAD_FIELDS、AUTHORIZATION_FIELDS、MutationIntent；
[local store](../app/r1_local_store.py) begin_intent/stage/finalize；
[CoreJSON](../app/canonical.py)；[F3 SQL](../app/control_plane/r1_f3_candidate.sql) 原 authorization 保存及 terminal 重放。

## 4. Semantic Digest Contract / 语义摘要合同

### 4.1 已接受 invariant

INV-A-02、INV-C-04/05、INV-R-06。格式正确或签名有效不等于业务语义正确；
Authority 应独立检查其能确定的语义规则，不声称观察 Core DB 或客观世界已执行。

### 4.2 可以明确什么，仍不能把什么视作等价

| 语义对象 | 现行可明确的定义 | 缺失 contract / 不能擅自选择的前像 |
|---|---|---|
| effect / 效果 | F3 COMMIT result exact fields 是 mutation_id/state_version/value；实际 Core value 封装 payload、capability、requested_decision；业务 state_version 是 expected+1 | 新 effect_value_digest 究竟覆盖整个 staged_result、value、value.payload 或别的语义对象没有定义；确定性并不能选出唯一含义 |
| empty effect / 空业务效果 | ABORT 不产生 COMMIT 业务效果，不递增业务版本，但需要非空 abort_result 和独立 Audit/receipt/head 更新 | 尚无新 empty-effect 对象及其 digest 规则；不能任选空映射/空列表、删除 Audit，或以 abort_result_hash 冒充已定义 empty-effect digest |
| identity / 身份 | 当前 F3 是精确 UUID 的 qingyu_identity_id/continuity_id pair 加 committed GENESIS operation ref；alias 不赋权；owner/version 另受 fence 检查 | 新 canonical_identity_digest 的 exact fields/preimage/version/domain 未定义；不能自行把 owner 可变状态混入或漏掉必须身份锚 |
| scope / 作用域 | 现有 AuthenticatedCaller 的六项是 domain、continuity、runtime、session、storage-generation、actor；由服务端认证取得并与请求核对，非 body 自认证 | 新 authorization_scope_digest 的对象边界、是否/如何包含 lease/owner/epoch 等请求资格、exact encoding/domain 未定义；字段列表不是新的签名 scope 合同 |
| payload preimage / 载荷前像 | request hash 覆盖完整 JCS envelope；result hash 覆盖各分支 result；Core Audit payload_hash 沿 CoreJSON 对 mutation_id、value、outcome decision 的映射 | 新 payload_digest 指原业务 payload、带 decision 的 source request 还是完整 wire payload 尚未选定；三者不能互称 |

**SD-01 — 明确校验职责。** Core 构造受治理结果和 Audit，Authority 验证其可解释的请求、结果规则与绑定，
Core 消费终态后重算并一致落地。现有精确字段校验不证明任意 payload 的业务含义已经有定义，
也不证明 Authority 观察了 Core 物理事务。

当前 Authority command 对 staged_result 固定的是外层 mutation/version/value 结构；Core producer 的 value 投影不能被描述为
所有可接纳请求都已通过独立业务语义验证。当前 prepare store 接收 request、caller、staged/abort result bytes，
没有接收两条完整 Core Audit wire；不能据此声称 Authority 已独立重算全部 Audit 内容。
这标明旧 F3 scoped evidence 的上限，不撤销其限定 PASS，也不把新候选要求当成旧生产事故。

**SD-02 — 编码与语义同时必要。** 后续每个新 digest 必须同时标明输入对象、字段来源/包含与排除项、
规范化/拒绝规则、version/domain 与双方重算责任；不能仅给 H256 类型或公开 label hash。
现行 request/result 的普通 SHA256 不得笼统称为已 domain-separated；
receipt/Ack 的既有签名 prefix 不能移植成未定义语义 digest 的前缀。

### 4.3 需要用户决策 / 不属于 R1 / 处置

- **需要用户决策：** 先确认 Q-VERSION 的兼容目标及受治理操作范围；若拟超出当前 mutation 状态/结果语义，
  需明确范围授权。已确认范围内的 exact preimage 定义属于团队合同工作，不能用反复追问用户代替。
- **不属于 R1：** 将任意外部世界副作用或用户 proposition 的客观真实性纳入签名证明；不引入新的泛化执行协议。
- **Semantic completion：PARTIAL / NOT FROZEN。A-02/B-02 P2 仍 OPEN。**
  本轮指出不可互换的精确现行对象，但没有擅选新 effect/identity/scope/payload 定义来关闭问题。

## 5. Genesis / Lineage Contract / 创世与历史接续合同

### 5.1 已接受 invariant

INV-C-01/06、INV-R-04/05、INV-A-01；initial owner、immutable identity、duplicate prevention、
失败 attempt 留永久证据但不占成功 GENESIS 的 canonical receipt #1，以及首链/代际 origin 仍必须定义。
C01 自动反回滚延期没有删除这些基础责任。

### 5.2 现行 v1 能保留的精确定义

**GL-01 — Authority v1 首 receipt。** 当前 `r1_protocol.py:395–419` 的 sequence 1：
generation 1 只接受 COMMITTED/ACTIVATED 的 AUTHORITY_GENESIS_ACTIVATION，携带 signed origin digest；
后续 generation 只接受相应 AUTHORITY_DR_ACTIVATION，并要求 previous_generation = current-1 及原序列/head/DR artifact 绑定。
这说明 validator 接受什么，不证明 issuance/恢复 ceremony 已实现。

**GL-02 — Authority seed 与 Core Audit head 不混用。**
`genesis_head_seed` 使用既有 GENESIS_PREFIX 与 JCS 对象，含 domain/instance、generation 1、
provisioning UUID、已验证 signed-origin digest、receipt-key ID、Operator-Root-key ID；不是任意零头，也不凭 hash 自证来源。
现行 Core 从已验证 GENESIS receipt_hash 建立后续 Authority cursor（next sequence 2），
本地首 Audit predecessor 为 null，其首行 hash 须等于已准入 GENESIS evidence 的 Audit hash。
Authority receipt predecessor 与本地 Audit predecessor 是两条不同的绑定，不得互换。

**GL-03 — V1 evidence 原样验证。** 旧 receipt、签名、origin、Audit bytes/head 按其原版本验证和保存；
不能重新序列化、重新签名、转成 V2 对象后称历史本来如此，不能靠本地 state 或一个新 UUID 补 provenance。
通用 `verify_generation_opening` helper 不等于现行 Core 已有完整 DR admission。

### 5.3 缺失 contract / OPEN

| 必须回答的边界 | 当前答案与禁止默认值 |
|---|---|
| first V2 predecessor | **UNDEFINED**：尚无受批准的 V1 receipt hash→V2 predecessor/sequence 规则；不得默认 zero、重 hash V1 或另开无来源链 |
| first V2 Audit head | **UNDEFINED**：必须说明消费的是哪条经验证 V1 Audit、其原 bytes/hash 和新高水位关系；Authority 头不能代替 Audit 头 |
| V1 evidence handling | 原版本验证与不改历史已确定；V2 读取/接续旧证据的具体规则未冻，不能把保留原文件当衔接已成立 |
| generation opening | v1 检验公式存在；新目标下 pin/key/old head/新 admission/旧 pending 的关系及授权范围未冻 |
| GENESIS attempt 与 receipt #1 | 区别是已接受要求；仍缺 initial ownership、duplicate prevention、attempt 永久证据的位置/绑定及何时唯一成为 canonical GENESIS 的完整合同。本文不发明新日志或对象 |

### 5.4 需要用户决策 / 不属于 R1 / 处置

- **需要用户决策：** Q-VERSION 须明确是保留现有 v1 消费边界，还是要求新 V2 接续以及哪些历史版本/初始与恢复场景纳入。
  具体 predecessor/编码由后续已批准的合同工作给出，不能在本轮禁止新协议时暗选。
- **不属于 R1：** 自动证明任意 clone 已不存在、外部单调 witness/IBCS、从副本自证最新性。
  V1 原历史核验、GENESIS 和明确的 generation lineage 仍在 R1。
- **Genesis/Lineage completion：PARTIAL / NOT FROZEN；A-03 P2 OPEN。**
  源码：[v1 protocol](../app/control_plane/r1_protocol.py) genesis_head_seed/verify_generation_opening；
  [Core-local](../app/r1_local_store.py) constructor/_audit；[admission](../app/control_plane/r1_admission.py) 的 GENESIS 验证入口。

## 6. Key Rotation Scope / 密钥轮换范围

### 6.1 已接受 invariant

INV-O-01、INV-C-07、INV-R-08：固定 canonical trust 来源、test-only 不升格 production、
旧签名真实性不因新权限变动而重写、initial provisioning 授权不等于 rotation 授权。

### 6.2 必须按 key 类型分别判断

| 对象 | 已接受/现存边界 | 缺失 contract 与范围状态 |
|---|---|---|
| Operator Root | K-Root 明确无在线 replacement/rotation；existing key/pin 不覆盖；冲突、丢失、轮换需求必须独立 recovery amendment。acceptance 本机加密 custody 与未来 production offline Root 分开 | 不能把 receipt-key 或 TLS 轮换批准推及 Root；本轮无任何 Root 改动授权 |
| Authority receipt-signing key | 固定 AuthorityPin tuple；receipt_key_id = SHA256(raw Ed25519 public-key bytes)，不是任意文本 label；当前 signer 仅使用预置能力 | R1 是否必须支持 key transition/历史 key 选择与停用边界仍缺明确范围裁决，B-03 未关闭 |
| TLS/SPKI pin | 属于当前端点认证/部署绑定，不能与 receipt key ID 互换；初始 intent 固定目标 TLS origin | 新旧 pin/deployment 变更的授权、兼容/拒绝与历史证据关系未由 initial-only contract 覆盖；如纳入 rotation 须明示 |

### 6.3 若属于 R1：合同边界，不是轮换协议

必须先界定适用 key 类型和参与方、old/new identity 的可核验关系、允许生效的范围/边界、
历史 receipt 如何选择已被授权的旧 public key、新旧 pending 如何处理、冲突/未知/撤销如何拒绝，
以及谁有权批准、谁验证。**这些是必须交付的边界清单，不是本文提供了新消息格式或轮换状态机。**

当前 K-Intent 的唯一批准是 APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION，generation 1；
其中没有旧/新 receipt key 或 rotation boundary。初始 envelope version 2 与终态 V2 名称相同不产生授权继承。

### 6.4 若延期：必须有明确授权，当前没有

- **需要用户决策 Q-ROTATION：** 明确 receipt-key 与 TLS/SPKI 的 rotation 分别属于 R1，还是延期；同时保留 Root 的现有独立 amendment 边界。
- **缺失 contract：** 保留时需上述合同；延期时需可引用的明确用户范围批准及受影响历史验证、固定 pin 下失效/丢失时的 STOP 责任。
- **不属于 R1：** 已明确禁止的 Root 在线自替换/TOFU、将 test Root 提升为 production；不能据此推断所有 key rotation 都已被用户延期。
- 当前 **rotation 范围未决定，延期授权 NOT PROVIDED**。本报告不选择任一分支。
- **Rotation completion：OPEN / NOT FROZEN；B-03 P2 OPEN。**

## 7. Override Immutability / 例外授权不可变性

### 7.1 已接受 invariant

INV-R-07、INV-C-02、INV-A-01/05：原授权不改写、同 ID 内容不可变、终态不可反转、
普通 retry 不变为新的例外授权。C-MIN-02 是旧模型忠实性缺陷，不是生产事故。

### 7.2 可明确的非协议条款

**OV-01 — ID uniqueness。** 一个已受理的 override 授权身份只能指向一个不可变内容。
不能因失败/重试复用该身份赋予第二内容；不同例外决定需要不同的授权身份且仍须完整验证，
“换一个 ID”本身不产生授权或允许反转 terminal。此处不把 operation UUID 的既有 namespace 自动套给 override；
跨何种 domain/continuity 的 uniqueness、ID 格式及分配方仍须独立冻结。

**OV-02 — content binding。** 被批准的例外必须明确指向原 operation/原授权与前序、适用 scope/reason、
所允许的前向决定/候选语义；其内容在受理时不可变并在 Core/Authority 校验时一致。
这是关系要求，不是新的字段清单、hash formula 或可执行 override 命令。原记录不得被就地编辑。

**OV-03 — conflict behavior。** 同 ID + 经该合同定义的完全相同内容只能重放原受理/结果；
同 ID + 不同内容拒绝并保留原记录。任何路径遇到已成立 terminal 都先保留该历史事实，
不能以“更强签名”覆盖；终态尚未成立时何种前向例外可与普通 dispatch 竞争及如何定序，仍缺合同。
未知远端结果时不自动造 override。

### 7.3 缺失 contract / 决策 / 范围

- **缺失 contract：** override ID 的精确 uniqueness scope/格式/分配责任、内容相等的字节规则、
  原授权/前序关联、批准权限、各 operation type 的允许动作、与原 dispatch/已成立 terminal 的竞争/拒绝边界及永久记录责任。
- **需要用户决策 Q-OVERRIDE：** R1 必需的人工恢复/强制解决具体允许哪些未终态操作和前向动作；
  哪些例外必须拒绝。若要删减原必需治理能力须明确新范围裁决，不能利用“若保留”一词静默删除。
- **不属于 R1：** 任意修改终态、改写原授权、绕过 fences 的万能管理员接口，以及 Byzantine/多见证 override 协议。
- **当前普通 v1 路径无此新权限。** K-F3 §5 明确 Root-authorized forced resolution 不等于普通 ABORT；
  当前 consumer 的 bootstrap/lease/owner-transfer/restore 等生命周期仍拒绝。
- **Override completion：PARTIAL / NOT FROZEN；C-MIN-02 P2 OPEN。**
  同 ID=1 两次不同内容的旧反例仍保留，未修改/重跑模型。

## 8. 六类旧 Findings 的完成门槛

| 原问题与等级 | 本轮提供的明确内容 | 仍 OPEN 的原因 / 后续冻结门槛 |
|---|---|---|
| A-01 P1 / C-MIN-01 P2（根因保留 P1） | REC-01–05、动作资格分类、六个持久窗口 | Q-REC 未决定且完整合法有限路径未定义；需消除循环而不豁免安全 |
| B-01 P1 | 当前两分支 Audit→request 的真实依赖；authorization 存储关联与 receipt 直接绑定的区别 | Q-VERSION/新旧对象关系未决定，完整新图和 exact bytes 未冻 |
| A-02/B-02 P2 | 两套编码和五种语义对象的真实现行定义、不可互换项 | 新 preimage/语义规则未唯一确定；需同一实际输入双方可重算及变异拒绝证据 |
| A-03 P2 | v1 GENESIS seed、首 Audit/head/cursor、origin/DR 检验边界 | first V2/历史衔接、attempt/首 receipt 及 generation opening 未冻 |
| B-03 P2 | Root/receipt/TLS 三类 key 边界和 initial-only Intent 的限制 | Q-ROTATION 未决定；没有受批准的延期或轮换合同 |
| C-MIN-02 P2 | 同 ID/content/前序/终态优先的不可变关系，保持模型缺陷性质 | Q-OVERRIDE 与 exact content/冲突/竞争规则未冻，模型/实证未修复 |

本轮没有将“新增条款”“映射到编号”或“报告忠实”记为旧 Finding CLOSED。
当前六类合同存在 PARTIAL/OPEN，满足用户指定 STOP 条件；只完成本报告的独立核对与证据收口，
不继续填造新协议、不更换候选、不自动下一轮修补。

## 9. 最少需要的后续裁决与责任

| 决策 | 用户应确定的范围 | 团队在获准范围内应负责的合同工作 |
|---|---|---|
| Q-REC | 普通完整 crash 与 restore 的准入责任、正常写入关闭期间允许的既有工作处理范围 | 前提/资格/拒绝规则、六窗口有限路径；不能让用户设计权限检查细节 |
| Q-VERSION | 是否仍引入新 V2 terminal/Audit、兼容哪些 V1/GENESIS/代际场景；后续精确合同设计的授权边界 | 完整请求依赖、两分支语义、实际 preimages、历史接续与 first-link；不擅自放弃 V2 或套用 rejected schema |
| Q-ROTATION | receipt/TLS 的轮换属于 R1 还是明确延期；Root 现有边界不自动改变 | 保留则编写限定合同；延期则精确记录授权和停机/历史验证责任，不能自行选项 |
| Q-OVERRIDE | 必需人工恢复/强制解决的 operation/action 边界；任何范围删减需明确批准 | 唯一 ID/content/前序/权限/并发终态规则及模型忠实性；不创建万能 bypass |

上述缺口不是数据库或 Python 环境问题，不通过搭环境、跑旧测试或创建签名解决。
即使未来必要合同全部冻结并重新审查，也只是后续实施授权/验收的前置，不自动形成 Implementation Gate PASS。
实际实现与目标数据库、迁移前后权限、crash/retry/inspector、独立最终 Gate 仍须其各自证据和授权。

## 10. 独立 Review 与最终保护

Lead 整理本报告，两名只读分析 Worker 提供 bytes/semantics 与 lineage/trust 依据；
他们不是本报告的最终独立 Reviewer。文档完成后由未参与编写的 Reviewer 独立核对同一不可变快照，
保留原始身份、时间、hash、结论与 Finding。作者不代写独立结论。

Review 必须分别说明“报告是否忠实/一致”和“必要合同是否已完整冻结”，不能以第一项代替第二项。
任一 P1/P2/OPEN/PARTIAL 保存结果后 STOP；不自动实质修改受审正文或复审直到 PASS。
产品实现、旧合同、旧候选/模型/vector、历史证据保持不变；LONG_RUN_STATE 仅追加本轮事实。
最终 Review 输出、受审 hash、文件增量和原 Core 保护值以本轮 evidence disposition 为准。

**当前项目状态保持：Implementation Gate BLOCKED；Minimal Trust Design BLOCKED；六类历史 Findings OPEN；
C01 DEFERRED / REMOVED FROM R1 REQUIRED SCOPE；Foundation Closure NOT ENTERED。**
