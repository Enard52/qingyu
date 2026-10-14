# R1 Scoped Control Plane Contract / 有界替代合同候选

任务：R1_SCOPE_DECISION_AND_CONTRACT_DESIGN。候选标识：SCOPED-20260915-01。
状态：一次正式替代设计候选；独立 A/B/C verdict 见本轮 evidence 的 disposition。
本文件不是产品实现、部署准入、Signed Migration Intent 或 Acceptance 结果。
证据目录：evidence/r1-acceptance-marathon/scoped-contract-20260915T151851Z/。
本候选的冻结清单与 SHA-256 见该目录 candidate-manifest.json。

## 1. 权威来源、授权变化与事实边界

优先顺序：本轮用户四项明确裁决；已经 PASS 的 Boundary / Invariants；
本候选在明确获授权范围内的新定义；未被本候选明确替代的既有合同。
既有失败合同及审查原文不修改、不追认。23 项 invariant 的保证不因换名消失。

来源：
- R1_CONTROL_PLANE_BOUNDARY_REVIEW.md，SHA-256 2aac26bd0b95a0b85cc2a869133676e7f4e96b059423c67404842cc8beb35845。
- R1_CONTROL_PLANE_INVARIANTS.md，SHA-256 bb7d769a170fe0ade9c6c6faf743c9ade4022b4f7fa211389f6ff2e5276a47b5。
- R1_CONTRACT_COMPLETION_REVIEW.md，SHA-256 bbb4a7616197e7957d726422187632271b40590bfb231f00a8a24f4596ed9737；及 contract-completion-20260915T135207Z 的 manifest、A/B/C、disposition。
- boundary-fresh-20260915T125431Z 的 Boundary / Invariants 新独立审查与 disposition。更早原文 NOT LOCATED 保留，不补造。
- K-F3 = CONTROL_PLANE_R1_COORDINATOR_CONTRACT.md；K-Root = CONTROL_PLANE_R1_ROOT_PROVISIONING.md；K-Intent = CONTROL_PLANE_R1_SIGNED_INTENT_CONTRACT.md。
- 原 Minimal Trust 审查和 stop-probes，引用沿用上述 completion manifest。
来源字节受 intake 的 226 文件清单保护；本轮不重新定义一套历史真实性。

本轮设计显式替代的窄点：V2 的字节与直接授权绑定、在新业务关闭时的有限恢复资格、
专门 opening/lineage、pending MUTATION 的 Root ABORT 例外。
K-F3 的 V1 ACTIVE/原 lease/session 原样匹配仍是 V1 事实；本候选不倒写 V1。
将来实施 V2 才能采用这里的独立当前 operation execution lease；不得把旧 lease 延长或豁免。

### 1.1 四项范围裁决

| 裁决 | 本候选落地 | 明确不包含 |
|---|---|---|
| Q-REC | 预批 RecoveryPolicy、固定 Inventory、当前 ExecutionGrant、独立 LocalFinishPermit；六窗口恢复保持新业务关闭 | 每次重启人工批准；READY 位自认证；任意 clone/rollback 自动证明；witness/IBCS |
| Q-VERSION | V2 请求/授权/候选/receipt/Audit 完整图；真新 GENESIS、停写 V1→V2、明确 generation opening | 热升级、混合 canonical writer、双写、自动降级、在途改版本、重编码/重签 V1 |
| Q-ROTATION | 固定 Operator Root、receipt key、HTTPS origin/SPKI；精确 key mapping；失效停止 | 三种密钥互换；receipt/TLS rotation；自动换钥恢复同身份；完整生产密钥生命周期 |
| Q-OVERRIDE | 仅未终态 MUTATION 的独立 Root-signed forward ABORT；保持原 dispatch | forced COMMIT、历史反转、fence bypass、GENESIS/lease/owner/key/restore 强制终态 |

Operator Root 仍遵守 K-Root：R1_ACCEPTANCE_TEST_ONLY，已授权本地 Windows acceptance ceremony，
不能声称独立离线生产 Root；加密仓库外 custody、用户交互 passphrase、canonical public/Registry64 pin。
本轮只定义新授权 body/验证责任，不读取现场 Root/pin/ACL、不签名、不改变 custody。
未来 production Root 必须独立 ceremony；本 test Root 不能提升。
丢失、失信或更换需另一个受审 recovery amendment，不能把延期写成已经解决。

### 1.2 必须保留的八项 V1 精确事实

1. 原 requested decision 与 source INTENT 在 PREPARE 前持久冻结；依赖 Ack 的 exact terminal authorization 在 Ack/staging 后、terminal POST 前冻结。两者不同。
2. V1 request/result 用其原 RFC8785 JCS；Core Audit 用原 CoreJSON
   （ensure_ascii=True、sort_keys=True、紧凑分隔符、UTF-8）。不互换编码器。
3. V1 request 已带两分支结果与 Audit commitments，不能只画 receipt 的下游图掩盖上游回边。
4. V1 receipt 没有 authorization_digest；Authority 原记录关联不等于 receipt 直接签名证明授权。
5. V1 顶层 core_audit_candidate_hash 是 COMMIT candidate；ABORT 实际 Audit 经选中 abort_result 的 result hash 绑定。
6. ABORT 不产生 COMMIT 业务效果，不增加业务 state_version，但产生非空结果、Audit、receipt、head 更新。
7. Authority 验证其可解释的业务语义、调用来源和承诺，不观察 Core 物理提交或客观世界。
8. Authority PostgreSQL 与 Core-local SQLite 各自原子，不是天然跨库事务。本候选不替换存储架构。

现有 F3 只支持 capability=core_governance，单个独立 provisioned Core continuity。
Authority sequence 仍全局；其它 continuity 消耗的 receipt 不得跳过。未提供跨 continuity 同步协议，缺口 STOP。

## 2. 假设、责任与自动保证的上限

沿用 T1–T6：
T1：完整可信已准入历史与一个获准 Authority 上下文；
T2：各库自身事务持久性，未承诺两库原子性；
T3：完整精确语义与字节合同；
T4：固定可信配置、保护代码、服务端认证来源与当前 fencing；
T5：Operator/管理员/owner/密钥保管方可信，对来源与旧上下文隔离作真实判断；
T6：ordinary intact crash 后服务最终可用、合法资格可取得、公平调度且存在足够稳定的执行后缀。
对于有限时效 grant/permit，还要求最终有一次合法有效期窗口足以完成相应执行/本地收尾；
永久超过 deadline 的调度/传输延迟与不可信时钟不属于这里的条件性可达性证明。
T6 不把 ACTIVE 或 no-pending 作为恢复前提，不覆盖永久网络隔离、缺失/失信历史或无限换代/撤权。

| 责任方 | 必须保证 | 不能声称 |
|---|---|---|
| Core | INTENT/dispatch 精确持久、只走认证固定 API、同 ID reconciliation、独立全证据验证、本地 exact pre/post 与原子 apply | 从本地重建 Authority truth；凭远端签名跳过本地冲突；把 payload 当外部事实 |
| Authority | 独立认证、语义重算、当前 grant/fences、同一事务唯一终态及 receipt/head、不可变字节 query、独立 ABORT 授权 registry | 观察 Core DB 的物理提交；由 receipt 证明世界；用 body 声称的 caller 自认证 |
| Operator | 预批恢复政策、真实来源/隔离判断、固定 trust、限定 opening/restore/ABORT 签署与 custody | 口头确认替代历史；复活旧 lease；用 Root 越过当前 fence 或改历史 |

准入失败不能自动新建 identity/数据库/Root。新 UUID 仅提供对象标识，不提供 provenance。
未知、签名失信、来源不完整或冲突必须关闭相关写入口，保留可解释证据，不“修成一致”。

## 3. 状态维度与最小转换

禁止一个 ACTIVE/non-ACTIVE 枚举吞并所有权限。以下状态是独立维度：
- 来源：UNVERIFIED / INTACT_ADMITTED / MANUAL_RESTORE_ADMITTED / UNKNOWN / CONFLICT。
- 新业务入口：CLOSED / OPEN。
- 当前执行资格：NONE / RECOVERY_QUERY / LIVE_OPERATION_GRANT / LOCAL_FINISH_PERMIT。
- operation 持久进度：INTENT / PREPARED / DISPATCH_FIXED / REMOTE_TERMINAL / LOCAL_FINALIZED。
- 远端知识：NOT_QUERIED / UNKNOWN / AUTHENTICATED_NOT_FOUND / PREPARED / VERIFIED_TERMINAL。
- 本地状态关系：EXACT_PRE / EXACT_SAME_POST / CONFLICT。
- 当前时效：policy、authenticated session、operation execution lease、grant/permit 各自有效或失效。
- generation/fence：Authority、storage、control-plane、owner、epoch、state 分别比较；不是一个共享 generation。

核心序列：

    CLOSED + verify admission/policy/component
      -> seal existing-operation Inventory
      -> query / acquire operation grant
      -> original PREPARE / original semantic dispatch
      -> independently verify historical terminal
      -> acquire LocalFinishPermit
      -> exact-pre atomic apply OR exact-same-post replay
      -> LOCAL_FINALIZED + this operation's recovery block cleared
      -> separately assess normal business admission (not an automatic transition)

operation 的远端状态只有 absent→PREPARED→一个 COMMITTED 或 ABORTED；
UNKNOWN 是观察状态，不是 Authority terminal。
Authority proposal/signing 是事务内临时态，不是可向客户端宣布的新 canonical 状态。
普通受治理 mutation 不得在 PREPARED 内另生 operation ID；本合同的 retry 指原 operation。

### 3.1 非 ACTIVE 原因对应的权限

| 原因 | 允许的有限动作 | 禁止动作 / 退出条件 |
|---|---|---|
| 启动尚未核验 | 本地只读检查；独立获准的 trust 配置读取 | 不网络发业务，不据 READY 位 advance |
| intact + 有效预批 policy | 固定清单协调记录、同 ID query、重新获得当前 grant、原操作 dispatch、合法 local finish | 新业务、清单扩充、owner/key/GENESIS 强制终态 |
| HTTP timeout/non-200/未知响应 | 保存观察、对同 ID 在正确认证 Authority query | 自动 ABORT/override、新 ID、把未验 404 当不存在 |
| session/grant/lease 到期 | 重新认证并给同一 operation 续发新的受限 grant；验证历史终态 | 不复活旧 grant、不改原 request/auth bytes |
| owner/epoch/state 或任一语义 generation 改变 | 历史查询；具明确许可时 exact-pre/post 的历史收尾 | 对 stale 原操作创建新 terminal；不能把 re-admission 当 fence mapping |
| restore/clone/storage 替换/来源不足 | 隔离和人工具体上下文核验；授权范围内历史 replay | 无上下文授权不自动推进，不缩短历史 |
| policy/principal/trust 失效 | 拒绝新授权和新业务；仅有独立有效读资格时读已授权历史 | 不 TOFU、不换 key/pin 继续 |
| 本地或远端冲突 | quarantine，留证据 | 不选一份“看起来对”的结果覆盖 |

## 4. Recovery Contract / 预批政策与当前执行资格

### 4.1 精确记录与验证主体

所有 V2 typed 对象的 exact field catalog、类型、拒绝规则见同目录 codec-schema-catalog.md；
它是本候选规范附件，必须与主文同一 manifest 冻结，不是可任意更新的实现参考。
共同 C2/H2/S2 规则见 §6。时间为 UTC Unix 毫秒。

RecoveryPolicy（Root 签名）的必需字段：
policy_id、deployment_admission_digest、authority_domain_id、authority_instance_id、
authority_generation、continuity_id、qingyu_identity_id、genesis_operation_id、
core_installation_id、storage_generation_id、control_plane_generation_id、
runtime_principal、component_artifact_digest、trust_config_digest、restoration_context_digest（普通为 null）、capabilities、
allowed_operation_type=MUTATION、issued_at、expires_at、operator_root_key_id、root_signature。
restore policy 的 restoration_context_digest 必须等 H2(完整已签 RestorationContext)，只允许
QUERY_EXISTING、APPLY_VERIFIED_TERMINAL、PERSIST_COORDINATION；禁止为旧操作签发新 terminal grant。
policy_id 在该 domain 唯一，byte-for-byte 不可变；更新需要新的 Root 签名 policy ID，
不能覆盖旧记录。当前有效/撤销 registration 与签名 body 分开保存，撤销不改历史 body。
capabilities 是严格排序且去重的以下闭集子集：
QUERY_EXISTING、PREPARE_EXISTING、FIX_ORIGINAL_DISPATCH、TERMINATE_ORIGINAL、
APPLY_VERIFIED_TERMINAL、PERSIST_COORDINATION。
完整自动六窗口恢复要求具备这六项；缺项 policy 不可被标为具备完整恢复承诺。

Core protected loader 独立验证 canonical Root/profile/pin、部署 admission、组件 artifact digest、
安装身份、同一 trust/identity/generation 以及 policy 签名和有效期；不能只从 DB 读一个 READY。
Authority 独立验证 Root 签名、注册状态、同一 deployment/trust/identity/generations，
并以现有服务端认证链得到当前 runtime principal/session，而非相信 body。
预批准主体只限指定受保护 recovery component。Runtime/Migrator 永无 Root signing/private key。

RecoveryInventory 必需字段：
inventory_id、policy_digest、core_installation_id、runtime_principal、session_id、
entries[]；每 entry 只有 operation_id、request_digest、source_decision_digest、local_commit_id。
按 operation_id 严格排序去重。
Core 在入口关闭的本地事务中扫描并固定既有完整 INTENT、原 bytes/本地 checkpoint/stage 记录。
清单允许远端尚不存在的既有 INTENT，不要求每项已 PREPARED；这是 AUTHORIZED 死锁的解除点。
认证 Core 将完整被引用 request/source 交给 Authority；Authority 保存 accepted inventory 原 bytes。
其完整性来自 T1/T4/T5 下受保护 Core 对已存 operation 的可信声明，不是 Authority 对 Core DB 的观测。
仅靠客户端 JSON 无法签发 inventory。后来的 recovery session 需要新的 immutable inventory，
条目必须是本地已有记录的固定集合或已完成后的子集；新业务关闭期间不得新增 payload/ID 混入。
inventory_id 同内容重放、不同内容冲突；Authority 以原 request/source 的 operation 键交叉核验。
恢复 API 接受 existing operation ID，不接受用同 grant 任意传一份新业务请求。

ExecutionGrant 是 Authority receipt key 签署的当前、单 operation 执行租约：
grant_id、grant_sequence、policy_digest、inventory_digest、operation_id、
request_digest、source_decision_digest、authority_domain_id、authority_instance_id、
authority_generation、continuity_id、qingyu_identity_id、genesis_operation_id、
owner_identity、owner_version、continuity_epoch、expected_state_version、
storage_generation_id、control_plane_generation_id、runtime_principal、session_id、
lease_id、lease_generation、issued_at、expires_at、receipt_key_id、receipt_signature。
它不依赖 Ack、StagedEvidence 或 terminal authorization，避免 PREPARED 死锁和新的 hash 回环。
这里 lease_id/generation 是新受限 operation execution lease，不是给过期原业务 lease 改时间。
当前 grant 的 ID、序号、session、lease、deadline 由 Authority 管理；每次续发产生新 immutable body，
原 grant 留存，current pointer 原子切换，新 terminal 只能使用 current grant。
grant 不授予新业务入口，不是 owner takeover 或普通业务 lease issuance 接口。

### 4.2 签发与继承规则

可继承：已核验的 identity/GENESIS、原 intent/payload/decision/source authorization、
operation/local_commit IDs、已保存 Ack/dispatch、已准入历史及同一受保护安装的 policy。
不可继承为当前能力：死进程、旧认证 session、过期 lease/grant、缓存 ACTIVE、未验证 fence。

Authority 在 generation/head→continuity→operation→session/key 的一致序列化顺序中签发：
1. 当前 policy registration、部署和认证 principal/component 正确；policy、session 未过期。
2. inventory 的原 operation/request/source 完整、固定且 scope 合法；原 actor 是已准入 owner。
   body principal 不是授权证明；历史 caller 来源由原认证记录和受保护 recovery assertion 验证。
3. 当前 identity/GENESIS、owner identity/version、epoch、expected state、storage/control-plane、
   Authority tuple 与原 semantic target 完全一致。
4. 本 op 可以是当前唯一 unresolved；不要求没有本 op pending，也不要求 Core 新业务 OPEN。
   其它冲突 unresolved 拒绝；已有 terminal 则返回历史查询路径，不签发再次 terminal 的能力。
5. 产生当前 session-bound 单 op lease/grant；最大 grant 有效期 30 秒，且不超过 policy/session 有效期。
6. policy 允许的动作取交集，禁止所有未注册动作。每次调用仍独立验证完整输入与 scope。

同 policy 同可信部署中的普通 crash 重新认证后可自动取得上述资格，不需要 Operator 每次批准。
正常 ACTIVE 路径也先持久化 INTENT；其进入同样的单 op grant 流程，额外要求当前 normal
business admission 与原普通业务 lease/session 在初次 source admission 时有效。
进入 recovery 后以受限新 grant 的当前资格继续原操作，不能新增 source；原业务 lease只作来源。
policy 缺失/无法确认时不能宣称自动恢复可达；它是生产部署前置条件，不是事故后临时发明。

### 4.3 新 terminal 的最终资格

PREPARE 检查 request/两分支/当前 grant 后，原请求和 signed Ack 同事务持久，不消耗 terminal sequence。
新 terminal 必须从 PREPARED 出发，选择普通 original authorization 或 §9 的单独 ABORT 例外。
最后事务再次检查当前 grant pointer/serial、authenticated session、operation lease、policy、
owner/epoch/state/generation、admission/barrier、Authority/audit predecessor、key/pin 与 action scope。
恢复 admission 是“只允许此 op”，不需要全面 ACTIVE，也不许绕过同 op 的当前 fences。
签名前检查不能代替签名后 finalize 与真实 commit 边界的时间检查：
必须采用当前数据库时钟而非事务开始时间，提交 guard 拒绝被持有至 deadline 之后的事务。
完整 proposal、签名、终态选择、Authority 治理效果、receipt、sequence、Authority head、
可重算的最终 Core Audit head 必须同一 Authority 事务成立；失败均不消耗序号。
Core business effect 仍在后续自己的本地事务，不伪装成这里已经发生。

改变 semantic fence 后，不允许通过重新映射 grant 将 stale 原 mutation 继续写入。
可验证历史 terminal 不被新 fence 推翻；没有历史 terminal 且不能合法取得资格则停止并报告具体冲突。
T6 的普通完整 crash 恢复不承诺在任意管理员换代/永久撤权后还必须完成原新 terminal。

### 4.4 历史终态的 LocalFinishPermit

LocalFinishPermit 必需字段：
permit_id、permit_sequence、policy_digest、inventory_digest、restoration_context_digest（普通为 null）、
core_installation_id、runtime_principal、session_id、operation_id、request_digest、
source_decision_digest、terminal_digest、before_checkpoint、after_checkpoint、
issued_at、expires_at、receipt_key_id、receipt_signature。
LocalCheckpoint 精确为 state_version、audit_ref、authority_ref（及公共 type/version）。
Authority 签署许可和预期前后态，不声称观察 Core DB。

取得许可需要当前认证恢复主体/适用 policy、完整历史 evidence bundle、正确固定 key/version、
receipt/原请求/原 source/实际 authorization/实际 grant/候选/两条链都验证成功。
before 从原 durable intent 的可信 saved cursor 与 expected state 取得；
after 从 verified receipt、选定 AuditContent→AuditRecord 和 state_after 取得，不取最新全局 head。
普通恢复限原 logical installation/storage/control-plane；restore 必须附 §8 的完整 Root 上下文。

历史 grant/lease/session 的“在 terminal 决定时有效”需由完整签名与 Authority 原执行证据验证；
不要求它们现在仍 live。当前 finish 资格与历史 truth 是两个判定。

Core 在自己的单一事务里：
- 当前 local policy/component/session 未被本地受保护撤销，permit 有效且对象/安装/上下文正确；
- 若 exact 原 pre checkpoint、完整 pre audit/receipt 链、该 mutation 尚无 canonical 结果：
  原子发布选定 effect、result、AuditRecord、原 receipt 与 checkpoint、FINALIZED 标记。
- 若 exact 本 op 已保存同一 receipt/结果/Audit 的 post：原样返回，无二次 effect/seq/version。
- 任何第三状态、缺证据、同版本不同 head、已有另一结果：quarantine，禁止覆盖。
单纯 state_version 相同不足以判断 exact pre/post。

有限许可：max 30 秒、不得超 policy/session；Core 对可信时钟误差上限 1000ms 作保守提前到期判断，
时钟保证失效则拒绝 apply。Authority 撤销阻止新 permit；已经发出的有界许可不是跨库即时撤回。
Core 已观察到的本地保护撤销立即禁止 apply。不得声称可以原子地同时观察远端撤销与提交 SQLite。
此有限授权语义不改变历史 receipt，不允许新 terminal；验证模型若抽象为同步撤销只支持该抽象，
不构成真实跨库撤销/时钟证明。

## 5. 六个持久窗口的合法轨迹

全表每一步新业务入口均 CLOSED；先获 policy/inventory 对应有限资格，而非先要求 ACTIVE。
最终节点是 LOCAL_FINALIZED 且此 op 协调阻塞已清除；之后另走正常 admission，不自动开放业务。

| 窗口 | 合法恢复轨迹 |
|---|---|
| W1 INTENT 已落盘，尚无 PREPARE | 固定已有 intent 清单→认证同 ID query；确证 NOT_FOUND→当前 grant→原 request PREPARE→保存原 Ack/stage→固定原选择授权→原 dispatch→验证 receipt→finish permit→本地完成 |
| W2 PREPARE 发出，Ack/响应未存 | 同 ID query；PREPARED 取原 Ack；确证 NOT_FOUND 重发相同 bytes；terminal 取全证据；UNKNOWN 只再 query→余下步骤同 W1 |
| W3 PREPARED，exact authorization 未存 | 在 FIX_ORIGINAL_DISPATCH 资格下由原 source/request/Ack/stage 固定原选择；无需 ACTIVE；取得当前 grant→原选择 terminal→finish |
| W4 dispatch 已存，远端不确定 | 不改原 auth bytes；query；PREPARED 时新 grant + 同 auth 重试；terminal 直接验证；UNKNOWN 只 query |
| W5 remote terminal 已成立，本地未落实 | 验完整 terminal bundle→当前 finish permit→exact pre 原子落实；旧 lease 到期不改变该历史 |
| W6 本地已完成，返回响应丢失 | 验证 exact same post/原 bytes→原样重放；不再次写业务效果，不申请另一次 terminal |

非 200 POST 无论响应 body 声称什么都先进入同 ID reconciliation；
可信 NOT_FOUND 必须来自固定端点、完成 TLS/服务端认证、正确 domain/version/op 的查询结果。
响应不完整、错误 key、错误 instance 或未知代码不能升级成 NOT_FOUND。
查询只能消除知识不确定性，不自动形成新授权。
重复 crash/recovery 使用同 source/operation/dispatch；grant 可更新，但每份 terminal receipt 绑定实际使用的那一份。
旧 AUTHORIZED/PREPARED 死锁在新有限模型中必须出现完整可达轨迹，不只删除 guard 名称。

## 6. Byte Binding 与 Semantic Digest Contract

### 6.1 C2、H2、S2 的精确定义

C2 是本候选独立编码，不是 JCS。
允许 JSON null/bool/string/array/object/integer；所有数字必须整数且绝对值 <= 9007199254740991，
计数/时间 U 为 0..该上界、P 为 1..该上界。拒绝 float、NaN/Infinity、重复 key、NUL、
Unicode surrogate、未知协议字段/类型/版本，以及 bool 充当 integer。
文本为 Unicode scalar；不做 Unicode normalization；键按 scalar code point 排序。
编码等价于合格输入上的 Python JSON ensure_ascii=True、sort_keys=True、separators=(',',':')，
UTF-8；固定短 escape，小写 \u，非 BMP scalar 输出对应 surrogate escape pair。
解码后 scalar 有效不意味着 wire 可任意：接收 wire 必须与 C2(decoded) byte-for-byte 相同。
UUID 为小写规范连字符形；H 为 64 小写 hex；Ed25519 签名表示为 128 小写 hex。
每个注册 typed 对象必需 exact type 和整数 version=2。协议容器的嵌套结构也 exact fields；
业务 payload 可以递归 C2 JSON，但不能借 payload 开放额外协议字段。
新 V2 不接受 float payload 的限制是显式输入范围缩小，不改变原 V1 格式解释。
TEXT256 长度 1..256 Unicode scalar；普通 TEXT 1..4096；所有 resource limit 超限拒绝，不截断重编码。
wire 最大 1 MiB，嵌套深度最大 32，单容器最多 4096 元素；超限 fail closed。

定义（|| 为 bytes 拼接，NUL 为单 byte 0x00）：

    H2(x) = hex_lower(SHA256(
        ASCII("QINGYU-R1-SCOPED-V2/" + x.type) || NUL || C2(x)))

    S2(x) = ASCII("QINGYU-R1-SCOPED-SIGN-V2/" + x.type) || NUL ||
            C2(x 删除且仅删除该类型声明的签名字段)

规范签名为 Ed25519(S2(x))；Authority 类型用 receipt_signature，Root 类型用 root_signature。
key ID 仍保留在签名前像内；H2(signed_object) 包括签名 bytes，不 hash “去签名版本”冒充完整对象。
unsigned 类型无 S2，不能给任意 JSON 添 signature 变成可信授权。
本轮 reference 使用明显标记的 synthetic signature bytes，只测试 wire/preimage，
不执行真实签名，不声称 Ed25519 或 canonical Root 验证 PASS。

另有明确的历史/外部 bytes 承诺：
RAW256(b)=hex_lower(SHA256(b))，b 必须是 archive 中可取得的完整原 bytes，
不是文件路径/标签/转译后的 JSON。原 V1 receipt/Audit hash 则按其原有版本算法直接保留。
H2、RAW256 与旧版本 hash 不能互换。

### 6.2 全部业务对象和精确前像

以下字段均另含公共 type/version；字段类型细节与嵌套 exact fields 见冻结 catalog。
没有未声明 extension。每一 *_digest 的来源在本节或 §6.4 中唯一指定。

| 对象 type | exact fields（除 type/version） |
|---|---|
| identity | qingyu_identity_id, continuity_id, genesis_operation_id |
| authority_ref | wire_version, authority_generation, authority_sequence, receipt_hash |
| audit_ref | wire_version, audit_sequence, audit_hash |
| requested_scope | trust_domain_id, authority_domain_id, authority_instance_id, authority_generation, actor_identity, owner_version, continuity_epoch, expected_state_version, storage_generation_id, control_plane_generation_id, lease_id, lease_generation, caller_runtime_id, session_id, capability, expected_authority_ref, expected_audit_ref |
| business_intent | operation_id, mutation_id, local_commit_id, identity, scope, payload, requested_decision, created_at, reason |
| business_payload | value |
| source_decision | authorization_id, authorization_kind, intent_digest, identity_digest, scope_digest, authorization_principal, requested_decision, created_at |
| business_effect | entries |
| mutation_result | mutation_id, result_state, state_version, effect_digest, value |
| audit_content | operation_id, mutation_id, identity_digest, scope_digest, intent_digest, source_decision_digest, payload_digest, decision, result_state, state_version, effect_digest, result_digest, audit_sequence, previous_audit_ref, created_at |
| branch_bundle | decision, effect, result, audit_candidate |
| mutation_request | intent, source_decision, commit, abort |
| prepare_ack | authority_domain_id, authority_instance_id, authority_generation, operation_id, identity_digest, request_digest, source_decision_digest, commit_candidate_digest, abort_candidate_digest, prepare_execution_grant_digest, authority_predecessor, prepared_at, receipt_key_id, receipt_signature |
| staged_evidence | operation_id, local_commit_id, request_digest, ack_digest, commit_candidate_digest, abort_candidate_digest |
| terminal_authorization | authorization_id, operation_id, local_commit_id, request_digest, source_decision_digest, ack_digest, decision, candidate_digest, staging_evidence_digest, no_local_business_commit, created_at |
| terminal_receipt | authority_domain_id, authority_instance_id, authority_generation, operation_id, operation_type, identity_digest, request_digest, source_decision_digest, ack_digest, authorization_kind, semantic_authorization_digest, execution_grant_digest, decision, result_state, candidate_digest, effect_digest, result_digest, audit_candidate_digest, state_before, state_after, audit_sequence, authority_sequence, previous_authority_ref, decided_at, receipt_key_id, receipt_signature |
| audit_record | candidate, receipt_digest |

identity 是 immutable UUID pair + committed genesis operation reference，qingyu_identity_id:continuity_id=1:1。
continuity_alias 不进入 identity，不授予权限；owner 是可变 fence，不是 identity digest 的成员。
intent 的 requested_decision 仅 COMMIT/ABORT；scope.capability 仅 core_governance。
source_decision.authorization_kind 固定 CALLER_INTENT，principal 是可信已认证 caller，
source.requested_decision=intent.requested_decision，且三个 digest 分别 H2(intent/identity/scope)。
source 的 authorization_id 与后续 exact terminal authorization_id 是不同对象 ID，不混为一次保存。

令 V 为：

    {"payload": intent.payload,
     "capability": "core_governance",
     "requested_decision": intent.requested_decision}

COMMIT effect.entries 精确一个 {"mutation_id":intent.mutation_id,"value":V}；
ABORT effect.entries 精确 []。empty-business-effect 的完整 C2 bytes 是：

    {"entries":[],"type":"business_effect","version":2}

COMMIT result：
mutation_id=原值，result_state=COMMITTED，state_version=expected+1，effect_digest=H2(commit effect)，value=V。
ABORT result：
mutation_id=原值，result_state=ABORTED，state_version=expected，effect_digest=H2(empty effect)，value=null。
加一溢出拒绝。业务效果只是在 canonical governed-result 集合登记冻结值/更新版本，
不执行 payload 中的程序，也不表示用户 proposition 为客观真。

AuditContent 独立按分支生成：operation/mutation、identity/scope/intent/source/payload digest 均取原对象；
decision/result_state/state_version/effect/result digest 取该分支；
audit_sequence=原 expected_audit_ref.audit_sequence+1，previous_audit_ref=原完整 ref，
created_at=原 intent.created_at。
它没有 request/Ack/auth/receipt digest；不会因 override 或 grant 续发改变。
BranchBundle 包含真实 effect、result、AuditContent，不只是 hash 标签。
request 两分支永久冻结；无论原 requested COMMIT 还是 ABORT，都有两份候选，但普通 dispatch 只能原选择。

Authority 从完整 intent/source、认证 scope、可信 checkpoint 独立重算上述两个 BranchBundle，比较 C2；
不接受客户端自报 effect/result/audit hash 就算通过。
Core 同样重算，并检查 payload 的 C2 前像没有被同 mutation ID 替换。
Authority 只对自己的治理 state_version/head 执行相应推进；Core 的 V 登记仍由本地事务完成。

Ack commit/abort_candidate_digest=H2(各完整 BranchBundle)，prepare_execution_grant_digest=当时实际 grant。
StagedEvidence 是 Core 完整 durable stage 的认证声明，不是远端物理观察。
terminal_authorization 在 Ack 后固定；普通 decision 必须等原 source choice；
COMMIT 的 no_local_business_commit 固定 false（不表示已经提交），ABORT 必须 true。
其 candidate_digest 取原对应 BranchBundle，staging_evidence_digest=H2(StagedEvidence)。

receipt.operation_type=MUTATION；authorization_kind=NORMAL 或 OPERATOR_ABORT：
NORMAL.semantic_authorization_digest=H2(完整 terminal_authorization)；
OPERATOR_ABORT.semantic_authorization_digest=H2(完整已签 abort_override)。
receipt.execution_grant_digest=最终实际当前 grant，不是 Ack 的旧 prepare grant。
其它 request/source/Ack/identity/branch/effect/result/AuditContent 都逐一直接绑定；
state_before/after、两条 sequence/predecessor 与独立可信状态一致。
signed receipt 不承诺自己的下游 final AuditRecord。

Final AuditRecord.candidate=被选原 AuditContent，
receipt_digest=H2(完整已签 terminal_receipt)。
最终 audit_head=H2(AuditRecord)，不是 H2(AuditContent)。
Authority 可在完成签名后计算并与 terminal/head 原子存储这个 head；Core 之后独立重算和落实。
ABORT 的结果仍非空且 final AuditRecord 仍包含相反终态的真实授权路径，原 source 不被篡改。

### 6.3 完整依赖图及无环性

    verified previous AuthorityRef/AuditRef + immutable business intent
       -> SourceDecision (intent/identity/scope)
       -> COMMIT/ABORT effect -> result -> AuditContent -> BranchBundle
       -> MutationRequest
       -> current ExecutionGrant (request/source/inventory; no Ack/auth dependency)
       -> signed PrepareAck
       -> StagedEvidence -> fixed TerminalAuthorization
                      OR independent signed AbortOverride (original source + abort bundle)
       -> signed TerminalReceipt (actual authorization + actual grant + original candidates)
       -> Final AuditRecord
       -> next operation's previous references

Root/pin/provisioning/admission/policy 来源先于 request；inventory 只回引已存在 request/source，
不能反过来放入 request。renewed grant 不改 request/auth，因此不会引入新回边。
time n 的 request 只含 time n-1 final Audit head；
同一次 receipt 只含 preterminal AuditContent，不能包含同一次 AuditRecord hash。
这是覆盖真实 request/两个 Audit commitments 的完整图，不是只看 certificate 下游。

原失败构造 request→candidate→authorization/receipt→candidate 是环；
新设计没有 candidate→同 request 或同 receipt 的边。
将 downstream receipt hash 写回 preterminal AuditContent，或把 future exact authorization digest
放入 grant/request，必须作为拒绝的格式变更，不允许“迭代 hash 到稳定值”。

### 6.4 Digest 注册表与重算责任

H2 对象一一对应：
identity_digest→identity；scope_digest→requested_scope；intent_digest→business_intent；
payload_digest→business_payload(value=原 payload)；source_decision_digest→source_decision；
effect_digest→business_effect；result_digest→mutation_result；
audit_candidate_digest→audit_content/opening_audit_content（由 receipt discriminator 决定）；
candidate_digest 与 commit/abort_candidate_digest→branch_bundle；
request_digest→mutation_request；ack_digest→prepare_ack；staging_evidence_digest→staged_evidence；
semantic_authorization_digest→terminal_authorization 或 abort_override；
execution/prepare_execution_grant_digest→execution_grant；
receipt_digest/terminal_digest→完整已签 terminal_receipt 或 opening_receipt（具体流程限定）；
policy_digest→完整已签 recovery_policy；inventory_digest→recovery_inventory；
trust_config_digest→authority_pin；
opening_authorization_digest→完整已签 opening_authorization；
opening_prepare_digest→完整已签 opening_prepare；
source_snapshot_digest→source_snapshot；
history_archive_digest→archive_manifest；
operation_inventory_digest→source_operation_inventory；
restoration_context_digest→完整已签 restoration_context，普通场景必须 null。
genesis attempt/event 的 previous digest 只指对应已存在完整对象；首条 previous 必须 null，不能 zero hash。

以下为 RAW256：deployment_admission_digest、component_artifact_digest、initializer_artifact_digest、
restore_source_state_digest、source_deployment_digest、source_fencing_evidence_digest、attempt event 的 evidence_digest。
它们分别取明确给出的原部署 admission bytes、受保护恢复/initializer 组件 artifact bytes、
已核验恢复源状态 bytes、来源部署证据 bytes、来源隔离证据 bytes、该 attempt 的事实证据 bytes。每份必须可以按 archive role/index/byte_length/sha256 取回；
除模型显式 synthetic 环境假设，不得只提供 H256 标签。
signed_origin_digest 单独严格保留当前 r1_provisioning.py 的定义：
SHA256(ASCII("QINGYU-CP-R1-PROVISIONING-ORIGIN") || NUL ||
V1-JCS({"intent": 原 intent_envelope, "completion": 原 completion_envelope}))。
两份原 envelope 及其既有验签/实际 origin observations 都必须齐备；不等于仅 SHA256(origin 文件)。
K-Intent 仍按原 envelope/version/sign 域验证；这个历史 origin 摘要不赋予新 V2 opening/ABORT 权限。
receipt_key_id=RAW256(raw32 Ed25519 public key)；operator_root_key_id 依 K-Root 同 raw32 指纹；
server_spki_sha256 是传输证书 SPKI DER bytes 的 SHA256，不是 receipt public key。
原版本 AuthorityRef.receipt_hash 和 AuditRef.audit_hash 使用该原版本规则；
V2 使用完整 signed receipt H2 和 final AuditRecord H2。seq0 仅真新 genesis 用 §8 origins。

重算责任：Core 与 Authority 各自完整重算 mutation binding；
Operator/受保护 admission validator 核验原来源 artifacts、Root-only body、fixed pin；
Authority 独立重检相同来源和当前执行事实；Core 只取得公共可验证证据，不取得 DB 凭据。
源码 artifact hash 不是代码可信执行证明，必须与 T4 protected deployment 一起使用。

## 7. 固定 AuthorityPin、版本与证据验证

AuthorityPin(type=authority_pin) exact fields：
authority_domain_id、authority_instance_id、authority_generation、
receipt_public_key（raw32 lower hex）、receipt_key_id、api_version、
https_origin、server_spki_sha256、operator_root_key_id。
receipt_key_id 必须 SHA256(bytes.fromhex(receipt_public_key))；label 不参与身份。
https_origin 使用原固定规范 HTTPS origin，无 userinfo/path/query/fragment；
host/port 必须与 canonical admission 和原 URI 规则完全相同，不跟随新 endpoint/redirect。
terminal/Audit version2、api_version、K-Intent envelope version2 三者独立。
写版本在 opening 后唯一为 V2；旧 V1 只按原被授权验证规则读取，不能拿 V2 S2/H2 验 V1。

AuthorityPin 对象形状本身不授予信任：必须由 canonical Root/public/Registry64 pin、
已批准公共 fingerprint、受保护 deployment admission 和已核验来源共同确立。
Core 在发送 Bearer 前验证 TLS/SPKI 与端点，不向不匹配端点重发凭据。
固定 pin 失效、key/public bytes 对不上、未知 key ID/版本、未经 opening 改 instance/generation、
receipt key 或 TLS 被判失信/丢失：关闭新 terminal 和新业务，拒绝新的信任接纳并报告 STOP。
对于已授权旧历史，只能在既有信任仍有效且版本验证链完整时读取；
不能把签名形式正确等同于已失信 key 下证据仍可信。
不存在 fallback key、TOFU、Root 自动生成、自动换 pin 或 receipt key rotation。

历史终态查询必须返还完整原 bytes 证据：
request、SourceDecision（原 request 内）、原 Ack、stage、
NORMAL exact authorization 或完整 OPERATOR_ABORT artifact、
prepare grant 与实际 terminal grant、signed receipt、原 candidate 及可重算 AuditRecord、
对应可信 lineage/历史当前资格证据。
缺失任何 receipt 所承诺对象都不能声称独立绑定验证完成。
相同 operation 键查询是只读，不重签、不补序号，不要求拿新 lease 重新“决定”历史。
旧版本按其原格式取证，明确 V1 无 receipt-level authorization_digest，不伪造该字段补洞。

## 8. Genesis / Lineage / Opening Contract

本节三种 opening 是初始化/受控切换/具体恢复资格，不是 mutation 强制终态或 Root 万能 override。
不扩展 owner transfer/lease issuance/key change 为新例外。
正常 owner/lease 治理仍须既有认证、drain/resolve、当前 fences；当前产品没有对应完整生产 API 的事实不变。
本候选不把“未实施 API”伪装成已完成验收，也不要求用新 ABORT 例外替代那些生命周期。

### 8.1 来源快照、全量清单与完整性

SourceSnapshot exact fields：
source_kind（V1_OFFLINE_UPGRADE/V2_GENERATION_RESTORE）、identity、
source_authority_domain_id、source_authority_instance_id、source_authority_generation、
authority_tip、audit_tip、state_version、owner_identity、owner_version、continuity_epoch、
storage_generation_id、control_plane_generation_id、signed_origin_digest、
history_archive_digest、operation_inventory_digest、source_deployment_digest、
source_fencing_evidence_digest、captured_at。

ArchiveManifest exact entries 为 role/index/byte_length/sha256，按 role/index 严格排序唯一；
roles 使用冻结 catalog 的闭集，保存原 request/source/authorization/Ack/receipt/Audit、
origin、deployment、fencing、源状态、attempt 等必要证据，引用哪个 role 必须有对应原 bytes。
plain sha256 是实际原 bytes 的 RAW256；不能用“存在一个 manifest”代替完整历史。
SourceOperationInventory 明确包含 Authority 与 Core 来源中的全部 operation 联集，
包括 Core INTENT 但远端尚无的记录；不能仅查 Authority PREPARED 表。
entry 为 operation_id、wire_version、request_raw_sha256、authorization_raw_sha256（可 null）、
terminal_ref（可 null）、audit_ref（可 null）、state（INTENT/PREPARED/COMMITTED/ABORTED）；
按 op 排序唯一并与全量来源导出逐条对应。
切换时所有条目必须有可验证 terminal/audit，且 Core 已准确落实；任意 INTENT/PREPARED、
missing dispatch/evidence、未知响应或无法验证的条目均阻止切换。

快照两个 tip 分开：
Authority 从 admitted origin 沿原全局 receipt 序列验证到 authority_tip；
Core 从 admitted origin 沿原 Audit 与所绑定 receipts 验证到 audit_tip。
另有 continuity 占用全局 sequence 时必须提供连续全局历史，不跳 cursor；
本 bounded Core 无同步能力时 STOP，而非补造 per-continuity receipt sequence。

来源完整、停写、旧实例隔离及完整导出的判断由可信 Operator + 独立观察依 T1/T5 作出。
hash 证明这些提供 bytes 没变，不证明“没有未导出的尾部”或克隆已物理隔离。
SourceSnapshot body 自己写 source_complete 不提供证明；模型 bool 只是明确前提。
缺少旧 Authority 历史、只有较旧备份、未知 tail、来源不确定：拒绝开篇，不从 Core state 重建 Authority。
旧 pending 必须按其原版本/原合法资格收尾；不能靠 opening 丢弃或迁移成 V2。

### 8.2 OpeningAuthorization 与 PREPARED

OpeningAuthorization（Root 签名）exact fields：
opening_id、opening_kind（NEW_GENESIS/V1_TO_V2/GENERATION_RESTORE）、identity、
source_snapshot（新 GENESIS 为 null，其余必需）、
target_authority_domain_id、target_authority_instance_id、target_authority_generation、
target_storage_generation_id、target_control_plane_generation_id、
core_installation_id、initializer_principal、initializer_artifact_digest、
initial_or_current_owner_identity、owner_version、continuity_epoch、state_version、
signed_origin_digest、deployment_admission_digest、trust_config_digest、
receipt_key_id、tls_origin、tls_spki_sha256、operator_root_key_id、
issued_at、expires_at、reason、root_signature。

该授权不包含未来 receipt/final Audit hash。initializer 必须属于当前 protected admission，
不能由任意 Runtime body 冒名。完整授权 raw bytes 固定后，同 opening_id 不同内容冲突。
已存在 opening/identity/source refs/目标 registration 均逐条交叉验证。
opening 签发/执行不接纳测试 Root 提升 production，fixed receipt key/TLS 均不变。
其版本/签名域与 K-Intent initial provisioning envelope 完全独立，没有编号相同的授权继承。

OpeningPrepare（signed Authority PREPARED）exact fields：
opening_id、opening_authorization_digest、audit_candidate_digest、genesis_attempt_digest、
target_authority_domain_id、target_authority_instance_id、target_authority_generation、
prepared_at、receipt_key_id、receipt_signature。
类型本身表示 PREPARED，不含可写 result_state。
NEW_GENESIS 的 genesis_attempt_digest=H2(当前 GenesisAttempt)，其余 opening 为 null；
receipt 经 opening_prepare_digest 直接绑定成功尝试，而不反向引用未来 SUCCEEDED event。
Authority 在 exclusive opening admission 下锁住目标 registration/head/identity/owner reservation，
验证 Root scope/deadline、固定 trust、真实来源、无冲突映射/旧 pending；
原子保存 immutable opening authorization、候选、目标条件及 signed prepare。
普通 mutation 入口仍关闭，不能拿 mutation grant 执行 opening，也不能反过来。

OpeningReceipt exact fields：
opening_id、opening_kind、identity_digest、opening_authorization_digest、opening_prepare_digest、
source_snapshot_digest（NEW_GENESIS 为 null）、authority_domain_id、authority_instance_id、
authority_generation、authority_sequence、previous_authority_ref、audit_candidate_digest、
state_version、owner_identity、owner_version、continuity_epoch、
decided_at、receipt_key_id、receipt_signature。
该类型只有成功 COMMITTED/ACTIVATED 含义，没有“失败也占 canonical sequence”的变体。

OpeningAuditContent exact fields：
opening_id、opening_kind、identity_digest、opening_authorization_digest、source_snapshot_digest、
state_version、owner_identity、owner_version、continuity_epoch、audit_sequence、previous_audit_ref。
Final AuditRecord 仍为 {candidate:OpeningAuditContent,receipt_digest:H2(signed OpeningReceipt)}
加公共 type/version。Authority 在一次最终事务内重新检查 opening 资格/锁/时间，
同时保存 receipt、Authority head、最终 Audit head、identity/owner/generation activation。
签名或事务失败不消耗 canonical seq。

Core 的受保护 initializer 独立验证全链和原字节；当前 deployment/principal/artifact/pin 必须有效。
已成立 opening 按 decided_at 的历史 Root 授权有效性验证，不把过期签名授权当新 opening 能力。
local apply 只限授权的安装/target storage/control-plane/identity：
新 GENESIS 要求已验证空新目标；bridge/restore 要求已验证 source 的 exact checkpoint 和状态。
在自己的单一事务中只作 exact pre→精确 post 或 exact same opening post replay，第三状态 quarantine。
不能以 Authority 的成功签名假设 Core 已经物理提交。响应丢失只 query 同 opening_id，返回原 receipt，
重启不创建另一个 GENESIS、另一 signature truth 或新的成功序号。
该专门初始化收尾资格不是把 RecoveryPolicy.allowed_operation_type 扩为 GENESIS。

### 8.3 真新 GENESIS 与 attempt 永久证据

NEW_GENESIS 仅限真实新 Authority history/新身份，source_snapshot=null，
target_authority_generation=1、owner_version=1、continuity_epoch=1、state_version=0。
opening_id 等于 identity.genesis_operation_id；两 UUID 身份对来自已核验 provisioning 与 Root plan，
而非每次 request 重启新生成。初始 owner 明确为 initial_or_current_owner_identity。

AuthorityOrigin(type=authority_origin) 与 AuditOrigin(type=audit_origin) exact fields 相同：
identity_digest、opening_authorization_digest、signed_origin_digest、trust_config_digest。
不同 H2 域确保两种锚不同。两个真正的 seq0 predecessor：
AuthorityRef=(wire_version2,generation1,sequence0,H2(AuthorityOrigin))；
AuditRef=(wire_version2,sequence0,H2(AuditOrigin))。
这些不是 zero/default head，不是已发生的 receipt；仅作为有来源的新身份 genesis 前序。
成功 GENESIS 是 Authority receipt1、Core Audit1；共享已有 Authority 历史的新 continuity
不能套用“每个 identity 都占全局 receipt1”，该多 continuity 初始化不在此 bounded opening 内。

GenesisAttempt exact fields：
attempt_id、opening_id、opening_authorization_digest、identity_digest、
attempt_number、previous_attempt_digest（首条 null）、created_at。
GenesisAttemptEvent exact fields：
event_id、attempt_id、previous_event_digest（首事件 null）、
state（PREPARED/GENESIS_ATTEMPT_ABORTED/SUCCEEDED）、reason_code、evidence_digest、created_at。
这是 Authority 单库 append-only 证据，不是外部 witness、Local Journal 实现或 IBCS。
PREPARED event 的 evidence bytes 包含该 signed OpeningPrepare；
SUCCEEDED event 的 evidence bytes 包含原 successful receipt；receipt 不回引 future success event。

登记 attempt 与身份/continuity/genesis op/初始 owner/plan 的唯一 reservation 在同一事务。
一个身份对及任一单独 UUID 不得映射到两份 plan；attempt_id 同内容 replay/不同内容 conflict。
所有新 attempt 必须原 opening_id/授权/身份/owner 不变、attempt_number 前一+1、链接原 attempt；
不得用新 identity 绕过失败 reservation。至多一个 live PREPARED attempt，至多一个 successful attempt。

失败转为 GENESIS_ATTEMPT_ABORTED 的依据必须是可确定的原尝试失败：
在同一锁边界确认无已提交 canonical terminal、无仍可提交的 proposal、
失败事务已回滚/资格确定拒绝，并保存明确 cause 证据。
timeout、断连或响应未知不满足这个条件；先同 opening_id/attempt_id query。
不向 Root 提供“强制 ABORT GENESIS”接口。失败记录不清空 reservation、不删除证据，
不消耗 receipt/Audit 序号，不建立 canonical identity。
成功 finalization 将唯一 successful attempt 关联与 genesis receipt1/identity/owner/head 原子保存。
后续 query/retry 返回原成功证据；不能再次分配 canonical receipt1。
若原 opening 授权已到期且尚未成功，不复活它；停止等待单独明示修订，而非修改原 body。

要求的轨迹：

    attempt1 PREPARED -> 可证明失败 -> GENESIS_ATTEMPT_ABORTED（永久证据，canonical seq仍0）
    attempt2 同一plan/identity/owner PREPARED -> 成功 -> GENESIS receipt1 / Audit1
    attempt2 同内容重复 -> 原 receipt1；其它内容或第二成功 -> conflict

### 8.4 停写 V1→V2 桥接

前置：完整受支持现行 V1 历史、原 origin/pin/admission；源业务停止、旧 writer 被隔离；
全源 operation 联集没有 pending，Core 全部准确落实；V1 各对象按原算法验证。
源不能被强求签一个其 V1 不支持的 V2 envelope；由 Operator 在停写后对完整原证据签新 opening。

同一 identity/GENESIS/owner/epoch/state、同一 Authority instance/generation、固定 key/TLS；
不改变 api_version，不靠新UUID替代provenance。
设源 Authority tip=(1,g,n,hR1)，Core Audit tip=(1,m,hA1)。
first V2 opening receipt：

    authority_generation = g
    authority_sequence = n + 1
    previous_authority_ref = (wire_version=1,g,n,hR1)

first V2 OpeningAuditContent：

    audit_sequence = m + 1
    previous_audit_ref = (wire_version=1,m,hA1)

first V2 final Audit head=H2({type:audit_record,version:2,candidate:上述内容,
receipt_digest:H2(first V2 signed opening receipt)})。
后续 request.previous refs 指这个真实 V2 opening receipt/final AuditRecord。
旧 hR1/hA1 是原已验证 bytes 下的原 hash，不是 RAW256/H2 再包装替代。
桥接只追加一次新 activation evidence，不 re-sign/reencode V1，不把 V2 直接授权证明倒赋给 V1。

停写状态、源 writer 隔离及目标部署选择是 Operator 责任；opening receipt 与 Core local apply
完成前不开放 V2 business。任一中断只恢复此 opening；不能同时重开 V1 writer。
自动 downgrade/双写/在途改版本不提供；无法合法完成旧 pending 时拒绝桥接。

### 8.5 人工恢复与 generation opening

RestorationContext（Root 签名）exact fields：
context_id、identity、source_snapshot、target_core_installation_id、
target_storage_generation_id、target_control_plane_generation_id、target_authority_pin_digest、
restore_start_checkpoint、restore_source_state_digest、allowed_actions、
issued_at、expires_at、reason、operator_root_key_id、root_signature。
allowed_actions 精确为 APPLY_VERIFIED_TERMINAL、VERIFY_HISTORY（排序去重）。
只允许指定来源/目标从已核验起始 checkpoint 重放已成立历史，不产生任何新旧 operation terminal。

Operator 必须给出具体旧 Authority 来源及其完整最终 tail、旧 writer 隔离证据、可信备份状态、
其在完整历史中的精确 restore_start_checkpoint、目标安装/存储/control-plane 与固定 trust。
Core 独立验证备份状态/链及每条历史 receipt/result/原授权/Audit，不能仅验证 Root “批准”。
Authority 历史必须来自 Authority 完整记录；不能取 Core 状态反建历史。
若 Core 落后但旧 Authority 历史完整，允许在关闭新业务的 target 上逐条 replay，
每条需 target-bound policy/finish permit 与 RestorationContext 精确映射原 source→target。
原 request/receipt generation 不改，policy 只批准 target 本地收尾，不给 stale request 新 terminal。
重放顺序和 exact pre/post 都由已验证链决定；不能凭版本相同跳过头差异。

GENERATION_RESTORE 只有完成上述历史追齐、所有旧 pending 合法完成、
已核验旧 source final snapshot 和旧 writer 隔离之后可开始。
old=(g,n,hR)，new Authority generation=g+1，新的 target instance/storage 明确，
identity/GENESIS/owner/version/epoch/state 与 source 相同；receipt key、TLS origin/SPKI、Operator Root 不变。
新 opening receipt=(V2,g+1,sequence1)，previous_authority_ref 指 old(g,n,hR)；
Audit sequence 继续 m+1，previous_audit_ref 指旧实际 final audit tip，不重置。
Authority generation 开启权限来自专用 Root opening scope，不是 receipt key rotation。
新 generation 不使 stale mutation 的原 expected_generation 突然合法。

ordinary intact crash 不进入该人工路径。
已知 clone/restore/storage replacement、未知来源、未知 canonical tail 或旧未终态无法合法完成：
只保留只读调查/隔离，禁止 opening；不能拿“recovery_context 签过”消除证据缺口。

## 9. Mutation-only ABORT Override / 独立不可变例外

AbortOverride(type=abort_override)，Root 签名 exact fields：
override_id、operation_id、request_digest、source_decision_digest、
supersedes_authorization_id、previous_authorization_digest、
identity_digest、scope_digest、authorized_decision=ABORT、
abort_candidate_digest、reason、issued_at、expires_at、operator_root_key_id、root_signature。
supersedes_authorization_id 指原 SourceDecision.authorization_id；
previous_authorization_digest 必须等原 source_decision_digest，不是“最近任意管理员授权”。
scope_digest=原完整 RequestedScope，包括 domain/identity 相关绑定、owner/epoch/generation/原 source lease。
原 requested choice 由 request+source 的直接摘要关系取得并核验，不写回该原值。
无递归 override 链、无通用 supersedes 引擎；每 op 最多一条 accepted override。

此 artifact 仅允许原 MUTATION 未终态且原 source=request.requested_choice 的 operation 使用原 ABORT bundle。
Root 只是允许这个 forward ABORT；当前 grant、owner/epoch/state/generation、时间与所有 locked fences 仍检查。
原请求本来就是 ABORT 的普通流程不要求 Root；新增例外不是替代正常授权格式。
Runtime/Migrator 只能验证/提交已签公共 artifact，不能载入私钥自行签发。

Authority registry 唯一键=(authority_domain_id,override_id)，保存完整 C2 signed bytes。
- 同 ID、相同 bytes：返回已有接受结果/原 receipt；不二签、不再次消费序号。
- 同 ID、不同 bytes：conflict，保留原对象和冲突证据，不 overwrite。
- 不同 ID、同一 op：不能替换已接受例外或已终态；不沿新 ID 重试绕过唯一性。
- 已终态：任何迟到 override 均不能改 terminal；query 提供原已成立结果。
- 不同 domain/body content、过期/错误 Root、强制 COMMIT、非 MUTATION、改 payload、
  错 predecessor/candidate：拒绝，不能进入 accepted registry。

accepted override、选择 ABORT、实际 semantic authorization digest、terminal receipt/sequence/head
与业务 state 不增量的决定同一 Authority 最终事务。仅保存一次“收到提案”的非 canonical 审计
不等于已接受例外；不得出现 half accepted override 供下一次绕开检验。
普通 COMMIT 与例外 ABORT 通过同一 operation serialization point 竞争：
先提交者唯一胜出；另一方不得新选结果，进入同 ID history query。
即使 SourceDecision=ABORT，也不能伪造普通 COMMIT 来赢这场竞争。

Core 提交例外前独立验证 Root/scope/原请求/原 source/predecessor/原 ABORT bundle、
exact pre 以及不存在本 op 本地 canonical COMMIT，然后保存独立 exception-dispatch 记录和
no-local-business-commit 事实声明。它不编辑原 ordinary dispatch/auth/request/choice。
未知远端结果只触发 query；不自动创建或请求 override。

Core 遇到相反 ABORT：
1. receipt.authorization_kind 必须 OPERATOR_ABORT，实际 authorization digest 匹配完整已签 artifact；
2. 验 Root 在该决定历史时点的授权有效性、operation/request/source/original auth ID/predecessor；
3. 重算原 request.abort 的 effect/result/AuditContent，与 receipt 直接绑定完全一致；
4. 验实际 grant 与 receipt 当时当前 fences 证据，而不是把 Root 当 fence 豁免；
5. 当前 LocalFinishPermit + exact local pre（或 exact same ABORT post）满足后才原子落实；
6. 缺 artifact、无法解释相反决定、已有 canonical COMMIT、前后态冲突：quarantine，不落地。

原因链是“原 choice 未改 + 独立 Root forward ABORT 取原预冻 ABORT candidate”。
最终 AuditRecord 经 receipt_digest 连接真正例外来源；原 AuditContent 不被事后改成另一个前像。
普通 retry 重放原 auth，不等于例外授权。

## 10. 与 23 项已接受 invariant 的逐项映射

| 已接受 invariant | 新候选保证位置 / 验证责任 |
|---|---|
| INV-A-01 唯一 terminal | §3/4.3/9，同 op 序列化、唯一acceptedoverride、终态不可反转；模型两种竞态序 |
| INV-A-02 认证与语义绑定 | §4.1/6/7，服务端principal + 重算两分支 + receipt直接actualauth/grant |
| INV-A-03 当前 fences | §4.2–4.3，新单op lease不是复活原lease，最终commit/currenttime重检；历史读分离 |
| INV-A-04 Authority 原子性 | §4.3/8.2/9，proposal/sign/finalize/receipt/sequence/head同一库事务；不声称跨库 |
| INV-A-05 原字节重放 | §5/6/9，ID/content冲突、原Ack/auth/receipt不重签、不第二seq |
| INV-C-01 INTENT 先持久 | §4.1/5/6.2，request/source/IDs在network前，既有INTENT可入recovery清单 |
| INV-C-02 dispatch 时点 | §5 W3/6.2，Ack/stage后固定exactauth，grant续发不改它 |
| INV-C-03 UNKNOWN | §3.1/5/9，只同ID查询，non-200不autoabort/override |
| INV-C-04 全证据终态验证 | §4.4/6.2/7/9，原候选/授权/两链/actualgrant全部重算，反向ABORT须完整例外 |
| INV-C-05 Core 本地原子 | §4.4/6.2，effect/Audit/receipt/checkpoint同事务；ABORT无业务版本增量 |
| INV-C-06 历史/身份/checkpoint | §4.4/8，exactpre/post、genesis锚、两链独立、不得用最新globalhead替原savedcursor |
| INV-C-07 Core API 边界 | §2/7，只HTTPS固定pin前发送凭据，无Authority SQL/Rootprivate/receiptsecret |
| INV-O-01 Root custody | §1.1/7，保留test-only本地ceremony、canonicalpublic/Registry64和production分离 |
| INV-O-02 Operator 限权 | §2/8/9，来源判断不代替history，不强制COMMIT/绕fence/新UUID证明provenance |
| INV-O-03 角色最小权限 | §2/11，保留未来真实migration前/后权限门；本轮不运行也不声称PASS |
| INV-R-01 多状态维度 | §3，每种非ACTIVE原因不同权限，remote knowledge与持久进度分离 |
| INV-R-02 普通 crash | §4/5，预批准可自动恢复，不每次人工、不换名restore |
| INV-R-03 条件恢复可达 | §5，六窗口旧死锁合法路径；有限模型公平稳定T6，未要求ACTIVE/no本oppending |
| INV-R-04 历史 vs 当前 | §4.3–4.4/8.5，历史授权时效不复活新写；显式restore映射仅localfinish |
| INV-R-05 Genesis/lineage | §8，非零origin、两个predecessor、attempt永久证据/成功#1/初始owner/防重复 |
| INV-R-06 全图和真实前像 | §6，C2/H2/S2、全字段与分支语义、无环图、真实vectors而非labelhash |
| INV-R-07 例外不可变 | §9，ID/content/predecessor/原授权绑定、同op唯一、oppositeABORT可解释或隔离 |
| INV-R-08 key/pin/版本 | §1.1/7/8，固定key mapping，Root/receipt/TLS三分、明确rotation延期 |

## 11. 六类旧 Findings：新候选处理、证据与未证明部分

这些是本候选设计层处理声明，最终是否完成由同一冻结候选 A/B/C 决定。
旧报告仍 OPEN/历史 BLOCKED，不宣称已有产品修复。

| 历史问题 | 实际设计处理 | 本轮证据 | 仍不能据此证明 |
|---|---|---|---|
| A-01 / C-MIN-01 恢复死锁 | §4–5，既有无PREPARE INTENT清单、PREPARED下固定原auth、独立currentgrant/finishpermit | recovery_model.py / recovery-model-results.md：12根具体轨迹、所有稳定可达态可收尾、28检查组 | 真数据库锁/时钟/认证、无条件availability |
| B-01 完整摘要回环 | §6，intent/source→两候选→request→Ack/auth→receipt→finalAudit | reference codec、DAG与反例、实际规范bytes/hash | 产品同一规则实现、密码学正确性 |
| A-02 / B-02 语义前像 | §6.2，真实payload、COMMIT登记值/版本、emptyeffect、非空ABORTresult | synthetic-vectors.json 与 codec-results.md，branch重算/变异拒绝 | 外部世界效果、任意payload执行语义 |
| A-03 首链/GENESIS | §8，独立两头、原V1 hash、新origin、attempt与成功receipt1分离、恢复来源门 | opening/lineage vectors与有限拒绝示例 | 真实provisioning来源完整、实际隔离、现数据库历史 |
| B-03 key lifecycle | §1.1/7，用户明确延期receipt/TLSrotation，固定exactpublic→ID、独立pin、失效STOP | AuthorityPin向量/版本拒绝 + 本轮用户裁决 | 完整长期production key生命周期、自动换钥恢复 |
| C-MIN-02 override改内容 | §9，独立RootABORT、原auth不改、globalID冲突与terminal原子、Core解释相反ABORT | recovery模型：同ID内容冲突、两竞态序、越权/迟到/UNKNOWN拒绝；byte artifact绑定 | 实际并发数据库锁/真实Root签名/生产行为 |

旧源码含未实现部分及此前六项发现保持原状态。若 reviewer 发现本候选 P0/P1/P2/OPEN/PARTIAL，
本轮立即停在该候选；不自动 patch 后连续审查，不用“模型PASS”压过合同缺口。

## 12. 隔离验证、独立 Gate 与后续前置

新程序只在本轮 evidence 目录使用 stdlib/合成数据运行，不导入产品、不接网络/DB/Docker，
不装依赖、不读取现场数据/秘密、不用真实Root签名。
recovery model 是有限状态/显式认证签名与各库原子性假设；其中 SET_GOVERNED_VALUE 是抽象的
状态登记标签，不是新增产品 capability，tuple result/effect 不是规范 wire；实际唯一 capability、
嵌套 requested_decision 和完整字节语义以 §6 与 reference vectors 为准。
reference codec 是设计编码/语义重算，
不是生产实现。每个结果报告保存真实 stdout、合法轨迹、拒绝例、覆盖范围与未覆盖项。
state/edge/count 仅可说明有限规模，不是安全证明。标准定义与范围若未由该参考实现执行，须显式说明。

内部作者完成后仅冻结一次主文+规范catalog+模型/编码器+合成向量+验证报告/清单。
A/B/C 是非本候选作者，先独立提交原始报告后才相互参照，审查同一 candidate manifest SHA-256。
各自分别判定：报告/证据忠实性、范围内合同完整性、验证/限制、本替代合同 Design Gate。
主文的候选身份冻结不等于产品 Candidate Freeze；后者本轮禁止。

即使全部 PASS，仅新替代合同 Design Gate PASS。实施仍需新的明确授权及：
- 以该完整受审候选为唯一实现依据，编写产品变更/迁移与回归计划；
- 对受影响 trust/signature/deployment/Windows identity/public-pin ACL 做对应影响回归；
- 真实隔离 PostgreSQL migration 前权限门、后表/过程/默认权限/负向门及实际migration/fingerprint；
- 真实 crash/retry/并发/fence/clock/签名与完整产品/独立review证据；
- 获准后才 signed intent、部署或新的产品 Candidate Freeze。
这些未在本轮执行，不假造 PASS。

恒定状态：
旧 Minimal Trust = 历史 BLOCKED / STOP；
产品 Implementation Gate = BLOCKED；
Foundation Closure = NOT ENTERED；
C01 = DEFERRED / REMOVED FROM R1 REQUIRED SCOPE。
最终 Design Gate 以 disposition 原始 A/B/C 结论为准，不能仅 fidelity PASS。
Resume Token：R1_ACCEPTANCE_CLOSURE_MARATHON。
