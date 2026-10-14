# Qingyu Core Phase 1 设计报告

## Core Contract + Continuity Model — Architecture Design Gate

---

## 0. 元信息与约束（Meta / Constraints）

| 项 | 值 |
| --- | --- |
| 本轮性质 | Stage 0 — Architecture Closure；Core 只设计不实现；Gateway 仅允许 Frozen Maintenance Amendment #1 |
| 报告版本 | v1.2 — Stage 0 Architecture Closure：继承 v1.1，并闭合 Epistemic、continuity ID/alias、epoch fencing、GENESIS trust anchor 与 Gateway Amendment #1 |
| 上游冻结基线 | Gateway Phase 3 CLOSED / FROZEN，Freeze Commit `bb107edadce0168b14189b47e902fd4c31fe3f19` |
| Gateway Alembic head | `0016_real_export_evidence` |
| 本轮允许动作 | 只读调查；修订本报告；在 Gateway 自身变更控制下实现/测试 GET-only Evidence Query API |
| 本轮禁止动作 | 重开 Gateway Phase 3；修改 Gateway Evidence schema/migration/importer；安装 Hermes；创建 Core 代码/DB/migration；实现 Journal、Memory Intelligence、User/Relationship Model |
| 交付物 | 本报告 v1.2；Gateway Amendment #1 的代码、测试、契约与验收记录；不含 Core 实现或新 migration |
| 只读调查证据 | `gateway/docs/{SOURCE_OF_TRUTH_CONTRACT,RUNTIME_INDEPENDENCE_CONTRACT,GATEWAY_BOUNDARY_FREEZE,BACKUP_RESTORE_RUNBOOK,PHASE3_FINAL_ACCEPTANCE_REPORT}.md`；`gateway/app/models.py`；`gateway/app/importers/{query,service,processor}.py`；`gateway/app/main.py`；`gateway/.ai-dev-team/*`；`git log` / `git status` |

### 0.1 三个必须继承的既有事实（不可推翻）

1. 权威链方向：`Raw Archive → Normalized Evidence → Derived Memory → Context → Runtime → Model`，派生只允许向下，禁止反向权威（`SOURCE_OF_TRUTH_CONTRACT.md`）。
2. Gateway 不可被下游污染：Runtime / Context / Derived Memory 不得改写或删除 Evidence；`staging/` 清理权限只覆盖 service-owned 临时数据（`GATEWAY_BOUNDARY_FREEZE.md`）。
3. 可重建性：删除 Runtime、Journal、Context cache、Derived Memory 都不得摧毁历史（`RUNTIME_INDEPENDENCE_CONTRACT.md`）。

### 0.2 上游依赖闭环（Stage 0，Gateway Amendment #1）

v1.1 基线时 Gateway 对外只有 archive/import API，Evidence 重建仅存在于进程内。Stage 0 已授权 **Gateway Frozen Maintenance Amendment #1**：在不重开 Phase 3、不改变 Evidence 模型的前提下，新增稳定 GET-only Evidence Query API、独立 evidence-read capability、显式 allow-list DTO 与有界高水位分页。Core 只能经该 API 读取 Gateway Historical Evidence，禁止 DB 直连。该能力须通过 Gateway full regression 与 Reviewer A/B/C final gate 后才视为 CLOSED。

### 0.3 术语（Terminology）

| 术语 | 中文 | 含义 |
| --- | --- | --- |
| Qingyu Identity | 清语身份 | "还是同一个清语" 的根身份，永久、不可再生 |
| Continuity | 连续性 | 一个身份的连续经验流，跨 session / 模型 / runtime 存活 |
| Continuity Alias | 连续性别名 | 人类可读查找名；`qingyu-main` 属此层，不能参与身份、租约或授权判定 |
| GENESIS Trust Anchor | 初始身份信任锚 | Core DB 之外由 owner 固定的已认证身份清单，用于防重复 GENESIS 与 restore identity verification |
| Fencing Authority | 写隔离权威 | 不随 Core restore 克隆、负责签发全局单调 epoch 与撤销旧写权的治理权威 |
| Constitution | 宪法 | 最高保护的治理性契约（身份、人格约束、关系原则、主权与连续性规则） |
| Versioned Intelligence State | 可版本化智能状态 | 对用户 / 关系 / 自身的长期可修正理解 |
| Assertion | 断言 | Core 中一条不可变、带来源与证据的理解记录 |
| Projection | 投影 | 从状态计算出的只读视图（含 SOUL.md、Runtime 可读摘要） |
| Runtime | 运行时 | 现在在哪里运行（Hermes 等），可丢弃 |
| Model | 模型 | 这一刻用哪颗脑子，只是推理提供方 |

---


## 1. Qingyu Core 定义（Definition）

**Qingyu Core = 一个与模型、运行时、会话无关的、可版本化、可审计、可纠正的"连续存在"层。**

它只回答三个问题：

1. 归属：这些历史属于哪个连续存在？（Identity / Continuity）
2. 长期理解：当前对自身、用户、关系的长期理解是什么，以及它如何演化？（Versioned Intelligence State）
3. 不可被悄悄改写的规则：哪些规则受最高保护？（Constitution）

明确的不等式（已冻结）：

```text
Gateway               = 系统/来源曾记录到什么（字节真源 + 归一化 Historical Evidence；不等于 Objective World Truth）
Qingyu Core           = 这些历史属于哪个连续存在 + 当前对自身/用户/关系的长期可修正理解
Memory Intelligence   = 从 Evidence 产生可重建 Derived State（Derived State Producer，不是 Source-of-Truth）
Runtime               = 现在在哪里运行
Model                 = 这一刻使用哪颗脑子
```

关键性质：

- Core 不是"语义记忆数据库"：它是**归属 + 治理 + 可修正理解**。
- Core 不产出"世界事实"：它产出的是关于理解的、带来源与证据的断言。
- Core 不可被推导层覆盖：Memory Intelligence 的产出是**提案**，进入 Core 必须经过显式写入规则（§9 / §13）。
- Memory Intelligence 是 **Derived State Producer**：它可依契约产生 DERIVED assertion/state，并须通过 schema、provenance、原子性与审计门；这不表示每条 DERIVED assertion 都需人工审批。只有 Constitution amendment 永远是 proposal-only，必须由治理主体批准。

### 1.1 Core 的逻辑分层

| 层 | 名称 | 内容 | 保护级别 |
| --- | --- | --- | --- |
| L0 | Constitution | 身份、人格约束、关系原则、主权、连续性规则 | 最高（独立 capability） |
| L1 | Identity & Continuity Registry | identity / continuity / epoch / runtime 注册 | 高（append-only + 审计） |
| L2 | Evidence Reference Index | 指向 Gateway evidence 的引用与解析状态 | 高（只读上游） |
| L3 | Versioned Intelligence State | User Model / Relationship Model / Beliefs / Preferences / Hypotheses | 中高（append-only + supersession） |
| L4 | Projections | Runtime-neutral 只读投影（含 SOUL.md） | 可重建（可丢弃） |
| X | Audit Ledger / Governance | 审计、审批、actor 记录 | 高（append-only） |

**本轮只冻结 L0–L2 的契约与 L3/L4 的形状，不实现任何一层。Current State（当前状态/瞬时上下文）本轮明确不实现。**

---

## 2. Core 与 Gateway 边界

| 维度 | Gateway（已冻结） | Qingyu Core（本设计） |
| --- | --- | --- |
| 回答 | 系统/来源曾记录到什么；不裁决客观世界真相 | 属于谁 + 长期怎么理解 |
| 真源 | Raw Archive 字节（SHA-256 + manifest） | 不持有世界真源；持有"理解断言"与其证据引用 |
| 可变性 | 只追加；已提交证据不可改写 | 可修正（新增断言 + supersede），不可静默覆盖 |
| 删除语义 | 长期证据不可删（需独立授权流程） | Derived 可重建；Constitution / Identity 高保护 |
| 身份 | Conversation / Node / Message / Revision / Attachment 身份 | Qingyu Identity / Continuity / 断言身份 |
| 对外 | ingest + archive + Amendment #1 GET-only evidence query | continuity + projections + event ingest + 治理（未来） |
| 依赖方向 | 不依赖 Core、不依赖 Runtime | 依赖 Gateway 的 evidence 引用（只读） |

硬规则：

1. Core 不得复制 Evidence 字节并把副本升级为更高权威；允许缓存展示用片段，但必须标记为 convenience copy，冲突时 Gateway 胜出（§14）。
2. Core 不得成为 Evidence 的唯一存放处；删除 Core 不得使 Gateway 历史失效。
3. Core 不得反向写 Gateway 的 Evidence、parser 身份、provenance、Node 拓扑。
4. Gateway 不得为 Core 而依赖 Runtime / Model / Memory Engine；Amendment #1 的只读 Evidence Query API 属 Gateway 自己的变更控制，不引入反向依赖。
5. 引用而非外键：Core 引用 Gateway evidence 只能通过引用 + 校验，不得建立跨库外键（§19）。

---

## 3. Core 与 Runtime 边界

| Runtime 可以 | Runtime 不可以 |
| --- | --- |
| 请求授权的 Context / Evidence 引用 | 创建 Qingyu identity |
| 通过显式契约提交 append-only Runtime Event | 重置 continuity |
| 调用 Tool / Model | 删除 Qingyu 历史 |
| 保存自己的 operational state、缓存、窗口 | 把 `state.db` / `MEMORY.md` / 缓存 / 转录 / prompt / 模型输出当作 Qingyu 唯一历史 |
| 上报 reconciliation checkpoint | 覆盖 User Model / Relationship Model / Constitution |

**判定测试（可执行）**：把 Runtime 目录整体删除、重装一个全新 Runtime、只给它 `continuity_id` 与凭据，它必须能够重新取回同一 identity、同一 `constitution_version`、当前 User / Relationship projection 与连续性历史，并能继续运行。做不到，说明 Runtime 越界持有了不该属于它的状态。

---

## 4. Qingyu Identity Contract

### 4.1 六层身份标识（互不替代）

| 标识 | 语义 | 创建者 | 可变性 | 生命周期 | 可否缺失 |
| --- | --- | --- | --- | --- | --- |
| `qingyu_identity_id` | 谁是清语（根身份） | Core genesis（一次性） | 永不可变、永不重用 | 永久（直到显式 retire） | 否 |
| `continuity_id` | 一条连续经验流的 opaque UUIDv4；调用方不得解释其结构 | **Phase 1 仅 Core GENESIS**；future versioned fork contract reserved | 分配后不可变、不可重用、不可 remap | 与身份同寿命 | 否 |
| `continuity_alias` | 人类可读查找别名（首个 continuity 默认 `qingyu-main`） | Core 治理动作 | 可审计 rename；旧 alias tombstone 且不可转配 | 与 continuity 绑定 | 可以 |
| `continuity_epoch` | continuity-scoped fencing generation | GENESIS 创建 0；其后仅 non-cloned authoritative fencing authority 可签发 | 严格单调递增 | 永久 | 否（初始 0） |
| `runtime_instance_id` | 某个已安装 Runtime 部署实例 | Runtime 安装时注册 | 可轮换 / 吊销 | 该安装的生命周期 | 可以 |
| `runtime_session_id` | 一次执行会话 | Runtime | 会话内不变 | 会话级，短命 | 可以 |
| `model_instance` / `provider` | 某次推理的提供方与模型版本 | Runtime 声明，Core 记录 | 每次推理可不同 | 单次推理 | 可以 |
| Evidence identity | Gateway 的 Archive / Conversation / Node / Revision / Attachment | Gateway | 只追加 | 永久 | 否（作为证据引用时） |

**唯一判据**：`还是同一个清语` ⟺ `qingyu_identity_id` 未变。其它标识都是环境属性，不是身份。

### 4.1.1 基数不变量（Cardinality，冻结）

**Phase 1 冻结：`qingyu_identity_id : continuity_id = 1 : 1`。** 即一个身份恰有一条连续经验流。

理由：若允许"一个身份多条 continuity"或"一条 continuity 多个身份"，§4.3 的 fork / merge / restore 判定将失去唯一答案，§4.2 的 15 场景矩阵也不再成立。**"一身份多连续流"需要独立治理设计，明确不在 Phase 1 支持。**

派生规则：

1. `continuity_id` 在创建时必须绑定唯一 `qingyu_identity_id`，绑定后不可改绑。
2. Phase 1 不支持 fork/new-identity 创建路径；只有唯一 GENESIS 可创建 identity/continuity。未来若另立版本化 fork contract，仍必须原子创建新的 1:1 identity/opaque continuity pair，且不得复用 `qingyu-main` alias。
3. `continuity_epoch` 的**作用域是 `continuity_id`**（1:1 下等价于身份域）。
4. Phase 1 的 canonical identifier profile 冻结为 UUIDv4；API/Runtime 必须把它当作不透明字符串，不得从格式、排序或位布局推断业务语义。

### 4.1.2A `continuity_alias` 边界（冻结）

1. `qingyu-main` 只能是 `continuity_alias`，永远不得写入 `continuity_id`。
2. alias 不得作为主键、外键、写请求 canonical target、lease key、capability scope 或 identity equality 判据。
3. alias 只允许在显式 lookup/read 路径解析；成功响应必须返回 canonical `continuity_id`。
4. alias rename 是治理动作，必须审计；旧 alias 进入 tombstone，永不转配给另一 continuity，防止 confused-deputy。

### 4.1.2 `continuity_epoch` 的强制作用（冻结）

epoch **不是**展示字段，必须同时具备四个强制点，否则 §4.3 的 split-brain 防护退化为约定：

1. **绑定写租约**：写租约是 `(continuity_id, epoch)`；持租约者才能写入。
2. **提交时写入校验**：任何 Core 状态写入必须携带 `epoch`，且在该 mutation 的最终 serialization / commit point 由 non-cloned linearizable write gate 校验 `request.epoch == current_epoch`；仅在可被克隆的 Core DB 内比较 epoch 不构成 fencing。落后即拒写（`EPOCH_STALE`）并降级为只读。
3. **进入 projection 与断言**：每条断言与每个 projection 都返回 `continuity_id + continuity_epoch + state_version`，使陈旧客户端可自检。
4. **non-cloned commit gate**：每次 mutation 的最终提交必须由线性一致 write gate 或实际共享存储的原生 fence 校验；Core 本地副本的校验不能替代它。

上述四个强制点必须服从一个**不会随本次 Core point-in-time restore 一同克隆的 authoritative fencing authority**。只存在于被恢复 Core DB 内的 epoch/lease 行不足以阻止两个相同快照分别计算出同一个 `n+1` 并同时写入。

冻结补充规则：

1. 仅 GENESIS 可创建 epoch `0`；Runtime、restore process 与客户端不得自行选择或递增 epoch。
2. restore activation、`WRITER_TRANSFER`、影响写授权的 `GOVERNANCE_OWNER_TRANSFER`、`CONTINUITY_UNRETIRE`、forced lease revocation 等改变合法写者集合的动作，必须由 write gate 原子使旧 lease/未消费 permit 失效，并签发严格大于全部已签发值的新 epoch。
3. 所有 Core mutation 必须携带 `continuity_id + continuity_epoch + lease_id/fencing_token + mutation_id + actor/capability`。每次 mutation 都必须经同一个 non-cloned、线性一致的 write gate 在**提交时** CAS 校验/消费 `(continuity_id, epoch, lease, mutation_id, expected_state_version)`；没有该 gate 的 commit permit，Core DB 事务不得提交或对外可见。若采用共享存储原生 fencing，则比较必须发生在实际持久化资源的同一 serialization point。
4. `epoch < current` ⇒ `EPOCH_STALE`；`epoch > current` ⇒ `EPOCH_NOT_ISSUED`；epoch 相等但 lease/token 不匹配 ⇒ `LEASE_FENCED`。三者均 fail-closed、零业务副作用且不推进 `state_version`。
5. restore 必须先进入 `RESTORE_QUARANTINED` 只读态；只有完成 GENESIS anchor 身份验证、旧写权撤销并取得新 epoch 后，才能记录 `CONTINUITY_REBASED` 并激活写入。
6. fencing authority 不可达、最大已签发 epoch 无法证明、或仍可能存在无法撤销的写者时，返回 `RESTORE_FENCE_UNPROVEN` 并保持只读；不得用 wall clock 仲裁。
7. 网络分区中的旧 writer 即使从未“观察到”新 epoch，也无法取得下一次 commit permit；已签发但未消费的旧 epoch permit 在 epoch CAS 提升时原子失效。write gate 的 permit/commit ledger 以 `mutation_id` 幂等，Core 本地提交结果若与 gate 状态不明，必须进入 recovery reconciliation，绝不自行重放或推定成功。

**跨持久化提交协议（冻结）**：为避免“gate 已 COMMITTED、Core 尚未发布”的可见性洞，mutation 采用 per-continuity exclusive commit barrier：① gate 对 `(trust_domain_id, continuity_id, active_core_storage_generation_id, epoch, lease, mutation_id, payload_hash, expected_state_version)` 做线性一致 CAS，进入 `PREPARED`、分配下一全局 `state_version` 并阻止 owner/epoch/storage-generation 切换；② 唯一 active storage generation 在一个本地事务写入 assertion + audit hash + assigned state_version，行的可见性由 gate 状态决定（`PREPARED` 时任何 read/projection 必须阻塞或 fail-closed）；③ Core 把绑定 storage generation、DB commit identity、payload/audit hash 的 publish receipt 交回 gate，gate 验证后 CAS `PREPARED → COMMITTED`，此刻自动成为唯一线性化/可见点并释放 barrier；API 随后才返回成功。崩溃发生在本地 commit 前则同 request 重试；发生在本地 commit 后/gate commit 前，则只允许同一 active generation 按完全匹配的本地记录幂等完成 gate CAS，任何不匹配永久 quarantine。

owner/epoch/restore/storage-generation 切换必须先进入 `DRAINING` 并冻结新 PREPARE。原 active storage 可达时，必须收敛全部 PREPARED。若其永久不可达，当前 owner 的 domain-bound restore authorization 可使 control plane 在同一 CAS 中撤销旧 generation credential、把该 generation 所有未决 PREPARED 终结为 `ABORTED` 并记录审计，然后才切换；PREPARED 从未成为可见提交，旧 generation 以后恢复也因所有 read/write/receipt 路径都校验 active generation 而不能暴露或提交它。所有 COMMITTED 已在其绑定 active generation 完整落库。restore generation 激活前必须 materialize gate 的全部 COMMITTED state/audit high-water（已知 ABORTED provisional slots 可形成显式 gap）；缺口返回 `RESTORE_STATE_GAP`。

同一 receipt 不能在另一 generation 发布。`ABORTED` 后只允许同一 `mutation_id + identical payload_hash` 在新 active generation/epoch 建立新 attempt；旧 attempt 永久终止，payload 不同返回冲突，新 attempt 取得新的 state-version candidate。状态不明返回 `MUTATION_OUTCOME_UNKNOWN`；同一 mutation 重试/查询不得形成两个 COMMITTED。write gate ledger 是写序/fence/visibility 权威而非用户内容仓库，不能被 Core point-in-time backup 克隆。

### 4.1.3 展示名归属（非身份）

人类可读名（"清语"）**不参与身份判定**，归属 Constitution（可版本化）。`qingyu_identity_id` 保持不透明标识，不得由名字推导。

### 4.1.4 `retire` 生命周期（冻结）

`retire` = 全局只读 + 保持可查询 + 不可原地撤销。撤销本身是一次新的治理动作并留下审计；`retire` 不删除任何历史。

**措辞澄清（冻结 — 闭环 A-8）**："不可原地撤销"的准确含义分两层，避免实现时二义：**(a) 可查询性永远不可撤销**——retire 后任何历史都保持可查询；**(b) 写能力不可原地恢复**——如需恢复写能力，必须走新的治理动作 `CONTINUITY_UNRETIRE`（记录授权人、原因、生效 `epoch` + 审计），且**不产生新的 identity / continuity**。实现不得把 retire 做成"一个可被直接 UPDATE 回去的布尔位"。

### 4.2 事件判定矩阵（15 个场景）

| 场景 | 新 identity | 新 continuity_id | 正确记录方式 |
| --- | --- | --- | --- |
| `/new` | 否 | 否 | `SESSION_RESET`（关闭旧 session，开新 session） |
| `/reset` | 否 | 否 | `SESSION_RESET` + 记录 reason；不得清空 Core 状态 |
| context compression | 否 | 否 | Runtime 内部；仅在影响理解时记 `CONTEXT_COMPACTED` |
| ChatGPT 新会话 | 否 | 否 | 证据侧产生新的 Conversation 证据；连续性不变 |
| Hermes 新 session | 否 | 否 | `SESSION_STARTED`（带新 `runtime_session_id`） |
| Hermes 重启 | 否 | 否 | 非正常退出记 `TURN_ABORTED`，随后 `SESSION_STARTED` |
| Hermes 重装 | 否 | 否 | 吊销旧 `runtime_instance_id` + 注册新实例（`RUNTIME_REBOUND`） |
| Windows 重启 | 否 | 否 | 同 Hermes 重启 |
| 模型 GPT → Claude | 否 | 否 | `MODEL_CHANGED`（记 provider / model / version） |
| provider 切换 | 否 | 否 | `MODEL_CHANGED` |
| Memory Engine 重建 | 否 | 否 | Derived 层事件；Constitution / Identity 不受影响 |
| Local Journal replay | 否 | 否 | 幂等去重，标记 `DUPLICATE` 或 `ACCEPTED` |
| 数据库 restore | 否 | 否 | 先只读隔离并验证 GENESIS anchor；由 fencing authority 签发 `> max_issued_epoch`，再记 `CONTINUITY_REBASED` |
| 备份恢复到第二台机器 | 否 | 否 | 同上；未取得唯一新 fence 前保持只读（§4.4） |
| 同一 continuity 同时跑两个 runtime | 否 | 否 | 允许多 Runtime 并发读；写入必须持 lease，否则只读降级 |

**结论：以上 15 种情况，产生新 identity 的数量 = 0，产生新 continuity_id 的数量 = 0。** `continuity_epoch` 仅在改变合法写者集合的治理动作中变化，包括 restore activation / rebase、ownership transfer、unretire 与 forced lease revocation；普通 session/runtime/model 变化不推进 epoch。

### 4.3 fork / merge / clone / 双写

| 动作 | 是否允许 | 语义 |
| --- | --- | --- |
| Fork 出"另一个清语" | **Phase 1 禁止** | 返回 `FORK_NOT_SUPPORTED`；不得复制 Constitution/State/provenance 或创建半成品 identity。未来启用必须先有独立版本化继承合同与新 trust domain/GENESIS 规则 |
| Merge 两个 identity | 不允许 | 两个主体不能合并成"同一个存在"；只能在证据层建立关联 |
| Clone（备份复制） | 允许，且只是备份 | 副本不具写权限；恢复副本保持同一 identity，须经 anchor 验证并取得 `> max_issued_epoch` 的 fence |
| 同一 identity 双写 | 禁止 | 写入需写权限 lease；无 lease 者降级为只读 |

**合法 Runtime 写者交接（WRITER_TRANSFER，冻结）**：缺少显式交接流程时，运维无法区分"授权切换"与"脑裂"。因此定义治理动作 `WRITER_TRANSFER`，必须记录 `from_runtime_instance_id` / `to_runtime_instance_id`、`continuity_id`、生效 `epoch`、授权治理 principal、时间；切换时 write gate 原子作废旧租约/未消费 permit 并签发新 epoch。该动作不改变 governance owner。未走该动作的写者切换一律按 split-brain 处理。

**Restore 到旧快照后继续写入的冲突语义**：

1. 恢复动作先进入只读 quarantine；通过 anchor 验证并由 fencing authority 签发 `> max_issued_epoch` 后，才产生 `CONTINUITY_REBASED` 审计记录。只有已证明当前值就是最大已签发值时，新值才恰好为 `+1`。
2. 另一副本即使处于网络分区且未收到通知，也会因每次提交无法通过共享 write gate 而 fail-closed；epoch 较小的一方必须停止写入并转为只读（lease 失效），不得回滚对方的写入。
3. 两边历史已经分歧时：绝不自动合并。必须由所有者显式发起 reconcile，逐条决定保留 / 合并 / 降级为 `CONTESTED`，并保留双方 provenance。
4. 仲裁依据必须可验证：**主依据 = 单调 `continuity_epoch` + 写租约心跳计数**；服务器时间只作辅助（记录 `clock_skew_ms` / `clock_quality`）。禁止用服务器时间戳单独仲裁。

### 4.4 删除与灾难恢复

| 删除对象 | 后果 | 可否恢复 |
| --- | --- | --- |
| Derived Intelligence | 需要重建；历史不受影响 | 可从 Evidence 重建 |
| Runtime cache | 无影响 | 不适用 |
| Local Journal | 未同步的 Runtime Event 丢失 | 不可恢复（明确视为有损） |
| Qingyu Core | 丢失长期理解与治理契约 | 必须能从 Core 自己的备份单元恢复 |
| Gateway Evidence | 丢失历史真源 | 只能从 Gateway 备份恢复（冻结流程） |

**灾难恢复不变量**：Core 恢复后 `qingyu_identity_id` 与 `continuity_id` 必须通过 pinned GENESIS anchor 验证并保持不变；恢复实例保持只读，直到 authoritative fencing authority 签发 `> max_issued_epoch`。审计链保留。Core 备份单元必须至少包含：identity registry、continuity ledger、Constitution 版本链、审计账本、Versioned Intelligence State。

**Split-brain 防止与检测**：安全性不依赖旧 writer 主动观察通知。任何写入都必须先通过 non-cloned linearizable write gate；分区、authority 不可达或 permit 状态不明一律拒写。观察到更高 epoch 仍须停止并上报，但这只是诊断路径，不是唯一防线。

### 4.5 GENESIS Trust Anchor（Stage 0 blocker，冻结）

`GENESIS` 是一次显式、owner-authorized、原子、可审计的 bootstrap ceremony，只能在未初始化的 Core trust domain 执行。普通服务启动、Runtime enrollment、数据库 migration 与 restore 均不得隐式触发 GENESIS。

1. **稳定 trust domain**：bootstrap 前由 owner-controlled root 建立不可由空 Core DB 自行生成的 `trust_domain_id`。non-cloned authoritative genesis registry 以它作为全局唯一 CAS key；两个独立空数据库即使使用不同 `genesis_request_id`，也只能有一个 canonical GENESIS manifest 获准。
2. **先定 manifest，再唯一 claim storage**：先确定 canonical manifest 与全部 IDs。每个空 Core storage 必须先向 non-cloned registry 取得不可由 DB backup 克隆的 `core_storage_instance_id` / `storage_generation_id` 与绑定 credential。registry 以 `(trust_domain_id, manifest_hash, genesis_request_id)` CAS `EMPTY → PREPARED_UNCLAIMED`，再以第二次 CAS 只允许一个 storage generation 进入 `CLAIMED`；相同 request/manifest 可幂等查询，但非 claimed generation 在任何本地 GENESIS 写入前返回 `GENESIS_STORAGE_NOT_CLAIMED`。不同 manifest/request 返回 `GENESIS_CONFLICT`。
3. **跨持久化状态机**：registry 状态冻结为 `PREPARED_UNCLAIMED → CLAIMED(storage_generation) → CORE_COMMITTED(commit_receipt) → ANCHOR_PUBLISHED → COMMITTED`。只有 claimed generation 可在本地单事务创建 genesis/identity/continuity/alias/initial owner/epoch-0/audit；commit receipt 必须绑定 trust domain、storage generation、manifest hash 与本地 commit identity，并在 registry 只登记一次。崩溃恢复规则固定：`CLAIMED` 时只查询该 generation；未落库则用原 manifest 重试，精确匹配则登记唯一 receipt，不同 manifest则永久 quarantine；`CORE_COMMITTED` 时幂等注册 epoch 0/发布同 hash anchor；`ANCHOR_PUBLISHED` 时只验证同一签名并完成。非 claimed 空 DB 永不写 GENESIS。不得生成新 IDs、第二 manifest、自动清除/抢占 reservation；人工放弃须 root 签名且证明 claimed storage 与所有持久化点均无本 manifest。
4. **duplicate prevention**：Core 内 singleton/unique genesis slot只是第二道约束；全局防重的权威是上述 registry 的 unique storage claim + commit receipt。只有 registry=`COMMITTED`、epoch 0 已注册且 claimed generation 被设为 active 时，GENESIS 才对外成功。超时/状态不明返回 `GENESIS_OUTCOME_UNKNOWN` 并保持未激活，重试同一 request 查询状态。
5. **anchor 内容**：至少固定 trust domain、contract/profile version、identity ID、continuity ID、ID scheme、initial epoch、initial governance owner fingerprint、rollback-witness set IDs/public-key fingerprints、quorum threshold（Phase 1 = 2-of-3）、witness protocol/recovery-authorization policy version、genesis nonce、created_at 与 canonical manifest hash/signature；由 owner-controlled root 认证并独立备份/固定。仅持有 Core/control-plane backup 不授予 recovery 权限。
6. **restore identity verification**：Restore 不是 GENESIS。激活前比较备份 genesis record、identity ID、continuity ID、initial owner fingerprint 与 anchor hash；identity/continuity/hash 不一致 ⇒ `RESTORE_IDENTITY_MISMATCH`，initial owner anchor 不一致 ⇒ `RESTORE_INITIAL_OWNER_MISMATCH`。再从 non-cloned governance authority 验证**当前** owner policy/签名所有权链及吊销状态；当前授权不可证明 ⇒ `RESTORE_OWNER_UNPROVEN`。以上均保持只读；禁止生成替代 ID、用 alias 猜测身份或让已吊销 initial owner 激活旧备份。
7. **ownership 分层**：initial owner 是不可变的 `genesis_initial_owner_fingerprint`；当前治理所有权由 non-cloned authority 的签名 `GOVERNANCE_OWNER_TRANSFER` 链决定；Runtime writer assignment 仅使用 `WRITER_TRANSFER`。三者不得复用同一字段或事件。GENESIS 后没有 Runtime 自动获得写权；首个 Runtime 仍须 `RUNTIME_ENROLL`、显式 capability grant 与 lease acquisition。
8. **职责边界与物理约束**：Core trust anchor / genesis registry / governance authority / fencing write gate / suppression authority / audit sequencer 属 Core 治理基础设施。Phase 1 强制这些 non-cloned authority 是同一线性一致 control-plane store/transaction domain 的逻辑模块，使 owner/epoch/generation/redaction/audit CAS 可原子组合；不得部署成无法原子协调的独立权威。Gateway 及其备份 runbook 不承担 Core 身份验证，也不保存 Core identity/alias registry。

### 4.5.1 Governance owner transfer 与 restore authorization（冻结）

1. non-cloned governance registry 的 current record 为 `(trust_domain_id, continuity_id, owner_version, owner_principal_id, owner_key_fingerprint, record_hash, status)`；每个签名 transfer envelope 必须包含 operation type=`GOVERNANCE_OWNER_TRANSFER`、`trust_domain_id`、目标 `continuity_id`、完整 current owner record hash/version/fingerprint、目标 principal/key、trust-domain-scoped `request_id`、reason、created_at，并由当前 owner key 对 canonical envelope 签名。任一字段不得从请求外上下文隐式补入。
2. `GOVERNANCE_OWNER_TRANSFER` 通过线性一致 CAS 从精确 previous record 推进到 `owner_version+1`。相同 request/envelope 重试幂等返回同一结果；相同 request 不同 payload、stale previous version 或并发 loser 分别返回 `OWNER_TRANSFER_CONFLICT` / `OWNER_VERSION_STALE`，零治理副作用。
3. governance registry 与 fencing write gate 必须共享同一线性一致 control-plane commit domain；owner CAS 的生效点同时吊销旧 owner governance capability、其授权的活动 lease/未消费 permit，并在写者集合变化时签发新 epoch。Phase 1 **不允许**跨事务域 fallback；无法提供该原子边界的部署不合规且必须保持 continuity 未激活。
4. restore activation signed envelope 必须包含 operation type=`RESTORE_ACTIVATE`、`trust_domain_id`、`continuity_id`、完整 current owner record hash/version/fingerprint、restore manifest hash、目标 storage instance/generation、requested epoch action 与 trust-domain-scoped request ID，并由 registry 当前 owner 签名；control plane 在签发 restore epoch时原子消费。initial owner anchor 只验证起源，不能替代当前 owner授权；跨 domain/continuity 重放在验签阶段即拒绝。
5. 崩溃恢复只查询 request ID 与 authoritative control-plane state：CAS 前崩溃无变化；CAS 后按同一 envelope 幂等返回；不得根据 Core backup 中的 owner 记录推断 current owner。所有 owner version、撤销与 restore authorization 都纳入统一 control-plane 原子备份及审计。

### 4.6 Identity / GENESIS / Fencing 验收合同（未来实现强制）

1. `qingyu-main` 作为 `continuity_id` 必须失败；作为 alias 可解析到 opaque UUIDv4。
2. alias rename 不改变 identity/continuity；旧 alias 不得转配另一 continuity。
3. identity 与 continuity 只能原子形成完整 1:1 对，禁止 orphan、延迟绑定或 rebind。
4. 对同一 `trust_domain_id`，两个独立空 Core DB 的并发相同 GENESIS request 只创建一次并幂等返回同一 IDs；并发不同 request/manifest 只能一个取得 registry reservation，另一个 `GENESIS_CONFLICT`。
5. 已初始化 Core、startup、migration 与 restore 均不得触发 GENESIS。
6. restore 中 identity/continuity/initial-owner/anchor 任一不匹配，或当前 governance owner policy/吊销状态无法证明时保持只读；owner 轮换后的合法新 owner 可按签名链激活，已吊销旧 owner 用旧快照激活必须失败。
7. missing/stale/future epoch 与错误 lease token 均被拒绝，业务数据和 `state_version` 不变。
8. 两个相同快照恢复实例必须服从同一 non-cloned linearizable write gate，最多一个能取得逐 mutation commit permit；旧 writer 即使暂停后恢复且未收到新 epoch 通知也无法提交。authority 不可达时双方均不得自行激活或写入。
9. 对 `PREPARED_UNCLAIMED`、`CLAIMED`、`CORE_COMMITTED`、`ANCHOR_PUBLISHED` 每个崩溃边界做故障注入；相同 request 被两个空物理 DB 并发使用时只能一个 storage generation 获得 claim 且只有该 DB 出现 GENESIS record；不同 request 永不形成第二 GENESIS，唯一 commit receipt/epoch 0 注册恰好一次。
10. GENESIS 后首个 Runtime 默认只读；未 enroll/grant/lease 的写请求失败。
11. Gateway Evidence Query API 不接受 alias 作为 selector，不创建/remap continuity，且查询语义不因任何 continuity claim 改变。
12. 并发 owner transfer 只能一个 CAS 成功；重放/stale owner 失败。owner 轮换与 restore activation 的每个崩溃边界均须证明旧 owner 不能签发新 epoch 或取得 commit permit。
13. gate PREPARED 前、本地 commit 后/gate COMMITTED 前逐点故障；owner/epoch/restore 切换在任何 PREPARED 未收敛时不得完成，读取遇到 state-version gap 必须阻塞/fail-closed，COMMITTED receipt 在另一 storage generation 发布必须失败。
14. owner-transfer 与 restore envelope 在另一 `trust_domain_id` / `continuity_id` 重放必须返回 scope 错误且零副作用；签名覆盖 operation type 与完整 current owner record hash。
15. restore storage generation 必须连续 materialize 到 gate 的 committed state/audit high-water；落后备份返回 `RESTORE_STATE_GAP` 并保持 quarantine。
16. 原 active storage 永久丢失时分别覆盖“无 PREPARED”和“存在 PREPARED”：current owner 可撤销 generation；后者必须先权威 ABORT 并审计。旧 generation 后续恢复不能读写，ABORTED mutation 仅能以同 ID/同 payload 在新 generation 安全重试且最多一个 COMMITTED。
17. GENESIS/governance/write/restore/suppression 并发争用同一 audit head 时只能线性产生一条连续链；同 seq/同 predecessor 分叉必须在业务状态生效前被 audit sequencer CAS 拒绝。
18. control-plane restore 必须覆盖：单模块旧快照、整体一致旧快照、跨快照拼接、snapshot/WAL 缺口、witness 分歧与全损恢复；只有达到 2-of-3 latest COMMITTED checkpoint 的完整原子单元可申请新 generation，其余全部 quarantine。
19. 两个独立实例从同一 snapshot+WAL 并发恢复时，2-of-3 monotonic witness CAS 只能给一个 instance/new generation recovery claim；loser不能签发 owner/epoch/storage credential/permit。逐点故障覆盖 local PREPARED、witness PREPARED、local COMMITTED、witness COMMITTED、recovery claimed/activated；无 commit receipt 的 PREPARED 可审计 ABORT，有 receipt 的必须幂等收口，witness不得双签。
20. 仅持合法 snapshot+WAL但无 current-owner签名、替换 witness set、本地伪造3个 witnesses、旧 set 在轮换生效点后重放、跨 domain recovery envelope 均必须在 claim 前拒绝；合法 witness rotation须旧/新 quorum cross-certificate连续且可从 GENESIS anchor 验证。

---

## 5. `continuity_id` Contract

| 问题 | 规则 |
| --- | --- |
| 谁创建 | Phase 1 仅唯一 Core GENESIS；其它创建路径全部拒绝 |
| 是否可变 | 不可变；分配后永不变更，永不重用 |
| 是否可复制 | 可复制到备份；副本无写权限 |
| 是否可 fork | Phase 1 不支持，稳定返回 `FORK_NOT_SUPPORTED`；未来版本另审 |
| 是否可 merge | identity 之间不可 merge；同一 continuity 内可 reconcile |
| 删除语义 | 随 identity retire 一起退役（`retired`），不物理删除历史 |
| 灾难恢复 | 先验证 continuity identity / GENESIS anchor；恢复实例保持隔离，由非克隆 Fencing Authority 签发严格大于历史 `max_issued_epoch` 的新 epoch 后才可写 |
| Runtime 如何引用 | Runtime 用 `continuity_id` 请求 Context / 提交 Event；Core 校验其存在且未退役 |
| Event 如何引用 | 每个 Runtime Event 必须携带 `continuity_id`；不匹配则拒收 |
| Context 如何引用 | 每个 Projection / Context 必须返回 `continuity_id + continuity_epoch + state_version`，使陈旧缓存可检测 |

编码：Phase 1 `continuity_id` 使用 UUIDv4 canonical text form，创建后不可变、不可重用、不可 remap；消费者必须按 opaque string 处理。`qingyu-main` 仅是首个 continuity 的 alias。alias 可采用 `^[a-z0-9][a-z0-9-]{2,63}$`，在有效 alias 与 tombstone 的联合命名空间内唯一。

补充冻结规则：

1. **绑定与基数**：`continuity_id` 与 `qingyu_identity_id` 为 1:1 且绑定后不可改绑（§4.1.1）。
2. **epoch 作用域**：`continuity_epoch` 属于 continuity；写租约与写校验都以 `(continuity_id, epoch)` 为键（§4.1.2）。
3. **退役语义**：identity `retire` ⇒ 其 continuity 一并进入只读保留态，历史仍可查询，不物理删除（§4.1.4）。
4. **拒收而非自动创建**：任何未知或已退役的 `continuity_id` 一律 `REJECTED`；Core 不得因某个 Runtime 声明了陌生 continuity 而自动创建它。
5. **禁止外部标识替代**：Hermes session id、ChatGPT conversation id、model id、provider id、数据库主键一律不得用作 continuity identity。

---

## 6. Runtime / Session Identity

- `runtime_instance_id`：一个安装实例（例如某台机器上的某个 Hermes 安装）。可吊销、可轮换；轮换产生审计记录，**不产生**身份变化。
- `runtime_session_id`：一次会话，短命，可丢弃，永远不是 Qingyu Identity。
- `turn_id`：一轮交互；用于串联 `USER_ACCEPTED` / `ASSISTANT_COMPLETED` / `TURN_ABORTED`。
- 多 Runtime 并存：允许并发读与并发事件提交（append-only）；对 Core 状态的写入需要写 lease，避免双写。

---

## 7. Model Independence

GPT / Claude / Gemini / local model / future model 全部只是 runtime inference provider。

- 切换模型产生 `MODEL_CHANGED` 事件，不产生新 Qingyu。
- 模型可以影响本轮的推理与措辞；模型不拥有身份。
- 推论（必须在产品上显式承认）：模型更换后"清语还是清语"（身份 / 理解 / 关系连续），但**表达风格可能改变**。若某段措辞本身重要，它必须被显式提升为 Core 断言才能跨模型存活，而不是依赖某个模型"记得"。
- Core 的 Projection 必须模型无关：同一 `state_version` 对任何模型呈现同一语义内容。
- 模型不得参与 identity 判定；`MODEL_CHANGED` 不得触发 continuity 变更或 Derived 重建。

---


## 8. Constitution Contract

### 8.1 Canonical 位置

Canonical Constitution 存于 **Qingyu Core**（治理性契约，不是 Evidence）；`SOUL.md` 只是它的 Runtime projection（§18）。它不得以 Hermes `state.db`、`MEMORY.md` 或某个 prompt 文件为权威副本。

### 8.2 版本化

- `constitution_version`：单调递增版本号 + 内容哈希。
- 每次修订 = 不可变 revision，带 `revision_id`、`previous_revision_id`、`actor`、`change_class`、`reason`、`evidence_refs[]`（若由某次对话驱动则引用 Gateway evidence）、`created_at`、`approval`。
- 修订形成不可变链；禁止原地改写。

### 8.3 谁可以修改

| 行动者 | 能否修改 Constitution | 条件 |
| --- | --- | --- |
| 用户（所有者）显式修改 | 可以 | 显式治理动作；记录 reason + 证据引用 |
| 治理流程（带审批） | 可以 | 需要审批记录 |
| 自动 Memory Intelligence | 禁止 | 只能提交 `PROPOSED_AMENDMENT` 提案，默认不生效 |
| Runtime / Model | 禁止 | 只能提交提案或转述用户意图 |

**用户显式修改 vs 模型自动学习**：前者是权力行为（立即生效 + 审计）；后者是建议（inert 直到批准）。二者在数据上必须是不同 `change_class`，不可混淆。

### 8.4 内容分区（建议）

1. Identity & Sovereignty：清语是谁、记忆属于谁、谁拥有最终决定权。
2. Stable persona constraints：稳定人格约束（跨模型保持一致的最小集合）。
3. Relationship principles：关系原则（如何对待用户、边界与承诺）。
4. Continuity rules：什么算同一个清语、什么算新 session。
5. Governance：谁能改什么、如何审批、如何审计。

### 8.5 高保护属性

- 修改需要独立 capability（`constitution_admin`），不与 Runtime / Memory Intelligence 共享。
- 每次修改产生审计记录；删除 Constitution revision 不在正常能力范围内（只能新增或标记退役）。
- Constitution 是本设计中唯一允许 `UNGROUNDED`（无 evidence）的持久化内容，因为它是治理起点而非推导结论。

---

## 9. User Model Contract

### 9.1 两条正交轴（核心设计判断）

- **kind 轴（这是哪一类主张）**：`FACT` / `BELIEF` / `HYPOTHESIS` / `PREFERENCE` / `RELATIONSHIP_STATE`（+ 可扩展 `EVENT_INTERPRETATION`）。
- **epistemic_source 轴（它凭什么存在）**：`USER_STATED` / `INFERRED` / `OBSERVED_PATTERN` / `SYSTEM_DERIVED`。

**结论：两轴正交，不可合一。** 用户给出的例子正是判据：

- "我喜欢 X" = `kind=PREFERENCE` + `source=USER_STATED`
- "他似乎更喜欢 X" = `kind=PREFERENCE` + `source=INFERRED`

二者 kind 相同、权威不同，因此绝不能被合并成同一条事实。把 `USER_STATED` 当作一个 kind 是设计错误。

### 9.2 断言字段（最小字段集）

| 字段 | 说明 |
| --- | --- |
| `assertion_id` | 不可变主键 |
| `identity_id` / `continuity_id` | 归属 |
| `subject` | `qingyu` / `user` / `relationship` / `external` |
| `kind` | 见 §9.1 |
| `statement` / `statement_json` | 人可读表述 + 结构化表述 |
| `epistemic_source` | 见 §9.1 |
| `content_confidence` | 对内容的置信度（0..1） |
| `claim_origin` | **派生字段（禁止独立写入）**：`USER_STATED → USER_SPEECH_ACT`，其余 `→ DERIVED_PROCESS`（§9.3）；只描述来源，不描述命题真假 |
| `speaker_principal_id` / `principal_binding_ref` | 仅 `USER_STATED` 必填：受治理的用户 principal；Gateway v1 引用 exact observation/archive custody attestation，Runtime 引用 interaction-principal binding，禁止裸 `source_account_id` 充当证明 |
| `speaker_authentication` | `VERIFIED` / `UNVERIFIED`；只有 `VERIFIED` 可进入 `USER_STATED` |
| `gateway_evidence_refs[]` | Gateway Historical Evidence 引用（§14.1） |
| `runtime_event_refs[]` | Core 已接受的 Runtime Event 引用（§14.2）；与 Gateway namespace 分离 |
| `input_assertion_ids[]` | 派生/rollup 所依赖的 Core assertions；不得塞入 Gateway evidence ref |
| `valid_from` / `valid_to` | 语义有效期（不等于记录时间） |
| `supersedes` / `superseded_by` | 修正链 |
| `lifecycle_status` | `ACTIVE` / `SUPERSEDED` / `RETRACTED` / `CONTESTED` / `EXPIRED` / `REDACTED`（§13.1） |
| `integrity_flag` | `OK` / `SUSPECT` / `UNRESOLVED_EVIDENCE`（与生命周期正交，§9.4） |
| `reason` | 为什么建立 / 为什么被取代 |
| `producer_id` / `producer_type` / `producer_version` | DERIVED 必填的不可变 emitter 身份；Memory Intelligence 只以 `producer_type=DERIVED_STATE_PRODUCER` 出现 |
| `trust_class` | 只读函数字段：assertion 仅允许 `VERIFIED_USER_SPEECH_ACT` / `DERIVED_OUTPUT`（§9.5）；不得由 producer/client 写入或升级 |
| `derivation_descriptor` / `derived_at` | DERIVED 必填；结构化固定 algorithm、model、非内容型 prompt artifact identity/version/digest、parameter schema + 实际 canonical values（或受控 artifact identity/version/digest）、seed/窗口/规则开关与 rebuild-contract version；禁止正文/secret/rendered prompt/input excerpt，不得只存一个自由文本版本号 |
| `derivation_version` | `derivation_descriptor` canonical form 的版本化 digest/短标识，仅用于索引与展示，不能替代 descriptor |
| `invalidation_status` / `invalidation_reason` / `invalidated_at` | DERIVED 独立状态：`VALID` / `STALE` / `INVALIDATED`；与 assertion lifecycle/integrity 正交 |
| `recorded_at` / `updated_at` | 记录时间（`updated_at` 仅用于状态迁移，不用于改写内容） |

**重要区分**：对 `USER_STATED`，证据只支持 speech act（"用户确实做过该陈述"）；它不支持 proposition truth（"X 客观为真"）。`claim_origin=USER_SPEECH_ACT` 只描述来源，`content_confidence` 不得因 `USER_STATED` 自动设为 1.0。内容仍可能过时、矛盾、误述或不可客观判定。

### 9.3 `claim_origin` 必须由来源派生（冻结）

`epistemic_source` 与来源分类若可各自独立写入，就会产生 `source=INFERRED` + `origin=USER_SPEECH_ACT` 这类自相矛盾记录。因此冻结：

- `claim_origin` 由 `epistemic_source` **函数派生**（`USER_STATED → USER_SPEECH_ACT`，其余三种 → `DERIVED_PROCESS`），实现层面必须做成生成列 / 约束或只读计算，**禁止独立写入**。
- 迁移或导入时必须校验该函数关系成立，不成立即拒绝写入。
- `USER_STATED` 必须同时证明 speech act 与 speaker 归属。Gateway v1 的 `SourceAccount`（包括 platform default/空 external account）只作导入路由，**绝不是身份认证**，不得单独绑定 principal。Gateway 路径要求：role=user bound revision、`create_time_parse_status == "parsed"`、`normalized_timestamp != null`，以及当前 owner 对精确 observation/archive scope 的不可变 custody attestation；其它 parse status 或缺 attestation 一律只保留未归属 Historical Evidence。Runtime 路径要求 Core 已接受事件、事件携带经 enrollment/capability 认证的 interaction principal binding，且 payload 明确是该 principal 的原话/确认。缺少任一证明时不能生成 `USER_STATED` assertion。
- `USER_ACCEPTED` 仅表示 Core 接受了 Runtime 事件，不自动表示用户认证或治理授权。使 boundary/commitment 生效的 governance action 还必须由当前 owner capability 独立签名验证。
- Gateway v1 custody attestation 为 `{attestation_id, trust_domain_id, speaker_principal_id, archive_object_id, conversation_observation_id, source_observation_fingerprint+version, valid_source_time_interval, owner_record_hash/version, attested_at, request_id, signature, audit_ref}`；也可用签名 observation manifest + inclusion proof 批量表达，但禁止 wildcard `source_account_id/platform`。签名覆盖完整 scope/hash/principal/interval，admin/read token、上传者或 ZIP 自述均不能创建 attestation。source message time 必须落在半开 `[valid_from, valid_to)`；同一 observation/speech scope 的冲突 principal attestations使其未归属并触发治理审计。
- Runtime principal binding 是版本化治理记录 `{binding_id, runtime_subject, speaker_principal_id, valid_from, valid_to, owner_version, authorization_ref, lifecycle, audit_ref}`，有效区间同样为半开、不得重叠。Gateway attestation和 Runtime binding 的创建、缩短、撤销都需 current owner 授权、同事务审计并推进 `state_version`，不得追溯改写；restore 必须从 governance authority/audit验证完整历史，无法证明则相关 speech acts 全部未归属。
- 用户对 boundary / commitment 的明确治理动作可以使规则生效，但这是 owner governance authority，不是把 proposition 晋升成 Objective World Truth。

### 9.4 生命周期与完整性必须分离（冻结）

单字段 `status` 无法同时表达"这条断言是否已被取代"与"它的证据是否仍可解析"。因此拆为：

- `lifecycle_status ∈ {ACTIVE, SUPERSEDED, RETRACTED, CONTESTED, EXPIRED, REDACTED}`
- `integrity_flag ∈ {OK, SUSPECT, UNRESOLVED_EVIDENCE}`

一条断言可以同时是 `SUPERSEDED` + `SUSPECT`；`SUSPECT` 不影响"历史可查询"，只影响它能否作为当前依据。

### 9.5 禁止混同的规则

1. `USER_STATED` 断言不得被 DERIVED 断言改写或 supersede。`INFERRED` / `OBSERVED_PATTERN` / `SYSTEM_DERIVED` 只能对其 `CONTEST`、降低 freshness、建议 `EXPIRE`，或等待新的已认证 `USER_STATED` / owner governance action；不得单独使明确用户陈述退出 current view。
2. `INFERRED` / `OBSERVED_PATTERN` / `SYSTEM_DERIVED` 不得静默改写为 `USER_STATED`。用户确认时产生新的 `USER_STATED` 断言，并链接被确认的推导断言；这只改变 claim origin，不裁决命题客观为真。
3. 普通断言不得 `UNGROUNDED`。`UNGROUNDED` 仅允许 Constitution bootstrap；GENESIS 由 trust anchor 支撑，不以 `UNGROUNDED` 断言代替。
4. 可执行谓词冻结为 `is_derived_process := epistemic_source != USER_STATED`；因此 `INFERRED`、`OBSERVED_PATTERN`、`SYSTEM_DERIVED` 全部必须带 producer、trust class、完整 input refs、descriptor、derived time 与 invalidation 字段，不能借不同枚举绕过。无模型/无 prompt 的纯规则 producer 使用显式 `model:null, prompt:null, applicability:NOT_APPLICABLE`，descriptor 仍按版本化 canonical JSON profile 计算 digest。
5. DERIVED producer 不得创建或修改 principal binding。输入变为 `REDACTED` / `RETRACTED` / `UNRESOLVED_EVIDENCE` 时，所有传递 descendants 原子转为 `INVALIDATED`；输入变为普通 `SUPERSEDED` / `CONTESTED` / `EXPIRED` / `SUSPECT`、出现与输入/输出矛盾的新证据，或 producer/descriptor 退役时，传递 descendants 转为 `STALE`。两者都立即退出 current projection并审计原因/根输入/闭包范围；恢复必须生成新 assertion，旧输出保留可查询。唯一窄豁免是 `reason=SUPERSEDED_BY_CANONICAL_ROLLUP` 的**representational leaf**：它只允许以包含该 leaf 的完整 canonical leaf-set 生成的当前 rollup R 保持 VALID，不豁免任何其它 descendant；leaf 的任何 integrity/invalidation/内容型 lifecycle 变化仍使 R 失效。事务顺序固定为 lock semantic group → flatten/validate leaf set → compute closure/exemption → 原子发布 leaf/old-rollup lifecycle + R ACTIVE/VALID + audit/state version。
6. `trust_class` 函数约束：`epistemic_source=USER_STATED` 且 §9.3 speaker/binding 验证通过 ⇒ `VERIFIED_USER_SPEECH_ACT`；所有 `is_derived_process` ⇒ `DERIVED_OUTPUT`。`GATEWAY_RECORDED` 只属于 Gateway Evidence/ref 层，`RUNTIME_ASSERTED` 只属于 Runtime Event 层，均不得直接写入 assertion trust class；`GATEWAY_LINKED` 不改变 Runtime payload，也不把 DERIVED 输出升级。

**未来实现验收**：default/空 external-account SourceAccount、admin 上传伪造/他人 ZIP、错误或 wildcard custody attestation、错误 principal、无有效 source-native message time、仅 `USER_ACCEPTED` 但未认证 speaker 均不得创建 `USER_STATED`；只有 owner-signed exact observation/archive attestation 可归属。全部 hard/soft 触发器必须传递标记所有派生后代；2/3/更多同义 D 的全部到达排列、并发和重放必须 flatten 到同一 leaf set/output identity；重建产生新 assertion 并保留旧 provenance。

### 9.6 跨 epistemic source 修正矩阵（冻结）

`U = USER_STATED`，`D = INFERRED | OBSERVED_PATTERN | SYSTEM_DERIVED`；三种 D 之间**没有隐含权威排序**。以下动作与 assertion/lifecycle links、审计、`state_version` 必须在同一本地发布事务完成：

| old → new（同 semantic key） | 同 proposition | 矛盾 proposition |
| --- | --- | --- |
| U → U | 新 U `SUPERSEDE` 旧 U（reason=`USER_REITERATED`），新 U ACTIVE | 时间顺序明确则新 U `SUPERSEDE` 旧 U；时间重叠/顺序不明则双方 `CONTESTED` |
| U → D | U 保持 ACTIVE；D 以 `CORROBORATES` 链接并置为 `SUPERSEDED`（不进入 current view） | U 保持 ACTIVE；D=`CONTESTED` 并以 `CHALLENGES` 链接，禁止 supersede U |
| D → U | U ACTIVE 并 `SUPERSEDE` D（reason=`USER_CONFIRMED`） | U ACTIVE 并 `SUPERSEDE` D（reason=`USER_CORRECTED`） |
| D → D（同一明确 replacement lineage） | 新 D 可 `SUPERSEDE` 旧 D；必须声明 predecessor 与 producer/rebuild policy | 有显式、预先版本化的 adjudication policy 才可 supersede，否则双方 `CONTESTED` |
| D → D（不同 lineage/source） | 必须运行无模型 `corroboration-rollup-v1`：对同一 semantic-key/proposition/valid-interval 的**完整 immutable leaf equivalence class** flatten + dedupe + sort，产生引用全部 leaves 的 canonical `SYSTEM_DERIVED` rollup；leaves/旧 rollup均 `SUPERSEDED`，唯一新 rollup ACTIVE。失败则整次写入拒绝 | 双方 `CONTESTED`；必须由新 U、owner governance adjudication 或版本化 deterministic policy 解决 |

`CORROBORATES` / `CHALLENGES` 是 provenance relation，不是假装成 supersession。rollup 遇到既有 rollup 必须递归展开到原始 leaves，禁止把嵌套 rollup 当 leaf；用全部 sorted leaf IDs、canonical proposition/key/interval、policy version 计算 descriptor digest 与 output identity/idempotency key。semantic-group version 采用 CAS；并发 loser 重新读取完整 class 再得到同一 output，三条以上输入的任意到达排列、重放和 restore 必须一致。仅使用 §9.5 representational-leaf 窄豁免。用户确认 derived assertion 时创建新 U，旧 D 按矩阵迁移并保留；任何路径都不得产生同键/区间两个 ACTIVE。

---

## 10. Relationship Model Contract

### 10.1 需要版本化的内容

| 内容 | 建议 kind | 是否必须 evidence |
| --- | --- | --- |
| relationship stage | `RELATIONSHIP_STATE` | 是（阶段性判断必须有依据） |
| interaction preferences | `PREFERENCE` | 是 |
| boundaries / 边界 | `RELATIONSHIP_STATE`（高保护） | 是；用户 speech act 可通过治理动作使边界生效，但不等于 proposition 客观为真 |
| shared conventions（约定） | `FACT` / `RELATIONSHIP_STATE` | 是 |
| important shared events | `FACT`（+ 事件解读另立断言） | 是（引用 Gateway evidence 或 Runtime Event） |
| relationship interpretation | `BELIEF` / `HYPOTHESIS` | 是 |
| unresolved relationship context | `HYPOTHESIS` / `OPEN_QUESTION` | 是（并明确标记"尚未解决"） |

### 10.2 硬规则

1. 一次模型生成的浪漫措辞，永不自动成为 Relationship Fact。它最多是 `INFERRED` 的 `RELATIONSHIP_STATE` / `BELIEF`，未确认前不得进入高权威层。
2. 边界（boundaries）与承诺属高保护：模型不得自行放宽；放宽必须来自用户显式陈述。
3. 关系理解可以成长、可以修正，不能因换 Runtime 清零：删除 Runtime 后，Relationship projection 必须能原样重建。
4. "未解决" 必须是一等状态，不能因为想要一致而被迫编造结论。
5. 关系主张的确认路径与 §9.3 一致：用户显式确认产生新的 `USER_STATED` / `USER_SPEECH_ACT` 来源记录，不把命题晋升为 Objective World Truth。

---

## 11. Belief / Hypothesis Contract

**是否需要独立语义类型？需要，但不是把所有类型塞进一个枚举。**

建议：`kind` 采用封闭但可版本扩展的枚举（`FACT` / `BELIEF` / `HYPOTHESIS` / `PREFERENCE` / `RELATIONSHIP_STATE`），并显式绑定以下维度：

| 维度 | 取值 | 作用 |
| --- | --- | --- |
| `kind` | 上述枚举 | 语义类别 |
| `epistemic_source` | USER_STATED / INFERRED / OBSERVED_PATTERN / SYSTEM_DERIVED | 权威来源 |
| `content_confidence` | 0..1 | 对内容的置信 |
| `contradiction_links[]` | assertion_id | 显式记录矛盾（不隐藏） |
| `supersession` | supersedes / superseded_by | 修正链 |
| `revision` | 断言不可变 | 修订 = 新增 + 链接，不是 UPDATE |

Epistemic status 判定示例：

- "用户自己说自己英语较弱" → `kind=FACT`（关于用户自述的事实）+ `source=USER_STATED`；同时可派生 `kind=BELIEF`（关于其能力）+ `source=INFERRED`。二者必须具有不同 epistemic status，且不可互相覆盖。
- "系统推断用户可能偏好中文技术解释" → `kind=HYPOTHESIS` / `PREFERENCE` + `source=INFERRED`，带 `derivation_version`，可被用户一句话推翻。

**`kind=FACT` 的边界（冻结）**：`FACT` 仅表示"某来源提出了事实性 proposition 且 Core 登记了该 claim"，**不等于 Objective World Truth**。Gateway Evidence 是最高级 Historical Evidence，证明系统/来源曾记录到什么，也不裁决客观世界真相（对齐 `SOURCE_OF_TRUTH_CONTRACT.md`）。因此 `FACT` 必须同时携带 `epistemic_source`；任何来源的 `FACT` 都不得仅凭其 kind/source 被称为“客观已确认事实”。

矛盾处理：两条 ACTIVE 断言实质冲突时标记 `CONTESTED`（两条都保留），并显式暴露待解决；禁止静默择一。这是"允许修正而不是清空"和"允许矛盾存在"的共同落地方式。

---

## 12. Versioning

三条不得混淆的版本线：

1. **Evidence 版本线**（Gateway 已冻结）：`revision_fingerprint`、`semantic_revision_fingerprint`、`source_observation_fingerprint`、`canonical_fragment_fingerprint`（各自带 `*_version`）。
2. **Core 治理版本线**：`constitution_version`、`state_version`（Versioned Intelligence State 的整体版本 / 游标）、`continuity_epoch`。
3. **推导版本线**：结构化 `derivation_descriptor`（algorithm + model + prompt artifact + parameter schema + canonical actual values/artifact refs + seed/window/flags + rebuild contract）及其 `derivation_version` digest，写入每条 DERIVED 断言。非敏感值直接 canonicalize；敏感/内容型配置只保存受控 artifact identity/version/digest，secret/正文不得进入 descriptor；重建必须解析完全相同 artifact versions。

规则：

- 断言的语义内容不可变；修订 = 新增断言 + supersession 链接。唯一受控例外是 §13.1 `REDACT` 对 payload 的墓碑替换；它不改变 assertion identity/provenance。Core 内的 tombstone、descendant invalidation、审计与 `state_version` 必须同一事务提交；跨 non-cloned suppression authority 采用 §13.1 的显式 `BLOCKING → COMMITTED` 协议，不虚构跨存储单事务。
- `state_version` 单调递增；Projection 必须携带它，使缓存与陈旧读取可检测。
- 任何"当前视图"都是 `state_version` 的函数：`projection = f(assertions @ state_version)`，必须可重算。
- 三条版本线不得互相替代：Constitution 版本变化不改变 Evidence 指纹；Evidence 指纹变化不得自动改变 Constitution。

**`state_version` 粒度（冻结）**：`state_version` 是 **per-continuity 的全局单调游标**。推进条件：任何断言写入、任何 lifecycle / integrity / `invalidation_status|reason|at` 迁移、任何传递失效闭包、任何 Constitution 生效修订。所有导致 assertion 进入/退出 current projection 的变化都必须在同一发布事务推进版本并触发 cache invalidation。**不推进**：重复事件（`DUPLICATE`）、被拒绝的写入（`REJECTED`）、只读查询、未改变持久 assertion 状态的 Derived cache refresh。`state_version` 不得回退；恢复后的首个写入版本必须由 non-cloned write gate 从其 authoritative high-water 分配，严格大于全部已提交版本，不得仅按恢复点本地 `+1`；`continuity_epoch` 同时区分恢复前后。

### 12.1 写入原子性与状态增长（冻结 — 闭环 C-10 / B-10）

**写入原子性（C-10）**：断言写入、对应审计记录、`state_version` 推进**必须在同一事务内完成**，不允许出现"断言已落库但审计缺失"或"`state_version` 已推进但断言未落库"的中间态。批量导入对齐 Gateway 已确立的 `IMPORT_BATCH_COMMIT` 整批提交语义：**整批成功或整批不留痕**，不得部分提交。

**状态增长（B-10）**：Versioned Intelligence State 允许增长，但**永不通过删除旧断言来控量**。允许的控量机制只有"在保留原断言的前提下派生摘要 / 卷起（rollup）断言"，且摘要断言必须：① 通过 `input_assertion_ids[]` 指向原始断言（不得伪装成 Gateway evidence ref）；② 带独立 `derivation_version`；③ 可被原始断言推翻。具体保留 / 卷起策略（阈值、压缩周期）**本轮不设计**，转为 Phase 2 前独立议题，但其不可逆原则自本轮起冻结。

### 12.2 Audit tamper evidence（冻结）

Core audit 不是只靠数据库 `append-only` 权限。每个 trust domain 只有一个位于统一 non-cloned control plane 的线性一致 audit sequencer；它以 CAS 唯一分配 `audit_seq` 并验证 `previous_record_hash == current_audit_head`。版本化 canonical record 记录 `record_hash`、operation type、actor/capability、continuity/epoch/state version、request/mutation ID、result code 与时间；hash chain 不记录被 REDACT 的正文。所有改变 identity、owner、writer、Constitution、assertion、lifecycle/integrity/invalidation、principal binding、redaction 或 restore 状态的操作都必须产生记录。

所有 control-plane 模块共享同一存储事务边界：GENESIS/owner/restore/suppression/write-gate 的业务 CAS 必须在同一事务消费下一 audit slot并推进唯一 audit head，否则业务状态不生效。Core mutation 的 gate PREPARE 预留 audit slot，本地事务写相同 record，gate 只在 receipt 匹配时原子 `COMMITTED + audit-head advance`；ABORTED 也以独立审计 record 消费/关闭其 provisional slot，禁止链分叉。不得用“稍后周期性备份”留下可回滚未锚定窗口。key rotation 通过带前后 key fingerprint、旧/新 key 交叉签名的审计记录完成；丢失验证链不得静默开新链。

启动/restore 必须从 GENESIS 到 authoritative latest audit high-water 验证序号连续、hash、签名/receipt、continuity/epoch/state-version 对应关系。删除、插入、重排、fork chain、重复 seq、并发 authority 基于同一前驱、Core DB 自报 high-water 高于/低于 authority、或任一 receipt 不匹配 ⇒ `AUDIT_CHAIN_INVALID` / `AUDIT_HIGH_WATER_UNPROVEN`，保持 quarantine 且 current projection 不可服务。未来验收必须覆盖跨模块并发 CAS、各崩溃边界与逐类篡改，并证明只有一条 audit head、旧备份不能回滚审计或治理状态。

---

## 13. Correction / Supersession

**核心不变量：不能被清空，但允许被修正。**

```text
State V1 (ACTIVE)
   |  superseded_by
   v
State V2 (ACTIVE)      <- V1 变为 SUPERSEDED，内容仍在
```

禁止：`UPDATE old_belief SET content = new_belief`（历史消失）。允许的四类修正：

| 动作 | 语义 | 结果 |
| --- | --- | --- |
| SUPERSEDE | 新理解取代旧理解 | 旧 = `SUPERSEDED`，新 = `ACTIVE`，链保留 |
| RETRACT | 认为旧断言本身错误 / 不该存在 | 旧 = `RETRACTED`（仍可查询） |
| CONTEST | 出现无法立即解决的矛盾 | 两条都 `CONTESTED` |
| EXPIRE | 超过 `valid_to` 自然失效 | 旧 = `EXPIRED`，无替代 |

必须能回答的两个问题（可验证验收）：

1. "清语以前为什么这样理解我？" → 返回被 `SUPERSEDED` 的断言 + `reason` + `evidence_refs` + `derivation_version`。
2. "后来为什么改了判断？" → 返回取代者的 `reason` + `evidence_refs` + `derivation_version` + 触发时间。

**具体推演（User Model 案例）**：

- `A1` 2026：`kind=PREFERENCE`、`source=USER_STATED`、`lifecycle_status=SUPERSEDED`、`integrity_flag=OK`、"喜欢 A"、`valid_from=2026`、`superseded_by=A2`
- `A1'` 2027：`kind=PREFERENCE`、`source=INFERRED`、`lifecycle_status=EXPIRED`、"似乎不再提 A"、带完整 derivation descriptor/input refs；它可降低 A1 freshness 或触发复核，但**不得** supersede A1
- `A2` 2028：`kind=PREFERENCE`、`source=USER_STATED`、`lifecycle_status=ACTIVE`、"明确不喜欢 A"、`supersedes=A1`、`reason="用户在会话中明确否定"`
- 当前视图：不喜欢 A（来源：用户明确陈述，2028）
- 历史查询：权威修正链 A1 → A2；A1' 作为独立 derived observation 保留并链接其输入，但不进入该 supersession 链。2026 的记录没有被删除。

**验收要求**：任何"当前视图"都必须可被重算；任何被修正的断言都必须仍可查询到 `reason` 与 `evidence_refs`。做不到即视为设计不达标。

**有效区间唯一性（冻结）**：任一有效时刻，同一 `(subject, kind, 语义键)` **至多一条 `ACTIVE`**。

- 语义键的定义由各 kind 决定（例如 `PREFERENCE` 用"偏好对象"作键），必须在契约层显式声明，而不是隐含在文本里。
- 出现重叠且内容实质冲突时：不静默择一，双方置 `CONTESTED` 并显式暴露待解决。
- 迟到事件（§15.3）只允许**新增**断言，**不得**改写既有 `ACTIVE` 断言的有效区间；因此迟到内容只能通过 `SUPERSEDE` / `CONTEST` 进入视图。
- 无实质冲突的能力型偏好（例如"喜欢 A"与"喜欢 B"）不属于重叠冲突：它们语义键不同。

### 13.1 用户发起的删除 / 擦除（冻结默认规则）

用户主权与"历史不可清空"必须同时成立，因此不允许出现"用户要求删除、系统回答不能删"。冻结如下默认规则：

1. **支持内容擦除（REDACT），不支持记录销毁**。用户显式要求删除敏感 `statement` 时执行 `REDACT`：
   - `lifecycle_status = REDACTED`；
   - `statement` / `statement_json` 被墓碑替换（如 `[redacted by user request]`），原文不再可读；
   - **保留** `assertion_id`、`kind`、`epistemic_source`、`recorded_at`、supersession 链位置与 `reason=USER_DELETION_REQUEST`；Phase 1 不保留原文 plaintext 或无密钥 deterministic hash。为实现防重新物化，必须在独立 suppression ledger 保存由 server-only 高熵密钥计算、带 canonicalization/profile version 的 keyed commitment；密钥不得进入 Core 普通 DB 备份、API、projection 或日志；
   - 审计记录记录"谁在何时要求删除"，但不记录被删内容。
2. **级联范围必须显式**：REDACT 一条断言不得静默删除其派生断言；按 §9.5 将全部传递 descendants 原子置为 `invalidation_status=INVALIDATED`、退出 projection 并留下审计，敏感内容已传播进 descendant payload 时还必须逐条 REDACT。
3. **硬限制（必须对用户明说，不得承诺做不到的事）**：REDACT 只作用于 **Core**。若同一内容也存在于 Gateway Evidence（例如某次导入的对话原文），Core 的擦除**不会**删除 Gateway 中的证据。端到端删除需要 Gateway 走其独立的、另行授权的证据删除流程（Phase 3 明确未实现该能力）。
4. **禁止伪擦除**：不得以"标记隐藏"冒充擦除。只要原文仍能被任何 Core 路径读出，就不算 REDACT 完成。
5. **防重新物化**：所有 Gateway Evidence、Runtime Event、派生任务、cache refill、replay 与普通 Core API materialization 都必须在写入/返回前用同一 canonicalization profile 计算 keyed commitment 并查询 suppression ledger；命中即返回稳定抑制结果且不得把原文写入 assertion/projection/cache/log。该策略不删除、不改写、也不降低 Gateway Evidence 的历史权威。
6. **恢复传播**：suppression ledger 与密钥材料是独立、受保护、不可随旧 Core point-in-time backup 回退的恢复单元。Core restore 必须保持只读 quarantine，先取得不早于已知 redaction high-water 的 ledger、验证连续性并重放 tombstone，再开放任何内容读取/派生。无法证明 latest suppression high-water 时返回 `REDACTION_LEDGER_UNPROVEN`；旧备份不得直接服务读取。
7. **Phase 1 强度已决**：Phase 1 不要求 cryptographic erase；采用原子墓碑替换 + server-only keyed suppression commitment + 审计。keyed commitment 是匹配材料，不是原文完整性声明，也不能宣称端到端删除；逐断言密钥销毁仅作为未来可选强化。
8. **provenance 内容纪律**：`derivation_descriptor` 保存 prompt/template artifact ID/version/digest、parameter schema，并保存非敏感实际值的 canonical JSON；敏感/内容型参数只保存受控 artifact ID/version/digest。不得保存 secret、rendered prompt、input excerpt、chain-of-thought 或用户正文；实际用户输入只通过三类 refs 表达。所有实际值/artifact refs 都进入 descriptor digest。Schema validator 对内容型 descriptor fail-closed；未来导入旧格式内容型 descriptor时，该字段与 statement 一样进入 REDACT tombstone/suppression/恢复测试范围。

**跨存储 suppression 协议（冻结）**：non-cloned suppression authority 维护单调 `redaction_seq`、`previous_record_hash`、签名 record hash 与 authoritative high-water。① 以 `(trust_domain_id, redaction_request_id, assertion_id, keyed_commitment, canonicalization_version)` 线性一致 CAS 写入 `BLOCKING`；自该生效点起所有 Core read/materialization gate 先查询 authority，命中即拒绝正文，即使 Core tombstone 尚未提交；② Core 在单一本地事务写 tombstone + descendant invalidation + audit + state version；③ 携本地 receipt 将同一 ledger record 幂等推进 `COMMITTED`。崩溃在①后只会“先阻断、后待收口”，不会重新披露；恢复按 request ID/chain state完成同一 tombstone，不能换 ID。密钥轮换须保留可验证 key-version 或在受保护域重算全部 commitments，不得打断历史匹配。

restore 选择 authoritative high-water 的唯一来源是该 non-cloned authority 的线性一致 latest record及其签名/hash-chain连续性，不采用 Core backup 自报值。`BLOCKING` 与 `COMMITTED` 均必须在恢复读取前应用；chain 缺口、签名失败、authority 不可达或 backup 宣称高于 authority 时一律 `REDACTION_LEDGER_UNPROVEN` 并 quarantine。

**未来实现验收**：对 `BLOCKING` 前后、Core tombstone transaction 前后及 ledger COMMITTED 前后逐点故障注入；结果只能是“尚未接受删除”或“已立即阻断且可幂等收口”，不得出现已确认 REDACT 后可读原文。Gateway replay、Runtime retry、derived rebuild、cache refill 与 API 读取均不能重新物化命中内容；恢复旧 Core backup 在验证并应用 authoritative latest suppression high-water 前保持只读且不能返回正文。

---

## 14. Evidence Linkage

### 14.1 Gateway Historical Evidence 引用（Phase 1 v1 可解析 profile，冻结）

Core 禁止持久化 Amendment #1 无法重解析的“裸对象 UUID”。v1 profile 只允许下列 observation-scoped locator；`ARCHIVE_OBJECT`、`ARCHIVE_OBSERVATION`、`CONVERSATION`、`CONVERSATION_NODE`、`MESSAGE`、`MESSAGE_OBSERVATION`、`ATTACHMENT`、`IMPORT_BATCH_COMMIT`、`SOURCE_ACCOUNT`、`IMPORT_JOB` 仅可作为 API 返回的溯源属性，**不得**单独成为 assertion evidence ref。

| `object_type` | 必填 locator scope | 唯一解析路径 | 验证材料 |
| --- | --- | --- | --- |
| `CONVERSATION_OBSERVATION` | `conversation_observation_id` | `GET .../{observation_id}/nodes` 的 `observation` | `source_observation_fingerprint` + `canonical_fragment_fingerprint` 及各 version、`observed_at` |
| `MAPPING_NODE_OBSERVATION` | `conversation_observation_id + mapping_node_observation_id` | 在该 observation 的 node pages 中按 immutable ID 定位 | node 的 source/canonical fingerprints + versions、父子拓扑 |
| `MESSAGE_REVISION` | `conversation_observation_id + mapping_node_observation_id + message_revision_id` | 在该 observation 的 node pages 中定位 bound revision；不得按 message 裸 ID 猜 latest | `revision_fingerprint` / `semantic_revision_fingerprint` + versions，以及可用的 bound message-observation fingerprints/time |
| `ATTACHMENT_OBSERVATION` | `conversation_observation_id + attachment_id + attachment_observation_id` | `GET .../{observation_id}/attachments/{attachment_id}/observations` 中按 immutable attempt ID 定位 | canonical fingerprint + version（若 Gateway 对该失败/缺失 attempt 返回 null，则冻结为 `IDENTITY_AND_SCOPE` verification，必须逐字段比对 attempt number/status/observed_at，禁止伪造 fingerprint） |

公共结构冻结为 `{layer:GATEWAY, object_type, locator:{...父作用域...}, verification:{mode, fingerprint?, fingerprint_version?, observed_at, expected_fields?}}`。`object_id` 不得脱离 locator scope。source-native stable key、ZIP member 与 RFC 6901 locator 不进入 Core ref、projection 或日志；扩展 object type 必须先新增可寻址 allow-list API、404/完整性语义及契约测试，再版本化此 profile，不能靠 DB 直连补洞。

`SOURCE_ACCOUNT` 特别禁止作为 assertion evidence：它只参与 §9.3 的 Core-governed principal binding，账号存在本身不证明用户身份或任何 proposition。

### 14.2 Runtime Event 与派生输入 namespace（冻结）

- `runtime_event_ref = {layer: CORE_RUNTIME_EVENT, event_id, runtime_instance_id, observed_at}`：只引用 Core 已接受事件。
- `input_assertion_ids[]`：只引用 Core assertion，用于 derivation / rollup provenance。
- 三个 namespace 不得互换、复用同一 object type 或通过 convenience conversion 隐式升级。

### 14.3 规则

1. Core 允许缓存展示用片段（例如原文一段），但必须标记为 convenience copy，冲突时 Gateway 胜出；此时断言降级为 `SUSPECT`，不得静默删除或静默改写。
2. Runtime-only 的事件（从未出现在任何导出里的交互）通过 Runtime Event / Journal 获得自己的引用身份，trust class = `RUNTIME_ASSERTED`：它证明"该 runtime 断言 / 观察到了这件事"，不证明世界如此。
3. 每条普通持久化断言必须至少有一个 `gateway_evidence_ref` / `runtime_event_ref` / `input_assertion_id`；`USER_STATED` 必须引用可验证 user speech act。只有 Constitution bootstrap 可显式 `UNGROUNDED`。
4. 模型自己的 prose 永不是"不可质疑证据"；它最多是 `DERIVED` 断言的中间产物，必须带 `derivation_version`。
5. 引用必须按 namespace 校验：Core 恢复或启动时解析引用；不可解析者标 `SUSPECT` 并保留（§22）。
6. `GATEWAY_LINKED` 只证明 Runtime Event 与指定 Gateway evidence 存在可验证关联；不得改变 emitter payload 的 `RUNTIME_ASSERTED` trust class，不得把 payload 晋升为 source fact 或改写 Gateway provenance。
7. Gateway Evidence 是最高级 Historical Evidence；它证明 Gateway 曾保存/归一化到什么，不等于 Objective World Truth。
8. Amendment 游标只在一次 bounded-high-water enumeration pass 内有效，不是持久完整 checkpoint，也不提供 snapshot/exactly-once。Core 必须周期性丢弃旧 cursor、从第一页开始 fresh rescan；conversation 与 attachment 两条流分别按 immutable `conversation_observation_id` / `attachment_observation_id` 幂等去重。并发晚提交可缺席本 pass，但必须能在后续 fresh pass 被发现。
9. v1 四种 ref 的 contract tests 必须分别证明：父 scope 缺失/错误被拒绝；合法 ref 可仅经 Amendment API 重解析；fingerprint/expected-fields 不匹配迁移为 `UNRESOLVED_EVIDENCE`；404 不触发 DB fallback。无法满足者不得持久化为 Gateway ref。

---


## 15. Runtime Event Contract（只设计，不实现）

### 15.1 字段

| 字段 | 语义 | 产生者 | 必填 | 时钟 |
| --- | --- | --- | --- | --- |
| `event_id` | 事件幂等标识（producer 侧唯一，UUID） | Runtime | 是 | - |
| `continuity_id` | 归属校验 | Runtime 提交，Core 校验 | 是 | - |
| `runtime` | 运行时种类（如 `hermes`） | Runtime | 是 | - |
| `runtime_instance_id` | 安装实例 | Runtime | 是 | - |
| `runtime_session_id` | 会话 | Runtime | 视 event_type | - |
| `turn_id` | 一轮交互 | Runtime | 视 event_type | - |
| `event_type` | 事件类型（封闭枚举） | Runtime | 是 | - |
| `role` | user / assistant / system / tool | Runtime | 视类型 | - |
| `event_time` | 事件发生时间（事件时钟） | Runtime | 是 | producer |
| `observed_at` | Core 接收时间（观察时钟） | Core | 是（Core 生成） | Core |
| `ingest_seq` | Core 分配的全序（排序权威） | Core | 是 | Core 单调 |
| `clock_skew_ms` / `clock_quality` | 时钟可信度 | Core 计算 | 否 | - |
| `payload` | 类型化载荷（有界、无密钥） | Runtime | 视类型 | - |
| `evidence_status` | `NONE` / `RUNTIME_ASSERTED` / `GATEWAY_LINKED` | Core | 是 | - |
| `gateway_evidence_refs[]` | `GATEWAY_LINKED` 时必需；只建立关联，不改变 payload trust class | Runtime / Core | 条件 | - |
| `sync_status` | `PENDING` / `ACCEPTED` / `DUPLICATE` / `REJECTED` / `CONFLICT` | Core | 是 | - |
| `schema_version` / `emitter_version` | 兼容性 | Runtime | 是 | - |
| `context_status` | `FULL` / `DEGRADED` / `UNAVAILABLE` | Runtime | 是（`ASSISTANT_COMPLETED` 等） | - |
| `degradation_reason` | 降级原因（如 `CORE_UNAVAILABLE` / `CONTEXT_RETRIEVAL_FAILED`） | Runtime | `context_status != FULL` 时必填 | - |

**幂等键建议**：`(continuity_id, runtime_instance_id, event_id)`。同一键重复到达返回 `DUPLICATE`，不产生任何新断言、不改变 `state_version`。

### 15.2 事件类型（最小集合）

`SESSION_STARTED`、`USER_ACCEPTED`、`ASSISTANT_COMPLETED`、`TURN_ABORTED`、`SESSION_RESET`、`SESSION_ENDED`、`MODEL_CHANGED`；另建议 Core 生成的 `RUNTIME_REBOUND`、`CONTINUITY_REBASED`。

### 15.3 排序规则

**以 `ingest_seq` 排序，绝不以 `event_time` 排序。** 原因：Runtime 时钟不可信。迟到事件允许接受（标 `late=true`），它可以创建 `valid_from` 更早的断言，但不得回退当前视图。

### 15.4 与身份的连接

`identity_id` 由 Core 依据 `continuity_id` 推导，**绝不接受客户端传入**。未知或已退役的 `continuity_id` ⇒ 拒收（`REJECTED`），不得自动创建 identity / continuity。

### 15.5 接收侧强制校验（冻结）

事件接收路径必须依次通过以下校验，任一失败即 `REJECTED`（不得部分写入）：

1. **凭据有效**：`runtime_instance_id` 已注册且未被吊销（§21.4）。
2. **能力绑定**：`(runtime_instance_id, continuity_id)` 必须存在授权绑定；跨绑定提交一律拒绝。**仅声明作用域不够，必须在接收路径强制校验。**
3. **continuity 存在且未退役**，且 `epoch` 未过期（§4.1.2）。
4. **schema 版本兼容**且载荷在大小 / 字段白名单内。
5. **幂等判定**：命中幂等键则返回 `DUPLICATE`，不产生副作用。

### 15.6 降级必须留痕（冻结）

当本轮因 Core / Gateway / context retrieval 不可用而未能注入个性化上下文时，`ASSISTANT_COMPLETED` 必须携带 `context_status=DEGRADED|UNAVAILABLE` 与 `degradation_reason`。理由：否则事后无法区分"因为没有上下文所以没提"与"故意不提"，会污染后续对历史的解读（§23）。

---

## 16. Local Journal Boundary（只设计）

| 负责 | 不负责 |
| --- | --- |
| Runtime hot-path 的持久捕获（断网可积压） | User Model / Relationship Model |
| 重放（replay）与本地去重记录 | semantic memory / Context ranking |
| checkpoint / cursor 维护 | identity / continuity / Constitution |

**同步语义（不得声称 exactly-once）**：

- 传输保证：**at-least-once**。
- 接收侧：**idempotent**（按 §15.1 幂等键去重）。
- 因此可获得"**exactly-once effect**（恰好一次效果）"，但绝不声称"exactly-once delivery"。报告、文档与对外说明必须使用前一种措辞。
- ack 规则：Core 持久提交后才 ack；Journal 只在收到 ack 后推进 cursor。
- cursor 建议：按 `(runtime_instance_id, journal_id)` 维护单调 checkpoint；重启后从 checkpoint 重放，重复事件被去重。

**边界纪律**：Journal 永远是可丢弃的传输缓冲，不是权威。它绝不允许成为某段历史的唯一副本（长期只存在于 Journal 属于设计缺陷）。Journal 内容视为 `RUNTIME_ASSERTED`，须校验 schema，绝不可用于 identity / Constitution。

### 16.1 backlog 必须可观察（冻结）

"有丢失风险"不能只停留在免责声明。冻结以下要求：

1. **阈值化告警**：定义未同步条数阈值与未同步时长阈值；任一越界必须产生可见状态标记。
2. **用户可见性**：当存在未同步片段时，必须在该时段的会话/运维视图中暴露"存在未同步片段"标记（不暴露内容，只暴露状态）。
3. **异常判据**：任何"某段历史长期只存在于 Journal"的情况视为**异常**（而非正常缓冲），必须告警并进入同步补偿。
4. **禁止静默丢弃**：超出容量的处理方式必须是拒绝新写入 + 告警，而不是悄悄覆盖旧事件。

---

## 17. Hermes Boundary

### 17.1 允许

请求 Qingyu Context（授权范围内）；提交 Runtime Event；调用 Tool；调用 Model；保存自己的 operational state；上报 reconciliation checkpoint。

### 17.2 禁止

创建 Qingyu identity；重置 continuity；删除 Qingyu history；把 `state.db` / `MEMORY.md` 升级为 Qingyu 的 source of truth；覆盖 User Model / Relationship Model；静默修改 Constitution。

### 17.3 删除测试（必须成立）

删除整个 Hermes 安装后，Qingyu Core 仍完整存在；新 Runtime 绑定同一 `continuity_id` 后可继续。Core 不得把任何必需状态只放在 Hermes 侧；Hermes 侧只允许 cache 与未同步 Journal。

### 17.4 Adapter 契约（未来）

建议以**显式契约**（版本化 OpenAPI / JSON Schema）暴露三类能力：① 读取 projection（只读、按 `continuity_id` 限定）；② 提交 Runtime Event（append-only、幂等）；③ 请求 Evidence 引用（经 Gateway 只读 API）。除这三类外，Runtime 不应获得任何直接数据库访问。

---

## 18. `SOUL.md` Projection Boundary

- `SOUL.md` = Constitution 的 Runtime projection，是**生成物、只读、可重算**。
- 它不是权威副本；直接编辑 `SOUL.md` 不改变 Constitution（必须被检测并报告漂移）。
- 每个 projection 必须携带：`constitution_version`、`projection_version`、内容哈希、生成时间。
- 漂移检测：启动时比对哈希；不一致则报告并重新生成，**不得**反向把文件内容写回 Constitution。
- 同理适用于任何面向模型的 prompt 片段、persona 摘要、`MEMORY.md`。

---

## 19. Storage Recommendation

比较维度：ownership boundary / backup / consistency / migration isolation / portability / disaster restore / accidental writes / Local Journal 集成 / future scaling。

| 方案 | 隔离强度 | 备份 | Migration 隔离 | 误写风险 | 恢复独立度 | 结论 |
| --- | --- | --- | --- | --- | --- | --- |
| A 同 PG + 不同 schema | 弱（同角色可跨 schema 写） | 中 | 弱 | 高 | 低 | 不推荐 |
| B 同 PG 实例 + 不同 database + 不同 owner role | 中高 | 强（独立 dump） | 强 | 低 | 中（共享实例故障域） | Phase 1 推荐 |
| C 独立 PostgreSQL 实例 | 最强 | 最强 | 最强 | 最低 | 高 | 生产目标形态 |
| D SQLite + PG hybrid | 弱（若 SQLite 成权威则破坏可重建性） | 弱 | 中 | 高 | 低 | 仅限 Runtime Journal / cache |
| E 其他 | 视实现 | 视实现 | 视实现 | 视实现 | 视实现 | 本轮不评估 |

**推荐**：

1. **Phase 1 采用 B**：独立 database + 独立 owner role + 独立 dump 单元 + 独立 migration 历史。理由：在单机环境下以最低成本获得真正的逻辑隔离与独立备份。
2. **生产目标形态 C**：当要求"独立故障域 / 独立 RPO-RTO"时升级为独立实例。设计不得依赖同实例共置（禁止跨库事务、禁止跨库外键、禁止共享连接池独占假设）。
3. **明确拒绝 A**：schema 级隔离不足以支撑主权边界（同角色可跨 schema 写）。
4. **明确限制 D**：SQLite 只能出现在 Runtime 本地（Journal、cache），绝不允许成为 Core 或 Evidence 的权威存储。
5. **禁止跨库外键**：Core 引用 Gateway evidence 只能通过引用 + 校验，不能通过数据库外键（否则破坏独立恢复）。

### 19.1 Core Schema 迁移与降级政策（冻结 — 闭环 C-8）

Gateway 已在 `docs/Migration_Downgrade_Policy.md` 冻结「前向迁移是唯一受支持的生产路径；降级仅用于一次性开发 / 迁移验证库，且可能是破坏性的」。Core 承载最高保护数据（Constitution 版本链、identity registry、审计账本、Versioned Intelligence State），**必须继承并加强该政策**：

1. **前向迁移唯一受支持**：Core 生产库只允许 forward migration；降级不在支持范围内。
2. **降级必须 fail-closed**：任何 downgrade 路径在非一次性库上必须**显式失败并停止**，不得"尽力而为"地执行。判定"一次性库"必须依赖显式标记（如库级 `purpose=disposable` 标签或独立库名约定），不得靠默认值。
3. **禁止破坏性降级触碰高保护对象**：任何会丢弃 Constitution revision、审计记录或断言历史的降级脚本都不得发布——包括"仅用于开发"的版本，因为脚本会被误用于生产。
4. **迁移与数据真实性分离**：迁移不得"修复"任何断言内容或改写 `reason` / `evidence_refs`；schema 迁移只改变结构，不改变语义。
5. **可验证**：Core 的迁移发布需附"降级爆炸半径"说明（哪些表 / 列会丢失），并随 migration 长期保留，接受审计（对齐 Gateway 已发布 `Migration_Downgrade_Policy.md` 的做法）。

---

## 20. Physical Repository Recommendation

候选：单 repo / multi repo / monorepo modules。

| 维度 | 单 repo（Gateway+Core+Runtime） | multi repo（推荐） | monorepo modules |
| --- | --- | --- | --- |
| 主权边界 | 弱（同一历史可跨模块改） | 强 | 弱 |
| 意外耦合 | 高（易 import 对方 ORM） | 低 | 中（可加 lint 约束） |
| Migration 隔离 | 弱 | 强 | 中 |
| 备份分层 | 差 | 好（各自备份单元） | 中 |
| 开发便利 | 好 | 中 | 好 |
| 冻结保证 | 破坏 Gateway 冻结 | 保住 | 削弱 |

**推荐：multi repo + 唯一契约耦合点**

```text
<repo>\gateway        # FROZEN Evidence（已存在，本轮不改）
<repo>\core           # Qingyu Core（未来创建，本轮不创建）
<repo>\contracts      # 版本化契约（OpenAPI / JSON Schema / 事件枚举），唯一耦合点
D:\Hermes-Qingyu-PoC     # Disposable Runtime（用户草图位置）
```

说明与取舍：

- 唯一允许的耦合是契约产物（版本化 OpenAPI / JSON Schema / 事件类型枚举 / projection schema）。Core 不得 import Gateway 的 SQLAlchemy models；Runtime 不得 import Core 或 Gateway 的内部模块。
- 建议给契约引入显式版本与 CI 兼容性检查，避免"契约漂移"这一 multi repo 的主要代价。
- 备选：把 Core 与 Runtime 放进同一仓库的两个 package（Core 稳定、Runtime 可丢弃），但 Gateway 必须始终独立。该备选开发便利更好，代价是丢掉 Core/Runtime 的物理隔离。
- 路径已由 Stage 0 冻结：`<repo>\gateway`、`<repo>\core`、`<repo>\contracts`、`D:\Hermes-Qingyu-PoC`。本轮仅 Gateway 已存在；不得提前创建其余路径。

---


## 21. Permissions / Security

### 21.1 能力划分（capability model）

| 主体 | Gateway | Core | Constitution |
| --- | --- | --- | --- |
| Gateway 迁移者 | DDL（离线） | 无 | 无 |
| Gateway 服务 | Evidence 读写（自己的库） | 无 | 无 |
| Core 服务 | 只读 evidence（仅经稳定 read-only Evidence Query API） | Core 读写 | 可提交提案 |
| Core 迁移者 | 无 | Core DDL（离线） | 无 |
| Runtime（Hermes） | 只读（经 Gateway API，受限 token） | 只读 projection + append-only 事件提交 | 只读 |
| Owner / Governance | - | 治理动作 | 唯一可修改 |

### 21.2 硬规则

1. Hermes 不得持有 Gateway DB owner 权限；不得持有无约束 Core admin 权限。
2. Core 不得持有任何 Gateway DB 角色（包括所谓只读角色）；只读能力必须经稳定 Evidence Query API 提供。
3. Constitution 修改是独立 capability（`constitution_admin`），与 Runtime、与 Memory Intelligence 分离。
4. 凭据可吊销：按 `runtime_instance_id` 发放；吊销产生审计记录，且不删除任何历史。
5. Secret 隔离：模型 provider key 只存在于 Runtime；Core 不存 provider 密钥；Core 与 Gateway 的连接凭据不得写入任何日志、报告、错误信息、导出物。
6. 审计：所有 Core 变更（尤其 Constitution 与 supersession）必须产生 append-only 审计记录，含 actor（user / runtime / governance）、reason、时间、影响范围。
7. 最小特权：Runtime 的 Core 凭据只能访问投影视图（只读）与事件提交端点（append-only，且作用域限定为自身 `runtime_instance_id` + `continuity_id`）。
8. 隐私：对外 DTO 与日志必须使用显式 allow-list；不得泄露 DB URL、令牌、服务器文件系统路径、原始异常文本、traceback、lease token、进程 ID（继承 Gateway 隐私契约）。
9. Runtime 不得直接连接 Core / Gateway 数据库；只能经契约 API。
10. Core 同样不得直接连接 Gateway 数据库或持有任何 Gateway DB role；只能持独立的 evidence-read API capability。现有可调用 ingest/retry 的通用凭据不得发给 Core。

### 21.3 Runtime enrollment 契约（冻结）

缺乏注册 / 授权流程时，"删除 Hermes 后仍能继续"在身份层成立、在授权层却无路径。冻结以下流程：

| 动作 | 语义 | 必填记录 |
| --- | --- | --- |
| `RUNTIME_ENROLL` | 新实例首次注册 | 授权人、`runtime_instance_id`、绑定的 `continuity_id`、能力集合、有效期 |
| 能力授予 | 从默认**只读**提升为可写 | 显式授予；写入需写租约（§4.1.2） |
| 能力吊销 | 立即失效 | 吊销人、时间、原因；**不删除任何历史** |
| `RUNTIME_REBOUND` | 吊销后重新注册（如重装） | 旧实例记录 + 新实例记录 + 授权人 |

规则：**新实例默认只读**；写能力必须显式授予；绑定不可跨 `continuity_id` 复用。凭据轮换不改变 identity / continuity（§4.2）。

### 21.4 Core 侧敏感内容最小披露（冻结）

Core 承载 Constitution 与 User Model，敏感度高于一般业务数据，因此在继承 Gateway 隐私契约之外补充：

1. **按 Runtime 最小披露**：projection 只返回该 Runtime 完成本轮所需的字段；不得整表下发。
2. **禁止出界**：Constitution 全文、User / Relationship Model 原始断言、审计明细不得进入日志、错误信息、导出物或第三方调用。
3. **日志纪律**：只允许记录标识与计数（如 `assertion_id`、数量、状态），不得记录 `statement` 原文，除非处于显式审计模式并已授权。
4. **静态加密**：记为部署层要求（Core DB 与备份的静态加密），不进入本轮 Schema 设计。
5. **失败信息**：对外错误只返回稳定错误码，不返回内部路径 / SQL / 堆栈。

---

## 22. Backup / Restore Responsibility

三层独立备份单元：

| 层 | 内容 | 恢复后必须成立 |
| --- | --- | --- |
| 1 Gateway Evidence | Raw objects + manifests + Evidence DB | 字节与拓扑可重建（已冻结验收） |
| 2 Qingyu Core data | Core DB（identity/continuity、Constitution、local audit copy、Versioned State） | 与 control-plane committed state/audit high-water 完整对账后才可读写 |
| 3 Core non-cloned control plane | **一个不可拆分原子单元**：genesis registry + anchor metadata + governance owner/capability + fencing/write gate + storage-generation registry + suppression authority/key metadata + audit sequencer；一致 snapshot + WAL/consensus log | 恢复到外部 quorum 证明的 latest `control_plane_tx_seq`，随后轮换 control-plane generation、storage generation/credential 与 epoch；任何部分缺失/拼接/回退均 quarantine |
| 4 Runtime | 可丢弃；Local Journal 可能含未同步事件 | 丢失 = 有损，必须显式声明 |

规则：

1. Gateway、Core data 与 Core control plane 各自是独立恢复单元；control-plane 内部模块绝不可分别备份/恢复或跨时间点拼接，也不得只存在于 Core DB backup 中。
2. 恢复顺序：先 Gateway（或至少先验证 Gateway 可用），再 Core —— 因为 Core 断言引用 Gateway evidence。
3. 引用完整性检查：Core 启动 / 恢复时校验 evidence_refs 是否可解析；不可解析的断言标 `SUSPECT` 并保留，绝不静默丢弃。
4. 一致性检查项：`constitution_version`、`continuity_epoch`、`state_version`、active storage/control-plane generation、owner version、redaction seq、audit seq/head、evidence_ref 可解析率。
5. 禁止把 Core 备份塞进 Runtime 目录；禁止让 Runtime 成为任何备份的保管方。
6. Core 备份必须包含恢复所需的一切：恢复后不得需要 Hermes、Mem0/Graphiti、模型 provider 或网络推理才能回答"我是谁 / 当前理解是什么"。
7. control plane 使用全局单调 `control_plane_tx_seq`。3 个 rollback witnesses 位于独立故障域，其身份/公钥/2-of-3 threshold/protocol version 必须匹配 pinned GENESIS anchor；各自维护线性一致、持久化、不可回退的 `(trust_domain_id, generation, committed_tx_seq, checkpoint_hash, current_owner_record_hash/key, witness_set_version, recovery_claim)` CAS state。同一 generation/seq 绝不对两个 digest 签名，低于 high-water 永远拒绝。witness 只见 hashes/counters/public keys，不见用户正文；本地配置不能替换 anchor 中的 witness set。
8. 普通 control-plane transaction 协议冻结为：本地 consensus/WAL 先 durable `PREPARED(tx_id,digest,expected_head)` → 2-of-3 witness CAS 同一 `WITNESS_PREPARED`（并发 loser不得推进）→ control-plane quorum durable COMMIT并产生可验证 commit receipt → witnesses 验证 receipt 后 CAS `COMMITTED`，此时才推进 quorum latest/对外生效。崩溃恢复按 tx ID：有 durable commit receipt则幂等完成 witness COMMITTED；无 receipt则以 quorum CAS `ABORTED` 并终止本地 PREPARED。ABORTED/loser 不推进 committed high-water；API 在 witness COMMITTED 前不返回成功。
9. control-plane restore 必须先由候选实例生成不可从 backup 克隆的 `control_plane_instance_id`/public key，并对 anchored witness quorum latest checkpoint 验证 snapshot+WAL。`RECOVERY_CLAIM` canonical envelope 必须签名覆盖 operation、trust domain、完整 latest owner record hash/version/key fingerprint、checkpoint hash、old/new generation、candidate instance/key、witness-set version 与 request ID，并由 latest checkpoint 指定的**当前 governance owner key**授权；Phase 1 不允许“持备份即授权”或未预先冻结的替代恢复者。witness 各自验证 owner签名/吊销/scope与 anchored set 后，才以2-of-3 CAS唯一 claim；loser永久不激活。claim holder恢复后由 quorum CAS `RECOVERY_PREPARED → ACTIVE`，撤销旧 credentials、签发更高 epoch并发布 checkpoint。claimant崩溃时全局 quarantine；仅同 request幂等继续，或 current owner 签名 recovery-abort/reclaim，witness不得靠超时双签。
10. witness set/threshold/protocol 的轮换是高保护治理动作：envelope 绑定 trust domain、old/new set/version、threshold、owner record与生效 generation/seq，由 current owner签名；必须由旧 quorum确认授权、由新 quorum确认接管，并在同一 control-plane/audit transaction形成 old→new cross-certificate。旧 witnesses 持久标记 retired/new-set hash，拒绝为生效点后的旧 set checkpoint/recovery claim签名。缺任一 quorum或链验证失败则不生效。
11. snapshot+WAL 必须覆盖不可拆分原子状态并达到 anchored current witness set 的 2-of-3 latest COMMITTED checkpoint；整体旧快照即使自洽也不能 claim。部分/整体 rollback、跨快照拼接、双 claim、witness equivocation、替换 set、旧 set 重放或低于 quorum high-water ⇒ fail-closed。control-plane 全损也只能由已授权 claimant从 quorum latest完整 snapshot+WAL恢复；无法证明授权/达到 checkpoint/取得 quorum则不可写或服务敏感 projection，禁止重新 GENESIS或人工重置 high-water。

### 22.1 重新链接与 `SUSPECT` 复位（冻结）

允许"先恢复 Core、后恢复 Gateway"这一顺序，但必须把重新链接做成可验证流程：

1. Core 可先启动，此时不可解析的 evidence_refs 一律标 `integrity_flag=SUSPECT`（§9.4），断言仍可查询、不得删除。
2. Gateway 恢复后，Core 执行**一致性重扫（reconciliation）**：逐条重解析 `SUSPECT` 引用。
3. 重扫结果必须单调安全：`SUSPECT` 是检查中状态；解析成功且验证材料匹配 ⇒ `SUSPECT → OK`；404、scope/ID 不匹配、指纹或 expected-fields 不匹配 ⇒ `SUSPECT → UNRESOLVED_EVIDENCE`（单值状态迁移，不同时持有两值，且**不得**自动改写断言内容）。仅在后续完整重扫重新验证成功时，`UNRESOLVED_EVIDENCE → OK`；每次迁移都推进 `state_version` 并审计。
4. 重扫必须留下审计记录（扫描范围、时间、结果计数），使"恢复顺序"可被事后验证。
5. 由 `SUSPECT` / `UNRESOLVED_EVIDENCE` 断言支撑的当前视图，必须对下游标注不确定性，而不是静默照常输出。

---

## 23. Failure Semantics

统一不变量（对全部失败模式生效）：

- 不得制造虚假历史：不得合成证据、不得无凭据回填断言、不得把 DERIVED 静默提升为 STATED。
- 不得因上层失败而丢失下层权威。
- 失败必须留下可观察的标记（事件侧 `sync_status`、断言侧 `integrity_flag`、以及审计记录），而不是静默成功。

Identity/GENESIS/governance/fencing 的稳定 fail-closed 错误码冻结为：`INVALID_CONTINUITY_ID_FORMAT`、`CONTINUITY_ALIAS_NOT_CANONICAL_ID`、`CONTINUITY_UNKNOWN`、`CONTINUITY_RETIRED`、`IDENTITY_CONTINUITY_BINDING_MISMATCH`、`FORK_NOT_SUPPORTED`、`EPOCH_REQUIRED`、`EPOCH_STALE`、`EPOCH_NOT_ISSUED`、`LEASE_REQUIRED`、`LEASE_FENCED`、`MUTATION_RETRY_CONFLICT`、`GENESIS_NOT_INITIALIZED`、`GENESIS_ALREADY_EXISTS`、`GENESIS_CONFLICT`、`GENESIS_STORAGE_NOT_CLAIMED`、`GENESIS_ANCHOR_MISMATCH`、`GENESIS_OUTCOME_UNKNOWN`、`OWNER_TRANSFER_CONFLICT`、`OWNER_VERSION_STALE`、`OWNER_TRANSFER_OUTCOME_UNKNOWN`、`RESTORE_IDENTITY_MISMATCH`、`RESTORE_INITIAL_OWNER_MISMATCH`、`RESTORE_OWNER_REVOKED`、`RESTORE_OWNER_UNPROVEN`、`RESTORE_AUTHORIZATION_INVALID`、`RESTORE_AUTHORIZATION_SCOPE_MISMATCH`、`RESTORE_REQUEST_CONFLICT`、`RESTORE_STATE_GAP`、`RESTORE_FENCE_UNPROVEN`、`MUTATION_OUTCOME_UNKNOWN`、`REDACTION_LEDGER_UNPROVEN`、`AUDIT_CHAIN_INVALID`、`AUDIT_HIGH_WATER_UNPROVEN`、`CONTROL_PLANE_ROLLBACK_DETECTED`、`CONTROL_PLANE_HIGH_WATER_UNPROVEN`、`CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT`、`CONTROL_PLANE_RECOVERY_AUTHORIZATION_INVALID`、`CONTROL_PLANE_WITNESS_SET_MISMATCH`、`CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE`。所有拒绝均不得自动创建/改绑 ID，不自行推进 epoch/owner/state version，不写可见业务记录。

API 映射冻结：格式/shape 错误为 422；认证/能力不足为 401/403；already-exists、binding/version/lease/epoch/anchor/identity、storage claim、state gap、audit invalid 与并发 CAS 冲突为 409 且默认不可盲重试；authority/high-water 不可证明及三个 `*_OUTCOME_UNKNOWN` 为 503、保持未激活/只读。Outcome-unknown 只能用**同一** `genesis_request_id` / owner-transfer `request_id` / `mutation_id` 查询 authoritative status 或幂等重试，不得换 ID 重发。

Control-plane 映射冻结：`CONTROL_PLANE_ROLLBACK_DETECTED` / `CONTROL_PLANE_WITNESS_SET_MISMATCH` = 409 security-integrity incident，普通请求不可重试，必须 critical alert且只允许签名 recovery ceremony；`CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT` = 409，loser永久不得激活，只能查询winner；`CONTROL_PLANE_RECOVERY_AUTHORIZATION_INVALID` = 403，不得重试同一篡改/无签名 envelope，需 current owner 重新签发；`CONTROL_PLANE_HIGH_WATER_UNPROVEN` / `CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE` = 503，保持全局 quarantine，可在同一 recovery request 下等待 quorum/证明恢复。任何一种都不得自动选择较低 checkpoint或创建新 GENESIS。

Restore authorization 逐项映射：已撤销旧 owner ⇒ 403 `RESTORE_OWNER_REVOKED`（永久，需当前 owner 新签）；stale owner version/record ⇒ 409 `OWNER_VERSION_STALE`；相同 request+相同 envelope 已消费 ⇒ 幂等返回既有结果，相同 request+不同 payload ⇒ 409 `RESTORE_REQUEST_CONFLICT`；签名/内容篡改 ⇒ 403 `RESTORE_AUTHORIZATION_INVALID`；跨 trust-domain/continuity/operation 重放 ⇒ 403 `RESTORE_AUTHORIZATION_SCOPE_MISMATCH`；当前 authority 无法读取/证明 ⇒ 503 `RESTORE_OWNER_UNPROVEN`（只可同 request 查询）。initial-owner anchor mismatch 使用 `RESTORE_INITIAL_OWNER_MISMATCH`，不得与 current-owner 状态合并。

| 失败 | 受影响能力 | 必须保持的不变量 | 禁止行为 | 降级行为 |
| --- | --- | --- | --- | --- |
| Gateway unavailable | 新证据引用、历史回溯 | 已有 Core 状态不被改写 | 不得伪造 evidence_ref | projection 可读；涉证据操作 fail-closed（明确报错，不猜） |
| Core unavailable | 长期个性化、事件落库 | Gateway 证据不受影响 | Runtime 不得把本地文件当权威 | Runtime 用 Local Journal 捕获 + 无个性化回复（可明示） |
| Journal unavailable | 离线事件捕获 | 不得谎称已持久化 | 不得静默丢弃并假装成功 | 内存缓冲 + 明确告警；承认有丢失风险 |
| Hermes crash | 当轮交互 | Core / Gateway 不变 | 不得补写编造的事件 | 未完成轮次标 `TURN_ABORTED`；重启后从 checkpoint 继续 |
| model provider unavailable | 当轮推理 | Core 不变 | 不得改变 identity / continuity | 切换 provider / model（产生 `MODEL_CHANGED`）或明确失败 |
| Memory Intelligence failure | Derived 更新 | 保留 last-good 版本 | 不得部分写入、不得 supersede 任何断言 | 标记 stale；下次重试；不得阻塞聊天 |
| context retrieval failure | 个性化 | Core 不变 | 不得假装"我记得" | 无个性化回复 + 明示不确定性 |
| restore from backup | 全局 | pinned anchor 验证 identity / continuity；新 epoch 必须 `> max_issued_epoch` | 不得自动合并分歧历史或本地自行 `+1` | 进入只读 quarantine；authority 不可达则 `RESTORE_FENCE_UNPROVEN` |
| duplicate Runtime Event | - | `state_version` 不变 | 不得产生第二条断言 | 幂等返回 `DUPLICATE` |
| out-of-order Event | 排序 | 当前视图不回退 | 不得用 `event_time` 重排历史 | 按 `ingest_seq` 落库，标 `late=true` |
| runtime clock mismatch | 时间语义 | 排序不受影响 | 不得用 runtime 时钟仲裁 | 以 `ingest_seq` 为序；记录 `clock_skew_ms` 与 `clock_quality` |

---

## 24. Token / Cost Implications

| 操作 | 模型 token 目标 | 落地方式 |
| --- | --- | --- |
| Core DB 操作 | 0 | 纯 SQL / 规则 |
| Journal | 0 | 本地落盘 + 重放 |
| Continuity / Identity 解析 | 0 | 按 ID 查询 |
| Context retrieval | 优先非模型 | DB / 规则 / 时间窗 / embedding + 廉价本地逻辑；LLM 摘要必须是显式且被缓存的一步 |
| Memory Intelligence | 异步 / 批量 | 事件驱动，增量，预算受限 |
| 普通聊天一轮 | 1 次主模型调用 | Core 只做只读 projection 注入 |

硬性禁止的形态：`每轮聊天 → 4 次强模型分析 → 才能回复`。

补充要求：

1. 预计算投影：Runtime 热路径必须能一次廉价读拿到 projection（因此 projection 需物化且带 `state_version`）。
2. 预算降级方向：Memory Intelligence 超预算时降级为 no-op（保留 stale 标记），绝不降级为"阻塞回复"。
3. 可观测：每次写入应能说明它是否触发了模型调用（0-token 路径必须可验证）。

---

## 审查执行说明（Execution Note）

本轮为 Architecture Design Gate，无实现改动。设计正文（§0–§24）与全部冻结规则由 Lead 撰写，Lead 对全部结论负责并已独立复验审查所引用的仓库事实。

审查按任务书 §二十五 的三份互不引用的章程执行：Reviewer A（身份 / 连续性）、Reviewer B（数据 / 状态治理）、Reviewer C（运行时 / 失败 / 主权）。

**方法学限制（必须如实记录）**：本会话的协作通道存在投递缺陷——子智能体在多数情况下收不到任务包（只收到模型切换通知），仅"全历史 fork"通道可投递。后果是审查实际由**少于预期的智能体实例**完成，独立性弱于任务书要求的"至少三路独立 Review"：

| 审查轴 | 产出者 | 独立性评价 |
| --- | --- | --- |
| Reviewer A（身份 / 连续性） | 独立审查智能体（含第二轮补充发现 B-8 / C-8） | 由不同于 Lead 的智能体执行 |
| Reviewer C（运行时 / 失败 / 主权） | 独立审查智能体（含第三轮闭环复核） | 由不同于 Lead 的智能体执行 |
| Reviewer B（数据 / 状态治理） | 与 A 轴同一审查进程内的分章程审查 | **未取得独立智能体复核**，为已知缺口 |

因此：本报告的审查结论应视为"分章程审查 + Lead 独立复验"，**不等于**组织级三路独立审查。建议在具备正常子智能体槽位的会话中，对 §25–§27 与 §29 再跑一次外部独立复核，尤其是 B 轴（版本化、supersession、Evidence linkage）。

审查全程只读：未修改 `<repo>\gateway`（工作树 clean，HEAD `bb107ed`），未创建目录、数据库、代码或 migration。

审查取证基线：`gateway/docs/{SOURCE_OF_TRUTH_CONTRACT,GATEWAY_BOUNDARY_FREEZE,RUNTIME_INDEPENDENCE_CONTRACT,BACKUP_RESTORE_RUNBOOK}.md`、`gateway/app/models.py`、`gateway/app/main.py`、`gateway/app/importers/query.py`、`gateway/alembic/versions/`、本报告 §0–§24。

### 再验证记录（Re-verification，第二轮）

第二轮为补充复核，专门寻找首轮未覆盖的问题（含"用户要求删除"与"迁移降级政策"两个方向），发现 B-8、C-8 两项 P1。该轮由独立审查智能体执行；其全部仓库事实主张已由 Lead 逐条复验。

本轮复核对报告依赖的既有事实逐条做了命令级取证（全部只读）：

| 报告断言 | 取证命令 | 结果 |
| --- | --- | --- |
| `gateway/app/main.py` 仅暴露 archive / import 两个路由，无对外 Evidence 查询 API（§0.2） | `rg -n "include_router" gateway/app/main.py` | 仅 `archive_router`、`import_router`；`app/` 下只有 `api_archive.py`、`api_import.py` |
| Evidence 重建只存在于进程内（§0.2） | `rg -n "class EvidenceTreeQuery" gateway/app/importers/query.py` | 命中 `EvidenceTreeQuery.reconstruct` |
| §14.1 证据对象枚举与真实模型一致 | `rg -n "^class " gateway/app/models.py` | 14 个类，与 §14.1 枚举逐一对齐 |
| Gateway Alembic head = `0016_real_export_evidence`（§0） | `ls gateway/alembic/versions` | 最新为 `0016_real_export_evidence.py` |
| Gateway 已冻结仓库工作树 clean | `git -C gateway status --short`（HEAD `bb107ed`） | 无改动 |
| Gateway 已有 fail-closed 迁移政策（支撑新增 C-8） | `gateway/docs/Migration_Downgrade_Policy.md` | 确认"前向迁移是唯一受支持生产路径；破坏性 downgrade 仅限一次性开发库" |

复核发现的新问题（不由 §25–§27 覆盖）已并入 §28（OQ-10…OQ-14）与 §29（复核补充发现）。复核同样未修改 `<repo>\gateway`、未创建目录 / 数据库 / 代码 / migration。

### 闭环复核（Closure Pass，第三轮：把发现落成冻结规则）

第二轮复核产出的发现不能只停留在"登记"。本轮追加一次**闭环复核**，口径为「该发现是否已在报告主体中形成可执行的冻结规则（字段 / 枚举 / 校验点 / 治理动作 / fail-closed 行为）」，逐条结果记录在 §29.1。本轮新增的冻结落点：

| 发现 | 新增落点 | 内容 |
| --- | --- | --- |
| C-8 | §19.1 | Core Schema 迁移与降级政策：前向迁移唯一受支持；降级在非一次性库上 fail-closed；禁止破坏性降级触碰高保护对象 |
| C-10 | §12.1 | 断言写入 + 审计记录 + `state_version` 推进必须同事务；批量对齐 `IMPORT_BATCH_COMMIT` 整批语义 |
| B-7 / B-10 | §12.1 | 禁止以删除旧断言控量；只允许在保留原断言前提下的派生摘要 / 卷起；具体策略延期 |
| A-8 | §4.1.4 | `retire` 措辞二分：可查询性不可撤销；写能力恢复须走 `CONTINUITY_UNRETIRE` 治理动作 |

同时修正两处术语残留不一致：§13 的 User Model 案例仍沿用旧字段名 `status`（已改为 `lifecycle_status` / `integrity_flag`）、§23 统一不变量中的失败标记措辞含糊（已明确为「事件侧 `sync_status`、断言侧 `integrity_flag`、审计记录」）。闭环复核不改变任何既有冻结结论，只消除文本与契约的不一致。

**v1.1 当时仍未关闭的项（历史记录；v1.2 状态见 §28–§30）**：

| 项 | 问题 | 需要谁决定 |
| --- | --- | --- |
| P1-0 | Gateway Evidence Query API | **CLOSED**：Amendment #1 implemented；full regression 与 A/B/C final gate PASS |
| P1-9（B-8） | REDACT 与擦除强度 | v1.2 已关闭：Phase 1 无 cryptographic erase；新增 durable suppression |
| OQ-3 | Core 物理路径与仓库分区 | v1.2 已按标准路径关闭 |
| OQ-14 | Core 读取 Gateway 的凭据路径 | v1.2 已关闭：只读 API，禁止 DB 直连 |
| OQ-11 / OQ-12 / OQ-13 | fork / GENESIS / 审计防篡改 | v1.1 历史结论；v1.2 已禁用 Phase 1 fork，并冻结 GENESIS 与审计链 |

---

## 25. Reviewer A — Identity / Continuity（v1.1 历史审查记录；当前闭环见 §29.1 / §32）

审查范围：§4 身份契约、§5 `continuity_id` 契约、§6 Runtime / Session 身份、§7 模型独立性、§12 版本线、§15.4 身份连接。

**v1.1 历史结论：有条件通过（PASS with conditions）。** v1.2 新增 A-9/A-10/A-11 独立审查并已在 §4.1–§5 形成冻结规则；最终状态以本轮 Reviewer A final gate 为准。

**闭环（Closure）**：A-1→§4.1.1、A-2/A-11→§4.1.2、A-3/A-8→§4.1.4、A-4→§4.3、A-9→§4.1/§5、A-10/A-12→§4.5。合同侧 blocker 已关闭；当前 Reviewer A final gate 已 PASS（见 §32）。

| 编号 | 严重性 | 问题 | 是否阻塞冻结 |
| --- | --- | --- | --- |
| A-1 | P1 | identity 与 continuity 的基数不变量未冻结 | 是 |
| A-2 | P1 | `continuity_epoch` 语义与作用域未定义 | 是 |
| A-3 | P2 | identity `retire` 生命周期未定义 | 否 |
| A-4 | P2 | 备份副本 → 正式写者的所有权交接流程缺失 | 否 |
| A-5 | P3 | 人类可读名与 `qingyu_identity_id` 的关系未定义 | 否 |

**A-1（P1，必改）identity / continuity 基数不变量未冻结。**
证据：§4.1 把 `qingyu_identity_id` 与 `continuity_id` 并列描述；§4.3 允许 fork 产生「新的 `qingyu_identity_id`」；§5 允许「创建」continuity —— 但报告从未声明两者的基数关系。
风险：若实现允许「一个 identity 多条 continuity」或「一条 continuity 多个 identity」，将直接破坏 §4「一个身份一条连续历史流」的核心不变量，使 fork / restore / merge 判定失去唯一答案。
建议冻结：Phase 1 强制 `qingyu_identity_id : continuity_id = 1 : 1`；「一身份多连续流」显式列为需要独立治理的未来阶段，不在 Phase 1 支持。

**A-2（P1，必改）`continuity_epoch` 的作用域未定义。**
证据：§4.1 定义 epoch 单调递增；§4.4 / §5 要求在 restore、rebase 时 `+1` 并要求 projection 返回 epoch；但报告未定义 epoch 在**写入校验**与**租约**中的强制作用。
风险：epoch 若仅用于展示，无法阻止 §4.3 场景 2「旧副本继续写」；split-brain 检测缺少强制点，退化为“约定”而非“契约”。
建议冻结：epoch 必须同时 (a) 绑定写租约 `(continuity_id, epoch)`；(b) 出现在每条断言与每个 projection 中；(c) 写入时校验 `request.epoch == current_epoch`，落后即拒写并降级只读。

**A-3（P2）identity `retire` 生命周期未定义。** §4.1 提及「直到显式 retire」，但未定义 retire 后是否禁写、是否仍可读、能否撤销、continuity 是否随之退役。建议 Phase 1 冻结为：`retire` ⇒ 全局只读 + 保持可查询 + 不可原地撤销（撤销本身是一次新的治理动作并留下审计）。

**A-4（P2，v1.1 历史 finding）写者交接流程缺失。** 该 finding 已由 `WRITER_TRANSFER` 与 v1.2 §4.1.2 的 authoritative fencing write gate 关闭；governance owner 轮换由独立 `GOVERNANCE_OWNER_TRANSFER` 链负责，恢复不再允许本地自行 `epoch+1`。

**A-5（P3）人类可读名归属未定义。** 展示名「清语」不应进入身份判定；建议归入 Constitution（可版本化），`qingyu_identity_id` 保持不透明 UUID。

---

## 26. Reviewer B — Data / State Governance（v1.1 历史审查记录；独立复核与当前闭环见 §32）

审查范围：§9 User Model、§10 Relationship Model、§11 Belief / Hypothesis、§12 Versioning、§13 Correction / Supersession、§14 Evidence Linkage。

**v1.1 历史结论：有条件通过（PASS with conditions）。** v1.2 已取得真正独立 Reviewer B 首轮审查；其 B-11…B-20 findings 由 §1/§2/§9–§15/§21 的 Stage 0 修订闭环，最终状态以 Reviewer B second pass 为准。

**闭环（Closure）**：B-1/B-12→§9.3、B-2→§9.4、B-3/B-20→§13、B-4→§12、B-5/B-11→§11、B-6/B-18→§14.1、B-7/B-10→§12.1、B-8/B-14→§13.1、B-13/B-16/B-17→§14.2–§14.3、B-15→§21。合同侧 blocker 已关闭，待独立 second pass。

| 编号 | 严重性 | 问题 | 是否阻塞冻结 |
| --- | --- | --- | --- |
| B-1 | P1 | `epistemic_source` 与 `statement_authority` 冗余且可自相矛盾 | 是 |
| B-2 | P1 | `status` 枚举混装「生命周期」与「完整性」两类语义 | 是 |
| B-3 | P1 | 缺少同键有效区间重叠的唯一性规则 | 是 |
| B-4 | P2 | `state_version` 粒度与推进条件未定义 | 否 |
| B-5 | P2 | `kind=FACT` 与「Core 不持有世界真源」需钉死边界 | 否 |
| B-6 | P2 | §14.1 证据对象类型枚举与 Gateway 实际模型不完全对应 | 否 |
| B-7 | P3 | Versioned Intelligence State 无限增长无保留策略 | 否 |

**B-1（P1，必改）双轴与 `statement_authority` 冗余。**
证据：§9.1 定义 `epistemic_source` 四值（`USER_STATED` / `INFERRED` / `OBSERVED_PATTERN` / `SYSTEM_DERIVED`）；§9.2 另设 `statement_authority ∈ {STATED, DERIVED}`；§9.3 规则 1/2 的正确性依赖二者一致。
风险：可能出现 `epistemic_source=INFERRED` 但 `statement_authority=STATED` 的矛盾记录，从而绕过 §9.3「不得静默升级」。
建议冻结：`statement_authority` 必须由 `epistemic_source` **派生**（`USER_STATED→STATED`，其余 `→DERIVED`），作为生成列 / 约束，禁止独立写入；或删除该字段并从 source 计算。

**B-2（P1，必改）`status` 语义混装。**
证据：§9.2 `status` 含 `ACTIVE / SUPERSEDED / RETRACTED / CONTESTED`（生命周期）、`EXPIRED`（有效期）、`SUSPECT`（证据完整性，见 §14.2 规则 1 与 §22 规则 3）。
风险：一条已 `SUPERSEDED` 的断言同时可能 `SUSPECT`，单字段无法表达，导致「历史可查询」与「引用是否仍可解析」纠缠。
建议冻结：拆为 `lifecycle_status ∈ {ACTIVE, SUPERSEDED, RETRACTED, CONTESTED, EXPIRED}` 与 `integrity_flag ∈ {OK, SUSPECT, UNRESOLVED_EVIDENCE}`。

**B-3（P1，必改）缺少同键重叠唯一性规则。**
证据：§13 允许 `valid_from` / `valid_to`（含 2026→2028 变更示例）；§15.3 允许迟到事件创建 `valid_from` 更早的断言且「不得回退当前视图」；但报告未规定同一 `(subject, kind, 语义键)` 在**重叠有效区间**内能否并存两条 `ACTIVE`。
风险：当前视图可能出现两条例外 `ACTIVE`，语义不确定，「当前理解」不可重算。
建议冻结：任一有效时刻，同一 `(subject, kind, key)` 至多一条 `ACTIVE`；出现重叠即置 `CONTESTED` 并显式暴露；迟到事件只允许新增断言，**不得**改写既有 `ACTIVE` 的有效区间。

**B-4（P2）`state_version` 粒度未定义。** 建议冻结为 per-continuity 全局单调游标：重复事件（`DUPLICATE`）不推进；任何断言写入或状态迁移推进 `+1`；`projection = f(assertions @ state_version)` 必须可重算。

**B-5（P2）`kind=FACT` 的定义需钉死。** 必须明确：`FACT` = 「某来源提出的事实性 claim」，**不等于 Objective World Truth**；Gateway Evidence 只对“系统/来源曾记录到什么”具有最高 Historical Evidence 权威，同样不裁决客观世界真相（对齐 `SOURCE_OF_TRUTH_CONTRACT.md`）。

**B-6（P2）§14.1 证据对象类型枚举不完整。**
证据：实测 `gateway/app/models.py` 现有类为 `ArchiveObject, ArchiveObservation, SourceAccount, ImportJob, ImportBatchCommit, Conversation, Message, MessageRevision, MessageObservation, Attachment, AttachmentObservation, ConversationNode, ConversationObservation, MappingNodeObservation`；§14.1 未列 `MESSAGE`、`SOURCE_ACCOUNT`、`IMPORT_JOB`。
建议：补全枚举，或显式说明「`Message` 身份不单独引用，内容以 Revision / Observation 为准」「`SourceAccount` / `ImportJob` 不作为断言证据对象」。

**B-7（P3）增长无保留策略。** append-only 需要配套卷起 / 摘要（不删除原断言），否则 projection 计算随历史无界增长。

---

## 27. Reviewer C — Runtime / Failure / Sovereignty（v1.1 历史审查记录；当前闭环见 §32）

审查范围：§3 Core / Runtime 边界、§15 Runtime Event、§16 Journal、§17 Hermes 边界、§18 `SOUL.md` 投影、§21 权限、§22 备份恢复、§23 失败语义。

**结论：有条件通过（PASS with conditions）。** §3 的可执行「删除测试」、§18 的投影漂移检测、§23 的失败语义矩阵方向正确。下列 C-1、C-2、C-3 需补齐（C-1、C-2 阻塞冻结）。

**闭环（Closure）**：C-1→§21.3、C-2→§16.1、C-3→§15.6、C-4→§15.5、C-5/A-11→§4.1.2/§4.3、C-6→§21.4、C-7→§22.1、C-8→§19.1、C-9/B-15→§21/OQ-14、C-10→§12.1。合同侧 blocker 已关闭；当前 Reviewer C final gate 已 PASS（见 §32）。

| 编号 | 严重性 | 问题 | 是否阻塞冻结 |
| --- | --- | --- | --- |
| C-1 | P1 | 新 Runtime 实例的注册 / 授权（enrollment）契约缺失 | 是 |
| C-2 | P1 | Journal backlog 风险只有免责声明，缺少可观察强制项 | 是 |
| C-3 | P1 | 降级回复未要求在事件流中留痕 | 否（强烈建议） |
| C-4 | P2 | §15 未强制 `(runtime_instance_id, continuity_id)` 能力绑定校验 | 否 |
| C-5 | P2 | split-brain 仲裁依据未给出时间替代方案 | 否 |
| C-6 | P2 | Core 敏感内容最小披露 / 加密要求未定义 | 否 |
| C-7 | P3 | Core-only restore 后与 Gateway 的重新链接仅部分覆盖 | 否 |

**C-1（P1，必改）Runtime enrollment 契约缺失。**
证据：§3 判定测试要求「只给它 `continuity_id` 与凭据」即可恢复；§21.4 要求凭据按 `runtime_instance_id` 发放并可吊销；但报告未定义**首次注册 → 绑定 continuity → 能力授予 → 吊销后重注册**的流程。
风险：「Hermes 删除 / 重装后清语仍存在」在身份层成立，却缺少可执行的授权路径 —— 谁批准新实例写？吊销后如何重新绑定？
建议冻结 Phase 1：定义 `RUNTIME_ENROLL` 治理动作（授权人、绑定 `continuity_id`、能力集合、有效期）+ 吊销与重注册语义；新实例默认**只读**，写能力必须显式授予。

**C-2（P1，必改）Journal backlog 缺少可观察强制项。**
证据：§16 与 §23 只要求「明确告警」「承认有丢失风险」，未定义阈值或强制可见标记。
建议：定义未同步年龄 / 条数阈值，并要求在用户可见路径暴露「存在未同步片段」的状态标记；把「某段历史长期仅存在于 Journal」视为需告警的异常。

**C-3（P1）降级回复必须留痕。**
证据：§23 规定 Core / Gateway 不可用时「无个性化回复 + 明示」。
风险：事后无法区分「因为没有上下文所以没提」与「故意不提」，会污染后续对历史的解读。
建议：`ASSISTANT_COMPLETED` 等事件增加 `context_status ∈ {FULL, DEGRADED, UNAVAILABLE}` 与 `degradation_reason`，并规定降级时必填。

**C-4（P2）能力绑定校验需进入事件接收路径。** §21 声明了作用域，但 §15 的接收校验未包含 `(runtime_instance_id, continuity_id)` 绑定校验，建议在 §15 显式加入。

**C-5（P2）split-brain 仲裁依据不完整。** §4.3 禁止「用服务器时间戳单独仲裁」，但租约 TTL 本身依赖时间。建议明确：主依据为单调 epoch + 心跳计数，时间仅作辅助并记录 skew（与 §15.1 的 `clock_skew_ms` / `clock_quality` 一致）。

**C-6（P2）Core 敏感内容最小披露未定义。** §21.8 只继承 Gateway 隐私契约；而 Core 承载 Constitution 与 User Model（高度敏感）。建议显式规定：projection 按 Runtime 最小披露、Core 敏感字段禁止进入日志 / 导出 / 错误信息，静态加密记为部署层要求。

**C-7（P3）重新链接仅部分覆盖。** §22 规定不可解析引用标 `SUSPECT` 并保留；建议补充 Gateway 恢复后的**一致性重扫（reconciliation）**与 `SUSPECT` 复位规则，使「先恢复 Core、后恢复 Gateway」成为可验证路径。

---

## 28. OPEN Architectural Questions（待确认的架构问题）

| 编号 | 问题 | 是否阻塞设计冻结 | 需要谁决定 |
| --- | --- | --- | --- |
| OQ-1 | `qingyu_identity_id : continuity_id` 冻结为 1:1（A-1） | **RESOLVED / APPROVED**：§4.1.1 | 用户 / 架构所有者 |
| OQ-2 | `continuity_epoch` 同时绑定写租约与 projection 校验（A-2） | **RESOLVED / APPROVED**：§4.1.2；恢复 fencing 由 §4.1.2 补充规则约束 | 用户 / 架构所有者 |
| OQ-3 | Core 物理路径与仓库分区 | **RESOLVED**：`<repo>\gateway`、`<repo>\core`、`<repo>\contracts`、`D:\Hermes-Qingyu-PoC` | 用户 |
| OQ-4 | 是否授权 Gateway 走自身变更控制新增只读 Evidence Query API | **RESOLVED / AUTHORIZED**：Gateway Frozen Maintenance Amendment #1；独立 evidence-read capability，Core 禁止 DB 直连 | 用户 / Gateway 架构 |
| OQ-5 | identity `retire` 语义：只读保留、可否撤销（A-3） | **RESOLVED / APPROVED**：§4.1.4（可查询性不可撤销；恢复写能力走新 `CONTINUITY_UNRETIRE` 治理动作） | 架构所有者 |
| OQ-6 | Phase 1 是否要求**多 Runtime 并发写**，还是先「单写者 + 只读副本」？ | 非阻塞（影响租约复杂度） | 用户 / 架构所有者 |
| OQ-7 | 展示名「清语」与本地化命名归属（A-5） | 非阻塞 | 用户 |
| OQ-8 | Constitution 审批模型：单所有者签名，还是多签治理？ | 非阻塞（影响 §8.3） | 用户 |
| OQ-9 | Context retrieval 是否允许 embedding；若允许，如何在**模型无关**前提下保证 embedding 可重建？ | 非阻塞（影响 §24 与未来阶段） | 架构所有者 |
| OQ-10 | 用户显式要求删除敏感 `statement` 时的擦除强度 | **RESOLVED**：Phase 1 不要求 cryptographic erase；采用 §13.1 的墓碑 + durable suppression + 审计；密码学擦除延期 | 用户 / 架构所有者 |
| OQ-11 | fork 出新 identity 时如何继承 | **RESOLVED FOR PHASE 1**：不支持 fork，`FORK_NOT_SUPPORTED`；未来启用前另立版本化合同 | 架构所有者 |
| OQ-12 | `GENESIS` trust anchor、duplicate prevention、restore identity verification、epoch bootstrap、initial ownership | **RESOLVED / BLOCKER CLOSED BY CONTRACT**：§4.5；未来实现必须通过其验收门 | 用户 / 架构所有者 |
| OQ-13 | 审计账本防篡改 | **RESOLVED**：§12.2 per-record hash chain + non-cloned commit/control-plane anchor + restore fail-closed | 架构所有者 |
| OQ-14 | Core 读取 Gateway Evidence 的路径 | **RESOLVED**：只允许稳定 read-only Evidence Query API；禁止任何 Gateway DB 直连/角色 | 用户 / Gateway 架构 |

---

## 29. P0 / P1 / P2 Design Risks（设计风险）

定级口径：按「若照本报告直接实现会产生何种后果」定级，而非按讨论复杂度。

**P0（3 项，均已形成 Stage 0 可执行合同，仍待最终复核）**：A-9（opaque `continuity_id` 与 alias 分离）由 §4.1/§5 关闭；A-10（GENESIS duplicate prevention）由 §4.5 的 trust-domain registry CAS、`PREPARED → COMMITTED` 幂等状态机、epoch-0 注册与故障恢复关闭；A-11（克隆恢复脑裂）由 §4.1.2 的逐 mutation non-cloned linearizable commit gate、restore quarantine 与 `> max_issued_epoch` 关闭。三项均是未来实现的强制验收门，不得降级为文档建议。

**P1（11 项：10 项已关闭，1 项为跨仓库依赖，需用户 / 架构决策）**

| 编号 | 来源 | 风险 | 关闭条件 | 状态 |
| --- | --- | --- | --- | --- |
| P1-0 | §0.2 | Gateway 无对外只读 Evidence Query API，Core 的 Evidence 引用在物理上不可解析 | OQ-4/OQ-14 已批准 Gateway Frozen Maintenance Amendment #1；以独立只读 capability、显式 allow-list DTO 与 v1 scoped resolver profile 落地 | **CLOSED — full regression + final gates PASS** |
| P1-1 | A-1 | 身份 / 连续性基数不确定 ⇒ 不变量失效 | 冻结 1:1 | CLOSED — §4.1.1 |
| P1-2 | A-2 | epoch 无强制作用 ⇒ split-brain 不可检测 | epoch 绑定租约 + 写校验 + projection | CLOSED — §4.1.2 |
| P1-3 | B-1/B-12 | 来源字段可自相矛盾或被误读为 truth authority | `claim_origin` 由 source 派生；speech act 与 proposition truth 分离 | CLOSED — §9.3 |
| P1-4 | B-2 | 生命周期与完整性混装 ⇒ 「历史可查询」与「引用可解析」纠缠 | 拆分 `lifecycle_status` / `integrity_flag` | CLOSED — §9.4 |
| P1-5 | B-3 | 重叠有效区间无唯一性 ⇒ 当前视图不可重算 | 冻结「同键任一时刻至多一条 ACTIVE」 | CLOSED — §13 |
| P1-6 | C-1 | 无 enrollment 契约 ⇒ 「删除 Hermes 后继续」缺可执行路径 | 定义 `RUNTIME_ENROLL` + 吊销 / 重注册 | CLOSED — §21.3 |
| P1-7 | C-2 | Journal 丢失风险无强制可见项 ⇒ 免责声明替代契约 | 定义 backlog 阈值与可见标记 | CLOSED — §16.1 |
| P1-8 | C-3 | 降级回复不留痕 ⇒ 污染后续历史解读 | 事件增加 `context_status` / `degradation_reason` | CLOSED — §15.6 |
| P1-9 | B-8/B-14 | 用户发起的删除、重新派生与再次披露风险 | REDACT 墓碑 + durable suppression + 明示 Gateway 边界；Phase 1 不要求 cryptographic erase | CLOSED — §13.1 |
| P1-10 | C-8 | Core 未继承 Gateway 的 fail-closed 迁移 / 降级政策 | 冻结「前向迁移唯一受支持 + 降级 fail-closed」 | CLOSED — §19.1 |

**P2（Stage 0 当前）**：A-3、A-4、A-6、B-4、B-5/B-11、B-6/B-18、B-9、C-4、C-5/A-11、C-6、C-9/B-15 已形成冻结合同；fork 在 Phase 1 明确禁用，审计防篡改由 §12.2 关闭。GENESIS 已提升为 P0 blocker并由 §4.5 合同关闭。

**P3（5 项：4 项已关闭，1 项显式延期）**：A-5→§4.1.3、A-8→§4.1.4、C-7→§22.1、C-10→§12.1 已关闭；**B-7 / B-10（无界增长的卷起 / 摘要策略）延期**——不可逆原则已在 §12.1 冻结，具体保留策略转入 Phase 2 前独立议题（见 §30）。

### 复核补充发现（第二轮，章程同 §25–§27，独立取证）

| 编号 | 审查 | 严重性 | 问题 | 关闭条件 | 状态 |
| --- | --- | --- | --- | --- | --- |
| B-8 | B | P1 | 用户发起的删除 / 擦除路径缺失，与 §13「不能被清空」直接冲突：用户提出删除时系统无契约可循 | 冻结 REDACT 默认规则（§13.1）；残余强度选项交 OQ-10 | CLOSED — §13.1 |
| C-8 | C | P1 | Core 未继承 Gateway 已确立的 fail-closed 迁移 / 降级政策；Core 承载最高保护数据，破坏性 downgrade 会直接损坏「不可清空」不变量 | 冻结「前向迁移唯一受支持 + downgrade 必须 fail-closed（仅一次性库例外）」 | CLOSED — §19.1 |
| A-6 | A | P2 | fork 继承语义未定义 | Phase 1 禁用 fork，稳定 `FORK_NOT_SUPPORTED`；未来启用另审 | CLOSED — §4.3 / §5 |
| A-7 / A-10 | A | P0（v1.2 提升） | `GENESIS` bootstrap 信任锚未定义，可能产生重复 genesis | §4.5 冻结 duplicate prevention / restore verification / epoch bootstrap / initial ownership | CLOSED（Stage 0 blocker） |
| B-9 | B | P2 | 审计账本只有 append-only 权限约束，无防篡改要求 | §12.2 per-record chain + non-cloned synchronous anchors + restore verification | CLOSED |
| C-9 / B-15 | C/B | P2→P1 | Core↔Gateway 凭据路径未定义 | OQ-14 冻结为仅稳定 read-only API；禁止任何 DB 直连/角色 | CLOSED — §21 / OQ-14 |
| A-8 | A | P3 | `retire`「不可撤销」表述含混（恢复可写 vs 仅恢复可查询） | 措辞澄清为二义其一 | CLOSED — §4.1.4 |
| B-10 | B | P3 | Versioned State 的卷起 / 摘要策略缺失（B-7 未闭环） | 冻结「不删除原断言 + 允许派生摘要断言」，保留策略留后续阶段 | 不可逆原则 CLOSED — §12.1；保留策略 DEFERRED |
| C-10 | C | P3 | 未定义 Core 跨表写入原子性边界（断言 / 审计 / `state_version`） | 冻结「三者同事务」；批量导入对齐 `IMPORT_BATCH_COMMIT` 的整批提交语义 | CLOSED — §12.1 |

**v1.1 复核时 P1 状态（历史）**：当时 P1-0 仍 OPEN。v1.2 已由 OQ-4/OQ-14 授权 Gateway Amendment #1；当前状态只以 §29.1 / §32 为准。

### 29.1 审查闭环状态（Closure Status）

口径：**"已关闭" = 该发现已在报告主体中形成可执行的冻结规则（字段 / 枚举 / 校验点 / 治理动作 / fail-closed 行为），而不仅是"已被讨论"或"已被认可"。** 每条均可被独立复核——复核者只需读到对应小节，不必依赖本报告之外的对话记录。

| 编号 | 发现摘要 | 落点（冻结位置） | 落点形态 | 状态 |
| --- | --- | --- | --- | --- |
| A-1 | identity / continuity 基数未冻结 | §4.1.1 | 冻结不变量 1:1 + 三条派生规则 | CLOSED |
| A-2 | `continuity_epoch` 无强制作用 | §4.1.2、§5 补充规则 2 | 四个强制点：写租约键 / 提交时 epoch 校验 / 进入断言与 projection / non-cloned linearizable commit gate | CLOSED |
| A-3 | `retire` 生命周期未定义 | §4.1.4、§5 补充规则 3 | 只读 + 可查询 + 不可原地撤销 | CLOSED |
| A-4 | 写者交接流程缺失 | §4.3 | `WRITER_TRANSFER` 治理动作；与 `GOVERNANCE_OWNER_TRANSFER` 分离；未走该动作即按 split-brain 处理 | CLOSED |
| A-5 | 展示名与身份的关系 | §4.1.3 | 展示名归 Constitution，身份保持不透明 | CLOSED |
| A-6 | fork 继承语义 | §4.3、§5、OQ-11 | Phase 1 禁用 fork；未来启用另立版本化合同 | CLOSED |
| A-7 / A-10 | `GENESIS` 信任锚 | §4.5 | trust-domain CAS + unique storage claim + restore current-owner authorization + epoch-0/bootstrap + witness recovery fencing；未来实现强制验收 | CLOSED（final re-review PASS） |
| A-8 | `retire` 措辞二义 | §4.1.4 | 两层澄清：可查询性不可撤销 + 写能力需 `CONTINUITY_UNRETIRE` 治理动作 | CLOSED |
| B-1 / B-12 | source 与 truth authority 可混淆 | §9.2–§9.5 | 改为 `claim_origin` 来源派生；speech act 与 proposition truth 结构性分离 | CLOSED |
| B-2 | 生命周期与完整性混装 | §9.4、§9.2 | 拆为 `lifecycle_status` / `integrity_flag` 两字段 | CLOSED |
| B-3 | 同键重叠有效区间无唯一性 | §13「有效区间唯一性」 | 至多一条 ACTIVE + 冲突置 `CONTESTED` + 迟到只新增 | CLOSED |
| B-4 | `state_version` 粒度未定义 | §12 | per-continuity 单调游标 + 明确的推进 / 不推进清单 | CLOSED |
| B-5 / B-11 | `FACT` / Gateway Evidence 与 Objective World Truth 边界 | §1、§2、§11、§14.3 | FACT 是 claim；Gateway 只具最高 Historical Evidence 权威，不裁决 Objective World Truth | CLOSED |
| B-6 | 证据对象枚举与 Gateway 模型不一致 | §14.1 | 按 `app/models.py` 实际类名补全 + `MESSAGE` / `SOURCE_ACCOUNT` / `IMPORT_JOB` 使用规则 | CLOSED |
| B-7 | 无界增长无保留策略 | §12.1（不可逆原则） | 禁止以删除旧断言控量；保留策略转 Phase 2 前独立议题 | 原则 CLOSED / 策略 DEFERRED |
| B-8 / B-14 | 用户删除、重新派生与披露抑制 | §13.1 | 墓碑 + durable suppression policy + 禁止 cache/replay/derivation/API 重新物化；不删除 Gateway Evidence；Phase 1 不要求 cryptographic erase | CLOSED |
| B-9 | 审计账本无防篡改要求 | §12.2、OQ-13 | per-record chain + non-cloned synchronous anchors + restore fail-closed | CLOSED |
| B-10 | 卷起 / 摘要策略缺失 | §12.1 | 「不删除原断言 + 允许派生摘要断言」机制冻结；阈值策略延期 | 原则 CLOSED / 策略 DEFERRED |
| C-1 | Runtime enrollment 契约缺失 | §21.3 | `RUNTIME_ENROLL` / 能力授予 / 吊销 / `RUNTIME_REBOUND`；新实例默认只读 | CLOSED |
| C-2 | Journal backlog 无强制可见项 | §16.1 | 四项强制：阈值告警 / 用户可见标记 / 异常判据 / 禁止静默丢弃 | CLOSED |
| C-3 | 降级回复不留痕 | §15.6、§15.1 | `context_status` + `degradation_reason` 必填规则 | CLOSED |
| C-4 | 能力绑定校验未进入接收路径 | §15.5 规则 2 | 接收侧强制校验 `(runtime_instance_id, continuity_id)` | CLOSED |
| C-5 | split-brain 仲裁依据不完整 | §4.3 规则 4 | 主依据 = 单调 epoch + 租约心跳计数；时间仅辅助 | CLOSED |
| C-6 | Core 敏感内容最小披露未定义 | §21.4 | 最小披露 / 禁止出界 / 日志纪律 / 加密要求 / 稳定错误码 | CLOSED |
| C-7 | Core 恢复后的重新链接不完整 | §22.1 | 一致性重扫 + `SUSPECT` 单调安全复位 + 审计 + 下游不确定性标注 | CLOSED |
| C-8 | 未继承 Gateway fail-closed 迁移政策 | §19.1 | 前向迁移唯一受支持 + 降级 fail-closed + 禁止破坏性降级触高保护对象 | CLOSED |
| C-9 / B-15 | Core↔Gateway 凭据路径 | §21、OQ-14、Gateway Amendment #1 | 仅稳定 read-only Evidence Query API + 独立只读 capability；禁止任何 DB 角色 | CLOSED |
| C-10 | 跨表写入原子性边界未定义 | §12.1 | 断言 + 审计 + `state_version` 同事务；批量对齐 `IMPORT_BATCH_COMMIT` | CLOSED |
| P1-0 | Gateway 缺对外只读 Evidence 查询 API | OQ-4/OQ-14、Gateway Amendment #1 | GET-only API、bounded-high-water、独立 capability、privacy/error contract、真实 PostgreSQL测试 | CLOSED |

**Stage 0 冻结判定：CLOSED。** Core 合同侧的 Epistemic、opaque identity/alias、linearizable fencing、GENESIS/control-plane trust anchor、principal attribution、Derived/REDACT/audit治理已形成可执行冻结规则；Gateway Amendment #1 已实现。Gateway full regression `352 passed, 1 skipped`，Reviewer A/B/C final gate 均 PASS 且 P0/P1/P2=0。详见 §32；现在进入 STOP。

---

## 30. 推荐下一实现阶段（Recommended Next Phase）

**建议命名**：Phase 2 — Core Foundation Implementation Gate（核心基础落地门）。原则：契约优先、0 模型 token、每个 Stage 独立验收。

**Stage 0（Architecture Closure + approved Gateway Amendment）**：冻结 Epistemic / identity / alias / epoch / GENESIS 合同；依 OQ-4/OQ-14 的明确授权，仅在 Gateway 自身变更控制下实施 read-only Evidence Query API。该 Amendment 是对冻结边界的窄修订，不重新开发 Phase 3。

> Stage 0 现状（v1.2）：**CLOSED**。OQ-1/OQ-2/OQ-3/OQ-4/OQ-5/OQ-10/OQ-11/OQ-12/OQ-13/OQ-14 已决；P1-0 CLOSED。B-7/B-10 的具体容量/rollup 阈值可在不可逆原则下延期，不改变任何身份、证据、审计或删除安全合同。

**Stage 1（契约 Contract）**：建立 contract 产物（版本化 OpenAPI / JSON Schema + 封闭事件枚举）：identity、continuity、assertion、evidence_ref、runtime_event、projection。加入契约兼容性 CI 检查（这是 multi repo 方案的主要代价，必须显式管理）。

**Stage 2（Core bootstrap）**：采用存储方案 B（独立 database + 独立 owner role + 独立 dump 单元），落地 identity / continuity registry 与 audit ledger。纯 SQL / 规则，**0 模型 token**。

**Stage 3（Versioned Intelligence State）**：落地断言不可变写入 + supersession / retraction / contest 状态机（§13），实现 B-1…B-3 的冻结规则。纯规则，**0 模型 token**。

**Stage 4（Projection）**：实现 Runtime-neutral 只读 projection，含 `SOUL.md` 生成与哈希漂移检测（§18）。

**Stage 5（Runtime Event / Local Journal）**：实现幂等 ingest（at-least-once + idempotent，禁止声称 exactly-once）与 Local Journal checkpoint / 重放（§15 / §16）。

**明确不在下一阶段**：Memory Intelligence 推导引擎、embeddings 算法、Mem0 / Graphiti schema、heartbeat、thoughts、agenda、voice、avatar、proactive messaging。

**Phase 2 质量门**：每个 Stage 必须「实现 + 可执行测试 + 独立 Reviewer」三者通过后才可进入下一 Stage；不得批量跨越。

---

## 31. STOP（本轮终点）

v1.1 的“严格只读、未修改 Gateway”是上一设计门的历史快照。v1.2 Stage 0 已由用户明确授权 **Gateway Frozen Maintenance Amendment #1**；该窄修订不重开 Phase 3。

- Gateway Phase 3 冻结基线仍为 `bb107edadce0168b14189b47e902fd4c31fe3f19` / Alembic `0016_real_export_evidence`；Amendment #1 已由 `70f2847f76d658e3d11001878a42f3f49e138686` 正式提交，闭环状态由 `08ab990aeb2fdd69ff41e6f09ed5bfaefef43c0c` 记录，Gateway 工作树 clean；
- 未安装 Hermes；
- 未创建 Qingyu Core 代码、目录、数据库或 migration；
- 未实现 Local Journal、MemoryProvider、Mem0、Graphiti、User Model、Relationship Model。

Stage 0 已满足 Amendment 实现、Gateway full regression 和 Reviewer A/B/C final gate 全部 PASS，现为 **CLOSED / STOPPED**。不得创建 Core、进入 Stage 1、安装 Hermes 或扩展到 Memory Intelligence；后续工作必须由新的明确授权启动。

---

## 32. Stage 0 Final Closure Record

- Gateway Phase 3 frozen baseline commit：`bb107edadce0168b14189b47e902fd4c31fe3f19`；Amendment #1 commit：`70f2847f76d658e3d11001878a42f3f49e138686`；Stage 0 closure commit / final Gateway HEAD：`08ab990aeb2fdd69ff41e6f09ed5bfaefef43c0c`；Alembic head：`0016_real_export_evidence`。
- Environment Preflight：PASS；Python 3.12.10、原始 `.venv` / pip 健康。此前单次失败归类为 transient Windows `CreateProcessAsUserW access denied`，非 venv/Python/dependency corruption。
- Amendment #1：GET-only Evidence Query API、独立 evidence-read capability、server-only cursor signing key、显式 allow-list DTO、bounded-high-water enumeration、observation-scoped attachment attempts、all-path no-store/safe errors。
- 验证：真实 allowlisted PostgreSQL `qingyu_test`（transaction rollback）覆盖 joins/pagination/late commit/fresh rescan/dedupe；目标 Evidence/Auth/Privacy `26 passed`；最终 Gateway full regression **`352 passed, 1 skipped, 2 warnings`**；`compileall`、`git diff --check`、Alembic heads PASS。
- Reviewer A final gate（Identity / Continuity / GENESIS / fencing / control-plane）：**PASS，P0=0 / P1=0 / P2=0**。
- Reviewer B final gate（Epistemic / Data-State Governance，独立）：**PASS，P0=0 / P1=0 / P2=0**。
- Reviewer C final gate（Gateway API / Security / Privacy / Failure）：**PASS，P0=0 / P1=0 / P2=0**。
- 边界确认：未创建 Core 目录/DB/migration，未安装 Hermes，未实现 Local Journal 或 Memory Intelligence；Gateway Phase 3 保持 CLOSED/FROZEN，Amendment #1 不重开 Phase 3。
- 工作树说明：Amendment #1 与 closure metadata 均已正式提交；Gateway 工作树 clean。Phase 3 frozen baseline、Amendment commit 与 final Gateway HEAD 分别记录，不互相混同。

**Final status: Qingyu Core Phase 1 — Stage 0 CLOSED. STOP.**
