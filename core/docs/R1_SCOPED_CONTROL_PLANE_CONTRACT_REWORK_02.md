# R1 Scoped Control Plane Contract Rework 02 / 第二次定点合同返工

任务：R1_SCOPED_CONTRACT_TARGETED_REWORK_02。
候选标识：SCOPED-REWORK-20260915-02。
本文件是 Rework 01 的真实第二次受控修订，不是另起名字删除失败历史。
只在本轮独立 disposition 记录最终 Design Gate；本正文不是 PASS 声明。
产品 Implementation Gate = BLOCKED；Foundation Closure = NOT ENTERED。
C01 = DEFERRED / REMOVED FROM R1 REQUIRED SCOPE。

本轮证据目录：
evidence/r1-acceptance-marathon/scoped-contract-rework-02-20260915T184222Z/。
本候选主文、统一资格合同、完整 catalog、模型、编码器、向量和实际验证
必须按同一 candidate-manifest.json 核验；受审后不修候选再二审。

## 1. 来源、适用顺序与明确替代范围

最高约束是 34674f43 用户授权、四项已决定的范围，以及已 PASS Boundary / 23 Invariants。
本次只解决七个原始编号所指的三类 P2，不重新决定产品范围。
旧 Minimal Trust、原 scoped、Rework 01 BLOCKED / STOP 和原始等级、报告保持原样。

固定基础文档：
- R1_CONTROL_PLANE_BOUNDARY_REVIEW.md，SHA256
  2aac26bd0b95a0b85cc2a869133676e7f4e96b059423c67404842cc8beb35845。
- R1_CONTROL_PLANE_INVARIANTS.md，SHA256
  bb7d769a170fe0ade9c6c6faf743c9ade4022b4f7fa211389f6ff2e5276a47b5。
- R1_SCOPED_CONTROL_PLANE_CONTRACT_REWORK_01.md，79,322 bytes，SHA256
  d8dcc01e35a835a69d6027dbf1c9e8cbe82a7f505358e18cac87c197aea6d5bd。
- Rework 01 evidence/scoped-contract-rework-01-20260915T162454Z 内
  candidate-manifest.json，SHA256
  6df90edcd6af4d9a17b2796d35b1572062def3b216a241ccbcde227c815e3e54；
  原 reviewer-a/b/c.md 和 disposition 按本轮 intake 原 bytes/hash 保全。
- K-F3、K-Core、K-Root、K-Intent 仅在未被先前获授权 V2 条款明确替代处继续适用；
  V1 实际历史不得重写。Contract Completion 的旧未决状态是历史，不再重复询问 Q-REC 等。

本文件采用明确的“固定基础 + 定点替代”，而非复制 79 KB 旧正文并留下矛盾。
以下引用只继承规范义务，不继承旧候选的 readiness、覆盖计数、PASS 推论或旧程序。
所有本轮 exact fields 以新完整 catalog 为准；它不是旧目录的可选补充。
统一资格/历史附件与主文同属规范，两者若不一致即 BLOCKED，不用优先级掩盖缺项。

| 固定基础章节 | 本候选处理 |
|---|---|
| §1.1 四项范围、§1.2 八项 V1 事实、§2 T1–T6/三方责任 | 全部保留；本轮不是再次裁决 |
| §3 进度、知识、准入、时效、独立 fences；§3.1 原因/权限 | 保留；DISPATCH_FIXED 细化为下述三持久点，不合并两库 |
| §4.1/4.1a 主体、policy、inventory、source 与闭集动作 | 保留原来源/隔离/不可变内容和 restore 上界；对象字段由新 catalog 完整表达 |
| §4.2 grant 发行与继承 | 保留原语义 fences、受限 lease、非 ACTIVE 恢复；改用下述发行位置/前缀及 grant body 版本 |
| §4.3 PREPARE/terminal | 保留原最终事务/序号/当前 fences/提交时效；另绑定 PREPARE/FIX/TERMINATE 各自执行位置 |
| §4.4 permit 与 exact pre/post | 替代为本文件发行、首次使用、已完成事实查询三分法；保留 bounded remote-recall 上限 |
| §4.5 执行历史输入/顺序 | 用本文件及 qualification-history-contract.md 完整替代时间选最后登记的做法 |
| §5 六个原持久窗口 | 保留原窗口初态/恢复要求；新轨迹须经过合法 FIX 三步，不能引用旧 73 项作为证明 |
| §6.1 C2/H2/S2、§6.2 业务语义、§6.4 摘要责任 | 保留编码/语义；受影响四 signed body 及 non-wire fields 采用新 catalog；§6.3 图加入发行/执行/本地 use 依赖 |
| §7 固定 trust/version；§8 Genesis、V1 bridge、generation opening | 保留原业务/身份/首链/来源完整性；§8.1 全部 source Core 已落实是 opening 条件，不统领 §8.5 history-only。依 §6 区分真实落后 tail 与 aligned source，并纳入新资格证据；不重签/重编码旧历史 |
| §9 mutation-only ABORT override | 保留全域 ID/content、原授权、单终态/前序；普通和例外 FIX 均经三步；FIX_ACCEPTED 不提前“接受 override”；相反 ABORT 收尾第 5 步也改用首次 APPLY / return_completed 区分 |
| §10/11/12 旧 evidence/映射/结论 | 只作历史来源；本候选以本文件及本轮实际结果、映射、独立意见为准 |

四项范围明确保持：
Q-REC 普通 intact crash 预批动作受限恢复；人工 restore 只验证/收尾获准历史。
Q-VERSION V2 与受控停写离线 V1→V2；不热升级、混合 writer、重编码 V1。
Q-ROTATION 固定 Root、receipt key、TLS/SPKI 分离，已批准 receipt/TLS rotation 延期；
失信则停止，test-only 本机 Root 不提升 production，不新增自动换钥。
Q-OVERRIDE 仅未终态 MUTATION 的独立前向 ABORT；不 forced COMMIT、回写历史或 fence bypass。
本轮不访问现场 Root、公钥/pin/ACL/服务身份/私钥，不实际签署任何材料。

## 2. 三方责任与三个判定时点

Authority 负责自己受信任登记的顺序与事件，自己事务中的资格和唯一终态。
Core 负责原 intent/提案/接受证据/完成事实的独立本地持久性及完整验证。
Operator 仍承担真实来源、完整历史、受保护部署、人工 restore 和旧 writer 隔离责任。
一个 UUID、hash 或内部自洽的日志不能代替这些来源事实。

| 判定 | 检查主体/证据 | 位置 | 后续变动的含义 |
|---|---|---|---|
| 发行资格 | 发行者 fixed receipt key；指定已存在 session/principal；policy/inventory/context/scope | GRANT_ISSUED 或 PERMIT_ISSUED 自身 Authority 位置 p 的前缀 p−1 | 后来有效的 session 不补正早发；后来撤销不抹掉合法发行 |
| 动作资格 | 当次 PREPARE/FIX/TERMINATE 的真实普通执行者；APPLY 的原 permit 本地主体 | 三个独立 A 执行位置；或独立 C 本地使用位置 | 当前失效阻止新动作；原历史记录不重写 |
| 历史验证 | 原 request/source、发行和执行快照、精确输出、原主体和完整认证登记 | 绑定原位置与完整一致日志，非调用者有利 cut | 不要求历史 grant 今天仍 live；也不从历史有效推导当前写权 |
| 既有事实查询 | 当前合法 QUERY 主体；原完整接受/terminal/completion 证据 | 验证已有位置，不分配新的 FIX/APPLY 位置 | 不续发历史签名、不新增效果、不替换原主体 |

普通恢复重新认证可取得同一逻辑安装/原操作的新当前 grant；
旧 session、旧 grant、旧 lease 不继承为能力。
需继续原操作的 policy、完整 inventory、原源授权是部署前提，不临时靠 READY 位发明。
拥有当前资格也不能改变 request、source、原决定、operation/local_commit IDs。
UNKNOWN/缺证据保持不可写；矛盾/不同内容/错 scope 拒绝并保留冲突，不自动修复。

T1/T4 对 authentic complete registry、固定 source、受保护代码/认证/time 的前提保留；
T2 只各库原子，T5 来源/隔离责任保留，T6 只稳定合法后缀的条件性恢复。
本候选不保证隐藏 rollback 检测、恶意管理员/签名者防护、无限故障活性或跨库即时撤销。

## 3. 统一事件顺序与来源绑定

精确定义见本轮 qualification-history-contract.md §§2–5 和完整 catalog；
此处固定不可省略的语义，不另造第三套 clock。

Authority Qualification Registry 与 Core Local Registry 各自：
1. 独立入场来源固定 Header；由 fixed AuthorityPin/原 protected deployment/context 重建 expected header。
2. registry_id 从固定 scope 标识确定；registry_digest 只 hash 不可变 Header，不 hash 可追加的整条日志。
3. 每事件连续、唯一、从 1 开始序号；由所属域实际 head+1 分配，不收 caller-selected cut。
4. recorded_at 同域非递减，允许同毫秒；不回填早时间、无缺口/重复或任意数组排序解释。
5. 位置绑定自身事件 p；资格来自严格 prefix p−1。事件 exact input/output raw 必须可取回。
6. 完整日志重放导出 policy/session/inventory/lease/fence/grant/permit pointer/phase/barrier；
   snapshot 是与导出状态相等的断言，不是独立“有效”旗标。
7. 同一次验证的所有 Authority contexts 必须引用同一完整 canonical 日志，
   不能拼接几份单独看似有利但互不相容的前缀。

A 执行 event.recorded_at = snapshot.checked_at，
并等对应 Ack.prepared_at / FIX_ACCEPTED.accepted_at / receipt.decided_at。
A 发行 event.recorded_at = issuance_snapshot.issued_at = grant/permit.issued_at。
C 首次使用记录时间等自身 use snapshot 的检查时间。
事件顺序不替代时效：issued_at <= action_time < expires_at，等于到期拒绝。
签名/事务等待后还须在真实最终提交边界重查 deadline；有限模型不证明数据库 deferred guard。

先执行再同毫秒 revoke：重放旧 p−1 仍验证原事实；
先 revoke 再同毫秒新动作：当前 head 的 prefix 已失效，拒绝。
+1 ms 不是解决机制，只是保留控制组。
不使用微秒、sleep 或改写后来事件时间消除碰撞。
新增真实事件只追加，不改变原位置或原 signed bytes。

wrong registry、scope、instance/generation、kind、主体、input/output、time、
caller-old-cut 或有矛盾的完整记录拒绝。
来源或实际顺序缺失而无法证明时 UNKNOWN，禁止依赖写。
日志来源/完整性必须来自受信任责任方，合成完整日志的 hash 本身不证明真实性或未回滚。

A 与 C 的序号不比较大小；时钟也不是全局同一执行点。
两域之间通过已存在 exact bytes/digest/认证观察建立因果引用；
Authority 不声称观察 Core commit，也不对其本地事务做远端锁。
Core 的即时资格仅针对本地事实及已经观察到的认证远端信息，遵守既有有界许可上限。

## 4. FIX：新动作与已有事实不是一回事

必须区分三个分别可 crash 的提交点：

    原 INTENT / request / source / choice
      → Core 非消费性 proposal
      → Authority FIX_ACCEPTED（该域当前资格检查）
      → Core 保存原 acceptance 并发布 dispatch
      → Authority 独立检查当前 terminal 资格
      → 已有 terminal 的本地 finish

### 4.1 Core proposal

原 request/source/已验证 Ack/stage/normal authorization 或独立 exception authorization
以精确 bytes 和原主体声明固定。proposal 只能协调，不可 terminal 消费。
其创建者属于原历史，不能要求原创建 session/grant 在每次后续 restart 永远 live；
但 proposal 也不因此成为旧资格的永久授权。
本地 PERSIST/QUERY 与业务 FIX 权限区分。普通/restore 共用 helper 仍按实际动作检查。
供新的 FIX_ACCEPTED 消费的 proposal 仅由 policy 允许 FIX 的 ordinary component 在合法本地协调资格下固定；
这不代替 Authority 对真实 FIX 的 live grant 检查，proposal 尚不是已完成的 FIX 证明；
restore 的 PERSIST 只存 context 内既有历史，不可借“尚不可消费”标签创建新的业务/exception proposal。

### 4.2 Authority acceptance

对同域同 operation/kind/proposal 的新 FIX，真实 authenticated actor 必须为获准 ordinary
MUTATION_RECOVERY；当前 policy/session/inventory、grant pointer/serial、有效期、lease、
原 request/source/content、owner/epoch/state/各 generations、phase/barrier 全部合格。
grant 与执行 snapshot 均在该域实际序列化位置绑定；不能从 PREPARE 或 terminal 两端倒推中间。
normal 与 override 都走这个边界，未合格拒绝，不产生 usable dispatch。
Root ABORT 不提升 restore 权限，不豁免当前 fences。

FIX_ACCEPTED 绑定 proposal_digest/execution_digest/accepted_at/kind，
其自身原事件保存 exact input/output。它不是 terminal、canonical receipt 或 accepted override。
Root override 仍只在 §9 原最终 Authority transaction 与 terminal 同时接受。
一个 op 的不同合法 normal/exception proposals 可竞争，但不会各自取得第二 canonical terminal。
同 kind/原键的不同内容冲突，原记录不可替换。

### 4.3 Core publication、查询和重试

Core 独立验证原 proposal→A acceptance/execution proof 后在自身事务保存原接受事实，
绑定自己的 local position 和 fix_acceptance_digest，再成为 terminal 可消费的 dispatch。
该提交不是 A 事务，也不是重做原 FIX。普通 restart 后当前获准 QUERY/PERSIST 可以保存
原精确接受证明；不能替换原 FIX actor/cut 或重签。

三步任意响应丢失只查询原 IDs：
未接受 proposal 后来在新当前 grant 下完成真正的新 acceptance 是合法新事件；
旧无资格 FIX/非法 consumable dispatch 缺乏原 acceptance 不能被新 grant 追认。
已合法接受但旧 grant 后来过期/撤销，其 exact-history 查询仍可成功；
若要创建新 terminal，仍需独立当前 qualification。
直接/间接 stage、stage_override、helper、query 后继续、restart/new session、新 grant、
exact retry、permit/restore 桥接都遵守同一分类。

restore 即使拥有复制来的 normal dispatch、旧 grant、Root override 或获准 read/persist，
仍不能借 publication、helper、模式、新 ID 或 lifecycle 名称生成新 mutation terminal。
它只可核验并收尾获准的原 source 已成立历史；允许整个世界有 source 合法 terminal，
但 restore_created_terminals 必须为 0。
若本地对“原 proposal/原 acceptance”无法确认，保留 UNKNOWN，不从缓存补造。

## 5. Grant / Permit 发行、使用及完成记录

四种受影响 signed body 保持 type 和 version=2，新增必需 contract_revision=2：
execution_grant、prepare_ack、terminal_receipt、local_finish_permit。
新 non-wire 历史对象使用 history_version=2。
缺版本或少字段不得默认为本轮合法历史；此变更仅新候选，不声称旧已部署历史自动兼容。

### 5.1 发行 cut 与当前资格

grant/permit 增 issuance_digest。
IssuanceSnapshot 绑定自己 A 位置、时间、issuer/subject/session、policy/inventory、
context、operation/request/source、上游 body projection 和 fences/target。

body projection 只删除 issuance_digest 和 receipt_signature；保留 contract_revision。
projection 先确定 → issuance snapshot → issuance_digest → signed body/S2 → event output。
pre-issuance prefix 不要求新 grant/permit pointer 预先存在，所以无自依赖。

SESSION_CREATE 必须在发行 p 之前，指定主体/policy 必须在当时 ACTIVE 且范围相符。
同毫秒先 create 再 issue 合法；先 issue 后 create 非法。
发行者固定 receipt key，不能把 Root/TLS key 当发行者。
当时错 session/scope/gen/policy/inventory/context 不可用“现在已补齐”修复历史。

Grant 另需 producing action 集合、当前语义 fences、受限 operation lease；
仍允许原 INTENT 尚未 remote PREPARED 的恢复，不要求 ACTIVE、清掉本 op pending 或拥有 Ack。

Permit 另需完整已验证 terminal/两链/原 source、exact before/after；
restore 还需获准 source→target/context/旧 writer 隔离。
不要求活 execution grant，也不要求它将授权的 APPLY 事先完成。
before 来自原可信 saved cursor，不取当前 global head；
after 来自选定原 receipt/result/effect/Audit，不凭现在 state_version 拼凑。

### 5.2 首次 APPLY

Core 实际消费者必须等 permit 原 subject/session，不能用一个后来合法新主体替换。
当前受保护 local policy/component/session、目标操作/安装/两 local generations、
context、scope、原 pre 状态及当前已观察 permit pointer 都必须合格。
本地已观察撤销、过期、替换拒绝新使用。
重复观察同一旧发行/session记录不得清除受保护撤销或把当前指针倒退；保留对象撤销事实和
已观察的来源顺序。只有真正新发行/新准入记录经完整验证才能形成新的当前资格，
不能用旧响应重装旧 permit 后再 APPLY。
max 30 秒且不得超 policy/session/context；可信时间保守检查 now+1000 < expires_at。
丢失时钟保证则拒绝，不静默降低标准。

Authority revoke 阻止新 permit；已发有界 permit 不承诺跨库即时 recall。
Core 已观察到的认证撤销/替换立即约束后续本地 use。
这是原 §4.4 的既有授权边界，不是本轮扩权或共享时钟的新保证。

### 5.3 CompletionRecord 与纯历史返回

Core 原子保存选定 effect/result/Audit、原 receipt、checkpoint/FINALIZED 与完整
CompletionRecord/local-use proof。证明绑定原 permit issuance、当前使用资格位置、
原 request/source/target 和精确 post，不能只有一个 finalized=true。

首次 apply 只从完整 exact pre 转换一次；第三状态、同 version 不同 head/内容、
另一个结果/receipt 或缺链均拒绝，不覆盖。
完成后 return_completed 是纯 QUERY：当前读资格 + 完整原发行/原 use 证明 +
精确已保存 post，不需要续发历史 permit，也不产生新 effect/序号/签名。
历史合法不能授权重新消费；历史 permit/session 后来失效不自动抹除既有完成事实。

## 6. 全部 bytes / digest 方向与保存义务

原 C2（不是 JCS）、H2/S2 域分离、36 typed domains、业务 Effect/EmptyEffect、
identity/scope/payload preimage、两分支 result/Audit 构造、V1 原 raw、V2 两首链、
fixed key/SPKI 映射全部保留，新完整 catalog 逐型列明 exact shape/类型/来源/版本/拒绝。

增加的执行绑定：
- prepare_ack.prepare_execution_digest 绑定 PREPARE snapshot。
- terminal_receipt.fix_execution_digest 绑定 FIX_ACCEPTED 的 execution snapshot。
- terminal_receipt.terminal_execution_digest 绑定 TERMINATE snapshot。
- grant/permit.issuance_digest 绑定本对象原发行 snapshot。
- 各 RegistryEvent 的 input_digest/output_digest 绑定 exact raw；位置只回指不可变 Header 与自身序号。
- Core proposal、acceptance publication、local use/completion、认证观察均有 exact non-wire schema。
- Source/archive 必須保存本轮实际引用的完整 registry、snapshots 和 proposal/acceptance/publication、
  issuance/use 证据 raw；只存三张 signed body 不是完整历史验证输入。
  已 aligned 的 opening source 必须有实际 source 完成证明；history-only tail 则可保留源 Core
  真实落后与 Authority 已成立的完整 terminal，不能要求先做缺失的 source APPLY 才准 restore。
  两类 profile 的真实 heads/state 必须明确，不能把预期 Core post 冒充已发生的 source 完成；
  generation opening 仍拒绝未 aligned 的 source。
  HISTORY_ONLY_TAIL 的 authority_tip 是真实 A terminal tail，audit_tip/state_version 是源 Core
  实际 tip/state；未落实 inventory 项保留真实 terminal_ref、audit_ref=null。
  DERIVED_AUDIT 只代表待应用派生值，不是源 Core 已保存 Audit；profile 本身须被 archive 绑定，
  validator 仍独立重算是否 aligned，不能只相信标签。Root context 绑定原差异和可信 backup。

整体方向是：
原 trust/source/IDs/业务语义 → request；
原受信登记 prefix + grant projection → grant issuance → signed grant；
原 request/grant + PREPARE execution → Ack；
request/Ack/stage/authorization → Core proposal；
proposal + current qualification → FIX snapshot/acceptance → Core publication；
原 evidence/current terminal grant → TERMINATE snapshot → signed receipt → final Audit；
原完整历史 + 当前收尾主体/target → permit projection/issuance → signed permit；
原 permit/observed state + Core 当前 use snapshot → exact local completion。

序号预分配是同域事务内身份，不是提前输出的 receipt 或 own-output digest。
snapshot 不能 hash 包含自身的 RegistryEvent/整条未来日志；
event output 是下游，Header 不依赖事件。完整归档是这些已存在 bytes 的下游清单。
实际候选对象/raw 依赖图须由非作者重新构图/拓扑核算，不能只相信上述文字图。
依赖缺失/循环、跨域错误连接、canonical bytes 变异都阻塞 readiness。

此外必须独立核验事件因果图：每个域前一事件→下一事件，加上实际跨域输入提供事件→消费事件。
单看对象 hash DAG 不够，因为 position 不 hash 整个 prefix；例如 Core 先观察一份依赖未来
Core publication 的 receipt，随后才发布该 dispatch，即使单项摘要能重算，事件因果仍成环。
这种未来输入/循环历史必须拒绝，不能用两域时间比较或“最后所有记录都存在”替代。
来源 provider 必须是被绑定的正确域/实际位置，不能任选一个同 hash 的临时记录。

真实签名仅作为来源前提；语义 validator 仍须独立验证全部发行/执行关系。
合成 a5 签名和 S2 前像不等于真实 Ed25519/曲线/证书/TLS 验证。
V1 reference 仍只 ASCII/safe-integer 子集，不能标成完整 RFC8785/JCS。

## 7. 持久窗口与条件性恢复义务

原六窗口 COMMIT/ABORT 必须来自真实有限转换，不删除可达初态：
1. 原 INTENT、未 PREPARE；
2. PREPARE 发送不确定/Ack 未确认；
3. PREPARED、dispatch 未固定；
4. dispatch 已固定、terminal 发送不确定；
5. 已有 terminal、本地未完成；
6. 本地完成、响应丢失。

窗口 3/4 进一步覆盖 proposal 已存但 A 未接受、A 已接受但 C 未发布、
C 已发布但未 terminal 三独立持久点。
每个 ordinary 合法后缀需要先取得当前资格，在新业务 CLOSED 下完成原 op；
不依赖 ACTIVE，不通过换 ID/新业务/临时豁免/自动 ABORT 走出 pending。
原已完成事实查询不得因为当前没有旧 grant 而死锁。

source→restore 正例必须先由 source credential 真正完成原 terminal，
再固定真实历史/context 并由 restore 收尾，不向 fixture 凭空放结果。
normal COMMIT、normal ABORT、opposite Root ABORT 分开覆盖，restore 新 terminal 数 0。
restore 的 producing helpers/mode/old grant/override/new ID 负例、override ID-content conflict、
normal/override 顺序竞争及相同 bytes 重试仍是必测。

这些是有限模型的明确义务，不是全部生产时钟、调度、DB 并发或无限状态活性证明。
缺少必需场景不能仅以“有限模型”免责。

## 8. 23 项不变量：保留责任与本轮可验证范围

此表是义务/检查映射，不是 23 项产品 PASS；实际执行及未覆盖处以本轮结果和独立报告为准。

| Invariant | 保留责任与本轮证据连接 |
|---|---|
| INV-A-01 | 单 op 唯一不可反转 terminal；FIX_ACCEPTED 不占 canonical seq；normal/override 两顺序及重放检查 |
| INV-A-02 | 认证、签名、业务语义分开；完整两分支和重新计算摘要后的错主体/内容/资格仍须拒绝 |
| INV-A-03 | PREPARE/FIX/TERMINATE 三当前位置；最终 pointer/lease/session/fences/time 重检，合法历史与新写分离 |
| INV-A-04 | A 本域事件/输出/terminal 原子；C publication 独立提交；三 FIX crash 窗口检验原子抽象，不证明真实 DB |
| INV-A-05 | 同 ID exact bytes 返回；旧 grant 失效不重签历史；同 ID 异内容拒绝 |
| INV-C-01 | 原 INTENT/source/choice/IDs 网络前固定；restart 不换意图 |
| INV-C-02 | proposal 不授权；合法 acceptance 原文持久发布才允许 POST；normal/exception 不改彼此 |
| INV-C-03 | timeout/non-200/UNKNOWN 只查询同 ID；不虚构 NOT FOUND/terminal/acceptance 或自动 ABORT |
| INV-C-04 | 原 source/request/Ack/stage/三个 execution/grants/issuance/receipt/两链全部验证先于 effect |
| INV-C-05 | exact pre 首次 APPLY，exact post 纯查询，第三状态拒绝；CompletionRecord 与 effect/result/Audit/checkpoint 同本地事务 |
| INV-C-06 | saved 原链与 checkpoint 验证，不以 state_version/当前 global head/projection 替代 |
| INV-C-07 | fixed API/machine trust；expected RegistryHeader 来自独立来源，不自算 hash 自认证；Core 无 Authority SQL/签名秘密 |
| INV-O-01 | test-only 本机 Root 与 production 分离；custody/pin 不碰，不能自动生成或换根 |
| INV-O-02 | 来源完整、人工 restore 与旧 writer 隔离仍 Operator 责任；restore 不创造 source 历史 |
| INV-O-03 | 最小权限/迁移前后真实验收保留未来责任；文档和合成 registry 不授予实际 DB/OS 能力 |
| INV-R-01 | 来源、权限、知识、进度、时间、fences 分开；proposal/接受/发布/terminal/完成不混同 |
| INV-R-02 | ordinary intact crash 有预批受限恢复，不改称人工 restore；新 session 合法资格可继续原 op |
| INV-R-03 | COMMIT/ABORT 六原窗口与三 FIX 持久点的合法后缀，T6 稳定窗口、不依赖 ACTIVE |
| INV-R-04 | 原位置验证执行/发行，当前本地资格控制 first use；历史完成不授予新 effect，后续撤销不改旧事实 |
| INV-R-05 | GENESIS attempt/#1、两首链、V1 bridge/generation lineage 不变；新 registry seq 不是 receipt seq |
| INV-R-06 | 完整 exact typed/nested/non-wire 前像、版本、DAG；所有新cut/issuance/proposal/use字节纳入核算 |
| INV-R-07 | mutation-only Root ABORT，原 normal auth 不改；ID/content/predecessor 和单终态竞争不可变 |
| INV-R-08 | Root/receipt-key/TLS SPKI 各自固定映射与失信停止，已批准 rotation 延期不重裁 |

未来验收义务明确保留：真实 A/C 单库持久性与序列化/冲突处理、post-sign/commit deadline、
同域真实日志完整导出和不可替换来源、受保护 Core 日志、认证/时钟、真正签名/验签、
TLS/OS/ACL、PostgreSQL 权限和 migration。它们未在本轮执行，也不是新设计声称已证明的事。

## 9. 三类目标与六类历史记录分开

| 当前授权目标 / 原级别 | 本候选合同处理 | 必须核对的反例/控制 |
|---|---|---|
| A-RW01-01 / REWORK-B-02 / C-REWORK-01，P2 | FIX acceptance 自己当前 guard/历史snapshot，三个持久点，拒绝不能留 usable dispatch | 旧 session grant、expired/revoked normal/override；非法记录不能被续发洗白；先新合法grant→新FIX正例 |
| A-RW01-02 / REWORK-B-01 / C-REWORK-02，P2 | 来源绑定 Header/Position，自身event与严格prefix，signed snapshot digest | terminal后同毫秒policy/grant revoke仍接受原历史；相反顺序新动作拒绝；+1ms、错cut/source/content/回填/调用者旧cut |
| REWORK-B-03，P2 | 原 issuance位置、session/policy/inventory/context真实前提；first use/history/completed 分离 | ordinary/restore早于session拒绝；同ms两顺序；现在合法不能补早发；首用失效拒绝而既有完成可读 |

原始三类 P2 在旧候选中的 OPEN 不回写。新候选是否设计层充分处理必须由本轮实际证据
和正式独立 Review 判定，不由此“处理方式”表自动关闭，更不等于产品已修复。

| 六类 Minimal 历史根因 | 原编号 / 等级 / 记录 | 本轮关联（仅设计层） |
|---|---|---|
| 恢复循环 | A-01 P1 / C-MIN-01 P2，共享根因保留 P1；旧 OPEN | 当前grant后FIX、六窗口非ACTIVE合法后缀，不能借旧73项直接关闭 |
| 完整请求图不闭合 | B-01 P1；旧 OPEN | 新issuance/execution/use并入完整无环前像图 |
| 语义摘要前像 | A-02 / B-02 P2；旧 OPEN | effect/empty/identity/scope/payload和新字段真实bytes |
| GENESIS/版本/首链 | A-03 P2；旧 OPEN | 保留两首链/attempt/V1/generation与完整source，有限profile不夸大 |
| rotation/key mapping | B-03 P2；旧 OPEN | 已批准延期不重问；固定映射/失信停止保留，延期不是产品修复 |
| override模型忠实性 | C-MIN-02 P2；旧 OPEN | ID/content/predecessor、独立例外及单终态；FIX_ACCEPTED不提前接受override |

另列原 restore 越权：
A-SCOPED-01 / SCOPED-B-01 / C-SCP-01，均原 P2。
Rework 01 已提供主体/动作隔离、旧反例保全与 source→restore finish 正例；
本轮必须回归新 FIX/publication/permit/helper 路径，不将其与本轮普通 FIX 漏guard合并改名。
原 A-SCOPED-02 / SCOPED-B-02 / C-SCP-02、SCOPED-B-03、SCOPED-B-04（原 P2）
关于附件、历史输入和执行口径的记录全部保留；新附件和真实输出只属于新候选。

## 10. 受控 authoring、就绪与一次独立设计复审

先保存原实际 probes、原命令/stdout/hash；再在新候选中检验同前提坏输入与对应合法路径。
作者修改、内部检验和非作者机械核算均不是正式 A/B/C Gate。
不把旧作者数目、模型assertions、向量数和产品tests相加，也不设 73/279 等目标数量。
实际结果、日志、代表独立 expected 与完整 bytes 核算分别保存。

正式 readiness 必须同时满足三类必需定义、原反例/合法正例、
主文/统一note/catalog/model/encoder/vectors/results一致、无未解释循环、无必需TODO。
未就绪不把半成品送正式Gate。
完成时固定同一候选 manifest/哈希；这只是设计审查快照，不是产品 Candidate Freeze。
非作者 A/B/C 独立先固定意见再互读，每份给：
证据忠实性、范围内合同完整性、模型/bytes有效性与限制、本轮Design Gate。

一轮正式复审出现当前 P0/P1/P2/OPEN/PARTIAL 即保留原文 STOP，
不修改候选继续二审，不自动第三次返工。
若编制期间出现新结构性 P0/P1、必须扩大信任/产品范围或弱化 accepted invariant，
保存具体反例/冲突即 STOP。
所有通过也只表示 Rework 02 Design Gate PASS；
Implementation BLOCKED、Foundation NOT ENTERED、C01 DEFERRED 仍保持。

工作区只允许新增本主文和本轮 evidence，LONG_RUN_STATE 末尾追加。
原 260 件基线及 LONG_RUN_STATE 原 23,547 bytes 前缀必须不变。
原 Core 9 dirty tracked、diff object 9594b6b6f5374094a88bcb068d5bcd7afd875d18 不变；
不 Git 写、不产品/测试/migration改动、不DB/Docker/network/Root现场访问。
所有文件写入串行 apply_patch。实际 authoring/review/最终保护证据以本轮文件为准。

