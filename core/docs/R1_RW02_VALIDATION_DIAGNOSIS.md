# R1_RW02_VALIDATION_DIAGNOSIS

Task：R1_RW02_VALIDATION_DIAGNOSIS。Resume Token：R1_ACCEPTANCE_CLOSURE_MARATHON。
本轮状态：**COMPLETED（有界诊断与证据整理，不是 Design PASS）**。
开始：2026-09-16 03:40:34 UTC。主控 /root；新诊断者 /root/diag_override_time、/root/diag_permit_subject；新非作者相关路径核查者 /root/diag_related_paths。最大并发含 Lead 4；文件写入串行。ai-dev-team 用于只读调查、分工与真实证据交接，用户禁止第三次返工优先于通用返工流程。

Rework 02 Design Gate = BLOCKED / STOP；Implementation Gate = BLOCKED；Foundation Closure = NOT ENTERED；C01 = DEFERRED / REMOVED FROM R1 REQUIRED SCOPE。A-RW02-01、RW02-B-01、C-RW02-01 均仍 P2 OPEN。原六项历史 Findings、四项既定范围及 Boundary / 23 Invariants 的原 scoped PASS 不变。

## 1. 结论与证据边界

三个原始成功探针都按保存的原文重新执行，仅适配冻结源文件绝对路径；各自 exit 0，得到原先接受/拒绝关系。另行新增的邻近控制与原反例分开保存，不冒充旧 Reviewer 当时执行。

三个问题的**已证实局部根因均归 A**：必要关系已在现行文字/字段中定义，当前格式可以取回验证所需输入；参考候选的特定入口遗漏关系或与模型/其他入口不一致。本轮没有找到必须增产品 scope、新协议、委托规则或新历史格式才能判定这三项的 B 类缺口。不是证明整个合同没有 B 类问题。

C 类未知主要是现实来源认证、不可替换存储、真实执行时限与攻击可行性，以及原 B 未审剩余范围。它们不能由合成探针填补；也不取消已实测的参考验证器责任缺口。未发现需要本轮扩大范围才能继续的结构性 P0/P1；不将这一有限观察外推为全项目无 P0/P1。

可确认的共同模式：同一安全义务在不同入口的责任不闭合，正常构造出的关联被某些接收/回放入口当作既定事实。不能证明三项由一个函数、一个缺失 helper 或完全相同的架构根因造成：
- A 是原动作授权期限没有在 producer / 独立 replay 重检，而模型及完整 bundle 有检查。
- B 是局部 use/CompletionRecord 内部一致，但实际引用 target 没有连接到由原请求重建的正确 target。
- C 是 permit 与 issuance 的两个主体声明相同，但没有连接到其指定 session 的真实准入主体。
这支持重新明确验证责任及独立输入期望，**不支持现在自动补三个 if 或要求所有入口共用一个 helper**。

## 2. 固定受审来源与接管保护

工作树 <repo>/core-r1-implementation；branch ai/task-r1-canonical-implementation；
HEAD e490134ba9ced81be182b4c24eb41c970258f325；
tag r1/pre-minimal-trust-pivot-e490134，tag object 0a9bcb0401d13f14429b6a934454de358361f34e。

本文路径简写仅用于精确定位，不创建新规范：
- **E** = docs/evidence/r1-acceptance-marathon/scoped-contract-rework-02-20260915T184222Z。
- **D** = docs/evidence/r1-acceptance-marathon/rw02-validation-diagnosis-20260916T034034Z。
- **M** = docs/R1_SCOPED_CONTROL_PLANE_CONTRACT_REWORK_02.md。
- **Q** = E/qualification-history-contract.md。
- **C:n** = E/codec_reference.py 第 n 行；**R:n** = E/recovery_model.py 第 n 行。
- **I** = docs/R1_CONTROL_PLANE_INVARIANTS.md。Boundary 原文为 docs/R1_CONTROL_PLANE_BOUNDARY_REVIEW.md。
- **E1** = docs/evidence/r1-acceptance-marathon/scoped-contract-rework-01-20260915T162454Z。仅作必要历史静态对比，绝不代替 E。

实际读取 LONG_RUN_STATE、disposition、manifest、原 A/C 完整报告及 B 保存的完整局部报告；读取当前主文/统一附件、相关 exact schemas、模型/codec 路径、原始探针和所引 invariants。不是用入口摘要代替原文。未恢复旧任务 structured reasoning，也未无限搜索缺失日志。

接管以旧保护清单和必要增量核对：原 260 项 + 上轮实际新增 27 项 = 当前受保护 287 项，并非机械要求历史数量。E manifest 的 21 新材料 + 27 继承来源全部实际长度/SHA256 相符。旧 LRS 23547-byte 前缀保护保留；本轮以接管时完整 28494-byte LRS（SHA256 01782d098d45df8c2d66ff820db9083e45effa5db77c67c99599b43f94775def）作为追加前缀。

关键版本：
- M：30566 bytes；6ed77c42ba6b85daf7b8f2d45de6fe2a5bc32f0c8126cfef252fa218fb174737。
- E/candidate-manifest.json：13228 bytes；9933c90886e8859e2b70f3f7f182e31ff1bfb41baeb0d31578f97998c6de0838。
- E/codec_reference.py：235470 bytes；4adb8ee1885ecb3d508a3580b8c5166d360efbb2c857c5637d4e1e862dfb7c18。
- E/recovery_model.py：78576 bytes；74ec125f5f82efd36b7afbb34581f154b3b044f61614815d150577205c80b0ca。
- 用户给定 9c5d80ea6e8693b452015b86c2766e934b532c911bbb70bfab12cb829fcaa280 是 E/final-verification.json 的真实 hash，不是 M 或 manifest。
- 其余原件/新增证据逐件源版本、路径、长度与 SHA256 见本轮 package-manifest.json；没有将 checkpoint SHA 冒称这些未提交附件的 commit 身份。

## 3. A-RW02-01：原动作时点上的 override 授权

合同：M §2–4、Q §2–3；继承 Rework01 主文 §9（815–855）；I INV-A-03、INV-R-04、INV-R-07。同一 AbortOverride 的 issued_at <= 实际新动作时点 < expires_at；合法 proposal 不使后来的 FIX/terminal 永久获权。历史判断原时点，不以查询 wall clock 反转原合法事实。

原输入：fixture override；原 authorization 与 request/proposal/grant/session 均不改。override expiry=1789488005000；proposal=1789488000060；grant expiry=1789488010050。保留原 A 的 A 日志前 11 event、Core 前 5 event；只移动后续动作时间。

实际路径：authority_action C:2040–2058 自建 snapshot/event → replay_authority → verify_execution_at C:1253–1299 → Core replay / causality → 更新 registry。已查 position、真实 subject/current grant、原 request/source/proposal/Ack、acceptance/publication/output；FIX 分支 C:1281–1289 未将 override interval 连到 accepted_at；terminal C:1290–1299 调用的 verify_terminal_bindings C:340–374 也未查该期限。verify_exact_fix_history C:2060–2065 复用该回放，只比较原 acceptance。

原反例实际：expiry−1、expiry、expiry+1 新 FIX 与 exact history 均 ACCEPT，publication ACCEPT；在 FIX+2 的已过期新 terminal 仍 ACCEPT。模型同义 expiry 新 FIX 返回 OVERRIDE_INVALID、状态不变。

本轮新增真正同绑定 full-bundle 对照：
- FIX=e−3、terminal=e−1：producer、history、完整 bundle 全部接受。
- FIX=e−2、terminal=e：producer/history 接受；完整 bundle REJECT: override interval at Authority acceptance/terminal。
- FIX=e、terminal=e+2：同上。
C:1675–1676 的原区间 guard 因而不再仅有原 A 静态观察，而有本轮新动态证据。未回写原 A 的“未执行 full-bundle”记录。

合法控制：保留原合法 FIX/terminal 与所有 wires 不变，override 过期后用新的有效 finish permit 完成首次收尾；完成后旧 permit 过期仍两次返回 IDEMPOTENT_SAME_POST，Core registry/completion 不变。过期 permit 首次用拒绝，已完成输入再用 first-use 入口拒绝。模型在 4999 接受、5000 拒绝新 FIX/terminal；5001 可返回 EXACT_FIX_FACT / EXACT_TERMINAL_FACT、不变状态。

影响是规范参考 producer 已新登记了合同不准的接受，独立历史入口仍认可；更晚 full bundle 拒绝不补正上游。不是“所有过期历史都应拒绝”。exact FIX helper 明示不认证当前查询 caller，本轮不向该纯历史 helper 发明额外权限职责。非法 terminal 后再发 permit 的传播仅静态确认调用关系，未作为新的已执行反例。

完整命令、字段变化、stdout 和边界：D/diag-a-time-probe.py、diag-a-time-raw.txt、diag-a-time-report.md。原 Appendix A 源码 SHA256 1b720a7a6875553fbf79c25d511dd77bfd6c8bb5b9d6cfd0c548608c3414850c。

## 4. RW02-B-01：完成证明引用的 target 必须属于本次原操作

合同：M §5.3、§6；Q §5、§8；I INV-C-04/05、INV-R-04/06。正确期望目标来自原 request.intent.identity、operation/request/source、terminal/Audit、local policy 的 installation/generations/context 与 pin，C:1301–1305 重建。

真实 FinishTarget 有 identity_digest，没有独立 continuity_id 字段；continuity 属于 identity 前像并被其 H2 绑定。不能凭摘要向 schema 添加字段。

原反例先 consume_finish 产生合法完成，再替换该历史 APPLY 引用 target 的 identity_digest 与 operation_id，联动重算 target → use_input → local snapshot → CompletionRecord → APPLY event。原 permit/issuance/request/terminal、顶层正确 target 和实际 post/effect/result/Audit 保持不变。原 identity='12'*32 是没有完整前像的显式错误摘要，原 B 已如实标界。

实际经过 C:1436–1438 原 source、C:1471–1472 原 use 主体与原时点 deadline；C:1473–1483 仅查局部 target checkpoints/installation/generations/context 与内部 target_digest 一致。finish_history C:1772 另验证顶层 target 是原 request 重建目标，却未连接历史 APPLY 实际引用 target。return_completed C:1817–1825 验原 permit/issuance/event 和 effect/result/Audit，仍缺这个连接。结果 baseline 与错误证明均 IDEMPOTENT_SAME_POST；completion target 与正确 bundle target 不等。

新增相邻控制不冒充原 B 探针：保留相同原操作/permit/terminal/post，使用另一完整 schema-valid identity 前像、仅 continuity 改动的完整 identity 前像、仅 operation 改动，联动重算同一条历史证明链。replay_core、finish_history、return_completed 以及再次 completed query 都接受。schema-valid 只证明前像真实可重算，不证明另一身份在同一 Authority 已获准。

正负对照：正确 target 同样重绑定接受；首次输入顶层 target 的错 identity/op 拒绝；正确完成记录在 permit 过期后仍能查，过期首次用拒绝；历史 use.result_digest 与实际 selected result 不符的完整查询拒绝（实际 post 不改）。由此范围不是全部消费者或全部 post 校验失效，而是完成历史的目标关联缺口。没有执行新恶意业务 APPLY、没有证明真实存储可被改写。

模型 R:260–284 从 permit/source/receipt/session 重建 target/CompletionRecord，R:523–525 全等比较；wire codec 却能接受独立可变 target 引用。这不等同于模型与 codec 共享完全相同的数据表示。正常 producer C:1793–1802 从已验证 bundle target 同时构造 use/completion，构造正确不证明接收任意符合承诺输入形状的历史时也验证该关系。

原 B 成功探针源码 SHA256 2b184bbb328462fcad4bf2025e2c113660fd21d1976519b06b2882aa1a5f20f3；本轮 stdout 与其保存文本换行归一后相同。新补充核查报告为 D/related-paths-supplement.md；探针 D/related-paths-probe.py；原始输出 D/related-paths-output.jsonl。

## 5. C-RW02-01：发行声明主体与已准入 session 的实际主体

合同：M §2、§5.1–5.2；Q §4–5；catalog 的 issuance/local_finish_permit；I INV-A-02、INV-C-04、INV-R-04/06。必须验证发行位置已有、active、scope/policy 合格的 named session/principal。后来有效的主体不得补正过去错配的发行。

原输入 ordinary_finish / finish / lag_finish：只改 permit.runtime_principal 与 issuance snapshot.runtime_principal 为 unregistered-runtime，保留 session/enrollment/policy/inventory/时间/scope/source/target。用探针内独立 stdlib C2 子集和 hash 重算 body projection → issuance → permit H2 → Authority event → Core observation；不是保留坏 hash 等待错误拒绝。三例原 digests 与原 C 报告相同。

verify_issuance_at C:1202–1215 查声明彼此相等、原 session 指定的真实 subject 通过 check_subject、issuer key 与 pin 相符；PERMIT C:1236–1251 查 terminal/target/context/generations/sequence，却遗漏声明 runtime_principal == 已取回真实主体 runtime_principal。C:1243 只比 installation/context。GRANT 分支的 lease/principal / verify_grant_bindings 不能补 PERMIT 分支。

三例 replay_authority 与完整 finish_history 全 ACCEPT；verify_finish C:1784 拒绝 first use original permit subject。首次用的拒绝是有效保护，不能倒推发行历史正确。

新增控制使用另一实际构造并独立验证准入的合成主体 B（自身 deployment、policy、enrollment、session、inventory，不是改个 label），把 permit 声明改 B 但保持其发行记录指定 A session/policy。发行/history 仍接受；当前合格 A 拒绝首次用；即便换成已核验当前合格 B，也因原 policy/session 等不符拒绝，不能洗白过去发行。合法 A→A 与 B→B 均接受。

其余有限控制：合法发行/首次用接受；原发行合法而当前 now 到 permit 的 conservative deadline 时历史接受、首次用拒绝；合法完成后到 expiry+1 两次 query 返回同一 post 且不改 bundle；不能再次 first-use。另将同一错误 permit 下游联动到合成完成证明，Authority 发行仍接受，而 finish_history / return_completed 在 C:1471 拒绝 permit original local use subject。该历史是人为合成变异，不是错误 permit 通过 consume_finish 的产物；不能把未检查发行混称已证明存在非法 APPLY 利用链。

角色区分：permit 声明主体；session.enrollment 中主体；由已准入 policy/material/session 确定的认证主体；issuance 固定的主体；当前消费或 QUERY 主体，五者各有时点职责。receipt issuer key / Operator Root / TLS 不是 runtime subject。没有要求所有角色字段机械相等，也没有加入未授权的委托映射。模型把 session 实体嵌入 permit、issue_snapshot 从该 session 派生主体（R:248–257），不能独立表示 wire 的两份主体声明错配；这是表示限制，不是动态验证过那份错误 wire。

原 C 探针源码 SHA256 3b83e9c5752259a7046ef8994239967902460e9e5808c39eb14f89642110e368。D/permit-subject-probe.py、permit-subject-results.json、permit-subject-diagnosis.md 给出实际命令、输出及重绑定清单。

## 6. 唯一验证责任矩阵

本节为本轮唯一矩阵；Worker 事实报告没有另设责任台账。单元格以“存在/缺失；位置；输入→时点；结果；证据”记载。A±、B±、C± 分别指 §3–5 的原反例及新增正负控制和对应 D 原始输出；“静态/动态未测”不能解释为已覆盖。纯 terminal 与后续 permit/use 的 N/A 仅针对此处具体关系，不免除其他职责。

| 具体安全关系 | 合同依据 | 模型 | producer | terminal/history 验证 | 完成历史查询 | permit 发行历史 | 首次本地收尾 | 重复查询/重放 |
|---|---|---|---|---|---|---|---|---|
| A：同一 override 对新 FIX/terminal 原发生时点有效；之后到期不反转原合法事实 | M §2–4，Q §2–3，RW01 §9，I A-03/R-04/R-07；原 auth+动作时点；越界新动作拒绝、合法历史保留；A± | **存在** R:188–192、391、406；原 auth+event.recorded_at；新动作与原事件回放按原时间；边界 OVERRIDE_INVALID/原状态；晚查询仍返回原事实；A± 动态 | **缺失** C:2040–2058→1281–1299；原 proposal/auth+新服务端 at；检查其他 grant/subject 而遗漏 override 时限；越界仍更新 registry；A± 动态 | **不一致** exact FIX C:2060–2065/replay 缺失，原坏 accepted_at 仍 ACCEPT；full bundle C:1675–1676 **存在**，原 FIX+receipt+auth 严格 interval，坏历史 REJECT；两端 A± 动态 | **存在，间接** C:1810→1754→1675；原 full bundle/原时点，不用 now 作旧 override deadline；C:1812 另检当前 QUERY；合法过期历史 A+；坏 bundle 的 guard 动态、把它接完整 completed 的组合未另测 | **依赖缺失路径** C:1237–1238、1704；原 replay terminal 的资格；未独立 full-bundle interval；非法 terminal 后发行的传播仅静态、动态 UNKNOWN；合法旧 terminal 后新 permit A+ | **存在，间接** C:1778→1754→1675 验原 terminal；C:1785 验当前 permit；旧 override 已到期但原 terminal 合法可首次收尾；A± 动态；不要求旧 override 现在仍有效 | 模型 R:711–715/744–745 晚查询原事实不变，A±；codec exact FIX 原坏时间重复回放仍缺失，full/completed 保留上述前置；当前 QUERY 与原动作时间分离；A+ 重复无写，first-use 重消费拒绝 |
| B：原 use/completion 实际引用的完整目标 == 由原 request/identity/continuity/op/source/terminal/pin 重建目标 | M §5.3/6，Q §5/8，I C-04/05/R-04/06；完整前像而非字段自洽；错关系拒绝，正确 post 纯读保留；B± | **存在于抽象表示** R:260–284、523–525；permit/source/receipt/session→原 APPLY 重建全记录相等，否则 COMPLETION_CONTENT_BINDING；静态，不称独立错wire动态；codec B± 证明表示差异 | **正确构造，但非独立接收验证** C:1793–1802；从先验证的 bundle.target→实际首次 APPLY/use/completion；共享同一 target；B+ consume 实测，不可向接收任意历史泛化 | **缺失** C:1473–1483 的局部历史 target 仅查 checkpoint/local generation 等；C:1772 独立顶层 target 正确却没接起来；原 APPLY 时点结构/source/use 合格仍收错 identity/continuity/op target；B± 动态。单独 terminal 阶段 N/A：use 尚未生成 | **缺失** C:1817–1825；查询原 permit、use、completion、post，但没有 actual-use target 与本次 correct-target 等式；B− IDEMPOTENT_SAME_POST；B+ 正常；use 中错误 result commitment 拒绝 | **存在于发行目标** C:1239–1242；原 request/terminal/policy/pin→发行 snapshot target；严格等于 finish_target，失配 permit issue target/checkpoints；合法发行 B+沿用，错误发行target未另测；将来 APPLY 引用关系此时 N/A：尚未发生 | **存在顶层检查** C:1772/1778 +1793；当前 local 对原请求的 bundle target 不符拒绝 full finish target differs（B±）；不能因此证明以后接收历史实际target也匹配 | **缺失同一连接** C:1809 每次重放既有历史，错target两次同成功且记录不变（B−）；正确完成后 permit过期查询成功/过期首次用拒绝（B+）；不是第二次业务 APPLY，也非现场伪造能力证明 |
| C：permit/issuance 声称主体 == 发行位置指定 session 的已准入真实主体，且与当前 use 分离 | M §2/5.1–5.2，Q §4–5，I A-02/C-04/R-04/06；发行原 prefix 的主体与scope；后来的当前资格不修过去；C± | **按构造一致/表示限制** R:248–257、333–359；permit嵌入session、从session派生发行principal并验证qualified；不具备wire独立principal矛盾维度；静态 UNKNOWN 对该wire反例，非缺少合同字段 | **正确构造** issue_permit C:1687–1706；从已准入 policy/session 派生body/snapshot→发行；合法 A→A/B→B C+；不是任意外来 issuance 的独立semantic oracle | **发行-history缺失** C:1766→1209–1251；原body==snapshot，但与原session实际主体未连接；三fixture及真实合成B claim+A session C− ACCEPT；纯原 terminal 此关系 N/A：permit 尚未存在 | **未完成发行责任，但另有use防线** C:1810→1766 缺失同上；C:1767→1471 校验原APPLY主体；合法完成 C+，不当作错发行可完成的证据；完成查询仍需原发行独立成立 | **直接缺失** C:1209、1211–1214、1236–1251；snapshot/body取声明，state取真实session/policy；各自校验但无连接；错发行C− ACCEPT；正确发行C+；GRANT额外绑定不替PERMIT | **存在** C:1784；原permit对当前authenticated policy/inventory/session/principal；错主体拒绝 first use original permit subject；合格B当前主体不能修原A发行；C±；C:1785到期拒绝，发行历史保留 | **历史/当前分开** C:1471 原APPLY主体，1812 当前QUERY，1779禁止completed输入再first-use；C+两次query不改原记录，C−主体冲突use回放拒绝（见C原始记录）；发行历史自身反复回放仍漏检，非后续防线可豁免 |

矩阵中的模型代码错误文字以实际模型为准；模型静态行没有冒充本轮额外模型动态探针。矩阵不声明未测 permutation 或原 B 全量 bytes/模型范围通过。

## 7. 为什么前两轮没发现：可证事实与推断

事实：
1. Rework01 codec C1:908 已对完整 terminal 比较 override 区间；C1:1595–1602 有相应 expired/future 输入。Rework01没有当前 return_completed / verify_issuance_at / verify_exact_fix_history / authority_action 这些函数定义，也没有当前 CompletionRecord / FinishTarget 对象表示（只读检索）。因此不能断言“两轮都是完全相同新入口漏洞没发现”。旧失败仍是旧失败。
2. RW02 A 相关默认 fixture 将 override 放在 STAMP+55..+5000，FIX/terminal 为 +60/+80；C:2213–2214 的 expiry 用 session.expires_at，而 C:2250–2257 缩短 grant。它们不能隔离“仅 override 到期、其他资格仍活”的动作边界。模型的 expired/future override author check R:1197–1201 在 propose_override，不等于后续 acceptance/terminal 边界。
3. RW02 C:1793–1802 用同一个正确 target 生产 use/completion；C:2297–2308 和 E/independent-codec-semantics-probe.py:231–235 先用这个 producer 生成完成记录再测试期限/缺use。该独立 probe:157、232 的 completion 预期来自同一已生成完成对象，不独立重建它实际引用的 target。
4. permit 正常 fixture/issue_permit 从 policy 派生 principal，原 session 存在/时间/scope 测试不等于对两个可独立变更主体字段的关系变异。模型嵌入session，不暴露wire的重复声明维度。独立语义核算 E/independent-codec-semantics-probe.py:130–132 的 issue_ok 也只验证 fin.subject 和 terminal，没有把 permit/snapshot 声称 principal 接回 session 实体；这是可定位的同一未检关联，不表示所有独立核算都同源。
5. 摘要/bytes 相等与完整前像DAG证明“对象是这些字节”，不自动证明“对象之间必须具备的语义关系正确”。原计数 125/383 与内部QA结果是有限证据，不是覆盖证明；本轮未为追求计数重新运行全量产品/模型/codec程序。
6. 正式 A/C 实际发现各自问题，B 实际找到反例后扩展运行中止、没有可用 stdout/退出码。不能称正式三方全部遗漏了这三个问题，也不能把 B 缺失输出补成失败或成功。

推断：有界检查多数基于正确构造 fixture，局部正例生成与consumer期望共享关联假设，加上责任拆分后的新入口没逐条映射外部负向语义，足以解释为何已有计数仍留下这三项。该解释有上面源码和输入证据支持，但作者的完整思考过程、所有未保存试验和原 B 中止扩展内容 **UNKNOWN**。没有声称找到唯一组织/心理原因。

建议先重新明确入口责任：哪些入口给新权、哪些入口证明原时点事实、哪些入口只返回原结果；把每项必需关系的独立来源与拒绝点对应起来。是否共享实现 helper 另行设计；共享漏检的 replay 已是 A/C 的传播方式，共享本身不是安全证明。

## 8. 原 B 与本轮相关路径补充核查

原 /root/rw02_reviewer_b 的完整 Review 继续 **NOT COMPLETED**，原报告逐字保留：
- 原负责范围包括完整模型、bytes/前像/DAG、来源与顺序、发行/历史/本地收尾等独立核算。
- 实际已完成：21+27快照hash、合法terminal/三类finish、相关局部代码/合同阅读、一条成功取得stdout的 RW02-B-01。原记录已说明未做全面审查。
- 未完成或无法确认：模型主体/有限轨迹全审、作者/QA全结果、手写全bytes/S2/RAW和全依赖图、同毫秒/来源/早发permit所有新控制、完整旧反例再跑。后续中止调用内容/结果不能推断。

本轮新 /root/diag_related_paths 未参与 RW02相应产物编写，按当前授权执行 **“Rework 02 相关路径补充核查”**：
重现原 B 成功探针；独立检查历史use实际目标与查询目标，完整 identity/continuity/op 控制；追踪相邻发行/首次/重复路径，并与 A/C 有界事实核对。新报告自身给出实际时间、命令、代码位置和未覆盖项。
这只补本轮相关路径，不冒充原 B、不倒填其完成状态；没有重试原未知中止扩展，没有开新正式 A/B/C，也没有额外文档 PASS Gate。

## 9. 未来最小工作与重新授权条件（不执行）

若用户另行授权修复，应将影响范围限定为三项关系涉及的冻结候选职责闭合；不默认允许改产品、DB、角色、Root 或扩大产品范围：
- A：新 FIX、新 terminal、独立原历史验证及依赖它们的发行入口，对同一原 override / 实际动作时间给出一致答案；拒绝不新增接受事实。保留原合法事实后来失效仍可读与当前首次用单独授权。
- B：从原request/source/terminal/pin重建正确目标，并证明历史use/completion实际引用的是该目标；不能只重复局部内部等式。保留正确 identity/continuity/op 和真实 post/result/Audit 的正例；错误者在有责任的历史接收入口拒绝。
- C：发行位置的body/snapshot声明与指定session的已准入主体/scope建立合同要求的连接；合法A→A、B→B保留，B声明+A会话拒绝，即便B当前合格也不能补正过去。首次用/完成查询不能重折叠成同一时点。
- 验收按矩阵逐入口提供独立正负期望：字段替换明确固定量和下游重绑定；边界时间隔离其他expiry；检查拒绝理由与不变状态；正常producer正确构造不能作唯一oracle。保留原失败快照，不回写历史。
- 如发现原format真正无法取回关系或需新trust/productscope，届时归B，停止请求新设计授权，不由现在预先批准。

在修复且另行独立审查完成前保持 Design BLOCKED。真实身份/认证来源、不可替换完整存储、实际 DB 权限与事务/时钟边界、crypto/签后提交/OS crash/故障恢复仍依赖正式实现与验收；本轮合成诊断不能替代。不能承诺下一轮必过，不启动 Rework03 / Revision2 / IBCS / Candidate Freeze / Signed Intent。

## 10. 实际执行、交付与保护

所有新 Python 仅现有 stdlib 解释器 -I -B -S，在 D 隔离 cwd 读取原 E；没有 monkey-patch、候选包装修复、前像/schema/guard/state-machine修改。合成来源假设沿用候选，未做真实签名/验签。三个探针命令/输出保存在 D；原成功脚本均 exit 0。A/B 最终落盘复跑 exit 0 见各报告；C 落盘最后复跑 2026-09-16 03:57:43–03:58:51 UTC exit 0，与所存 JSON 除实际时钟外逐项一致（执行者交接，Lead已读保存原结果）；C JSON 时间值含 -12:00 偏移，不因字段名含 utc 而当成零偏移。stdout / JSON 记录的保存形式在各报告说明：A 为换行归一文本；B 的 JSON 保留原子进程 stdout（含CRLF）及字节hash；C 的JSON保存原执行结果和输入。没有用旧结果冒充本轮输出，也没有把JSON容器数量算成测试通过数。

过程限制/错误不隐去：C 早期 stdout 探针对含 bytes 对象做 JSON hash 报 TypeError，仅诊断中未变比较改为 deepcopy equality，没有候选改动；原 A 附录B历史exit1不重跑。导出预检查曾暂停7件材料：宽松 token regex 把已知分支 ai/task-r1-canonical-implementation 内的 sk- 子串误判；只在同一白名单中精确核对7/7都是该公开分支，未输出可疑值、未导出当时待核材料、未改原件。后续 token 边界明确后重新全白名单检查；若有未分类疑似秘密则不生成ZIP。该有限扫描不声称证明任意编码秘密都不存在。

新包名：R1_RW02_VALIDATION_DIAGNOSIS_EVIDENCE_20260916T034034Z.zip（位于 D）。
D/README-evidence-package.md 说明相对目录、复现和来源；D/package-manifest.json 是显式白名单及逐件SHA256，D/package-export-result.json 给出实际ZIP长度/hash/成员校验结果（该外部结果不递归装进自身ZIP）。

包只含必要工程原文：完整RW02主文/manifest、模型/codec/catalog/shared合同、合成vectors/results、原A/C完整审查、原B完整保存片段和中止说明、disposition/final保护结果、相关原QA、必要RW01静态来源、Boundary/Invariants原文，以及本轮诊断/补充核查/实际stdout。没有整仓、用户附件/聊天、DB、私钥、凭据、custody或无关个人文件；仅检查明确白名单，不扫描现场秘密。manifest中未打包的继承材料只作为精确历史引用，不称本包是全项目复审环境。未声称接收方 Qingyu 或当前 ChatGPT 已读取本机文件；须用户自行上传ZIP。

收口保护详见 D/final-verification.json 与包外 export 结果：
原 Core HEAD 5d4133a71df69d6c7c51644cfb54b9e410e4ab11；
原9个dirty tracked、42981-byte diff，Git blob 9594b6b6f5374094a88bcb068d5bcd7afd875d18 保持；staged为空。
实现工作树 HEAD/branch/tag 不变，287项原件除 LRS末尾追加外无变，LRS原28494字节前缀不变。工作树仍dirty，不做Git写入或提交。
实际变更仅本报告、D中的诊断/证据包材料及LRS增量；没有访问Gateway/DB/Docker/网络/真实secret/现场Root或pin/ACL/身份；没有安装、产品测试、迁移或Acceptance。

本轮仅完成获准的诊断与证据整理，已 STOP。未进行第三次返工，未修改候选或产品实现，未解除任何 Design / Implementation 阻塞，未进入 Candidate Freeze、真实签名、迁移、数据库验收或 Foundation Closure。
