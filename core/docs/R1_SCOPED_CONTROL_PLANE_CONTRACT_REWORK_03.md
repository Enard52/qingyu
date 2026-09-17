# R1 Scoped Control Plane Contract — Rework 03
Task: R1_SCOPED_CONTRACT_TARGETED_REWORK_03. Resume Token: R1_ACCEPTANCE_CLOSURE_MARATHON.

## 1. 继承与边界
本轮是在 RW02 已失败候选上的第三次、显式获准局部返工；不是改名重新开始。完整继承 docs/R1_SCOPED_CONTROL_PLANE_CONTRACT_REWORK_02.md 及其 qualification-history-contract.md、既有恢复模型和全部 23 项 accepted invariant。三项修复的唯一责任矩阵为 docs/R1_RW02_VALIDATION_DIAGNOSIS.md §6；本文件只作实际修改/测试映射，不另建职责体系。
旧 RW02 / Diagnosis 原件均不改；旧失败、六类历史 Findings 与旧 B NOT COMPLETED 不倒填。四项产品范围裁决及 Root/receipt-key/TLS-SPKI 角色、rotation 延期、ordinary/restore 隔离和信任前提不变。
本候选仅为设计参考：产品 Implementation Gate BLOCKED；Foundation NOT ENTERED；C01 DEFERRED / REMOVED FROM R1 REQUIRED SCOPE。固定本次评审快照不是产品 Candidate Freeze。

## 2. 三项已接受关系的落实
A：verify_execution_at 在已绑定原事件、snapshot、输出后，分别对原 FIX accepted_at 和 terminal decided_at 检查 issued_at <= action_time < expires_at。authority_action 的临时副本通过回放后才发布；exact FIX / 独立 Authority replay / terminal bundle / 后续发行均保留其责任。纯历史不使用查询 wall clock，不把后来过期倒推为原历史无效。
B：replay_core 的 APPLY 接收边界调用单向 Authority replay，_verified_permit_target 从其验证后的原 permit/issuance事件、原 policy、request/source、terminal/Audit/pin 重建完整 target，并接到 use/snapshot/completion。finish_history 与 return_completed 将查询对象接回原完成证明。内部 helper 不接收“调用者正确target”，不以当前 QUERY policy 替代原 policy。Authority replay 不调用 Core replay。
C：verify_issuance_at 先 subject_from/check_subject 验证发行位置 prefix 中的 policy/session/enrollment/inventory，再把 body（已与 snapshot 相等）的 runtime_principal 接回实际 enrollment 主体。GRANT 原有约束保留，PERMIT 补齐漏检；不以消费方修补历史，不新增委托。
本轮新增的独立期望来自已有合同与原记录，不以 candidate helper 作唯一 oracle。

### 修改/测试定位（不是第二套职责矩阵）
- A：旧 verify_execution_at:1253 → 新 :1257，区间检查 :1295、:1307；authority_action:2093 与 verify_exact_fix_history:2113 沿用。targeted 的 A.* 覆盖 FIX-only 三边界、合法 FIX/到期 terminal、独立历史与后续入口。
- B：_verified_permit_target:1315、replay_core:1418 / APPLY :1514、finish_history:1794、return_completed:1857。targeted 的 B.* 逐项替换 12 个关系字段、原 B 反例、完整 identity / continuity 前像、全部下游摘要重绑及新的合法 QUERY policy/session。
- C：verify_issuance_at:1205 / :1218。targeted 的 C.* 覆盖 ordinary_finish / finish / lag_finish，实际准入 A/B 配对、错误历史不得由当前 B 补正、首次使用与完成历史的阶段区别。
三族各入口、输入固定量、实际拒绝理由、下游摘要、状态不变值完整保存在 targeted-results.json；短解释为 targeted-regression.md。未修改上述矩阵本身。

## 3. 格式与证据
现有 wire schema、nested/nonwire schema、domain、version、C2/H2/S2/RAW 规则不变；continuity 仍位于完整 identity 前像，不新增 FinishTarget 字段。合法对象及摘要保持不变；派生 metadata/检查拒绝理由变化须在作者与 QA 记录中逐项解释。
本轮目录 N：docs/evidence/r1-acceptance-marathon/scoped-contract-rework-03-20260916T043240Z。
原目录 E：docs/evidence/r1-acceptance-marathon/scoped-contract-rework-02-20260915T184222Z。
N/candidate-manifest.json 按实际 bytes/SHA256 绑定本主文、新参考 codec/catalog/vectors/results、测试/QA与作者执行证据，以及明确继承的未变来源；不改旧 manifest。未变模型从 E 执行，没有另造模型。

实际编制与内部回归已完成（不同类别不得相加）：
- codec 实际 --test 与最终 --check 均 exit 0；383 个继承检查（131 ACCEPT / 252 REJECT），3 个派生产物逐字节匹配。详见 codec-run-log.md / codec-author-change-note.md。
- 定点测试最终 old/new 各 164 条入口观察（A 41 / B 70 / C 53）；旧 65 条合同违例复现，新 0 违例、failures=[]。这不是 164 个产品测试或独立漏洞；旧 passed 只指旧行为复现。含合法新 QUERY-only policy/session、旧 session 撤销/permit 过期、重复读取不变以及 FIX-only 边界。
- 非作者 internal-independent-qa.py 最终 --part all 实际 exit 0，model/bytes/semantics/trajectories 四项全符合；新独立语义 111 条均匹配，独立方程取原发行 prefix，不以目标/helper 自证。
- 继承有限模型本次实际运行与原 model-results.json 完全一致（125 named checks），另有独立模型 45 项有限控制；普通恢复/restore 隔离和三 FIX 持久点保留。
- 独立完整字节/前像核算：36 typed domains、112 typed values、421 nonwire、309 RAW；702 节点/2441 边、0 缺失前像。15 registry / 8 场景及另外 6 个合法 terminal/completed 事件世界无环；静态调用图 Core→Authority 单向，Authority 不到 Core。
- 继承独立时序/来源控制实际重跑 62 项；原旧 oracle 的主体/目标关联盲区没有冒充已修，其缺口由本轮独立语义方程补充。qa-results.json 与 internal-independent-qa-report.md 保存精确改编源码/hash/子进程输出和限制。
- 规范表/信任前提/所有合法向量分组逐项相等；整个 vectors 文件唯一变化是任务标签 02→03。catalog 加入本轮落实定位，results 更新来源元数据。没有为匹配旧结果更改输入。

作者与测试的进程运行记录均在本轮保存。作者一次大 stdout 捕获被工具截断后没有从部分数据落盘；通过真实生成 hash、分块读取完整材料和最终全量 --check 恢复导出。既有 --serve 名称实际仅 stdio，不涉及网络。QA 报告内存组装的一次 JS 引号错误没有修改候选/文件，也不是测试失败；记录保留。


## 4. 判定边界
本次完整候选编制与内部回归完成；接下来只进行一次新 A/B/C 独立设计复审，三者核验同一 manifest。新 B 必须覆盖旧 B 未完成但本轮必需的模型、完整字节/前像/依赖、来源历史与资格时序范围；原 B 状态不变。
任何本轮实质 P0/P1/P2/OPEN/PARTIAL 则保留证据 STOP，禁止修候选后再审。只有三方完整通过才可宣布本轮 scoped Design Gate PASS；不解除产品 Gate。正式结论保存在本轮 disposition.md，不能由作者记录替代。
合成字节及假定签名、有限模型，不证明真实 crypto、DB/OS 原子性、并发/崩溃、部署 provenance 或 live admission；这些仍须后续单独授权实现与真实验收。本轮不访问这些系统。

## 5. 保护基线
只允许新候选/本轮 evidence 与 LONG_RUN_STATE 末尾增量。intake-baseline.json 保护 305 件既有材料及 LRS 32082-byte 前缀；最终核验另存 final-verification.json。
HEAD e490134ba9ced81be182b4c24eb41c970258f325 / branch ai/task-r1-canonical-implementation / tag r1/pre-minimal-trust-pivot-e490134 保持；原 Core 9 个 dirty tracked 文件完整 diff object 必须保持 9594b6b6f5374094a88bcb068d5bcd7afd875d18。工作树允许 dirty，不声明 Git clean，不提交。
禁止并未执行产品/现有测试修改、迁移、签名、部署、DB/Docker/Gateway/网络/秘密或现场 Root/pin/ACL/身份访问、依赖安装或 Git 状态写入。没有重做 Boundary/Invariants/Windows Identity Gate。

