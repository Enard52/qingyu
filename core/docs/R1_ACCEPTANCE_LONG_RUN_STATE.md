# R1 Acceptance Closure Marathon — Long-Run State

RESUME TOKEN: `R1_ACCEPTANCE_CLOSURE_MARATHON`

- Status / 状态：BLOCKED / `SIMPLIFIED TRUST MODEL STILL UNSOUND`。Revision 6 三位独立 Reviewer 均 BLOCKED；按用户 Stop Rule 不创建 Revision 7。
- LAST COMPLETED PHASE：Phase 1 只读基线与 Phase 2 缺口分类；C01 Design Revision 3 已完成但独立 Review BLOCKED，不能计为闭合阶段。
- CURRENT PHASE：R1 Trust Model Simplification Gate / REVISION 6 REVIEW BLOCKED；Marathon Phase 3 尚未进入。
- CURRENT GATE：R1 Implementation Gate 尚未通过；F1/F2/F3/F4/F9、Root/public pin、Windows Identity 的既有冻结结论不重开。
- CURRENT BLOCKER：R1-MARATHON-C01 / OPEN。Revision 6 narrowed IBCS to a trusted monotonic anchor and removed Authority confirmation correctness, but Reviewer B found structural P1-E (receipt candidate timing impossible; Authority signs unvalidated Core semantics; no exact V2 schema/common tuple/IBCS Signed Intent pin lineage). Reviewer C found structural P1-F (no pre-PREPARE immutable authorized_decision; model does not prove CAS/business effect or lost append query). Reviewer A found P2 conflict in IBCS identity mismatch quarantine and activation-ticket model coverage. IMPLEMENTATION NOT STARTED; NO REVISION 7.
- Worktree：`<repo>\core-r1-implementation`。
- Branch：`ai/task-r1-canonical-implementation`。
- CURRENT COMMIT：`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`，本轮已重新读取；工作树保留前序未提交修改。
- CANDIDATE DIGEST：NOT FROZEN。旧 F3 SQL source digest `334f03a7d4ecbcf9bbfbf0052eb9c5e7d9182749589501a4c66913886db50912` 不是 Acceptance Candidate ID。
- LATEST TEST：前阶段有证据的 118 targeted PASS、485 full PASS / 4 legacy skipped，本轮未重跑。新纯结构 probe：COMMITTED opening ACCEPTED、ABORTED opening REJECTED（invalid genesis opening）。收尾 `git diff --check` exit 0；155 个此前 inventory 文件均未改变；报告限定秘密标记扫描 0 命中，不等同完整 checkpoint secret certification。
- 已完成：当前授权和团队 skill/references 阅读；完整 HEAD/status/diff/untracked/source inventory；与前序 F3 inventory 比较无已有文件变化；原 Core、public fingerprint、Registry64 public pin、两项 SCM 服务状态、受保护 probe deployment 的 226 项文件 digest 核验（0 mismatch）；三项并行只读分析；纯内存 GENESIS receipt shape 矛盾复现。
- 正在进行：无任务。Revision 6 model reported 77,824 states / 1,789,952 transitions / 100,000 seeded random checks PASS, but Reviewers showed it is not faithful evidence for ticket/CAS/lost-response properties. Final reports: `genesis-design-review-v6-a.md`, `-v6-b.md`, `-v6-c.md`; root-cause/fallback disposition: `revision6_unsound_disposition.md`.
- Worker assignment：Lead authored separate Revision 6 threat/ADR/operator/acceptance/model documents. Three new independent read-only Reviewers A/B/C assessed threat model, trust chain and decision gate. Product write Worker=0; maximum Reviewer concurrency=3.
- NEXT EXACT ACTION：STOP. Do not create Revision 7 or implement C01. A future user architecture decision must choose either (A) minimum fallback: exact Authority terminal + durable authorized decision/CAS + manual fail-closed restore/no automatic clone activation, deferring external witness; or (B) select and contract a mature external append-only/transparency/consensus-backed witness before a new separately authorized architecture phase. See `revision6_unsound_disposition.md`.
- 本轮报告：`docs/R1_ACCEPTANCE_CLOSURE_REPORT.md`；证据：`docs/evidence/r1-acceptance-marathon/`。
- STOP INTEGRITY：Revision 6 STOP 时重新核验 implementation HEAD `5d4133a71df69d6c7c51644cfb54b9e410e4ab11`、tracked diff object `bfe460243ee2fb499e54975e4b8bc999879bb53c` 与起始快照相同，`git diff --check` exit 0（仅 CRLF 警告）；原 Core HEAD 相同、精确 9 dirty tracked、固定 hash `9594b6b6f5374094a88bcb068d5bcd7afd875d18` PASS。本轮仅设计文档、非产品模型和审查证据变化，无产品代码、数据库或部署操作；无模型 `.pyc` 残留。
- C01 DESIGN：BLOCKED / SIMPLIFIED TRUST MODEL STILL UNSOUND（Rev6 A=P2 BLOCKED, B=P1-E OPEN, C=P1-F OPEN）；IMPLEMENTATION：NOT STARTED；P1-A/B/D and canonical first receipt direction PRESERVED but unimplemented；independent design Reviewer：BLOCKED。`R1-MARATHON-C01` remains OPEN; NO REVISION 7.

## Stop evidence / 停止依据

原 Core 只读合同 `docs/CONTROL_PLANE_R1_REMEDIATION_PLAN.md:259–287,299–306,347–353,385–393`：prepare 不占终态序列；GENESIS 也必须 PREPARED；FORCE_ABORT 覆盖 every operation type 并输出有序 ABORTED。
implementation `app/control_plane/r1_schema.py:222–228`：首次 continuity 产生之前持久化 GENESIS PREPARED。
implementation `app/control_plane/r1_protocol.py:395–409`：generation 1 / sequence 1 只接受 COMMITTED / ACTIVATED 的 GENESIS。
纯结构验证保留相同 opening envelope，仅把结果改为 ABORTED，返回 `invalid genesis opening`；未签名、未创建密钥、未访问数据库。

这不是撤回 F3 的冻结 PASS：F3 验收范围从已存在的 GENESIS / active lease 开始；首次 issuance / forced resolution 是本次新增必需范围。
未创建 Candidate、Signed Intent、acceptance DB、角色、volume、network、commit 或 tag。没有进入 Foundation Closure。

## Task DAG / 阶段依赖

Phase 0 状态 → 1 基线 → 2 缺口分类 → 3 必要发行流程 + 4 continuity 边界 +
5 只读 production inspector → 6 实现/独立审查/回归 → 7 Candidate Freeze →
8 Git checkpoint → 9 canonical artifact 核验 → 10 expected catalog →
11 签名 payload 独立审查 → 12 用户交互签名 → 13–14 全新 target/身份 →
15–19 migration/catalog/权限/runtime/crash/inspector 验收 → 20 独立最终审查 →
21 完整回归/候选一致性 → 22 evidence commit/tag → 23 Gate decision/STOP。

候选签名绑定的 migration/catalog/source 字节必须在冻结前准备好；后续验证/封装不能
偷偷改变 candidate-bound 内容。任何改变使旧 freeze/signature 失效，重新 freeze/review/sign。
这条依赖约束不提前允许 migration、签名、提交或创建 acceptance target。

## Permanent protections / 永久边界

- 原 `<repo>\core` 严格只读；期望 HEAD 如上，9 dirty tracked，diff object hash
  `9594b6b6f5374094a88bcb068d5bcd7afd875d18`，本轮已重新实测一致。
- 固定 public fingerprint `e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`；不读取/输出 Root 私钥、passphrase 或 production secret values。
- 不触碰 Gateway/legacy DB/container/volume/network；不复用已销毁的 F3 临时数据库作为 Acceptance。
- Windows Identity FROZEN PASS；仅实际影响范围回归，不重跑 7,146 项验收。
- 实现与 Review 分离；共享 dirty worktree 尚无安全并发写隔离，因此产品写入串行，阅读/设计/审查可并行。
- Root passphrase / UAC、P0/P1/P2、新的不可安全继续 blocker、legacy/秘密/原 Core 风险或平台限制时暂停并更新本文件。
- Foundation Closure / Memory Intelligence / Hermes / User Model / Relationship Model / Proactive Runtime 均不得进入。
