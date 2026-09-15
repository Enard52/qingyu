# R1 Core Invariant Remediation Report

日期：2026-09-14。最终：**BLOCKED / STOP；未提交，未推进下一阶段。**

## 1. Overall / 总体结论

BLOCKED。生产 R1 coordinator 未实现，依用户明确规则，不能把共享内存
Authority 的修复等同于当前生产 R1 的 F3 CLOSED。

独立审查发现的问题已完成一轮代码返工及 A/B 复审。最终完整测试
367 passed / 4 skipped；A/B/C 均在各自限定实现范围内 PASS，无剩余 P0/P1/P2。
这不消除生产 coordinator 缺失这一明确 OPEN 项。

| Finding | 最终限定范围状态 |
| --- | --- |
| F1 | CLOSED（当前 Core/shared），Reviewer A PASS |
| F2 | CLOSED（当前 Core/shared），Reviewer A PASS |
| F3 | shared 路径修复、B 有界 PASS；current-R1 coordinator 未实现 / OPEN |
| F4 | CLOSED，Reviewer C PASS |
| F9 | CLOSED（当前 Core），Reviewer B 返工后独立复审 PASS |

本报告只覆盖 F1/F2/F3/F4/F9。F5/F6/F7/F8 未处理；未自动进入其它阶段。

## 2. Git 基线与证据

- 工作树：`<repo>\core-r1-implementation`。
- 分支：`ai/task-r1-canonical-implementation`。
- HEAD：`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`。
- 工作树有此前未提交实现；本轮无提交，不能称为 clean 或发布认证。
- 开始前完整记录 status、diff、文件清单与源码哈希，时间为
  `2026-09-14T16:39:22.641045Z`，见
  [baseline/inventory.json](evidence/r1-core-invariants/baseline/inventory.json)。
- 测试初始基线：283 passed / 4 legacy skipped。

## 3. F1 — 隔离与 GENESIS 写资格

适用性：CURRENT，当前 Core/shared 路径真实存在，不是 ALREADY FIXED。
复现了 GENESIS 外部完成失败后仅 metadata 隔离、ControlPlaneState 仍 READY，
以及 metadata 隔离后租约、治理写入与 owner transfer 仍可通过。

修复方向：双投影隔离并清除租约；统一 fresh canonical write eligibility；
验证确切 GENESIS、完成 receipt、当前 Authority 与身份/版本/代际，
在准备与终态重新检查。外部已成功、本地收尾失败的同 ID 重试，必须核实既有
记录及审计/Authority 后才恢复写资格；无证明时继续隔离。

首轮 16 项服务失败复现后通过；另补 stale GENESIS identity-map 失败后修复。
Reviewer A 后续独立发现终态审计/receipt 缓存的 P1 与冻结 GENESIS 字段检查
不足的 P2。第一轮返工增加 fresh 全链校验、完整 receipt 绑定与持久 GENESIS
常量检查；新增失败回归转为通过。Reviewer A 重新读取最终源码、运行 76 项
定向测试及 7 个原失败探针，A1/A2 CLOSED；F1 当前实现 CLOSED / 有界 PASS。

## 4. F2 — 恢复对账

适用性：CURRENT。原实现接受 self-consistent local seq 1 对 manifest/Authority
seq 3；外部同步失败后本地已 ACTIVE，重试可能只凭 receipt 返回成功。

修复方向：绑定本地 audit sequence/hash、hash-bound state version、canonical
identity、epoch、owner、storage/control-plane generation 与 manifest/Authority。
先持久化 PREPARED/隔离的同一 rebase，再对齐外部 checkpoint，最后才发布本地
READY/ACTIVE。失败重试复核真实状态，不能重新生成另一个 rebase。

已包含同步前失败、同步后丢响应、Authority 完成后本地事务失败、旧 restore
receipt 重放等隔离测试。返工后在外部完成后 fresh 重载并完整复核恢复记录及
审计行；Reviewer A 独立复测原失败和合法恢复/新 owner/历史请求时序，均符合
不变量。F2 当前实现 CLOSED / 有界 PASS。

## 5. F3 — 最终租约 fencing

| 路径 | 适用性及结论 |
| --- | --- |
| Shared Core 的 InMemoryControlPlane | CURRENT；原 A prepare → B takeover → A commit 被接受，先失败复现后修复；独立 Reviewer B 已验证限定范围 fencing |
| Legacy PostgreSQL adapter | disabled / forensic-only；没有执行或修改，不能报告其数据库行为 PASS |
| Current production R1 canonical coordinator | NOT IMPLEMENTED / OPEN；没有可验收的生产最终 COMMIT 路径，不能假装 CLOSED |

共享实现现在在同一 Authority 锁内重新核验 immutable intent/payload/local commit
ID、租约 ID/generation/expiration、epoch、storage、state version、GENESIS 与
recovery。拒绝路径不推进版本/审计；已 COMMITTED 的同内容重放只返回既有历史。

35 项新增 fencing 测试；Reviewer B 另做锁前状态变化的五类探针和
25 轮 × 16 并发相同提交，均只推进一次。详见独立报告。

边界：共享旧接口仍有既存 ABORTED 同上下文重新 prepare 行为，不是 R1 signed
terminal lifecycle 实现。本轮未扩展改写其生命周期，也未把共享接口认证为
生产 R1 coordinator。F3 总体仍 OPEN。

## 6. F4 — 先验证 TLS/SPKI，再发送凭据

适用性：CURRENT → **CLOSED；Reviewer C PASS，无 P0/P1/P2**。

旧版 response 后检查 SPKI；真实 loopback 重现错误 SPKI、有效 CA/hostname
时已泄露 306 字节 HTTP 数据（只含明确的测试 token/body）。

最小 transport 使用标准库 HTTPSConnection 的实际 connect 门：TLS 1.3、CA、
hostname、SPKI 全部成功后，才读取 bearer credential 并发送 HTTP；自动重开
连接也必须经过同一检查。无环境代理、重定向跟随、明文降级或未验证复用。

| 独立真实 TLS 情况 | 服务端 HTTP 字节 | Authorization / body | 凭据提供器调用 |
| --- | ---: | --- | ---: |
| 正确 CA / hostname / SPKI | 263 | 允许收到 / 收到 | 1 |
| 正确 CA / hostname，错误 SPKI | 0 | 未收到 / 未收到 | 0 |
| 错误 CA | 0 | 未收到 / 未收到 | 0 |
| 错误 hostname | 0 | 未收到 / 未收到 | 0 |

Reviewer C 独立运行 32 项 client/TLS/protocol 测试，另做 4 个真实连接探针，
包括同一连接对象重开换证、隐式建连和错误信息脱敏。

## 7. F9 — 不可变历史 receipt

适用性：CURRENT。原版 m1 retry 的 seq 属于 m1，hash 却取 metadata 当前 m2
head，已先复现。修复按 receipt.audit_seq 精确读取 hash-bound audit row，
与原 Authority terminal permit 的 mutation、版本、local commit、audit reference
绑定，不能拼接当前全局 head。

已验证 m1 首次、m2 前重试、m2 后、m3 后的完整结果一致。Reviewer B 另外观察
重试零 INSERT/UPDATE/DELETE/REPLACE，且 Authority 状态不变；22 类矛盾/缺失
绑定均拒绝。其后独立发现首次 terminal publication 使用缓存中的 MutationReceipt
的 P1，已通过第一轮返工修复：首次终态与历史重放共用 fresh 锁定 receipt +
audit + Authority permit 完整校验。Reviewer B 对最终源码独立运行 76 项测试及
44 个逐字段/删除检查，均正确拒绝矛盾状态，外部已 COMMITTED 的真实决定未
被篡改成 ABORTED。原 P1 CLOSED；F9 当前实现 CLOSED / 有界 PASS。

## 8. 共享不变量与状态权威

见 [Core Invariant Contract](CONTROL_PLANE_R1_CORE_INVARIANT_CONTRACT.md)。
metadata、ControlPlaneState、GENESIS attempt 与 local receipt 是需要共同核验的
本地持久投影，任何一个 READY 位都不能单独授予治理权威。当前 Authority 提供
独立状态检查；真实生产的独立持久性尚未实现，不由内存 fixture 证明。

隔离原子更新两个本地投影并清租约；恢复用 PREPARED → checkpoint 对账 →
终态发布，crash 后依原 ID、原 audit row 和 fresh Authority 重新验证，不能
从 Core state 补造 Authority history。终态审计与 receipt 必须读取实际持久值，
不能把 SQLAlchemy identity-map 缓存当作最新事实。

## 9. 故障注入与独立 Review

- GENESIS：外部未完成、外部成功/本地收尾失败、同 ID retry、双投影隔离。
- RESTORE：本地落后、版本/身份不符、sync 前后失败、本地终态失败、历史请求。
- LEASE：到期、接管、旧 epoch、state version/代际变化、prepare 后隔离、quorum。
- RECEIPT：m1/m2/m3 历史稳定性、行绑定矛盾/缺失、终态跨会话修改。
- TLS：正确连接允许；错误 pin/CA/hostname 与重开连接零 HTTP 泄露。

实现与 Reviewer 完全分离，最多 3 个并行 Worker（运行时共 4 槽含 Lead）。
Worker：state、fencing、TLS；独立 Reviewer：A（F1/F2）、B（F3/F9）、C（F4）。
按 ai-dev-team 质量门，A/B 的发现返给原 Worker 完成 1 轮返工，保留原失败证据。
A/B/C 最终有界 PASS，无各自审查范围内 P0/P1/P2；F3 current-R1 缺失不是
共享 patch 的审查 PASS 所能替代的生产证明。

Reviewer A 最终消息返回被平台拦截，但其最终复审已经执行并写入独立报告。
Lead 随后核对报告的最终 verdict、76 项结果、7 个独立原失败探针、恢复时序
及准确源码哈希，确认有已完成的落盘审查证据；没有从 Lead 测试臆推 A PASS。

## 10. 完整测试

首轮冻结候选为 356 passed / 4 skipped / 302 warnings，后被独立发现的问题
降为历史证据。第一轮返工冻结后，Lead 重新运行完整 suite：
**367 passed / 4 skipped / 413 warnings，7.97 秒，exit 0**。
新增 84 项：35 service、35 fencing、14 TLS；未安装或升级依赖。
定向 service/fencing/foundation 共 76 passed。实际 DB 行为仍未验收。

## 11. 跳过项

4 项 `tests/test_control_plane_postgres.py`，原因是 legacy direct-DB acceptance
forensic-only，且本轮禁止连接真实数据库。**这些 skip 不等于 DB PASS。**

## 12. Diff / 语法

返工后重新运行 `git diff --check` 与 app/tests/tools compileall，均 exit 0。
既有 datetime/Alembic 配置 deprecation 没有扩大范围修复。

## 13. 秘密扫描

对新增/修改 remediation 源码和证据做 PEM private-key、含密码 PostgreSQL URI、
literal secret 检查；唯一新源码命中为公开的 synthetic TLS TEST_TOKEN。
未读取真实 Root 私钥或 passphrase，也未将实际秘密写入 Git/报告/日志。
临时测试 CA/证书不是 acceptance Root。

## 14. Root / public / pin 完整性

只读核验 public 文件 SHA-256 与 PublicKeyId 仍为：
`e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`。
Registry64 的 PinVersion DWORD 1、Profile R1_ACCEPTANCE_TEST_ONLY、TestOnly
DWORD 1、PublicKeyId STRING 均未改变。无 ACL、custody、Root、pin 或部署修改。

## 15. Legacy Gateway

无 Docker 操作、无 Gateway/legacy DB 连接或写入、无 volume/role/container 操作。
没有将 legacy 环境用于本轮测试或模拟生产证据。

## 16. 原 Core 工作区

`<repo>\core` HEAD 保持
`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`，9 个 tracked dirty 产品文件保留。
只读、按原生字节计算的 tracked diff object hash 仍为：
`9594b6b6f5374094a88bcb068d5bcd7afd875d18`。
无 checkout/reset/stash/merge/覆盖。

## 17. Signed Migration Intent

NOT STARTED。未签发最终 intent。候选 Authority 源码属于 migration artifact
dependency closure，其修复改变候选摘要；未通过改写 migration/snapshot 保留旧
摘要。未来签署必须绑定另行批准的最终候选，而非修复前源码。

## 18. PostgreSQL Acceptance

NOT STARTED。无 provisioning、真实权限验收、Alembic CLI 或 migration。
source-only snapshot 验证不等于 live schema/catalog 证明。

## 19. Windows Identity & Trust Boundary

**FROZEN PASS 保留**，遵循用户最新补充，不重新进入该 Gate。
原 7,146 checks / 0 failure、283 passed / 4 legacy skipped 及独立 Reviewer PASS
仍是此前受保护部署的冻结证据。该部署本轮未更新；不把源码候选伪称为已部署。
仅做源码摘要、pin loader、protocol 等影响范围回归，未重跑完整身份验收。

## 20. Foundation Closure

NOT ENTERED。Remediation 与 Implementation Gate 均不是 Foundation Closure。

## 21. 本轮 Git / diff 分类

无 commit；HEAD 未推进，工作树仍 dirty，implementation tracked dirty 共 11 项
（8 项此前已有，加本轮原先 clean 的 audit/Authority/services）。

与开始时每个文件的 SHA-256 比较，本轮实际修改的既有路径仅：

- `app/services.py`：统一资格、GENESIS/restore reconciliation、receipt。
- `app/audit.py`：第一轮审查返工新增共享 fresh 全链/行绑定检查。
- `app/control_plane/authority.py`：shared fencing 与配套恢复检查。
- `app/control_plane/r1_client.py`：发送前 TLS/SPKI 门。
- `tests/test_r1_client.py`：transport seam 兼容，保留协议检查。
- `docs/CONTROL_PLANE_R1_IMPLEMENTATION_STATE.md`：阶段状态。

新增：三组 regression、Core Invariant Contract/Report、完整 evidence 目录及
`tools/capture_invariant_baseline.ps1`。既有源文件没有删除。最终四个产品源码
SHA-256 及完整 diff 分类见 Lead evidence；报告和证据不混充产品代码变更。

此前 trust/bootstrap、migration/schema、Windows identity 文件仍属先前未提交
实现，不混称为本次新增；模型、依赖声明和 migration 不因本轮被重新设计。

## 22. 下一步 / STOP

**本轮已经 STOP；不提交、不推进 Gate。** 剩余明确阻塞是 F3 current-R1
coordinator 未实现。其实现/验收需要新的范围授权；本轮不擅自扩展开发。

内存/SQLite/loopback 证据不是部署后 PostgreSQL 的锁、权限、持久性或性能验收。
保护部署保持先前版本；未来候选部署或签署必须使用其实际最终源码摘要。

只有 F1/F2/F3/F4/F9 全部 CLOSED 且 Reviewer 无 P0/P1/P2，下一阶段才是
**Signed Migration Intent**，不是 Windows Runtime Identity Gate。

最终完整验证记录见 [Lead evidence](evidence/r1-core-invariants/lead-verification.md)；
独立报告：[A](evidence/r1-core-invariants/reviewer-a.md)、
[B](evidence/r1-core-invariants/reviewer-b.md)、
[C](evidence/r1-core-invariants/reviewer-c.md)。
