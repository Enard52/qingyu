# R1 F3 Production Coordinator Report

日期：2026-09-14。范围仅为本轮 F3；以下 PASS 不代表完整 R1 Implementation
Gate、正式 PostgreSQL Acceptance 或 Foundation Closure。

## 1. Overall

**R1 F3 COORDINATOR IMPLEMENTATION = PASS；F3 = CLOSED。**
独立 A/B/C 限定范围 PASS，无剩余 P0/P1/P2。实际 PostgreSQL/TLS 与完整回归已完成。
完整 R1 Implementation Gate 仍待后续独立授权的迁移/部署/验收，不在本轮宣布 PASS。

## 2. Coordinator implementation

仓库：`<repo>\core-r1-implementation`。
新增 `app/control_plane/r1_commands.py`、`r1_coordinator.py`、`r1_postgres_store.py`、
`r1_admission.py`、`r1_api.py`、`r1_server.py`、`r1_candidate_schema.py`、
`r1_f3_candidate.sql`；Core 新增 `app/r1_local_store.py`、`r1_service.py`、
`service_factory.py`。契约为 `CONTROL_PLANE_R1_COORDINATOR_CONTRACT.md`。
这不是 InMemory 包装器或运行时 fake。

## 3. Production canonical path

Web/CLI → `build_core_service` → `R1CoreConsumer` + durable local INTENT →
`AuthorityClient` pinned HTTPS → authenticated Authority API → `R1Coordinator`
→ `R1PostgresStore` → restricted SECURITY DEFINER procedures。
实际工厂→Core→TLS→API→协调器→PostgreSQL 集成测试已通过。

## 4. Shared InMemory status

仅用于既有 test/development 路径；本轮未修改 shared Authority/service/audit。
其历史 PASS 不作为 current-R1 的数据库原子性证明。

## 5. Legacy PostgreSQL adapter status

保持 forensic-only / disabled；未修改或复用为新协调器。4 个旧直连测试继续跳过，
不解释为 legacy DB PASS。

## 6. Current-R1 coordinator status

真实实现 mutation PREPARE/COMMIT/ABORT/query 和 durable reconciliation。
前提是已独立准入的 ACTIVE GENESIS、owner、continuity、runtime/session 和 lease。
GENESIS/lease 签发、owner takeover、恢复/强制解决 API 未实现，调用继续拒绝。

## 7. Final COMMIT predicate

在最终事务中重新核验原始 envelope/hash、operation/mutation/local_commit ID、
结果/audit hashes、授权原始 bytes、Authority 域/实例/generation、canonical identity/
GENESIS/owner、state/epoch/storage/control-plane generation、current lease/session、
recovery/admission、receipt key 与数据库当前时钟。PREPARE 不是永久 commit permit。

## 8. Lease fencing

精确匹配 lease ID、generation、runtime、session、storage、epoch、ACTIVE 状态和期限。
过期、替换、撤销、旧 holder 均拒绝；finalize 再检查，COMMIT deferred guard 再检查期限。
takeover 不会自动删除旧 PREPARED barrier，也不会把旧 intent 授予新 holder。

## 9. Epoch / state / generation fencing

epoch、state version、owner version、active storage、control-plane generation 及
Authority generation/status 漂移会 fence stale COMMIT。存在真实 PostgreSQL 锁竞争和
完整状态/ledger/head 前后对比，不以 SQLite 证明 PostgreSQL 并发。

## 10. Recovery / quarantine fencing

仅 recovery ACTIVE 且 admission OPEN 可进入决定。QUARANTINED、recovery PREPARED、
封闭 admission 均拒绝。测试中的 transition 是明确标注的 privileged fixture 注入，
不冒充已实现的 production recovery/restore ceremony。

## 11. Terminal lifecycle

仅 PREPARED → COMMITTED 或 ABORTED。SQL 冻结原请求、PrepareAck、授权及 terminal。
ABORTED 不转 COMMITTED。两个终态都发布一个预冻结 Core Audit；COMMIT 推进业务版本，
ABORT 仅推进 audit/Authority sequence，不推进业务版本。既有 wire v1 字段不被重解释。

## 12. Idempotent replay

相同 ID/请求返回原签名 bytes；terminal POST 还须相同授权 bytes。更换 payload、scope、
decision 或 transaction-evidence hash 拒绝。历史 GET/retry 不重新签名、不重复推进
state/audit/head。第二次正常 mutation 后重放第一项仍使用其原始保存 cursor。

## 13. Crash / retry reconciliation

网络前持久化 INTENT、operation/local-commit ID、请求决定与两份候选；terminal POST 前
持久化 Ack 和精确授权。异常只进入 RECONCILIATION_REQUIRED，不自动 ABORT。
覆盖 PREPARE 成功但 Ack 未保存、COMMIT 成功但响应丢失、ABORT 决定的重启保留、
连接中断、损坏/孤立终态，以及 sibling finalize 后迟到错误。
Reviewer A 的迟到错误 P2 已修复并独立关闭：仅经签名链和 Audit membership 证明的
终态可忽略迟到错误，不清除较新 pending barrier。

## 14. Atomicity strategy

PostgreSQL generation → continuity → operation → session/key 锁序。
proposal、签名前语义检查、独立验签、只接收 ID+signature 的 finalize、业务/audit/
terminal/global head 更新属于同一事务；proposal 绑定 transaction ID/backend PID。
未 finalize、错连接、签名失败、延期过期、finalize 后断连均不能留下部分决定。
Adapter 要求显式 SQL COMMIT 成功后才返回，修复了 closed context 跳过 COMMIT 的风险。

## 15. Concurrency evidence

并发覆盖：A/B prepare、16-way prepare/finalize、A PREPARED 后 B takeover 的双方提交、
stale/current holder race、commit 与 quarantine/recovery/epoch/state/storage/CP generation/
Authority sealed 的两种锁顺序。通过 Events 与 `pg_blocking_pids()` 观察真实等待关系。
同一个合法 terminal 最多发生一次，其余为同一历史 receipt 或明确拒绝。

## 16. PostgreSQL evidence

**TEST-ONLY ISOLATED；不是正式 Acceptance。** PostgreSQL 16.15，完整资源身份/镜像/
网络/角色/建库和销毁记录见 `evidence/r1-f3-coordinator/postgres-environment.md`。
新容器/volume/两个网络均以 `r1_f3_test_only_6c4192408f8f4aff9bb154cd9fee33be` 为前缀。
新 base DB 为 `r1_f3_test_6c4192408f8f4aff9bb154cd9fee33be`，`127.0.0.1:57372`，
system ID `7685449160524886054`。各测试使用独立新建并销毁的同前缀测试 DB。
SQL TLS 仅在该 disposable local profile 明确禁用；Authority HTTPS 实测 TLS1.3。
Core-local workflow 使用临时持久 SQLite 测试库；不据此声称 Core PostgreSQL 锁或权限已验收。
本轮真实 PostgreSQL 原子性证据针对 Authority coordinator/store。
最终测试后，本轮容器/volume/两个网络已精确核验并销毁，公开证据保留。

F3 candidate source digest：
`334f03a7d4ecbcf9bbfbf0052eb9c5e7d9182749589501a4c66913886db50912`。
旧 authored snapshot 仍为：
`c2176cd47c65f7143b38f651218bcf3cbe238da27c7f74ec8fff88171e4c9aef`。
候选 SQL 未偷偷写入正式 Alembic。测试 catalog 观察不是正式 schema Acceptance；
后续须将候选纳入受审查的签名迁移 artifact 与正式 fingerprint/权限验收。

## 17. Production integration / fail-closed

两个支持的 factory 重载 canonical machine public pin，和 public admission 比较。
缺失 signed origin/observations、pin 冲突、错误 runtime DB 身份、未准入本地状态均拒绝。
Core 没有 Authority DB、receipt signer 或 Root 私钥能力。配置齐全不代表准入。
真实 production inspector/secret custody/正式 migration admission 未完成时仍不能部署。
本地 store 为单 continuity；跨 continuity 全局 receipt gap 明确 fail closed，未实现链同步。

## 18. Reviewer A

最终 PASS；1 项 P2 已 CLOSED，无剩余 P0/P1/P2。
独立初始 pure 123 PASS；修复后 pure 42 PASS + actual PostgreSQL/TLS 10 PASS。
详见 `evidence/r1-f3-coordinator/reviewer-a.md`。

## 19. Reviewer B

PASS，无 P0/P1/P2；独立选择真实 PostgreSQL 41 PASS。
实际证明 restricted runtime 及 F3 fencing/atomicity；不声称完整未来
reader/operator/migrator/default-privilege Acceptance 权限矩阵通过。
详见 `evidence/r1-f3-coordinator/reviewer-b.md`。

## 20. Reviewer C

最终 PASS，无 P0/P1/P2。原 70 PASS/1 FAIL 被完整保留并诊断为 TLS 测试观测竞争 P3。
修正前 100/100 独立探针安全边界正确，其中 7 次服务端记录竞争。
只修测试同步，未修改生产 TLS、未删除安全断言。独立修正后 71 PASS，额外 80/80 PASS；
P3 CLOSED。详见 `evidence/r1-f3-coordinator/reviewer-c.md`。

## 21. Targeted tests

最终 F3 全专项：**118 passed / 2 warnings，43.56 秒**。
证据：`evidence/r1-f3-coordinator/postgres/final-targeted/`。
包含真实 PostgreSQL/TLS、durable Core、签名、并发、故障与全部新 consumer 用例。

## 22. Full suite result

本轮开始实测 **367 passed / 4 skipped**。
最终 **485 passed / 4 legacy skipped / 415 warnings，49.30 秒**。
证据：`evidence/r1-f3-coordinator/postgres/final-full/`。
`git diff --check`、compile/syntax、旧 schema snapshot 验证 PASS。
warnings 为已有/当前依赖 deprecation 提示，未为消除提示升级或重解析依赖。
前面的失败轮次未抹除：runtime-round-01 34/4、round-03 62/2 等用于保留修复证据。

## 23. F1/F2/F4/F9 regression

保持 CLOSED。独立于新路径的相关回归含 Root pin 单测共 122 PASS，最终完整套件再执行。
冻结 service/audit/shared Authority/protocol/root loader/正式 migration 等文件哈希保持。
F4 原 TLS 方法未改变；仅追加 commit/abort。TLS fixture 的 test-only 同步变更有独立复审。

## 24. Secret leakage scan

非 ignored 仓库源码/报告的 private PEM 实体标记扫描 0 findings。
报告工具不会输出 Docker Config.Env、DSN、测试密码、真实 private key/passphrase。
全部自动签名使用 synthetic 测试材料；未读取/哈希/复制 acceptance Root 私钥。
这不是对所有形式秘密的穷尽扫描，未扫描外部 custody；详细范围见 final integrity JSON。

## 25. Root/public/pin integrity

公共文件 SHA-256 与 Registry64 `PublicKeyId` 均保持：
`e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`。
PinVersion DWORD 1；Profile String `R1_ACCEPTANCE_TEST_ONLY`；TestOnly DWORD 1。
未重新创建 Root、安装/更换 pin、改变公钥或私钥 custody。

## 26. Windows Identity Gate

**FROZEN PASS**；没有重跑全部 7,146 项验收。新工厂调用既有未改 loader，执行了相关
public-pin/配置单测；未改变 protected deployment、服务身份或 ACL。

## 27. Legacy safety

本轮团队对 Gateway/legacy **零连接、零写入、零迁移、零资源修改**。
没有使用 `gateway-db-1`、`gateway_qingyu_postgres` 或 legacy network/volume/database。
只核验自己的测试目标，不以连接 legacy 来证明“未连接”。不替其他进程声明数据库无写入。

## 28. Original Core workspace hash

`<repo>\core` 保持只读；HEAD
`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`，9 个原 dirty tracked 文件不变；
tracked diff object hash 保持
`9594b6b6f5374094a88bcb068d5bcd7afd875d18`。
开始与最终 inventory 记录于 `evidence/r1-f3-coordinator/baseline/`、`final-integrity/`。

## 29. Git

**NO FINAL COMMIT**；未自动 stage/commit。implementation HEAD 仍为上项 SHA，分支仍为
`ai/task-r1-canonical-implementation`，工作树保留未提交修改。
previous changes 与 F3 的区别由逐文件 baseline/final SHA-256 inventory 给出，
不能把当前 `git diff --stat` 中全部旧 service/authority 变更归给 F3。
本轮改动既有入口为 config/main/cli/client，另有 TLS test-only 修正和状态文档；
主要协调器/本地 store/SQL/protocol commands/新测试为 F3 新增。

## 30. Signed Migration Intent

**NOT STARTED**。没有使用真实 Root 私钥签发最终 intent/completion/attestation。

## 31. PostgreSQL Acceptance

**NOT STARTED**。未创建 acceptance target，未执行正式 Alembic upgrade/downgrade。
新建并销毁的仅是本轮 F3 disposable 测试环境。

## 32. Foundation Closure

**NOT ENTERED**。不因 F3 PASS、测试通过或环境清理而宣布 Foundation Closure。

## 33. Next Step

**ALLOW SIGNED MIGRATION INTENT** 作为下一阶段；等待用户新授权后才能开始。
该阶段必须保留独立部署观察、canonical artifact/catalog/权限矩阵和真实验收条件，
不能把 synthetic fixture、source digest 或本轮测试库提升为真实历史/正式准入。
当前仍有限制：未实现 GENESIS/lease/owner/recovery 发行流程、跨 continuity 链同步和
production deployment inspectors；完整 R1 Gate 尚未通过。本轮现在 STOP。
