# R1 Windows Identity & Trust Boundary Report

验收日期：2026-09-14 UTC。仅覆盖本轮明确授权的 Windows 身份、ACL 修正、受保护部署与真实进程验收。

## 1. Status / 状态

**R1 Windows Identity & Trust Boundary = PASS。**
**Control Plane R1 Implementation Gate 仍为 BLOCKED**，未将本轮结果视为数据库或 Foundation Closure 验收。

## 2. ACL Change Authorization Used / 实际使用的 ACL 授权

实际修改以下 4 个文件系统对象及 5 个 Registry64 对象：

- `C:\ProgramData\Qingyu`
- `C:\ProgramData\Qingyu\ControlPlane`
- `C:\ProgramData\Qingyu\ControlPlane\R1`
- `C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub`
- `HKLM\SOFTWARE\Qingyu`
- `HKLM\SOFTWARE\Qingyu\ControlPlane`
- `HKLM\SOFTWARE\Qingyu\ControlPlane\R1`
- `HKLM\SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot`
- `HKLM\SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly`

每个对象仅增加 Runtime 与 Migrator 各一条明确 SID 的只读 ACE，共 **18 条**。
公钥文件为 Read，必要目录为不继承的 ReadAndExecute，注册表为不继承的 ReadKey。
没有新增 Everyone、Users、Authenticated Users 或 ALL SERVICES 授权。
逐条二进制 ACE 对比确认原 ACE、owner、group 和 DACL_PROTECTED 保持；Windows 写回 ACL 时额外设置了 AUTO_INHERITED 元数据位，已在证据中明确记录。
未改变 public bytes、Root identity 或 pin 名称、类型、值。Registry32 未修改。

调整前后证据：`C:\ProgramData\QingyuR1IdentityEvidence\acl-before.json`、`acl-after.json`；独立差异核验见封存目录 `state-audit.json`。

## 3–5. Operator / Runtime / Migrator identities / 三类身份

| 用途 | Windows 身份 | 完整 SID |
| --- | --- | --- |
| Operator / 操作员 | `<HOST>\<operator>` | `<operator-SID>` |
| Runtime / 运行服务 | `NT SERVICE\QingyuControlPlaneR1Acceptance` | `S-1-5-80-521220990-1857042447-2197016169-2159567703-611382270` |
| Migrator / 迁移验证作业 | `NT SERVICE\QingyuControlPlaneR1AcceptanceMigrator` | `S-1-5-80-3253374542-705302118-4188924831-1122857046-3825746319` |

两个服务是独立的 Windows SCM 虚拟账户，不需要长期人工密码。服务类型 WIN32_OWN_PROCESS，DEMAND_START；验收后均为 Stopped。
实际服务 token：Primary token、elevated=false、无 Administrators 组；仅有 `SeChangeNotifyPrivilege`，未持有任何被检查的危险特权，即使以 disabled 状态也不存在。
完整性级别实际为 High（`S-1-16-12288`），如实记录；服务 token 的 High 标签没有被当作管理员身份，SID、组、特权和实际访问结果分别验证。
组中包含系统默认 Users、SERVICE、Authenticated Users、ALL SERVICES 等；未向这些宽泛组新增信任材料权限。

最终采集中，Runtime 宿主 PID 及 Python 子 PID、Migrator 宿主 PID 及 Python 子 PID，均通过独立 CIM 观察取得账户 SID、父子关系、启动命令和受保护可执行路径，与各自 probe 报告严格关联。准确数值见 `observed-processes.json`。
操作员能够申请私钥文件的读取、写入、删除和 ACL 修改权限；本轮仅打开并关闭句柄，没有读取私钥字节或执行解密/签署。

## 6–8. Public / HKLM / Private ACL / 公钥、pin 与私钥权限

正式 loader 在两个服务身份下均读取成功，结果：

- SHA-256 / PublicKeyId：`e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`
- PinVersion：DWORD `1`
- Profile：字符串 `R1_ACCEPTANCE_TEST_ONLY`
- TestOnly：DWORD `1`
- Registry64 为 canonical；Registry32 的 Qingyu pin 树缺失，返回错误码 2，符合合同。未将缺失误记为拒绝访问。
- 现有 `HKLM\SOFTWARE` 父键在两个视图都检查了修改能力，服务不能创建冲突树。

私钥仍位于 `C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly\operator-root-encrypted.pem`。
私钥和 custody 目录 ACL 未修改，仍仅允许操作员、Administrators、SYSTEM。
两个服务申请私钥 read/write/append/delete/WRITE_DAC/WRITE_OWNER，以及 custody 列目录权限，均返回 **Windows ERROR_ACCESS_DENIED (5)**。
没有读取、哈希、复制、解密或输出私钥内容，也没有接收 passphrase。

## 9. Acceptance Deployment Path / 受保护部署

`C:\Program Files\Qingyu\ControlPlane\R1\Acceptance`

独立于开发 worktree；开发目录权限保持原样。
部署包含最小 SCM 宿主、Python 3.12.10 embedded、精确依赖副本、正式 trust loader、原生 ACL 模块、验证代码和探针。
这是 test-only 身份验收启动器，不代表 R1 Authority API 或完整迁移执行器已经实现。
所有文件及目录由 Administrators 管理；SYSTEM/Administrators 可写，指定服务仅 Read/Execute。
Reviewer 逐个检查了 282 个部署对象（包括目录和空目录），未发现服务可写项或重解析路径。

## 10. Deployment Manifest / 清单及摘要

最终部署清单：`C:\Program Files\Qingyu\ControlPlane\R1\Acceptance\manifest.json`。
清单包括 **226 个文件**的完整 POSIX-relative path 与 SHA-256，清单自身另行取摘要。

Manifest SHA-256：
`9b18d33d4eef0928ea6e123ac9f29f53849173f9e1b3bb8fbdf030dac1aef4ac`

封存目录：
`C:\ProgramData\QingyuR1IdentityEvidence\sealed-20260914T1626156607097Z`

启动前和结束后均核验完整文件集与每个摘要；Reviewer 独立重新计算 226 个文件并确认一致。部署应用/探针也逐文件与 implementation source 对比通过。
CPython archive 已核对冻结 SHA-256 `156c7eea90d58cd7e91a23f28a0056616b13e9f4cf4901b7b99b837b7848c6da`。
依赖复用既有精确材料：cryptography 50.0.1、cffi 2.1.1、pycparser 3.0、rfc8785 0.1.4；没有安装、升级或重新解析依赖，没有污染系统 Python。
此 manifest 是本地受保护的部署清单，不是 Operator Root 签名或最终 migration artifact 授权。

## 11–14. Real Process Tests / 真实进程正向与负向测试

Runtime：正式 pin loader、公钥读取、双 registry view 行为、部署 manifest、隔离 Python/module 路径均通过。
Migrator：相同读验证通过，并用 RFC 8032 非 canonical 公开测试向量成功验签、拒绝篡改消息；没有签署最终 intent。
两个服务的公钥覆盖、追加、删除、重命名/替换所需权限，以及父目录创建替换、delete-child、ACL/owner 修改权限全部拒绝。
pin 的 SET_VALUE（覆盖四字段、增加冲突值、删除值）、CREATE_SUB_KEY、DELETE、WRITE_DAC、WRITE_OWNER 全部拒绝。
部署 loader、Python、依赖、manifest 及父目录写入/删除/替换/ACL/owner 权限全部拒绝。
两个服务均不能打开 canonical 私钥，因而不能以该 Root 签署；能够运行通用公开验签代码不被解释为拥有 canonical 签署权。

所有负向探测都对**现有真实对象申请相应操作权限后立即关闭句柄**。
没有真的覆盖、删除、重命名或修改 ACL；错误码 5 才计为拒绝，错误码 2/3 等不冒充权限拒绝。
重命名/替换同时核验对象 DELETE 和父目录 delete-child/create 权限。

## 15. Effective Access Matrix / 实际有效权限矩阵

“允许”表示实际句柄申请成功；“拒绝”表示错误码 5。操作员的写/删除/ACL 也只申请权限，不执行操作。

| 资源 / 操作 | Operator / 操作员 | Runtime / 运行服务 | Migrator / 迁移验证 |
| --- | --- | --- | --- |
| Private Root：读取 | 允许 | 拒绝 | 拒绝 |
| Private Root：写入 | 允许 | 拒绝 | 拒绝 |
| Private Root：删除 | 允许 | 拒绝 | 拒绝 |
| Private Root：修改 ACL | 允许 | 拒绝 | 拒绝 |
| Canonical Public：读取 | 允许 | 允许 | 允许 |
| Canonical Public：写入 | 允许 | 拒绝 | 拒绝 |
| Canonical Public：删除 | 允许 | 拒绝 | 拒绝 |
| Canonical Public：修改 ACL | 允许 | 拒绝 | 拒绝 |
| Canonical HKLM pin：读取 | 允许 | 允许 | 允许 |
| Canonical HKLM pin：写入 | 允许 | 拒绝 | 拒绝 |
| Canonical HKLM pin：删除 | 允许 | 拒绝 | 拒绝 |
| Canonical HKLM pin：修改 ACL | 允许 | 拒绝 | 拒绝 |
| Deployment：读取/执行 | 允许 | 允许 | 允许 |
| Deployment：修改 | 允许 | 拒绝 | 拒绝 |
| Deployment：替换 | 允许 | 拒绝 | 拒绝 |
| Deployment：删除 | 允许 | 拒绝 | 拒绝 |
| Deployment：修改 ACL | 允许 | 拒绝 | 拒绝 |

总计 **7,146 项证据断言，0 失败**。每个身份报告覆盖 229 个文件、45 个目录、12 个注册表位置和 2 个服务对象。
该计数是证据断言数，不是 PostgreSQL 测试数。

## 16. Privilege Escalation Review / 提权路径审查

两个服务无 Administrators membership，无 SeTakeOwnership、SeRestore、SeBackup、SeDebug、SeImpersonate 等危险特权。
两个服务均无 service CHANGE_CONFIG/WRITE_DAC/WRITE_OWNER；服务注册表定义也仅管理员/SYSTEM 可写。
宿主固定绝对 Python/脚本路径、工作目录和角色，拒绝额外服务启动参数；子环境清空，只保留固定 Windows 系统路径。
Python 使用 `-I`，embedded `_pth` 只列受保护 runtime/zip，不启用 site；不加载开发路径或用户 PYTHONPATH，不写 bytecode。额外应用和依赖路径在 manifest 通过后才加入，均位于受保护部署。
原生 DLL 读取限定 System32。未发现可借可写 parent、PATH、模块或 manifest 绕过 Root/pin 检查的路径。
ProgramData/系统盘根目录允许创建无关子项的既有系统权限没有被扩大；对既有受保护子树的 delete-child、delete、owner/ACL 修改仍拒绝。

现场发现旧 PowerShell ACL 检查在服务 token 下受 ConstrainedLanguage 限制；已替换为原生只读检查，保持相同拒绝条件并增加异常 ACE 拒绝测试。
实现使用 Windows 的 [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow) 和 [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo) 读取 owner/DACL，不调整系统策略或启用额外特权。
原生模块已加入当前尚未签署的 artifact/dependency 源文件边界；migration revision、DDL 和 EXPECTED_SNAPSHOT_SHA256 未修改。旧 operator parent-preflight 消费者仅做同等原生接口兼容修正，未执行 ceremony。

## 17. Independent Reviewer / 独立审查

`identity_independent_reviewer`：**PASS；无 P0/P1/P2、OPEN 或 PARTIALLY FIXED**。
其独立子审查 `loader_check` 检查完整部署 ACL/路径/模块解析及宿主启动边界，也无本范围问题。
Reviewer 独立重算 manifest、核对现场 ACL、原 ACE 差异、公钥/pin、SCM 配置、真实 PID/SID 关联、输出与封存副本摘要，并重新运行证据评估和 100 项原生 ACL 测试。
未参与实现；没有仅复述实现者测试结果。

## 18. Full Tests / 完整测试

- 完整现有及新增 suite：**283 passed，4 skipped**。
- 4 个 skip 仍是预先禁止的 legacy direct-DB 测试；未连接 PostgreSQL。
- 原生 ACL 单独测试：100 passed（含真实 Win32 内存安全描述符测试）。
- 证据评估器：25 项合成负向/缺失证据测试通过。
- `git diff --check`：通过。
- 部署清单、源代码副本一致性、18 条精确 ACL delta、封存副本四份逐字节 hash 比较：通过。
- 57 条既有弃用警告保留；未改依赖或无关模型代码消除警告。

## 19. Secret Leakage Scan / 秘密泄漏检查

源文件/文档及封存 JSON 的私钥块、常见凭证格式扫描没有命中。该扫描只覆盖明确模式，不宣称可以识别任意秘密。
本轮没有读取/记录 passphrase，也没有读取、哈希、复制或输出 canonical 私钥字节。
部署只含非秘密材料；生成的 Python bytecode cache 在受控新部署内清除，可重新生成，不涉及用户信任材料。

## 20. Legacy Safety / 旧系统保护

本轮没有连接或调用任何 PostgreSQL、Docker/container/volume 操作。
`gateway-db-1`、`gateway_qingyu_postgres` 及 legacy databases/volumes 零触碰；没有创建数据库、容器、volume 或 PostgreSQL role。

## 21. Original Workspace / 原工作区

`<repo>\core` HEAD：`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`。
9 个原 tracked dirty 文件保持；最终重新计算 diff object hash：
`9594b6b6f5374094a88bcb068d5bcd7afd875d18`。

实现工作树仍为 `<repo>\core-r1-implementation`，分支 `ai/task-r1-canonical-implementation`，HEAD 同上；存在预先已有及本轮未提交修改。**本轮未 commit**。

## 22–25. Stage Boundaries / 阶段边界与下一步

22. Signed Migration Intent：**NOT STARTED**。
23. PostgreSQL：**NOT STARTED**；未执行 Alembic。
24. Foundation Closure：**NOT ENTERED**。
25. Next Step：**ALLOW SIGNED MIGRATION INTENT**。仅允许下一阶段设计/准备进入；具体执行等待下一条明确授权，不自动签署、不自动启动数据库。

本轮在此 STOP。现有加密私钥、public pin、服务和部署保留。服务保持按需启动且已停止；未清理或销毁 acceptance 生命周期资源。未来生产 Root 必须重新经过独立离线 ceremony，不能提升本测试 Root。

## Team / 团队与修改范围

按 ai-dev-team 技能，将宿主、探针/评估器、契约、原生 ACL 分配给有界 Worker，之后启动未参与实现的 Reviewer。最多 3 个并行 Worker，含 Lead 不超过 4 个活动智能体。
实现 Worker：`identity_host_worker`、`identity_probe_worker`、`identity_contract_worker`、`identity_native_acl_worker`；审查为上述独立 Reviewer 及其 `loader_check`。

本轮文件范围：

- `app/control_plane/r1_root_pin.py`、`r1_windows_acl.py`、`r1_schema_snapshot.py`。
- `tools/provision_r1_acceptance_root.py` 的原生 parent-preflight 兼容调用。
- `tools/r1_windows_identity/` 下宿主、prepare/refresh/collect/audit 脚本、probe 与 assess。
- `tests/test_r1_root_pin.py`、`test_r1_root_provisioning.py`、`test_r1_schema_snapshot.py`、`test_r1_windows_acl.py`、`test_r1_identity_assessment.py`。
- Windows identity contract、本报告、implementation state、signed-intent contract 的依赖边界说明。

保留的范围限制：这是本机 acceptance trust boundary 的时点证据；不对已被攻陷的 Operator/Administrators/SYSTEM 提供隔离，也不代表整个 Windows OS 沙箱或未来 API/数据库权限验收。其它 R1 Implementation blockers 仍见 implementation state。
