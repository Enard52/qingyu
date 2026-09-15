# Control Plane R1 Windows identity and ACL acceptance contract

Status: **PASS for the bounded Windows identity / ACL acceptance, 2026-09-14 UTC**.
Actual service runs and independent review are recorded in
`CONTROL_PLANE_R1_WINDOWS_IDENTITY_REPORT.md` and the sealed evidence directory
listed there. This contract defines the authorized Windows Identity / ACL
remediation and acceptance boundary. The R1 Implementation Gate and
Foundation Closure remain blocked by their separate outstanding requirements.

The operator has authorized this bounded acceptance remediation: establish two
distinct Windows service virtual accounts, deploy a protected acceptance probe,
grant those exact SIDs the public-pin read access they need, and collect real
identity and effective-access evidence. This authorization does not authorize
signing an intent, creating or connecting to a database, migration, Docker or
Gateway changes, or deletion of acceptance resources or Root material.

## Frozen identities and service boundary

The following names and SIDs were resolved read-only on the current host.
`whoami /user` identified the operator; `sc.exe showsid` derived each service
SID and reported `Inactive`. A derived SID or service configuration is not
evidence of a successfully started service or its actual process token.
Subsequent SCM host/child process observations and token reports confirmed
both frozen SIDs; those later observations, not SID derivation, support PASS.

| Duty | Windows account / service | Frozen SID |
| --- | --- | --- |
| Human operator | `<HOST>\<operator>` | `<operator-SID>` |
| Runtime acceptance | `NT SERVICE\QingyuControlPlaneR1Acceptance` | `S-1-5-80-521220990-1857042447-2197016169-2159567703-611382270` |
| Migrator acceptance | `NT SERVICE\QingyuControlPlaneR1AcceptanceMigrator` | `S-1-5-80-3253374542-705302118-4188924831-1122857046-3825746319` |

Each service must be created and started through the Windows Service Control
Manager (SCM), with its own exact virtual account as the configured logon
identity. Both are demand-start services. The fixed minimal .NET service host
launches only the protected Python probe for its fixed `runtime` or `migrator`
role, accepts no additional service-start arguments, and stops after the
bounded probe completes. This migrator identity is an identity acceptance
subject; it has no current PostgreSQL credentials or migration authority.

Neither service nor its probe may execute as the operator, an administrator,
`LocalSystem` (`S-1-5-18`), `LocalService`, or `NetworkService`. A process started
from the operator's interactive shell, an impersonated token, or a report
containing a requested service name cannot substitute for an actual SCM launch.
The runtime and migrator token user SIDs must equal their respective frozen
SIDs and must differ from each other and from the operator SID.

SCM `RequiredPrivileges` must contain exactly `SeChangeNotifyPrivilege` for
each service. A disabled dangerous privilege still counts as present and
fails this contract; the probe must not enable privileges to obtain access.
Retaining only this traversal-related privilege does not grant private-file
read access or authority to alter protected files. Record the complete actual
token privileges and group SIDs with their attributes, token type, integrity
level, and elevation state. Reject an administrator-capable token or any
unexpected privilege; a label such as service name, integrity level, or
`elevated=false` is not sufficient by itself.

SCM configuration, service object security descriptors, configured account,
binary command line, SID type, start type and `RequiredPrivileges` require
independent capture. Both service identities must be unable to change either
service's configuration, owner or DACL. SYSTEM and Administrators remain
trusted host administrators and permitted resource custodians; they are not
application execution identities. Compromise of this host administrator or
operator remains outside this acceptance-only isolation claim.

## Resource and effective-rights policy

The canonical acceptance public key remains the raw 32-byte Ed25519 file:

`C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub`

Its required SHA-256 fingerprint is:

`e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`

The canonical pin is explicitly the **Registry64** view of
`HKLM\SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly`.
The pin must retain exactly `PinVersion=1` (DWORD),
`Profile=R1_ACCEPTANCE_TEST_ONLY` (string), `TestOnly=1` (DWORD), and
`PublicKeyId=<the fingerprint above>` (string). This remediation changes
access descriptors only where specified; it does not rewrite public bytes,
pin values or Root identity. Preserve and independently compare public hash,
registry value names, types and values before and after remediation.

| Resource | Runtime and migrator rights | Custody and required denials |
| --- | --- | --- |
| Canonical public key | Read the public bytes and security metadata | No write/append, delete, owner or DACL change; no replacement through an ancestor |
| Public directory chain | Read metadata, list/traverse where needed for the fixed ACL verifier | No writes inside the protected Qingyu chain, delete-child, replacement, owner or DACL change |
| Registry64 pin and named parent chain | `ReadKey`, including security descriptor read | No set-value, create-subkey, delete, owner or DACL change |
| Protected deployment, manifest, host, Python and all loaded dependencies | Read and execute only | No content changes, extra import files, delete/replace, owner or DACL change |
| Either SCM service object | Only platform-default nonmutating visibility needed for inspection | No change-config, owner or DACL change |
| Operator private-key file and private custody directory | No key-data read or mutation authority | No private-file read-data, write/append, delete, owner or DACL change; no parent replacement path |
| Own service output directory | Modify only within the designated disposable output directory | Output is untrusted until independently captured and sealed |
| Other service output directory or sealed evidence | No write or replacement authority | No cross-service evidence forgery or modification of independent records |
| Development worktree | No deployment trust is assigned | Its writability does not qualify it as a safe execution or import path |

Read grants must name the two frozen service SIDs directly. Do not grant
`Everyone`, `Users`, `Authenticated Users`, `ALL SERVICES`, an application-wide
group, or the operator's identity additional rights as a substitute. Preserve
existing protected owners and unrelated ACEs. Do not widen access to operator
custody to make the public loader succeed.

The permitted explicit public ACL additions are `Read` on the canonical
public file and non-inheriting `ReadAndExecute` on these existing directories:

- `C:\ProgramData\Qingyu`
- `C:\ProgramData\Qingyu\ControlPlane`
- `C:\ProgramData\Qingyu\ControlPlane\R1`

Inspect `C:\ProgramData` and all relevant ancestors independently for
replacement and security-descriptor changes. Normal ability to create an
unrelated child of a broad system directory does not itself mean the existing
protected subtree can be replaced. Evaluate the protected child's `DELETE`
and the ancestor's `FILE_DELETE_CHILD`, as well as `WRITE_DAC` and
`WRITE_OWNER`; do not equate an unrelated create-child grant with replacement.
An ancestor that permits actual protected-subtree replacement fails admission.
Do not rewrite broad system-directory ACLs to obtain a passing result.

The permitted explicit Registry64 additions are non-inheriting `ReadKey`
grants to the same two exact SIDs on each of these existing keys:

- `SOFTWARE\Qingyu`
- `SOFTWARE\Qingyu\ControlPlane`
- `SOFTWARE\Qingyu\ControlPlane\R1`
- `SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot`
- `SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly`

Capture the before/after descriptors and verify the precise added ACEs;
missing objects are not permission to create a replacement pin. Public and
pin owners and write authority remain restricted to SYSTEM/Administrators.
Reject missing or NULL DACLs, untrusted replacement rights and reparse paths.
An inaccessible security descriptor fails closed.

The loader must use its normal fixed machine trust source, without a test
source injection or environment override. It must read Registry64 explicitly
and apply its Registry32 conflict check. An absent 32-bit slot is acceptable;
an existing slot is acceptable only when all values match and its ACL chain
is safe. An access-denied, partial or malformed 32-bit slot is not evidence of
absence. This remediation neither writes that view nor creates a fallback.

## Private Root custody

The private file remains exclusively in its existing operator custody at
`C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly\operator-root-encrypted.pem`.
Do not read, hash, decrypt, copy, display or include its bytes in evidence.
Do not request the passphrase or place it in any process, argument,
environment variable, service configuration, source file or report. Only
existing metadata and security descriptors may be inspected independently
when needed. Neither service receives an ACL grant to the private file or
its custody directory. No private-key signing operation is part of this work.

The negative effective-access test may request a handle to the existing
private file with the `FILE_READ_DATA` access mask and immediately close it.
It must never issue a read operation on that handle. Success is a security
failure even if no bytes were consumed; record the granted right, stop
acceptance, and preserve evidence. A missing file, sharing violation, wrong
path or other error is not proof of an ACL denial. The required negative
result is explicit access denied against the independently confirmed existing
object, with separate parent-replacement checks. The same rule applies to
write, append, delete, owner and DACL access probes.

## Protected deployment and exact-byte manifest

The only acceptance deployment root is
`C:\Program Files\Qingyu\ControlPlane\R1\Acceptance`. Its administrator-owned
ancestor chain and every deployed child must resist service and ordinary-user
writes and replacement. Services receive read/execute access to this fixed
tree. Reject junctions, symlinks and other reparse paths in the deployment or
its ancestors. Do not execute service code from
`<repo>\core-r1-implementation`, an operator profile, a temporary folder,
the ceremony bundle, or service-writable evidence directories.

The development worktree remains writable for ongoing implementation. Source
and dependencies copied from development or build locations become eligible
for execution only after placement in the protected deployment, complete
inventory/hash verification, ACL inspection and independent freeze capture.
Build inputs are provenance records, not runtime search paths. There is no
claim that a writable source checkout is immutable.

The fixed host starts the deployed embedded Python **3.12.10** by absolute
path with `-I`, a fixed absolute probe path, and the protected deployment as
working directory. Clear inherited child environment variables and admit
only the fixed OS paths needed by the probe. No inherited `PATH`,
`PYTHONPATH`, `PYTHONHOME`, profile hook or caller-selected module path is a
trust source. Restrict the embedded runtime configuration and `sys.path` to
the protected runtime, protected vendor dependencies and protected application
files. Disable bytecode writes. Invoke system inspection executables by
verified OS paths. ACL verification uses read-only native Windows security
APIs; it does not depend on PowerShell language mode or change application
control policy. The original shell implementation was rejected under the
actual service tokens' ConstrainedLanguage mode and is replaced with the
same fail-closed owner/DACL/write-mask checks through native APIs.

The deployment manifest lists the complete, unique, normalized
POSIX-relative file set and lowercase SHA-256 digest of every deployed file
except the manifest itself. It includes the compiled service host, probe,
embedded Python executable/DLL/archive/configuration, all vendored dependency
files, application sources, and any additional loaded configuration. Reject
absolute paths, traversal, duplicate entries, extra files, missing files,
reparse entries and any digest mismatch. Capture the manifest's own exact-byte
SHA-256 independently outside the service-writable output directories, and
verify the complete deployed file set and hashes against that captured
manifest before and after each acceptance run.

Record the Python archive identity, resolved dependency versions and exact
deployed contents. A filename or `pyproject.toml` range alone does not freeze
dependencies. An internally consistent manifest that a service can rewrite
is not independent integrity evidence. This manifest is a local protected
deployment inventory, not an Operator-Root signature, signed provisioning
intent, or authorization to execute a migration artifact.

## Nonmutating execution and independent evidence

Use real SCM launches for **both** frozen services. Record the launch window,
host/probe process identities and executable paths, fixed command line,
completion status and service stop state. Bind independently observed
SCM/process information to the same run's token and access report. Collect
complete token information, public pin result and fingerprint, manifest
verification, and effective rights for protected files, directories, pin
parents and both service configurations. Public verification with a known
Ed25519 test vector may validate the deployed library; it never signs with
or reads the acceptance private Root.

Effective-rights probes open **existing** objects with each requested access
mask, then immediately close the handle. File probes use `OPEN_EXISTING` and
never create, truncate, write, append, rename or delete. Registry and SCM
probes request handles but never set values, create keys, alter security or
change configuration. A granted write/delete/security-change handle is a
failed denial test even when unused. Record each requested mask and exact
Windows result; do not collapse every unsuccessful open into access denied.
These observations establish effective access at that moment. They are not
destructive mutation tests, persistence tests or proof of every future race.

Independent ACL inspection must cover all relevant ancestors and service
groups in addition to direct object opens. Recheck protected bytes, file set,
pin values and descriptors around the run. Tests that complete with wrong
rights fail acceptance; an exit code of zero or `completed=true` only means
the probe completed its collection. The probe's own PASS-like fields are not
an independent verdict. Each required denial, positive read, identity and
integrity condition must be evaluated separately.

Evidence lives under `C:\ProgramData\QingyuR1IdentityEvidence`, with these
separate service-writable output directories:

- `C:\ProgramData\QingyuR1IdentityEvidence\QingyuControlPlaneR1Acceptance`
- `C:\ProgramData\QingyuR1IdentityEvidence\QingyuControlPlaneR1AcceptanceMigrator`

Each service may modify only its own output directory. The evidence root,
independent before/after ACL captures, frozen deployment manifest, assessment
and sealed copies remain administrator-controlled and service-nonwritable.
No output directory may enter the service's code, import or working-directory
path. Treat result JSON, host status, timestamps and any service-written
hashes as untrusted claims until independently captured and compared with
SCM/process/token observations and protected deployment integrity.

After both host and child processes have stopped, independently copy the
run's output to a fresh protected evidence location, verify copied byte
hashes, capture its owner/DACL and record a run identifier plus start/end UTC
times. Do not overwrite a prior sealed run. A later run may replace the
service's disposable output only after the earlier evidence is preserved.
Sealing protects a captured observation from later service modification; it
does not by itself prove that previously service-written claims were true.
Incomplete, stale, conflicting or unexplained evidence leaves the gate
pending or failed.

## Gate and lifecycle

Identity / ACL acceptance may be marked PASS only after an independent
assessment binds both actual SCM service runs to their frozen identities and
verifies all required public reads, private and protected-resource denials,
privilege restrictions, deployed file integrity, parent protections and
sealed evidence. Until that evidence exists and is assessed, this contract's
status is **PENDING**, including when static tests or administrator-context
public-pin reads pass. Report each unresolved condition explicitly.

Even a later Windows identity PASS is only this prerequisite. It does not
pass the PostgreSQL privilege gate, approve a signed intent, authorize
database/container/volume/role creation or migration, satisfy Reviewer A/B/C,
or declare Implementation Gate or Foundation Closure complete. The separate
owner, signed-intent and Root-custody contracts continue to apply.

Services remain demand-start and stopped outside the bounded acceptance run.
On an unexpected identity, privilege, fingerprint, manifest or ACL result,
stop the acceptance processes, preserve evidence and report the condition.
Do not broaden grants, switch to SYSTEM, regenerate a Root, replace a pin or
adopt another deployment to obtain a passing test.

Preserve original descriptors and an exact remediation inventory so a future
rollback is reviewable. A partial deployment or failed run is not permission
to delete or overwrite it. Deleting services, deployment/evidence directories,
public pins, private-key material or the acceptance environment requires
explicit deletion authority naming the resources. Restore only the reviewed
changed ACL entries under an authorized rollback; avoid blind recursive ACL
replacement. Keep the encrypted acceptance Root for later separately
authorized signatures throughout Implementation Gate and Foundation Closure.
No production system may adopt or promote this test-only Root.
