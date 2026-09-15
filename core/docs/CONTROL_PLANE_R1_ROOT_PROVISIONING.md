# R1 acceptance Operator Root — local operator ceremony

Status: **test-only acceptance Root created by the human operator; fixed
public key and 64-bit HKLM pin installed and runtime-read verified**. The
encrypted private key remains in local operator
custody and the 32-byte public export has approved SHA-256 fingerprint
`e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`.
No database or migration has been installed. This is
not a production trust anchor or authority to create a database.

This is a narrow acceptance-only amendment to the original remediation plan
§13 description of an offline operator root. The plan's requirement that the
private key remain outside Authority/Core **process and data custody** still
applies; only the separate-machine/offline-location requirement is relaxed for
this test profile. All production interpretations of §13 remain unchanged.

## Acceptance-only local custody amendment

The operator runs `tools/provision_r1_acceptance_root.py
create-local-acceptance` on the current Windows acceptance host, through the
one-command wrapper. This is **not** an independent offline Root. The command
creates a test-only Ed25519 key once, writes **encrypted PKCS#8** outside
every Git worktree in restricted
`C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly`, and exports only
its raw 32-byte public key to a separate file. The human types the passphrase
interactively; it never enters command arguments, environment variables,
logs, Git, database, fixtures, reports or Codex context. The private key
remains on this host solely in operator custody throughout R1 Implementation
Gate and Foundation Closure for later authorized signatures. Application,
API and migration processes must not read it or run as the operator principal;
this separation must be independently proved before executable admission.
The runtime loads only the protected public pin. A local administrator or
compromised operator session remains a test-only threat-boundary limitation.

Before creation, the operator must pre-stage a private-key directory with
owner and DACL restricted to the operator SID, SYSTEM, and Administrators.
The tool audits the directory and its ancestors for replacement/delete-child,
write-DAC, write-owner and reparse hazards **before generation or writing**.
It requires an existing absolute directory and refuses a Git worktree. The
private file is created with exclusive-create semantics, flushed, and never
overwritten or automatically removed. If the process stops after private
creation but before public export, `export-public-local-acceptance` derives only the
missing public export from the **same** encrypted private key. It does not
generate a second root.

After the exclusive private write, the tool also verifies the **actual file**
owner/DACL before exporting the public key or reporting success. An unsafe
inherited file ACL fails closed and leaves the private file in operator custody
for explicit operator recovery; it is never silently replaced.

The protected package at `C:\ProgramData\QingyuR1Operator\CeremonyBundle`
carries Python 3.12.10,
exact pinned dependencies, the canonical tool and a one-command PowerShell
launcher. It stages an ACL-restricted sibling `AcceptanceTestOnly` custody
directory on the local fixed disk. On the current host the operator runs
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File
C:\ProgramData\QingyuR1Operator\CeremonyBundle\CREATE_R1_ACCEPTANCE_ROOT.ps1` and enters the
passphrase twice. The wrapper independently reads back the public fingerprint
and writes a non-secret report. It does not install the pin or access a database.

Underlying canonical command (the wrapper supplies paths; this is not an
additional operator step):

```powershell
python -m tools.provision_r1_acceptance_root create-local-acceptance `
  --private-path '<operator-local-ACL-custody>\operator-root-encrypted.pem' `
  --public-path '<public-output>\operator-root-acceptance-test-only.pub'
```

The operator compares the returned `public_key_id` (lowercase SHA-256 of the
raw public key) with an independent local readback. That ID is public
fingerprint metadata, **not** proof that the host has installed the pin.
The private key is already on the acceptance host but must never be copied to
runtime, API, migration, Git or database custody. The tool does not print its
content, encrypted bytes, password, or full private path.

## Acceptance-host pin installation

The acceptance host administrator first stages the fixed public directory
`C:\ProgramData\Qingyu\ControlPlane\R1` and the 64-bit HKLM parent
`SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot`, with owner/DACL allowing
write, delete-child and ACL changes only to SYSTEM/Administrators. No generic
Users/Authenticated Users/Everyone write, parent replacement, NULL DACL, or
reparse point is allowed. The operator verifies this policy using normal
Windows administrative controls before continuing. The tool independently
checks the staged parents; it does not repair them or create a weaker fallback.

After the operator separately reviews and approves the fingerprint, run the
existing pin installer as an administrator on the acceptance host:

```powershell
python -m tools.provision_r1_acceptance_root install-public-pin `
  --public-path 'C:\ProgramData\QingyuR1Operator\CeremonyBundle\public\operator-root-acceptance-test-only.pub' `
  --expected-key-id '<operator-approved-public-fingerprint>'
```

The installer writes only the fixed public file
`C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub`
and the fixed **64-bit** HKLM
`SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly` slot.
The values are `PinVersion=1` (DWORD),
`Profile=R1_ACCEPTANCE_TEST_ONLY` (string), `TestOnly=1` (DWORD), and
`PublicKeyId=<fingerprint>` (string). No environment-selected or Python-bitness
fallback is allowed. A missing 32-bit slot is acceptable; a duplicate 32-bit
slot is acceptable only if all values match exactly and its ACL is safe. A
conflicting, partial, malformed, or inaccessible 32-bit slot refuses the
installation. The installer never writes the 32-bit view.
The operator supplies the fingerprint from the separately reviewed local
ceremony report; the installer compares it before any write. The public file
does not get to declare its own trust identity, and application/API/migration
must never perform trust-on-first-use.

The public file is exclusive-created unless an interrupted prior attempt left
the exact same bytes. Any existing 64-bit slot, including a partial slot,
refuses replacement; even a slot appearing between preflight and creation is
rejected using Windows' newly-created-key disposition. The newly created slot
must pass ACL inspection **before values are written**, and the completed pin
must pass runtime read/ACL verification **afterward**. Operator remediation of
an incomplete slot requires a separate explicit authorization.
Failure means **no trust** even if some public material was written. The
operator records public fingerprint, fixed pin location, duplicate-equivalent
status and a reviewed ceremony timestamp without recording secrets.

## Rotation and recovery

R1 defines **no online replacement or rotation** of this root. Re-running
creation cannot overwrite an existing private or public key. Re-running pin
installation cannot overwrite an existing 64-bit pin. A conflict, corrupt
partial installation, loss of private custody, or need for rotation is a
fail-closed event requiring a separately approved recovery amendment and
forensic preservation, not a retry that trusts a newly generated key.

Keep the encrypted test-only private key throughout R1 Implementation Gate
and Foundation Closure for necessary re-signing. Do not destroy it after
creation. The end of acceptance requires separate explicit authorization
before deleting the private key, public pin or isolated acceptance environment.
A future production Root requires a new independent offline ceremony and must
never adopt or promote this acceptance Root.

Pin installation is only the first trust-bootstrap prerequisite. A signed
complete provisioning/migration intent, target isolation checks, migration
artifact verification, and real PostgreSQL privilege acceptance remain
separate gates. No database/container/volume/role may be created merely
because this procedure exists or a public pin is present.
