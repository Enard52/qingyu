param([Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]+$')][string]$EvidenceName)
$ErrorActionPreference = 'Stop'
$r1Repo = '<repo>\core-r1-implementation'
$r1Evidence = Join-Path $r1Repo ('docs\evidence\r1-f3-coordinator\' + $EvidenceName)
if (Test-Path -LiteralPath $r1Evidence) { throw 'Refusing to replace existing evidence' }
$r1Baseline = Get-Content -LiteralPath (Join-Path $r1Repo 'docs\evidence\r1-f3-coordinator\baseline\inventory.json') -Raw | ConvertFrom-Json
$r1Hashes = [ordered]@{}
$r1Changes = @()
$r1PrivateMarkers = @()
Push-Location $r1Repo
try {
    foreach ($r1Relative in @(& git ls-files --cached --others --exclude-standard | Sort-Object -Unique)) {
        $r1Path = Join-Path $r1Repo $r1Relative
        if (-not (Test-Path -LiteralPath $r1Path -PathType Leaf)) { continue }
        if (-not $r1Relative.StartsWith('docs/evidence/r1-f3-coordinator/')) {
            $r1Hash = (Get-FileHash -LiteralPath $r1Path -Algorithm SHA256).Hash.ToLowerInvariant()
            $r1Hashes[$r1Relative] = $r1Hash
            $r1Old = $r1Baseline.source_hashes.PSObject.Properties[$r1Relative]
            if ($null -eq $r1Old -or $r1Old.Value -ne $r1Hash) {
                $r1Changes += [ordered]@{path=$r1Relative; kind=$(if ($null -eq $r1Old) {'F3_NEW'} else {'F3_CHANGED_PREEXISTING'}); sha256=$r1Hash}
            }
        }
        # Inspect only nonignored repository text. Never enter external custody.
        if ([IO.Path]::GetExtension($r1Path) -in @('.py','.ps1','.sql','.md','.json','.txt','.toml','.ini','.pem','.key')) {
            $r1Matches = @(Select-String -LiteralPath $r1Path -Pattern '^-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----$' -CaseSensitive)
            foreach ($r1Match in $r1Matches) { $r1PrivateMarkers += [ordered]@{path=$r1Relative; line=$r1Match.LineNumber} }
        }
    }
    $r1Frozen = @('app/audit.py','app/services.py','app/control_plane/authority.py','app/control_plane/postgres.py',
        'app/control_plane/migration.py','app/control_plane/__init__.py','app/control_plane/r1_protocol.py',
        'app/control_plane/r1_root_pin.py','app/control_plane/r1_windows_acl.py','app/control_plane/r1_schema.py',
        'app/control_plane/r1_schema_snapshot.py','app/control_plane/r1_provisioning.py',
        'control_plane_alembic/env.py','control_plane_alembic/versions/0001_control_plane_r1_initial.py',
        'alembic/env.py','alembic/versions/0001_core_foundation.py','pyproject.toml')
    $r1FrozenFailures = @($r1Frozen | Where-Object { $r1Hashes[$_] -ne $r1Baseline.source_hashes.PSObject.Properties[$_].Value })
    $r1OriginalHash = (& cmd.exe /d /c 'git -C <repo>\core diff --binary --no-ext-diff --no-textconv | git -C <repo>\core hash-object --stdin').Trim()
    $r1OriginalFiles = @(& git -C <repo>\core diff --name-only)
    $r1PublicHash = (Get-FileHash -LiteralPath 'C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub' -Algorithm SHA256).Hash.ToLowerInvariant()
    $r1Registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $r1Key = $r1Registry.OpenSubKey('SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly',$false)
        if ($null -eq $r1Key) { throw 'Canonical public pin missing' }
        try {
            $r1Pin = [ordered]@{}
            foreach ($r1Field in @('PinVersion','Profile','TestOnly','PublicKeyId')) {
                $r1Pin[$r1Field] = [ordered]@{value=$r1Key.GetValue($r1Field); kind=$r1Key.GetValueKind($r1Field).ToString()}
            }
        } finally { $r1Key.Dispose() }
    } finally { $r1Registry.Dispose() }
    $r1Head = (& git rev-parse HEAD).Trim()
    $r1OriginalHead = (& git -C <repo>\core rev-parse HEAD).Trim()
    $r1ExpectedPublic = 'e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1'
    $r1Passed = ($r1Head -eq $r1Baseline.head -and $r1OriginalHead -eq $r1Baseline.head -and $r1OriginalFiles.Count -eq 9 -and
        $r1OriginalHash -eq '9594b6b6f5374094a88bcb068d5bcd7afd875d18' -and $r1FrozenFailures.Count -eq 0 -and
        $r1PrivateMarkers.Count -eq 0 -and $r1PublicHash -eq $r1ExpectedPublic -and
        $r1Pin.PinVersion.value -eq 1 -and $r1Pin.PinVersion.kind -eq 'DWord' -and
        $r1Pin.TestOnly.value -eq 1 -and $r1Pin.TestOnly.kind -eq 'DWord' -and
        $r1Pin.Profile.value -eq 'R1_ACCEPTANCE_TEST_ONLY' -and $r1Pin.Profile.kind -eq 'String' -and
        $r1Pin.PublicKeyId.value -eq $r1ExpectedPublic -and $r1Pin.PublicKeyId.kind -eq 'String')
    New-Item -ItemType Directory -Path $r1Evidence | Out-Null
    [ordered]@{
        captured_utc=[DateTime]::UtcNow.ToString('o'); scope='F3 public integrity evidence only'; pass=$r1Passed;
        head=$r1Head; branch=(& git branch --show-current); status=@(& git status --short);
        original_head=$r1OriginalHead; original_status=@(& git -C <repo>\core status --short);
        original_dirty_files=$r1OriginalFiles; original_tracked_diff_object_hash=$r1OriginalHash;
        frozen_source_failures=$r1FrozenFailures; public_file_sha256=$r1PublicHash; registry64_public_pin=$r1Pin;
        private_pem_marker_findings=$r1PrivateMarkers;
        secret_scan_limit='Nonignored repository files and reports, private PEM material markers. No real private custody accessed; no claim of exhaustive secret detection.';
        changed_since_turn_baseline=$r1Changes; source_hashes=$r1Hashes;
        windows_identity_gate='FROZEN PASS; no full rerun'; final_commit='NOT CREATED'
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $r1Evidence 'integrity.json') -Encoding UTF8
    Write-Output ('F3 integrity PASS=' + $r1Passed + '; original dirty count=' + $r1OriginalFiles.Count + '; private PEM findings=' + $r1PrivateMarkers.Count)
    if (-not $r1Passed) { throw 'F3 integrity check failed; see public report' }
} finally { Pop-Location }
