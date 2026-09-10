param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath
)

$ErrorActionPreference = "Stop"
$sourceDatabase = "qingyu_phase3_commit5_source"
$restoreDatabase = "qingyu_phase3_commit5_restore"
$sourceRoot = [IO.Path]::GetFullPath("D:\q5src")
$restoreRoot = [IO.Path]::GetFullPath("D:\q5dst")
$backupRoot = [IO.Path]::GetFullPath("D:\q5backup")
$dumpPath = Join-Path $backupRoot "evidence.dump"
$containerDump = "/tmp/qingyu_phase3_commit5.dump"
$containerRestoreDump = "/tmp/qingyu_phase3_commit5_restore.dump"
$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
$alembic = Join-Path $PSScriptRoot "..\.venv\Scripts\alembic.exe"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Assert-ExactPath([string]$Actual, [string]$Expected) {
    if ([IO.Path]::GetFullPath($Actual) -ne [IO.Path]::GetFullPath($Expected)) {
        throw "Unsafe path mismatch: $Actual"
    }
}

function Remove-ExactDirectory([string]$Path, [string]$Expected) {
    Assert-ExactPath $Path $Expected
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Invoke-Native([string]$File, [string[]]$Arguments) {
    $output = & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE"
    }
    return $output
}

function Reset-Database([string]$Name) {
    if ($Name -notin @($sourceDatabase, $restoreDatabase)) {
        throw "Unsafe database name: $Name"
    }
    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "psql", "-U", "qingyu", "-d", "postgres",
        "-v", "ON_ERROR_STOP=1", "-c",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$Name' AND pid <> pg_backend_pid();"
    ) | Out-Null
    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "psql", "-U", "qingyu", "-d", "postgres",
        "-v", "ON_ERROR_STOP=1", "-c", "DROP DATABASE IF EXISTS $Name;"
    ) | Out-Null
}

function Get-FileInventory([string]$Root) {
    return @(
        Get-ChildItem -LiteralPath $Root -File -Recurse | Sort-Object FullName | ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($Root.Length).TrimStart("\").Replace("\", "/")
                size_bytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
}

$sample = Get-Item -LiteralPath $SamplePath
if (-not $sample.PSIsContainer -and $sample.Length -gt 0) {
    $sampleHash = (Get-FileHash -LiteralPath $sample.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
} else {
    throw "Sample path is not a non-empty file"
}
if ($sampleHash -ne "04c54e6f87bd2113c5183ba7a2f24b2694c333e5eab6f42308f654063ee4b040") {
    throw "Sample #001 SHA-256 mismatch"
}

Assert-ExactPath $sourceRoot "D:\q5src"
Assert-ExactPath $restoreRoot "D:\q5dst"
Assert-ExactPath $backupRoot "D:\q5backup"
Remove-ExactDirectory $sourceRoot "D:\q5src"
Remove-ExactDirectory $restoreRoot "D:\q5dst"
Remove-ExactDirectory $backupRoot "D:\q5backup"
New-Item -ItemType Directory -Path $sourceRoot, $restoreRoot, $backupRoot | Out-Null

Reset-Database $sourceDatabase
Reset-Database $restoreDatabase

$sourceResult = $null
$restoreResult = $null
try {
    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "createdb", "-U", "qingyu", "-T", "template0", $sourceDatabase
    ) | Out-Null
    $env:DATABASE_URL = "postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/$sourceDatabase"
    $env:APP_ENV = "test"
    $env:API_TOKEN = "commit5-acceptance-local-only"

    $sourceIdentity = Invoke-Native "docker" @(
        "exec", "gateway-db-1", "psql", "-U", "qingyu", "-d", $sourceDatabase,
        "-Atc", "select current_database()"
    )
    if ($sourceIdentity.Trim() -ne $sourceDatabase) { throw "Source DB identity mismatch" }

    Invoke-Native $alembic @("upgrade", "0015_attachment_observations") | Out-Null
    $revision0015 = (Invoke-Native $alembic @("current")).Trim()
    if ($revision0015 -notmatch "0015_attachment_observations") { throw "0015 migration gate failed" }
    Invoke-Native $alembic @("upgrade", "head") | Out-Null
    $sourceRevision = (Invoke-Native $alembic @("current")).Trim()
    if ($sourceRevision -notmatch "0016_real_export_evidence") { throw "0016 migration gate failed" }

    Invoke-Native $python @(
        (Join-Path $repoRoot "scripts\phase3_sample_acceptance.py"),
        "import", "--root", $sourceRoot, "--sample", $sample.FullName
    ) | Out-Null
    $sourceJson = (Invoke-Native $python @(
        (Join-Path $repoRoot "scripts\phase3_sample_acceptance.py"),
        "validate", "--root", $sourceRoot
    ) | Select-Object -Last 1)
    $sourceResult = $sourceJson | ConvertFrom-Json

    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "pg_dump", "-U", "qingyu", "-d", $sourceDatabase,
        "-Fc", "--no-owner", "--no-privileges", "--serializable-deferrable", "-f", $containerDump
    ) | Out-Null
    Invoke-Native "docker" @("cp", "gateway-db-1`:$containerDump", $dumpPath) | Out-Null
    $hostDumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-Native "docker" @("exec", "gateway-db-1", "rm", "-f", $containerDump, $containerRestoreDump) | Out-Null
    Invoke-Native "docker" @("cp", $dumpPath, "gateway-db-1`:$containerRestoreDump") | Out-Null
    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "pg_restore", "--list", $containerRestoreDump
    ) | Out-Null

    foreach ($relative in @("archive", "manifests")) {
        $source = Join-Path $sourceRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            throw "Backup source is missing: $source"
        }
        $reparse = Get-ChildItem -LiteralPath $source -Recurse -Force |
            Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
        if ($reparse) { throw "Backup source contains a reparse point" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $backupRoot $relative) -Recurse
    }

    $inventoryFiles = Get-FileInventory $backupRoot | Where-Object { $_.path -ne "inventory.json" }
    $inventory = [ordered]@{
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
        source_database = $sourceDatabase
        alembic_revision = $sourceRevision
        base_git_commit = (Invoke-Native "git" @("rev-parse", "HEAD")).Trim()
        source_state = "commit5_candidate_with_tested_source_hashes"
        postgres_version = (Invoke-Native "docker" @("exec", "gateway-db-1", "postgres", "--version")).Trim()
        pg_dump_version = (Invoke-Native "docker" @("exec", "gateway-db-1", "pg_dump", "--version")).Trim()
        parser_name = "chatgpt-export"
        parser_version = "1"
        batch_contract_version = "1"
        sample_sha256 = $sampleHash
        dump_sha256 = $hostDumpHash
        tested_source_files = @(
            "app/importers/query.py",
            "app/importers/service.py",
            "app/importers/worker.py",
            "scripts/phase3_sample_acceptance.py"
        ) | ForEach-Object {
            $file = Join-Path $repoRoot $_
            [ordered]@{
                path = $_
                sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        files = $inventoryFiles
    }
    $inventory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backupRoot "inventory.json") -Encoding utf8

    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "createdb", "-U", "qingyu", "-T", "template0", $restoreDatabase
    ) | Out-Null
    $restoreIdentity = Invoke-Native "docker" @(
        "exec", "gateway-db-1", "psql", "-U", "qingyu", "-d", $restoreDatabase,
        "-Atc", "select current_database()"
    )
    if ($restoreIdentity.Trim() -ne $restoreDatabase) { throw "Restore DB identity mismatch" }
    Invoke-Native "docker" @(
        "exec", "gateway-db-1", "pg_restore", "-U", "qingyu", "-d", $restoreDatabase,
        "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges", $containerRestoreDump
    ) | Out-Null
    Copy-Item -LiteralPath (Join-Path $backupRoot "archive") -Destination (Join-Path $restoreRoot "archive") -Recurse
    Copy-Item -LiteralPath (Join-Path $backupRoot "manifests") -Destination (Join-Path $restoreRoot "manifests") -Recurse
    if (Test-Path -LiteralPath (Join-Path $restoreRoot "staging")) {
        throw "Restore root unexpectedly contains staging"
    }

    $env:DATABASE_URL = "postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/$restoreDatabase"
    $restoreRevision = (Invoke-Native $alembic @("current")).Trim()
    if ($restoreRevision -notmatch "0016_real_export_evidence") { throw "Restore revision mismatch" }
    Invoke-Native $alembic @("check") | Out-Null
    $unvalidatedForeignKeys = Invoke-Native "docker" @(
        "exec", "gateway-db-1", "psql", "-U", "qingyu", "-d", $restoreDatabase,
        "-Atc", "select count(*) from pg_constraint where contype = 'f' and not convalidated"
    )
    if ($unvalidatedForeignKeys.Trim() -ne "0") { throw "Restore has unvalidated foreign keys" }
    $restoreJson = (Invoke-Native $python @(
        (Join-Path $repoRoot "scripts\phase3_sample_acceptance.py"),
        "validate", "--root", $restoreRoot
    ) | Select-Object -Last 1)
    $restoreResult = $restoreJson | ConvertFrom-Json

    foreach ($field in @(
        "conversations", "nodes", "messages", "null_nodes", "roots", "branch_parents",
        "leaves", "current_nodes", "current_path_nodes", "attachments", "referenced_bytes",
        "raw_only_blobs", "evidence_digest", "archive_objects"
    )) {
        if ($sourceResult.$field -ne $restoreResult.$field) {
            throw "Source/restore mismatch: $field"
        }
    }
    if ($sourceResult.orphan_objects.Count -ne 0 -or $restoreResult.orphan_objects.Count -ne 0) {
        throw "Archive object orphan inventory is not empty"
    }

    $acceptance = [ordered]@{
        status = "PASS"
        source_database = $sourceDatabase
        restore_database = $restoreDatabase
        migration_0015 = $revision0015
        migration_head = $sourceRevision
        restore_revision = $restoreRevision
        source = $sourceResult
        restore = $restoreResult
        dump_sha256 = $inventory.dump_sha256
        staging_restored = $false
        foreign_keys_unvalidated = 0
    }
    $acceptance | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backupRoot "acceptance-result.json") -Encoding utf8
    $acceptance | ConvertTo-Json -Depth 8
}
finally {
    Remove-ExactDirectory $sourceRoot "D:\q5src"
    Remove-ExactDirectory $restoreRoot "D:\q5dst"
    Reset-Database $sourceDatabase
    Reset-Database $restoreDatabase
    Invoke-Native "docker" @("exec", "gateway-db-1", "rm", "-f", $containerDump, $containerRestoreDump) | Out-Null
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:API_TOKEN -ErrorAction SilentlyContinue
}
