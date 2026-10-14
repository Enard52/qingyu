$ErrorActionPreference = 'Stop'
$repo = '<repo>\core-r1-implementation'
$out = Join-Path $repo 'docs\evidence\r1-f3-coordinator\baseline'
if (Test-Path -LiteralPath $out) { throw 'F3 baseline already exists; refusing replacement' }
New-Item -ItemType Directory -Path $out -Force | Out-Null
Push-Location $repo
try {
    $files = @(& git ls-files --cached --others --exclude-standard | Sort-Object -Unique)
    $hashes = [ordered]@{}
    foreach ($relative in $files) {
        if ($relative.StartsWith('docs/evidence/r1-f3-coordinator/')) { continue }
        $source = Join-Path $repo $relative
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            $hashes[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    [ordered]@{
        captured_utc = [DateTime]::UtcNow.ToString('o')
        head = (& git rev-parse HEAD)
        branch = (& git branch --show-current)
        status = @(& git status --short)
        source_hashes = $hashes
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'inventory.json') -Encoding UTF8
    & git diff --binary --no-ext-diff --no-textconv | Set-Content -LiteralPath (Join-Path $out 'tracked-before.diff') -Encoding UTF8
    foreach ($relative in @('app/audit.py','app/services.py','app/config.py','app/main.py','app/control_plane/authority.py','app/control_plane/r1_client.py','app/control_plane/r1_protocol.py','app/control_plane/r1_schema.py','app/control_plane/r1_schema_snapshot.py')) {
        Copy-Item -LiteralPath (Join-Path $repo $relative) -Destination (Join-Path $out ($relative.Replace('/','__') + '.txt'))
    }
    Write-Output 'F3 baseline recorded; prior changes preserved.'
} finally { Pop-Location }
