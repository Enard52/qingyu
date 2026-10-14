$ErrorActionPreference='Stop'
$repo='<repo>\core-r1-implementation'
$out=Join-Path $repo 'docs\evidence\r1-core-invariants\baseline'
if (Test-Path -LiteralPath $out) { throw 'Baseline already captured; refuse replacement' }
New-Item -ItemType Directory -Path $out -Force | Out-Null
Push-Location $repo
try {
    $files=@(& git ls-files --cached --others --exclude-standard | Sort-Object -Unique)
    $hashes=[ordered]@{}
    foreach($f in $files) {
        if($f.StartsWith('docs/evidence/r1-core-invariants/')) { continue }
        $path=Join-Path $repo $f
        if(Test-Path -LiteralPath $path -PathType Leaf) {$hashes[$f]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    $record=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');head=(& git rev-parse HEAD);branch=(& git branch --show-current);status=@(& git status --short);source_hashes=$hashes;original_core_diff_object='9594b6b6f5374094a88bcb068d5bcd7afd875d18';public_fingerprint='e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1';pin=@{PinVersion=1;Profile='R1_ACCEPTANCE_TEST_ONLY';TestOnly=1;PublicKeyId='e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1'}}
    $record|ConvertTo-Json -Depth 6|Set-Content -LiteralPath "$out\inventory.json" -Encoding UTF8
    & git diff --binary | Set-Content -LiteralPath "$out\tracked-before.diff" -Encoding UTF8
    foreach($f in @('app/services.py','app/control_plane/authority.py','app/control_plane/r1_client.py','app/models.py','app/schemas.py')) {
        Copy-Item -LiteralPath (Join-Path $repo $f) -Destination (Join-Path $out ($f.Replace('/','__')+'.txt'))
    }
    Write-Output 'Baseline captured. Product workers may now start.'
} finally {Pop-Location}
