# Operator-only update of reviewed acceptance harness, never trust material.
$ErrorActionPreference = 'Stop'
$deployment = 'C:\Program Files\Qingyu\ControlPlane\R1\Acceptance'
$evidence = 'C:\ProgramData\QingyuR1IdentityEvidence'
foreach ($n in @('QingyuControlPlaneR1Acceptance','QingyuControlPlaneR1AcceptanceMigrator')) {
    if ((Get-Service -Name $n).Status -ne 'Stopped') { throw 'Stop acceptance services before deployment update' }
}
# Keep prior evidence, including failed probes, in an operator-controlled history.
$history = Join-Path $evidence ('history-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
New-Item -ItemType Directory -Path $history | Out-Null
Copy-Item -LiteralPath "$deployment\manifest.json" -Destination "$history\manifest.json"
foreach ($n in @('QingyuControlPlaneR1Acceptance','QingyuControlPlaneR1AcceptanceMigrator')) {
    foreach ($file in @('result.json','host-status.json')) {
        $p = "$evidence\$n\$file"
        if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination "$history\$n-$file" }
    }
}
Copy-Item -LiteralPath "$PSScriptRoot\probe.py" -Destination "$deployment\probe.py" -Force
foreach ($file in @('__init__.py','authority.py','r1_protocol.py','r1_root_pin.py','r1_windows_acl.py','r1_provisioning.py','r1_schema_snapshot.py','r1_schema.py')) {
    Copy-Item -LiteralPath "$PSScriptRoot\..\..\app\control_plane\$file" -Destination "$deployment\app\control_plane\$file" -Force
}
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /target:exe /reference:System.ServiceProcess.dll "/out:$deployment\ServiceHost.exe" "$PSScriptRoot\ServiceHost.cs"
if ($LASTEXITCODE -ne 0) { throw 'Compile failed' }
# Discard only generated cache files in this exact new acceptance deployment.
# Source and embedded standard-library archive remain the canonical inputs.
foreach ($cache in (Get-ChildItem -LiteralPath $deployment -Recurse -File -Filter '*.pyc')) {
    if (!$cache.FullName.StartsWith($deployment + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Cache outside deployment' }
    if ($cache.Directory.Name -ne '__pycache__') { throw 'Unexpected bytecode location' }
    Remove-Item -LiteralPath $cache.FullName
}
$files=[ordered]@{}
foreach ($f in (Get-ChildItem -LiteralPath $deployment -File -Recurse | Sort-Object FullName)) {
    if ($f.FullName -eq "$deployment\manifest.json") { continue }
    $rel=$f.FullName.Substring($deployment.Length+1).Replace('\','/')
    $files[$rel]=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
@{files=$files} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$deployment\manifest.json" -Encoding UTF8
Copy-Item -LiteralPath "$deployment\manifest.json" -Destination "$evidence\deployment-manifest.json" -Force
Write-Output 'Reviewed harness refreshed; prior evidence retained.'
