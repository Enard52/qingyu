$ErrorActionPreference = 'Stop'
$deployment = 'C:\Program Files\Qingyu\ControlPlane\R1\Acceptance'
$evidence = 'C:\ProgramData\QingyuR1IdentityEvidence'
$names = @('QingyuControlPlaneR1Acceptance','QingyuControlPlaneR1AcceptanceMigrator')
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
$sealed = Join-Path $evidence "sealed-$stamp"
New-Item -ItemType Directory -Path $sealed | Out-Null
function VerifyManifest {
    $m=Get-Content -Raw -LiteralPath "$deployment\manifest.json" | ConvertFrom-Json
    $files=@(Get-ChildItem -LiteralPath $deployment -Recurse -File | Where-Object FullName -ne "$deployment\manifest.json")
    if ($files.Count -ne @($m.files.PSObject.Properties).Count) { throw 'File set mismatch' }
    foreach ($f in $files) {
        $rel=$f.FullName.Substring($deployment.Length+1).Replace('\','/')
        $p=$m.files.PSObject.Properties[$rel]
        if ($null -eq $p -or (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $p.Value) { throw 'Deployed digest mismatch' }
    }
    return (Get-FileHash -LiteralPath "$deployment\manifest.json" -Algorithm SHA256).Hash.ToLowerInvariant()
}
$before=VerifyManifest
Copy-Item -LiteralPath "$deployment\manifest.json" -Destination "$sealed\manifest.json"
$observed=@()
foreach ($name in $names) {
    if ((Get-Service -Name $name).Status -ne 'Stopped') { throw 'Unexpected active acceptance service' }
    $started=[DateTime]::UtcNow
    Start-Service -Name $name
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    $servicePid=0
    $probePid=0
    while ([DateTime]::UtcNow -lt $deadline) {
        $service=Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($service.ProcessId -gt 0) { $servicePid=$service.ProcessId }
        if ($servicePid -gt 0) {
            $processes=@(Get-CimInstance Win32_Process -Filter "ProcessId=$servicePid OR ParentProcessId=$servicePid")
            foreach ($process in $processes) {
                if ($process.ExecutablePath -notlike "$deployment\*") { throw 'Unexpected observed executable' }
                $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
                if ($owner.ReturnValue -ne 0) { continue }
                if ($process.Name -eq 'python.exe') { $probePid=$process.ProcessId }
                $observed += [ordered]@{service=$name;pid=$process.ProcessId;parent_pid=$process.ParentProcessId;executable=$process.ExecutablePath;command_line=$process.CommandLine;owner_sid=$owner.Sid;creation_date=$process.CreationDate;observed_utc=[DateTime]::UtcNow.ToString('o')}
            }
        }
        if ($probePid -gt 0) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($probePid -eq 0) { throw 'Independent live probe observation missing' }
    $controller=Get-Service -Name $name
    $controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(50))
    $status=Get-Content -Raw -LiteralPath "$evidence\$name\host-status.json" | ConvertFrom-Json
    if ($status.outcome -ne 'completed' -or [DateTime]$status.utc -lt $started) { throw 'No fresh successful probe completion' }
    $result=Get-Content -Raw -LiteralPath "$evidence\$name\result.json" | ConvertFrom-Json
    if ($result.process.pid -ne $probePid -or $result.process.parent_pid -ne $servicePid) { throw 'Probe PID correlation failed' }
    Copy-Item -LiteralPath "$evidence\$name\result.json" -Destination "$sealed\$name.json"
    Copy-Item -LiteralPath "$evidence\$name\host-status.json" -Destination "$sealed\$name-host.json"
    foreach ($pair in @(@("$evidence\$name\result.json","$sealed\$name.json"),@("$evidence\$name\host-status.json","$sealed\$name-host.json"))) {
        if ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash) { throw 'Evidence copy digest mismatch' }
    }
    (& sc.exe qc $name),(& sc.exe qprivs $name),(& sc.exe qsidtype $name),(& sc.exe sdshow $name) | Set-Content -LiteralPath "$sealed\$name-scm.txt" -Encoding UTF8
}
& "$deployment\runtime\python.exe" -I "$deployment\probe.py" operator | Set-Content -LiteralPath "$sealed\operator.json" -Encoding UTF8
if ($LASTEXITCODE -ne 0) { throw 'Operator probe failed' }
if ((VerifyManifest) -cne $before) { throw 'Deployment changed during acceptance' }
$observed | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$sealed\observed-processes.json" -Encoding UTF8
$custody='C:\ProgramData\QingyuR1Operator\AcceptanceTestOnly\operator-root-encrypted.pem'
@{manifest_sha256=$before;completed_utc=[DateTime]::UtcNow.ToString('o');private_acl=(Get-Acl -LiteralPath $custody).Sddl;private_metadata_only=$true} | ConvertTo-Json | Set-Content -LiteralPath "$sealed\capture.json" -Encoding UTF8
Write-Output $sealed
