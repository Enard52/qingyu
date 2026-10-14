$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$deployment = 'C:\Program Files\Qingyu\ControlPlane\R1\Acceptance'
$evidence = 'C:\ProgramData\QingyuR1IdentityEvidence'
$source = '<repo>\core-r1-implementation'
$bundle = 'C:\ProgramData\QingyuR1Operator\CeremonyBundle'
$runtimeName = 'QingyuControlPlaneR1Acceptance'
$migratorName = 'QingyuControlPlaneR1AcceptanceMigrator'
$names = @($runtimeName, $migratorName)
$public = 'C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub'
$expected = 'e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1'
if ((Get-FileHash -LiteralPath $public -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Public fingerprint mismatch' }
if ((Get-FileHash -LiteralPath "$bundle\python-3.12.10-embeddable-amd64.zip" -Algorithm SHA256).Hash -ne '156C7EEA90D58CD7E91A23F28A0056616B13E9F4CF4901B7B99B837B7848C6DA') { throw 'Runtime archive mismatch' }
if (Test-Path -LiteralPath $deployment) { throw 'Deployment already exists; refuse overwrite' }
if (Test-Path -LiteralPath $evidence) { throw 'Evidence already exists; refuse overwrite' }
foreach ($name in $names) { if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Service already exists' } }
function AdminDirectory([string]$path) {
    if (!(Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
# Only newly created deployment ancestors may be initialized by this script.
$parents = @('C:\Program Files\Qingyu','C:\Program Files\Qingyu\ControlPlane','C:\Program Files\Qingyu\ControlPlane\R1')
foreach ($path in $parents) { if (Test-Path -LiteralPath $path) { throw "Existing deployment ancestor requires separate inspection: $path" } }
foreach ($path in ($parents + @($deployment,$evidence))) { AdminDirectory $path }
$filePaths = @('C:\ProgramData\Qingyu','C:\ProgramData\Qingyu\ControlPlane','C:\ProgramData\Qingyu\ControlPlane\R1',$public)
$regPaths = @('SOFTWARE\Qingyu','SOFTWARE\Qingyu\ControlPlane','SOFTWARE\Qingyu\ControlPlane\R1','SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot','SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly')
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
function PinValues {
    $key = $base.OpenSubKey($regPaths[-1])
    try { $v = [ordered]@{}; foreach ($n in ($key.GetValueNames() | Sort-Object)) { $v[$n] = @{value=$key.GetValue($n);kind=$key.GetValueKind($n).ToString()} }; return $v } finally { $key.Dispose() }
}
$pinBefore = PinValues | ConvertTo-Json -Depth 5 -Compress
$before = [ordered]@{files=@{};registry=@{};public_sha256=$expected;pin_values=(PinValues)}
foreach ($p in $filePaths) { $before.files[$p] = (Get-Acl -LiteralPath $p).Sddl }
foreach ($p in $regPaths) { $key=$base.OpenSubKey($p); try {$before.registry[$p]=$key.GetAccessControl().Sddl} finally {$key.Dispose()} }
$before | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$evidence\acl-before.json" -Encoding UTF8
Expand-Archive -LiteralPath "$bundle\python-3.12.10-embeddable-amd64.zip" -DestinationPath "$deployment\runtime"
Copy-Item -LiteralPath "$bundle\vendor" -Destination "$deployment\vendor" -Recurse
Copy-Item -LiteralPath '<home>\AppData\Local\Temp\qingyu-r1-protocol-test\Lib\site-packages\rfc8785' -Destination "$deployment\vendor\rfc8785" -Recurse
New-Item -ItemType Directory -Path "$deployment\app\control_plane" -Force | Out-Null
foreach ($f in @('__init__.py','canonical.py','errors.py')) { Copy-Item -LiteralPath "$source\app\$f" -Destination "$deployment\app\$f" }
foreach ($f in @('__init__.py','authority.py','r1_protocol.py','r1_root_pin.py','r1_windows_acl.py','r1_provisioning.py','r1_schema_snapshot.py','r1_schema.py')) { Copy-Item -LiteralPath "$source\app\control_plane\$f" -Destination "$deployment\app\control_plane\$f" }
Copy-Item -LiteralPath "$source\tools\r1_windows_identity\probe.py" -Destination "$deployment\probe.py"
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /target:exe /reference:System.ServiceProcess.dll "/out:$deployment\ServiceHost.exe" "$source\tools\r1_windows_identity\ServiceHost.cs"
if ($LASTEXITCODE -ne 0) { throw 'Service host compilation failed' }
foreach ($cache in (Get-ChildItem -LiteralPath $deployment -Recurse -File -Filter '*.pyc')) {
    if (!$cache.FullName.StartsWith($deployment + '\',[StringComparison]::OrdinalIgnoreCase) -or $cache.Directory.Name -ne '__pycache__') { throw 'Unexpected bytecode location' }
    Remove-Item -LiteralPath $cache.FullName
}
$sids = @{}
foreach ($name in $names) {
    $role = if ($name -eq $runtimeName) {'runtime'} else {'migrator'}
    & sc.exe create $name binPath= ('"' + $deployment + '\ServiceHost.exe" ' + $role) start= demand obj= "NT SERVICE\$name" DisplayName= $name
    if ($LASTEXITCODE -ne 0) { throw 'Service creation failed' }
    & sc.exe sidtype $name unrestricted
    if ($LASTEXITCODE -ne 0) { throw 'Service SID configuration failed' }
    & sc.exe privs $name SeChangeNotifyPrivilege
    if ($LASTEXITCODE -ne 0) { throw 'Service privileges configuration failed' }
    $sids[$name] = ([Security.Principal.NTAccount]::new('NT SERVICE',$name)).Translate([Security.Principal.SecurityIdentifier])
    AdminDirectory "$evidence\$name"
    $acl=Get-Acl -LiteralPath "$evidence\$name"
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sids[$name], 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath "$evidence\$name" -AclObject $acl
}
foreach ($path in ($filePaths + $parents + @($deployment,$evidence))) {
    $acl=Get-Acl -LiteralPath $path
    foreach ($sid in $sids.Values) {
        if ($path -eq $deployment) {
            $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
        } elseif ($path -eq $public) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'Read','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','Allow') }
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
foreach ($path in $regPaths) {
    $key=$base.OpenSubKey($path,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::ChangePermissions -bor [Security.AccessControl.RegistryRights]::ReadPermissions)
    try { $acl=$key.GetAccessControl(); foreach ($sid in $sids.Values) {$acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid,'ReadKey','None','None','Allow'))}; $key.SetAccessControl($acl) } finally {$key.Dispose()}
}
if ((Get-FileHash -LiteralPath $public -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Public changed' }
if ((PinValues | ConvertTo-Json -Depth 5 -Compress) -cne $pinBefore) { throw 'Pin values changed' }
$after = [ordered]@{files=@{};registry=@{};identities=@{};public_sha256=$expected;pin_values=(PinValues)}
foreach ($p in $filePaths) {$after.files[$p]=(Get-Acl -LiteralPath $p).Sddl}
foreach ($p in $regPaths) {$key=$base.OpenSubKey($p);try {$after.registry[$p]=$key.GetAccessControl().Sddl} finally {$key.Dispose()}}
foreach ($n in $names) {$after.identities[$n]=$sids[$n].Value}
$after | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$evidence\acl-after.json" -Encoding UTF8
$files=[ordered]@{}
foreach ($f in (Get-ChildItem -LiteralPath $deployment -File -Recurse | Sort-Object FullName)) {$rel=$f.FullName.Substring($deployment.Length+1).Replace('\','/');$files[$rel]=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
@{files=$files} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$deployment\manifest.json" -Encoding UTF8
Copy-Item -LiteralPath "$deployment\manifest.json" -Destination "$evidence\deployment-manifest.json"
$base.Dispose()
Write-Output 'PREPARED; services have not been started.'
