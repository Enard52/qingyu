param([Parameter(Mandatory=$true)][string]$SealedDirectory)
$ErrorActionPreference = 'Stop'
$evidence='C:\ProgramData\QingyuR1IdentityEvidence'
$deployment='C:\Program Files\Qingyu\ControlPlane\R1\Acceptance'
$root=Get-Content -Raw -LiteralPath "$evidence\acl-before.json" | ConvertFrom-Json
$after=Get-Content -Raw -LiteralPath "$evidence\acl-after.json" | ConvertFrom-Json
$sids=@($after.identities.PSObject.Properties.Value)
if ($sids.Count -ne 2) { throw 'Expected exact service SIDs' }
$checks=@()
function CheckDelta($name,$beforeSddl,$afterSddl,$readMask) {
    $b=[Security.AccessControl.RawSecurityDescriptor]::new($beforeSddl)
    $a=[Security.AccessControl.RawSecurityDescriptor]::new($afterSddl)
    $flagDelta=[int]$b.ControlFlags -bxor [int]$a.ControlFlags
    # Windows SetSecurityInfo marks the recomputed ACL AUTO_INHERITED. This
    # bookkeeping bit is not DACL_PROTECTED and does not grant any access.
    # Require all original ACE bytes and all other control bits unchanged.
    if ($b.Owner.Value -cne $a.Owner.Value -or $b.Group.Value -cne $a.Group.Value -or
        ($flagDelta -ne 0 -and ($flagDelta -ne 0x400 -or (([int]$a.ControlFlags -band 0x400) -eq 0)))) { throw 'Existing descriptor metadata changed' }
    function AceKey($ace) {
        $bytes=New-Object byte[] $ace.BinaryLength
        $ace.GetBinaryForm($bytes,0)
        [Convert]::ToBase64String($bytes)
    }
    $remaining=[Collections.Generic.List[string]]::new()
    foreach ($ace in $a.DiscretionaryAcl) { $remaining.Add((AceKey $ace)) }
    foreach ($ace in $b.DiscretionaryAcl) {
        if (!$remaining.Remove((AceKey $ace))) { throw 'Existing ACE altered or removed' }
    }
    if ($remaining.Count -ne 2) { throw 'Unexpected added ACE count' }
    foreach ($sid in $sids) {
        $expected=[Security.AccessControl.CommonAce]::new('None','AccessAllowed',$readMask,[Security.Principal.SecurityIdentifier]::new($sid),$false,$null)
        if (!$remaining.Remove((AceKey $expected))) { throw 'ACL addition exceeded precise read grant' }
    }
    [ordered]@{path=$name;added_exact_read_aces=2;existing_aces_preserved=$true;owner_and_protection_unchanged=$true;auto_inherited_marker_added=($flagDelta -eq 0x400)}
}
foreach ($p in $root.files.PSObject.Properties) {
    $readMask=if ($p.Name.EndsWith('.pub')) {0x120089} else {0x1200a9}
    $current=(Get-Acl -LiteralPath $p.Name).Sddl
    if ($current -cne $after.files.PSObject.Properties[$p.Name].Value) { throw 'File ACL drift since remediation' }
    $checks+=CheckDelta $p.Name $p.Value $current $readMask
}
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
try {
    foreach ($p in $root.registry.PSObject.Properties) {
        $key=$base.OpenSubKey($p.Name)
        try {$current=$key.GetAccessControl().Sddl} finally {$key.Dispose()}
        if ($current -cne $after.registry.PSObject.Properties[$p.Name].Value) { throw 'Registry ACL drift' }
        $checks+=CheckDelta $p.Name $p.Value $current 0x20019
    }
    $key=$base.OpenSubKey('SOFTWARE\Qingyu\ControlPlane\R1\OperatorRoot\AcceptanceTestOnly')
    try {
        if ($key.ValueCount -ne 4) { throw 'Unexpected pin fields' }
        foreach ($p in $root.pin_values.PSObject.Properties) {
            if ($key.GetValue($p.Name) -cne $p.Value.value -or $key.GetValueKind($p.Name).ToString() -cne $p.Value.kind) { throw 'Pin identity/type drift' }
        }
    } finally {$key.Dispose()}
} finally {$base.Dispose()}
$public='C:\ProgramData\Qingyu\ControlPlane\R1\operator-root-acceptance-test-only.pub'
if ((Get-FileHash -LiteralPath $public -Algorithm SHA256).Hash.ToLowerInvariant() -cne $root.public_sha256) { throw 'Public byte drift' }
$source='<repo>\core-r1-implementation'
foreach ($file in (Get-ChildItem -LiteralPath "$deployment\app" -Recurse -File -Filter '*.py')) {
    $rel=$file.FullName.Substring($deployment.Length+1)
    if ((Get-FileHash -LiteralPath $file.FullName).Hash -cne (Get-FileHash -LiteralPath "$source\$rel").Hash) { throw 'Deployed application differs from implementation source' }
}
if ((Get-FileHash -LiteralPath "$deployment\probe.py").Hash -cne (Get-FileHash -LiteralPath "$PSScriptRoot\probe.py").Hash) { throw 'Probe source mismatch' }
$serviceAcls=@{}
foreach ($name in @('QingyuControlPlaneR1Acceptance','QingyuControlPlaneR1AcceptanceMigrator')) {
    $serviceAcls[$name]=(Get-Acl -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$name").Sddl
}
$result=[ordered]@{passed=$true;public_bytes_unchanged=$true;pin_names_types_values_unchanged=$true;source_deployment_match=$true;canonical_acl_changes=$checks;service_registry_acls=$serviceAcls;sealed_evidence_acl=(Get-Acl -LiteralPath $SealedDirectory).Sddl;private_key_bytes_read=$false}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$SealedDirectory\state-audit.json" -Encoding UTF8
Write-Output 'Exact read-only ACL delta, unchanged public/pin, protected evidence and deployed source checks PASS.'
