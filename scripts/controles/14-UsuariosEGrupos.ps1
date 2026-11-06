$script:HW14Guids=@('0cce9235-69ae-11d9-bed3-505054503030','0cce9237-69ae-11d9-bed3-505054503030')
function Get-HW14State {
 param($Profile)
 $policy=Get-HWLocalPolicy -MergedPolicy
 $rights=@{}
 foreach($key in @('SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege')){$rights[$key]=if($policy.ContainsKey($key)){$policy[$key]}else{$null}}
 $audits=@(); foreach($guid in $script:HW14Guids){$audits+= [pscustomobject]@{GUID=$guid;Setting=(Get-HWAuditSetting -Guid $guid)}}
 $auditOK=(@($audits | Where-Object {$_.Setting -ne 3}).Count -eq 0)
 $administrators=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
 $members=@(Get-LocalGroupMember -SID $administrators -ErrorAction Stop |
   ForEach-Object { [pscustomobject]@{SID=$_.SID.Value;ObjectClass=$_.ObjectClass} })
 New-HWState -Id '14' -Name 'Direitos de usuarios/grupos e auditoria' -Current ([pscustomobject]@{Privileges=$rights;Administrators=$members;AuditSubcategories=$audits}) -Expected 'Direitos sensiveis revisados; auditoria de contas/grupos ativa' -Compliant $null -Status 'RequiresReview' -Note "Somente auditoria pode ser ativada automaticamente; privilegios exigem revisao de dependencias. Auditoria conforme: $auditOK."
}
function Set-HW14State {
 param($Profile)
 foreach ($guid in $script:HW14Guids) {
   if ((Get-HWAuditSetting -Guid $guid) -ne 3) { Set-HWAuditSetting -Guid $guid }
 }
}
function Test-HW14State {param($Profile) $s=Get-HW14State -Profile $Profile; (@($s.Current.AuditSubcategories | Where-Object {$_.Setting -ne 3}).Count -eq 0)}
