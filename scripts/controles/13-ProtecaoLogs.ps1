function Get-HW13State {
 param($Profile)
 $dir=Join-Path $env:SystemRoot 'System32\winevt\Logs'
 $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
 $p=Get-HWLocalPolicy -MergedPolicy
 $manager=if($p.ContainsKey('SeSecurityPrivilege')){$p['SeSecurityPrivilege']}else{'Indisponivel'}
 $channels=@(Get-WinEvent -ListLog Security,System -ErrorAction Stop |
   Select-Object LogName,SecurityDescriptor,LogMode,MaximumSizeInBytes)
 $clears=@(Get-HWEventSample -LogName Security -Id 1102; Get-HWEventSample -LogName System -Id 104)
 $current=[pscustomobject]@{
   LogDirectory=$dir
   Owner=[string]$acl.Owner
   Acl=@($acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited)
   SeSecurityPrivilege=$manager
   Channels=$channels
   ClearEventsLastSevenDays=$clears
 }
 New-HWState -Id '13' -Name 'Protecao dos logs e limpeza' -Current $current -Expected 'ACL/direito de limpeza restritos e coleta central aprovada' -Compliant $null -Status 'RequiresReview' -Note 'AUDIT-ONLY: nao modificar SDDL/ACL do EventLog sem preservar servicos e herancas. Eventos 1102 e 104 indicam limpeza quando ocorrerem.'
}
function Set-HW13State {param($Profile) throw 'Controle 13: modificar ACL/SDDL dos logs pode interromper o EventLog; requer politica aprovada e alteracao assistida.'}
function Test-HW13State {param($Profile) $false}
