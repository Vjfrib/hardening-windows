$script:HW11Guid='0cce9215-69ae-11d9-bed3-505054503030'
function Get-HW11State {
 param($Profile)
 $val=Get-HWAuditSetting -Guid $script:HW11Guid
 $events=@(Get-HWEventSample -LogName Security -Id 4624,4625,4740)
 $current=[pscustomobject]@{Setting=$val;EventsLastSevenDays=$events}
 New-HWState -Id '11' -Name 'Auditoria de logon' -Current $current -Expected 3 -Compliant ($val -eq 3) -Note 'Leitura por GUID via AuditQuerySystemPolicy. A amostra de eventos tem ate 1000 registros sem mensagem ou dados de conta.'
}
function Set-HW11State {param($Profile) Set-HWAuditSetting -Guid $script:HW11Guid}
function Test-HW11State {param($Profile) ((Get-HW11State -Profile $Profile).Compliant -eq $true)}
