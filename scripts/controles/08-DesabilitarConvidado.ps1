function Get-HW08State {
 param($Profile)
 $guest=Get-HWLocalUserByRid -Rid 501
 if (-not $guest) { return (New-HWState -Id '08' -Name 'Desabilitar Convidado' -Current $null -Expected 'Desabilitado' -Compliant $null -Status 'NotSupported' -Note 'Conta RID 501 nao encontrada.') }
 New-HWState -Id '08' -Name 'Desabilitar Convidado' -Current ([pscustomobject]@{SID=$guest.SID.Value;Enabled=$guest.Enabled}) -Expected 'Enabled=False' -Compliant (-not $guest.Enabled) -Note 'Detecta conta integrada por SID, independentemente do nome localizado.'
}
function Set-HW08State {param($Profile) $guest=Get-HWLocalUserByRid -Rid 501; if(-not $guest){throw 'RID 501 nao localizado.'}; if($guest.Enabled){Disable-LocalUser -SID $guest.SID -ErrorAction Stop} }
function Test-HW08State {param($Profile) ((Get-HW08State -Profile $Profile).Compliant -eq $true)}
