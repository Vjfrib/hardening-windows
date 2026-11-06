# Identificacao pela SID/RID 500; o nome muda, mas o SID permanece.
function Get-HW07State {
 param($Profile)
 $user=Get-HWLocalUserByRid -Rid 500
 if (-not $user) { return (New-HWState -Id '07' -Name 'Renomear Administrador' -Current $null -Expected 'Nome nao obvio' -Compliant $null -Status 'NotSupported' -Note 'Conta RID 500 nao encontrada.') }
 $name=[string]$Profile.Accounts.AdministratorNewName
 $valid=-not [string]::IsNullOrWhiteSpace($name) -and $name -notmatch '^(Administrator|Administrador|Admin|definir-aqui)$'
 $recovery=@(Get-HWRecoveryAdministratorSid -Administrator $user)
 $state=[pscustomobject]@{SID=$user.SID.Value;Name=$user.Name;Enabled=$user.Enabled;EnabledRecoverySIDs=$recovery}
 $ok=if ($valid -and ($user.Name -eq $name -or $recovery.Count -gt 0)) { $user.Name -eq $name }
 New-HWState -Id '07' -Name 'Renomear Administrador' -Current $state -Expected $(if($valid){$name}else{'Nome a definir'}) -Compliant $ok -Note 'Exige novo nome aprovado e outra conta administradora local habilitada com acesso de recuperacao confirmado.'
}
function Set-HW07State {
 param($Profile,[bool]$RecoveryAccessConfirmed)
 $name=[string]$Profile.Accounts.AdministratorNewName
 if ([string]::IsNullOrWhiteSpace($name) -or $name -match '^(Administrator|Administrador|Admin|definir-aqui)$') { throw 'Defina Accounts.AdministratorNewName com nome nao obvio e aprovado.' }
 $user=Get-HWLocalUserByRid -Rid 500
 if(-not $user){throw 'RID 500 nao localizado.'}
 if($user.Name -eq $name){return}
 if(-not $RecoveryAccessConfirmed -or @(Get-HWRecoveryAdministratorSid -Administrator $user).Count -eq 0){
   throw 'Confirme acesso de recuperacao por outra conta administradora local habilitada.'
 }
 if(Get-LocalUser -Name $name -ErrorAction SilentlyContinue){throw "Ja existe conta $name"}
 Rename-LocalUser -SID $user.SID -NewName $name -ErrorAction Stop
}
function Test-HW07State {param($Profile) ((Get-HW07State -Profile $Profile).Compliant -eq $true)}
