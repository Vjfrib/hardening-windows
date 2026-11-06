function Get-HW10State {
 param($Profile)
 $p=Get-HWLocalPolicy -MergedPolicy
 $current=[pscustomobject]@{
   SeDenyNetworkLogonRight=$p['SeDenyNetworkLogonRight']
   SeDenyRemoteInteractiveLogonRight=$p['SeDenyRemoteInteractiveLogonRight']
   DomainMember=Test-HWDomainMember
   SessionName=$env:SESSIONNAME
   RemotePowerShell=($null -ne (Get-Variable -Name PSSenderInfo -ValueOnly -ErrorAction SilentlyContinue))
 }
 New-HWState -Id '10' -Name 'Logon de rede de contas locais' -Current $current -Expected 'Negacao a contas locais, com excecoes e acesso remoto aprovados' -Compliant $null -Status 'RequiresReview' -Note 'Somente auditoria. Mudancas podem bloquear RDP, SMB, WinRM e administracao legitima.'
}
function Set-HW10State {param($Profile) throw 'Controle 10: configuracao deliberadamente manual; exige projeto de acesso remoto aprovado.'}
function Test-HW10State {param($Profile) $false}
