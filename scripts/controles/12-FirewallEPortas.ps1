function Get-HW12State {
 param($Profile)
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Name -in @('Domain','Private','Public')})
 $summary=@($profiles | Select-Object Name,Enabled,DefaultInboundAction)
 $local=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction)
 $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
   Select-Object Name,DisplayName,Enabled,Profile,Direction,Action,PolicyStoreSourceType)
 $ports=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object State -eq Listen |
   Sort-Object LocalPort,LocalAddress | Select-Object LocalAddress,LocalPort,OwningProcess)
 $udp=@(Get-NetUDPEndpoint -ErrorAction Stop |
   Sort-Object LocalPort,LocalAddress | Select-Object LocalAddress,LocalPort,OwningProcess)
 $bad=@($profiles | Where-Object { ([string]$_.Enabled -ne 'True') -or ([string]$_.DefaultInboundAction -ne 'Block') })
 $current=[pscustomobject]@{
   ActiveProfiles=$summary
   PersistentProfiles=$local
   EffectiveRules=$rules
   ListeningTcpPorts=$ports
   UdpEndpoints=$udp
 }
 $note=if ($profiles.Count -eq 3 -and $bad.Count -eq 0) {
   'Perfis efetivos habilitados com entrada bloqueada por padrao. Revise regras, portas e excecoes.'
 } else {
   'Um ou mais perfis efetivos nao apresentam a configuracao esperada. Revise regras, portas e excecoes.'
 }
 New-HWState -Id '12' -Name 'Firewall e portas em escuta' -Current $current -Expected 'Domain/Private/Public Enabled=True, DefaultInboundAction=Block; revisar excecoes' -Compliant $null -Note $note
}
function Set-HW12State {
 param($Profile)
 throw 'Controle 12: alteracoes de firewall e portas exigem revisao manual.'
}
function Test-HW12State {param($Profile) $false}
