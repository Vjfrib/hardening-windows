function Get-HW16State {
 param($Profile)
 $services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName)
 $dependencies=@(Get-Service -ErrorAction Stop | ForEach-Object {
   $required=@($_.ServicesDependedOn | Select-Object -ExpandProperty Name)
   if ($required.Count -gt 0) { [pscustomobject]@{Name=$_.Name;DependsOn=$required} }
 })
 $accounts=@($services | Where-Object {$_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService)|LocalService|NetworkService)$'} | Select-Object -First 50 Name,StartName,StartMode)
 New-HWState -Id '16' -Name 'Servicos e contas de servico' -Current ([pscustomobject]@{Services=$services;Dependencies=$dependencies;NonBuiltInAccountSample=$accounts}) -Expected 'Servicos e contas de servico revisados com dependencias e privilegios avaliados' -Compliant $null -Status 'RequiresReview' -Note 'Somente inventario de servicos, contas e dependencias. Qualquer alteracao exige revisao manual.'
}
function Set-HW16State {
 param($Profile)
 throw 'Controle 16: alteracoes de servicos e contas de servico exigem revisao manual.'
}
function Test-HW16State {param($Profile) $false}
