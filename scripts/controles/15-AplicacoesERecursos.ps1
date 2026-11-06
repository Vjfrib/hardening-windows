function Get-HW15State {
 param($Profile)
 $features=@()
 if(Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue){
   foreach($name in @($Profile.OptionalFeatures.Candidates)){
     try { $f=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop; $features+= [pscustomobject]@{Name=$f.FeatureName;State=[string]$f.State} }
     catch { $features+= [pscustomobject]@{Name=$name;State='IndisponivelOuAusente'} }
   }
 }
 $apps=@()
 foreach($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
   try { $apps+=@(Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object -First 50 DisplayName,DisplayVersion) } catch {}
 }
 New-HWState -Id '15' -Name 'Aplicacoes e recursos desnecessarios' -Current ([pscustomobject]@{Candidates=$features;InstalledAppsSample=$apps}) -Expected 'Somente recursos aprovados; avaliar SMB1, Telnet, TFTP se presentes' -Compliant $null -Status 'RequiresReview' -Note 'Inventario nao prova desnecessidade. Somente features da allowlist sao desabilitadas; apps de terceiros nao sao removidos.'
}
function Set-HW15State {
 param($Profile,[string[]]$ApprovedFeatures)
 if (@($ApprovedFeatures | Where-Object { $_ }).Count -eq 0) {
   throw 'Selecione nominalmente os recursos no arquivo de aprovacoes.'
 }
 $allowed=@($Profile.OptionalFeatures.ApprovedToDisable)
 $targets=@(foreach ($name in ($ApprovedFeatures | Sort-Object -Unique)) {
   if ([string]::IsNullOrWhiteSpace($name) -or $name -notin $allowed -or $name -notin @($Profile.OptionalFeatures.Candidates)) {
     throw "Recurso sem aprovacao nominal no perfil e no arquivo de aprovacoes: $name"
   }
   $f=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
   if ([string]$f.State -notin @('Enabled','Disabled','DisabledWithPayloadRemoved')) {
     throw "Estado pendente ou indisponivel para ${name}: $($f.State)."
   }
   if ([string]$f.State -eq 'Enabled') { $name }
 })
 foreach ($name in $targets) {
   $current=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
   if ([string]$current.State -ne 'Enabled') {
     throw "Estado mudou desde a leitura para ${name}: $($current.State)."
   }
   $result=Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop
   if ($result.RestartNeeded) { Write-Warning "O recurso $name exige reinicializacao para concluir a mudanca." }
 }
}
function Test-HW15State {
 param($Profile,[string[]]$ApprovedFeatures)
 if (@($ApprovedFeatures | Where-Object { $_ }).Count -eq 0) { return $false }
 foreach ($name in $ApprovedFeatures) {
   $feature=Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
   if ([string]$feature.State -notin @('Disabled','DisabledWithPayloadRemoved','DisablePending')) { return $false }
 }
 return $true
}
