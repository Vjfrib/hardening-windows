function Get-HW09State {
 param($Profile)
 $p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
 $v=Get-ItemProperty -LiteralPath $p -ErrorAction Stop
 $expected=@{EnableLUA=1;ConsentPromptBehaviorAdmin=2;PromptOnSecureDesktop=1}
 $actual=[ordered]@{}
 $complete=$true
 $matches=$true
 foreach ($name in @('EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop')) {
   $property=$v.PSObject.Properties[$name]
   $value=if ($null -ne $property -and $property.Value -is [int]) { $property.Value }
   if ($null -eq $value) { $complete=$false }
   if ($value -ne $expected[$name]) { $matches=$false }
   $actual[$name]=$value
 }
 $ok=if ($complete) { $matches }
 New-HWState -Id '09' -Name 'UAC com desktop seguro' -Current ([pscustomobject]$actual) -Expected $expected -Compliant $ok -Note 'As tres propriedades DWORD devem ser observadas antes de alterar. UAC pode exigir reinicio.'
}
function Set-HW09State {
 param($Profile)
 $p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
 $state=Get-HW09State -Profile $Profile
 if ($null -eq $state.Compliant) { throw 'Valor DWORD anterior ausente ou invalido. Revise a politica de UAC.' }
 foreach ($name in @('ConsentPromptBehaviorAdmin','PromptOnSecureDesktop','EnableLUA')) {
   if ($state.Current.$name -ne $state.Expected[$name]) {
     Set-ItemProperty -LiteralPath $p -Name $name -Value $state.Expected[$name] -Type DWord -ErrorAction Stop
   }
 }
}
function Test-HW09State {param($Profile) ((Get-HW09State -Profile $Profile).Compliant -eq $true)}
