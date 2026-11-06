# Controle 01: Comprimento minimo da senha. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW01State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'MinimumPasswordLength'
    $ok=($null -ne $actual -and $actual -ge [int]$Profile.Password.MinLength)
    New-HWState -Id '01' -Name 'Comprimento minimo da senha' -Current ($actual) -Expected ([int]$Profile.Password.MinLength) -Compliant $ok -Note 'Politica local pode ser sobreposta por dominio/GPO; comparar estado efetivo.'
}
function Set-HW01State {
    param($Profile)
    Set-HWSecurityValues -Values @{MinimumPasswordLength=[int]$Profile.Password.MinLength}
}
function Test-HW01State {
    param($Profile)
    return ((Get-HW01State -Profile $Profile).Compliant -eq $true)
}
