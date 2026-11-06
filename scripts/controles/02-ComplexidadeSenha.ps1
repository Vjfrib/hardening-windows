# Controle 02: Complexidade da senha. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW02State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'PasswordComplexity'
    $ok=($null -ne $actual -and $actual -eq [int][bool]$Profile.Password.ComplexityEnabled)
    New-HWState -Id '02' -Name 'Complexidade da senha' -Current ($actual) -Expected ([int][bool]$Profile.Password.ComplexityEnabled) -Compliant $ok -Note 'Politica local pode ser sobreposta por dominio/GPO; comparar estado efetivo.'
}
function Set-HW02State {
    param($Profile)
    Set-HWSecurityValues -Values @{PasswordComplexity=[int][bool]$Profile.Password.ComplexityEnabled}
}
function Test-HW02State {
    param($Profile)
    return ((Get-HW02State -Profile $Profile).Compliant -eq $true)
}
