# Controle 03: Historico de senhas. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW03State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'PasswordHistorySize'
    $ok=if ($actual -gt 24) { $null } else { $null -ne $actual -and $actual -ge [int]$Profile.Password.HistoryCount }
    New-HWState -Id '03' -Name 'Historico de senhas' -Current ($actual) -Expected ([int]$Profile.Password.HistoryCount) -Compliant $ok -Note 'Politica local pode ser sobreposta por dominio/GPO; comparar estado efetivo.'
}
function Set-HW03State {
    param($Profile)
    Set-HWSecurityValues -Values @{PasswordHistorySize=[int]$Profile.Password.HistoryCount}
}
function Test-HW03State {
    param($Profile)
    return ((Get-HW03State -Profile $Profile).Compliant -eq $true)
}
