# Controle 04: Duracao maxima da senha. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW04State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'MaximumPasswordAge'
    $minimum=Get-HWPolicyInt -Policy $policy -Key 'MinimumPasswordAge'
    $ok=if ($null -eq $minimum -or $minimum -lt 0) { $null } else { $null -ne $actual -and $actual -gt 0 -and $actual -gt $minimum -and $actual -le [int]$Profile.Password.MaxAgeDays }
    New-HWState -Id '04' -Name 'Duracao maxima da senha' -Current ([pscustomobject]@{MaximumPasswordAge=$actual;MinimumPasswordAge=$minimum}) -Expected ([int]$Profile.Password.MaxAgeDays) -Compliant $ok -Note 'A idade maxima deve ser superior a minima. A politica local pode ser sobreposta por dominio/GPO.'
}
function Set-HW04State {
    param($Profile)
    $target=[int]$Profile.Password.MaxAgeDays
    $minimum=Get-HWPolicyInt -Policy (Get-HWLocalPolicy) -Key 'MinimumPasswordAge'
    if ($null -eq $minimum -or $minimum -lt 0 -or $minimum -ge $target) {
        throw 'A idade minima da senha deve ser conhecida e menor que a idade maxima desejada.'
    }
    Set-HWSecurityValues -Values @{MaximumPasswordAge=$target} -Expected @{MinimumPasswordAge=$minimum}
}
function Test-HW04State {
    param($Profile)
    return ((Get-HW04State -Profile $Profile).Compliant -eq $true)
}
