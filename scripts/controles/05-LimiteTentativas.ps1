# Controle 05: Limite de tentativas de logon. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW05State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'LockoutBadCount'
    $target=[int]$Profile.Password.LockoutThreshold
    $note='Politica local pode ser sobreposta por dominio/GPO; comparar estado efetivo.'
    if ($null -ne $actual -and $actual -gt 0 -and $actual -lt $target) {
        New-HWState -Id '05' -Name 'Limite de tentativas de logon' -Current $actual -Expected $target -Compliant $null -Note 'Limite atual mais restritivo. Qualquer flexibilizacao exige revisao manual.'
        return
    }
    New-HWState -Id '05' -Name 'Limite de tentativas de logon' -Current $actual -Expected $target -Compliant ($null -ne $actual -and $actual -eq $target) -Note $note
}
function Set-HW05State {
    param($Profile)
    $target=[int]$Profile.Password.LockoutThreshold
    $policy=Get-HWLocalPolicy
    $current=Get-HWPolicyInt -Policy $policy -Key 'LockoutBadCount'
    if ($null -eq $current -or ($current -gt 0 -and $current -lt $target)) {
        throw 'Limite atual ausente ou mais restritivo. Revise manualmente antes de alterar.'
    }
    $duration=Get-HWPolicyInt -Policy $policy -Key 'LockoutDuration'
    $reset=Get-HWPolicyInt -Policy $policy -Key 'ResetLockoutCount'
    if ($null -eq $duration -or $duration -lt [int]$Profile.Password.LockoutDurationMinutes -or
        $null -eq $reset -or $reset -le 0 -or $reset -gt $duration) {
        throw 'Configure uma duracao e janela de bloqueio coerentes antes de aplicar o limite de tentativas.'
    }
    Set-HWSecurityValues -Values @{LockoutBadCount=$target} -Expected @{
        LockoutBadCount=$current; LockoutDuration=$duration; ResetLockoutCount=$reset
    }
}
function Test-HW05State {
    param($Profile)
    return ((Get-HW05State -Profile $Profile).Compliant -eq $true)
}
