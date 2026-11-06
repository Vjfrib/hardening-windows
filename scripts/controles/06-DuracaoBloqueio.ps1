# Controle 06: Duracao de bloqueio. Checklist Rodrigo Campos / Gabriel Cortez.
function Get-HW06State {
    param($Profile)
    $policy=Get-HWLocalPolicy
    $actual=Get-HWPolicyInt -Policy $policy -Key 'LockoutDuration'
    $reset=Get-HWPolicyInt -Policy $policy -Key 'ResetLockoutCount'
    $threshold=Get-HWPolicyInt -Policy $policy -Key 'LockoutBadCount'
    $ok=if ($null -eq $actual -or $null -eq $reset -or $null -eq $threshold -or ($actual -le 0 -and $threshold -gt 0)) {
        $null
    } else {
        $actual -ge [int]$Profile.Password.LockoutDurationMinutes -and $reset -gt 0 -and $reset -le $actual
    }
    New-HWState -Id '06' -Name 'Duracao de bloqueio' -Current ([pscustomobject]@{Duracao=$actual;ZerarContador=$reset;LimiteTentativas=$threshold}) -Expected ([pscustomobject]@{DuracaoMinima=[int]$Profile.Password.LockoutDurationMinutes;ZerarContadorPadrao=[int]$Profile.Password.ResetCounterMinutes}) -Compliant $ok -Note 'Validar duracao e janela antes de ativar bloqueio. Duracao indefinida com bloqueio ativo exige revisao manual.'
}
function Set-HW06State {
    param($Profile)
    $current=Get-HWLocalPolicy
    $currentDuration=Get-HWPolicyInt -Policy $current -Key 'LockoutDuration'
    $currentReset=Get-HWPolicyInt -Policy $current -Key 'ResetLockoutCount'
    $threshold=Get-HWPolicyInt -Policy $current -Key 'LockoutBadCount'
    if ($null -eq $currentDuration -or $null -eq $currentReset -or $null -eq $threshold -or
        ($currentDuration -le 0 -and $threshold -gt 0)) {
        throw 'Duracao ou janela anterior nao confiavel. Revise a politica no console.'
    }
    $targetDuration=[math]::Max([int]$Profile.Password.LockoutDurationMinutes,$currentDuration)
    $targetReset=if ($currentReset -gt 0 -and $currentReset -le $targetDuration) {
        $currentReset
    } else {
        [int]$Profile.Password.ResetCounterMinutes
    }
    if ($targetReset -le 0 -or $targetReset -gt $targetDuration) { throw 'Janela de bloqueio fora do intervalo permitido.' }
    Set-HWSecurityValues -Values @{LockoutDuration=$targetDuration;ResetLockoutCount=$targetReset} -Expected @{
        LockoutBadCount=$threshold; LockoutDuration=$currentDuration; ResetLockoutCount=$currentReset
    }
}
function Test-HW06State {
    param($Profile)
    return ((Get-HW06State -Profile $Profile).Compliant -eq $true)
}
