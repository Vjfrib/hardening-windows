Set-StrictMode -Version Latest

function Assert-HWApproval {
    param([string]$Id, $Approvals, [switch]$Rollback)
    $entry = $Approvals.Controls.PSObject.Properties[$Id]
    if ($null -eq $entry) { throw "Controle ${Id}: aprovacao ausente." }

    $approval = $entry.Value
    $flag = if ($Rollback) { 'RollbackEnabled' } else { 'Enabled' }
    $enabled = $approval.PSObject.Properties[$flag]
    if ($null -eq $enabled -or $enabled.Value -isnot [bool] -or -not $enabled.Value -or
        [string]::IsNullOrWhiteSpace([string]$approval.Ticket)) {
        throw "Controle ${Id}: defina $flag=true e um Ticket para esta operacao."
    }
    return $approval
}

function Assert-HWLabApproval {
    param($Approvals)
    foreach ($name in 'EnableMutations','ConfirmedLab') {
        $value = $Approvals.PSObject.Properties[$name]
        if ($null -eq $value -or $value.Value -isnot [bool] -or -not $value.Value) {
            throw "A aprovacao deve declarar $name=true."
        }
    }
    foreach ($name in 'SnapshotId','Approver','Reason') {
        $value = $Approvals.PSObject.Properties[$name]
        if ($null -eq $value -or $value.Value -isnot [string] -or
            [string]::IsNullOrWhiteSpace($value.Value)) {
            throw "A aprovacao deve identificar $name."
        }
    }
}

function Assert-HWProfile {
    param($Profile)
    $password = $Profile.Password
    $ranges = @{
        MinLength = @(12,14)
        HistoryCount = @(5,24)
        MaxAgeDays = @(1,90)
        LockoutThreshold = @(5,5)
        LockoutDurationMinutes = @(15,99999)
        ResetCounterMinutes = @(1,99999)
    }
    foreach ($name in $ranges.Keys) {
        $value = $password.PSObject.Properties[$name]
        $min, $max = $ranges[$name]
        if ($null -eq $value -or ($value.Value -isnot [int] -and $value.Value -isnot [long]) -or
            $value.Value -lt $min -or $value.Value -gt $max) {
            throw "Password.$name deve ser um inteiro entre $min e $max."
        }
    }
    if ($password.ComplexityEnabled -isnot [bool] -or -not $password.ComplexityEnabled) {
        throw 'O perfil exige Password.ComplexityEnabled=true.'
    }
    if ($password.ResetCounterMinutes -gt $password.LockoutDurationMinutes) {
        throw 'ResetCounterMinutes nao pode exceder LockoutDurationMinutes.'
    }
}

Export-ModuleMember -Function Assert-HWApproval,Assert-HWLabApproval,Assert-HWProfile
