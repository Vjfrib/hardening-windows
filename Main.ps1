#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [ValidateSet('Audit','Apply','Verify','Report','Rollback')][string]$Mode = 'Audit',
    [Alias('ControlId','Ids')][ValidateNotNullOrEmpty()][ValidatePattern('^(0[1-9]|1[0-6])$')]
    [string[]]$ControlIds = @('01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16'),
    [string]$ConfigPath,
    [string]$ApprovalPath,
    [Alias('OutputDir')][string]$OutputDirectory,
    [Alias('ApproveChanges')][switch]$ConfirmApply,
    [switch]$Demo,
    [string]$BackupPath,
    [string]$ReportPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-HWObservedState([string]$Id) {
    try { & "Get-HW${Id}State" -Profile $profile }
    catch {
        New-HWState -Id $Id -Name "Controle $Id" -Current $null -Expected 'Checklist' -Compliant $null -Status 'Error' -Note $_.Exception.Message
    }
}

function ConvertTo-HWComparable($State) {
    ConvertTo-Json -InputObject $State -Depth 16 -Compress
}

$lock = $null
$ownsLock = $false
try {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'scripts/config/perfil-academico.json' }
    if (-not $ApprovalPath) { $ApprovalPath = Join-Path $PSScriptRoot 'scripts/config/aprovacoes.json' }
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'output' }
    foreach ($module in 'Common','Safety','Backup','Reporting','Rollback') {
        Import-Module (Join-Path $PSScriptRoot "scripts/lib/$module.psm1") -DisableNameChecking
    }

    if ($Mode -eq 'Report') {
        if ($Demo) { throw 'Use -Mode Report com uma coleta existente, sem -Demo.' }
        if (-not $ReportPath) {
            $ReportPath = Join-Path $OutputDirectory 'results.json'
            if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
                $latest = Get-ChildItem -LiteralPath $OutputDirectory -Directory |
                    Where-Object { $_.Name -notmatch '-Demo-' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'results.json') -PathType Leaf) } |
                    Sort-Object Name -Descending | Select-Object -First 1
                if ($null -eq $latest) { throw 'Nenhuma coleta encontrada. Indique -OutputDirectory ou -ReportPath.' }
                $ReportPath = Join-Path $latest.FullName 'results.json'
            }
        }
        $source = Get-Item -LiteralPath $ReportPath
        $report = Read-HWJson $source.FullName
        if ($report.SchemaVersion -ne 1 -or @($report.Controls).Count -eq 0 -or $report.ExitCode -notin 0,1,2,3) {
            throw 'Formato de relatorio invalido.'
        }
        $resultPath = Save-HWReport -Report $report -Directory $source.DirectoryName
        Write-Host "Relatorios: $resultPath"
        exit $report.ExitCode
    }

    $ids = @($ControlIds | Select-Object -Unique)
    if ($Demo -and $Mode -ne 'Audit') { throw '-Demo somente pode ser usado no modo Audit.' }
    if ($Mode -eq 'Rollback' -and ($ids.Count -ne 1 -or -not $BackupPath)) {
        throw 'Rollback exige um unico -ControlIds e -BackupPath.'
    }
    $auditOnly = @('10','12','13','16')
    $reversible = @('01','02','03','04','05','06','07','08','09','11','14')
    if ($Mode -eq 'Rollback' -and $ids[0] -notin $reversible) {
        throw 'Este controle requer recuperacao por snapshot e revisao manual.'
    }
    if ($Mode -eq 'Apply' -and $ids -contains '05' -and $ids -contains '06') {
        $ids = @('06') + @($ids | Where-Object { $_ -ne '06' })
    }

    $mutation = $Mode -in 'Apply','Rollback' -and -not $WhatIfPreference
    $domain = $null
    $fingerprint = $null
    $approval = $null
    if (-not $Demo) {
        Assert-HWWindows
        if (-not [Environment]::Is64BitProcess) { throw 'Use PowerShell de 64 bits.' }
        $profile = Read-HWJson $ConfigPath
        Assert-HWProfile $profile
        $domain = Test-HWDomainMember
        if ($mutation) {
            try {
                if (-not $ConfirmApply) { throw 'Use -ConfirmApply para autorizar a operacao.' }
                if (-not (Test-HWAdministrator)) { throw 'Abra PowerShell como Administrador na VM.' }
                if ($domain -ne $false) { throw 'Alteracoes exigem workgroup confirmado; revise GPO/MDM separadamente.' }
                $approval = Read-HWJson $ApprovalPath
                Assert-HWLabApproval $approval
                $fingerprint = Get-HWMachineFingerprint
                $lock = [Threading.Mutex]::new($false, 'Global\UPE.HardeningWindows')
                try { $ownsLock = $lock.WaitOne(0) }
                catch [Threading.AbandonedMutexException] { $ownsLock = $true }
                if (-not $ownsLock) { throw 'Outra aplicacao ou restauracao esta em andamento.' }
            } catch {
                Write-Warning "Operacao bloqueada: $($_.Exception.Message)"
                exit 3
            }
        }
    }

    $utc = [DateTime]::UtcNow
    $runMode = if ($Demo) { 'Demo' } else { $Mode }
    $run = '{0:yyyyMMddTHHmmssfffffffZ}-{1}-{2}' -f $utc,$runMode,[guid]::NewGuid().ToString('N')
    $outputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $directory = Join-Path $outputRoot $run
    New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    $backupDir = Join-Path $directory 'backups'
    if ($mutation -and $Mode -eq 'Apply') {
        New-Item -ItemType Directory -Path $backupDir -ErrorAction Stop | Out-Null
    }

    $policyEvidence = $null
    if (-not $Demo -and (Test-HWAdministrator)) {
        $gpresultPath = Join-Path $directory 'gpresult.xml'
        try {
            $null = & gpresult.exe /SCOPE COMPUTER /X $gpresultPath 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $gpresultPath)) { throw 'gpresult indisponivel' }
            $policyEvidence = 'gpresult.xml'
        } catch {
            $policyEvidence = 'gpresult indisponivel; a origem efetiva precisa de revisao.'
        }
    }

    $controls = @{}
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'scripts/controles') -Filter '*.ps1') {
        if ($file.Name -notmatch '^(\d\d)-') { continue }
        if ($controls.ContainsKey($Matches[1])) { throw "ID duplicado: $($Matches[1])" }
        $controls[$Matches[1]] = $file
    }

    $halt = $false
    $rows = foreach ($id in $ids) {
        if (-not $controls.ContainsKey($id)) { throw "Modulo $id ausente." }
        $operation = 'ReadOnly'
        $detail = ''
        $evidence = ''
        if ($Demo) {
            $before = New-HWState -Id $id -Name $controls[$id].BaseName -Current 'FICTICIO' -Expected 'FICTICIO' -Compliant $null -Status 'ManualReview' -Note 'SIMULACAO. Nenhuma configuracao do Windows foi coletada.'
        } else {
            . $controls[$id].FullName
            $before = Get-HWObservedState $id
        }
        $after = $before
        if ($Mode -eq 'Apply') {
            $operation = 'Blocked'
            $entry = $null
            $setterStarted = $false
            try {
                if ($id -in $auditOnly) {
                    $operation = 'AuditOnly'
                } elseif ($before.Status -eq 'Error') {
                    $detail = 'A coleta inicial falhou.'
                } elseif ($before.Compliant -eq $true -or ($id -eq '14' -and $before.Status -ne 'Error' -and (Test-HW14State -Profile $profile))) {
                    $operation = 'Unchanged'
                } elseif ($halt) {
                    $detail = 'Alteracao anterior possivelmente parcial; somente leituras nesta execucao.'
                } elseif ($before.Status -ne 'NonCompliant' -and $id -notin '14','15') {
                    $detail = 'Estado exige revisao antes de qualquer alteracao.'
                } elseif ($WhatIfPreference) {
                    $null = $PSCmdlet.ShouldProcess("Controle $id", 'Aplicar hardening')
                    $operation = 'WhatIf'
                } else {
                    $permission = Assert-HWApproval -Id $id -Approvals $approval
                    $arguments = @{ Profile = $profile }
                    if ($id -eq '07') {
                        $confirmed = $approval.PSObject.Properties['RecoveryAccessConfirmed']
                        $arguments.RecoveryAccessConfirmed = ($null -ne $confirmed -and $confirmed.Value -is [bool] -and $confirmed.Value)
                    }
                    if ($id -eq '15') {
                        $allowed = $permission.PSObject.Properties['ApprovedFeatures']
                        if ($null -eq $allowed -or $allowed.Value -isnot [array] -or @($allowed.Value).Count -eq 0 -or
                            @($allowed.Value | Where-Object { $_ -isnot [string] }).Count -gt 0) {
                            throw 'O controle 15 exige nomes explicitos em ApprovedFeatures.'
                        }
                        $arguments.ApprovedFeatures = $allowed.Value
                    }
                    if ($PSCmdlet.ShouldProcess("Controle $id", 'Aplicar hardening')) {
                        $restorable = $id -in $reversible
                        $baseline = if ($restorable) { Get-HWReversibleState -Id $id } else { $before.Current }
                        Save-HWNativeEvidence -Directory $backupDir -Id $id
                        $entry = [pscustomobject]@{
                            SchemaVersion = 1; Id = $id; Run = $run; MachineFingerprint = $fingerprint
                            SnapshotId = $approval.SnapshotId; Ticket = $permission.Ticket
                            Status = 'Prepared'; Before = $baseline; Post = $null
                        }
                        $evidence = "backups/$id.json"
                        $entryPath = Join-Path $backupDir "$id.json"
                        Write-HWBackup -Path $entryPath -Entry $entry
                        if ($restorable -and (ConvertTo-HWComparable (Get-HWReversibleState -Id $id)) -cne (ConvertTo-HWComparable $baseline)) {
                            throw 'O estado mudou desde o backup. Revise antes de tentar novamente.'
                        }
                        $setterStarted = $true
                        & "Set-HW${id}State" @arguments | Out-Null
                        $after = Get-HWObservedState $id
                        if ($restorable) { $entry.Post = Get-HWReversibleState -Id $id }
                        $verified = if ($id -in '14','15') { & "Test-HW${id}State" @arguments } else { $after.Compliant }
                        if ($after.Status -eq 'Error' -or $verified -ne $true) { throw 'A verificacao posterior falhou.' }
                        $entry.Status = 'Applied'
                        Write-HWBackup -Path $entryPath -Entry $entry
                        $operation = 'Applied'
                    } else { $operation = 'Declined' }
                }
            } catch {
                $detail = $_.Exception.Message
                if ($setterStarted) {
                    $halt = $true
                    $operation = 'FailedPartial'
                    $after = Get-HWObservedState $id
                    $entry.Status = 'FailedPartial'
                    try { Write-HWBackup -Path $entryPath -Entry $entry }
                    catch { $detail += " Backup permaneceu em estado inseguro: $($_.Exception.Message)" }
                }
            }
        }

        if ($Mode -eq 'Rollback') {
            $operation = 'Blocked'
            $restoreStarted = $false
            try {
                if ($WhatIfPreference) {
                    $null = $PSCmdlet.ShouldProcess("Controle $id", 'Restaurar configuracao anterior')
                    $operation = 'WhatIf'
                } else {
                    $null = Assert-HWApproval -Id $id -Approvals $approval -Rollback
                    if ($id -eq '07' -and ($approval.RecoveryAccessConfirmed -isnot [bool] -or -not $approval.RecoveryAccessConfirmed)) {
                        throw 'O controle 07 exige acesso alternativo confirmado.'
                    }
                    $backupFile = (Get-Item -LiteralPath $BackupPath).FullName
                    $entry = Read-HWJson $backupFile
                    if ($entry.SchemaVersion -ne 1 -or $entry.Id -cne $id -or $entry.Status -cne 'Applied' -or
                        $entry.MachineFingerprint -cne $fingerprint -or $entry.SnapshotId -cne $approval.SnapshotId -or
                        $null -eq $entry.Before -or $null -eq $entry.Post) {
                        throw 'O backup deve ser completo, Applied, do mesmo ID, snapshot e Windows.'
                    }
                    if ($PSCmdlet.ShouldProcess("Controle $id", 'Restaurar configuracao anterior')) {
                        if ((ConvertTo-HWComparable (Get-HWReversibleState -Id $id)) -cne (ConvertTo-HWComparable $entry.Post)) {
                            throw 'O estado atual difere do pos-estado do backup. Revise a alteracao externa.'
                        }
                        $entry.Status = 'RestoreStarted'
                        Write-HWBackup -Path $backupFile -Entry $entry
                        $restoreStarted = $true
                        Restore-HWReversibleState -Id $id -State $entry.Before
                        if ((ConvertTo-HWComparable (Get-HWReversibleState -Id $id)) -cne (ConvertTo-HWComparable $entry.Before)) {
                            throw 'A verificacao da restauracao falhou.'
                        }
                        $entry.Status = 'Restored'
                        Write-HWBackup -Path $backupFile -Entry $entry
                        $after = Get-HWObservedState $id
                        $operation = 'Restored'
                        $evidence = $backupFile
                    } else { $operation = 'Declined' }
                }
            } catch {
                $detail = $_.Exception.Message
                if ($restoreStarted) {
                    $operation = 'FailedPartial'
                    $after = Get-HWObservedState $id
                }
            }
        }

        $status = if ($id -in $auditOnly -and -not $Demo -and $after.Status -ne 'Error') { 'AuditOnly' }
                  elseif ($after.Status -eq 'RequiresReview') { 'ManualReview' } else { $after.Status }
        [pscustomobject]@{
            Id = $id; Control = $after.Control; Status = $status; Operation = $operation
            Before = $before.Current; After = $after.Current; Recommended = $after.Expected
            Command = if ($operation -eq 'Restored') { 'Restore-HWReversibleState' }
                      elseif ($operation -in 'Applied','FailedPartial' -and $Mode -eq 'Apply') { "Set-HW${id}State" }
                      elseif (-not $Demo) { "Get-HW${id}State" } else { '' }
            Evidence = $evidence; Note = ("$($after.Note) $detail").Trim()
        }
    }
    $exitCode = if (@($rows | Where-Object Status -eq 'Error').Count -gt 0) { 1 }
                elseif ($WhatIfPreference -or @($rows | Where-Object {
                    $_.Operation -in 'Blocked','Declined','FailedPartial' -or $_.Status -in 'ManualReview','NotSupported','AuditOnly'
                }).Count -gt 0) { 3 }
                elseif ($Mode -ne 'Rollback' -and @($rows | Where-Object Status -eq 'NonCompliant').Count -gt 0) { 2 }
                else { 0 }
    $report = [pscustomobject]@{
        SchemaVersion = 1; Mode = $runMode; ExitCode = $exitCode
        Metadata = [pscustomobject]@{
            Run = $run; Utc = $utc.ToString('o'); Simulated = [bool]$Demo
            WhatIf = [bool]$WhatIfPreference; DomainMember = $domain; PolicyEvidence = $policyEvidence
        }
        Controls = @($rows)
    }
    $resultPath = Save-HWReport -Report $report -Directory $directory
    $rows | Select-Object Id,Control,Status,Operation | Format-Table -AutoSize
    Write-Host "Relatorios: $resultPath"
    exit $exitCode
} catch {
    Write-Error "Falha de orquestracao: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
} finally {
    if ($ownsLock) { $lock.ReleaseMutex() }
    if ($null -ne $lock) { $lock.Dispose() }
}
