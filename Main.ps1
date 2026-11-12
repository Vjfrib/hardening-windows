#Requires -Version 5.1
<#
.SYNOPSIS
    Hardening Windows · auditoria e aplicação controlada de 16 controles de segurança.

.DESCRIPTION
    Ponto de entrada único do projeto (UPE/POLI · Sistemas Operacionais 2026.2).

    Fluxo de uma aplicação:
      1 AUDITAR    estado antes de cada controle selecionado (Get-HWControlNN)
      2 PROTEGER   backup com escopo; o snapshot externo da VM é confirmado na aprovação
      3 AUTORIZAR  VM + IDs aprovados + escopo (scripts/config/aprovacoes.json)
      4 APLICAR    Set-HWControlNN com ShouldProcess (-WhatIf simula, -Confirm pergunta)
      5 VERIFICAR  estado depois (Get/Test) e relatórios em JSON, CSV, Markdown e HTML

    Audit é o modo padrão e nunca altera a máquina. Os controles 10, 12, 13 e 16
    são somente auditoria em qualquer modo.

.PARAMETER Mode
    Audit (padrão), Apply ou Rollback.

.PARAMETER ControlIds
    IDs de 01 a 16 (aceita 1 ou '01'). Padrão: todos.

.PARAMETER ProfilePath
    Perfil com os valores esperados. Padrão: scripts/config/perfil-academico.json
    ou, se ele não existir, scripts/config/perfil-academico.example.json.

.PARAMETER ApprovalPath
    Aprovação exigida pelo modo Apply. Padrão: scripts/config/aprovacoes.json.

.PARAMETER OutputDirectory
    Pasta onde cada execução cria uma subpasta com relatórios e backup. Padrão: .\saida

.PARAMETER BackupPath
    Pasta "backup" (ou o arquivo backup-escopo.json) de uma aplicação anterior. Usado em Rollback.

.EXAMPLE
    .\Main.ps1
    Audita os 16 controles.

.EXAMPLE
    .\Main.ps1 -Mode Audit -ControlIds '01','07','09','12'

.EXAMPLE
    .\Main.ps1 -Mode Apply -ControlIds '01','02','03' -WhatIf
    Mostra o que seria alterado, sem alterar.

.EXAMPLE
    .\Main.ps1 -Mode Rollback -BackupPath .\saida\20261112T101500-Apply\backup

.NOTES
    Códigos de saída: 0 sem não conformidades · 1 há não conformidades · 2 erro em algum controle · 3 execução bloqueada.
    Hardening reduz a superfície de ataque; não garante invulnerabilidade.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Apply', 'Rollback')]
    [string]$Mode = 'Audit',

    [ValidatePattern('^(0?[1-9]|1[0-6])$')]
    [string[]]$ControlIds = @('01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16'),

    [string]$ProfilePath,
    [string]$ApprovalPath,
    [string]$OutputDirectory,
    [string]$BackupPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

foreach ($module in 'Common', 'Safety', 'Backup', 'Reporting') {
    Import-Module (Join-Path $root "scripts/lib/$module.psm1") -Force -DisableNameChecking
}

if (-not $ProfilePath) {
    $ProfilePath = Join-Path $root 'scripts/config/perfil-academico.json'
    if (-not (Test-Path -LiteralPath $ProfilePath)) { $ProfilePath = Join-Path $root 'scripts/config/perfil-academico.example.json' }
}
if (-not $ApprovalPath) { $ApprovalPath = Join-Path $root 'scripts/config/aprovacoes.json' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'saida' }

$simulation = [bool]$WhatIfPreference
$ids = @($ControlIds | ForEach-Object { '{0:D2}' -f [int]$_ } | Sort-Object -Unique)   # aceita 1 ou '01'
$context = $null
$machine = $null
$lock = $null
$backup = $null
$approvedIds = @()
$exitCode = 3

function Invoke-HWAudit {
    <# Executa o Get de cada controle; erro em um controle não interrompe os demais. #>
    param([Parameter(Mandatory)][object[]]$Controls)
    $states = @{}
    foreach ($control in $Controls) {
        try { $states[$control.Id] = & "Get-HWControl$($control.Id)" -Context $context }
        catch {
            $states[$control.Id] = New-HWErrorState -Id $control.Id -Message $_.Exception.Message
            Write-HWLog -Context $context -Level Aviso -Message "Controle $($control.Id): $($_.Exception.Message)"
        }
    }
    return $states
}

# ------------------------------------------------------------------ Preparação e travas
try {
    $config = Read-HWJson -Path $ProfilePath
    Assert-HWProfile -Config $config
    $stamp = '{0:yyyyMMddTHHmmss}-{1}{2}' -f (Get-Date), $Mode, $(if ($simulation) { '-WhatIf' } else { '' })
    $runDirectory = Join-Path $OutputDirectory $stamp
    New-Item -ItemType Directory -Path $runDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    $context = New-HWContext -Config $config -Mode $Mode -RunDirectory $runDirectory
    $context.BackupDirectory = Join-Path $runDirectory 'backup'
    Write-HWLog -Context $context -Message "Modo $Mode$(if ($simulation) { ' (simulação)' }) · controles $($ids -join ', ') · perfil $ProfilePath"

    if (-not (Test-HWWindows)) { throw 'Este script só roda no Windows (10/11 Pro ou Windows Server compatível).' }
    $machine = Get-HWMachineInfo
    $context.Machine = $machine
    Write-HWLog -Context $context -Message "Máquina $($machine.ComputerName) · $($machine.OsCaption) build $($machine.OsBuild) · virtual=$($machine.IsVirtual) · domínio=$($machine.PartOfDomain)"
    Assert-HWSupportedPlatform -Machine $machine -Mode $Mode

    if (-not (Test-HWAdministrator)) {
        if ($Mode -ne 'Audit') { throw 'Abra o Windows PowerShell como Administrador para aplicar ou restaurar.' }
        Write-HWLog -Context $context -Level Aviso -Message 'Sem privilégio de administrador: secedit, auditpol e recursos opcionais falham e a auditoria fica incompleta.'
    }
    if ($machine.PSEdition -eq 'Core') {
        Write-HWLog -Context $context -Level Aviso -Message 'PowerShell 7 detectado: a referência do projeto é o Windows PowerShell 5.1 (powershell.exe).'
    }
    if ($machine.PartOfDomain) {
        Write-HWLog -Context $context -Level Aviso -Message 'Máquina em domínio: a GPO pode sobrepor a política local auditada.'
    }

    $catalog = @(Get-HWControlCatalog -Id $ids)
    if ($Mode -eq 'Apply') {
        if (-not (Test-Path -LiteralPath $ApprovalPath)) {
            throw "Aprovação não encontrada em $ApprovalPath. Copie scripts/config/aprovacoes.example.json e preencha."
        }
        $context.Approval = Read-HWJson -Path $ApprovalPath
        $applicable = @(Get-HWControlCatalog | Where-Object { $_.Tipo -eq 'Aplicavel' } | ForEach-Object { $_.Id })
        $approvedIds = @(Assert-HWApproval -Approval $context.Approval -Machine $machine -RequestedIds $ids -ApplicableIds $applicable)
        if ($approvedIds.Count -eq 0) { throw 'Nenhum dos IDs pedidos é aplicável e está em ControlesAprovados.' }
        Write-HWLog -Context $context -Message "Aprovação de $($context.Approval.Responsavel) válida até $($context.Approval.ValidaAte); IDs aprovados: $($approvedIds -join ', ')"
    }
    if ($Mode -eq 'Rollback') {
        if (-not $BackupPath) { throw 'Informe -BackupPath com a pasta backup de uma aplicação anterior.' }
        $backup = Read-HWBackup -Path $BackupPath -Machine $machine
        $inBackup = @($backup.Controls | ForEach-Object { [string]$_.Id })
        $catalog = @($catalog | Where-Object { $_.Id -in $inBackup })
        if ($catalog.Count -eq 0) { throw 'O backup não tem nenhum dos controles pedidos.' }
    }
    if ($Mode -ne 'Audit' -and -not $simulation) { $lock = Enter-HWLock }

    foreach ($control in $catalog) {
        . (Join-Path $root "scripts/controles/$($control.Arquivo)")
    }
} catch {
    $message = $_.Exception.Message
    if ($context) { Write-HWLog -Context $context -Level Erro -Message "Execução bloqueada: $message" }
    else { Write-Warning "Execução bloqueada: $message" }
    Exit-HWLock -Mutex $lock
    exit 3
}

# ------------------------------------------------------------------ Execução
$rows = @()
try {
    # 1 · AUDITAR
    $before = Invoke-HWAudit -Controls $catalog
    Save-HWJson -Path (Join-Path $context.RunDirectory 'estado-antes.json') -InputObject @($catalog | ForEach-Object { $before[$_.Id] })
    $after = @{}

    if ($Mode -eq 'Audit') {
        foreach ($control in $catalog) {
            $rows += New-HWRow -Control $control -Before $before[$control.Id] -After $null -Action 'Auditado'
        }
    }

    if ($Mode -eq 'Apply') {
        $toChange = @($catalog | Where-Object { $_.Id -in $approvedIds -and $before[$_.Id].Status -eq 'NaoConforme' })

        # 2 · PROTEGER
        if ($toChange.Count -gt 0 -and -not $simulation) {
            $null = New-HWBackup -Context $context -States @($toChange | ForEach-Object { $before[$_.Id] }) -Machine $machine -Confirm:$false
        }

        # 3 · AUTORIZAR e 4 · APLICAR
        $actions = @{}
        $stop = $false
        foreach ($control in $catalog) {
            $id = $control.Id
            $result = [pscustomobject]@{ Action = ''; Message = ''; Restart = $false }
            if ($control.Tipo -ne 'Aplicavel') { $result.Action = 'Somente auditoria' }
            elseif ($id -notin $approvedIds) { $result.Action = 'Não aprovado' }
            elseif ($before[$id].Status -eq 'Erro') { $result.Action = 'Não aplicado (erro na auditoria)' }
            elseif ($before[$id].Status -ne 'NaoConforme') { $result.Action = 'Nenhuma (já conforme ou revisar)' }
            elseif ($stop) { $result.Action = 'Interrompido (falha anterior)' }
            else {
                try {
                    $change = & "Set-HWControl$id" -Context $context
                    $result.Message = @($change.Actions) -join '; '
                    $result.Restart = [bool]$change.RestartNeeded
                    $result.Action = if ($change.Changed) { 'Aplicado' } elseif ($simulation) { 'Simulado' } else { 'Sem alteração' }
                    Write-HWLog -Context $context -Message "Controle ${id}: $($result.Action) · $($result.Message)"
                } catch {
                    $result.Action = 'Erro'
                    $result.Message = $_.Exception.Message
                    $stop = $true
                    Write-HWLog -Context $context -Level Erro -Message "Controle ${id}: $($result.Message). Aplicações seguintes interrompidas; use o rollback ou o snapshot."
                }
            }
            $actions[$id] = $result
        }

        # 5 · VERIFICAR
        $context.Cache.Clear()
        $after = Invoke-HWAudit -Controls $catalog
        foreach ($control in $catalog) {
            $id = $control.Id
            $result = $actions[$id]
            if ($result.Action -eq 'Aplicado') {
                $verified = (& "Test-HWControl$id" -Context $context) -or $after[$id].Status -eq 'Revisar'
                if (-not $verified) {
                    $result.Action = 'Erro'
                    $result.Message = "$($result.Message) · verificação falhou: estado depois = $($after[$id].Status)"
                }
            }
            $rows += New-HWRow -Control $control -Before $before[$id] -After $after[$id] -Action $result.Action -Message $result.Message -RestartNeeded $result.Restart
        }
    }

    if ($Mode -eq 'Rollback') {
        foreach ($control in $catalog) {
            $id = $control.Id
            $entry = @($backup.Controls | Where-Object { [string]$_.Id -eq $id })[0]
            $action = ''
            $message = ''
            $restart = $false
            try {
                $change = & "Restore-HWControl$id" -Context $context -Saved $entry.Observed
                $message = @($change.Actions) -join '; '
                $restart = [bool]$change.RestartNeeded
                $action = if ($change.Changed) { 'Restaurado' } elseif ($simulation) { 'Simulado' } else { 'Nada a restaurar' }
            } catch {
                $action = 'Erro'
                $message = $_.Exception.Message
            }
            Write-HWLog -Context $context -Message "Rollback ${id}: $action · $message"
            $rows += [pscustomobject]@{ Control = $control; Action = $action; Message = $message; Restart = $restart }
        }
        $context.Cache.Clear()
        $after = Invoke-HWAudit -Controls $catalog
        $rows = @($rows | ForEach-Object {
                New-HWRow -Control $_.Control -Before $before[$_.Control.Id] -After $after[$_.Control.Id] -Action $_.Action -Message $_.Message -RestartNeeded $_.Restart
            })
    }

    if ($after.Count -gt 0) {
        Save-HWJson -Path (Join-Path $context.RunDirectory 'estado-depois.json') -InputObject @($catalog | ForEach-Object { $after[$_.Id] })
    }

    $exitCode = Get-HWExitCode -Rows $rows
    $null = Export-HWReport -Context $context -Rows $rows -Machine $machine -ExitCode $exitCode -Simulation $simulation

    $summary = $rows | Format-Table Id, Nome, StatusAntes, Acao, StatusDepois -AutoSize | Out-String
    Write-Information $summary -InformationAction Continue
    if (@($rows | Where-Object { $_.Reinicio }).Count -gt 0) {
        Write-HWLog -Context $context -Level Aviso -Message 'Reinicie a VM para concluir as mudanças marcadas (UAC/recursos opcionais).'
    }
    Write-HWLog -Context $context -Message "Relatórios em $($context.RunDirectory) · código de saída $exitCode"
} catch {
    Write-HWLog -Context $context -Level Erro -Message "Falha inesperada: $($_.Exception.Message)"
    $exitCode = 2
} finally {
    Exit-HWLock -Mutex $lock
}
exit $exitCode
