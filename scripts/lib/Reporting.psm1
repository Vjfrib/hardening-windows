#Requires -Version 5.1
<#
    Reporting.psm1 · saídas de cada execução.

    resultados.json  tudo (estado antes/depois, ações, achados, máquina)
    resultados.csv   uma linha por controle
    relatorio.md     tabela legível no GitHub ou em editor
    relatorio.html   mesma tabela, para abrir no navegador e anexar como evidência
#>
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

function New-HWRow {
    <# Uma linha do relatório: o controle, o estado antes, a ação e o estado depois. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cria apenas um objeto em memória.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Control,
        [AllowNull()]$Before,
        [AllowNull()]$After,
        [string]$Action = 'Auditado',
        [string]$Message = '',
        [bool]$RestartNeeded = $false
    )
    [pscustomobject]@{
        Id            = $Control.Id
        Nome          = $Control.Nome
        Grupo         = $Control.Grupo
        Tipo          = $Control.Tipo
        StatusAntes   = $(if ($Before) { $Before.Status } else { 'Erro' })
        Acao          = $Action
        StatusDepois  = $(if ($After) { $After.Status } else { '' })
        Mensagem      = $Message
        Reinicio      = $RestartNeeded
        Achados       = $(if ($After) { @($After.Findings) } elseif ($Before) { @($Before.Findings) } else { @() })
        Antes         = $Before
        Depois        = $After
    }
}

function Get-HWExitCode {
    <# 0 = sem não conformidades; 1 = há não conformidades; 2 = houve erro; 3 = execução bloqueada. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $final = @($Rows | ForEach-Object { if ($_.StatusDepois) { $_.StatusDepois } else { $_.StatusAntes } })
    if (@($Rows | Where-Object { $_.Acao -eq 'Erro' }).Count -gt 0 -or $final -contains 'Erro') { return 2 }
    if ($final -contains 'NaoConforme') { return 1 }
    return 0
}

function ConvertTo-HWHtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    return [Net.WebUtility]::HtmlEncode([string]$Text)
}

function Export-HWReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [AllowNull()]$Machine,
        [Parameter(Mandatory)][int]$ExitCode,
        [bool]$Simulation = $false
    )
    $dir = $Context.RunDirectory
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $report = [pscustomobject]@{
        SchemaVersion = 1
        Gerado        = $generated
        Modo          = $Context.Mode
        Simulacao     = $Simulation
        CodigoSaida   = $ExitCode
        Perfil        = $(if (Test-HWProperty $Context.Config 'Perfil') { $Context.Config.Perfil } else { '' })
        Maquina       = $Machine
        Controles     = @($Rows)
    }
    Save-HWJson -Path (Join-Path $dir 'resultados.json') -InputObject $report -Depth 12

    $Rows | Select-Object Id, Nome, Grupo, Tipo, StatusAntes, Acao, StatusDepois, Reinicio, Mensagem,
    @{ Name = 'Achados'; Expression = { @($_.Achados) -join ' | ' } } |
        Export-Csv -LiteralPath (Join-Path $dir 'resultados.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false

    $machineText = if ($Machine) { "$($Machine.ComputerName) · $($Machine.OsCaption) (build $($Machine.OsBuild))" } else { 'não identificada' }
    $md = New-Object Collections.Generic.List[string]
    $md.Add('# Relatório de hardening · Windows')
    $md.Add('')
    $md.Add("- Gerado em: $generated")
    $md.Add("- Modo: $($Context.Mode)$(if ($Simulation) { ' (simulação -WhatIf)' })")
    $md.Add("- Máquina: $machineText")
    $md.Add("- Código de saída: $ExitCode")
    $md.Add('')
    $md.Add('| ID | Controle | Tipo | Antes | Ação | Depois | Achados |')
    $md.Add('|----|----------|------|-------|------|--------|---------|')
    foreach ($row in $Rows) {
        $findings = (@($row.Achados) -join '<br>') -replace '\|', '/'
        $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f $row.Id, $row.Nome, $row.Tipo, $row.StatusAntes, $row.Acao, $row.StatusDepois, $findings))
    }
    $md.Add('')
    $md.Add('Legenda: Conforme · NaoConforme · Revisar (decisão humana, ex.: portas e contas de serviço) · Erro.')
    $md.Add('Hardening reduz a superfície de ataque; não garante invulnerabilidade.')
    Set-Content -LiteralPath (Join-Path $dir 'relatorio.md') -Value $md -Encoding UTF8 -WhatIf:$false -Confirm:$false

    $colors = @{ Conforme = '#1b7f4b'; NaoConforme = '#b42318'; Revisar = '#b54708'; Erro = '#6941c6' }
    $html = New-Object Collections.Generic.List[string]
    $html.Add('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Relatório de hardening</title>')
    $html.Add('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#0f172a}table{border-collapse:collapse;width:100%}' +
        'th,td{border:1px solid #cbd5e1;padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}th{background:#0f766e;color:#fff}' +
        '.s{font-weight:600}</style></head><body>')
    $html.Add('<h1>Relatório de hardening · Windows</h1>')
    $html.Add(('<p>Gerado em {0} · Modo {1}{2} · Máquina {3} · Código de saída {4}</p>' -f
            (ConvertTo-HWHtmlText $generated), (ConvertTo-HWHtmlText $Context.Mode),
            $(if ($Simulation) { ' (simulação)' } else { '' }), (ConvertTo-HWHtmlText $machineText), $ExitCode))
    $html.Add('<table><tr><th>ID</th><th>Controle</th><th>Tipo</th><th>Antes</th><th>Ação</th><th>Depois</th><th>Achados</th></tr>')
    foreach ($row in $Rows) {
        $cells = @(
            (ConvertTo-HWHtmlText $row.Id), (ConvertTo-HWHtmlText $row.Nome), (ConvertTo-HWHtmlText $row.Tipo)
        )
        $before = '<span class="s" style="color:{0}">{1}</span>' -f $colors[[string]$row.StatusAntes], (ConvertTo-HWHtmlText $row.StatusAntes)
        $after = if ($row.StatusDepois) { '<span class="s" style="color:{0}">{1}</span>' -f $colors[[string]$row.StatusDepois], (ConvertTo-HWHtmlText $row.StatusDepois) } else { '' }
        $findings = (@($row.Achados) | ForEach-Object { ConvertTo-HWHtmlText $_ }) -join '<br>'
        $html.Add(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f
                $cells[0], $cells[1], $cells[2], $before, (ConvertTo-HWHtmlText $row.Acao), $after, $findings))
    }
    $html.Add('</table><p>Hardening reduz a superfície de ataque; não garante invulnerabilidade.</p></body></html>')
    Set-Content -LiteralPath (Join-Path $dir 'relatorio.html') -Value $html -Encoding UTF8 -WhatIf:$false -Confirm:$false
    return $report
}

Export-ModuleMember -Function 'New-HWRow', 'Get-HWExitCode', 'Export-HWReport'
