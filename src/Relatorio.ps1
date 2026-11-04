# Geração do relatório da execução (HTML e CSV).
# Este arquivo é carregado (dot-source) pelo Invoke-Hardening.ps1.

function ConvertTo-HtmlSeguro {
    param([AllowNull()][string]$Texto)
    if ($null -eq $Texto) { return '' }
    return ([System.Net.WebUtility]::HtmlEncode($Texto) -replace "`r?`n", '<br>')
}

function Format-CelulaStatus {
    param([string]$Status, [string]$Valor)
    if (-not $Status) { return '<td class="vazio">-</td>' }
    $classe = $Status.ToLower()
    return ('<td><span class="status {0}">{1}</span><div class="valor">{2}</div></td>' -f $classe, (ConvertTo-HtmlSeguro $Status), (ConvertTo-HtmlSeguro $Valor))
}

function Export-Relatorio {
    param(
        [Parameter(Mandatory = $true)][object[]]$Resultados,
        [Parameter(Mandatory = $true)][string]$Pasta,
        [Parameter(Mandatory = $true)][string]$Modo,
        [Parameter(Mandatory = $true)][datetime]$Inicio
    )
    $csv = Join-Path $Pasta 'resultado.csv'
    $Resultados | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -UseCulture

    $so = Get-CimInstance Win32_OperatingSystem
    $contagem = $Resultados | Group-Object StatusFinal | Sort-Object Name |
        ForEach-Object { '<span class="status {0}">{1}: {2}</span>' -f $_.Name.ToLower(), $_.Name, $_.Count }

    $linhas = foreach ($r in $Resultados) {
        '<tr><td class="id">{0}</td><td><strong>{1}</strong><div class="secao">{2}</div></td><td>{3}</td>{4}{5}<td>{6}</td><td class="detalhes">{7}</td></tr>' -f `
            $r.Id, (ConvertTo-HtmlSeguro $r.Item), (ConvertTo-HtmlSeguro $r.Secao), (ConvertTo-HtmlSeguro $r.Esperado),
            (Format-CelulaStatus $r.StatusAntes $r.ValorAntes), (Format-CelulaStatus $r.StatusDepois $r.ValorDepois),
            (ConvertTo-HtmlSeguro $r.Acao), (ConvertTo-HtmlSeguro $r.Detalhes)
    }

    $html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>Hardening Windows - $Modo - $env:COMPUTERNAME</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1b1b1b; background: #fff; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .meta { color: #555; font-size: 13px; margin-bottom: 16px; }
  .resumo { margin-bottom: 16px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { border: 1px solid #d0d0d0; padding: 6px 8px; vertical-align: top; text-align: left; }
  th { background: #f2f2f2; }
  .id { text-align: center; font-weight: bold; }
  .secao, .valor { color: #555; font-size: 12px; margin-top: 2px; }
  .detalhes { font-size: 12px; color: #333; max-width: 420px; }
  .vazio { color: #999; text-align: center; }
  .status { display: inline-block; padding: 1px 6px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-right: 6px; }
  .ok { background: #dff3e4; color: #145a2a; }
  .falha { background: #fbe0e0; color: #8a1414; }
  .revisar { background: #fff1cc; color: #6b4e00; }
  .erro { background: #e9e0fb; color: #4a1a8a; }
</style>
</head>
<body>
<h1>Hardening Windows: contas e políticas de acesso</h1>
<div class="meta">
  Máquina: <strong>$env:COMPUTERNAME</strong> &middot; $(ConvertTo-HtmlSeguro $so.Caption) ($($so.Version)) &middot;
  Modo: <strong>$Modo</strong> &middot; Usuário: $(ConvertTo-HtmlSeguro "$env:USERDOMAIN\$env:USERNAME") &middot;
  Início: $($Inicio.ToString('dd/MM/yyyy HH:mm:ss'))
</div>
<div class="resumo">$($contagem -join ' ')</div>
<table>
<thead><tr><th>#</th><th>Item</th><th>Esperado</th><th>Antes</th><th>Depois</th><th>Ação</th><th>Detalhes</th></tr></thead>
<tbody>
$($linhas -join "`n")
</tbody>
</table>
<p class="meta">OK = conforme o checklist. FALHA = fora do checklist. REVISAR = depende de uma decisão da ATI-PE (veja Detalhes). ERRO = o script não conseguiu verificar ou aplicar.</p>
</body>
</html>
"@
    $arquivoHtml = Join-Path $Pasta 'relatorio.html'
    Set-Content -Path $arquivoHtml -Value $html -Encoding UTF8
    return $arquivoHtml
}
