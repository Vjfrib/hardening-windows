Set-StrictMode -Version Latest

function Protect-HWCsvCell($Value) {
    if ([string]$Value -match '^\s*[=+@-]|^[\t\r\n]') { return "'$Value" }
    return $Value
}

function Save-HWReport {
    param($Report, [string]$Directory)
    $json = Join-Path $Directory 'results.json'
    $flat = @($Report.Controls | ForEach-Object {
        [pscustomobject]@{
            Id = Protect-HWCsvCell $_.Id
            Controle = Protect-HWCsvCell $_.Control
            Status = Protect-HWCsvCell $_.Status
            Operacao = Protect-HWCsvCell $_.Operation
            Antes = Protect-HWCsvCell (ConvertTo-Json -InputObject $_.Before -Depth 12 -Compress)
            Depois = Protect-HWCsvCell (ConvertTo-Json -InputObject $_.After -Depth 12 -Compress)
            Recomendado = Protect-HWCsvCell (ConvertTo-Json -InputObject $_.Recommended -Depth 12 -Compress)
            Evidencia = Protect-HWCsvCell $_.Evidence
            Observacoes = Protect-HWCsvCell $_.Note
        }
    })
    $heading = if ($Report.Metadata.Simulated) { 'Hardening Windows - SIMULACAO (dados ficticios)' }
               elseif ($Report.Metadata.WhatIf) { 'Hardening Windows - WhatIf (sem alteracao de politica)' }
               else { 'Hardening Windows - Evidencias da coleta' }
    $style = '<meta charset="utf-8"><style>body{font:14px Segoe UI,Arial,sans-serif;margin:30px;color:#182433}table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccd5df;padding:7px;vertical-align:top;overflow-wrap:anywhere}th{background:#edf2f9}</style>'
    $flat | Export-Csv -LiteralPath (Join-Path $Directory 'results.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
    $flat | ConvertTo-Html -Head $style -Title $heading -PreContent "<h1>$heading</h1>" |
        Set-Content -LiteralPath (Join-Path $Directory 'results.html') -Encoding UTF8 -WhatIf:$false -Confirm:$false
    $lines = @("# $heading", '', '| ID | Controle | Estado | Operacao |', '|---|---|---|---|')
    foreach ($row in $flat) {
        $cells = @($row.Id, $row.Controle, $row.Status, $row.Operacao) | ForEach-Object {
            [Net.WebUtility]::HtmlEncode([string]$_).Replace('|','&#124;') -replace '[\r\n]+',' '
        }
        $lines += '| ' + ($cells -join ' | ') + ' |'
    }
    $lines | Set-Content -LiteralPath (Join-Path $Directory 'results.md') -Encoding UTF8 -WhatIf:$false -Confirm:$false
    ConvertTo-Json -InputObject $Report -Depth 24 |
        Set-Content -LiteralPath $json -Encoding UTF8 -WhatIf:$false -Confirm:$false
    return $json
}

Export-ModuleMember -Function Save-HWReport
