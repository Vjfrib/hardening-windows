#Requires -Version 5.1
<#
.SYNOPSIS
    Verificação estática: analisa a sintaxe de todos os scripts e roda o PSScriptAnalyzer
    com as regras de compatibilidade do Windows PowerShell 5.1 (PSScriptAnalyzerSettings.psd1).
    Não executa nenhum controle. Roda em Windows ou Linux.
#>
[CmdletBinding()]
param([switch]$SkipAnalyzer)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$files = @(Get-ChildItem -LiteralPath $root -Recurse -Include '*.ps1', '*.psm1', '*.psd1' |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|saida)[\\/]' })
$failures = 0

foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) {
        $failures++
        Write-Warning ('{0}:{1} {2}' -f $file.Name, $e.Extent.StartLineNumber, $e.Message)
    }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) {
        $failures++
        Write-Warning "$($file.Name): sem BOM UTF-8 (o Windows PowerShell 5.1 leria os acentos errado)."
    }
}
Write-Information "Sintaxe e codificação: $($files.Count) arquivos verificados." -InformationAction Continue

if (-not $SkipAnalyzer) {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        throw 'PSScriptAnalyzer não instalado. Instale com: Install-Module PSScriptAnalyzer -Scope CurrentUser'
    }
    # Código que roda na máquina: regras de compatibilidade com o Windows PowerShell 5.1.
    # Testes usam Pester 5 (Should -Be etc.), que não existe no 5.1 de fábrica: sem essas regras.
    $settings = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'PSScriptAnalyzerSettings.psd1')
    $testSettings = @{ Severity = $settings.Severity; ExcludeRules = $settings.ExcludeRules; Rules = @{ PSUseCompatibleSyntax = $settings.Rules.PSUseCompatibleSyntax } }
    $results = @()
    $results += Invoke-ScriptAnalyzer -Path (Join-Path $root 'Main.ps1') -Settings $settings
    $results += Invoke-ScriptAnalyzer -Path (Join-Path $root 'scripts') -Recurse -Settings $settings
    $results += Invoke-ScriptAnalyzer -Path (Join-Path $root 'tests') -Recurse -Settings $testSettings
    $results = @($results | Where-Object { $_ })
    foreach ($r in $results) {
        $failures++
        Write-Warning ('{0}:{1} [{2}] {3}' -f $r.ScriptName, $r.Line, $r.RuleName, $r.Message)
    }
    Write-Information "PSScriptAnalyzer: $($results.Count) apontamento(s)." -InformationAction Continue
}

if ($failures -gt 0) { Write-Warning "$failures problema(s) encontrado(s)."; exit 1 }
Write-Information 'Verificação estática sem problemas.' -InformationAction Continue
exit 0
