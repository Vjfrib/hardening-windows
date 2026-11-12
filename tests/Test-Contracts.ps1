#Requires -Version 5.1
<#
.SYNOPSIS
    Roda os testes Pester (tests/pester): bibliotecas, contratos dos 16 controles com dublês
    e o comportamento do Main.ps1. Nenhum teste altera a máquina. Exige Pester 5.
#>
[CmdletBinding()]
param([string]$ResultPath)

$ErrorActionPreference = 'Stop'
$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) { throw 'Pester 5 não encontrado. Instale com: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -SkipPublisherCheck' }
Import-Module $pester -Force

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'pester'
$config.Run.Exit = $false
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
if ($ResultPath) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = $ResultPath
}
$result = Invoke-Pester -Configuration $config
Write-Information ("Pester: {0} passaram, {1} falharam, {2} ignorados, {3} arquivo(s) com falha de carga." -f $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.FailedContainersCount) -InformationAction Continue
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) { exit 1 }
exit 0
