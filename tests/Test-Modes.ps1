[CmdletBinding()]
param([string]$ScratchDirectory = [IO.Path]::GetTempPath())

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path $PSScriptRoot -Parent
$main = Join-Path $root 'Main.ps1'
$engine = (Get-Process -Id $PID).Path
$scratchParent = Get-Item -LiteralPath $ScratchDirectory
if (-not $scratchParent.PSIsContainer) { throw 'ScratchDirectory must be an existing directory.' }
$scratch = Join-Path $scratchParent.FullName ('hardening-modes-' + [guid]::NewGuid().ToString('N'))

function Invoke-Main {
    param([string]$EntryPoint, [string[]]$Arguments, [int]$ExpectedExit, [string]$ExpectedMessage)
    # A rejected invocation may print to stderr. Use its exit code for assertions.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $messages = & $engine -NoProfile -NonInteractive -File $EntryPoint @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne $ExpectedExit) {
        throw "Main $($Arguments -join ' ') returned $LASTEXITCODE, expected $ExpectedExit.$([Environment]::NewLine)$messages"
    }
    if ($ExpectedMessage -and $messages -notmatch $ExpectedMessage) {
        throw "Main did not report '$ExpectedMessage'.$([Environment]::NewLine)$messages"
    }
}

function Get-OnlyRun([string]$OutputDirectory) {
    $runs = @(Get-ChildItem -LiteralPath $OutputDirectory -Directory)
    if ($runs.Count -ne 1) { throw "Expected one run under $OutputDirectory, got $($runs.Count)." }
    return $runs[0]
}

New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $demoOutput = Join-Path $scratch 'demo'
    $missingConfig = Join-Path $scratch 'missing-config.json'
    Invoke-Main $main @('-Demo', '-OutputDirectory', $demoOutput, '-ConfigPath', $missingConfig) 3
    $run = Get-OnlyRun $demoOutput
    $jsonPath = Join-Path $run.FullName 'results.json'
    $report = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $ids = (1..16 | ForEach-Object { '{0:00}' -f $_ }) -join ','
    if ($report.Mode -ne 'Demo' -or $report.Metadata.Simulated -ne $true -or
        $report.ExitCode -ne 3 -or ($report.Controls.Id -join ',') -ne $ids) {
        throw 'Demo did not record the 16 controls as a simulation.'
    }
    $unexpected = @($report.Controls | Where-Object {
        $_.Status -ne 'ManualReview' -or $_.Before -cne 'FICTICIO' -or
        $_.After -cne 'FICTICIO' -or $_.Operation -ne 'ReadOnly'
    })
    if ($unexpected.Count -gt 0) { throw 'Demo returned unexpected data or state.' }

    $beforeReplay = ConvertTo-Json -InputObject $report -Depth 24 -Compress
    foreach ($format in 'csv','html','md') {
        Remove-Item -LiteralPath (Join-Path $run.FullName "results.$format")
    }
    Invoke-Main $main @('-Mode', 'Report', '-OutputDirectory', $run.FullName, '-ConfigPath', $missingConfig) 3
    $replayed = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    if ((ConvertTo-Json -InputObject $replayed -Depth 24 -Compress) -cne $beforeReplay) {
        throw 'Report did not preserve the saved collection.'
    }
    foreach ($format in 'csv','html','md') {
        if (-not (Test-Path -LiteralPath (Join-Path $run.FullName "results.$format") -PathType Leaf)) {
            throw "Report did not regenerate results.$format."
        }
    }
    if ((Get-Content -LiteralPath (Join-Path $run.FullName 'results.html') -Raw) -notmatch 'SIMULACAO') {
        throw 'The regenerated demo HTML did not preserve its simulation label.'
    }
    $null = Get-OnlyRun $demoOutput

    foreach ($mode in 'Apply','Rollback') {
        $rejectedOutput = Join-Path $scratch "rejected-$mode"
        $arguments = @('-Mode', $mode, '-Demo', '-ControlIds', '01', '-OutputDirectory', $rejectedOutput)
        if ($mode -eq 'Rollback') { $arguments += @('-BackupPath', (Join-Path $run.FullName 'results.json')) }
        Invoke-Main $main $arguments 1 '-Demo somente'
        if (Test-Path -LiteralPath $rejectedOutput) { throw "$mode accepted -Demo." }
    }

    # Use the real entry point and report modules, but replace native host access
    # and control logic in a temporary copy before testing an application preview.
    $mockRoot = Join-Path $scratch 'mock'
    New-Item -ItemType Directory -Path $mockRoot | Out-Null
    Copy-Item -LiteralPath $main -Destination $mockRoot
    Copy-Item -LiteralPath (Join-Path $root 'scripts') -Destination $mockRoot -Recurse

    @'
function Assert-HWWindows {}
function Test-HWAdministrator { $false }
function Test-HWDomainMember { $false }
function Read-HWJson([string]$Path) {
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}
'@ | Set-Content -LiteralPath (Join-Path $mockRoot 'scripts/lib/Common.psm1') -Encoding UTF8

    @'
function Get-HW01State($Profile) {
    [pscustomobject]@{
        Id = '01'; Control = 'Fixture'; Current = 8; Expected = $Profile.Password.MinLength
        Status = 'NonCompliant'; Compliant = $false; Note = ''
    }
}
function Set-HW01State($Profile) {
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'setter-called.txt'), 'unexpected setter')
    throw 'Setter ran under WhatIf.'
}
'@ | Set-Content -LiteralPath (Join-Path $mockRoot 'scripts/controles/01-SenhaMinima.ps1') -Encoding UTF8

    $previewOutput = Join-Path $scratch 'preview'
    $mockMain = Join-Path $mockRoot 'Main.ps1'
    Invoke-Main $mockMain @(
        '-Mode', 'Apply', '-ControlIds', '01', '-WhatIf',
        '-OutputDirectory', $previewOutput, '-ApprovalPath', $missingConfig
    ) 3
    $previewRun = Get-OnlyRun $previewOutput
    $preview = Get-Content -LiteralPath (Join-Path $previewRun.FullName 'results.json') -Raw | ConvertFrom-Json
    if ($preview.Metadata.WhatIf -ne $true -or $preview.Controls.Operation -ne 'WhatIf' -or
        $preview.Controls.Before -ne $preview.Controls.After -or
        (Test-Path -LiteralPath (Join-Path $previewRun.FullName 'backups')) -or
        (Test-Path -LiteralPath (Join-Path $mockRoot 'scripts/controles/setter-called.txt'))) {
        throw 'Apply -WhatIf did not remain read-only.'
    }
    Write-Host 'OK: Demo, Report, rejected Demo mutations, and read-only Apply -WhatIf.'
} finally {
    $created = Get-Item -LiteralPath $scratch -ErrorAction SilentlyContinue
    if ($null -ne $created -and $created.Parent.FullName -eq $scratchParent.FullName -and
        $created.Name -match '^hardening-modes-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $created.FullName -Recurse -Force
    }
}
