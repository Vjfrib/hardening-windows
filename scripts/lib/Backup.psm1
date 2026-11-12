#Requires -Version 5.1
<#
    Backup.psm1 · backup com escopo antes de aplicar e leitura para o rollback.

    O backup guarda o estado observado (Get) de cada controle que será alterado,
    com a impressão digital da máquina e um hash SHA-256 do arquivo. Também tenta
    exportar cópias completas (secedit, auditpol, chave do UAC) para consulta manual.

    Backup local NÃO substitui o snapshot externo da VM: ele só cobre a
    configuração que os controles sabem restaurar.
#>
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

$script:BackupFile = 'backup-escopo.json'

function Get-HWFileSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return (-join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })) }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function New-HWBackup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$States,
        [Parameter(Mandatory)]$Machine
    )
    $directory = $Context.BackupDirectory
    if (-not $PSCmdlet.ShouldProcess($directory, 'Gravar backup com escopo')) { return $null }
    New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false -Confirm:$false | Out-Null

    $payload = [pscustomobject]@{
        SchemaVersion = 1
        CreatedUtc    = [DateTime]::UtcNow.ToString('o')
        ComputerName  = $Machine.ComputerName
        Fingerprint   = $Machine.Fingerprint
        OsBuild       = $Machine.OsBuild
        Controls      = @($States | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Observed = $_.Observed } })
    }
    $path = Join-Path $directory $script:BackupFile
    $json = ConvertTo-Json -InputObject $payload -Depth 10
    Set-Content -LiteralPath $path -Value $json -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Set-Content -LiteralPath "$path.sha256" -Value (Get-HWFileSha256 -Path $path) -Encoding ASCII -WhatIf:$false -Confirm:$false

    # Cópias completas, só para consulta e recuperação manual.
    $exports = @(
        @{ Name = 'politica-local.inf'; Command = { param($f) & secedit.exe /export /cfg $f /quiet 2>&1 } }
        @{ Name = 'auditpol.csv'; Command = { param($f) & auditpol.exe /backup "/file:$f" 2>&1 } }
        @{ Name = 'uac.reg'; Command = { param($f) & reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' $f /y 2>&1 } }
    )
    $ErrorActionPreference = 'Continue'
    foreach ($export in $exports) {
        $file = Join-Path $directory $export.Name
        try {
            $null = & $export.Command $file
            if ($LASTEXITCODE -ne 0) { throw "código $LASTEXITCODE" }
        } catch {
            Write-HWLog -Context $Context -Level Aviso -Message "Cópia complementar $($export.Name) não gerada: $($_.Exception.Message)"
        }
    }
    Write-HWLog -Context $Context -Message "Backup com escopo gravado em $path"
    return $path
}

function Read-HWBackup {
    <# Lê o backup, confere o hash e confere que pertence a esta máquina. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Machine)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $candidate = Join-Path $Path $script:BackupFile
        if (-not (Test-Path -LiteralPath $candidate)) { $candidate = Join-Path (Join-Path $Path 'backup') $script:BackupFile }
        $Path = $candidate
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Backup não encontrado: $Path" }
    $hashFile = "$Path.sha256"
    if (-not (Test-Path -LiteralPath $hashFile)) { throw 'Arquivo .sha256 do backup ausente.' }
    $expected = (Get-Content -LiteralPath $hashFile -Raw).Trim()
    if ($expected -ne (Get-HWFileSha256 -Path $Path)) { throw 'Hash do backup não confere: arquivo alterado ou corrompido.' }
    $backup = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($backup.SchemaVersion -ne 1) { throw 'Versão de backup desconhecida.' }
    if ($backup.Fingerprint -ne $Machine.Fingerprint) {
        throw "Backup de outra máquina ($($backup.ComputerName)). Restauração recusada."
    }
    return $backup
}

Export-ModuleMember -Function 'New-HWBackup', 'Read-HWBackup', 'Get-HWFileSha256'
