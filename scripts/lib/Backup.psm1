Set-StrictMode -Version Latest

function Get-HWMachineFingerprint {
    $guid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $bytes = [Text.Encoding]::UTF8.GetBytes(([guid]$guid).ToString('D'))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','') }
    finally { $sha.Dispose() }
}

function Write-HWBackup {
    param([string]$Path, $Entry)
    $temp = "$Path.tmp"
    try {
        ConvertTo-Json -InputObject $Entry -Depth 16 | Set-Content -LiteralPath $temp -Encoding UTF8
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Save-HWNativeEvidence {
    param([string]$Directory, [string]$Id)
    if ($Id -in '01','02','03','04','05','06') {
        foreach ($kind in 'local','effective') {
            $file = Join-Path $Directory "$Id-$kind.inf"
            $arguments = @('/export','/cfg',$file,'/areas','SECURITYPOLICY','/quiet')
            if ($kind -eq 'effective') { $arguments += '/mergedpolicy' }
            $message = & secedit.exe @arguments 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
                throw "Falha ao exportar a politica $kind para o backup: $message"
            }
        }
    }
    if ($Id -in '11','14') {
        $file = Join-Path $Directory "$Id-audit.csv"
        $message = & auditpol.exe /backup "/file:$file" 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
            throw "Falha ao exportar a politica de auditoria para o backup: $message"
        }
    }
}

Export-ModuleMember -Function Get-HWMachineFingerprint,Write-HWBackup,Save-HWNativeEvidence
