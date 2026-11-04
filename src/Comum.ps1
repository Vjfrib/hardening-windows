# Funções de apoio usadas pelos itens do checklist.
# Este arquivo é carregado (dot-source) pelo Invoke-Hardening.ps1.

# SIDs conhecidos. Usamos SIDs, e não nomes, porque os nomes mudam com o
# idioma do Windows ("Administrators" x "Administradores").
$script:SID = @{
    Sistema          = 'S-1-5-18'
    Administradores  = 'S-1-5-32-544'
    Convidados       = 'S-1-5-32-546'
    ContaLocal       = 'S-1-5-113'
    # SIDs de serviço (fixos: derivados do nome do serviço)
    EventLog         = 'S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122'
    TrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
}

# GUIDs das subcategorias do auditpol. Os nomes das subcategorias mudam com o
# idioma do Windows; os GUIDs não.
$script:Subcategoria = @{
    Logon                       = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    BloqueioDeConta             = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    GerenciamentoDeContaUsuario = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    GerenciamentoDeGrupoSeguranca = '{0CCE9237-69AE-11D9-BED3-505054503030}'
}

$script:CacheDiretiva = $null
$script:PastaEvidencias = $null
$script:Fase = 'antes'

# ----------------------------------------------------------------------
# Geral
# ----------------------------------------------------------------------

function Test-Administrador {
    $identidade = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identidade
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Resultado padrão de um teste. Status: OK, FALHA ou REVISAR.
function New-Resultado {
    param(
        [bool]$Conforme = $false,
        [string]$Status = '',
        [string]$Valor = '',
        [string]$Detalhes = ''
    )
    if (-not $Status) {
        if ($Conforme) { $Status = 'OK' } else { $Status = 'FALHA' }
    }
    [pscustomobject]@{
        Status   = $Status
        Valor    = $Valor
        Detalhes = $Detalhes
    }
}

# Salva uma evidência (lista ou texto) na pasta da execução, separada por fase
# (antes/depois), como pede a seção 4 do checklist.
function Save-Evidencia {
    param(
        [Parameter(Mandatory = $true)][string]$Nome,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()]$Dados
    )
    if (-not $script:PastaEvidencias) { return }
    if (-not (Test-Path $script:PastaEvidencias)) {
        New-Item -ItemType Directory -Path $script:PastaEvidencias -Force | Out-Null
    }
    $caminho = Join-Path $script:PastaEvidencias ("{0}-{1}" -f $script:Fase, $Nome)
    if ($Nome -like '*.csv') {
        @($Dados) | Export-Csv -Path $caminho -NoTypeInformation -Encoding UTF8 -UseCulture
    } else {
        $Dados | Out-File -FilePath $caminho -Encoding UTF8
    }
}

# Executa um programa do Windows e devolve a saída. Lança erro se o código de
# saída não for zero. Não redireciona stderr: no Windows PowerShell 5.1 isso
# vira exceção quando $ErrorActionPreference = 'Stop'.
function Invoke-Programa {
    param(
        [Parameter(Mandatory = $true)][string]$Programa,
        [string[]]$Argumentos = @(),
        [int[]]$CodigosAceitos = @(0)
    )
    $saida = & $Programa @Argumentos
    if ($CodigosAceitos -notcontains $LASTEXITCODE) {
        throw ("{0} {1} terminou com código {2}. Saída: {3}" -f $Programa, ($Argumentos -join ' '), $LASTEXITCODE, ($saida -join ' '))
    }
    return $saida
}

# ----------------------------------------------------------------------
# Contas e SIDs
# ----------------------------------------------------------------------

function ConvertTo-Sid {
    param([Parameter(Mandatory = $true)][string]$Conta)
    $conta = $Conta.Trim()
    if ($conta.StartsWith('*')) { return $conta.Substring(1) }
    if ($conta -match '^S-1-') { return $conta }
    if ($conta.StartsWith('.\')) { $conta = $env:COMPUTERNAME + $conta.Substring(1) }
    try {
        return (New-Object Security.Principal.NTAccount $conta).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Não foi possível encontrar a conta '$Conta'."
    }
}

function ConvertTo-NomeConta {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate([Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

# Conta local pelo RID (500 = Administrador padrão, 501 = Convidado).
function Get-ContaLocalPorRid {
    param([Parameter(Mandatory = $true)][int]$Rid)
    Get-LocalUser | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1
}

# ----------------------------------------------------------------------
# Diretiva de segurança local (secedit)
# ----------------------------------------------------------------------

# Converte o texto de um arquivo .inf do secedit em: seção -> chave -> valor.
function ConvertFrom-ArquivoInf {
    param([string[]]$Conteudo)
    $resultado = @{}
    $secao = $null
    foreach ($linha in $Conteudo) {
        $texto = $linha.Trim()
        if ($texto -eq '' -or $texto.StartsWith(';')) { continue }
        if ($texto -match '^\[(.+)\]$') {
            $secao = $Matches[1]
            $resultado[$secao] = @{}
            continue
        }
        if ($null -eq $secao) { continue }
        $posicao = $texto.IndexOf('=')
        if ($posicao -lt 0) { continue }
        $chave = $texto.Substring(0, $posicao).Trim()
        $valor = $texto.Substring($posicao + 1).Trim()
        $resultado[$secao][$chave] = $valor
    }
    return $resultado
}

# Exporta a diretiva de segurança local. O resultado fica em cache até a
# próxima alteração.
function Get-DiretivaSeguranca {
    if ($null -ne $script:CacheDiretiva) { return $script:CacheDiretiva }
    $arquivo = Join-Path $env:TEMP ("hardening-export-{0}.inf" -f [guid]::NewGuid())
    try {
        Invoke-Programa -Programa 'secedit.exe' -Argumentos @('/export', '/cfg', $arquivo, '/quiet') | Out-Null
        $script:CacheDiretiva = ConvertFrom-ArquivoInf -Conteudo (Get-Content -Path $arquivo -Encoding Unicode)
    } finally {
        Remove-Item -Path $arquivo -ErrorAction SilentlyContinue
    }
    return $script:CacheDiretiva
}

function Clear-CacheDiretiva {
    $script:CacheDiretiva = $null
}

function Get-ValorDiretiva {
    param(
        [Parameter(Mandatory = $true)][string]$Secao,
        [Parameter(Mandatory = $true)][string]$Chave
    )
    $diretiva = Get-DiretivaSeguranca
    if ($diretiva.ContainsKey($Secao) -and $diretiva[$Secao].ContainsKey($Chave)) {
        return $diretiva[$Secao][$Chave]
    }
    return $null
}

# Aplica valores numa seção da diretiva de segurança local com secedit.
#   Area SECURITYPOLICY: seção [System Access] (senha e bloqueio)
#   Area USER_RIGHTS:    seção [Privilege Rights] (atribuição de direitos de usuário)
function Set-DiretivaSeguranca {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('System Access', 'Privilege Rights')][string]$Secao,
        [Parameter(Mandatory = $true)][hashtable]$Valores
    )
    if ($Secao -eq 'System Access') { $area = 'SECURITYPOLICY' } else { $area = 'USER_RIGHTS' }
    $base = Join-Path $env:TEMP ("hardening-{0}" -f [guid]::NewGuid())
    $linhas = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', "[$Secao]")
    foreach ($chave in $Valores.Keys) {
        $linhas += ("{0} = {1}" -f $chave, $Valores[$chave])
    }
    try {
        Set-Content -Path "$base.inf" -Value $linhas -Encoding Unicode
        $saida = & secedit.exe /configure /db "$base.sdb" /cfg "$base.inf" /areas $area /log "$base.log" /quiet
        if ($LASTEXITCODE -ne 0) {
            # O secedit às vezes devolve código diferente de zero só por avisos.
            # O teste "depois" confirma se a mudança entrou de fato.
            Write-Warning ("secedit /configure terminou com código {0}: {1}" -f $LASTEXITCODE, ($saida -join ' '))
        }
    } finally {
        Remove-Item -Path "$base.*" -ErrorAction SilentlyContinue
        Clear-CacheDiretiva
    }
}

# Contas (SIDs) que têm um direito de usuário, por exemplo SeDebugPrivilege.
function Get-DireitoUsuario {
    param([Parameter(Mandatory = $true)][string]$Direito)
    $valor = Get-ValorDiretiva -Secao 'Privilege Rights' -Chave $Direito
    if ([string]::IsNullOrWhiteSpace($valor)) { return @() }
    $sids = foreach ($parte in $valor.Split(',')) {
        if ($parte.Trim()) {
            try { ConvertTo-Sid $parte } catch { $parte.Trim() }
        }
    }
    return @($sids)
}

function Set-DireitoUsuario {
    param(
        [Parameter(Mandatory = $true)][string]$Direito,
        [Parameter(Mandatory = $true)][string[]]$Contas
    )
    $sids = $Contas | ForEach-Object { ConvertTo-Sid $_ } | Select-Object -Unique
    $valor = ($sids | ForEach-Object { "*$_" }) -join ','
    Set-DiretivaSeguranca -Secao 'Privilege Rights' -Valores @{ $Direito = $valor }
}

# Texto legível com os nomes das contas de um direito de usuário.
function Format-ListaContas {
    param([string[]]$Sids)
    if (-not $Sids -or $Sids.Count -eq 0) { return '(ninguém)' }
    return (($Sids | ForEach-Object { ConvertTo-NomeConta $_ }) -join ', ')
}

# ----------------------------------------------------------------------
# Registro
# ----------------------------------------------------------------------

function Get-ValorRegistro {
    param(
        [Parameter(Mandatory = $true)][string]$Caminho,
        [Parameter(Mandatory = $true)][string]$Nome
    )
    $item = Get-ItemProperty -Path $Caminho -Name $Nome -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Nome
}

function Set-ValorRegistro {
    param(
        [Parameter(Mandatory = $true)][string]$Caminho,
        [Parameter(Mandatory = $true)][string]$Nome,
        [Parameter(Mandatory = $true)][int]$Valor
    )
    if (-not (Test-Path $Caminho)) { New-Item -Path $Caminho -Force | Out-Null }
    New-ItemProperty -Path $Caminho -Name $Nome -Value $Valor -PropertyType DWord -Force | Out-Null
}

# ----------------------------------------------------------------------
# Auditoria (auditpol)
# ----------------------------------------------------------------------

# Valor de auditoria de uma subcategoria: 0 = nada, 1 = sucesso, 2 = falha,
# 3 = sucesso e falha. Lê o backup do auditpol, que traz números e GUIDs em
# vez de textos traduzidos.
function Get-ValorAuditoria {
    param([Parameter(Mandatory = $true)][string]$Guid)
    $arquivo = Join-Path $env:TEMP ("hardening-auditpol-{0}.csv" -f [guid]::NewGuid())
    try {
        Invoke-Programa -Programa 'auditpol.exe' -Argumentos @('/backup', "/file:$arquivo") | Out-Null
        foreach ($linha in (Get-Content -Path $arquivo)) {
            if ($linha -like "*$Guid*" -and $linha -match ',(\d+)\s*$') {
                return [int]$Matches[1]
            }
        }
        return 0
    } finally {
        Remove-Item -Path $arquivo -ErrorAction SilentlyContinue
    }
}

function Format-ValorAuditoria {
    param([int]$Valor)
    switch ($Valor) {
        0 { 'Sem auditoria' }
        1 { 'Sucesso' }
        2 { 'Falha' }
        3 { 'Sucesso e falha' }
        default { "Valor $Valor" }
    }
}

# Liga a auditoria de sucesso e/ou falha sem desligar o que já estiver ligado.
function Enable-Auditoria {
    param(
        [Parameter(Mandatory = $true)][string]$Guid,
        [switch]$Sucesso,
        [switch]$Falha
    )
    # Faz as subcategorias valerem mais que as categorias antigas (CIS 2.3.2.1).
    Set-ValorRegistro -Caminho 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Nome 'SCENoApplyLegacyAuditPolicy' -Valor 1
    $argumentos = @('/set', "/subcategory:$Guid")
    if ($Sucesso) { $argumentos += '/success:enable' }
    if ($Falha) { $argumentos += '/failure:enable' }
    Invoke-Programa -Programa 'auditpol.exe' -Argumentos $argumentos | Out-Null
}

# ----------------------------------------------------------------------
# Rede
# ----------------------------------------------------------------------

# Portas TCP em escuta, com o processo dono. Ignora endereços de loopback,
# que não podem ser acessados de outra máquina.
function Get-PortasEmEscuta {
    param([bool]$IgnorarDinamicas = $true)
    $processos = @{}
    Get-Process | ForEach-Object { $processos[[int]$_.Id] = $_.ProcessName }
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } |
        Where-Object { -not ($IgnorarDinamicas -and $_.LocalPort -ge 49152) } |
        ForEach-Object {
            [pscustomobject]@{
                Porta    = [int]$_.LocalPort
                Endereco = $_.LocalAddress
                Processo = $processos[[int]$_.OwningProcess]
            }
        } |
        Sort-Object Porta, Processo, Endereco -Unique
}

# ----------------------------------------------------------------------
# Backup antes do modo Aplicar
# ----------------------------------------------------------------------

function Save-Backup {
    param([Parameter(Mandatory = $true)][string]$Pasta)
    New-Item -ItemType Directory -Path $Pasta -Force | Out-Null
    $passos = [ordered]@{
        'diretiva de segurança (secedit)' = { Invoke-Programa -Programa 'secedit.exe' -Argumentos @('/export', '/cfg', (Join-Path $Pasta 'diretiva-seguranca.inf'), '/quiet') | Out-Null }
        'auditoria (auditpol)'            = { Invoke-Programa -Programa 'auditpol.exe' -Argumentos @('/backup', ("/file:" + (Join-Path $Pasta 'auditoria.csv'))) | Out-Null }
        'firewall (netsh)'                = { Invoke-Programa -Programa 'netsh.exe' -Argumentos @('advfirewall', 'export', (Join-Path $Pasta 'firewall.wfw')) | Out-Null }
        'registro do UAC'                 = { Invoke-Programa -Programa 'reg.exe' -Argumentos @('export', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', (Join-Path $Pasta 'uac.reg'), '/y') | Out-Null }
        'registro da LSA'                 = { Invoke-Programa -Programa 'reg.exe' -Argumentos @('export', 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa', (Join-Path $Pasta 'lsa.reg'), '/y') | Out-Null }
        'permissões da pasta de logs'     = { Invoke-Programa -Programa 'icacls.exe' -Argumentos @((Join-Path $env:windir 'System32\winevt\Logs'), '/save', (Join-Path $Pasta 'permissoes-winevt-logs.txt')) | Out-Null }
        'contas locais'                   = { Get-LocalUser | Select-Object Name, SID, Enabled, LastLogon, Description | Export-Csv -Path (Join-Path $Pasta 'contas-locais.csv') -NoTypeInformation -Encoding UTF8 }
        'serviços'                        = { Get-CimInstance Win32_Service | Select-Object Name, DisplayName, StartMode, State, StartName | Export-Csv -Path (Join-Path $Pasta 'servicos.csv') -NoTypeInformation -Encoding UTF8 }
    }
    foreach ($nome in $passos.Keys) {
        try {
            & $passos[$nome]
            Write-Host "  backup: $nome" -ForegroundColor DarkGray
        } catch {
            Write-Warning "Falha no backup de $nome : $($_.Exception.Message)"
        }
    }
}
