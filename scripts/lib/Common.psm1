#Requires -Version 5.1
<#
    Common.psm1 · utilidades compartilhadas pelos 16 controles.

    - Catálogo dos controles (ID, nome, grupo, arquivo, tipo).
    - Objetos de estado (Get/Test) e de mudança (Set/Restore).
    - Log da execução.
    - Leitura e escrita da política de segurança local (secedit).
    - Leitura e escrita das subcategorias de auditoria (auditpol).
    - Leitura e escrita de valores do registro.
    - Contas e grupos locais identificados por SID.
#>
Set-StrictMode -Version Latest

$script:HWCatalog = @(
    [pscustomobject]@{ Id = '01'; Nome = 'Comprimento mínimo da senha'; Grupo = 'Autenticação'; Arquivo = '01-SenhaMinima.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '02'; Nome = 'Complexidade de senha'; Grupo = 'Autenticação'; Arquivo = '02-ComplexidadeSenha.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '03'; Nome = 'Histórico de senhas'; Grupo = 'Autenticação'; Arquivo = '03-HistoricoSenhas.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '04'; Nome = 'Validade máxima da senha'; Grupo = 'Autenticação'; Arquivo = '04-ValidadeSenha.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '05'; Nome = 'Bloqueio após tentativas inválidas'; Grupo = 'Autenticação'; Arquivo = '05-LimiteTentativas.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '06'; Nome = 'Duração do bloqueio'; Grupo = 'Autenticação'; Arquivo = '06-DuracaoBloqueio.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '07'; Nome = 'Renomear Administrador (SID -500)'; Grupo = 'Identidades e acesso'; Arquivo = '07-RenomearAdministrador.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '08'; Nome = 'Desabilitar Convidado (SID -501)'; Grupo = 'Identidades e acesso'; Arquivo = '08-DesabilitarConvidado.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '09'; Nome = 'UAC elevado e área de trabalho segura'; Grupo = 'Identidades e acesso'; Arquivo = '09-UAC.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '10'; Nome = 'Logon de rede de contas locais'; Grupo = 'Identidades e acesso'; Arquivo = '10-LogonRedeContasLocais.ps1'; Tipo = 'SomenteAuditoria' }
    [pscustomobject]@{ Id = '11'; Nome = 'Auditoria de logon'; Grupo = 'Rastreabilidade'; Arquivo = '11-AuditoriaLogon.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '12'; Nome = 'Firewall e portas'; Grupo = 'Rastreabilidade'; Arquivo = '12-FirewallEPortas.ps1'; Tipo = 'SomenteAuditoria' }
    [pscustomobject]@{ Id = '13'; Nome = 'Proteção de logs'; Grupo = 'Rastreabilidade'; Arquivo = '13-ProtecaoLogs.ps1'; Tipo = 'SomenteAuditoria' }
    [pscustomobject]@{ Id = '14'; Nome = 'Contas e grupos'; Grupo = 'Rastreabilidade'; Arquivo = '14-UsuariosEGrupos.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '15'; Nome = 'Aplicações e recursos'; Grupo = 'Superfície'; Arquivo = '15-AplicacoesERecursos.ps1'; Tipo = 'Aplicavel' }
    [pscustomobject]@{ Id = '16'; Nome = 'Serviços e contas de serviço'; Grupo = 'Superfície'; Arquivo = '16-ServicosEContasServico.ps1'; Tipo = 'SomenteAuditoria' }
)

# Chaves de [System Access] que os controles 01-06 podem alterar. Qualquer outra é recusada.
$script:HWSystemAccessKeys = @(
    'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize',
    'MaximumPasswordAge', 'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount'
)

function Get-HWControlCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string[]]$Id)
    if ($Id) { return @($script:HWCatalog | Where-Object { $_.Id -in $Id }) }
    return @($script:HWCatalog)
}

function New-HWContext {
    <# Cria o contexto em memória que circula entre Main, bibliotecas e controles. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cria apenas um objeto em memória.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$Mode,
        [string]$RunDirectory,
        [string]$TempDirectory = [IO.Path]::GetTempPath()
    )
    [pscustomobject]@{
        Config          = $Config
        Approval        = $null
        Mode            = $Mode
        RunDirectory    = $RunDirectory
        BackupDirectory = $null
        TempDirectory   = $TempDirectory
        LogPath         = $(if ($RunDirectory) { Join-Path $RunDirectory 'execucao.log' } else { $null })
        Cache           = @{}
        Machine         = $null
    }
}

function New-HWState {
    <#
        Resultado de Get-HWControlNN.
        Compliant: $true (conforme), $false (não conforme) ou $null (exige revisão humana).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cria apenas um objeto em memória.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^(0[1-9]|1[0-6])$')][string]$Id,
        [AllowNull()]$Observed,
        [AllowNull()]$Expected,
        [AllowNull()][Nullable[bool]]$Compliant,
        [string[]]$Findings = @(),
        [string]$Note = ''
    )
    $status = if ($null -eq $Compliant) { 'Revisar' } elseif ($Compliant) { 'Conforme' } else { 'NaoConforme' }
    [pscustomobject]@{
        Id        = $Id
        Status    = $status
        Compliant = $Compliant
        Observed  = $Observed
        Expected  = $Expected
        Findings  = @($Findings)
        Note      = $Note
    }
}

function New-HWErrorState {
    <# Estado usado quando o Get de um controle falha (ex.: falta de privilégio, cmdlet ausente). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cria apenas um objeto em memória.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Message)
    [pscustomobject]@{
        Id        = $Id
        Status    = 'Erro'
        Compliant = $null
        Observed  = $null
        Expected  = $null
        Findings  = @("Erro na auditoria: $Message")
        Note      = ''
    }
}

function New-HWChange {
    <# Resultado de Set-HWControlNN e Restore-HWControlNN. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Cria apenas um objeto em memória.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][bool]$Changed,
        [string[]]$Actions = @(),
        [bool]$RestartNeeded = $false
    )
    [pscustomobject]@{
        Changed       = $Changed
        Actions       = @($Actions)
        RestartNeeded = $RestartNeeded
    }
}

function Write-HWLog {
    [CmdletBinding()]
    param(
        [AllowNull()]$Context,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Aviso', 'Erro')][string]$Level = 'Info'
    )
    $line = '{0:yyyy-MM-ddTHH:mm:ss.fffK} [{1}] {2}' -f (Get-Date), $Level, $Message
    if ($Context -and $Context.LogPath) {
        Add-Content -LiteralPath $Context.LogPath -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }
    switch ($Level) {
        'Aviso' { Write-Warning $Message }
        'Erro' { Write-Warning "ERRO: $Message" }
        default { Write-Information $Message -InformationAction Continue }
    }
}

function Read-HWJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Arquivo não encontrado: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try { return ($raw | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "JSON inválido em ${Path}: $($_.Exception.Message)" }
}

function Save-HWJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [int]$Depth = 10
    )
    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8 -WhatIf:$false -Confirm:$false
}

function Test-HWProperty {
    <# Verifica se um objeto (JSON ou hashtable) tem a propriedade, sem quebrar o StrictMode. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Assert-HWProfile {
    <# Valida o perfil antes de qualquer controle usar seus valores. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    $required = @{
        Password = @('MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'MaximumPasswordAge',
            'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount')
        Accounts = @('AdministratorNewName', 'ApprovedAdministrators')
        Uac      = @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'PromptOnSecureDesktop')
        Firewall = @('AllowedListeningPorts')
        Logs     = @('SecurityMinimumSizeKB', 'SystemMinimumSizeKB', 'ClearEventLookbackDays')
        Features = @('Candidates', 'ApprovedToDisable')
        Services = @('ReviewIfRunning')
    }
    foreach ($section in $required.Keys) {
        if (-not (Test-HWProperty $Config $section)) { throw "Perfil sem a seção '$section'." }
        foreach ($key in $required[$section]) {
            if (-not (Test-HWProperty $Config.$section $key)) { throw "Perfil sem '$section.$key'." }
        }
    }
    $p = $Config.Password
    if ([int]$p.MinimumPasswordLength -lt 12) { throw 'Password.MinimumPasswordLength deve ser >= 12 (checklist).' }
    if ([int]$p.PasswordComplexity -ne 1) { throw 'Password.PasswordComplexity deve ser 1 (checklist).' }
    if ([int]$p.PasswordHistorySize -lt 5) { throw 'Password.PasswordHistorySize deve ser >= 5 (checklist).' }
    if ([int]$p.MaximumPasswordAge -lt 1 -or [int]$p.MaximumPasswordAge -gt 90) { throw 'Password.MaximumPasswordAge deve ficar entre 1 e 90 dias (checklist).' }
    if ([int]$p.LockoutBadCount -lt 1 -or [int]$p.LockoutBadCount -gt 5) { throw 'Password.LockoutBadCount deve ficar entre 1 e 5 (checklist).' }
    if ([int]$p.LockoutDuration -lt 15) { throw 'Password.LockoutDuration deve ser >= 15 minutos (checklist).' }
    if ([int]$p.ResetLockoutCount -lt 1 -or [int]$p.ResetLockoutCount -gt [int]$p.LockoutDuration) {
        throw 'Password.ResetLockoutCount deve ficar entre 1 e LockoutDuration (regra do Windows).'
    }
}

# ---------------------------------------------------------------- Plataforma

function Test-HWWindows {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
}

function Test-HWAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-HWWindows)) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HWMachineInfo {
    <# Dados da máquina usados para decidir se é possível aplicar e para identificar o backup. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $machineGuid = $null
    try {
        $machineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch { $machineGuid = 'indisponivel' }
    $vmPattern = 'Virtual|VMware|VirtualBox|KVM|QEMU|Xen|HVM domU|Bochs|Parallels'
    $isVm = ([string]$cs.Model -match $vmPattern) -or ([string]$cs.Manufacturer -match 'QEMU|Xen|innotek|VMware|Parallels')
    $raw = '{0}|{1}|{2}' -f $env:COMPUTERNAME, $machineGuid, $os.BuildNumber
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw)) | ForEach-Object { $_.ToString('x2') })
    } finally { $sha.Dispose() }
    [pscustomobject]@{
        ComputerName  = $env:COMPUTERNAME
        OsCaption     = [string]$os.Caption
        OsVersion     = [string]$os.Version
        OsBuild       = [int]$os.BuildNumber
        ProductType   = [int]$os.ProductType   # 1 estação, 2 controlador de domínio, 3 servidor
        PartOfDomain  = [bool]$cs.PartOfDomain
        Domain        = [string]$cs.Domain
        Manufacturer  = [string]$cs.Manufacturer
        Model         = [string]$cs.Model
        IsVirtual     = [bool]$isVm
        Fingerprint   = $hash
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        PSEdition     = [string]$PSVersionTable.PSEdition
    }
}

# ---------------------------------------------------------------- secedit

function ConvertFrom-HWIni {
    <# Converte o texto de um .inf exportado pelo secedit em hashtable de seções. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)
    $result = @{}
    $section = ''
    foreach ($line in $Lines) {
        $text = $line.Trim()
        if ($text -eq '' -or $text.StartsWith(';')) { continue }
        if ($text -match '^\[(.+)\]$') {
            $section = $Matches[1]
            if (-not $result.ContainsKey($section)) { $result[$section] = @{} }
            continue
        }
        $eq = $text.IndexOf('=')
        if ($eq -lt 1 -or $section -eq '') { continue }
        $key = $text.Substring(0, $eq).Trim()
        $value = $text.Substring($eq + 1).Trim()
        $result[$section][$key] = $value
    }
    return $result
}

function Get-HWSecurityPolicy {
    <# Exporta a política local (SECURITYPOLICY e USER_RIGHTS) com secedit e guarda no cache da execução. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Context, [switch]$Refresh)
    if (-not $Refresh -and $Context.Cache.ContainsKey('SecurityPolicy')) { return $Context.Cache['SecurityPolicy'] }
    $file = Join-Path $Context.TempDirectory ('hw-secpol-{0}.inf' -f [guid]::NewGuid().ToString('N'))
    # No Windows PowerShell 5.1, stderr de programa nativo com "Stop" vira exceção antes de lermos o código de saída.
    $ErrorActionPreference = 'Continue'
    try {
        $output = & secedit.exe /export /cfg $file /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
            throw "secedit /export falhou (código $LASTEXITCODE): $($output -join ' ')"
        }
        $policy = ConvertFrom-HWIni -Lines (Get-Content -LiteralPath $file -Encoding Unicode)
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
    }
    $Context.Cache['SecurityPolicy'] = $policy
    return $policy
}

function Get-HWSystemAccessValue {
    <# Lê um valor numérico de [System Access]; devolve $null quando o Windows não exporta a chave. #>
    [CmdletBinding()]
    [OutputType([Nullable[int]])]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name)
    $policy = Get-HWSecurityPolicy -Context $Context
    if (-not $policy.ContainsKey('System Access')) { return $null }
    $section = $policy['System Access']
    if (-not $section.ContainsKey($Name)) { return $null }
    return [int]$section[$Name]
}

function Get-HWPrivilegeRight {
    <# Lê um direito de usuário (ex.: SeDenyNetworkLogonRight) e devolve a lista de SIDs/nomes. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Name)
    $policy = Get-HWSecurityPolicy -Context $Context
    if (-not $policy.ContainsKey('Privilege Rights')) { return @() }
    $section = $policy['Privilege Rights']
    if (-not $section.ContainsKey($Name)) { return @() }
    return @($section[$Name] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
}

function Set-HWSecurityValues {
    <#
        Aplica somente as chaves informadas de [System Access] com um modelo .inf
        temporário e um banco temporário do secedit. Depois relê a política e
        confirma que cada valor ficou como pedido.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Values
    )
    foreach ($key in $Values.Keys) {
        if ($key -notin $script:HWSystemAccessKeys) { throw "Chave fora do escopo dos controles 01-06: $key" }
    }
    # Ordem importa para o bloqueio: limite, janela de contagem, duração.
    $order = @('MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'MaximumPasswordAge',
        'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration')
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
    foreach ($key in $order) {
        if ($Values.ContainsKey($key)) { $lines += ('{0} = {1}' -f $key, [int]$Values[$key]) }
    }
    $lines += @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    $description = ($Values.Keys | Sort-Object | ForEach-Object { "$_=$($Values[$_])" }) -join ', '
    if (-not $PSCmdlet.ShouldProcess('Política de segurança local', "secedit /configure ($description)")) { return }

    $ErrorActionPreference = 'Continue'
    $id = [guid]::NewGuid().ToString('N')
    $inf = Join-Path $Context.TempDirectory "hw-apply-$id.inf"
    $db = Join-Path $Context.TempDirectory "hw-apply-$id.sdb"
    $log = Join-Path $Context.TempDirectory "hw-apply-$id.log"
    try {
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode -WhatIf:$false -Confirm:$false
        $output = & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /log $log /quiet 2>&1
        $exit = $LASTEXITCODE
        Write-HWLog -Context $Context -Message "secedit /configure ($description) -> código $exit"
    } finally {
        foreach ($f in @($inf, $db, $log, "$db.jfm")) {
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        }
    }
    $Context.Cache.Remove('SecurityPolicy')
    foreach ($key in $Values.Keys) {
        $now = Get-HWSystemAccessValue -Context $Context -Name $key
        if ($now -ne [int]$Values[$key]) {
            throw "secedit não aplicou $key=$($Values[$key]) (valor atual: $now; código $exit; $($output -join ' '))"
        }
    }
}

# ---------------------------------------------------------------- auditpol

function ConvertFrom-HWAuditCsv {
    <#
        Converte a saída de "auditpol /backup" em hashtable GUID -> valor (0 nenhum, 1 sucesso, 2 falha, 3 ambos).
        Usa a posição das colunas, porque os títulos podem vir traduzidos.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)
    $map = @{}
    $rows = @($Lines | Where-Object { $_.Trim() -ne '' } | ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value' | Select-Object -Skip 1)
    foreach ($row in $rows) {
        if ([string]$row.Guid -notmatch '^\{?[0-9a-fA-F-]{36}\}?$') { continue }
        $guid = ('{' + ([string]$row.Guid).Trim('{', '}').ToUpperInvariant() + '}')
        $value = 0
        if ([int]::TryParse([string]$row.Value, [ref]$value)) { $map[$guid] = $value }
    }
    return $map
}

function Get-HWAuditPolicy {
    <# Devolve o valor numérico de uma subcategoria de auditoria (0-3). Subcategoria ausente = 0. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Guid, [switch]$Refresh)
    if ($Refresh -or -not $Context.Cache.ContainsKey('AuditPolicy')) {
        $file = Join-Path $Context.TempDirectory ('hw-audit-{0}.csv' -f [guid]::NewGuid().ToString('N'))
        $ErrorActionPreference = 'Continue'
        try {
            $output = & auditpol.exe /backup "/file:$file" 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
                throw "auditpol /backup falhou (código $LASTEXITCODE): $($output -join ' ')"
            }
            $Context.Cache['AuditPolicy'] = ConvertFrom-HWAuditCsv -Lines (Get-Content -LiteralPath $file)
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        }
    }
    $key = ('{' + $Guid.Trim('{', '}').ToUpperInvariant() + '}')
    $map = $Context.Cache['AuditPolicy']
    if ($map.ContainsKey($key)) { return [int]$map[$key] }
    return 0
}

function Set-HWAuditPolicy {
    <# Define sucesso/falha de UMA subcategoria pelo GUID (independe do idioma do Windows). #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][ValidatePattern('^\{[0-9A-Fa-f-]{36}\}$')][string]$Guid,
        [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Value
    )
    $success = if ($Value -band 1) { 'enable' } else { 'disable' }
    $failure = if ($Value -band 2) { 'enable' } else { 'disable' }
    if (-not $PSCmdlet.ShouldProcess("Subcategoria $Guid", "auditpol /success:$success /failure:$failure")) { return }
    $ErrorActionPreference = 'Continue'
    $output = & auditpol.exe /set "/subcategory:$Guid" "/success:$success" "/failure:$failure" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set falhou para ${Guid} (código $LASTEXITCODE): $($output -join ' ')" }
    Write-HWLog -Context $Context -Message "auditpol $Guid -> $Value"
    $Context.Cache.Remove('AuditPolicy')
}

# ---------------------------------------------------------------- Registro

function Get-HWRegistryValue {
    <# Devolve o valor ou $null quando a chave/valor não existe. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Set-HWRegistryValue {
    <# Grava um DWORD; com -Value $null remove o valor (usado pelo rollback quando ele não existia). #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )
    if ($null -eq $Value) {
        if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Remover valor')) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        }
        return
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Definir DWORD $Value")) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value ([int]$Value) -PropertyType DWord -Force | Out-Null
    }
}

# ---------------------------------------------------------------- Contas locais

function Get-HWLocalAccountByRid {
    <# Localiza conta local pelo RID (500 Administrador, 501 Convidado), qualquer que seja o nome. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Rid)
    $suffix = "-$Rid"
    return (Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value.EndsWith($suffix) } | Select-Object -First 1)
}

function Get-HWLocalGroupMemberList {
    <#
        Membros de um grupo local identificado por SID (ex.: S-1-5-32-544).
        Get-LocalGroupMember falha com SIDs órfãos; nesse caso usa ADSI.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$GroupSid)
    $group = Get-LocalGroup -SID $GroupSid -ErrorAction Stop
    try {
        return @(Get-LocalGroupMember -SID $GroupSid -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID; ObjectClass = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource }
            })
    } catch {
        $adsi = [ADSI]("WinNT://./{0},group" -f $group.Name)
        return @($adsi.Invoke('Members') | ForEach-Object {
                $type = $_.GetType()
                $name = $type.InvokeMember('Name', 'GetProperty', $null, $_, $null)
                $class = $type.InvokeMember('Class', 'GetProperty', $null, $_, $null)
                $sid = $null
                try {
                    $bytes = $type.InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
                    $sid = (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value
                } catch { $sid = $null }
                [pscustomobject]@{ Name = [string]$name; SID = $sid; ObjectClass = [string]$class; Source = 'ADSI' }
            })
    }
}

Export-ModuleMember -Function @(
    'Get-HWControlCatalog', 'New-HWContext', 'New-HWState', 'New-HWErrorState', 'New-HWChange', 'Write-HWLog',
    'Read-HWJson', 'Save-HWJson', 'Test-HWProperty', 'Assert-HWProfile',
    'Test-HWWindows', 'Test-HWAdministrator', 'Get-HWMachineInfo',
    'ConvertFrom-HWIni', 'Get-HWSecurityPolicy', 'Get-HWSystemAccessValue', 'Get-HWPrivilegeRight', 'Set-HWSecurityValues',
    'ConvertFrom-HWAuditCsv', 'Get-HWAuditPolicy', 'Set-HWAuditPolicy',
    'Get-HWRegistryValue', 'Set-HWRegistryValue',
    'Get-HWLocalAccountByRid', 'Get-HWLocalGroupMemberList'
)
