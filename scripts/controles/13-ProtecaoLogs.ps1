# Controle 13 · Proteção dos logs (SOMENTE AUDITORIA) · checklist Rodrigo Campos e Gabriel Cortez
# Conceito de SO: a ACL limita quem lê, grava ou apaga os arquivos .evtx e os canais de evento.
function Get-HWControl13 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $logsPath = Join-Path $env:SystemRoot 'System32\winevt\Logs'
    $cfg = $Context.Config.Logs
    $acl = Get-Acl -LiteralPath $logsPath -ErrorAction Stop
    $channels = @(Get-WinEvent -ListLog @('Security','System') -ErrorAction Stop |
        Select-Object LogName, IsEnabled, MaximumSizeInBytes, LogMode, SecurityDescriptor)

    $findings = @()
    # Quem não é administrador/sistema não deveria poder gravar ou apagar na pasta dos logs.
    $weakSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-7')   # Todos, Usuários autenticados, Usuários, Anônimo
    $writeRights = [Security.AccessControl.FileSystemRights]'Write, Delete, ChangePermissions, TakeOwnership'
    $aclEntries = @()
    foreach ($rule in $acl.Access) {
        $sid = $null
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$rule.IdentityReference }
        $aclEntries += [pscustomobject]@{ Identidade = [string]$rule.IdentityReference; SID = $sid; Direitos = [string]$rule.FileSystemRights; Tipo = [string]$rule.AccessControlType }
        if ($rule.AccessControlType -eq 'Allow' -and $sid -in $weakSids -and ($rule.FileSystemRights -band $writeRights)) {
            $findings += "ACL de $logsPath permite escrita/remoção a $($rule.IdentityReference)."
        }
    }

    $minimum = @{ Security = [long]$cfg.SecurityMinimumSizeKB * 1KB; System = [long]$cfg.SystemMinimumSizeKB * 1KB }
    foreach ($channel in $channels) {
        if (-not $channel.IsEnabled) { $findings += "Canal $($channel.LogName) desabilitado." }
        if ($channel.MaximumSizeInBytes -lt $minimum[$channel.LogName]) {
            $findings += "Canal $($channel.LogName) com $([math]::Round($channel.MaximumSizeInBytes / 1KB)) KB; mínimo do perfil: $($minimum[$channel.LogName] / 1KB) KB."
        }
    }

    # Limpeza de rastros: 1102 (Security limpo) e 104 (outro log limpo) no período configurado.
    $since = (Get-Date).AddDays(-[int]$cfg.ClearEventLookbackDays)
    $clears = @()
    foreach ($query in @(@{ LogName = 'Security'; Id = 1102 }, @{ LogName = 'System'; Id = 104 })) {
        try {
            $clears += @(Get-WinEvent -FilterHashtable @{ LogName = $query.LogName; Id = $query.Id; StartTime = $since } -MaxEvents 20 -ErrorAction Stop |
                ForEach-Object { [pscustomobject]@{ Log = $query.LogName; Id = $_.Id; Quando = $_.TimeCreated.ToString('s') } })
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $findings += "Não foi possível consultar $($query.LogName)/$($query.Id): $($_.Exception.Message)" }
        }
    }
    if ($clears.Count -gt 0) { $findings += "Logs limpos $($clears.Count) vez(es) nos últimos $($cfg.ClearEventLookbackDays) dias (eventos 1102/104)." }

    $structuralOk = @($findings | Where-Object { $_ -match '^(ACL|Canal)' }).Count -eq 0
    $state = @{
        Id        = '13'
        Observed  = [pscustomobject]@{
            Pasta    = $logsPath
            Acl      = $aclEntries
            Canais   = @($channels | ForEach-Object { [pscustomobject]@{ Nome = $_.LogName; Habilitado = $_.IsEnabled; TamanhoMaximoKB = [math]::Round($_.MaximumSizeInBytes / 1KB); Modo = [string]$_.LogMode; SDDL = $_.SecurityDescriptor } })
            Limpezas = $clears
        }
        Expected  = 'Sem escrita para não administradores; canais habilitados e com tamanho mínimo; nenhuma limpeza sem registro'
        Compliant = $(if (-not $structuralOk) { $false } elseif ($clears.Count -gt 0) { $null } else { $true })
        Findings  = $findings
        Note      = 'Somente auditoria: trocar ACL ou tamanho de logs afeta serviços; o coletor central (ATI-PE) é a proteção definitiva.'
    }
    New-HWState @state
}

function Test-HWControl13 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl13 -Context $Context).Compliant -eq $true)
}
