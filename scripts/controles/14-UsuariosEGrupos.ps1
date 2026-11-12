# Controle 14 · Contas, grupos e direitos (auditar; aplicar só as subcategorias de auditoria)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: grupos e direitos de usuário entram no token de acesso; quem está em
# Administradores recebe privilégios totais após a elevação do UAC.
# O que este controle FAZ: inventaria contas locais, membros de grupos privilegiados e direitos
# sensíveis, e habilita a auditoria de criação/alteração de contas e grupos:
#   Gerenciamento de conta de usuário {0CCE9235-69AE-11D9-BED3-505054503030}  4720, 4722, 4724, 4738, 4740
#   Gerenciamento de grupo de segurança {0CCE9237-69AE-11D9-BED3-505054503030}  4732, 4733
# O que NÃO faz: não remove ninguém de grupo, não desabilita contas, não altera direitos.

$script:HWAudit14 = [ordered]@{
    GerenciamentoDeContaDeUsuario = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    GerenciamentoDeGrupo          = '{0CCE9237-69AE-11D9-BED3-505054503030}'
}
$script:HWPrivilegedGroups = [ordered]@{
    'S-1-5-32-544' = 'Administradores'
    'S-1-5-32-555' = 'Usuários da Área de Trabalho Remota'
    'S-1-5-32-551' = 'Operadores de Backup'
    'S-1-5-32-580' = 'Usuários de Gerenciamento Remoto'
}
$script:HWSensitiveRights = @('SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege',
    'SeLoadDriverPrivilege', 'SeImpersonatePrivilege', 'SeRemoteInteractiveLogonRight')

function Get-HWControl14 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $findings = @()
    $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name                 = $_.Name
                SID                  = $_.SID.Value
                Enabled              = [bool]$_.Enabled
                PasswordRequired     = [bool]$_.PasswordRequired
                PasswordNeverExpires = ($null -eq $_.PasswordExpires)
                LastLogon            = $(if ($_.LastLogon) { $_.LastLogon.ToString('s') } else { $null })
            }
        })
    foreach ($u in $users | Where-Object { $_.Enabled }) {
        if (-not $u.PasswordRequired) { $findings += "Conta habilitada sem senha obrigatória: $($u.Name)." }
        if ($u.PasswordNeverExpires) { $findings += "Conta habilitada com senha que nunca expira: $($u.Name)." }
        if ($null -eq $u.LastLogon) { $findings += "Conta habilitada que nunca fez logon: $($u.Name)." }
    }

    $groups = [ordered]@{}
    foreach ($sid in $script:HWPrivilegedGroups.Keys) {
        try { $groups[$script:HWPrivilegedGroups[$sid]] = @(Get-HWLocalGroupMemberList -GroupSid $sid) }
        catch { $groups[$script:HWPrivilegedGroups[$sid]] = @() }
    }
    $approved = @($Context.Config.Accounts.ApprovedAdministrators | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $admins = @($groups['Administradores'])
    $unexpectedAdmins = @($admins | Where-Object {
            $short = (([string]$_.Name) -split '\\')[-1].ToLowerInvariant()
            $short -notin $approved -and ([string]$_.Name).ToLowerInvariant() -notin $approved -and -not ([string]$_.SID).EndsWith('-500')
        })
    if ($approved.Count -eq 0) {
        $findings += 'Lista de administradores aprovados vazia (Accounts.ApprovedAdministrators, a definir com a ATI-PE).'
    } elseif ($unexpectedAdmins.Count -gt 0) {
        $findings += "Administradores fora da lista aprovada: $(($unexpectedAdmins | ForEach-Object { $_.Name }) -join ', ')."
    }

    $rights = [ordered]@{}
    foreach ($right in $script:HWSensitiveRights) { $rights[$right] = @(Get-HWPrivilegeRight -Context $Context -Name $right) }

    $audit = [ordered]@{}
    foreach ($name in $script:HWAudit14.Keys) {
        $audit[$name] = Get-HWAuditPolicy -Context $Context -Guid $script:HWAudit14[$name]
        if ($audit[$name] -ne 3) { $findings += "Auditoria $name = $($audit[$name]); esperado 3 (sucesso e falha)." }
    }
    $auditOk = @($audit.Values | Where-Object { $_ -ne 3 }).Count -eq 0

    $compliant = if (-not $auditOk) { $false } elseif ($approved.Count -eq 0) { $null } else { $unexpectedAdmins.Count -eq 0 }
    $state = @{
        Id        = '14'
        Observed  = [pscustomobject]@{
            Auditoria        = [pscustomobject]$audit
            Contas           = $users
            GruposPrivilegiados = [pscustomobject]$groups
            DireitosSensiveis = [pscustomobject]$rights
        }
        Expected  = 'Auditoria de contas e grupos = 3; administradores somente da lista aprovada'
        Compliant = $compliant
        Findings  = $findings
        Note      = 'Aplicação limitada às duas subcategorias de auditoria; mudanças em contas e grupos são decisão humana.'
    }
    New-HWState @state
}

function Set-HWControl14 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $actions = @()
    foreach ($name in $script:HWAudit14.Keys) {
        $guid = $script:HWAudit14[$name]
        if ((Get-HWAuditPolicy -Context $Context -Guid $guid) -eq 3) { continue }
        if ($PSCmdlet.ShouldProcess("Auditoria da subcategoria $name", 'Habilitar sucesso e falha')) {
            Set-HWAuditPolicy -Context $Context -Guid $guid -Value 3
            $actions += "$name=3"
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions)
}

function Test-HWControl14 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl14 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl14 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $actions = @()
    if ($null -eq $Saved -or $null -eq $Saved.Auditoria) { return (New-HWChange -Changed $false -Actions 'Backup sem auditoria') }
    foreach ($name in $script:HWAudit14.Keys) {
        if ($null -eq $Saved.Auditoria.$name) { continue }
        $guid = $script:HWAudit14[$name]
        $value = [int]$Saved.Auditoria.$name
        if ((Get-HWAuditPolicy -Context $Context -Guid $guid) -eq $value) { continue }
        if ($PSCmdlet.ShouldProcess("Auditoria da subcategoria $name", "Restaurar valor $value")) {
            Set-HWAuditPolicy -Context $Context -Guid $guid -Value $value
            $actions += "$name=$value"
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions)
}
