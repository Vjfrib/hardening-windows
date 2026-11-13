# Controle 07 · Renomear a conta interna Administrador (SID terminado em -500)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: o SID identifica a conta; o nome é só um rótulo. Renomear tira o alvo
# óbvio de ataques por nome, mas o SID -500 continua o mesmo (medida complementar).
# Ferramentas: Get-LocalUser / Rename-LocalUser (módulo LocalAccounts do Windows PowerShell 5.1).

# Nomes padrão em vários idiomas do Windows; qualquer um deles é considerado "óbvio".
$script:HWDefaultAdminNames = @('Administrator', 'Administrador', 'Administrateur', 'Administratör', 'Admin', 'Administrador local')

function Test-HWAdminNameAcceptable {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($script:HWDefaultAdminNames -notcontains $Name.Trim())
}

function Get-HWControl07 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $account = Get-HWLocalAccountByRid -Rid 500
    $desired = [string]$Context.Config.Accounts.AdministratorNewName
    if ($null -eq $account) {
        return (New-HWState -Id '07' -Observed $null -Expected 'Conta -500 com nome não óbvio' -Compliant $null -Findings @('Conta com SID -500 não encontrada.'))
    }
    $observed = [pscustomobject]@{
        SID       = $account.SID.Value
        Name      = $account.Name
        Enabled   = [bool]$account.Enabled
        LastLogon = $(if ($account.LastLogon) { $account.LastLogon.ToString('s') } else { $null })
    }
    $ok = Test-HWAdminNameAcceptable -Name $account.Name
    $findings = @()
    if (-not $ok) { $findings += "Conta -500 ainda se chama '$($account.Name)'." }
    if (-not (Test-HWAdminNameAcceptable -Name $desired)) {
        $findings += 'Novo nome ainda não definido no perfil (Accounts.AdministratorNewName, a combinar com a ATI-PE).'
    }
    $state = @{
        Id        = '07'
        Observed  = $observed
        Expected  = $(if (Test-HWAdminNameAcceptable -Name $desired) { $desired } else { 'Nome não óbvio (a definir)' })
        Compliant = $ok
        Findings  = $findings
        Note      = 'O SID -500 não muda: ferramentas que enumeram SIDs ainda encontram a conta.'
    }
    New-HWState @state
}

function Set-HWControl07 {
    <#
        Renomeia a conta -500 para Accounts.AdministratorNewName.
        Trava: nome definido, não óbvio e não usado por outra conta local.
        A senha, os grupos e o perfil da conta são preservados; scripts e
        tarefas que usam o nome antigo precisam ser revisados.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $current = Get-HWControl07 -Context $Context
    if ($null -eq $current.Observed) { throw 'Conta com SID -500 não encontrada.' }
    $desired = ([string]$Context.Config.Accounts.AdministratorNewName).Trim()
    if (-not (Test-HWAdminNameAcceptable -Name $desired)) {
        throw 'Defina Accounts.AdministratorNewName no perfil com um nome não óbvio aprovado.'
    }
    if ($desired -eq $current.Observed.Name) {
        return (New-HWChange -Changed $false -Actions "Conta -500 já se chama '$desired'")
    }
    if ($desired.Length -gt 20 -or $desired -match '["/\\\[\]:;|=,+*?<>@]') {
        throw "Nome '$desired' inválido para conta local (até 20 caracteres, sem caracteres especiais)."
    }
    $conflict = Get-LocalUser -Name $desired -ErrorAction SilentlyContinue
    if ($conflict) { throw "Já existe outra conta local chamada '$desired'." }
    $group = Get-LocalGroup -Name $desired -ErrorAction SilentlyContinue
    if ($group) { throw "Já existe um grupo local chamado '$desired'." }

    # Por padrão a conta -500 não é bloqueada pelo controle 05, por isso ela costuma ser a
    # conta de recuperação. Registre o novo nome no inventário da ATI-PE antes da mudança,
    # para que a equipe de suporte não fique sem saber com qual nome entrar.
    # Renomeia pelo SID, nunca pelo nome, para não atingir outra conta por engano.
    if ($PSCmdlet.ShouldProcess($current.Observed.SID, 'Renomear a conta interna Administrador')) {
        Rename-LocalUser -SID $current.Observed.SID -NewName $desired -ErrorAction Stop
        return (New-HWChange -Changed $true -Actions "Renomeada de '$($current.Observed.Name)' para '$desired'")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl07 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl07 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl07 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $null = $Context
    if ($null -eq $Saved -or [string]::IsNullOrWhiteSpace([string]$Saved.Name)) {
        return (New-HWChange -Changed $false -Actions 'Nome original ausente no backup')
    }
    $account = Get-HWLocalAccountByRid -Rid 500
    if ($null -eq $account) { throw 'Conta com SID -500 não encontrada.' }
    if ($account.SID.Value -ne [string]$Saved.SID) { throw 'SID da conta -500 difere do backup.' }
    if ($account.Name -eq $Saved.Name) { return (New-HWChange -Changed $false -Actions 'Nome já é o original') }
    if ($PSCmdlet.ShouldProcess($account.SID.Value, "Restaurar o nome '$($Saved.Name)'")) {
        Rename-LocalUser -SID $account.SID.Value -NewName ([string]$Saved.Name) -ErrorAction Stop
        return (New-HWChange -Changed $true -Actions "Renomeada de volta para '$($Saved.Name)'")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
