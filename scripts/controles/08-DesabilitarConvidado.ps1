# Controle 08 · Desabilitar a conta Convidado (SID terminado em -501)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: Convidado é uma identidade sem senha conhecida; desabilitada, a LSA recusa
# qualquer logon com ela, local ou pela rede.
# Ferramentas: Get-LocalUser / Disable-LocalUser, sempre pelo SID.

function Get-HWControl08 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $null = $Context
    $account = Get-HWLocalAccountByRid -Rid 501
    if ($null -eq $account) {
        return (New-HWState -Id '08' -Observed $null -Expected 'Desabilitada' -Compliant $true -Findings @() -Note 'Conta -501 não existe nesta máquina.')
    }
    $enabled = [bool]$account.Enabled
    $findings = @()
    if ($enabled) { $findings += "Conta Convidado '$($account.Name)' está habilitada." }
    $state = @{
        Id        = '08'
        Observed  = [pscustomobject]@{ SID = $account.SID.Value; Name = $account.Name; Enabled = $enabled }
        Expected  = 'Desabilitada'
        Compliant = (-not $enabled)
        Findings  = $findings
        Note      = 'Desabilitar não apaga a conta; ela pode ser reabilitada pelo rollback.'
    }
    New-HWState @state
}

function Set-HWControl08 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $current = Get-HWControl08 -Context $Context
    if ($null -eq $current.Observed -or -not $current.Observed.Enabled) {
        return (New-HWChange -Changed $false -Actions 'Convidado já desabilitado ou inexistente')
    }
    if ($PSCmdlet.ShouldProcess($current.Observed.SID, 'Desabilitar a conta Convidado')) {
        Disable-LocalUser -SID $current.Observed.SID -ErrorAction Stop
        return (New-HWChange -Changed $true -Actions "Conta '$($current.Observed.Name)' desabilitada")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl08 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl08 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl08 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $null = $Context
    if ($null -eq $Saved -or $Saved.Enabled -ne $true) {
        return (New-HWChange -Changed $false -Actions 'Convidado estava desabilitado; nada a restaurar')
    }
    if ($PSCmdlet.ShouldProcess([string]$Saved.SID, 'Reabilitar a conta Convidado')) {
        Enable-LocalUser -SID ([string]$Saved.SID) -ErrorAction Stop
        return (New-HWChange -Changed $true -Actions "Conta '$($Saved.Name)' reabilitada")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
