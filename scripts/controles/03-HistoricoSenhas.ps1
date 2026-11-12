# Controle 03 · Histórico de senhas (>= 5 senhas lembradas)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: o SAM guarda hashes das últimas senhas para impedir reutilização.
# Ferramenta: secedit, seção [System Access], chave PasswordHistorySize.

function Get-HWControl03 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $observed = Get-HWSystemAccessValue -Context $Context -Name 'PasswordHistorySize'
    $expected = [int]$Context.Config.Password.PasswordHistorySize
    $ok = ($null -ne $observed -and $observed -ge $expected)
    $findings = @()
    if (-not $ok) { $findings += "Histórico atual: $observed senhas; esperado: >= $expected." }
    $state = @{
        Id        = '03'
        Observed  = [pscustomobject]@{ PasswordHistorySize = $observed }
        Expected  = ">= $expected"
        Compliant = $ok
        Findings  = $findings
        Note      = 'Sem idade mínima de senha, o usuário pode trocar várias vezes seguidas e voltar à antiga.'
    }
    New-HWState @state
}

function Set-HWControl03 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $target = [int]$Context.Config.Password.PasswordHistorySize
    if ($PSCmdlet.ShouldProcess('Política de senha local', "PasswordHistorySize=$target")) {
        Set-HWSecurityValues -Context $Context -Values @{ PasswordHistorySize = $target }
        return (New-HWChange -Changed $true -Actions "PasswordHistorySize=$target")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl03 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl03 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl03 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    if ($null -eq $Saved.PasswordHistorySize) { return (New-HWChange -Changed $false -Actions 'Valor original ausente no backup') }
    $value = [int]$Saved.PasswordHistorySize
    if ($PSCmdlet.ShouldProcess('Política de senha local', "Restaurar PasswordHistorySize=$value")) {
        Set-HWSecurityValues -Context $Context -Values @{ PasswordHistorySize = $value }
        return (New-HWChange -Changed $true -Actions "PasswordHistorySize=$value")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
