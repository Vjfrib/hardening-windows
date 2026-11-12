# Controle 01 · Comprimento mínimo da senha (>= 12 caracteres)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: a base de políticas (SAM/LSA) persiste as regras de autenticação.
# Ferramenta: secedit, seção [System Access], chave MinimumPasswordLength.

function Get-HWControl01 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $observed = Get-HWSystemAccessValue -Context $Context -Name 'MinimumPasswordLength'
    $expected = [int]$Context.Config.Password.MinimumPasswordLength
    $ok = ($null -ne $observed -and $observed -ge $expected)
    $findings = @()
    if (-not $ok) { $findings += "Senha mínima atual: $observed caracteres; esperado: >= $expected." }
    $state = @{
        Id        = '01'
        Observed  = [pscustomobject]@{ MinimumPasswordLength = $observed }
        Expected  = ">= $expected"
        Compliant = $ok
        Findings  = $findings
        Note      = 'Em domínio, a GPO prevalece sobre a política local.'
    }
    New-HWState @state
}

function Set-HWControl01 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    # Altera somente MinimumPasswordLength; as demais chaves da política ficam como estão.
    # O valor vem do perfil (scripts/config), já validado por Assert-HWProfile.
    # Contas existentes só são afetadas na próxima troca de senha.
    $target = [int]$Context.Config.Password.MinimumPasswordLength
    if ($PSCmdlet.ShouldProcess('Política de senha local', "MinimumPasswordLength=$target")) {
        Set-HWSecurityValues -Context $Context -Values @{ MinimumPasswordLength = $target }
        return (New-HWChange -Changed $true -Actions "MinimumPasswordLength=$target")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl01 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl01 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl01 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    if ($null -eq $Saved.MinimumPasswordLength) { return (New-HWChange -Changed $false -Actions 'Valor original ausente no backup') }
    $value = [int]$Saved.MinimumPasswordLength
    if ($PSCmdlet.ShouldProcess('Política de senha local', "Restaurar MinimumPasswordLength=$value")) {
        Set-HWSecurityValues -Context $Context -Values @{ MinimumPasswordLength = $value }
        return (New-HWChange -Changed $true -Actions "MinimumPasswordLength=$value")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
