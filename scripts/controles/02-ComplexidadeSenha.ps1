# Controle 02 · Complexidade de senha habilitada
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: o filtro de senha da LSA recusa senhas sem 3 de 4 classes de caracteres
# e senhas que contenham o nome da conta.
# Ferramenta: secedit, seção [System Access], chave PasswordComplexity (1 = habilitada).

function Get-HWControl02 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $observed = Get-HWSystemAccessValue -Context $Context -Name 'PasswordComplexity'
    $expected = [int]$Context.Config.Password.PasswordComplexity
    $ok = ($observed -eq $expected)
    $findings = @()
    if (-not $ok) { $findings += "Complexidade atual: $observed; esperado: $expected (habilitada)." }
    $state = @{
        Id        = '02'
        Observed  = [pscustomobject]@{ PasswordComplexity = $observed }
        Expected  = $expected
        Compliant = $ok
        Findings  = $findings
        Note      = 'Recomendações modernas (NIST SP 800-63B-4) priorizam comprimento e listas de senhas vazadas.'
    }
    New-HWState @state
}

function Set-HWControl02 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $target = [int]$Context.Config.Password.PasswordComplexity
    if ($PSCmdlet.ShouldProcess('Política de senha local', "PasswordComplexity=$target")) {
        Set-HWSecurityValues -Context $Context -Values @{ PasswordComplexity = $target }
        return (New-HWChange -Changed $true -Actions "PasswordComplexity=$target")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl02 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl02 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl02 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    if ($null -eq $Saved.PasswordComplexity) { return (New-HWChange -Changed $false -Actions 'Valor original ausente no backup') }
    $value = [int]$Saved.PasswordComplexity
    if ($PSCmdlet.ShouldProcess('Política de senha local', "Restaurar PasswordComplexity=$value")) {
        Set-HWSecurityValues -Context $Context -Values @{ PasswordComplexity = $value }
        return (New-HWChange -Changed $true -Actions "PasswordComplexity=$value")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
