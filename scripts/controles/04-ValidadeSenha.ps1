# Controle 04 · Validade máxima da senha (<= 90 dias)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: o SAM registra a data da última troca e força a troca ao vencer.
# Ferramenta: secedit, seção [System Access], chave MaximumPasswordAge (-1 = nunca expira).

function Get-HWControl04 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $observed = Get-HWSystemAccessValue -Context $Context -Name 'MaximumPasswordAge'
    $expected = [int]$Context.Config.Password.MaximumPasswordAge
    $ok = ($null -ne $observed -and $observed -ge 1 -and $observed -le $expected)
    $findings = @()
    if ($observed -eq -1 -or $observed -eq 0) { $findings += 'Senhas nunca expiram.' }
    elseif (-not $ok) { $findings += "Validade atual: $observed dias; esperado: entre 1 e $expected." }
    $state = @{
        Id        = '04'
        Observed  = [pscustomobject]@{ MaximumPasswordAge = $observed }
        Expected  = "1..$expected dias"
        Compliant = $ok
        Findings  = $findings
        Note      = 'Rotação periódica é exigência do checklist; NIST SP 800-63B-4 recomenda trocar só com indício de comprometimento.'
    }
    New-HWState @state
}

function Set-HWControl04 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    # Contas com "senha nunca expira" marcada continuam isentas (ver controle 14).
    $target = [int]$Context.Config.Password.MaximumPasswordAge
    if ($PSCmdlet.ShouldProcess('Política de senha local', "MaximumPasswordAge=$target")) {
        Set-HWSecurityValues -Context $Context -Values @{ MaximumPasswordAge = $target }
        return (New-HWChange -Changed $true -Actions "MaximumPasswordAge=$target")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl04 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl04 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl04 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    if ($null -eq $Saved.MaximumPasswordAge) { return (New-HWChange -Changed $false -Actions 'Valor original ausente no backup') }
    $value = [int]$Saved.MaximumPasswordAge
    if ($PSCmdlet.ShouldProcess('Política de senha local', "Restaurar MaximumPasswordAge=$value")) {
        Set-HWSecurityValues -Context $Context -Values @{ MaximumPasswordAge = $value }
        return (New-HWChange -Changed $true -Actions "MaximumPasswordAge=$value")
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
