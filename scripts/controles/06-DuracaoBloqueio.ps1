# Controle 06 · Duração do bloqueio de conta (>= 15 minutos)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: a conta bloqueada fica indisponível até o tempo expirar ou um administrador liberar.
# Ferramenta: secedit, chave LockoutDuration (minutos; -1 = até um administrador desbloquear).

function Get-HWControl06 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $duration = Get-HWSystemAccessValue -Context $Context -Name 'LockoutDuration'
    $window = Get-HWSystemAccessValue -Context $Context -Name 'ResetLockoutCount'
    $threshold = Get-HWSystemAccessValue -Context $Context -Name 'LockoutBadCount'
    $min = [int]$Context.Config.Password.LockoutDuration
    $ok = ($null -ne $duration -and ($duration -eq -1 -or $duration -ge $min))
    $findings = @()
    if (-not $ok) { $findings += "Duração atual: $duration min; esperado: >= $min." }
    if ($threshold -eq 0) { $findings += 'Bloqueio desabilitado: a duração só vale com o controle 05 aplicado.' }
    $state = @{
        Id        = '06'
        Observed  = [pscustomobject]@{ LockoutDuration = $duration; ResetLockoutCount = $window }
        Expected  = ">= $min min"
        Compliant = $ok
        Findings  = $findings
        Note      = 'Duração longa reduz força bruta, mas aumenta o impacto de bloqueios propositais.'
    }
    New-HWState @state
}

function Set-HWControl06 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $cfg = $Context.Config.Password
    $values = @{ LockoutDuration = [int]$cfg.LockoutDuration }
    $window = Get-HWSystemAccessValue -Context $Context -Name 'ResetLockoutCount'
    if ($null -ne $window -and $window -gt $values.LockoutDuration) {
        # Mantém a regra do Windows: janela de contagem <= duração.
        $values.ResetLockoutCount = [int]$cfg.ResetLockoutCount
    }
    $text = ($values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" }) -join ', '
    if ($PSCmdlet.ShouldProcess('Política de bloqueio de conta', $text)) {
        Set-HWSecurityValues -Context $Context -Values $values
        return (New-HWChange -Changed $true -Actions $text)
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl06 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl06 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl06 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $values = @{}
    foreach ($key in 'ResetLockoutCount', 'LockoutDuration') {
        if ($null -ne $Saved.$key) { $values[$key] = [int]$Saved.$key }
    }
    if ($values.Count -eq 0) { return (New-HWChange -Changed $false -Actions 'Valores originais ausentes no backup') }
    $text = ($values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" }) -join ', '
    if ($PSCmdlet.ShouldProcess('Política de bloqueio de conta', "Restaurar $text")) {
        Set-HWSecurityValues -Context $Context -Values $values
        return (New-HWChange -Changed $true -Actions $text)
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}
