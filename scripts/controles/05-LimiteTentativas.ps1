# Controle 05 · Bloqueio de conta após 5 tentativas inválidas
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: a LSA conta falhas de autenticação por conta e bloqueia ao atingir o limite.
# Ferramenta: secedit, chaves LockoutBadCount (limite) e ResetLockoutCount (janela, minutos).
# Regra do Windows: ResetLockoutCount <= LockoutDuration. Se a duração atual for menor que a
# janela pedida, a duração também é ajustada na mesma operação (valor do perfil, controle 06).

function Get-HWControl05 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $threshold = Get-HWSystemAccessValue -Context $Context -Name 'LockoutBadCount'
    $window = Get-HWSystemAccessValue -Context $Context -Name 'ResetLockoutCount'
    $duration = Get-HWSystemAccessValue -Context $Context -Name 'LockoutDuration'
    $max = [int]$Context.Config.Password.LockoutBadCount
    $ok = ($null -ne $threshold -and $threshold -ge 1 -and $threshold -le $max)
    $findings = @()
    if ($threshold -eq 0) { $findings += 'Bloqueio de conta desabilitado (tentativas ilimitadas).' }
    elseif (-not $ok) { $findings += "Limite atual: $threshold tentativas; esperado: entre 1 e $max." }
    $state = @{
        Id        = '05'
        Observed  = [pscustomobject]@{ LockoutBadCount = $threshold; ResetLockoutCount = $window; LockoutDuration = $duration }
        Expected  = "1..$max tentativas"
        Compliant = $ok
        Findings  = $findings
        Note      = 'Limite baixo ajuda contra força bruta, mas permite negação de serviço por bloqueio proposital.'
    }
    New-HWState @state
}

function Set-HWControl05 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $cfg = $Context.Config.Password
    $values = @{
        LockoutBadCount   = [int]$cfg.LockoutBadCount
        ResetLockoutCount = [int]$cfg.ResetLockoutCount
    }
    $duration = Get-HWSystemAccessValue -Context $Context -Name 'LockoutDuration'
    if ($null -eq $duration -or ($duration -ne -1 -and $duration -lt $values.ResetLockoutCount)) {
        $values.LockoutDuration = [Math]::Max([int]$cfg.LockoutDuration, $values.ResetLockoutCount)
    }
    $text = ($values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" }) -join ', '
    if ($PSCmdlet.ShouldProcess('Política de bloqueio de conta', $text)) {
        Set-HWSecurityValues -Context $Context -Values $values
        return (New-HWChange -Changed $true -Actions $text)
    }
    return (New-HWChange -Changed $false -Actions 'Simulado ou não confirmado')
}

function Test-HWControl05 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl05 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl05 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $values = @{}
    foreach ($key in 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration') {
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
