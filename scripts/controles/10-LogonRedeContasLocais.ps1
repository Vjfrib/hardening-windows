# Controle 10 · Logon de rede de contas locais (SOMENTE AUDITORIA)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: direitos de usuário (SeDenyNetworkLogonRight etc.) decidem quem obtém token
# por logon de rede. Negar a contas locais (S-1-5-113) dificulta movimento lateral com a mesma
# senha de administrador local em várias máquinas (pass-the-hash).
# Por que só auditoria: negar logon de rede pode cortar compartilhamentos e administração remota
# usados pela ATI-PE; a decisão e a exceção precisam ser deles.

$script:HWLocalAccountSids = @{
    'S-1-5-113' = 'Conta local'
    'S-1-5-114' = 'Conta local e membro do grupo Administradores'
}

function Get-HWControl10 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $denyNetwork = @(Get-HWPrivilegeRight -Context $Context -Name 'SeDenyNetworkLogonRight')
    $denyRdp = @(Get-HWPrivilegeRight -Context $Context -Name 'SeDenyRemoteInteractiveLogonRight')
    $allowNetwork = @(Get-HWPrivilegeRight -Context $Context -Name 'SeNetworkLogonRight')
    $tokenFilter = Get-HWRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy'

    $findings = @()
    $blocked = @($denyNetwork | Where-Object { $script:HWLocalAccountSids.ContainsKey($_) })
    if ($blocked.Count -eq 0) {
        $findings += 'Contas locais podem fazer logon pela rede (S-1-5-113/114 fora de SeDenyNetworkLogonRight).'
    }
    if ($tokenFilter -eq 1) {
        $findings += 'LocalAccountTokenFilterPolicy=1: administradores locais recebem token completo pela rede.'
    }
    if ($allowNetwork -contains 'S-1-1-0') { $findings += 'SeNetworkLogonRight inclui Todos (S-1-1-0).' }
    $state = @{
        Id        = '10'
        Observed  = [pscustomobject]@{
            SeDenyNetworkLogonRight           = $denyNetwork
            SeDenyRemoteInteractiveLogonRight = $denyRdp
            SeNetworkLogonRight               = $allowNetwork
            LocalAccountTokenFilterPolicy     = $tokenFilter
        }
        Expected  = 'S-1-5-113 ou S-1-5-114 negados na rede; LocalAccountTokenFilterPolicy diferente de 1'
        Compliant = ($blocked.Count -gt 0 -and $tokenFilter -ne 1)
        Findings  = $findings
        Note      = 'Somente auditoria: aplicar exige decisão da ATI-PE sobre compartilhamentos e administração remota.'
    }
    New-HWState @state
}

function Test-HWControl10 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl10 -Context $Context).Compliant -eq $true)
}
