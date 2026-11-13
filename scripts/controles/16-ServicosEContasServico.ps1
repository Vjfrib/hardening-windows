# Controle 16 · Serviços e contas de serviço (SOMENTE AUDITORIA)
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: cada serviço é um processo iniciado pelo SCM com a conta indicada em
# StartName; o token dessa conta define o que o serviço pode fazer. Dependências fazem um
# serviço parar outros.
# O que FAZ: lista serviços com contas fora das contas internas do Windows, caminhos de
# executável sem aspas e com espaço (escalada de privilégio clássica) e serviços da lista de
# revisão do perfil que estão em execução ou automáticos, com seus dependentes.
# Por que só auditoria: parar ou trocar a conta de um serviço pode derrubar aplicações; a
# lista de contas de serviço aprovadas é da ATI-PE.

$script:HWBuiltinServiceAccounts = @('LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService',
    'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\SYSTEM')

function Test-HWUnquotedServicePath {
    <# Verdadeiro quando o caminho do executável tem espaço e não está entre aspas. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $false }
    $text = $PathName.Trim()
    if ($text.StartsWith('"')) { return $false }
    if ($text -notmatch '^(?<exe>.+?\.exe)(\s|$)') { return $false }
    return ($Matches['exe'] -match '\s')
}

function Get-HWControl16 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $review = @($Context.Config.Services.ReviewIfRunning)
    $findings = @()

    $customAccounts = @($services | Where-Object {
            $account = [string]$_.StartName
            $account -and $account -notin $script:HWBuiltinServiceAccounts -and $account -notlike 'NT SERVICE\*'
        } | ForEach-Object { [pscustomobject]@{ Servico = $_.Name; Conta = $_.StartName; Inicio = $_.StartMode; Estado = $_.State } })
    foreach ($c in $customAccounts) { $findings += "Serviço $($c.Servico) roda como $($c.Conta): confirmar dono, senha e privilégios." }

    $unquoted = @($services | Where-Object { Test-HWUnquotedServicePath -PathName $_.PathName } |
        ForEach-Object { [pscustomobject]@{ Servico = $_.Name; Caminho = $_.PathName; Conta = $_.StartName } })
    foreach ($u in $unquoted) { $findings += "Caminho sem aspas no serviço $($u.Servico): $($u.Caminho)" }

    $flagged = @($services | Where-Object { $_.Name -in $review -and ($_.State -eq 'Running' -or $_.StartMode -eq 'Auto') } | ForEach-Object {
            $dependents = @()
            try { $dependents = @((Get-Service -Name $_.Name -ErrorAction Stop).DependentServices | ForEach-Object { $_.Name }) } catch { $dependents = @() }
            [pscustomobject]@{ Servico = $_.Name; Nome = $_.DisplayName; Inicio = $_.StartMode; Estado = $_.State; Conta = $_.StartName; Dependentes = $dependents }
        })
    foreach ($f in $flagged) { $findings += "Serviço da lista de revisão ativo: $($f.Servico) ($($f.Inicio)/$($f.Estado)); dependentes: $(@($f.Dependentes).Count)." }

    $compliant = if ($unquoted.Count -gt 0 -or $flagged.Count -gt 0) { $false } elseif ($customAccounts.Count -gt 0) { $null } else { $true }
    $state = @{
        Id        = '16'
        Observed  = [pscustomobject]@{
            TotalServicos       = $services.Count
            EmExecucao          = @($services | Where-Object { $_.State -eq 'Running' }).Count
            ContasNaoInternas   = $customAccounts
            CaminhosSemAspas    = $unquoted
            ListaDeRevisaoAtiva = $flagged
        }
        Expected  = 'Sem caminhos sem aspas; serviços da lista de revisão parados; contas de serviço aprovadas'
        Compliant = $compliant
        Findings  = $findings
        Note      = 'Somente auditoria: desabilitar serviços ou trocar contas exige a lista aprovada da ATI-PE.'
    }
    New-HWState @state
}

function Test-HWControl16 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl16 -Context $Context).Compliant -eq $true)
}
