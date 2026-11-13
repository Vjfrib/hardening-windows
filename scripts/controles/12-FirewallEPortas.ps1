# Controle 12 · Firewall e portas (SOMENTE AUDITORIA) · checklist Rodrigo Campos e Gabriel Cortez
# Conceito de SO: o firewall filtra a pilha de rede; a porta identifica o serviço em escuta.
function Get-HWControl12 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object LocalAddress, LocalPort, OwningProcess)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } |
        Select-Object LocalAddress, LocalPort, OwningProcess)
    $processes = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) { $processes[[int]$p.Id] = $p.ProcessName }

    $listening = @($tcp | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
            [pscustomobject]@{ Protocolo = 'TCP'; Endereco = [string]$_.LocalAddress; Porta = [int]$_.LocalPort; Processo = $processes[[int]$_.OwningProcess] }
        } | Sort-Object Porta, Endereco -Unique)
    $udpList = @($udp | ForEach-Object {
            [pscustomobject]@{ Protocolo = 'UDP'; Endereco = [string]$_.LocalAddress; Porta = [int]$_.LocalPort; Processo = $processes[[int]$_.OwningProcess] }
        } | Sort-Object Porta, Endereco -Unique)

    # Regras de entrada habilitadas que liberam administração remota conhecida.
    $remoteAdminPorts = @{ 22 = 'SSH'; 135 = 'RPC'; 445 = 'SMB'; 3389 = 'RDP'; 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS' }
    $inboundAllow = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -PolicyStore ActiveStore -ErrorAction SilentlyContinue)

    $findings = @()
    foreach ($p in $profiles) {
        if ([string]$p.Enabled -ne 'True') { $findings += "Perfil $($p.Name) do firewall desligado." }
        if ([string]$p.DefaultInboundAction -eq 'Allow') { $findings += "Perfil $($p.Name) permite entrada por padrão." }
    }
    $allowed = @($Context.Config.Firewall.AllowedListeningPorts | ForEach-Object { [int]$_ })
    $unexpected = @($listening | Where-Object { $_.Porta -notin $allowed })
    foreach ($item in $listening | Where-Object { $remoteAdminPorts.ContainsKey($_.Porta) }) {
        $findings += "Porta de administração remota em escuta: $($item.Porta) ($($remoteAdminPorts[$item.Porta]), $($item.Processo))."
    }
    if ($allowed.Count -eq 0) {
        $findings += 'Lista de portas aprovadas vazia no perfil (Firewall.AllowedListeningPorts, a definir com a ATI-PE).'
    } elseif ($unexpected.Count -gt 0) {
        $findings += "Portas TCP fora da lista aprovada: $((@($unexpected | ForEach-Object { $_.Porta }) | Sort-Object -Unique) -join ', ')."
    }

    $profilesOk = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -eq 'Allow' }).Count -eq 0
    $compliant = if (-not $profilesOk) { $false } elseif ($allowed.Count -eq 0) { $null } else { $unexpected.Count -eq 0 }
    $state = @{
        Id        = '12'
        Observed  = [pscustomobject]@{
            Perfis               = @($profiles | ForEach-Object { [pscustomobject]@{ Nome = [string]$_.Name; Ligado = [string]$_.Enabled; EntradaPadrao = [string]$_.DefaultInboundAction; SaidaPadrao = [string]$_.DefaultOutboundAction } })
            PortasTcpEmEscuta    = $listening
            PortasUdp            = $udpList
            RegrasEntradaPermitir = $inboundAllow.Count
        }
        Expected  = 'Domain/Private/Public ligados, entrada padrão bloqueada, só portas aprovadas em escuta'
        Compliant = $compliant
        Findings  = $findings
        Note      = 'Somente auditoria: restringir portas sem a lista da ATI-PE pode derrubar serviços e o acesso remoto.'
    }
    New-HWState @state
}

function Test-HWControl12 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl12 -Context $Context).Compliant -eq $true)
}
