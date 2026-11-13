# Controle 15 · Aplicações e recursos opcionais do Windows
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: cada recurso habilitado traz binários, serviços e portas que ampliam a superfície.
# O que FAZ: inventaria aplicações instaladas (registro) e recursos opcionais candidatos
# (ex.: SMB1Protocol, TelnetClient, TFTP, PowerShell 2.0). Desabilita APENAS os recursos que
# estão presentes, habilitados E listados em Features.ApprovedToDisable no perfil.
# O que NÃO faz: não desinstala aplicações e não mexe em recurso fora da lista aprovada.

$script:HWUninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

function Get-HWInstalledApplication {
    [CmdletBinding()]
    param()
    @(Get-ItemProperty -Path $script:HWUninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) } |
        ForEach-Object {
            [pscustomobject]@{
                Nome    = [string]$_.DisplayName
                Versao  = $(if ($_.PSObject.Properties['DisplayVersion']) { [string]$_.DisplayVersion } else { '' })
                Editor  = $(if ($_.PSObject.Properties['Publisher']) { [string]$_.Publisher } else { '' })
            }
        } | Sort-Object Nome -Unique)
}

function Get-HWControl15 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $cfg = $Context.Config.Features
    $features = @()
    foreach ($name in @($cfg.Candidates)) {
        $feature = $null   # recurso desconhecido nesta edição/versão do Windows fica como "Ausente"
        try { $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop }
        catch { if ($_.Exception.Message -match 'elevat|eleva') { throw } }
        $state = if ($feature) { [string]$feature.State } else { 'Ausente' }
        $features += [pscustomobject]@{ Nome = [string]$name; Estado = $state }
    }
    $enabled = @($features | Where-Object { $_.Estado -eq 'Enabled' })
    $approved = @($cfg.ApprovedToDisable)
    $findings = @()
    foreach ($f in $enabled) {
        $suffix = if ($f.Nome -in $approved) { 'aprovado para desabilitar' } else { 'NÃO aprovado: decisão da ATI-PE' }
        $findings += "Recurso habilitado: $($f.Nome) ($suffix)."
    }
    $apps = @(Get-HWInstalledApplication)
    $state = @{
        Id        = '15'
        Observed  = [pscustomobject]@{ Recursos = $features; Aplicacoes = $apps; TotalAplicacoes = $apps.Count }
        Expected  = 'Nenhum recurso candidato habilitado; aplicações revisadas contra a lista da ATI-PE'
        Compliant = ($enabled.Count -eq 0)
        Findings  = $findings
        Note      = 'Lista de aplicações é inventário para revisão; desinstalar não é automatizado.'
    }
    New-HWState @state
}

function Set-HWControl15 {
    <#
        Desabilita somente recursos presentes, habilitados e aprovados.
        Usa -NoRestart: quem opera a VM reinicia; o relatório marca quando é necessário.
        Recursos comuns e o motivo:
          SMB1Protocol                      protocolo explorado pelo WannaCry (EternalBlue)
          TelnetClient / TFTP               protocolos sem criptografia
          MicrosoftWindowsPowerShellV2Root  PowerShell 2.0 permite contornar o registro de scripts
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $current = Get-HWControl15 -Context $Context
    $approved = @($Context.Config.Features.ApprovedToDisable)
    $targets = @($current.Observed.Recursos | Where-Object { $_.Estado -eq 'Enabled' -and $_.Nome -in $approved })
    $skipped = @($current.Observed.Recursos | Where-Object { $_.Estado -eq 'Enabled' -and $_.Nome -notin $approved })
    $actions = @()
    $changed = $false
    $restart = $false
    foreach ($s in $skipped) { $actions += "$($s.Nome): mantido (não aprovado)" }
    foreach ($target in $targets) {
        $name = $target.Nome
        if ($PSCmdlet.ShouldProcess("Recurso opcional $name", 'Desabilitar (sem reiniciar)')) {
            $result = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop
            $changed = $true
            if ($result.RestartNeeded) { $restart = $true }
            $actions += "${name}: desabilitado"
        }
    }
    if ($targets.Count -eq 0 -and $skipped.Count -eq 0) { $actions += 'Nenhum recurso candidato habilitado' }
    return (New-HWChange -Changed $changed -Actions $actions -RestartNeeded $restart)
}

function Test-HWControl15 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl15 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl15 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $null = $Context
    $actions = @()
    $restart = $false
    foreach ($item in @($Saved.Recursos | Where-Object { $_.Estado -eq 'Enabled' })) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $item.Nome -ErrorAction SilentlyContinue
        if ($null -eq $feature -or [string]$feature.State -eq 'Enabled') { continue }
        if ($PSCmdlet.ShouldProcess("Recurso opcional $($item.Nome)", 'Reabilitar (sem reiniciar)')) {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $item.Nome -NoRestart -ErrorAction Stop
            if ($result.RestartNeeded) { $restart = $true }
            $actions += "$($item.Nome): reabilitado"
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions -RestartNeeded $restart)
}
