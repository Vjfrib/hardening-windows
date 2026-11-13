# Controle 09 · UAC habilitado, com consentimento na área de trabalho segura
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: com UAC, o administrador recebe dois tokens (filtrado e completo); o completo
# só é usado após consentimento. A área de trabalho segura isola o prompt de outros processos.
# Ferramenta: registro HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.
#   EnableLUA = 1                  UAC ligado (mudança exige reinício)
#   ConsentPromptBehaviorAdmin = 2 pedir consentimento na área de trabalho segura
#   PromptOnSecureDesktop = 1      prompt na área de trabalho segura

$script:HWUacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

function Get-HWControl09 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $expected = [ordered]@{}
    foreach ($property in $Context.Config.Uac.PSObject.Properties) { $expected[$property.Name] = [int]$property.Value }
    $observed = [ordered]@{}
    $findings = @()
    foreach ($name in $expected.Keys) {
        $value = Get-HWRegistryValue -Path $script:HWUacPath -Name $name
        $observed[$name] = $value
        if ($null -eq $value -or [int]$value -ne $expected[$name]) {
            $findings += "$name = $(if ($null -eq $value) { 'ausente' } else { $value }); esperado: $($expected[$name])."
        }
    }
    $state = @{
        Id        = '09'
        Observed  = [pscustomobject]$observed
        Expected  = [pscustomobject]$expected
        Compliant = ($findings.Count -eq 0)
        Findings  = $findings
        Note      = 'EnableLUA só passa a valer após reiniciar.'
    }
    New-HWState @state
}

function Set-HWControl09 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $current = Get-HWControl09 -Context $Context
    $actions = @()
    $restart = $false
    foreach ($property in $current.Expected.PSObject.Properties) {
        $now = $current.Observed.($property.Name)
        if ($null -ne $now -and [int]$now -eq [int]$property.Value) { continue }
        if ($PSCmdlet.ShouldProcess("UAC: $($property.Name)", "Definir $($property.Value)")) {
            Set-HWRegistryValue -Path $script:HWUacPath -Name $property.Name -Value ([int]$property.Value) -Confirm:$false
            $actions += "$($property.Name)=$($property.Value)"
            if ($property.Name -eq 'EnableLUA') { $restart = $true }
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions -RestartNeeded $restart)
}

function Test-HWControl09 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl09 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl09 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $null = $Context
    $actions = @()
    $restart = $false
    foreach ($property in $Saved.PSObject.Properties) {
        $now = Get-HWRegistryValue -Path $script:HWUacPath -Name $property.Name
        if ("$now" -eq "$($property.Value)") { continue }
        $label = if ($null -eq $property.Value) { 'remover (não existia)' } else { "restaurar $($property.Value)" }
        if ($PSCmdlet.ShouldProcess("UAC: $($property.Name)", $label)) {
            Set-HWRegistryValue -Path $script:HWUacPath -Name $property.Name -Value $property.Value -Confirm:$false
            $actions += "$($property.Name): $label"
            if ($property.Name -eq 'EnableLUA') { $restart = $true }
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions -RestartNeeded $restart)
}
