# Controle 11 · Auditoria de logon (sucesso e falha) e de bloqueio de conta
# Checklist de Rodrigo Campos e Gabriel Cortez. Detalhes em docs/matriz-controles.md.
# Conceito de SO: o serviço de log de eventos registra as decisões de autenticação da LSA
# conforme a política de auditoria avançada (subcategorias).
# Ferramenta: auditpol, sempre pelo GUID da subcategoria (o nome muda com o idioma do Windows).
#   Logon            {0CCE9215-69AE-11D9-BED3-505054503030}  eventos 4624 (sucesso) e 4625 (falha)
#   Bloqueio de conta {0CCE9217-69AE-11D9-BED3-505054503030}  falhas por conta bloqueada (4625)
#   O evento 4740 (conta bloqueada) vem de "Gerenciamento de conta de usuário" (controle 14).
# Valores: 0 nenhum, 1 sucesso, 2 falha, 3 sucesso e falha.

$script:HWAudit11 = [ordered]@{
    Logon           = @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Required = 3 }
    BloqueioDeConta = @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Required = 2 }
}

function Get-HWControl11 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $observed = [ordered]@{}
    $findings = @()
    foreach ($name in $script:HWAudit11.Keys) {
        $item = $script:HWAudit11[$name]
        $value = Get-HWAuditPolicy -Context $Context -Guid $item.Guid
        $observed[$name] = $value
        if (($value -band $item.Required) -ne $item.Required) {
            $findings += "Subcategoria $name = $value; esperado incluir $($item.Required)."
        }
    }
    # Sem esta opção, uma GPO antiga por categoria pode sobrepor as subcategorias.
    $force = Get-HWRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
    $observed['SCENoApplyLegacyAuditPolicy'] = $force
    if ($force -ne 1) {
        $findings += 'SCENoApplyLegacyAuditPolicy diferente de 1: categorias antigas podem sobrepor as subcategorias (revisar).'
    }
    $ok = (($observed['Logon'] -band 3) -eq 3) -and (($observed['BloqueioDeConta'] -band 2) -eq 2)
    $state = @{
        Id        = '11'
        Observed  = [pscustomobject]$observed
        Expected  = 'Logon = 3 (sucesso e falha); Bloqueio de conta inclui falha'
        Compliant = $ok
        Findings  = $findings
        Note      = 'Eventos 4624/4625 no log Security; 4740 depende do controle 14. Sem coletor central, logs ficam só na máquina.'
    }
    New-HWState @state
}

function Set-HWControl11 {
    <#
        Habilita somente as duas subcategorias do escopo do controle.
        Nenhuma outra subcategoria e nenhuma categoria inteira é alterada.
        O valor atual é combinado (bit a bit) com o exigido, então o que já
        estava habilitado continua habilitado.
        Ordem: primeiro Logon (4624/4625), depois Bloqueio de conta.
        Cada subcategoria passa por ShouldProcess separadamente, então
        -WhatIf mostra as duas decisões e -Confirm pergunta uma a uma.
        O GUID é usado no lugar do nome porque "Logon" vira "Fazer logon"
        no Windows em português.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context)
    $actions = @()
    $before = Get-HWControl11 -Context $Context
    if (($before.Observed.Logon -band 3) -eq 3) {
        $actions += 'Logon já audita sucesso e falha'
    } else {
        # Subcategoria Logon: eventos 4624 e 4625.
        # Escopo aprovado: sucesso e falha.
        $guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        if ($PSCmdlet.ShouldProcess('Auditoria da subcategoria Logon', 'Habilitar sucesso e falha')) {
            Set-HWAuditPolicy -Context $Context -Guid $guid -Value 3
            $actions += 'Logon=3'
        }
    }
    if (($before.Observed.BloqueioDeConta -band 2) -ne 2) {
        $guid = $script:HWAudit11['BloqueioDeConta'].Guid
        $value = [int]$before.Observed.BloqueioDeConta -bor 2
        if ($PSCmdlet.ShouldProcess('Auditoria da subcategoria Bloqueio de conta', "Habilitar falha (valor $value)")) {
            Set-HWAuditPolicy -Context $Context -Guid $guid -Value $value
            $actions += "BloqueioDeConta=$value"
        }
    }
    $changed = @($actions | Where-Object { $_ -match '=' }).Count -gt 0
    return (New-HWChange -Changed $changed -Actions $actions)
}

function Test-HWControl11 {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Context)
    return ((Get-HWControl11 -Context $Context).Compliant -eq $true)
}

function Restore-HWControl11 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Saved)
    $actions = @()
    foreach ($name in $script:HWAudit11.Keys) {
        if ($null -eq $Saved.$name) { continue }
        $guid = $script:HWAudit11[$name].Guid
        $value = [int]$Saved.$name
        if ((Get-HWAuditPolicy -Context $Context -Guid $guid) -eq $value) { continue }
        if ($PSCmdlet.ShouldProcess("Auditoria da subcategoria $name", "Restaurar valor $value")) {
            Set-HWAuditPolicy -Context $Context -Guid $guid -Value $value
            $actions += "$name=$value"
        }
    }
    return (New-HWChange -Changed ($actions.Count -gt 0) -Actions $actions)
}
