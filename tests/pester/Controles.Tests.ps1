#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Contratos dos 16 controles com dublês (mocks): nenhuma chamada real ao Windows.
    - Get devolve estado com Id, Status, Observed, Expected e Findings.
    - Set altera somente o escopo do controle e respeita -WhatIf.
    - Controles somente auditoria não têm Set nem Restore.
    Em Linux, os cmdlets exclusivos do Windows são criados como funções vazias para poderem ser simulados.
#>

BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/lib/Common.psm1') -Force -DisableNameChecking
}

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($m in 'Common', 'Safety', 'Backup', 'Reporting') {
        Import-Module (Join-Path $script:Root "scripts/lib/$m.psm1") -Force -DisableNameChecking
    }
    $stubs = @{
        'Get-LocalUser'                  = 'param([string]$Name, [object]$SID)'
        'Rename-LocalUser'               = 'param([object]$SID, [string]$NewName, [string]$Name)'
        'Disable-LocalUser'              = 'param([object]$SID, [string]$Name)'
        'Enable-LocalUser'               = 'param([object]$SID, [string]$Name)'
        'Get-LocalGroup'                 = 'param([string]$Name, [object]$SID)'
        'Get-WindowsOptionalFeature'     = 'param([switch]$Online, [string]$FeatureName)'
        'Disable-WindowsOptionalFeature' = 'param([switch]$Online, [string]$FeatureName, [switch]$NoRestart)'
        'Enable-WindowsOptionalFeature'  = 'param([switch]$Online, [string]$FeatureName, [switch]$NoRestart)'
        'Get-NetFirewallProfile'         = 'param([string]$PolicyStore)'
        'Get-NetFirewallRule'            = 'param([string]$Direction, [string]$Action, [string]$Enabled, [string]$PolicyStore)'
        'Get-NetTCPConnection'           = 'param([string]$State)'
        'Get-NetUDPEndpoint'             = 'param()'
        'Get-WinEvent'                   = 'param([string[]]$ListLog, [hashtable]$FilterHashtable, [int]$MaxEvents)'
        'Get-Acl'                        = 'param([string]$LiteralPath)'
        'Get-CimInstance'                = 'param([string]$ClassName)'
        'Get-Service'                    = 'param([string]$Name)'
    }
    foreach ($name in $stubs.Keys) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            $body = "[CmdletBinding()] $($stubs[$name]) throw 'stub de teste: $name não deveria ser chamado sem mock'"
            Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create($body))
        }
    }
    Get-ChildItem -LiteralPath (Join-Path $script:Root 'scripts/controles') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

    function Get-TestContext {
        $config = Read-HWJson -Path (Join-Path $script:Root 'scripts/config/perfil-academico.example.json')
        $ctx = New-HWContext -Config $config -Mode Apply -RunDirectory $TestDrive
        $ctx.Cache['SecurityPolicy'] = ConvertFrom-HWIni -Lines (Get-Content -LiteralPath (Join-Path $script:Root 'tests/fixtures/secedit-export.inf') -Encoding Unicode)
        $ctx.Cache['AuditPolicy'] = ConvertFrom-HWAuditCsv -Lines (Get-Content -LiteralPath (Join-Path $script:Root 'tests/fixtures/auditpol-backup.csv'))
        return $ctx
    }
}

Describe 'Contrato comum dos controles' {
    It 'controle <Id> define Get e Test; Set e Restore só se for aplicável' -TestCases @(Get-HWControlCatalog | ForEach-Object { @{ Id = $_.Id; Tipo = $_.Tipo } }) {
        param($Id, $Tipo)
        Get-Command "Get-HWControl$Id" -CommandType Function | Should -Not -BeNullOrEmpty
        Get-Command "Test-HWControl$Id" -CommandType Function | Should -Not -BeNullOrEmpty
        $set = Get-Command "Set-HWControl$Id" -CommandType Function -ErrorAction SilentlyContinue
        $restore = Get-Command "Restore-HWControl$Id" -CommandType Function -ErrorAction SilentlyContinue
        if ($Tipo -eq 'Aplicavel') {
            $set | Should -Not -BeNullOrEmpty
            $restore | Should -Not -BeNullOrEmpty
            $set.Parameters.ContainsKey('WhatIf') | Should -BeTrue
            $restore.Parameters.ContainsKey('WhatIf') | Should -BeTrue
        } else {
            $set | Should -BeNullOrEmpty
            $restore | Should -BeNullOrEmpty
        }
    }
}

Describe '01-06 · política de senha e bloqueio' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        Mock Set-HWSecurityValues { }
    }
    It 'audita o Windows padrão (fixture) como não conforme em 01-05 e 06' {
        foreach ($id in '01', '02', '03', '05', '06') {
            (& "Get-HWControl$id" -Context $script:Ctx).Status | Should -Be 'NaoConforme' -Because "controle $id"
        }
        (Get-HWControl04 -Context $script:Ctx).Status | Should -Be 'Conforme'   # 42 dias <= 90
    }
    It 'Set-HWControl01 aplica somente MinimumPasswordLength=12' {
        $change = Set-HWControl01 -Context $script:Ctx -Confirm:$false
        $change.Changed | Should -BeTrue
        Should -Invoke Set-HWSecurityValues -Times 1 -Exactly -ParameterFilter { $Values.Count -eq 1 -and $Values['MinimumPasswordLength'] -eq 12 }
    }
    It 'Set-HWControl0<Id> respeita -WhatIf' -TestCases @(@{ Id = 1 }, @{ Id = 2 }, @{ Id = 3 }, @{ Id = 4 }, @{ Id = 5 }, @{ Id = 6 }) {
        param($Id)
        $change = & "Set-HWControl0$Id" -Context $script:Ctx -WhatIf
        $change.Changed | Should -BeFalse
        Should -Invoke Set-HWSecurityValues -Times 0 -Exactly
    }
    It 'Set-HWControl05 aplica limite e janela, e ajusta a duração quando ela é menor que a janela' {
        $null = Set-HWControl05 -Context $script:Ctx -Confirm:$false
        Should -Invoke Set-HWSecurityValues -Times 1 -Exactly -ParameterFilter {
            $Values['LockoutBadCount'] -eq 5 -and $Values['ResetLockoutCount'] -eq 15 -and $Values['LockoutDuration'] -eq 15
        }
    }
    It 'Set-HWControl05 não mexe na duração quando ela já comporta a janela' {
        $script:Ctx.Cache['SecurityPolicy']['System Access']['LockoutDuration'] = '30'
        $null = Set-HWControl05 -Context $script:Ctx -Confirm:$false
        Should -Invoke Set-HWSecurityValues -Times 1 -Exactly -ParameterFilter { -not $Values.ContainsKey('LockoutDuration') }
    }
    It 'Get-HWControl04 marca "nunca expira" (-1) como não conforme' {
        $script:Ctx.Cache['SecurityPolicy']['System Access']['MaximumPasswordAge'] = '-1'
        $state = Get-HWControl04 -Context $script:Ctx
        $state.Status | Should -Be 'NaoConforme'
        $state.Findings | Should -Contain 'Senhas nunca expiram.'
    }
    It 'Restore-HWControl05 restaura os três valores salvos' {
        $saved = [pscustomobject]@{ LockoutBadCount = 0; ResetLockoutCount = 10; LockoutDuration = 10 }
        $null = Restore-HWControl05 -Context $script:Ctx -Saved $saved -Confirm:$false
        Should -Invoke Set-HWSecurityValues -Times 1 -Exactly -ParameterFilter { $Values['LockoutBadCount'] -eq 0 -and $Values['LockoutDuration'] -eq 10 }
    }
}

Describe '07 · renomear Administrador' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        $script:Admin = [pscustomobject]@{ Name = 'Administrator'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' }; Enabled = $false; LastLogon = $null }
        Mock Get-HWLocalAccountByRid { $script:Admin } -ParameterFilter { $Rid -eq 500 }
        Mock Get-LocalUser { }
        Mock Get-LocalGroup { }
        Mock Rename-LocalUser { }
    }
    It 'considera não conforme o nome padrão e conforme um nome não óbvio' {
        (Get-HWControl07 -Context $script:Ctx).Status | Should -Be 'NaoConforme'
        $script:Admin.Name = 'adm-lab-upe'
        (Get-HWControl07 -Context $script:Ctx).Status | Should -Be 'Conforme'
    }
    It 'recusa aplicar sem nome definido no perfil' {
        { Set-HWControl07 -Context $script:Ctx -Confirm:$false } | Should -Throw '*AdministratorNewName*'
        Should -Invoke Rename-LocalUser -Times 0 -Exactly
    }
    It 'recusa nome que já existe em outra conta' {
        $script:Ctx.Config.Accounts.AdministratorNewName = 'suporte'
        Mock Get-LocalUser { [pscustomobject]@{ Name = 'suporte' } } -ParameterFilter { $Name -eq 'suporte' }
        { Set-HWControl07 -Context $script:Ctx -Confirm:$false } | Should -Throw '*Já existe*'
    }
    It 'renomeia pelo SID -500, nunca pelo nome' {
        $script:Ctx.Config.Accounts.AdministratorNewName = 'adm-lab-upe'
        $change = Set-HWControl07 -Context $script:Ctx -Confirm:$false
        $change.Changed | Should -BeTrue
        Should -Invoke Rename-LocalUser -Times 1 -Exactly -ParameterFilter { "$SID" -eq 'S-1-5-21-1-2-3-500' -and $NewName -eq 'adm-lab-upe' }
    }
    It 'respeita -WhatIf' {
        $script:Ctx.Config.Accounts.AdministratorNewName = 'adm-lab-upe'
        $null = Set-HWControl07 -Context $script:Ctx -WhatIf
        Should -Invoke Rename-LocalUser -Times 0 -Exactly
    }
    It 'restaura o nome original do backup' {
        $script:Admin.Name = 'adm-lab-upe'
        $saved = [pscustomobject]@{ SID = 'S-1-5-21-1-2-3-500'; Name = 'Administrator' }
        $null = Restore-HWControl07 -Context $script:Ctx -Saved $saved -Confirm:$false
        Should -Invoke Rename-LocalUser -Times 1 -Exactly -ParameterFilter { $NewName -eq 'Administrator' }
    }
}

Describe '08 · Convidado' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        $script:Guest = [pscustomobject]@{ Name = 'Convidado'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-501' }; Enabled = $true }
        Mock Get-HWLocalAccountByRid { $script:Guest } -ParameterFilter { $Rid -eq 501 }
        Mock Disable-LocalUser { }
    }
    It 'desabilita pelo SID -501 quando habilitada' {
        (Get-HWControl08 -Context $script:Ctx).Status | Should -Be 'NaoConforme'
        $null = Set-HWControl08 -Context $script:Ctx -Confirm:$false
        Should -Invoke Disable-LocalUser -Times 1 -Exactly -ParameterFilter { "$SID" -eq 'S-1-5-21-1-2-3-501' }
    }
    It 'não faz nada quando já está desabilitada' {
        $script:Guest.Enabled = $false
        (Get-HWControl08 -Context $script:Ctx).Status | Should -Be 'Conforme'
        $null = Set-HWControl08 -Context $script:Ctx -Confirm:$false
        Should -Invoke Disable-LocalUser -Times 0 -Exactly
    }
}

Describe '09 · UAC' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        $script:Reg = @{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1 }
        Mock Get-HWRegistryValue { $script:Reg[$Name] }
        Mock Set-HWRegistryValue { }
    }
    It 'altera só os valores divergentes e marca reinício quando muda EnableLUA' {
        (Get-HWControl09 -Context $script:Ctx).Status | Should -Be 'NaoConforme'
        $change = Set-HWControl09 -Context $script:Ctx -Confirm:$false
        $change.RestartNeeded | Should -BeTrue
        Should -Invoke Set-HWRegistryValue -Times 2 -Exactly
        Should -Invoke Set-HWRegistryValue -Times 1 -Exactly -ParameterFilter { $Name -eq 'ConsentPromptBehaviorAdmin' -and $Value -eq 2 }
        Should -Invoke Set-HWRegistryValue -Times 0 -Exactly -ParameterFilter { $Name -eq 'PromptOnSecureDesktop' }
    }
    It 'restaura removendo valor que não existia' {
        $saved = [pscustomobject]@{ EnableLUA = 1; ConsentPromptBehaviorAdmin = $null; PromptOnSecureDesktop = 1 }
        $script:Reg = @{ EnableLUA = 1; ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
        $null = Restore-HWControl09 -Context $script:Ctx -Saved $saved -Confirm:$false
        Should -Invoke Set-HWRegistryValue -Times 1 -Exactly -ParameterFilter { $Name -eq 'ConsentPromptBehaviorAdmin' -and $null -eq $Value }
    }
}

Describe '10 · logon de rede (somente auditoria)' {
    It 'aponta contas locais liberadas na rede' {
        $ctx = Get-TestContext
        Mock Get-HWRegistryValue { $null }
        $state = Get-HWControl10 -Context $ctx
        $state.Status | Should -Be 'NaoConforme'
        ($state.Findings -join ' ') | Should -Match 'S-1-5-113'
        ($state.Findings -join ' ') | Should -Match 'Todos'
    }
    It 'fica conforme quando S-1-5-113 está negado' {
        $ctx = Get-TestContext
        $ctx.Cache['SecurityPolicy']['Privilege Rights']['SeDenyNetworkLogonRight'] = '*S-1-5-32-546,*S-1-5-113'
        Mock Get-HWRegistryValue { $null }
        (Get-HWControl10 -Context $ctx).Compliant | Should -BeTrue
    }
}

Describe '11 e 14 · auditoria' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        Mock Set-HWAuditPolicy { }
        Mock Get-HWRegistryValue { 1 }
    }
    It 'Set-HWControl11 habilita Logon com valor 3 pelo GUID e Bloqueio de conta preservando o sucesso' {
        (Get-HWControl11 -Context $script:Ctx).Status | Should -Be 'NaoConforme'
        $null = Set-HWControl11 -Context $script:Ctx -Confirm:$false
        Should -Invoke Set-HWAuditPolicy -Times 1 -Exactly -ParameterFilter { $Guid -eq '{0CCE9215-69AE-11D9-BED3-505054503030}' -and $Value -eq 3 }
        Should -Invoke Set-HWAuditPolicy -Times 1 -Exactly -ParameterFilter { $Guid -eq '{0CCE9217-69AE-11D9-BED3-505054503030}' -and $Value -eq 3 }
    }
    It 'Set-HWControl14 só toca nas duas subcategorias que precisam' {
        Mock Get-LocalUser { @() }
        Mock Get-HWLocalGroupMemberList { @() }
        $null = Set-HWControl14 -Context $script:Ctx -Confirm:$false
        Should -Invoke Set-HWAuditPolicy -Times 1 -Exactly
        Should -Invoke Set-HWAuditPolicy -Times 1 -Exactly -ParameterFilter { $Guid -eq '{0CCE9235-69AE-11D9-BED3-505054503030}' -and $Value -eq 3 }
    }
    It 'Get-HWControl14 pede revisão quando a lista de administradores aprovados está vazia' {
        $script:Ctx.Cache['AuditPolicy']['{0CCE9235-69AE-11D9-BED3-505054503030}'] = 3
        Mock Get-LocalUser { @([pscustomobject]@{ Name = 'aluno'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' }; Enabled = $true; PasswordRequired = $true; PasswordExpires = $null; LastLogon = $null }) }
        Mock Get-HWLocalGroupMemberList { @([pscustomobject]@{ Name = 'PC\aluno'; SID = 'S-1-5-21-1-2-3-1001'; ObjectClass = 'User'; Source = 'Local' }) }
        $state = Get-HWControl14 -Context $script:Ctx
        $state.Status | Should -Be 'Revisar'
        ($state.Findings -join ' ') | Should -Match 'nunca expira'
        $script:Ctx.Config.Accounts.ApprovedAdministrators = @('outro')
        (Get-HWControl14 -Context $script:Ctx).Status | Should -Be 'NaoConforme'
        $script:Ctx.Config.Accounts.ApprovedAdministrators = @('aluno')
        (Get-HWControl14 -Context $script:Ctx).Status | Should -Be 'Conforme'
    }
    It 'Set-HWControl11 respeita -WhatIf' {
        $null = Set-HWControl11 -Context $script:Ctx -WhatIf
        Should -Invoke Set-HWAuditPolicy -Times 0 -Exactly
    }
}

Describe '12 · firewall e portas (somente auditoria)' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        Mock Get-NetFirewallProfile {
            @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' },
                [pscustomobject]@{ Name = 'Private'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' },
                [pscustomobject]@{ Name = 'Public'; Enabled = 'False'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' })
        }
        Mock Get-NetTCPConnection {
            @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 3389; OwningProcess = 1 },
                [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 9000; OwningProcess = 1 })
        }
        Mock Get-NetUDPEndpoint { @() }
        Mock Get-NetFirewallRule { @() }
        Mock Get-Process { @([pscustomobject]@{ Id = 1; ProcessName = 'svchost' }) }
    }
    It 'aponta perfil desligado e porta de administração remota' {
        $state = Get-HWControl12 -Context $script:Ctx
        $state.Status | Should -Be 'NaoConforme'
        ($state.Findings -join ' ') | Should -Match 'Public'
        ($state.Findings -join ' ') | Should -Match '3389'
        @($state.Observed.PortasTcpEmEscuta).Count | Should -Be 1   # loopback fica de fora
    }
    It 'pede revisão quando os perfis estão certos mas não há lista de portas aprovadas' {
        Mock Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' }) }
        (Get-HWControl12 -Context $script:Ctx).Status | Should -Be 'Revisar'
        $script:Ctx.Config.Firewall.AllowedListeningPorts = @(3389)
        (Get-HWControl12 -Context $script:Ctx).Status | Should -Be 'Conforme'
    }
}

Describe '13 · proteção de logs (somente auditoria)' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        $script:OldSystemRoot = $env:SystemRoot
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $env:SystemRoot = "$TestDrive" }
        Mock Get-WinEvent {
            @([pscustomobject]@{ LogName = 'Security'; IsEnabled = $true; MaximumSizeInBytes = 20MB; LogMode = 'Circular'; SecurityDescriptor = 'O:BAG:SYD:' },
                [pscustomobject]@{ LogName = 'System'; IsEnabled = $true; MaximumSizeInBytes = 32MB; LogMode = 'Circular'; SecurityDescriptor = 'O:BAG:SYD:' })
        } -ParameterFilter { $null -ne $ListLog }
        Mock Get-WinEvent { throw [Exception]::new('No events were found') } -ParameterFilter { $null -ne $FilterHashtable }
        Mock Get-Acl { [pscustomobject]@{ Access = @() } }
    }
    AfterEach { $env:SystemRoot = $script:OldSystemRoot }
    It 'aponta o log Security menor que o mínimo do perfil' {
        $state = Get-HWControl13 -Context $script:Ctx
        $state.Status | Should -Be 'NaoConforme'
        ($state.Findings -join ' ') | Should -Match 'Security com 20480 KB'
    }
}

Describe '15 · aplicações e recursos' {
    BeforeEach {
        $script:Ctx = Get-TestContext
        $script:Features = @{ SMB1Protocol = 'Enabled'; TelnetClient = 'Enabled'; TFTP = 'Disabled' }
        Mock Get-WindowsOptionalFeature {
            if ($script:Features.ContainsKey($FeatureName)) { [pscustomobject]@{ FeatureName = $FeatureName; State = $script:Features[$FeatureName] } }
        }
        Mock Disable-WindowsOptionalFeature { [pscustomobject]@{ RestartNeeded = $true } }
        Mock Get-HWInstalledApplication { @([pscustomobject]@{ Nome = '7-Zip'; Versao = '24.08'; Editor = 'Igor Pavlov' }) }
    }
    It 'inventaria e marca recurso ausente' {
        $state = Get-HWControl15 -Context $script:Ctx
        $state.Status | Should -Be 'NaoConforme'
        ($state.Observed.Recursos | Where-Object Nome -eq 'MicrosoftWindowsPowerShellV2Root').Estado | Should -Be 'Ausente'
        $state.Observed.TotalAplicacoes | Should -Be 1
    }
    It 'desabilita só o que está habilitado E aprovado' {
        $script:Ctx.Config.Features.ApprovedToDisable = @('SMB1Protocol', 'TFTP')
        $change = Set-HWControl15 -Context $script:Ctx -Confirm:$false
        $change.RestartNeeded | Should -BeTrue
        Should -Invoke Disable-WindowsOptionalFeature -Times 1 -Exactly
        Should -Invoke Disable-WindowsOptionalFeature -Times 1 -Exactly -ParameterFilter { $FeatureName -eq 'SMB1Protocol' -and $NoRestart }
        ($change.Actions -join ' ') | Should -Match 'TelnetClient: mantido'
    }
    It 'não desabilita nada sem aprovação' {
        $null = Set-HWControl15 -Context $script:Ctx -Confirm:$false
        Should -Invoke Disable-WindowsOptionalFeature -Times 0 -Exactly
    }
}

Describe '16 · serviços (somente auditoria)' {
    It 'detecta caminho de serviço sem aspas: <Caminho> -> <Esperado>' -TestCases @(
        @{ Caminho = 'C:\Program Files\App\svc.exe -k'; Esperado = $true }
        @{ Caminho = '"C:\Program Files\App\svc.exe" -k'; Esperado = $false }
        @{ Caminho = 'C:\Windows\system32\svchost.exe -k netsvcs'; Esperado = $false }
        @{ Caminho = ''; Esperado = $false }
    ) {
        param($Caminho, $Esperado)
        Test-HWUnquotedServicePath -PathName $Caminho | Should -Be $Esperado
    }
    It 'aponta serviço da lista de revisão em execução e pede revisão de conta não interna' {
        $ctx = Get-TestContext
        Mock Get-CimInstance {
            @([pscustomobject]@{ Name = 'RemoteRegistry'; DisplayName = 'Registro Remoto'; StartMode = 'Auto'; State = 'Running'; StartName = 'NT AUTHORITY\LocalService'; PathName = 'C:\Windows\system32\svchost.exe -k localService' },
                [pscustomobject]@{ Name = 'AppSvc'; DisplayName = 'App'; StartMode = 'Auto'; State = 'Running'; StartName = '.\svc_app'; PathName = '"C:\App\app.exe"' })
        }
        Mock Get-Service { [pscustomobject]@{ DependentServices = @() } }
        $state = Get-HWControl16 -Context $ctx
        $state.Status | Should -Be 'NaoConforme'
        @($state.Observed.ListaDeRevisaoAtiva).Count | Should -Be 1
        @($state.Observed.ContasNaoInternas).Count | Should -Be 1
    }
}
