#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Testes das bibliotecas (Common, Safety, Backup, Reporting). Rodam em Linux e Windows.

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($m in 'Common', 'Safety', 'Backup', 'Reporting') {
        Import-Module (Join-Path $script:Root "scripts/lib/$m.psm1") -Force -DisableNameChecking
    }
    $script:Fixtures = Join-Path $script:Root 'tests/fixtures'
    $script:ProfileExample = Join-Path $script:Root 'scripts/config/perfil-academico.example.json'
}

Describe 'Catálogo' {
    It 'tem exatamente 16 controles, IDs 01 a 16, e cada arquivo existe' {
        $catalog = @(Get-HWControlCatalog)
        $catalog.Count | Should -Be 16
        ($catalog.Id -join ',') | Should -Be '01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,16'
        foreach ($c in $catalog) { Join-Path $script:Root "scripts/controles/$($c.Arquivo)" | Should -Exist }
    }
    It 'marca 10, 12, 13 e 16 como somente auditoria' {
        $auditOnly = @(Get-HWControlCatalog | Where-Object Tipo -eq 'SomenteAuditoria' | ForEach-Object Id)
        ($auditOnly -join ',') | Should -Be '10,12,13,16'
    }
}

Describe 'Perfil' {
    It 'aceita o perfil de exemplo' {
        { Assert-HWProfile -Config (Read-HWJson -Path $script:ProfileExample) } | Should -Not -Throw
    }
    It 'recusa valores mais fracos que o checklist: <Campo> = <Valor>' -TestCases @(
        @{ Campo = 'MinimumPasswordLength'; Valor = 8 }
        @{ Campo = 'PasswordHistorySize'; Valor = 2 }
        @{ Campo = 'MaximumPasswordAge'; Valor = 120 }
        @{ Campo = 'LockoutBadCount'; Valor = 0 }
        @{ Campo = 'LockoutDuration'; Valor = 5 }
    ) {
        param($Campo, $Valor)
        $config = Read-HWJson -Path $script:ProfileExample
        $config.Password.$Campo = $Valor
        { Assert-HWProfile -Config $config } | Should -Throw
    }
    It 'recusa perfil sem seção obrigatória' {
        $config = Read-HWJson -Path $script:ProfileExample
        $config.PSObject.Properties.Remove('Uac')
        { Assert-HWProfile -Config $config } | Should -Throw "*Uac*"
    }
}

Describe 'Leitura do secedit e do auditpol' {
    It 'converte o .inf exportado pelo secedit (UTF-16)' {
        $ini = ConvertFrom-HWIni -Lines (Get-Content -LiteralPath (Join-Path $script:Fixtures 'secedit-export.inf') -Encoding Unicode)
        $ini['System Access']['MinimumPasswordLength'] | Should -Be '0'
        $ini['System Access']['LockoutBadCount'] | Should -Be '10'
        $ini['Privilege Rights']['SeDenyNetworkLogonRight'] | Should -Be '*S-1-5-32-546'
    }
    It 'lê valores numéricos e direitos pelo contexto' {
        $ctx = New-HWContext -Config (Read-HWJson -Path $script:ProfileExample) -Mode Audit
        $ctx.Cache['SecurityPolicy'] = ConvertFrom-HWIni -Lines (Get-Content -LiteralPath (Join-Path $script:Fixtures 'secedit-export.inf') -Encoding Unicode)
        Get-HWSystemAccessValue -Context $ctx -Name 'MaximumPasswordAge' | Should -Be 42
        Get-HWSystemAccessValue -Context $ctx -Name 'NaoExiste' | Should -BeNullOrEmpty
        (Get-HWPrivilegeRight -Context $ctx -Name 'SeNetworkLogonRight') | Should -Contain 'S-1-1-0'
        @(Get-HWPrivilegeRight -Context $ctx -Name 'SeDenyRemoteInteractiveLogonRight').Count | Should -Be 0
    }
    It 'converte o CSV do auditpol pela posição das colunas (inglês)' {
        $map = ConvertFrom-HWAuditCsv -Lines (Get-Content -LiteralPath (Join-Path $script:Fixtures 'auditpol-backup.csv'))
        $map['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 1
        $map['{0CCE9237-69AE-11D9-BED3-505054503030}'] | Should -Be 3
        $map.ContainsKey('') | Should -BeFalse
    }
    It 'converte o CSV do auditpol com títulos em português' {
        $map = ConvertFrom-HWAuditCsv -Lines (Get-Content -LiteralPath (Join-Path $script:Fixtures 'auditpol-backup-ptbr.csv') -Encoding UTF8)
        $map['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 3
    }
    It 'trata subcategoria ausente como 0 e aceita GUID sem chaves' {
        $ctx = New-HWContext -Config (Read-HWJson -Path $script:ProfileExample) -Mode Audit
        $ctx.Cache['AuditPolicy'] = ConvertFrom-HWAuditCsv -Lines (Get-Content -LiteralPath (Join-Path $script:Fixtures 'auditpol-backup.csv'))
        Get-HWAuditPolicy -Context $ctx -Guid '0cce9215-69ae-11d9-bed3-505054503030' | Should -Be 1
        Get-HWAuditPolicy -Context $ctx -Guid '{0CCE9999-69AE-11D9-BED3-505054503030}' | Should -Be 0
    }
    It 'Set-HWSecurityValues recusa chave fora do escopo dos controles 01-06' {
        $ctx = New-HWContext -Config (Read-HWJson -Path $script:ProfileExample) -Mode Apply
        { Set-HWSecurityValues -Context $ctx -Values @{ NewAdministratorName = 'x' } -WhatIf } | Should -Throw '*fora do escopo*'
    }
}

Describe 'Estados' {
    It 'traduz Compliant em Status' {
        (New-HWState -Id '01' -Compliant $true).Status | Should -Be 'Conforme'
        (New-HWState -Id '01' -Compliant $false).Status | Should -Be 'NaoConforme'
        (New-HWState -Id '01' -Compliant $null).Status | Should -Be 'Revisar'
        (New-HWErrorState -Id '01' -Message 'x').Status | Should -Be 'Erro'
    }
}

Describe 'Aprovação (Safety)' {
    BeforeEach {
        $script:Machine = [pscustomobject]@{ ComputerName = 'VM-LAB'; IsVirtual = $true; Manufacturer = 'QEMU'; Model = 'Standard PC' }
        $script:Approval = [pscustomobject]@{
            Responsavel = 'Prof.ª Responsável'; Maquina = 'VM-LAB'; ValidaAte = '2099-12-31'
            AmbienteDeLaboratorio = $true; SnapshotConfirmado = $true; ContaDeRecuperacaoConfirmada = $true
            PermitirMaquinaFisica = $false; ControlesAprovados = @('01', '07', '12', '15')
        }
        $script:Applicable = @('01', '02', '03', '04', '05', '06', '07', '08', '09', '11', '14', '15')
    }
    It 'devolve só IDs pedidos, aprovados e aplicáveis (12 é somente auditoria)' {
        $ids = Assert-HWApproval -Approval $script:Approval -Machine $script:Machine -RequestedIds @('01', '02', '12', '15') -ApplicableIds $script:Applicable
        ($ids -join ',') | Should -Be '01,15'
    }
    It 'bloqueia quando <Caso>' -TestCases @(
        @{ Caso = 'a máquina é outra'; Campo = 'Maquina'; Valor = 'OUTRA'; Erro = '*OUTRA*' }
        @{ Caso = 'a aprovação venceu'; Campo = 'ValidaAte'; Valor = '2000-01-01'; Erro = '*vencida*' }
        @{ Caso = 'não há snapshot'; Campo = 'SnapshotConfirmado'; Valor = $false; Erro = '*snapshot*' }
        @{ Caso = 'não é laboratório'; Campo = 'AmbienteDeLaboratorio'; Valor = $false; Erro = '*laborat*' }
        @{ Caso = 'não há conta de recuperação'; Campo = 'ContaDeRecuperacaoConfirmada'; Valor = $false; Erro = '*recupera*' }
        @{ Caso = 'não há responsável'; Campo = 'Responsavel'; Valor = ' '; Erro = '*respons*' }
        @{ Caso = 'a data é inválida'; Campo = 'ValidaAte'; Valor = '31/12/2099'; Erro = '*AAAA-MM-DD*' }
    ) {
        param($Caso, $Campo, $Valor, $Erro)
        $null = $Caso
        $script:Approval.$Campo = $Valor
        { Assert-HWApproval -Approval $script:Approval -Machine $script:Machine -RequestedIds @('01') -ApplicableIds $script:Applicable } | Should -Throw $Erro
    }
    It 'bloqueia máquina física sem autorização explícita' {
        $script:Machine.IsVirtual = $false
        { Assert-HWApproval -Approval $script:Approval -Machine $script:Machine -RequestedIds @('01') -ApplicableIds $script:Applicable } | Should -Throw '*virtual*'
        $script:Approval.PermitirMaquinaFisica = $true
        { Assert-HWApproval -Approval $script:Approval -Machine $script:Machine -RequestedIds @('01') -ApplicableIds $script:Applicable } | Should -Not -Throw
    }
    It 'recusa plataforma antiga, domínio e controlador de domínio para alterar' {
        $base = @{ OsBuild = 19045; ProductType = 1; PartOfDomain = $false; Domain = 'WORKGROUP'; PSEdition = 'Desktop' }
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$base) -Mode Apply } | Should -Not -Throw
        $old = $base.Clone(); $old.OsBuild = 9600
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$old) -Mode Audit } | Should -Throw
        $domain = $base.Clone(); $domain.PartOfDomain = $true
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$domain) -Mode Audit } | Should -Not -Throw
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$domain) -Mode Apply } | Should -Throw '*domínio*'
        $dc = $base.Clone(); $dc.ProductType = 2
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$dc) -Mode Rollback } | Should -Throw '*GPO*'
        $core = $base.Clone(); $core.PSEdition = 'Core'
        { Assert-HWSupportedPlatform -Machine ([pscustomobject]$core) -Mode Apply } | Should -Throw '*5.1*'
    }
    It 'impede duas execuções simultâneas (mutex)' {
        $name = "Local\HW-Teste-$([guid]::NewGuid().ToString('N'))"
        $first = Enter-HWLock -Name $name
        try {
            $job = Start-Job -ScriptBlock {
                $m = New-Object Threading.Mutex($false, $using:name)
                $m.WaitOne(0)
            }
            ($job | Wait-Job | Receive-Job) | Should -BeFalse
            Remove-Job $job
        } finally { Exit-HWLock -Mutex $first }
    }
}

Describe 'Backup com escopo' {
    BeforeEach {
        $script:Machine = [pscustomobject]@{ ComputerName = 'VM-LAB'; Fingerprint = 'abc123'; OsBuild = 19045 }
        $script:Ctx = New-HWContext -Config (Read-HWJson -Path $script:ProfileExample) -Mode Apply -RunDirectory $TestDrive
        $script:Ctx.BackupDirectory = Join-Path $TestDrive "backup-$([guid]::NewGuid().ToString('N'))"
        $script:States = @(
            (New-HWState -Id '01' -Observed ([pscustomobject]@{ MinimumPasswordLength = 0 }) -Compliant $false),
            (New-HWState -Id '08' -Observed ([pscustomobject]@{ SID = 'S-1-5-21-1-2-3-501'; Name = 'Guest'; Enabled = $true }) -Compliant $false)
        )
    }
    It 'grava e relê o backup da mesma máquina' {
        $path = New-HWBackup -Context $script:Ctx -States $script:States -Machine $script:Machine -Confirm:$false -WarningAction SilentlyContinue
        $path | Should -Exist
        "$path.sha256" | Should -Exist
        $read = Read-HWBackup -Path $script:Ctx.BackupDirectory -Machine $script:Machine
        @($read.Controls).Count | Should -Be 2
        $read.Controls[1].Observed.Enabled | Should -BeTrue
    }
    It 'recusa backup alterado depois de gravado' {
        $path = New-HWBackup -Context $script:Ctx -States $script:States -Machine $script:Machine -Confirm:$false -WarningAction SilentlyContinue
        (Get-Content -LiteralPath $path -Raw) -replace '"MinimumPasswordLength":\s*0', '"MinimumPasswordLength": 99' | Set-Content -LiteralPath $path
        { Read-HWBackup -Path $path -Machine $script:Machine } | Should -Throw '*Hash*'
    }
    It 'recusa backup de outra máquina' {
        $null = New-HWBackup -Context $script:Ctx -States $script:States -Machine $script:Machine -Confirm:$false -WarningAction SilentlyContinue
        $other = [pscustomobject]@{ ComputerName = 'OUTRA'; Fingerprint = 'zzz'; OsBuild = 19045 }
        { Read-HWBackup -Path $script:Ctx.BackupDirectory -Machine $other } | Should -Throw '*outra máquina*'
    }
    It 'não grava nada com -WhatIf' {
        $path = New-HWBackup -Context $script:Ctx -States $script:States -Machine $script:Machine -WhatIf
        $path | Should -BeNullOrEmpty
        $script:Ctx.BackupDirectory | Should -Not -Exist
    }
}

Describe 'Relatórios' {
    BeforeAll {
        $script:Catalog = @(Get-HWControlCatalog -Id '01', '12')
    }
    It 'calcula o código de saída' {
        $ok = New-HWRow -Control $script:Catalog[0] -Before (New-HWState -Id '01' -Compliant $true)
        $bad = New-HWRow -Control $script:Catalog[0] -Before (New-HWState -Id '01' -Compliant $false)
        $review = New-HWRow -Control $script:Catalog[1] -Before (New-HWState -Id '12' -Compliant $null)
        $err = New-HWRow -Control $script:Catalog[0] -Before (New-HWState -Id '01' -Compliant $false) -After (New-HWState -Id '01' -Compliant $false) -Action 'Erro'
        $fixed = New-HWRow -Control $script:Catalog[0] -Before (New-HWState -Id '01' -Compliant $false) -After (New-HWState -Id '01' -Compliant $true) -Action 'Aplicado'
        Get-HWExitCode -Rows @($ok, $review) | Should -Be 0
        Get-HWExitCode -Rows @($ok, $bad) | Should -Be 1
        Get-HWExitCode -Rows @($fixed) | Should -Be 0
        Get-HWExitCode -Rows @($ok, $err) | Should -Be 2
    }
    It 'gera JSON, CSV, Markdown e HTML com texto escapado' {
        $dir = Join-Path $TestDrive 'relatorio'
        New-Item -ItemType Directory -Path $dir | Out-Null
        $ctx = New-HWContext -Config (Read-HWJson -Path $script:ProfileExample) -Mode Audit -RunDirectory $dir
        $state = New-HWState -Id '12' -Compliant $null -Findings @('Porta <3389> | RDP')
        $rows = @(New-HWRow -Control $script:Catalog[1] -Before $state)
        $null = Export-HWReport -Context $ctx -Rows $rows -Machine $null -ExitCode 0
        foreach ($f in 'resultados.json', 'resultados.csv', 'relatorio.md', 'relatorio.html') { Join-Path $dir $f | Should -Exist }
        $json = Get-Content -LiteralPath (Join-Path $dir 'resultados.json') -Raw | ConvertFrom-Json
        $json.Controles[0].Id | Should -Be '12'
        (Get-Content -LiteralPath (Join-Path $dir 'relatorio.html') -Raw) | Should -Match '&lt;3389&gt;'
        (Get-Content -LiteralPath (Join-Path $dir 'relatorio.md') -Raw) | Should -Match 'Porta <3389> / RDP'
    }
}
